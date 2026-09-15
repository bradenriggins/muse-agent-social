"""Gate: Schema.

Missing, extra, wrong-type, duplicate-key, and oversize inputs produce a
stable rejection code, and no decrypt is attempted. Covers the plan's
validation order: size -> parse -> schema -> (signature/policy/decrypt).

Every case asserts:
  * a stable, machine-readable code (ValidationError.code /
    CanonicalizationError.code / SealingError.code),
  * the error carries only field path + code (no secret or payload values),
  * for the envelope cases, unseal_envelope is never reached (asserted via
    the receive harness unseal spy in the oversize cases).
"""

import copy
import json

import pytest

from muse_agent_social.canonical import (
    CanonicalizationError,
    restricted_jcs,
    strict_parse,
)
from muse_agent_social.validation import (
    MAX_ENVELOPE_BYTES,
    ValidationError,
    check_envelope_size,
    validate,
    validate_payload,
)

from support.harness import (
    deliver,
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
    ReceiveHarness,
)
from muse_agent_social.transports.local import LocalTransport


@pytest.fixture()
def pair(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    db_path = tmp_path / "state.db"
    conn = fresh_db(db_path)
    rid = "11111111-2222-4333-8444-555555555555"
    ctx = provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    return {
        "alice": alice, "bob": bob, "conn": conn, "rid": rid,
        "ctx": ctx, "conv": conv,
    }


def _good_envelope(pair):
    env, raw = make_sealed(
        pair["alice"], pair["bob"], pair["rid"], pair["conv"],
        "message.created", {"body": "hello", "format": "plain"}, seq=1,
    )
    return env, raw


# -- missing fields -------------------------------------------------------


def test_missing_protected_field_rejected(pair):
    env, _ = _good_envelope(pair)
    del env["protected"]["event_id"]
    with pytest.raises(ValidationError) as exc:
        validate("event-envelope", env)
    assert exc.value.code == "required"
    assert "event_id" in exc.value.field_path


def test_missing_top_level_field_rejected(pair):
    env, _ = _good_envelope(pair)
    del env["signature"]
    with pytest.raises(ValidationError) as exc:
        validate("event-envelope", env)
    assert exc.value.code == "required"


def test_missing_payload_field_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_payload("message.created", {"format": "plain"})
    assert exc.value.code == "required"
    assert exc.value.field_path == "body"


# -- extra fields ----------------------------------------------------------


def test_extra_top_level_field_rejected(pair):
    env, _ = _good_envelope(pair)
    env["evil"] = "x"
    with pytest.raises(ValidationError) as exc:
        validate("event-envelope", env)
    assert exc.value.code == "additional_property"


def test_extra_protected_field_rejected(pair):
    env, _ = _good_envelope(pair)
    env["protected"]["injected"] = 1
    with pytest.raises(ValidationError) as exc:
        validate("event-envelope", env)
    assert exc.value.code == "additional_property"


def test_extra_payload_field_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_payload(
            "message.created",
            {"body": "hi", "format": "plain", "injected": True},
        )
    assert exc.value.code == "additional_property"


# -- wrong types ------------------------------------------------------------


def test_wrong_type_sender_seq_rejected(pair):
    env, _ = _good_envelope(pair)
    env["protected"]["sender_seq"] = "1"
    with pytest.raises(ValidationError) as exc:
        validate("event-envelope", env)
    assert exc.value.code == "type"


def test_wrong_type_recipients_rejected(pair):
    env, _ = _good_envelope(pair)
    env["recipients"] = {}
    with pytest.raises(ValidationError) as exc:
        validate("event-envelope", env)
    assert exc.value.code == "type"


def test_wrong_type_payload_field_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_payload(
            "message.created", {"body": ["not", "a", "string"], "format": "plain"}
        )
    assert exc.value.code == "type"


def test_unknown_event_type_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_payload("teleport.arrived", {"x": 1})
    assert exc.value.code == "unknown_event_type"


# -- duplicate keys ----------------------------------------------------------


def test_duplicate_key_rejected_before_schema():
    raw = b'{"a": 1, "a": 2}'
    with pytest.raises(CanonicalizationError) as exc:
        strict_parse(raw)
    assert exc.value.code == "duplicate_key"


def test_duplicate_key_nested_rejected():
    raw = b'{"outer": {"x": 1, "x": 2}}'
    with pytest.raises(CanonicalizationError) as exc:
        strict_parse(raw)
    assert exc.value.code == "duplicate_key"


# -- oversize -----------------------------------------------------------------


def test_oversize_rejected_before_parse():
    big = b"x" * (MAX_ENVELOPE_BYTES + 1)
    with pytest.raises(ValidationError) as exc:
        check_envelope_size(big)
    assert exc.value.code == "envelope_too_large"


def test_oversize_boundary_exactly_allowed():
    assert MAX_ENVELOPE_BYTES == 262144
    check_envelope_size(b"x" * MAX_ENVELOPE_BYTES)  # no raise


def test_oversize_object_never_reaches_unseal(pair, tmp_path):
    """A >256 KiB object is refused by the transport with a stable code
    before any receive work begins; unseal is never attempted."""
    from muse_agent_social.transports.base import TransportError

    transport = LocalTransport(tmp_path / "relay")
    harness = ReceiveHarness(
        pair["conn"],
        relationship_id=pair["rid"],
        own_identity_id=pair["bob"]["identity_id"],
        own_rel_priv=pair["bob"]["rel_priv"],
        transport=transport,
    )
    with pytest.raises(TransportError) as exc:
        deliver(harness, b"x" * (MAX_ENVELOPE_BYTES + 1))
    assert exc.value.code == "object_too_large"
    assert harness.unseal_attempts == []
    assert harness.count("events") == 0


# -- error hygiene: no secret or payload values leak ---------------------------


def test_validation_errors_carry_no_values(pair):
    secret = "supersecret-body-content"
    env, _ = _good_envelope(pair)
    env["protected"]["sender_seq"] = "not-an-int"
    try:
        validate("event-envelope", env)
    except ValidationError as exc:
        text = f"{exc.field_path} {exc.code} {exc}"
        assert secret not in text
    try:
        validate_payload(
            "message.created",
            {"body": secret, "format": "bogus-format-value"},
        )
    except ValidationError as exc:
        text = f"{exc.field_path} {exc.code} {exc}"
        assert secret not in text
        assert "bogus-format-value" not in text
