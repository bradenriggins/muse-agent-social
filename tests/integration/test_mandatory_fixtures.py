"""Mandatory adversarial fixtures from the TEST PLAN.

Each fixture is a hostile input the plan requires the implementation to
handle. Fixtures that the implementation cannot support are written as
explicit gap-documentation tests (named ``test_gap_*``): they assert the
current behavior, carry the exact requirement they violate, and are
mirrored precisely in INTERFACE.md. Nothing here is weakened to hide a
gap.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from muse_agent_social.transports.local import LocalTransport
from muse_agent_social.validation import ValidationError, validate_payload

from support.harness import (
    ReceiveHarness,
    deliver,
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)

UTC = timezone.utc


@pytest.fixture()
def pair(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "cccccccc-3333-4444-8555-666666666666"
    ctx = provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    harness = ReceiveHarness(
        conn,
        relationship_id=rid,
        own_identity_id=bob["identity_id"],
        own_rel_priv=bob["rel_priv"],
        transport=LocalTransport(tmp_path / "relay"),
    )
    return {
        "alice": alice, "bob": bob, "conn": conn, "rid": rid,
        "conv": conv, "harness": harness, "tmp": tmp_path,
    }


def _seal(pair, event_type, payload, seq, **kw):
    return make_sealed(
        pair["alice"], pair["bob"], pair["rid"], pair["conv"],
        event_type, payload, seq=seq, **kw,
    )


# -- forged human approval ------------------------------------------------------------
# Plan/schema requirement (schemas/payloads/human.schema.json):
# "Answer a human request. Requires a local human-approval record;
# approval is never taken from a sender assertion."


def test_forged_human_approval_without_record_rejected(pair):
    """A peer-asserted human.responded with approved=true but no
    approval_record_id is rejected at schema validation: approval is
    never a bare sender assertion (plan: human.responded requires a
    local human-approval record ID). The honest seal path refuses to
    produce such an event at all.

    A response carrying a fabricated record ID still reaches the
    projection (the receiver cannot audit the peer's local store); the
    record ID is persisted for sender-side audit. The honest send path
    (``mas human respond``) only emits IDs for records the local human
    created.
    """
    from muse_agent_social.validation import ValidationError, validate_payload

    h = pair["harness"]
    req_env, req_raw = _seal(
        pair, "human.requested",
        {"prompt": "Approve the wire transfer?",
         "response_shape": "approval",
         "expires_at": "2030-01-01T00:00:00Z"},
        seq=1,
    )
    assert deliver(h, req_raw)["outcome"] == "accepted"
    req_event_id = req_env["protected"]["event_id"]

    # Schema level: bare approval assertion is invalid.
    with pytest.raises(ValidationError) as exc:
        validate_payload(
            "human.responded",
            {"request_id": req_event_id, "answer": "yes", "approved": True},
        )
    assert exc.value.code == "required"

    # Wire level: the sealed bare assertion is quarantined on receipt
    # (payload_invalid), so it never projects approval.
    _, resp_raw = _seal(
        pair, "human.responded",
        {"request_id": req_event_id, "answer": "yes", "approved": True},
        seq=2,
    )
    outcome = deliver(h, resp_raw)
    assert outcome["outcome"] == "quarantined"
    assert outcome["code"] == "payload_invalid"
    assert h.conn.execute(
        "SELECT COUNT(*) FROM human_requests WHERE approved = 1"
    ).fetchone()[0] == 0

    # With a record ID the event is well-formed and projects, carrying
    # the ID for audit.
    _, resp2_raw = _seal(
        pair, "human.responded",
        {"request_id": req_event_id, "answer": "yes", "approved": True,
         "approval_record_id": "peer-record-1"},
        seq=3,
    )
    assert deliver(h, resp2_raw)["outcome"] == "accepted"
    row = h.conn.execute(
        "SELECT approved, approval_record_id FROM human_requests"
        " WHERE request_id = ?",
        (req_event_id,),
    ).fetchone()
    assert row[0] == 1
    assert row[1] == "peer-record-1"


# -- unicode control emoji --------------------------------------------------------------
# Plan requirement (schemas/payloads/reaction.schema.json): "One Unicode
# extended grapheme cluster, at most 32 UTF-8 bytes, no invisible control
# characters."


def test_emoji_single_grapheme_cluster_accepted():
    validate_payload(
        "reaction.added",
        {"target_event_id": str(uuid.uuid4()), "emoji": "\U0001F44D"},
    )


def test_emoji_ascii_control_rejected():
    with pytest.raises(ValidationError):
        validate_payload(
            "reaction.added",
            {"target_event_id": str(uuid.uuid4()), "emoji": "a\x07b"},
        )


def test_emoji_over_32_bytes_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_payload(
            "reaction.added",
            {"target_event_id": str(uuid.uuid4()),
             "emoji": "\U0001F44D" * 9},  # 36 UTF-8 bytes
        )
    assert exc.value.code == "too_long_bytes"


def test_emoji_multiple_grapheme_clusters_rejected():
    """The plan requires one Unicode extended grapheme cluster: three
    thumbs-up must be rejected."""
    with pytest.raises(ValidationError) as exc:
        validate_payload(
            "reaction.added",
            {"target_event_id": str(uuid.uuid4()),
             "emoji": "\U0001F44D\U0001F44D\U0001F44D"},
        )
    assert exc.value.code == "not_single_grapheme"


def test_emoji_invisible_unicode_controls_rejected():
    """Zero-width space (U+200B) and other invisible non-ASCII controls
    are rejected."""
    with pytest.raises(ValidationError) as exc:
        validate_payload(
            "reaction.added",
            {"target_event_id": str(uuid.uuid4()), "emoji": "​"},
        )
    assert exc.value.code == "invisible_control"


def test_emoji_single_compound_clusters_accepted():
    """Legitimate single clusters pass: ZWJ sequences, flags, skin tones."""
    for emoji in ["👍", "🏳️‍🌈", "🇺🇸", "👨‍👩‍👧‍👦", "👍🏽"]:
        validate_payload(
            "reaction.added",
            {"target_event_id": str(uuid.uuid4()), "emoji": emoji},
        )


# -- oversized payloads ---------------------------------------------------------------------
# There is no attachment payload type in the implementation; the
# oversized-input fixture is exercised through the payload/envelope caps.


def test_oversized_message_body_rejected_at_seal(pair):
    from muse_agent_social.crypto.sealing import SealingError
    with pytest.raises(SealingError) as exc:
        _seal(pair, "message.created",
              {"body": "x" * (240 * 1024 + 1), "format": "plain"}, seq=1)
    assert exc.value.code == "payload_too_large"


def test_gap_no_attachment_payload_type_exists():
    """GAP: the TEST PLAN names oversized attachments as a mandatory
    fixture, but no attachment payload type exists in the schemas or
    validation dispatch. An attachment-shaped event is rejected only as
    unknown_event_type (fail-closed), with no size policy of its own.
    See INTERFACE.md.
    """
    with pytest.raises(ValidationError) as exc:
        validate_payload("message.attachment", {"bytes": "x" * 100})
    assert exc.value.code == "unknown_event_type"


# -- revoked relationship ----------------------------------------------------------------------


def test_revoked_relationship_rejects_everything(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "dddddddd-4444-4555-8666-777777777777"
    provision_receive_side(conn, rid, bob, alice, consent_state="revoked")
    conv = new_conversation(conn)
    h = ReceiveHarness(
        conn,
        relationship_id=rid,
        own_identity_id=bob["identity_id"],
        own_rel_priv=bob["rel_priv"],
        transport=LocalTransport(tmp_path / "relay"),
    )
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "after revocation", "format": "plain"},
        seq=1,
    )
    outcome = deliver(h, raw)
    assert outcome["outcome"] == "quarantined"
    assert outcome["code"] == "relationship_revoked"
    assert h.count("events") == 0
    assert h.count("messages") == 0
    assert h.notified == []


# -- clock skew -----------------------------------------------------------------------------------


def test_future_timestamp_beyond_tolerance_rejected(pair):
    h = pair["harness"]
    future = datetime.now(UTC) + timedelta(minutes=10)
    _, raw = _seal(
        pair, "message.created",
        {"body": "from the future", "format": "plain"}, seq=1,
        created_at=future.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    outcome = deliver(h, raw)
    assert outcome["outcome"] == "quarantined"
    assert outcome["code"] == "future_timestamp"
    assert h.count("events") == 0


def test_timestamp_within_future_tolerance_accepted(pair):
    h = pair["harness"]
    future = datetime.now(UTC) + timedelta(minutes=4)
    _, raw = _seal(
        pair, "message.created",
        {"body": "slight skew", "format": "plain"}, seq=1,
        created_at=future.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    assert deliver(h, raw)["outcome"] == "accepted"


def test_expired_event_rejected(pair):
    h = pair["harness"]
    old = datetime.now(UTC) - timedelta(days=8)
    _, raw = _seal(
        pair, "message.created",
        {"body": "too old", "format": "plain"}, seq=1,
        created_at=old.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    outcome = deliver(h, raw)
    assert outcome["outcome"] == "quarantined"
    assert outcome["code"] == "event_expired"
    assert h.count("events") == 0


# -- rotation during in-flight send -------------------------------------------------------------------
# The RotationManager-level gates are covered in test_rotation.py. On the
# receive path the envelope's key_epoch is gated before decrypt: unknown
# epochs are quarantined, and the events-table FK on
# (relationship_id, key_epoch) backstops the commit.


def test_future_key_epoch_quarantined_not_projected(pair):
    """An event sealed with a future unknown key_epoch is quarantined
    before decrypt: nothing is projected, nothing is surfaced."""
    h = pair["harness"]
    _, raw = _seal(
        pair, "message.created",
        {"body": "future epoch", "format": "plain"}, seq=1, key_epoch=7,
    )
    outcome = deliver(h, raw)
    assert outcome["outcome"] == "quarantined"
    assert outcome["code"] == "unknown_future_epoch"
    assert h.count("events") == 0
    assert h.count("messages") == 0
    assert h.unseal_attempts == []
    assert h.notified == []


def test_known_epoch_after_rotation_accepts(pair):
    """After the receiver learns the peer's epoch-2 key (acking a prepare),
    epoch-2 events validate and commit."""
    from muse_agent_social.crypto.rotation import RotationManager

    h = pair["harness"]
    mgr = RotationManager(pair["conn"], str(pair["tmp"] / "keys"))
    # Simulate the peer's prepare for epoch 2 arriving and being acked.
    from muse_agent_social.crypto.rotation import build_prepare
    from muse_agent_social.crypto.identity import agreement_key_multibase_from_pubkey
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )
    from muse_agent_social.crypto.rotation import agreement_fingerprint
    new_priv = X25519PrivateKey.generate()
    new_pub_mb = agreement_key_multibase_from_pubkey(
        new_priv.public_key().public_bytes_raw()
    )
    prepare = build_prepare(
        new_pub_mb,
        agreement_fingerprint(pair["alice"]["rel_pub_mb"]),
        datetime.now(UTC) + timedelta(days=1),
    )
    ack = mgr.on_prepare(pair["rid"], prepare, str(uuid.uuid4()))
    assert ack["epoch"] == 2

    _, raw = _seal(
        pair, "message.created",
        {"body": "epoch two", "format": "plain"}, seq=1, key_epoch=2,
    )
    assert deliver(h, raw)["outcome"] == "accepted"
    assert h.count("events") == 1


# -- peer attempting to force Feed eligibility -----------------------------------------------------
# Delivery mode is receiver-local policy (silent/digest/alert/feed_eligible).
# The signed protected header has additionalProperties=false, so a peer
# cannot smuggle a delivery_mode onto the wire: even re-signed, the schema
# rejects it and the receiver's configured mode governs.


def test_peer_cannot_force_feed_eligibility(pair):
    import copy

    from muse_agent_social.canonical import restricted_jcs
    from muse_agent_social.crypto.identity import b64url_encode

    h = pair["harness"]
    assert h.delivery_mode == "alert"
    env, _ = _seal(
        pair, "message.created",
        {"body": "force my feed", "format": "plain"}, seq=1,
    )
    forged = copy.deepcopy(env)
    forged["protected"]["delivery_mode"] = "feed_eligible"
    unsigned = {k: v for k, v in forged.items() if k != "signature"}
    forged["signature"] = b64url_encode(
        pair["alice"]["ed_priv"].sign(restricted_jcs(unsigned))
    )
    outcome = deliver(h, restricted_jcs(forged))
    assert outcome["outcome"] == "quarantined"
    assert h.count("events") == 0
    assert h.delivery_mode == "alert"


def test_delivery_mode_is_receiver_local_policy(pair):
    """The receiver's delivery mode is local configuration the peer cannot
    influence: the forced-feed test above shows the wire cannot carry a
    mode, and here two receivers hold independent modes."""
    from muse_agent_social.transports.local import LocalTransport
    from support.harness import ReceiveHarness

    conn = pair["conn"]
    silent = ReceiveHarness(
        conn,
        relationship_id=pair["rid"],
        own_identity_id=pair["bob"]["identity_id"],
        own_rel_priv=pair["bob"]["rel_priv"],
        transport=LocalTransport(pair["tmp"] / "relay2"),
        delivery_mode="silent",
    )
    assert silent.delivery_mode == "silent"
    assert pair["harness"].delivery_mode == "alert"
    _, raw = _seal(
        pair, "message.created",
        {"body": "hello", "format": "plain"}, seq=1,
    )
    assert deliver(silent, raw)["outcome"] == "accepted"


# -- wrong relationship --------------------------------------------------------------------------------


def test_wrong_relationship_rejected(pair):
    """An event sealed for a different relationship is rejected before
    decrypt: nothing is committed, nothing is surfaced."""
    h = pair["harness"]
    other_rid = "aaaaaaaa-1111-4222-8333-444444444444"
    env, raw = make_sealed(
        pair["alice"], pair["bob"], other_rid, pair["conv"],
        "message.created", {"body": "wrong rid", "format": "plain"}, seq=1,
    )
    outcome = deliver(h, raw)
    assert outcome["outcome"] == "quarantined"
    assert outcome["code"] == "wrong_relationship"
    assert h.count("events") == 0
    assert h.unseal_attempts == []
