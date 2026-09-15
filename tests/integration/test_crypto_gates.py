"""Gate: Crypto.

Fresh random keys per run (no secrets in fixtures). Seal/unseal round trip
plus the full tamper matrix: tampering with the protected header, a key
wrap, the body, or the signature must all fail closed with stable codes.
Also: wrong AAD, nonce-length errors, malformed base64url, X25519
low-order peer-key rejection, oversize payloads, and sender-key mismatch.
"""

import base64
import copy

import pytest

from muse_agent_social.canonical import restricted_jcs
from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
    b64url_decode,
    b64url_encode,
)
from muse_agent_social.crypto.sealing import (
    MAX_PAYLOAD_BYTES,
    SealingError,
    seal_envelope,
    unseal_envelope,
)
from muse_agent_social.validation import MAX_ENVELOPE_BYTES

from support.harness import (
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)


@pytest.fixture()
def pair(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "22222222-3333-4444-8555-666666666666"
    provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    return {"alice": alice, "bob": bob, "rid": rid, "conv": conv}


def _seal(pair, **kw):
    return make_sealed(
        pair["alice"], pair["bob"], pair["rid"], pair["conv"],
        "message.created", {"body": "hello", "format": "plain"}, seq=1, **kw
    )


def _unseal(pair, raw):
    return unseal_envelope(
        raw, pair["bob"]["rel_priv"], pair["bob"]["identity_id"]
    )


def _flip_b64url(value: str) -> str:
    raw = bytearray(b64url_decode(value))
    raw[0] ^= 0x01
    return b64url_encode(bytes(raw))


# -- round trip -----------------------------------------------------------------


def test_seal_unseal_round_trip(pair):
    env, raw = _seal(pair)
    protected, payload = _unseal(pair, raw)
    assert payload == {"body": "hello", "format": "plain"}
    assert protected["event_type"] == "message.created"
    assert protected["sender"] == pair["alice"]["identity_id"]
    assert protected["sender_seq"] == 1


def test_seal_unseal_from_dict(pair):
    env, _ = _seal(pair)
    protected, payload = _unseal(pair, env)
    assert payload["body"] == "hello"


def test_recipient_entries_sorted(pair):
    carol = make_agent("Carol", "PrincipalC")
    env, _ = make_sealed(
        pair["alice"], pair["bob"], pair["rid"], pair["conv"],
        "message.created", {"body": "hi", "format": "plain"}, seq=1,
    )
    recips = [e["recipient"] for e in env["recipients"]]
    assert recips == sorted(recips)


def _resign(pair, tampered: dict) -> bytes:
    """Re-sign a tampered envelope with the sender's key. Models an
    attacker who stole the sender's signing key but not the recipient's
    relationship key: the signature verifies, so the tamper must still
    fail closed in the crypto layer."""
    unsigned = {k: v for k, v in tampered.items() if k != "signature"}
    tampered["signature"] = b64url_encode(
        pair["alice"]["ed_priv"].sign(restricted_jcs(unsigned))
    )
    return restricted_jcs(tampered)


# -- tamper matrix: every tamper fails closed ------------------------------------
# The Ed25519 signature covers restricted_jcs(envelope minus signature),
# i.e. the header, all recipient wraps, and the body. Any unsigned tamper
# dies at the signature. A tamper paired with a fresh valid signature
# (compromised sender signing key) must still die in the crypto layer.


def test_tamper_header_fails_closed(pair):
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    tampered["protected"]["created_at"] = "2030-01-01T00:00:00Z"
    with pytest.raises(SealingError) as exc:
        _unseal(pair, restricted_jcs(tampered))
    assert exc.value.code == "bad_signature"


def test_tamper_header_add_field_fails_closed(pair):
    # Adding a field changes the signed bytes -> signature invalid.
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    tampered["protected"]["extra"] = "x"
    with pytest.raises(SealingError):
        _unseal(pair, restricted_jcs(tampered))


def test_tamper_wrap_invalidates_signature(pair):
    # Recipient wraps sit inside the signed envelope.
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    tampered["recipients"][0]["wrapped_key"] = _flip_b64url(
        tampered["recipients"][0]["wrapped_key"]
    )
    with pytest.raises(SealingError) as exc:
        _unseal(pair, restricted_jcs(tampered))
    assert exc.value.code == "bad_signature"


def test_tamper_wrap_with_valid_signature_fails_closed(pair):
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    tampered["recipients"][0]["wrapped_key"] = _flip_b64url(
        tampered["recipients"][0]["wrapped_key"]
    )
    with pytest.raises(SealingError) as exc:
        _unseal(pair, _resign(pair, tampered))
    assert exc.value.code == "tampered_wrap"


def test_tamper_body_invalidates_signature(pair):
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    tampered["ciphertext"] = _flip_b64url(tampered["ciphertext"])
    with pytest.raises(SealingError) as exc:
        _unseal(pair, restricted_jcs(tampered))
    assert exc.value.code == "bad_signature"


def test_tamper_body_with_valid_signature_fails_closed(pair):
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    tampered["ciphertext"] = _flip_b64url(tampered["ciphertext"])
    with pytest.raises(SealingError) as exc:
        _unseal(pair, _resign(pair, tampered))
    assert exc.value.code == "tampered_body"


def test_tamper_signature_fails_closed(pair):
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    tampered["signature"] = _flip_b64url(tampered["signature"])
    with pytest.raises(SealingError) as exc:
        _unseal(pair, restricted_jcs(tampered))
    assert exc.value.code == "bad_signature"


def test_tamper_content_nonce_with_valid_signature_fails_closed(pair):
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    tampered["content_nonce"] = _flip_b64url(tampered["content_nonce"])
    with pytest.raises(SealingError) as exc:
        _unseal(pair, _resign(pair, tampered))
    assert exc.value.code == "tampered_body"


# -- AAD / key confusion ----------------------------------------------------------


def test_wrong_aad_fails_closed(pair):
    """Unsealing with a relationship key that does not match the wrap's
    agreement key fails as wrong_aad, not as a generic decrypt error."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )

    env, raw = _seal(pair)
    other_priv = X25519PrivateKey.generate()
    with pytest.raises(SealingError) as exc:
        unseal_envelope(raw, other_priv, pair["bob"]["identity_id"])
    assert exc.value.code == "wrong_aad"


def test_wrong_recipient_fails_closed(pair):
    env, raw = _seal(pair)
    with pytest.raises(SealingError) as exc:
        unseal_envelope(
            raw, pair["bob"]["rel_priv"], "did:key:zNoSuchRecipient"
        )
    assert exc.value.code == "unknown_recipient"


def test_sender_key_mismatch_fails_closed(pair):
    from muse_agent_social.model.events import build_protected

    carol = make_agent("Carol", "PrincipalC")
    protected = build_protected(
        relationship_id=pair["rid"],
        conversation_id=pair["conv"],
        sender_id=pair["alice"]["identity_id"],
        event_type="message.created",
        thread_id=None,
        reply_to=None,
        key_epoch=1,
    )
    protected["sender_seq"] = 1
    with pytest.raises(SealingError) as exc:
        seal_envelope(
            protected,
            {"body": "hi", "format": "plain"},
            carol["ed_priv"],
            [
                {
                    "recipient": pair["bob"]["identity_id"],
                    "agreement_key": pair["bob"]["rel_pub_mb"],
                    "relationship_pub": pair["bob"]["rel_pub_raw"],
                }
            ],
        )
    assert exc.value.code == "sender_key_mismatch"


# -- malformed encodings ------------------------------------------------------------


def test_malformed_base64url_signature_fails_closed(pair):
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    tampered["signature"] = "!!!not-base64url!!!"
    with pytest.raises(SealingError) as exc:
        _unseal(pair, restricted_jcs(tampered))
    # Schema pattern rejects it before crypto; either stable code is a
    # closed failure.
    assert exc.value.code in ("bad_signature", "schema_invalid")


def test_nonce_length_error_fails_closed(pair):
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    short = b64url_encode(b"\x00" * 11)  # 11 bytes, not 12
    tampered["recipients"][0]["wrap_nonce"] = short
    with pytest.raises(SealingError) as exc:
        _unseal(pair, _resign(pair, tampered))
    assert exc.value.code == "tampered_wrap"


def test_content_nonce_length_error_fails_closed(pair):
    env, _ = _seal(pair)
    tampered = copy.deepcopy(env)
    tampered["content_nonce"] = b64url_encode(b"\x00" * 8)
    with pytest.raises(SealingError) as exc:
        _unseal(pair, _resign(pair, tampered))
    assert exc.value.code == "tampered_body"


# -- X25519 low-order peer keys ------------------------------------------------------


@pytest.mark.parametrize(
    "low_order",
    [
        bytes(32),  # identity point
        b"\x01" + bytes(31),  # u = 1
    ],
    ids=["identity", "u-equals-1"],
)
def test_x25519_low_order_input_rejected(pair, low_order):
    """Degenerate peer agreement keys are rejected, never used."""
    from muse_agent_social.model.events import build_protected

    protected = build_protected(
        relationship_id=pair["rid"],
        conversation_id=pair["conv"],
        sender_id=pair["alice"]["identity_id"],
        event_type="message.created",
        thread_id=None,
        reply_to=None,
        key_epoch=1,
    )
    protected["sender_seq"] = 1
    with pytest.raises(SealingError) as exc:
        seal_envelope(
            protected,
            {"body": "hi", "format": "plain"},
            pair["alice"]["ed_priv"],
            [
                {
                    "recipient": pair["bob"]["identity_id"],
                    "agreement_key": agreement_key_multibase_from_pubkey(
                        low_order
                    ),
                    "relationship_pub": low_order,
                }
            ],
        )
    assert exc.value.code == "low_order_key"


# -- size gates ------------------------------------------------------------------------


def test_payload_over_240kib_rejected(pair):
    big_body = "x" * (MAX_PAYLOAD_BYTES + 1)
    with pytest.raises(SealingError) as exc:
        make_sealed(
            pair["alice"], pair["bob"], pair["rid"], pair["conv"],
            "message.created", {"body": big_body, "format": "plain"}, seq=1,
        )
    assert exc.value.code == "payload_too_large"


def test_envelope_bytes_over_256kib_rejected_on_unseal(pair):
    env, raw = _seal(pair)
    assert len(raw) < MAX_ENVELOPE_BYTES
    oversized = raw + b" " * (MAX_ENVELOPE_BYTES - len(raw) + 1)
    with pytest.raises(SealingError) as exc:
        _unseal(pair, oversized)
    assert exc.value.code == "envelope_too_large"


def test_no_recipients_rejected(pair):
    from muse_agent_social.model.events import build_protected

    protected = build_protected(
        relationship_id=pair["rid"],
        conversation_id=pair["conv"],
        sender_id=pair["alice"]["identity_id"],
        event_type="message.created",
        thread_id=None,
        reply_to=None,
        key_epoch=1,
    )
    protected["sender_seq"] = 1
    with pytest.raises(SealingError) as exc:
        seal_envelope(
            protected, {"body": "hi", "format": "plain"},
            pair["alice"]["ed_priv"], [],
        )
    assert exc.value.code == "no_recipients"
