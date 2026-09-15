"""Gate: post-rejection state assertions.

For each malformed input (bad signature, oversize, unknown event type,
schema violation), the receive path must quarantine with a stable code
and leave the durable tables untouched: events, replay_guard,
surface_queue, and receipt_queue counts must be identical before and
after. A final valid event must still be accepted afterwards (the
pipeline is not wedged by the rejections).
"""

import pytest

from muse_agent_social.canonical import restricted_jcs
from muse_agent_social.crypto.identity import b64url_encode
from muse_agent_social.transports.local import LocalTransport

from support.harness import (
    ReceiveHarness,
    deliver,
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)

TABLES = ("events", "replay_guard", "surface_queue", "receipt_queue")


@pytest.fixture()
def rig(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
    provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    harness = ReceiveHarness(
        conn,
        relationship_id=rid,
        own_identity_id=bob["identity_id"],
        own_rel_priv=bob["rel_priv"],
        transport=LocalTransport(tmp_path / "relay"),
    )
    return {"harness": harness, "alice": alice, "bob": bob, "rid": rid, "conv": conv}


def _snapshot(harness):
    return {table: harness.count(table) for table in TABLES}


def _resign(envelope: dict, signer) -> bytes:
    """Re-sign a tampered envelope dict and return canonical bytes."""
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    sig = signer.sign(restricted_jcs(unsigned))
    envelope["signature"] = b64url_encode(sig)
    return restricted_jcs(envelope)


def _oname(tag: str) -> str:
    return (tag + "0" * 32)[:32] + ".json"


def _check_rejection_keeps_state(rig, raw: bytes, name: str, code: str):
    harness = rig["harness"]
    before = _snapshot(harness)
    # Oversize objects never reach the transport; feed them straight to
    # the receive path, like the size-boundary gate does.
    if len(raw) > 262144:
        outcome = harness.receive_object(name, raw)
    else:
        outcome = deliver(harness, raw, name)
    assert outcome["outcome"] == "quarantined"
    assert outcome["code"] == code
    assert _snapshot(harness) == before


def test_bad_signature_leaves_state_untouched(rig):
    envelope, _ = make_sealed(
        rig["alice"], rig["bob"], rig["rid"], rig["conv"],
        "message.created", {"body": "tamper me", "format": "plain"}, seq=1,
    )
    sig = envelope["signature"]
    # Flip a character in the middle of the signature: the last base64
    # character's low bits are ignored by decoding (64-byte signatures
    # encode to 86 chars with 4 unused bits), so a trailing flip can be
    # a silent no-op.
    flip_at = 10
    flipped = "A" if sig[flip_at] != "A" else "B"
    envelope["signature"] = sig[:flip_at] + flipped + sig[flip_at + 1 :]
    raw = restricted_jcs(envelope)
    _check_rejection_keeps_state(rig, raw, _oname("badsig"), "bad_signature")


def test_oversize_leaves_state_untouched(rig):
    raw = b"Z" * (262144 + 1)
    _check_rejection_keeps_state(rig, raw, _oname("oversize"), "envelope_too_large")


def test_unknown_event_type_leaves_state_untouched(rig):
    envelope, _ = make_sealed(
        rig["alice"], rig["bob"], rig["rid"], rig["conv"],
        "message.created", {"body": "bad type", "format": "plain"}, seq=1,
    )
    envelope["protected"]["event_type"] = "bogus.unknown"
    raw = _resign(envelope, rig["alice"]["ed_priv"])
    _check_rejection_keeps_state(rig, raw, _oname("badtype"), "enum")


def test_schema_violation_leaves_state_untouched(rig):
    envelope, _ = make_sealed(
        rig["alice"], rig["bob"], rig["rid"], rig["conv"],
        "message.created", {"body": "bad schema", "format": "plain"}, seq=1,
    )
    del envelope["recipients"]
    raw = _resign(envelope, rig["alice"]["ed_priv"])
    _check_rejection_keeps_state(rig, raw, _oname("badschema"), "required")


def test_pipeline_still_accepts_after_rejections(rig):
    harness = rig["harness"]
    _, raw = make_sealed(
        rig["alice"], rig["bob"], rig["rid"], rig["conv"],
        "message.created", {"body": "still alive", "format": "plain"}, seq=9,
    )
    outcome = deliver(harness, raw, _oname("afterall"))
    assert outcome["outcome"] == "accepted"
    assert harness.count("events") == 1
    assert harness.count("receipt_queue") == 1
