"""Gate: exact 256 KiB envelope size boundary through the real receive path.

MAX_ENVELOPE_BYTES is 262144 and the receive size check is
``len(data) > MAX_ENVELOPE_BYTES``, so exactly 262144 bytes must be
ACCEPTED and 262145 bytes must be REJECTED with the stable code
``envelope_too_large``.

Two test-only accommodations (the receive-side gate itself is never
touched):

1. The sender-side ``seal_envelope`` additionally caps the plaintext
   payload at 240 KiB and the sealed envelope at 262144 bytes, so no
   legitimate sender can produce a 262144-byte envelope through the
   public API. The tests lift only those sender-side caps
   (monkeypatching the ``sealing`` module's own bindings, which
   ``seal_envelope`` reads as module globals) to mint
   cryptographically valid envelopes at the exact boundary. The
   receive-side ``validation.MAX_ENVELOPE_BYTES`` gate is what is under
   test.
2. The sealed envelope's fixed framing lands on a fixed residue mod 4
   (the ciphertext is base64, so only the framing decides it), which
   may not be 0. The tuner below measures the residue with a probe and
   picks a ``sender_seq`` whose decimal width shifts the framing to
   residue 0, making exactly 262144 reachable. ``sender_seq`` is an
   opaque per-sender counter; the receive path accepts any value.
"""

import pytest

from muse_agent_social.crypto import sealing
from muse_agent_social.transports.base import TransportError
from muse_agent_social.transports.local import LocalTransport
from muse_agent_social.validation import MAX_ENVELOPE_BYTES

from support.harness import (
    ReceiveHarness,
    deliver,
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)


@pytest.fixture()
def rig(tmp_path, monkeypatch):
    # Lift only the sender-side caps so the exact-boundary envelopes can
    # be minted. ``seal_envelope`` reads these as module globals on the
    # ``sealing`` module; the receive-side size gate lives on the
    # ``validation`` module and is untouched.
    monkeypatch.setattr(sealing, "MAX_PAYLOAD_BYTES", 600 * 1024)
    monkeypatch.setattr(sealing, "MAX_ENVELOPE_BYTES", 600 * 1024)
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
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


def _build(rig, seq: int, body: str) -> bytes:
    _, raw = make_sealed(
        rig["alice"], rig["bob"], rig["rid"], rig["conv"],
        "message.created", {"body": body, "format": "plain"}, seq=seq,
    )
    return raw


def _sealed_of_exact_size(rig, size: int) -> bytes:
    """Mint a valid sealed envelope of exactly *size* canonical bytes."""
    # The ciphertext is base64, so envelope sizes for one envelope shape
    # always share the framing's residue mod 4. Measure it, then pick a
    # sender_seq whose decimal width shifts the residue to size % 4.
    probe = _build(rig, 1, "")
    residue = len(probe) % 4  # b64 part is 0 mod 4, so this is the framing
    # seq=1 renders as one digit; seq=10**(d-1) renders as d digits, so the
    # framing grows by (d-1) chars. Pick d with
    # (residue + d - 1) % 4 == size % 4.
    digits_needed = (size - residue + 1) % 4 or 4
    seq = 10 ** (digits_needed - 1)
    base = len(_build(rig, seq, ""))
    assert base % 4 == size % 4, "residue alignment failed"
    # Envelope grows ~4 bytes per 3 body bytes (base64), monotonically in
    # steps of 0 or 4, so walking up from just below the estimate must
    # land exactly on target.
    pad = max(0, int((size - base) * 3 / 4) - 16)
    while True:
        raw = _build(rig, seq, "A" * pad)
        if len(raw) == size:
            return raw
        assert len(raw) < size, f"tuner overshot: {len(raw)} > {size}"
        pad += 1
        assert pad < 400000, "tuner failed to converge"


def test_exact_256kib_envelope_accepted(rig):
    assert MAX_ENVELOPE_BYTES == 262144
    raw = _sealed_of_exact_size(rig, 262144)
    outcome = deliver(rig["harness"], raw, "exact256k" + "0" * 23 + ".json")
    assert outcome["outcome"] == "accepted"
    assert rig["harness"].count("events") == 1


def test_256kib_plus_one_envelope_rejected(rig):
    # One byte over the boundary: the size gate fires before any parsing
    # or storage, so the object need only be the right length.
    raw = _sealed_of_exact_size(rig, 262144) + b"X"
    assert len(raw) == 262145
    name = "over256k" + "0" * 24 + ".json"
    harness = rig["harness"]
    # Layer 1: the transport refuses to upload an oversize object.
    with pytest.raises(TransportError) as exc:
        harness.transport.upload(name, raw)
    assert exc.value.code == "object_too_large"
    # Layer 2: the receive path itself rejects it with the stable code,
    # without touching the database. (Called directly because the
    # transport would not have accepted the upload.)
    outcome = harness.receive_object(name, raw)
    assert outcome["outcome"] == "quarantined"
    assert outcome["code"] == "envelope_too_large"
    assert harness.count("events") == 0
    assert harness.count("replay_guard") == 0
    assert harness.count("surface_queue") == 0
    assert harness.count("receipt_queue") == 0
