"""End-to-end: identity.rotated propagates a peer identity change over the relay.

Alice rotates her identity signing key. Bob receives the identity.rotated
event, verifies both cross-signatures against the pinned peer identity,
updates the stored peer identity (keeping the old id as
prior_peer_identity_id), and then accepts a message.created sealed under
Alice's new identity. A forged rotation announcement is quarantined and
leaves the stored identity untouched. Redelivery of the rotation event is
idempotent.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import muse_agent_social.cli as cli_mod
from muse_agent_social.crypto.identity import identity_id_from_pubkey
from muse_agent_social.crypto.rotation import rotate_identity_key
from muse_agent_social.model.cards import create_card
from muse_agent_social.model.invites import get_relationship
from muse_agent_social.policy.delivery import (
    set_accepted_receipts_enabled,
    set_policy,
)
from support.harness import (
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


@pytest.fixture()
def pair(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "bob.db")
    rid = "aaaaaaaa-bbbb-4ccc-8ddd-000000000001"
    keys_dir = tmp_path / "keys"
    provision_receive_side(conn, rid, bob, alice, keys_dir=str(keys_dir))
    set_accepted_receipts_enabled(conn, rid, False)
    set_policy(conn, rid, "alert")
    cli_mod._ensure_cli_tables(conn)
    conv = new_conversation(conn)
    return {
        "alice": alice,
        "bob": bob,
        "conn": conn,
        "rid": rid,
        "conv": conv,
        "state_dir": tmp_path,
        "keys_dir": keys_dir,
    }


def _ctx(pair):
    return SimpleNamespace(
        conn=pair["conn"],
        state_dir=pair["state_dir"],
        keys_dir=pair["keys_dir"],
        identity_id=pair["bob"]["identity_id"],
    )


def _receive(pair, raw, tag="obj"):
    acc = {"surfaces": 0, "receipts_queued": 0}
    name = f"{tag}-{'a' * 24}.json"
    try:
        outcome = cli_mod._receive_object_inner(
            _ctx(pair), pair["rid"], name, raw, acc
        )
    except cli_mod.CliError as exc:
        outcome = cli_mod._quarantine_outcome(
            _ctx(pair), pair["rid"], name, exc.code, str(exc)
        )
    return outcome, acc


def _rotate_alice(alice):
    """Build a real rotation announcement for alice with the shipped crypto."""
    new_priv = Ed25519PrivateKey.generate()
    new_id = identity_id_from_pubkey(new_priv.public_key().public_bytes_raw())
    now = datetime.now(timezone.utc)
    new_card = create_card(
        new_priv,
        "Alice",
        "PrincipalA",
        alice["card"]["bootstrap_agreement_key"],
        ["events/0.2", "threads/1", "receipts/1"],
        now,
        now + timedelta(days=365),
    )
    announcement = rotate_identity_key(alice["card"], alice["ed_priv"], new_priv)
    assert announcement["new_card"]["identity_id"] == new_id
    rotated_alice = dict(alice)
    rotated_alice["ed_priv"] = new_priv
    rotated_alice["identity_id"] = new_id
    rotated_alice["card"] = new_card
    return announcement, rotated_alice, new_id


def test_identity_rotation_end_to_end(pair):
    alice, bob = pair["alice"], pair["bob"]
    old_id = alice["identity_id"]
    announcement, new_alice, new_id = _rotate_alice(alice)

    # 1. Alice (old identity) sends identity.rotated; bob accepts it.
    _, raw = make_sealed(
        alice, bob, pair["rid"], pair["conv"],
        "identity.rotated", announcement, seq=1,
    )
    outcome, _ = _receive(pair, raw, tag="rot")
    assert outcome["outcome"] == "accepted", outcome

    # 2. Bob's stored peer identity moved to the new id; the old id is
    # kept as prior so delayed pre-rotation events stay attributable.
    rel = get_relationship(pair["conn"], pair["rid"])
    assert rel["peer_identity_id"] == new_id
    assert rel["prior_peer_identity_id"] == old_id
    assert rel["peer_display_name"] == "Alice"

    # 3. Alice's new identity sends a message; bob accepts and projects it.
    _, raw_msg = make_sealed(
        new_alice, bob, pair["rid"], pair["conv"],
        "message.created", {"body": "hello from the new key", "format": "plain"},
        seq=1,
    )
    outcome, acc = _receive(pair, raw_msg, tag="msg")
    assert outcome["outcome"] == "accepted", outcome
    assert acc["surfaces"] == 1
    assert pair["conn"].execute(
        "SELECT COUNT(*) FROM messages").fetchone()[0] == 1

    # 4. A forged rotation announcement (tampered cross-signature) is
    # quarantined and leaves the stored identity untouched.
    forged = deepcopy(announcement)
    sig0 = forged["cross_signatures"][0]["signature"]
    forged["cross_signatures"][0]["signature"] = (
        ("A" if sig0[0] != "A" else "B") + sig0[1:]
    )
    _, raw_forged = make_sealed(
        alice, bob, pair["rid"], pair["conv"],
        "identity.rotated", forged, seq=2,
    )
    outcome, _ = _receive(pair, raw_forged, tag="forged")
    assert outcome["outcome"] == "quarantined", outcome
    rel = get_relationship(pair["conn"], pair["rid"])
    assert rel["peer_identity_id"] == new_id
    assert rel["prior_peer_identity_id"] == old_id
    quar = pair["conn"].execute(
        "SELECT reason FROM receive_quarantine WHERE object_name LIKE 'forged%'"
    ).fetchone()
    assert quar is not None and quar["reason"] == "identity_rotation_rejected"

    # 5. Redelivery of the original rotation announcement is accepted
    # and idempotent: the identity does not move again.
    outcome, _ = _receive(pair, raw, tag="rot")
    assert outcome["outcome"] == "accepted", outcome
    rel = get_relationship(pair["conn"], pair["rid"])
    assert rel["peer_identity_id"] == new_id
    assert rel["prior_peer_identity_id"] == old_id


def test_rotation_announcement_from_unknown_old_identity_rejected(pair):
    """An identity.rotated whose old key id is not the pinned peer (nor the
    prior) fails the sender check before any crypto runs."""
    alice, bob = pair["alice"], pair["bob"]
    announcement, _, _ = _rotate_alice(alice)
    mallory = make_agent("Mallory", "PrincipalM")
    _, raw = make_sealed(
        mallory, bob, pair["rid"], pair["conv"],
        "identity.rotated", announcement, seq=1,
    )
    # Seal as mallory but claim alice's old identity as sender: seal_envelope
    # enforces identity_priv matches protected.sender, so instead we deliver
    # mallory's own sealed event and expect unknown_sender.
    outcome, _ = _receive(pair, raw, tag="mallory")
    assert outcome["outcome"] == "quarantined", outcome
    rel = get_relationship(pair["conn"], pair["rid"])
    assert rel["peer_identity_id"] == alice["identity_id"]
