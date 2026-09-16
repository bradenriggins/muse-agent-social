"""Lane A C2: rotation commit updates the peer agreement key.

After the acking side commits a rotation, ``relationships.peer_agreement_key``
must become the peer's NEW agreement key. Otherwise ``_recipients_for`` keeps
wrapping CEKs to the old key while labeling the envelope with the new
``key_epoch``: if the peer rotated because epoch 1 was compromised, the
attacker keeps reading everything.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from muse_agent_social.canonical import restricted_jcs
from muse_agent_social.cli import _recipients_for
from muse_agent_social.crypto.rotation import RotationManager
from muse_agent_social.crypto.sealing import (
    SealingError,
    seal_envelope,
    unseal_envelope,
)
from muse_agent_social.model.events import build_protected
from muse_agent_social.model.invites import get_relationship

from support.harness import (
    fresh_db,
    make_agent,
    new_conversation,
    provision_receive_side,
)

UTC = timezone.utc


@pytest.fixture()
def two_sides(tmp_path):
    """Two independent stores, one per agent, with a shared relationship."""
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    rid = "77777777-8888-4999-aaaa-bbbbbbbbbbbb"
    conn_a = fresh_db(tmp_path / "alice.db")
    conn_b = fresh_db(tmp_path / "bob.db")
    keys_a = tmp_path / "keys_a"
    keys_b = tmp_path / "keys_b"
    provision_receive_side(conn_a, rid, alice, bob, keys_dir=str(keys_a))
    provision_receive_side(conn_b, rid, bob, alice, keys_dir=str(keys_b))
    t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
    return {
        "alice": alice, "bob": bob, "rid": rid,
        "conn_a": conn_a, "conn_b": conn_b,
        "keys_a": keys_a, "keys_b": keys_b, "t0": t0,
        "tmp_path": tmp_path,
    }


def _full_handshake(fx):
    """Bob rotates; Alice acks; both sides commit. Returns the prepare."""
    t0, rid = fx["t0"], fx["rid"]
    mgr_a = RotationManager(fx["conn_a"], str(fx["keys_a"]))
    mgr_b = RotationManager(fx["conn_b"], str(fx["keys_b"]))
    begun = mgr_b.begin_rotation(rid, now=t0)
    ack = mgr_a.on_prepare(rid, begun["prepare"], str(uuid.uuid4()), now=t0)
    mgr_b.on_ack(rid, ack, now=t0)
    mgr_b.note_decrypted_new_wrap(rid, 2, now=t0)
    confirm = mgr_b.confirm_rotation(rid, now=t0)
    mgr_a.on_confirm(rid, confirm, now=t0)
    commit = mgr_a.build_commit_payload(rid, now=t0)
    mgr_a.mark_committed(rid, now=t0)
    mgr_b.on_commit(rid, commit, now=t0)
    return begun


def _load_priv(keys_dir, rid, epoch):
    raw = open(Path(keys_dir) / f"{rid}-e{epoch}.key", "rb").read()
    return X25519PrivateKey.from_private_bytes(raw)


def test_commit_updates_peer_agreement_key_on_acking_side(two_sides):
    begun = _full_handshake(two_sides)
    new_pub = begun["prepare"]["new_agreement_key"]
    old_pub = two_sides["bob"]["rel_pub_mb"]
    assert new_pub != old_pub

    rel_a = get_relationship(two_sides["conn_a"], two_sides["rid"])
    assert int(rel_a["key_epoch"]) == 2
    assert rel_a["peer_agreement_key"] == new_pub

    # The rotating side's view of its peer did not change: Alice never rotated.
    rel_b = get_relationship(two_sides["conn_b"], two_sides["rid"])
    assert int(rel_b["key_epoch"]) == 2
    assert rel_b["peer_agreement_key"] == two_sides["alice"]["rel_pub_mb"]


def test_post_commit_send_wraps_to_new_key_only(two_sides):
    """After commit, a message from the acking side wraps its CEK to the
    peer's NEW key; the OLD (simulated-compromised) key cannot decrypt it."""
    begun = _full_handshake(two_sides)
    new_pub = begun["prepare"]["new_agreement_key"]
    alice, bob, rid = two_sides["alice"], two_sides["bob"], two_sides["rid"]

    ctx = SimpleNamespace(
        conn=two_sides["conn_a"], state_dir=two_sides["tmp_path"]
    )
    rel = get_relationship(two_sides["conn_a"], rid)
    mgr_a = RotationManager(two_sides["conn_a"], str(two_sides["keys_a"]))
    recipients, key_epoch = _recipients_for(
        ctx, rel, mgr_a, bob["identity_id"]
    )
    assert key_epoch == 2
    assert [r["agreement_key"] for r in recipients] == [new_pub]

    protected = build_protected(
        relationship_id=rid,
        conversation_id=str(uuid.uuid4()),
        sender_id=alice["identity_id"],
        event_type="message.created",
        thread_id=None,
        reply_to=None,
        key_epoch=key_epoch,
    )
    protected["sender_seq"] = 1
    envelope = seal_envelope(
        protected,
        {"body": "post-rotation secret", "format": "plain"},
        alice["ed_priv"],
        recipients,
    )
    raw = restricted_jcs(envelope)

    # The peer's new key decrypts.
    bob_e2_priv = _load_priv(two_sides["keys_b"], rid, 2)
    _, payload = unseal_envelope(raw, bob_e2_priv, bob["identity_id"])
    assert payload["body"] == "post-rotation secret"

    # The old key (simulating the compromised epoch-1 key) cannot.
    with pytest.raises(SealingError):
        unseal_envelope(raw, bob["rel_priv"], bob["identity_id"])
