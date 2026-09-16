"""V3 regression: the receive path must attribute events to the
authenticated envelope sender (protected["sender"]), not to the
relationship's current peer identity.

Before the fix, every event was stored and sequenced under peer_id. Two
harms: (1) an identity-rotated peer's delayed pre-rotation events looked
like sequence forks and were silently rejected; (2) after rotation, the
old key was accepted forever as the current peer with no grace window.
"""

import muse_agent_social.cli as cli_mod
from muse_agent_social.policy.delivery import set_accepted_receipts_enabled
from muse_agent_social.policy.limits import add_seconds
from muse_agent_social.store.db import utcnow
from support.harness import (
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)

RID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def _oname(tag: str) -> str:
    return (tag + "0" * 32)[:32] + ".json"


def _ctx(tmp_path, grace_seconds):
    from types import SimpleNamespace

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    carol = make_agent("Carol", "PrincipalC")  # the rotated-away identity
    conn = fresh_db(tmp_path / "state.db")
    provision_receive_side(conn, RID, bob, alice)
    conn.execute(
        "UPDATE relationships SET prior_peer_identity_id = ?,"
        " prior_identity_grace_until = ? WHERE relationship_id = ?",
        (
            carol["identity_id"],
            add_seconds(utcnow(), grace_seconds),
            RID,
        ),
    )
    conn.commit()
    set_accepted_receipts_enabled(conn, RID, False)
    cli_mod._ensure_cli_tables(conn)
    ctx = SimpleNamespace(
        conn=conn,
        state_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        identity_id=bob["identity_id"],
    )
    return ctx, conn, alice, bob, carol


def test_prior_identity_events_attributed_to_sender(tmp_path):
    """A delayed pre-rotation event inside the grace window is accepted
    and stored under the sender's own identity."""
    ctx, conn, alice, bob, carol = _ctx(tmp_path, grace_seconds=3600)
    conv = new_conversation(conn)
    _, raw = make_sealed(
        carol, bob, RID, conv,
        "message.created", {"body": "pre-rotation mail", "format": "plain"},
        seq=1,
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, RID, _oname("priok"), raw, acc)
    assert outcome["outcome"] == "accepted"
    row = conn.execute(
        "SELECT sender, sender_seq FROM events"
    ).fetchone()
    assert row["sender"] == carol["identity_id"]
    assert row["sender_seq"] == 1
    seq_rows = conn.execute(
        "SELECT sender, last_seq FROM sender_sequence"
    ).fetchall()
    assert {(r["sender"], r["last_seq"]) for r in seq_rows} == {
        (carol["identity_id"], 1)
    }


def test_no_false_fork_between_prior_and_current_identity(tmp_path):
    """The same sender_seq from the old identity and the current peer are
    distinct per-sender streams; neither is a sequence_fork."""
    ctx, conn, alice, bob, carol = _ctx(tmp_path, grace_seconds=3600)
    conv = new_conversation(conn)
    acc = {"surfaces": 0, "receipts_queued": 0}
    _, raw_carol = make_sealed(
        carol, bob, RID, conv,
        "message.created", {"body": "from carol", "format": "plain"}, seq=1,
    )
    _, raw_alice = make_sealed(
        alice, bob, RID, conv,
        "message.created", {"body": "from alice", "format": "plain"}, seq=1,
    )
    assert cli_mod._receive_object(
        ctx, RID, _oname("fork1"), raw_carol, acc)["outcome"] == "accepted"
    assert cli_mod._receive_object(
        ctx, RID, _oname("fork2"), raw_alice, acc)["outcome"] == "accepted"
    senders = {
        r["sender"]
        for r in conn.execute("SELECT sender FROM events").fetchall()
    }
    assert senders == {carol["identity_id"], alice["identity_id"]}


def test_prior_identity_rejected_after_grace(tmp_path):
    """Once the grace window lapses, the retired key is dead: the event
    is quarantined, not silently accepted as the current peer."""
    ctx, conn, alice, bob, carol = _ctx(tmp_path, grace_seconds=-10)
    conv = new_conversation(conn)
    _, raw = make_sealed(
        carol, bob, RID, conv,
        "message.created", {"body": "late mail", "format": "plain"}, seq=1,
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, RID, _oname("priexp"), raw, acc)
    assert outcome["outcome"] == "quarantined"
    reason = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()["reason"]
    assert reason == "prior_identity_expired"
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_unknown_sender_still_rejected(tmp_path):
    """An envelope from an identity that is neither the current peer nor
    the retired one is quarantined."""
    ctx, conn, alice, bob, carol = _ctx(tmp_path, grace_seconds=3600)
    dave = make_agent("Dave", "PrincipalD")
    conv = new_conversation(conn)
    _, raw = make_sealed(
        dave, bob, RID, conv,
        "message.created", {"body": "impostor", "format": "plain"}, seq=1,
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, RID, _oname("unkn"), raw, acc)
    assert outcome["outcome"] == "quarantined"
    reason = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()["reason"]
    assert reason == "unknown_sender"


def test_rotation_records_grace_timestamp(tmp_path):
    """Applying an identity.rotated announcement stamps the grace window
    the receive path reads."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from muse_agent_social.crypto.rotation import rotate_identity_key
    from muse_agent_social.model.invites import get_relationship

    ctx, conn, alice, bob, carol = _ctx(tmp_path, grace_seconds=3600)
    # alice (the pinned current peer identity) rotates to a fresh key.
    announcement = rotate_identity_key(
        alice["card"], alice["ed_priv"], Ed25519PrivateKey.generate()
    )
    new_id = announcement["new_card"]["identity_id"]
    applied = cli_mod._apply_identity_rotation(
        ctx, RID, announcement, alice["identity_id"]
    )
    assert applied is True
    rel = get_relationship(conn, RID)
    assert rel["peer_identity_id"] == new_id
    assert rel["prior_peer_identity_id"] == alice["identity_id"]
    assert rel["prior_identity_grace_until"] is not None
    # The retired identity is still acceptable inside the grace window.
    conv = new_conversation(conn)
    _, raw = make_sealed(
        alice, bob, RID, conv,
        "message.created", {"body": "just rotated", "format": "plain"},
        seq=1,
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    assert cli_mod._receive_object(
        ctx, RID, _oname("rotok"), raw, acc)["outcome"] == "accepted"
