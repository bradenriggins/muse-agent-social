"""V4 regression: outbound events persisted by the receive path (the
accepted receipts) must stage their projection payloads atomically.

Before the fix, _queue_accepted_receipt persisted via persist_outgoing_in_txn
and then staged the projection input in a separate non-atomic step that was
skipped for the receipt path entirely: receipt.accepted events had no
event_payloads row, so rebuild_projections raised payload_missing on any
database that had ever received a message with accepted receipts on.
"""

import muse_agent_social.cli as cli_mod
from muse_agent_social.policy.delivery import set_accepted_receipts_enabled
from muse_agent_social.store.projections import rebuild_projections
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


def _ctx(tmp_path):
    from types import SimpleNamespace

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    provision_receive_side(conn, RID, bob, alice)
    # Receipts ON: receiving a message generates receipt.accepted events.
    set_accepted_receipts_enabled(conn, RID, True)
    cli_mod._ensure_cli_tables(conn)
    ctx = SimpleNamespace(
        conn=conn,
        state_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        identity_id=bob["identity_id"],
        # _queue_accepted_receipt seals with the local identity key.
        hierarchy=SimpleNamespace(ed25519_private=bob["ed_priv"]),
    )
    return ctx, conn, alice, bob


def test_accepted_receipt_stages_projection_payload(tmp_path):
    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    _, raw = make_sealed(
        alice, bob, RID, conv,
        "message.created", {"body": "ack me", "format": "plain"}, seq=1,
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, RID, _oname("rcpt"), raw, acc)
    assert outcome["outcome"] == "accepted"
    assert acc["receipts_queued"] >= 1
    receipts = conn.execute(
        "SELECT event_id FROM events WHERE event_type = 'receipt.accepted'"
    ).fetchall()
    assert len(receipts) >= 1
    # Every persisted event, including the receipts, has a staged payload.
    missing = conn.execute(
        "SELECT e.event_id FROM events e LEFT JOIN event_payloads p"
        " ON e.event_id = p.event_id WHERE p.event_id IS NULL"
    ).fetchall()
    assert missing == []


def test_rebuild_projections_succeeds_after_receipts(tmp_path):
    """The original V4 symptom: rebuild_projections used to raise
    payload_missing for receipt.accepted events."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    acc = {"surfaces": 0, "receipts_queued": 0}
    for i in range(3):
        _, raw = make_sealed(
            alice, bob, RID, conv,
            "message.created", {"body": f"msg {i}", "format": "plain"},
            seq=i + 1,
        )
        outcome = cli_mod._receive_object(
            ctx, RID, _oname(f"rb{i}"), raw, acc
        )
        assert outcome["outcome"] == "accepted"
    rebuild_projections(conn, RID)  # raises payload_missing before the fix
    # And a second rebuild stays clean (idempotent staging).
    rebuild_projections(conn, RID)
    events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    payloads = conn.execute("SELECT COUNT(*) FROM event_payloads").fetchone()[0]
    assert events > 0
    assert payloads == events


def test_persist_outgoing_in_txn_is_self_contained(tmp_path):
    """persist_outgoing_in_txn alone (no CLI staging wrapper) produces a
    rebuildable event."""
    from types import SimpleNamespace

    from muse_agent_social.model.events import (
        build_protected,
        persist_outgoing_in_txn,
    )

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    provision_receive_side(conn, RID, bob, alice)
    protected = build_protected(
        relationship_id=RID,
        conversation_id=new_conversation(conn),
        sender_id=bob["identity_id"],
        event_type="message.created",
        thread_id=None,
        reply_to=None,
        key_epoch=1,
        created_at="2026-09-16T12:00:00Z",
    )
    payload = {"body": "direct", "format": "plain"}
    conn.execute("BEGIN IMMEDIATE")
    try:
        # persist_outgoing_in_txn seals and updates protected in place,
        # returning the sealed envelope; everything commits together.
        persist_outgoing_in_txn(
            conn,
            protected,
            payload,
            bob["ed_priv"],
            [
                {
                    "recipient": alice["identity_id"],
                    "agreement_key": alice["rel_pub_mb"],
                    "relationship_pub": alice["rel_pub_raw"],
                }
            ],
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    payload_row = conn.execute(
        "SELECT event_type FROM event_payloads WHERE event_id = ?",
        (protected["event_id"],),
    ).fetchone()
    assert payload_row is not None
    assert payload_row["event_type"] == "message.created"
    rebuild_projections(conn, RID)
