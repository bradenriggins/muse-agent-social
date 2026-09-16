"""V1 regression: a hostile sender_seq must not trigger an unbounded
gap-fill loop.

One valid signed envelope with sender_seq near the schema max used to make
_update_seq_state insert ~9e15 sequence_gaps rows inside one transaction
(disk exhaustion, then a permanently wedged receive). The receive path now
quarantines jumps past last_seq + MAX_SEQ_GAP before committing, and the
projection layer caps recorded gap rows at the same constant while still
advancing the cursor.
"""

import muse_agent_social.cli as cli_mod
from muse_agent_social.policy.limits import MAX_SEQ_GAP
from muse_agent_social.policy.delivery import set_accepted_receipts_enabled
from muse_agent_social.store.db import transaction, utcnow
from muse_agent_social.store.projections import _update_seq_state
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
    set_accepted_receipts_enabled(conn, RID, False)
    cli_mod._ensure_cli_tables(conn)
    ctx = SimpleNamespace(
        conn=conn,
        state_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        identity_id=bob["identity_id"],
    )
    return ctx, conn, alice, bob


def test_update_seq_state_caps_gap_rows_but_advances_cursor(tmp_path):
    conn = fresh_db(tmp_path / "state.db")
    now = utcnow()
    with transaction(conn):
        _update_seq_state(conn, RID, "sender-x", 3 * MAX_SEQ_GAP, now)
    rows = conn.execute("SELECT COUNT(*) FROM sequence_gaps").fetchone()[0]
    assert rows == MAX_SEQ_GAP
    cursor = conn.execute(
        "SELECT max_seq FROM projection_cursors"
        " WHERE relationship_id = ? AND sender = ?",
        (RID, "sender-x"),
    ).fetchone()
    assert int(cursor["max_seq"]) == 3 * MAX_SEQ_GAP
    # A later event never re-inserts rows for the skipped range.
    with transaction(conn):
        _update_seq_state(conn, RID, "sender-x", 3 * MAX_SEQ_GAP + 10, now)
    rows = conn.execute("SELECT COUNT(*) FROM sequence_gaps").fetchone()[0]
    assert rows == MAX_SEQ_GAP + 9


def test_hostile_sender_seq_is_quarantined_before_commit(tmp_path):
    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    _, raw = make_sealed(
        alice, bob, RID, conv,
        "message.created", {"body": "boom", "format": "plain"},
        seq=9007199254740991,  # schema max: the attack value
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, RID, _oname("gapattack"), raw, acc)
    assert outcome["outcome"] == "quarantined"
    reason = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()["reason"]
    assert reason == "seq_gap_too_large"
    # Nothing was committed: no event, no gap rows, no burned sequence.
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM sequence_gaps").fetchone()[0] == 0
    assert (
        conn.execute("SELECT COUNT(*) FROM sender_sequence").fetchone()[0] == 0
    )


def test_moderate_jump_is_accepted_and_records_gaps(tmp_path):
    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    _, raw = make_sealed(
        alice, bob, RID, conv,
        "message.created", {"body": "jump", "format": "plain"},
        seq=MAX_SEQ_GAP - 5,
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, RID, _oname("gapok"), raw, acc)
    assert outcome["outcome"] == "accepted"
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    # The incremental projection recorded the (bounded) gap range.
    gaps = conn.execute("SELECT COUNT(*) FROM sequence_gaps").fetchone()[0]
    assert gaps == MAX_SEQ_GAP - 6


def test_rebuild_projections_survives_hostile_logged_seq(tmp_path):
    """Even if a huge-seq event is already in the log (e.g. written before
    the bound existed), rebuild_projections stays bounded."""
    import uuid

    from muse_agent_social.store.projections import (
        rebuild_projections,
        record_projection_input,
    )

    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    thread_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO threads(thread_id, conversation_id) VALUES (?, ?)",
        (thread_id, conv),
    )
    event_id = str(uuid.uuid4())
    with transaction(conn):
        conn.execute(
            "INSERT INTO events(event_id, relationship_id, conversation_id,"
            " thread_id, sender, sender_seq, created_at, key_epoch, event_type,"
            " replay_nonce, sealed_envelope)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'message.created', ?, ?)",
            (
                event_id, RID, conv, thread_id, alice["identity_id"],
                9007199254740990, utcnow(), "nonce-hostile", b"{}",
            ),
        )
        record_projection_input(
            conn,
            event_id=event_id,
            event_type="message.created",
            payload={"body": "prebound", "format": "plain"},
            reply_to=None,
        )
    rebuild_projections(conn, RID)
    gaps = conn.execute("SELECT COUNT(*) FROM sequence_gaps").fetchone()[0]
    assert gaps <= MAX_SEQ_GAP
    gaps = conn.execute("SELECT COUNT(*) FROM sequence_gaps").fetchone()[0]
    assert gaps <= MAX_SEQ_GAP
