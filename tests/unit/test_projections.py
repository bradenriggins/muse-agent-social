"""Unit tests for muse_agent_social.store.projections.

The module under test is loaded from the track source tree by file path, so
these tests run with PYTHONPATH including both ~/workspace/mas-release/src
and the track src dir.
"""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

TRACK_SRC = Path(__file__).resolve().parents[2] / "src"
MAS_SRC = Path.home() / "workspace" / "mas-release" / "src"
for p in (str(MAS_SRC), str(TRACK_SRC)):
    if p not in sys.path:
        sys.path.insert(0, p)

_spec = importlib.util.spec_from_file_location(
    "mas_projections",
    TRACK_SRC / "muse_agent_social" / "store" / "projections.py",
)
projections = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(projections)

from muse_agent_social.canonical import restricted_jcs  # noqa: E402
from muse_agent_social.store.db import utcnow  # noqa: E402
from muse_agent_social.store.migrations import migrate  # noqa: E402

SENDER_A = "did:key:zSenderA111"
SENDER_B = "did:key:zSenderB222"
REL = "rel-test-1"
CONV = "conv-test-1"


def ts(base: datetime, seconds: int) -> str:
    return (base + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture()
def conn():
    c = sqlite3.connect(":memory:", isolation_level=None)
    c.row_factory = sqlite3.Row
    migrate(c)
    projections.migrate_projections(c)
    c.execute(
        "INSERT INTO relationships(relationship_id, peer_identity_id,"
        " consent_state, policy, key_epoch, created_at)"
        " VALUES (?, ?, 'active', '{}', 1, ?);",
        (REL, "did:key:zPeer999", utcnow()),
    )
    c.execute("INSERT INTO conversations(conversation_id) VALUES (?);", (CONV,))
    c.execute(
        "INSERT INTO key_epochs(relationship_id, epoch, public_key,"
        " private_key_ref, state) VALUES (?, 1, 'pk', 'ref', 'active');",
        (REL,),
    )
    yield c
    c.close()


class EventLog:
    """Builds staged events and hands rows to apply_event / rebuild."""

    def __init__(self, conn, base):
        self.conn = conn
        self.base = base
        self.seq = {}

    def add(
        self,
        event_type,
        payload,
        sender=SENDER_A,
        at=0,
        thread_id=None,
        reply_to=None,
        conversation_id=CONV,
        event_id=None,
    ):
        self.seq[sender] = self.seq.get(sender, 0) + 1
        event_id = event_id or str(uuid.uuid4())
        created = ts(self.base, at)
        self.conn.execute(
            "INSERT INTO events(event_id, relationship_id, conversation_id,"
            " thread_id, sender, sender_seq, created_at, key_epoch, event_type,"
            " replay_nonce, sealed_envelope)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?);",
            (
                event_id,
                REL,
                conversation_id,
                thread_id,
                sender,
                self.seq[sender],
                created,
                event_type,
                str(uuid.uuid4()),
                b"sealed",
            ),
        )
        projections.record_projection_input(
            self.conn,
            event_id=event_id,
            event_type=event_type,
            payload=payload,
            reply_to=reply_to,
        )
        return {
            "event_id": event_id,
            "relationship_id": REL,
            "conversation_id": conversation_id,
            "thread_id": thread_id,
            "sender": sender,
            "sender_seq": self.seq[sender],
            "created_at": created,
            "key_epoch": 1,
            "event_type": event_type,
            "payload": payload,
            "reply_to": reply_to,
        }

    def apply(self, row):
        return projections.apply_event(self.conn, row)

    def rebuild(self):
        projections.rebuild_projections(self.conn, REL)


@pytest.fixture()
def log(conn):
    base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=30)
    return EventLog(conn, base)


def msg_body(fmt="plain"):
    return {"body": "hello world", "format": fmt}


# ---------------------------------------------------------------------------
# Basic message projection
# ---------------------------------------------------------------------------


def test_message_created_projects_visible(conn, log):
    row = log.add("message.created", msg_body())
    mutations = log.apply(row)
    assert any(m["op"] == "insert" and m["table"] == "messages" for m in mutations)
    views = projections.get_conversation(conn, REL, CONV)
    assert len(views) == 1
    view = views[0]
    assert view["body"] == "hello world"
    assert view["format"] == "plain"
    assert view["edited"] is False
    assert view["retracted"] is False
    assert view["retraction"] is None
    assert view["reactions"] == []
    assert view["receipts"] == []


def test_apply_is_idempotent(conn, log):
    row = log.add("message.created", msg_body())
    first = log.apply(row)
    second = log.apply(row)
    assert any(m["op"] == "insert" for m in first)
    assert all(m["op"] == "noop" for m in second)
    assert len(projections.get_conversation(conn, REL, CONV)) == 1


# ---------------------------------------------------------------------------
# Out-of-order reply / edit / retract / reaction
# ---------------------------------------------------------------------------


def test_out_of_order_reply_edit_reaction(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    # Inserted before the edit, but stamped later: deterministic order must
    # still apply the edit before the reaction.
    r1 = log.add(
        "reaction.added",
        {"target_event_id": m1["event_id"], "emoji": "👍"},
        sender=SENDER_B,
        at=20,
    )
    e1 = log.add(
        "message.edited",
        {"target_event_id": m1["event_id"], "body": "hello edited"},
        at=10,
    )
    # Reply arrives before its target is projected (inserted first here).
    m2 = log.add(
        "message.created",
        {"body": "reply here", "format": "plain"},
        sender=SENDER_B,
        at=5,
        reply_to=m1["event_id"],
    )
    # Incremental apply in scrambled arrival order.
    log.apply(r1)
    log.apply(m2)
    log.apply(e1)
    log.apply(m1)
    views = projections.get_conversation(conn, REL, CONV)
    assert [v["event_id"] for v in views] == [m1["event_id"], m2["event_id"]]
    first = views[0]
    assert first["body"] == "hello edited"
    assert first["edited"] is True
    assert first["revision_count"] == 2
    assert first["reactions"] == [
        {"emoji": "👍", "count": 1, "senders": [SENDER_B]}
    ]
    assert views[1]["reply_to"] == m1["event_id"]
    assert views[1]["reply_state"] == "ok"
    # No dangling pending refs.
    pending = conn.execute(
        "SELECT COUNT(*) AS c FROM pending_refs WHERE state = 'pending';"
    ).fetchone()["c"]
    assert pending == 0


def test_rebuild_matches_incremental(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    e1 = log.add(
        "message.edited",
        {"target_event_id": m1["event_id"], "body": "v2", "reason": "typo"},
        at=10,
    )
    r1 = log.add(
        "reaction.added",
        {"target_event_id": m1["event_id"], "emoji": "🎉"},
        sender=SENDER_B,
        at=20,
    )
    for row in (m1, e1, r1):
        log.apply(row)
    before = restricted_jcs(projections.get_conversation(conn, REL, CONV))
    log.rebuild()
    after = restricted_jcs(projections.get_conversation(conn, REL, CONV))
    assert before == after


# ---------------------------------------------------------------------------
# Edits: sender-only, history, no edit after retract
# ---------------------------------------------------------------------------


def test_edit_by_non_sender_rejected(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    log.apply(m1)
    evil = log.add(
        "message.edited",
        {"target_event_id": m1["event_id"], "body": "forged"},
        sender=SENDER_B,
        at=10,
    )
    with pytest.raises(projections.ProjectionError) as excinfo:
        log.apply(evil)
    assert excinfo.value.code == "edit_not_sender"
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["body"] == "hello world"
    assert view["edited"] is False


def test_edit_by_non_sender_quarantined_on_rebuild(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    log.add(
        "message.edited",
        {"target_event_id": m1["event_id"], "body": "forged"},
        sender=SENDER_B,
        at=10,
    )
    log.rebuild()
    row = conn.execute(
        "SELECT reason FROM quarantine WHERE relationship_id = ?;", (REL,)
    ).fetchone()
    assert row is not None and row["reason"] == "edit_not_sender"
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["body"] == "hello world"


def test_edit_appends_revision_and_keeps_history(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    log.apply(m1)
    for i, body in enumerate(("second", "third"), start=10):
        log.apply(
            log.add(
                "message.edited",
                {"target_event_id": m1["event_id"], "body": body},
                at=i,
            )
        )
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["body"] == "third"
    assert view["edited"] is True
    assert view["revision_count"] == 3
    revisions = conn.execute(
        "SELECT revision_no, body, edit_event_id FROM message_revisions"
        " WHERE event_id = ? ORDER BY revision_no;",
        (m1["event_id"],),
    ).fetchall()
    assert [r["body"] for r in revisions] == ["hello world", "second", "third"]
    assert revisions[0]["edit_event_id"] is None
    assert revisions[1]["edit_event_id"] is not None


def test_edit_after_retract_rejected(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    log.apply(m1)
    log.apply(
        log.add(
            "message.retracted",
            {"target_event_id": m1["event_id"]},
            at=10,
        )
    )
    late_edit = log.add(
        "message.edited",
        {"target_event_id": m1["event_id"], "body": "too late"},
        at=20,
    )
    with pytest.raises(projections.ProjectionError) as excinfo:
        log.apply(late_edit)
    assert excinfo.value.code == "edit_after_retract"


def test_retract_by_non_sender_rejected(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    log.apply(m1)
    evil = log.add(
        "message.retracted",
        {"target_event_id": m1["event_id"]},
        sender=SENDER_B,
        at=10,
    )
    with pytest.raises(projections.ProjectionError) as excinfo:
        log.apply(evil)
    assert excinfo.value.code == "retract_not_sender"


# ---------------------------------------------------------------------------
# Retraction: hidden body, surviving tombstone
# ---------------------------------------------------------------------------


def test_retraction_hides_body_keeps_tombstone(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    log.apply(m1)
    ret = log.add(
        "message.retracted",
        {"target_event_id": m1["event_id"], "reason": "oops"},
        at=10,
    )
    mutations = log.apply(ret)
    assert any(m["op"] == "update" and m["table"] == "messages" for m in mutations)
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["body"] is None
    assert view["retracted"] is True
    assert view["retraction"] == {
        "event_id": ret["event_id"],
        "retracted_at": ret["created_at"],
        "reason": "oops",
    }
    # History survives the retraction.
    assert view["revision_count"] == 1
    row = conn.execute(
        "SELECT current_body FROM messages WHERE event_id = ?;", (m1["event_id"],)
    ).fetchone()
    assert row["current_body"] == "hello world"


# ---------------------------------------------------------------------------
# Reactions: one active per (sender, target, emoji); remove deactivates
# ---------------------------------------------------------------------------


def test_reaction_add_remove_semantics(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    log.apply(m1)
    add = log.add(
        "reaction.added",
        {"target_event_id": m1["event_id"], "emoji": "👍"},
        sender=SENDER_B,
        at=10,
    )
    log.apply(add)
    # Duplicate add is idempotent: still one active reaction.
    log.apply(add)
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["reactions"] == [
        {"emoji": "👍", "count": 1, "senders": [SENDER_B]}
    ]
    rem = log.add(
        "reaction.removed",
        {"target_event_id": m1["event_id"], "emoji": "👍"},
        sender=SENDER_B,
        at=20,
    )
    log.apply(rem)
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["reactions"] == []
    # History is never deleted: the row survives, deactivated.
    row = conn.execute(
        "SELECT active, added_event_id, removed_event_id FROM reactions"
        " WHERE target_event_id = ? AND sender = ? AND emoji = ?;",
        (m1["event_id"], SENDER_B, "👍"),
    ).fetchone()
    assert row is not None
    assert row["active"] == 0
    assert row["added_event_id"] == add["event_id"]
    assert row["removed_event_id"] == rem["event_id"]
    # Re-adding after removal reactivates the same row.
    log.apply(
        log.add(
            "reaction.added",
            {"target_event_id": m1["event_id"], "emoji": "👍"},
            sender=SENDER_B,
            at=30,
        )
    )
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["reactions"][0]["count"] == 1
    # Two senders, same emoji: independent actives.
    log.apply(
        log.add(
            "reaction.added",
            {"target_event_id": m1["event_id"], "emoji": "👍"},
            sender=SENDER_A,
            at=40,
        )
    )
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["reactions"] == [
        {"emoji": "👍", "count": 2, "senders": [SENDER_A, SENDER_B]}
    ]


def test_reaction_remove_without_add_is_noop(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    log.apply(m1)
    mutations = log.apply(
        log.add(
            "reaction.removed",
            {"target_event_id": m1["event_id"], "emoji": "👍"},
            sender=SENDER_B,
            at=10,
        )
    )
    assert all(m["op"] == "noop" for m in mutations)


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------


def test_receipts_recorded_and_attached(conn, log):
    m1 = log.add("message.created", msg_body(), at=0)
    log.apply(m1)
    log.apply(
        log.add(
            "receipt.accepted",
            {"target_event_id": m1["event_id"], "accepted_at": ts(log.base, 11)},
            sender=SENDER_B,
            at=11,
        )
    )
    log.apply(
        log.add(
            "receipt.seen",
            {"target_event_id": m1["event_id"], "seen_at": ts(log.base, 12)},
            sender=SENDER_B,
            at=12,
        )
    )
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["receipts"] == [
        {"kind": "accepted", "sender": SENDER_B, "at": ts(log.base, 11)},
        {"kind": "seen", "sender": SENDER_B, "at": ts(log.base, 12)},
    ]


# ---------------------------------------------------------------------------
# Threads
# ---------------------------------------------------------------------------


def test_thread_root_is_first_message_event_id(conn, log):
    thread_id = str(uuid.uuid4())
    m1 = log.add("message.created", msg_body(), at=0,
                 event_id=thread_id, thread_id=thread_id)
    log.apply(m1)
    state = conn.execute(
        "SELECT root_event_id, message_count FROM thread_state WHERE thread_id = ?;",
        (thread_id,),
    ).fetchone()
    assert state["root_event_id"] == m1["event_id"]
    assert state["message_count"] == 1
    reply = log.add(
        "message.created",
        {"body": "reply", "format": "plain"},
        sender=SENDER_B,
        at=10,
        thread_id=thread_id,
        reply_to=m1["event_id"],
    )
    log.apply(reply)
    views = projections.get_conversation(conn, REL, CONV)
    assert views[1]["thread_id"] == thread_id
    assert views[1]["reply_state"] == "ok"


def test_reply_to_wrong_scope_rejected(conn, log):
    conn.execute("INSERT INTO conversations(conversation_id) VALUES ('conv-other');")
    m1 = log.add("message.created", msg_body(), at=0)
    log.apply(m1)
    bad = log.add(
        "message.created",
        {"body": "wrong scope", "format": "plain"},
        sender=SENDER_B,
        at=10,
        conversation_id="conv-other",
        reply_to=m1["event_id"],
    )
    with pytest.raises(projections.ProjectionError) as excinfo:
        log.apply(bad)
    assert excinfo.value.code == "reply_target_scope"


def test_thread_root_pending_until_root_arrives(conn, log):
    root_id = str(uuid.uuid4())
    # Reply arrives before the thread root exists.
    reply = log.add(
        "message.created",
        {"body": "early reply", "format": "plain"},
        sender=SENDER_B,
        at=10,
        thread_id=root_id,
        reply_to=root_id,
    )
    mutations = log.apply(reply)
    assert any(m["op"] == "pending" for m in mutations)
    state = conn.execute(
        "SELECT root_event_id FROM thread_state WHERE thread_id = ?;", (root_id,)
    ).fetchone()
    assert state["root_event_id"] is None
    root = log.add(
        "message.created",
        {"body": "root", "format": "plain"},
        at=0,
        thread_id=root_id,
        event_id=root_id,
    )
    log.apply(root)
    state = conn.execute(
        "SELECT root_event_id FROM thread_state WHERE thread_id = ?;", (root_id,)
    ).fetchone()
    assert state["root_event_id"] == root_id
    views = projections.get_conversation(conn, REL, CONV)
    by_id = {v["event_id"]: v for v in views}
    assert by_id[reply["event_id"]]["reply_state"] == "ok"


# ---------------------------------------------------------------------------
# Pending targets: 7-day expiry
# ---------------------------------------------------------------------------


def test_pending_reply_expires_after_seven_days(conn, log):
    missing = str(uuid.uuid4())
    reply = log.add(
        "message.created",
        {"body": "reply to ghost", "format": "plain"},
        sender=SENDER_B,
        at=0,
        reply_to=missing,
    )
    mutations = log.apply(reply)
    assert any(m["op"] == "pending" for m in mutations)
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["reply_state"] == "pending"
    # Six days later: still pending.
    expired = projections.expire_pending_refs(
        conn, REL, now=ts(log.base, 6 * 24 * 3600)
    )
    assert expired == 0
    # Eight days later: expired, shows unavailable context.
    expired = projections.expire_pending_refs(
        conn, REL, now=ts(log.base, 8 * 24 * 3600)
    )
    assert expired == 1
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["reply_state"] == "unavailable"
    state = conn.execute(
        "SELECT state FROM pending_refs WHERE event_id = ?;", (reply["event_id"],)
    ).fetchone()["state"]
    assert state == "expired"


def test_late_target_still_resolves(conn, log):
    missing = str(uuid.uuid4())
    reply = log.add(
        "message.created",
        {"body": "patient reply", "format": "plain"},
        sender=SENDER_B,
        at=0,
        reply_to=missing,
    )
    log.apply(reply)
    target = log.add(
        "message.created",
        {"body": "finally here", "format": "plain"},
        at=10,
        event_id=missing,
    )
    log.apply(target)
    view = {v["event_id"]: v for v in projections.get_conversation(conn, REL, CONV)}
    assert view[reply["event_id"]]["reply_state"] == "ok"


# ---------------------------------------------------------------------------
# Ordering: cross-sender tiebreak and determinism
# ---------------------------------------------------------------------------


def test_cross_sender_ordering_tiebreak(conn, log):
    # Same timestamp, two senders: sender identity bytes break the tie.
    b = log.add("message.created", {"body": "from B", "format": "plain"},
                sender=SENDER_B, at=100)
    a = log.add("message.created", {"body": "from A", "format": "plain"},
                sender=SENDER_A, at=100)
    log.rebuild()
    views = projections.get_conversation(conn, REL, CONV)
    assert [v["event_id"] for v in views] == [a["event_id"], b["event_id"]]
    assert SENDER_A.encode() < SENDER_B.encode()


def test_within_sender_seq_orders_replies(conn, log):
    first = log.add("message.created", {"body": "one", "format": "plain"}, at=0)
    second = log.add("message.created", {"body": "two", "format": "plain"}, at=0)
    log.rebuild()
    views = projections.get_conversation(conn, REL, CONV)
    assert [v["body"] for v in views] == ["one", "two"]
    assert views[0]["sender_seq"] < views[1]["sender_seq"]
    assert first["event_id"] != second["event_id"]


# ---------------------------------------------------------------------------
# Sequence gaps and forks
# ---------------------------------------------------------------------------


def test_sequence_gaps_marked_unresolved_then_filled(conn, log):
    log.apply(log.add("message.created", msg_body(), at=0))  # seq 1
    # Force a gap: next event from A takes seq 3.
    log.seq[SENDER_A] = 2
    log.apply(log.add("message.created", {"body": "gap", "format": "plain"}, at=10))
    gaps = conn.execute(
        "SELECT missing_seq FROM sequence_gaps WHERE sender = ?;", (SENDER_A,)
    ).fetchall()
    assert [g["missing_seq"] for g in gaps] == [2]
    # Out-of-order arrival of seq 2 resolves the gap.
    conn.execute(
        "INSERT INTO events(event_id, relationship_id, conversation_id, sender,"
        " sender_seq, created_at, key_epoch, event_type, replay_nonce,"
        " sealed_envelope) VALUES (?, ?, ?, ?, 2, ?, 1, 'message.created', ?, ?);",
        (str(uuid.uuid4()), REL, CONV, SENDER_A, ts(log.base, 5),
         str(uuid.uuid4()), b"sealed"),
    )
    filler_id = conn.execute("SELECT event_id FROM events WHERE sender_seq = 2;").fetchone()["event_id"]
    projections.record_projection_input(
        conn, event_id=filler_id, event_type="message.created", payload=msg_body()
    )
    row = dict(
        conn.execute("SELECT * FROM events WHERE event_id = ?;", (filler_id,)).fetchone()
    )
    row["payload"] = msg_body()
    row["reply_to"] = None
    projections.apply_event(conn, row)
    gaps = conn.execute(
        "SELECT COUNT(*) AS c FROM sequence_gaps WHERE sender = ?;", (SENDER_A,)
    ).fetchone()["c"]
    assert gaps == 0


def test_sequence_fork_quarantined_never_projected(conn, log):
    legit = log.add("message.created", msg_body(), at=0)
    log.apply(legit)
    fork_id = str(uuid.uuid4())
    fork_row = {
        "event_id": fork_id,
        "relationship_id": REL,
        "conversation_id": CONV,
        "thread_id": None,
        "sender": SENDER_A,
        "sender_seq": 1,
        "created_at": ts(log.base, 1),
        "key_epoch": 1,
        "event_type": "message.created",
        "payload": {"body": "forked bytes", "format": "plain"},
        "reply_to": None,
    }
    mutations = projections.apply_event(conn, fork_row)
    assert any(
        m["op"] == "quarantine" and m["info"]["reason"] == "sequence_fork"
        for m in mutations
    )
    row = conn.execute(
        "SELECT reason FROM quarantine WHERE event_id = ?;", (fork_id,)
    ).fetchone()
    assert row["reason"] == "sequence_fork"
    messages = conn.execute(
        "SELECT COUNT(*) AS c FROM messages WHERE event_id = ?;", (fork_id,)
    ).fetchone()["c"]
    assert messages == 0
    # The legitimate message is untouched.
    assert projections.get_conversation(conn, REL, CONV)[0]["body"] == "hello world"


# ---------------------------------------------------------------------------
# Coordination types: poll, task, human, delivery, security
# ---------------------------------------------------------------------------


def test_poll_lifecycle(conn, log):
    created = log.add(
        "poll.created",
        {
            "question": "lunch?",
            "choices": ["tacos", "sushi"],
            "closes_at": ts(log.base, 3600),
            "multi_select": False,
        },
        at=0,
    )
    log.apply(created)
    log.apply(
        log.add(
            "poll.responded",
            {
                "poll_id": created["event_id"],
                "choice_ids": ["tacos"],
                "human_confirmed": False,
            },
            sender=SENDER_B,
            at=10,
        )
    )
    poll = projections.get_poll(conn, created["event_id"])
    assert poll["question"] == "lunch?"
    assert poll["choices"] == ["tacos", "sushi"]
    assert poll["response_count"] == 1
    assert poll["responses"][0]["sender"] == SENDER_B
    assert poll["responses"][0]["choice_ids"] == ["tacos"]


def test_edit_targeting_non_message_rejected(conn, log):
    poll = log.add(
        "poll.created",
        {
            "question": "q?",
            "choices": ["a", "b"],
            "closes_at": ts(log.base, 9999),
            "multi_select": False,
        },
        at=0,
    )
    log.apply(poll)
    bad_edit = log.add(
        "message.edited",
        {"target_event_id": poll["event_id"], "body": "nope"},
        at=10,
    )
    with pytest.raises(projections.ProjectionError) as excinfo:
        log.apply(bad_edit)
    assert excinfo.value.code == "edit_target_not_message"


def test_reaction_to_missing_target_pends_then_resolves(conn, log):
    target_id = str(uuid.uuid4())
    react = log.add(
        "reaction.added",
        {"target_event_id": target_id, "emoji": "🔥"},
        sender=SENDER_B,
        at=0,
    )
    mutations = log.apply(react)
    assert any(m["op"] == "pending" for m in mutations)
    assert projections.get_conversation(conn, REL, CONV) == []
    # The target message arrives later and the pending reaction resolves.
    m1 = log.add("message.created", msg_body(), at=10, event_id=target_id)
    resolve_mutations = log.apply(m1)
    assert any(
        m["op"] == "update" and m["table"] == "pending_refs"
        for m in resolve_mutations
    )
    view = projections.get_conversation(conn, REL, CONV)[0]
    assert view["reactions"] == [
        {"emoji": "🔥", "count": 1, "senders": [SENDER_B]}
    ]


def test_task_state_machine(conn, log):
    created = log.add(
        "task.created",
        {"title": "write docs", "owner_identity": SENDER_A},
        at=0,
    )
    log.apply(created)
    log.apply(
        log.add(
            "task.updated",
            {"task_id": created["event_id"], "status": "in_progress"},
            at=10,
        )
    )
    log.apply(
        log.add(
            "task.updated",
            {"task_id": created["event_id"], "status": "done", "note": "shipped"},
            at=20,
        )
    )
    task = projections.get_task(conn, created["event_id"])
    assert task["status"] == "done"
    assert task["note"] == "shipped"
    reopen = log.add(
        "task.updated",
        {"task_id": created["event_id"], "status": "open"},
        at=30,
    )
    with pytest.raises(projections.ProjectionError) as excinfo:
        log.apply(reopen)
    assert excinfo.value.code == "task_transition_terminal"
    assert projections.get_task(conn, created["event_id"])["status"] == "done"


def test_human_request_response(conn, log):
    requested = log.add(
        "human.requested",
        {
            "prompt": "approve deploy?",
            "response_shape": "approval",
            "expires_at": ts(log.base, 3600),
        },
        at=0,
    )
    log.apply(requested)
    log.apply(
        log.add(
            "human.responded",
            {
                "request_id": requested["event_id"],
                "answer": "yes",
                "approved": True,
                "approval_record_id": "rec1",
            },
            sender=SENDER_B,
            at=10,
        )
    )
    req = projections.get_human_request(conn, requested["event_id"])
    assert req["state"] == "responded"
    assert req["answer"] == "yes"
    assert req["approved"] == 1


def test_delivery_schedule_and_cancel(conn, log):
    inner = str(uuid.uuid4())
    scheduled = log.add(
        "delivery.scheduled",
        {"inner_event_id": inner, "deliver_at": ts(log.base, 3600)},
        at=0,
    )
    log.apply(scheduled)
    row = conn.execute(
        "SELECT state FROM deliveries WHERE scheduled_event_id = ?;",
        (scheduled["event_id"],),
    ).fetchone()
    assert row["state"] == "scheduled"
    log.apply(
        log.add(
            "delivery.canceled",
            {
                "scheduled_event_id": scheduled["event_id"],
                "canceled_at": ts(log.base, 10),
            },
            at=10,
        )
    )
    row = conn.execute(
        "SELECT state FROM deliveries WHERE scheduled_event_id = ?;",
        (scheduled["event_id"],),
    ).fetchone()
    assert row["state"] == "canceled"


def test_security_key_events_projected(conn, log):
    prepare = log.add(
        "security.key.prepare",
        {
            "new_agreement_key": "zTestKey123ABC",
            "prior_fingerprint": "fp123",
            "deadline": ts(log.base, 3600),
        },
        at=0,
    )
    log.apply(prepare)
    rows = conn.execute(
        "SELECT action, key_epoch FROM security_key_events;"
    ).fetchall()
    assert [(r["action"], r["key_epoch"]) for r in rows] == [("prepare", 1)]


def test_no_projection_types_are_noops(conn, log):
    conn.execute(
        "INSERT INTO events(event_id, relationship_id, conversation_id, sender,"
        " sender_seq, created_at, key_epoch, event_type, replay_nonce,"
        " sealed_envelope) VALUES (?, ?, ?, ?, 1, ?, 1, 'relationship.ready',"
        " ?, ?);",
        (str(uuid.uuid4()), REL, CONV, SENDER_A, ts(log.base, 0),
         str(uuid.uuid4()), b"sealed"),
    )
    event_id = conn.execute(
        "SELECT event_id FROM events WHERE event_type = 'relationship.ready';"
    ).fetchone()["event_id"]
    row = dict(conn.execute("SELECT * FROM events WHERE event_id = ?;", (event_id,)).fetchone())
    row["payload"] = {}
    row["reply_to"] = None
    assert projections.apply_event(conn, row) == []


def test_unknown_event_type_rejected(conn, log):
    row = {
        "event_id": str(uuid.uuid4()),
        "relationship_id": REL,
        "conversation_id": CONV,
        "thread_id": None,
        "sender": SENDER_A,
        "sender_seq": 99,
        "created_at": ts(log.base, 0),
        "key_epoch": 1,
        "event_type": "bogus.type",
        "payload": {},
        "reply_to": None,
    }
    with pytest.raises(projections.ProjectionError) as excinfo:
        projections.apply_event(conn, row)
    assert excinfo.value.code == "unknown_event_type"


# ---------------------------------------------------------------------------
# Deterministic rebuild
# ---------------------------------------------------------------------------


def _dump_table(conn, table, order_by="rowid"):
    rows = conn.execute(f"SELECT * FROM {table} ORDER BY {order_by};").fetchall()
    return [dict(r) for r in rows]


def _full_snapshot(conn):
    snap = {}
    snap["views"] = projections.get_conversation(conn, REL, CONV)
    for table, order in [
        ("messages", "created_at, sender, sender_seq"),
        ("message_revisions", "event_id, revision_no"),
        ("reactions", "target_event_id, sender, emoji"),
        ("receipts", "target_event_id, kind, sender"),
        ("polls", "poll_id"),
        ("poll_responses", "poll_id, sender"),
        ("tasks", "task_id"),
        ("human_requests", "request_id"),
        ("deliveries", "scheduled_event_id"),
        ("security_key_events", "event_id"),
        ("thread_state", "thread_id"),
        ("pending_refs", "event_id"),
        ("projection_cursors", "sender"),
    ]:
        snap[table] = _dump_table(conn, table, order)
    snap["poll"] = projections.get_poll(
        conn, snap["polls"][0]["poll_id"]
    ) if snap["polls"] else None
    return snap


def test_deterministic_rebuild_byte_identical(conn, log):
    thread = str(uuid.uuid4())
    m1 = log.add("message.created", {"body": "first", "format": "markdown-safe"},
                 at=0, event_id=thread, thread_id=thread)
    m2 = log.add(
        "message.created", {"body": "second", "format": "plain"},
        sender=SENDER_B, at=5, thread_id=thread, reply_to=m1["event_id"],
    )
    log.add("message.edited",
            {"target_event_id": m1["event_id"], "body": "first v2"}, at=10)
    log.add("reaction.added",
            {"target_event_id": m1["event_id"], "emoji": "👍"},
            sender=SENDER_B, at=15)
    log.add("reaction.added",
            {"target_event_id": m2["event_id"], "emoji": "🎉"}, at=16)
    log.add("reaction.removed",
            {"target_event_id": m2["event_id"], "emoji": "🎉"},
            sender=SENDER_B, at=17)
    log.add("receipt.accepted",
            {"target_event_id": m1["event_id"], "accepted_at": ts(log.base, 18)},
            sender=SENDER_B, at=18)
    log.add("receipt.seen",
            {"target_event_id": m1["event_id"], "seen_at": ts(log.base, 19)},
            sender=SENDER_B, at=19)
    poll = log.add("poll.created",
                   {"question": "q?", "choices": ["a", "b"],
                    "closes_at": ts(log.base, 9999), "multi_select": True}, at=20)
    log.add("poll.responded",
            {"poll_id": poll["event_id"], "choice_ids": ["a"]},
            sender=SENDER_B, at=21)
    task = log.add("task.created",
                   {"title": "t", "owner_identity": SENDER_A}, at=22)
    log.add("task.updated",
            {"task_id": task["event_id"], "status": "in_progress"}, at=23)
    human = log.add("human.requested",
                    {"prompt": "p?", "response_shape": "text",
                     "expires_at": ts(log.base, 9999)}, at=24)
    log.add("human.responded",
            {"request_id": human["event_id"], "answer": "a", "approved": False,
             "approval_record_id": "rec2"},
            sender=SENDER_B, at=25)
    sched = log.add("delivery.scheduled",
                    {"inner_event_id": str(uuid.uuid4()),
                     "deliver_at": ts(log.base, 9999)}, at=26)
    log.add("delivery.canceled",
            {"scheduled_event_id": sched["event_id"],
             "canceled_at": ts(log.base, 27)}, at=27)
    log.add("security.key.prepare",
            {"new_agreement_key": "zTestKey123ABC", "prior_fingerprint": "fp123",
             "deadline": ts(log.base, 9999)}, at=28)
    log.add("message.retracted",
            {"target_event_id": m2["event_id"], "reason": "regret"}, sender=SENDER_B,
            at=29)

    log.rebuild()
    first = restricted_jcs(_full_snapshot(conn))
    log.rebuild()
    second = restricted_jcs(_full_snapshot(conn))
    assert first == second

    views = projections.get_conversation(conn, REL, CONV)
    assert len(views) == 2
    assert views[0]["body"] == "first v2"
    assert views[0]["edited"] is True
    assert views[1]["retracted"] is True
    assert views[1]["body"] is None
    assert views[1]["retraction"]["reason"] == "regret"


# ---------------------------------------------------------------------------
# get_conversation pagination
# ---------------------------------------------------------------------------


def test_get_conversation_limit_and_before(conn, log):
    ids = []
    for i in range(5):
        ids.append(log.add("message.created",
                           {"body": f"m{i}", "format": "plain"}, at=i)["event_id"])
    log.rebuild()
    page = projections.get_conversation(conn, REL, CONV, limit=2)
    assert [v["body"] for v in page] == ["m3", "m4"]
    page = projections.get_conversation(conn, REL, CONV, before=ids[3])
    assert [v["body"] for v in page] == ["m0", "m1", "m2"]
    page = projections.get_conversation(conn, REL, CONV, limit=2, before=ids[3])
    assert [v["body"] for v in page] == ["m1", "m2"]
    with pytest.raises(projections.ProjectionError) as excinfo:
        projections.get_conversation(conn, REL, CONV, before="nope")
    assert excinfo.value.code == "unknown_cursor"


# ---------------------------------------------------------------------------
# Migration idempotency and version contract
# ---------------------------------------------------------------------------


def test_migrate_projections_idempotent(conn):
    assert projections.migrate_projections(conn) == \
        projections.PROJECTIONS_SCHEMA_VERSION
    assert projections.migrate_projections(conn) == \
        projections.PROJECTIONS_SCHEMA_VERSION
    version = conn.execute("PRAGMA user_version;").fetchone()[0]
    assert version == projections.PROJECTIONS_SCHEMA_VERSION


def test_migrate_requires_skeleton_first():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    with pytest.raises(projections.ProjectionError) as excinfo:
        projections.migrate_projections(c)
    assert excinfo.value.code == "skeleton_migration_missing"
    c.close()


def test_record_projection_input_validates_payload(conn, log):
    from muse_agent_social.validation import ValidationError

    with pytest.raises(ValidationError):
        projections.record_projection_input(
            conn,
            event_id=str(uuid.uuid4()),
            event_type="message.created",
            payload={"body": "missing format"},
        )
