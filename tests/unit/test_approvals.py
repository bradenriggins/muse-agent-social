"""Unit tests for human-approval lifecycle and atomic consumption.

Covers: single-use claim (exactly one winner under concurrency), expiry
blocks consumption, and the critical invariant that the approval claim is
atomic with event persistence: a send that fails after claiming rolls the
claim back, so the human's approval is never burned without authorizing a
durably persisted event.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from muse_agent_social.model import approvals
from muse_agent_social.model.approvals import (
    ApprovalError,
    consume_approval,
    create_approval,
    get_approval,
)
from muse_agent_social.store import db
from muse_agent_social.store import migrations
from muse_agent_social.store.db import utcnow

RID = "rel-approval-1"
PEER = "did:key:zPeerApproval000000000000000001"


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(tmp_path / "a.db")
    migrations.migrate(c)
    c.execute(
        "INSERT INTO relationships(relationship_id, peer_identity_id,"
        " consent_state, policy, key_epoch, created_at)"
        " VALUES (?, ?, 'active', '{}', 1, ?);",
        (RID, PEER, utcnow()),
    )
    yield c
    c.close()


def _mk(conn, **over):
    kw = dict(
        relationship_id=RID,
        subject_type="human_request",
        subject_id="req-1",
        answer="yes",
        approved=True,
        created_at=utcnow(),
    )
    kw.update(over)
    return create_approval(conn, **kw)


def test_consume_once(conn):
    aid = _mk(conn)
    assert consume_approval(conn, aid, utcnow()) is True
    assert get_approval(conn, aid)["consumed_at"] is not None
    # Second claim loses.
    assert consume_approval(conn, aid, utcnow()) is False


def test_consume_unknown_id_fails(conn):
    assert consume_approval(conn, "nope" * 8, utcnow()) is False


def test_expired_approval_cannot_be_consumed(conn):
    past = (
        datetime.now(timezone.utc) - timedelta(seconds=25 * 3600)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    aid = _mk(conn, created_at=past)
    assert consume_approval(conn, aid, utcnow()) is False
    assert get_approval(conn, aid)["consumed_at"] is None


def test_explicit_expiry_honored(conn):
    aid = _mk(conn, expires_at="2020-01-01T00:00:00Z")
    assert consume_approval(conn, aid, utcnow()) is False


def test_bad_subject_type_rejected(conn):
    with pytest.raises(ApprovalError):
        _mk(conn, subject_type="bogus")


def test_concurrent_consume_exactly_one_winner(tmp_path):
    path = tmp_path / "a.db"
    seed = db.connect(path)
    migrations.migrate(seed)
    aid = create_approval(
        seed,
        relationship_id=RID,
        subject_type="poll",
        subject_id="poll-1",
        answer="tacos",
        approved=True,
        created_at=utcnow(),
    )
    seed.commit()
    seed.close()

    results = []
    barrier = threading.Barrier(8)

    def worker():
        c = db.connect(path)
        try:
            barrier.wait(timeout=15)
            results.append(consume_approval(c, aid, utcnow()))
            c.commit()
        finally:
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert results.count(True) == 1
    assert results.count(False) == 7


def _protected():
    eid = str(uuid.uuid4())
    return {
        "protocol": "mas/0.2",
        "event_id": eid,
        "relationship_id": RID,
        "conversation_id": RID,
        "sender": "did:key:zLocalApproval00000000000000002",
        "sender_seq": 0,
        "created_at": utcnow(),
        "deliver_at": utcnow(),
        "expires_at": None,
        "event_type": "human.responded",
        "thread_id": eid,
        "reply_to": None,
        "key_epoch": 1,
        "replay_nonce": uuid.uuid4().hex,
        "ephemeral_key": "ek",
    }


def test_failed_send_does_not_burn_approval(conn, monkeypatch):
    """The claim is inside the persistence transaction: when sealing
    fails, the transaction rolls back and the approval stays live."""
    from muse_agent_social.model import events

    aid = _mk(conn)
    conn.commit()

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated sealing failure")

    monkeypatch.setattr(events, "seal_envelope", _boom)
    with pytest.raises(RuntimeError, match="simulated sealing failure"):
        # persist_outgoing_in_txn runs inside the caller's transaction;
        # production callers (assign_and_persist_outgoing, the accepted-
        # receipt path) always provide one via db.transaction().
        with db.transaction(conn):
            events.persist_outgoing_in_txn(
                conn, _protected(), {"request_id": "req-1", "answer": "yes", "approved": True},
                None, [], approval_id=aid
            )
    row = get_approval(conn, aid)
    assert row["consumed_at"] is None


def test_consumed_approval_blocks_second_persist(conn, monkeypatch):
    """A raced approval fails the whole persist transaction: no event is
    stored and the error is stable."""
    from muse_agent_social.model import events
    from muse_agent_social.model.events import EventStoreError

    aid = _mk(conn)
    assert consume_approval(conn, aid, utcnow()) is True
    conn.commit()

    protected = _protected()
    with pytest.raises(EventStoreError) as excinfo:
        events.persist_outgoing_in_txn(
            conn, protected,
            {"request_id": "req-1", "answer": "yes", "approved": True},
            None, [], approval_id=aid
        )
    assert excinfo.value.code == "approval_consumed"
    assert (
        conn.execute(
            "SELECT 1 FROM events WHERE event_id = ?;", (protected["event_id"],)
        ).fetchone()
        is None
    )


def test_expired_approval_blocks_persist(conn):
    from muse_agent_social.model import events
    from muse_agent_social.model.events import EventStoreError

    past = (
        datetime.now(timezone.utc) - timedelta(seconds=25 * 3600)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    aid = _mk(conn, created_at=past)
    conn.commit()
    with pytest.raises(EventStoreError) as excinfo:
        events.persist_outgoing_in_txn(
            conn, _protected(), {"request_id": "req-1", "answer": "yes", "approved": True},
                None, [], approval_id=aid
        )
    assert excinfo.value.code == "approval_consumed"


def test_dry_run_validates_without_consuming(conn):
    """--dry-run must validate the approval record without consuming it
    and without any other side effect: the record stays live."""
    import argparse
    import muse_agent_social.cli as cli_mod
    from types import SimpleNamespace

    aid = _mk(conn)
    conn.commit()
    ctx = SimpleNamespace(conn=conn)
    args = argparse.Namespace(
        dry_run=True, approval_record=aid, _relationship_id=RID
    )
    result = cli_mod._require_approval_record(
        ctx, args, subject_type="human_request", subject_id="req-1",
        answer="yes", approved=True,
    )
    assert result == aid
    # The record was not consumed: still claimable.
    assert conn.execute(
        "SELECT consumed_at FROM human_approvals WHERE approval_id=?", (aid,)
    ).fetchone()["consumed_at"] is None


def test_dry_run_sentinel_skips_record_lookup(conn):
    """cmd_human_respond --dry-run passes approval_record='dry_run': the
    sentinel short-circuits before any record lookup, so no record is
    created or needed."""
    import argparse
    import muse_agent_social.cli as cli_mod
    from types import SimpleNamespace

    ctx = SimpleNamespace(conn=conn)
    args = argparse.Namespace(
        dry_run=True, approval_record="dry_run", _relationship_id="rel-1"
    )
    assert (
        cli_mod._require_approval_record(
            ctx, args, subject_type="ask", subject_id="q1",
            answer="yes", approved=True,
        )
        == "dry_run"
    )
    assert conn.execute("SELECT COUNT(*) FROM human_approvals").fetchone()[0] == 0


def test_poll_answer_encoding_is_collision_resistant():
    """Comma-joining choice ids is ambiguous (["a,b","c"] vs ["a","b,c"]
    both give "a,b,c"); the approval-bound encoding must be injective so
    one record cannot authorize a different choice set."""
    import muse_agent_social.cli as cli_mod

    a = cli_mod._poll_answer(["a,b", "c"])
    b = cli_mod._poll_answer(["a", "b,c"])
    assert a != b
    # Stable and round-trippable.
    assert cli_mod._poll_answer(["x", "y"]) == cli_mod._poll_answer(["x", "y"])
    import json

    assert json.loads(a) == ["a,b", "c"]


class _FakeStdin:
    def __init__(self, text, tty):
        self._lines = text.splitlines(keepends=True)
        self._tty = tty

    def isatty(self):
        return self._tty

    def readline(self):
        return self._lines.pop(0) if self._lines else ""


def test_human_gate_refuses_non_tty_stdin(monkeypatch):
    """Piped stdin cannot pass the human gate: a scripted agent must not
    be able to mint human approvals without a real terminal."""
    import sys
    import muse_agent_social.cli as cli_mod

    monkeypatch.setattr(sys, "stdin", _FakeStdin("", tty=False))
    with pytest.raises(cli_mod.CliError) as excinfo:
        cli_mod._require_human_presence("send X")
    assert excinfo.value.code == "human_presence_required"


def test_human_gate_rejects_wrong_confirmation(monkeypatch):
    import sys
    import muse_agent_social.cli as cli_mod

    for typed in ("approve\n", "yes\n", "\n"):
        monkeypatch.setattr(sys, "stdin", _FakeStdin(typed, tty=True))
        with pytest.raises(cli_mod.CliError) as excinfo:
            cli_mod._require_human_presence("send X")
        assert excinfo.value.code == "human_approval_declined"
    # Surrounding whitespace is stripped, so a padded APPROVE still counts.
    monkeypatch.setattr(sys, "stdin", _FakeStdin("APPROVE \n", tty=True))
    cli_mod._require_human_presence("send X")


def test_human_gate_accepts_exact_approve(monkeypatch, capsys):
    import sys
    import muse_agent_social.cli as cli_mod

    monkeypatch.setattr(sys, "stdin", _FakeStdin("APPROVE\n", tty=True))
    cli_mod._require_human_presence("send X")  # must not raise
    assert "APPROVE" in capsys.readouterr().out
