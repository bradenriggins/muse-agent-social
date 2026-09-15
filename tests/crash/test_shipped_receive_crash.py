"""H4: crash tests against the SHIPPED ``_receive_object_inner``.

Status: all green against the merged transactional receive.

Each test kills the receive once at one fault boundary, re-delivers the
same bytes, and proves exactly one terminal result: surfaced once, or
cleanly retryable. Never lost, never duplicated.

Fault boundaries:
  * event insert            -> kill during INSERT INTO events
  * projection queue insert -> kill during INSERT INTO projection_queue
  * surface queue insert    -> kill during INSERT INTO surface_queue
    (the shipped path has no post-commit surface drain; the surface
    decision is persisted as the surface_queue row inside the commit,
    so this insert IS the surfacing boundary)
  * commit                  -> kill at the commit of the atomic block
  * projection drain        -> kill inside apply_event, after commit
  * surfacing               -> see surface queue insert note above
  * commit-to-projection gap -> kill after commit returns, before the
    incremental apply_event runs

Boundaries inside the atomic commit transaction roll back cleanly and
retry to exactly-once. The post-commit boundaries (projection drain,
commit-to-projection gap) converge via the duplicate resume path,
which re-drains any still-queued projection before reporting accepted.
"""

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

import muse_agent_social.cli as cli_mod
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


class FaultInjected(Exception):
    """Simulated crash at a fault boundary."""


class FaultConn:
    """sqlite3 connection proxy that raises FaultInjected at one boundary.

    ``kill_sql``: raise on the first execute() containing the substring.
    ``kill_commit``: roll back and raise instead of committing when an
    execute() containing "COMMIT;" is seen (the transaction() helper
    commits via execute, not via the context-manager protocol).
    ``arm_commit_after``: only arm the commit kill after an execute()
    containing the substring has been seen, so the kill lands on the
    intended commit. ``kill_after_commit_execute``: after the armed
    commit succeeds, raise on the next execute() (the
    commit-to-projection gap).
    """

    def __init__(
        self,
        real: sqlite3.Connection,
        *,
        kill_sql: str | None = None,
        kill_commit: bool = False,
        arm_commit_after: str | None = None,
        kill_after_commit_execute: bool = False,
    ) -> None:
        self._real = real
        self._kill_sql = kill_sql
        self._sql_armed = kill_sql is not None
        self._kill_commit = kill_commit
        self._arm_commit_after = arm_commit_after
        self._commit_seen = False
        self._kill_after_commit_execute = kill_after_commit_execute
        self._gap_armed = False

    def execute(self, sql, params=()):
        if self._gap_armed:
            self._gap_armed = False
            raise FaultInjected("kill in commit-to-projection gap")
        if self._sql_armed and self._kill_sql in sql:
            self._sql_armed = False
            raise FaultInjected(f"kill at {self._kill_sql}")
        if self._arm_commit_after and self._arm_commit_after in sql:
            self._commit_seen = True
        if self._commit_seen and "COMMIT;" in sql:
            self._commit_seen = False
            if self._kill_commit:
                self._real.execute("ROLLBACK;")
                raise FaultInjected("kill at commit")
            if self._kill_after_commit_execute:
                result = self._real.execute(sql, params)
                self._gap_armed = True
                return result
        return self._real.execute(sql, params)

    def __enter__(self):
        self._real.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        # Commit kills are handled in execute() (the transaction() helper
        # commits via execute("COMMIT;")); nothing to do here.
        return self._real.__exit__(exc_type, exc, tb)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _oname(tag: str) -> str:
    return (tag + "0" * 32)[:32] + ".json"


@pytest.fixture()
def setup(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "11111111-2222-4333-8444-555555555555"
    provision_receive_side(conn, rid, bob, alice)
    # Keep the receipt path out of the fault window; the boundaries
    # under test do not involve receipts. Alert mode so the surface
    # decision is surfaces=1.
    set_accepted_receipts_enabled(conn, rid, False)
    set_policy(conn, rid, "alert")
    conv = new_conversation(conn)
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "crash me", "format": "plain"}, seq=1,
    )
    cli_mod._ensure_cli_tables(conn)
    return {
        "conn": conn,
        "rid": rid,
        "raw": raw,
        "state_dir": tmp_path,
        "identity_id": bob["identity_id"],
    }


def _ctx(setup, conn):
    keys_dir = Path(setup["state_dir"]) / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        conn=conn,
        state_dir=setup["state_dir"],
        keys_dir=keys_dir,
        identity_id=setup["identity_id"],
    )


def _counts(setup):
    conn = setup["conn"]
    return {
        "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "messages": conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
        "surface_queue": conn.execute(
            "SELECT COUNT(*) FROM surface_queue"
        ).fetchone()[0],
    }


def _receive(setup, conn, tag="obj"):
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object_inner(
        _ctx(setup, conn), setup["rid"], _oname(tag), setup["raw"], acc
    )
    return outcome, acc


def test_kill_at_event_insert_retries_cleanly(setup):
    """Kill during the events INSERT: the transaction rolls back, resume
    reprocesses fully, the event is stored and surfaced exactly once."""
    killer = FaultConn(setup["conn"], kill_sql="INSERT INTO events")
    with pytest.raises(FaultInjected):
        _receive(setup, killer)
    assert _counts(setup) == {"events": 0, "messages": 0, "surface_queue": 0}

    outcome, acc = _receive(setup, setup["conn"])
    assert outcome["outcome"] == "accepted"
    assert _counts(setup) == {"events": 1, "messages": 1, "surface_queue": 1}
    assert acc["surfaces"] == 1


def test_kill_at_projection_queue_insert(setup):
    """Kill during the projection_queue INSERT (inside the atomic receive
    transaction): everything rolls back, resume reprocesses fully, the
    event is stored and surfaced exactly once."""
    killer = FaultConn(setup["conn"], kill_sql="INSERT INTO projection_queue")
    with pytest.raises(FaultInjected):
        _receive(setup, killer)
    assert _counts(setup) == {"events": 0, "messages": 0, "surface_queue": 0}

    outcome, acc = _receive(setup, setup["conn"])
    assert outcome["outcome"] == "accepted"
    assert _counts(setup) == {"events": 1, "messages": 1, "surface_queue": 1}
    assert acc["surfaces"] == 1


def test_kill_at_surface_queue_insert(setup):
    """Kill during the surface_queue INSERT (inside the atomic receive
    transaction): everything rolls back, resume reprocesses fully, the
    event is stored and surfaced exactly once."""
    killer = FaultConn(setup["conn"], kill_sql="surface_queue")
    with pytest.raises(FaultInjected):
        _receive(setup, killer)
    assert _counts(setup) == {"events": 0, "messages": 0, "surface_queue": 0}

    outcome, acc = _receive(setup, setup["conn"])
    assert outcome["outcome"] == "accepted"
    assert _counts(setup) == {"events": 1, "messages": 1, "surface_queue": 1}
    assert acc["surfaces"] == 1


def test_kill_at_commit(setup):
    """Kill at the commit of the atomic receive transaction: the
    transaction rolls back, resume reprocesses fully, the event is
    stored and surfaced exactly once."""
    killer = FaultConn(
        setup["conn"],
        kill_commit=True,
        arm_commit_after="INSERT INTO events",
    )
    with pytest.raises(FaultInjected):
        _receive(setup, killer)
    assert _counts(setup) == {"events": 0, "messages": 0, "surface_queue": 0}

    outcome, acc = _receive(setup, setup["conn"])
    assert outcome["outcome"] == "accepted"
    assert _counts(setup) == {"events": 1, "messages": 1, "surface_queue": 1}
    assert acc["surfaces"] == 1


def test_kill_during_projection_drain_loses_projection(setup, monkeypatch):
    """Kill inside apply_event, after the commit: the event is durable
    but unprojected, with its projection_queue row still present. The
    duplicate resume path re-drains the projection, so the message
    converges exactly once instead of being silently lost."""
    real_apply_event = cli_mod.apply_event
    calls = {"n": 0}

    def dead_drain(conn, event_row):
        calls["n"] += 1
        if calls["n"] == 1:
            raise FaultInjected("kill during projection drain")
        return real_apply_event(conn, event_row)

    monkeypatch.setattr(cli_mod, "apply_event", dead_drain)
    with pytest.raises(FaultInjected):
        _receive(setup, setup["conn"])
    assert _counts(setup) == {"events": 1, "messages": 0, "surface_queue": 1}

    outcome, _ = _receive(setup, setup["conn"])
    assert outcome["outcome"] == "accepted"
    assert _counts(setup)["events"] == 1
    assert _counts(setup)["messages"] == 1, (
        "projection lost: resume reported accepted without projecting"
    )


def test_kill_in_commit_to_projection_gap_loses_projection(setup):
    """Kill after the commit returns but before the incremental
    apply_event runs: the event is durable with its projection_queue row
    present but unprojected. The duplicate resume path re-drains the
    projection, so the message converges exactly once."""
    killer = FaultConn(
        setup["conn"],
        arm_commit_after="INSERT INTO events",
        kill_after_commit_execute=True,
    )
    with pytest.raises(FaultInjected):
        _receive(setup, killer)
    assert _counts(setup) == {"events": 1, "messages": 0, "surface_queue": 1}

    outcome, _ = _receive(setup, setup["conn"])
    assert outcome["outcome"] == "accepted"
    assert _counts(setup)["events"] == 1
    assert _counts(setup)["messages"] == 1, (
        "projection lost: resume reported accepted without projecting"
    )
