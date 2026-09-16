"""V6 regression: storage failures must be classified, not swallowed
into an endless retry loop.

Before the fix, every exception from the receive core (including
deterministic ones like 'no such table' or a malformed database) produced
retry_pending forever: the object was never quarantined and the watcher
never advanced.
"""

import errno
import sqlite3
from types import SimpleNamespace

import pytest

import muse_agent_social.cli as cli_mod
from muse_agent_social.policy.delivery import set_accepted_receipts_enabled
from muse_agent_social.policy.limits import MAX_CONSECUTIVE_RECEIVE_FAILURES
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
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    provision_receive_side(conn, RID, bob, alice)
    set_accepted_receipts_enabled(conn, RID, False)
    cli_mod._ensure_cli_tables(conn)
    return (
        SimpleNamespace(
            conn=conn,
            state_dir=tmp_path,
            keys_dir=tmp_path / "keys",
            identity_id=bob["identity_id"],
        ),
        conn,
        alice,
        bob,
    )


def _fail_with(exc, monkeypatch):
    def raiser(*args, **kwargs):
        raise exc

    monkeypatch.setattr(cli_mod, "_receive_object_inner", raiser)


def _sealed(alice, bob, rid, conv):
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "x", "format": "plain"}, seq=1,
    )
    return raw


def test_deterministic_sqlite_error_is_quarantined(tmp_path, monkeypatch):
    """'no such table' is deterministic: quarantine with a durable
    storage_error reason instead of retrying forever."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    _fail_with(sqlite3.OperationalError("no such table: events"), monkeypatch)
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(
        ctx, RID, _oname("det"), _sealed(alice, bob, RID, new_conversation(conn)), acc
    )
    assert outcome["outcome"] == "quarantined"
    row = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()
    assert row["reason"] == "storage_error"


def test_malformed_database_is_quarantined(tmp_path, monkeypatch):
    """A corrupt database is not a retryable condition."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    _fail_with(
        sqlite3.DatabaseError("database disk image is malformed"), monkeypatch
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(
        ctx, RID, _oname("mal"), _sealed(alice, bob, RID, new_conversation(conn)), acc
    )
    assert outcome["outcome"] == "quarantined"
    row = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()
    assert row["reason"] == "storage_error"


def test_lock_contention_is_retryable_then_ceiling_hits(tmp_path, monkeypatch):
    """'database is locked' is transient: retry_pending, but the retry
    ceiling eventually quarantines the object so the watcher advances."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    _fail_with(sqlite3.OperationalError("database is locked"), monkeypatch)
    acc = {"surfaces": 0, "receipts_queued": 0}
    raw = _sealed(alice, bob, RID, new_conversation(conn))
    name = _oname("lock")
    outcome = cli_mod._receive_object(ctx, RID, name, raw, acc)
    assert outcome["outcome"] == "retry_pending"
    # Sightings 2..9 stay retryable; sighting 10 hits the ceiling.
    for _ in range(MAX_CONSECUTIVE_RECEIVE_FAILURES - 2):
        outcome = cli_mod._receive_object(ctx, RID, name, raw, acc)
        assert outcome["outcome"] == "retry_pending"
    outcome = cli_mod._receive_object(ctx, RID, name, raw, acc)
    assert outcome["outcome"] == "quarantined"
    row = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()
    assert row["reason"] == "retry_ceiling_exceeded"


def test_disk_full_is_retryable(tmp_path, monkeypatch):
    ctx, conn, alice, bob = _ctx(tmp_path)
    _fail_with(OSError(errno.ENOSPC, "No space left on device"), monkeypatch)
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(
        ctx, RID, _oname("full"), _sealed(alice, bob, RID, new_conversation(conn)), acc
    )
    assert outcome["outcome"] == "retry_pending"


def test_permission_error_is_quarantined(tmp_path, monkeypatch):
    ctx, conn, alice, bob = _ctx(tmp_path)
    _fail_with(OSError(errno.EACCES, "Permission denied"), monkeypatch)
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(
        ctx, RID, _oname("perm"), _sealed(alice, bob, RID, new_conversation(conn)), acc
    )
    assert outcome["outcome"] == "quarantined"
    row = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()
    assert row["reason"] == "storage_error"


def test_storage_error_quarantine_is_durable(tmp_path, monkeypatch):
    """The storage_error quarantine itself is written through the real
    path: it survives a fresh connection to the same DB file."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    db_path = tmp_path / "state.db"
    _fail_with(sqlite3.OperationalError("no such table: x"), monkeypatch)
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(
        ctx, RID, _oname("dur"), _sealed(alice, bob, RID, new_conversation(conn)), acc
    )
    assert outcome["outcome"] == "quarantined"
    conn.close()
    conn2 = fresh_db(db_path)
    row = conn2.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()
    assert row is not None
    assert row["reason"] == "storage_error"
    conn2.close()


def test_unwritable_bookkeeping_escalates_with_counting(tmp_path, monkeypatch, capsys):
    """When even the failure bookkeeping cannot write, the object is not
    spun on silently: each attempt warns on stderr, and the ceiling makes
    a best-effort quarantine write."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    _fail_with(sqlite3.OperationalError("database is locked"), monkeypatch)

    def dead_bookkeeping(*args, **kwargs):
        raise RuntimeError("bookkeeping dead")

    monkeypatch.setattr(cli_mod, "_storage_failure_outcome", dead_bookkeeping)
    acc = {"surfaces": 0, "receipts_queued": 0}
    raw = _sealed(alice, bob, RID, new_conversation(conn))
    name = _oname("bkfail")
    outcome = cli_mod._receive_object(ctx, RID, name, raw, acc)
    assert outcome["outcome"] == "retry_pending"
    assert "unwritable" in capsys.readouterr().err
    for _ in range(MAX_CONSECUTIVE_RECEIVE_FAILURES - 2):
        assert cli_mod._receive_object(ctx, RID, name, raw, acc)["outcome"] == "retry_pending"
    outcome = cli_mod._receive_object(ctx, RID, name, raw, acc)
    assert outcome["outcome"] == "quarantined"
    row = conn.execute("SELECT reason FROM receive_quarantine").fetchone()
    assert row["reason"] == "storage_error"
    err = capsys.readouterr().err
    assert "unwritable" in err
