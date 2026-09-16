"""Medium 2d: post-receive hook failures are logged loudly, never fatal.

A failing hook (rotation ceremony step, activation, bookkeeping) must not
wedge or roll back the receive: the event is already durably accepted and
surfaced. The failure is reported on stderr with the exception attached.
"""

from types import SimpleNamespace

import muse_agent_social.cli as cli_mod
from muse_agent_social.policy.delivery import set_accepted_receipts_enabled
from support.harness import (
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)


def _oname(tag: str) -> str:
    return (tag + "0" * 32)[:32] + ".json"


def test_hook_failure_warns_and_receive_still_accepted(tmp_path, capsys, monkeypatch):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    provision_receive_side(conn, rid, bob, alice)
    # Keep the receipt path out of the test; the hook block runs anyway.
    set_accepted_receipts_enabled(conn, rid, False)
    conv = new_conversation(conn)
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "hello", "format": "plain"}, seq=1,
    )
    cli_mod._ensure_cli_tables(conn)
    ctx = SimpleNamespace(
        conn=conn,
        state_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        identity_id=bob["identity_id"],
    )

    def boom(*args, **kwargs):
        raise RuntimeError("hook exploded")

    monkeypatch.setattr(cli_mod, "_post_receive_hooks", boom)

    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object_inner(ctx, rid, _oname("hookfail"), raw, acc)

    assert outcome["outcome"] == "accepted"
    err = capsys.readouterr().err
    assert "warning: post-receive hook failed" in err
    assert "hook exploded" in err
    # The event is fully persisted despite the hook failure.
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM replay_guard").fetchone()[0] == 1


def _ctx_for(tmp_path, alice, bob):
    from types import SimpleNamespace

    conn = fresh_db(tmp_path / "state.db")
    rid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    provision_receive_side(conn, rid, bob, alice)
    set_accepted_receipts_enabled(conn, rid, False)
    cli_mod._ensure_cli_tables(conn)
    return (
        SimpleNamespace(
            conn=conn,
            state_dir=tmp_path,
            keys_dir=tmp_path / "keys",
            identity_id=bob["identity_id"],
        ),
        rid,
        conn,
    )


def test_infra_operational_error_is_retry_pending_not_quarantine(
    tmp_path, monkeypatch
):
    """A storage-layer OperationalError (lock timeout, disk I/O) during
    receive must return retry_pending so the watcher leaves the object on
    the relay, never a terminal quarantine that deletes a peer's event we
    never stored."""
    import sqlite3

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    ctx, rid, conn = _ctx_for(tmp_path, alice, bob)

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(cli_mod, "_receive_object_inner", locked)
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, rid, _oname("oplock"), b"{}", acc)
    assert outcome["outcome"] == "retry_pending"
    # Nothing quarantined, nothing stored.
    assert conn.execute("SELECT COUNT(*) FROM receive_quarantine").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_infra_os_error_is_retry_pending(tmp_path, monkeypatch):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    ctx, rid, conn = _ctx_for(tmp_path, alice, bob)

    def io_fail(*args, **kwargs):
        raise OSError("disk I/O error")

    monkeypatch.setattr(cli_mod, "_receive_object_inner", io_fail)
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, rid, _oname("iofail"), b"{}", acc)
    assert outcome["outcome"] == "retry_pending"
    assert conn.execute("SELECT COUNT(*) FROM receive_quarantine").fetchone()[0] == 0


def test_hostile_input_still_quarantines_terminally(tmp_path):
    """Validation failures (bad signature bytes) stay terminal: the object
    is consumed so a hostile relay cannot wedge the watcher."""
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    ctx, rid, conn = _ctx_for(tmp_path, alice, bob)
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, rid, _oname("garbage"), b"not-json", acc)
    assert outcome["outcome"] == "quarantined"
    assert conn.execute("SELECT COUNT(*) FROM receive_quarantine").fetchone()[0] == 1


def test_future_created_at_is_terminally_quarantined(tmp_path):
    """created_at is not fully sender-controlled: the receive path bounds
    it against the recipient's clock. An event dated more than 5 minutes
    in the future is terminally quarantined. This is the other half of
    the time-capsule argument: a sender releasing a capsule early cannot
    satisfy both the capsule timing check and this clock bound."""
    from muse_agent_social.policy.limits import add_seconds
    from muse_agent_social.store.db import utcnow

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    ctx, rid, conn = _ctx_for(tmp_path, alice, bob)
    conv = new_conversation(conn)
    future = add_seconds(utcnow(), 600)
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "hello", "format": "plain"}, seq=1,
        created_at=future,
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, rid, _oname("futurets"), raw, acc)
    assert outcome["outcome"] == "quarantined"
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    reason = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()["reason"]
    assert reason == "clock_future"


def test_expired_window_is_terminally_quarantined(tmp_path):
    from muse_agent_social.policy.limits import add_seconds
    from muse_agent_social.store.db import utcnow

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    ctx, rid, conn = _ctx_for(tmp_path, alice, bob)
    conv = new_conversation(conn)
    old = add_seconds(utcnow(), -8 * 24 * 3600)
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "hello", "format": "plain"}, seq=1,
        created_at=old,
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, rid, _oname("oldts"), raw, acc)
    assert outcome["outcome"] == "quarantined"
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
