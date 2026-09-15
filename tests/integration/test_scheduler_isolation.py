"""Gate: scheduler per-row isolation (H6).

One poison row (release_fn raises) must not wedge every send: each due
row is processed in its own transaction, failures are counted per row,
and a row that fails MAX_RELEASE_ATTEMPTS times moves to the dead-letter
state and stops being attempted. Good rows release normally throughout.
"""

from datetime import datetime, timedelta, timezone

from muse_agent_social.scheduler import (
    MAX_RELEASE_ATTEMPTS,
    get_scheduled,
    list_scheduled,
    run_due,
    schedule,
)

from support.harness import (
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)

UTC = timezone.utc


def _ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _fixture(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "99999999-1111-4222-8333-444444444444"
    provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS test_outbox("
        " scheduled_id TEXT PRIMARY KEY, envelope BLOB NOT NULL,"
        " late_by_seconds INTEGER NOT NULL)"
    )
    conn.commit()
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "hello", "format": "plain"}, seq=1,
    )
    t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
    return {"conn": conn, "raw": raw, "t0": t0}


def test_poison_row_isolated_and_dead_letters(tmp_path):
    fx = _fixture(tmp_path)
    conn, t0, raw = fx["conn"], fx["t0"], fx["raw"]
    due = _ts(t0 - timedelta(minutes=1))
    good = schedule(conn, raw, due, None)
    poison = schedule(conn, raw, due, None)

    released = []

    def release_fn(conn, *, scheduled_id, sealed_event_envelope,
                   late_by_seconds):
        if scheduled_id == poison:
            raise RuntimeError("relay config broken")
        released.append(scheduled_id)
        conn.execute(
            "INSERT OR IGNORE INTO test_outbox(scheduled_id, envelope,"
            " late_by_seconds) VALUES (?, ?, ?)",
            (scheduled_id, bytes(sealed_event_envelope), late_by_seconds),
        )

    # Run 1: the good row releases; the poison row fails in isolation and
    # run_due does NOT propagate the exception.
    summary = run_due(conn, _ts(t0), release_fn)
    assert summary["released"] == [good]
    assert summary["failed"] == [poison]
    assert released == [good]
    assert get_scheduled(conn, good)["state"] == "released"
    assert get_scheduled(conn, poison)["state"] == "scheduled"

    # Runs 2..N-1: the poison row keeps failing without blocking anything.
    for _ in range(MAX_RELEASE_ATTEMPTS - 2):
        summary = run_due(conn, _ts(t0), release_fn)
        assert summary["released"] == []
        assert summary["failed"] == [poison]
        assert get_scheduled(conn, poison)["state"] == "scheduled"

    # Run N: the poison row dead-letters and stops being attempted.
    summary = run_due(conn, _ts(t0), release_fn)
    assert summary["dead"] == [poison]
    assert get_scheduled(conn, poison)["state"] == "dead"

    # Later runs never touch the dead row again.
    summary = run_due(conn, _ts(t0), release_fn)
    assert summary["failed"] == []
    assert summary["dead"] == []

    # Sends for other relationships keep working throughout: a fresh row
    # scheduled after the poisoning releases normally.
    fresh = schedule(conn, raw, due, None)
    summary = run_due(conn, _ts(t0), release_fn)
    assert summary["released"] == [fresh]
    assert released == [good, fresh]

    # Dead-lettered rows are listed by the inspect surface.
    dead = list_scheduled(conn, "dead")
    assert [r["scheduled_id"] for r in dead] == [poison]


def test_failure_counter_resets_only_on_success(tmp_path):
    """A row that fails twice then succeeds never dead-letters."""
    fx = _fixture(tmp_path)
    conn, t0, raw = fx["conn"], fx["t0"], fx["raw"]
    sid = schedule(conn, raw, _ts(t0 - timedelta(minutes=1)), None)
    attempts = []

    def flaky(conn, *, scheduled_id, sealed_event_envelope, late_by_seconds):
        attempts.append(scheduled_id)
        if len(attempts) < 3:
            raise RuntimeError("transient")
        conn.execute(
            "INSERT OR IGNORE INTO test_outbox(scheduled_id, envelope,"
            " late_by_seconds) VALUES (?, ?, ?)",
            (scheduled_id, bytes(sealed_event_envelope), late_by_seconds),
        )

    assert run_due(conn, _ts(t0), flaky)["failed"] == [sid]
    assert run_due(conn, _ts(t0), flaky)["failed"] == [sid]
    summary = run_due(conn, _ts(t0), flaky)
    assert summary["released"] == [sid]
    assert summary["dead"] == []
    assert get_scheduled(conn, sid)["state"] == "released"
