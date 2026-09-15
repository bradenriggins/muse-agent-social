"""Gate: Scheduler.

Due release, future deferral, expiry (explicit and default 24h late
window), release_fn failure rollback with safe retry, idempotent double
run_due, cancel semantics (idempotent cancel, cancel-after-release
rejection), schedule idempotency on scheduled_id, conflicting-id
rejection, and clock-skew blocking.
"""

from datetime import datetime, timedelta, timezone

import pytest

from muse_agent_social.policy.limits import (
    FUTURE_TOLERANCE_SECONDS,
    format_canonical_utc,
)
from muse_agent_social.scheduler import (
    AlreadyReleasedError,
    ScheduledIdConflictError,
    SchedulerError,
    UnknownScheduledIdError,
    cancel,
    get_scheduled,
    list_scheduled,
    request_retraction_after_release,
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


@pytest.fixture()
def sched(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "77777777-8888-4999-8000-111111111111"
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
        "message.created", {"body": "scheduled hello", "format": "plain"},
        seq=1,
    )
    t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
    calls = []

    def release_fn(conn, *, scheduled_id, sealed_event_envelope,
                   late_by_seconds):
        calls.append((scheduled_id, late_by_seconds))
        # Idempotent enqueue keyed on scheduled_id, as the contract
        # requires of the real release_fn.
        conn.execute(
            "INSERT OR IGNORE INTO test_outbox(scheduled_id, envelope,"
            " late_by_seconds) VALUES (?, ?, ?)",
            (scheduled_id, bytes(sealed_event_envelope), late_by_seconds),
        )

    return {
        "conn": conn, "raw": raw, "t0": t0, "calls": calls,
        "release_fn": release_fn,
    }


def _ts(dt):
    return format_canonical_utc(dt)


def test_due_event_released_exactly_once(sched):
    conn, t0 = sched["conn"], sched["t0"]
    sid = schedule(conn, sched["raw"], _ts(t0 - timedelta(minutes=1)), None)
    summary = run_due(conn, _ts(t0), sched["release_fn"])
    assert summary["released"] == [sid]
    assert summary["expired"] == []
    assert get_scheduled(conn, sid)["state"] == "released"
    assert sched["calls"] == [(sid, 60)]
    # A second run releases nothing: exactly-once.
    summary2 = run_due(conn, _ts(t0), sched["release_fn"])
    assert summary2["released"] == []
    assert sched["calls"] == [(sid, 60)]
    assert conn.execute("SELECT COUNT(*) FROM test_outbox").fetchone()[0] == 1


def test_future_event_not_released(sched):
    conn, t0 = sched["conn"], sched["t0"]
    sid = schedule(conn, sched["raw"], _ts(t0 + timedelta(hours=1)), None)
    summary = run_due(conn, _ts(t0), sched["release_fn"])
    assert summary["released"] == []
    assert sched["calls"] == []
    assert get_scheduled(conn, sid)["state"] == "scheduled"


def test_expired_event_never_released(sched):
    conn, t0 = sched["conn"], sched["t0"]
    sid = schedule(
        conn, sched["raw"],
        _ts(t0 - timedelta(hours=2)), _ts(t0 - timedelta(hours=1)),
    )
    summary = run_due(conn, _ts(t0), sched["release_fn"])
    assert summary["expired"] == [sid]
    assert summary["released"] == []
    assert sched["calls"] == []
    assert get_scheduled(conn, sid)["state"] == "expired"


def test_default_24h_late_window_expires(sched):
    conn, t0 = sched["conn"], sched["t0"]
    sid = schedule(conn, sched["raw"], _ts(t0 - timedelta(hours=25)), None)
    summary = run_due(conn, _ts(t0), sched["release_fn"])
    assert summary["expired"] == [sid]
    assert sched["calls"] == []


def test_late_but_within_window_released_with_late_by(sched):
    conn, t0 = sched["conn"], sched["t0"]
    sid = schedule(conn, sched["raw"], _ts(t0 - timedelta(hours=2)), None)
    summary = run_due(conn, _ts(t0), sched["release_fn"])
    assert summary["released"] == [sid]
    assert summary["late"][sid] == 7200
    assert sched["calls"] == [(sid, 7200)]


def test_release_fn_failure_rolls_back_and_retry_succeeds(sched):
    """A release_fn crash rolls the claim back; the row stays scheduled
    and a later run releases exactly once."""
    conn, t0 = sched["conn"], sched["t0"]
    sid = schedule(conn, sched["raw"], _ts(t0 - timedelta(minutes=1)), None)

    def boom(conn, **kw):
        raise RuntimeError("outgoing queue unavailable")

    with pytest.raises(RuntimeError):
        run_due(conn, _ts(t0), boom)
    assert get_scheduled(conn, sid)["state"] == "scheduled"
    assert conn.execute("SELECT COUNT(*) FROM test_outbox").fetchone()[0] == 0

    summary = run_due(conn, _ts(t0), sched["release_fn"])
    assert summary["released"] == [sid]
    assert sched["calls"] == [(sid, 60)]


def test_cancel_before_release(sched):
    conn, t0 = sched["conn"], sched["t0"]
    sid = schedule(conn, sched["raw"], _ts(t0 + timedelta(hours=1)), None)
    assert cancel(conn, sid) == "canceled"
    assert cancel(conn, sid) == "canceled"  # idempotent
    summary = run_due(conn, _ts(t0 + timedelta(hours=2)), sched["release_fn"])
    assert summary["released"] == []
    assert sched["calls"] == []


def test_cancel_after_release_rejected(sched):
    conn, t0 = sched["conn"], sched["t0"]
    sid = schedule(conn, sched["raw"], _ts(t0 - timedelta(minutes=1)), None)
    run_due(conn, _ts(t0), sched["release_fn"])
    with pytest.raises(AlreadyReleasedError):
        cancel(conn, sid)
    note = request_retraction_after_release(conn, sid)
    assert note["action"] == "request_retraction"
    assert note["scheduled_id"] == sid
    assert bytes(note["sealed_event_envelope"]) == bytes(sched["raw"])


def test_cancel_unknown_raises(sched):
    with pytest.raises(UnknownScheduledIdError):
        cancel(sched["conn"], "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")


def test_schedule_idempotent_on_same_id_and_bytes(sched):
    conn, t0 = sched["conn"], sched["t0"]
    sid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    first = schedule(conn, sched["raw"], _ts(t0 + timedelta(hours=1)), None,
                     scheduled_id=sid)
    second = schedule(conn, sched["raw"], _ts(t0 + timedelta(hours=1)), None,
                      scheduled_id=sid)
    assert first == second == sid
    assert len(list_scheduled(conn)) == 1


def test_schedule_conflicting_id_rejected(sched):
    conn, t0 = sched["conn"], sched["t0"]
    sid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    schedule(conn, sched["raw"], _ts(t0 + timedelta(hours=1)), None,
             scheduled_id=sid)
    with pytest.raises(ScheduledIdConflictError):
        schedule(conn, b'{"different": true}', _ts(t0 + timedelta(hours=1)),
                 None, scheduled_id=sid)


def test_schedule_rejects_bad_timestamps(sched):
    conn, t0 = sched["conn"], sched["t0"]
    with pytest.raises(SchedulerError):
        schedule(conn, sched["raw"], "not-a-timestamp", None)
    with pytest.raises(SchedulerError) as exc:
        schedule(conn, sched["raw"], _ts(t0 + timedelta(hours=2)),
                 _ts(t0 + timedelta(hours=1)))
    assert exc.value.code == "expires_not_after_deliver_at"


def test_schedule_rejects_oversize_envelope(sched):
    conn, t0 = sched["conn"], sched["t0"]
    with pytest.raises(SchedulerError) as exc:
        schedule(conn, b"x" * (262144 + 1), _ts(t0 + timedelta(hours=1)), None)
    assert exc.value.code == "envelope_too_large"


def test_clock_skew_blocks_scheduled_send(sched):
    conn, t0 = sched["conn"], sched["t0"]
    with pytest.raises(SchedulerError) as exc:
        schedule(conn, sched["raw"], _ts(t0 + timedelta(hours=1)), None,
                 clock_skew_seconds=float(FUTURE_TOLERANCE_SECONDS))
    assert exc.value.code == "clock_skew_blocks_scheduled_send"
    sid = schedule(conn, sched["raw"], _ts(t0 - timedelta(minutes=1)), None)
    with pytest.raises(SchedulerError) as exc:
        run_due(conn, _ts(t0), sched["release_fn"],
                clock_skew_seconds=float(FUTURE_TOLERANCE_SECONDS) + 1)
    assert exc.value.code == "clock_skew_blocks_scheduled_send"
    assert get_scheduled(conn, sid)["state"] == "scheduled"
