"""Unit tests for the sender-side scheduled-delivery scheduler.

Covers: schedule stores locally and never uploads, cancel-before-release
is final, cancel-after-release becomes a retraction request, late release
marks late_by_seconds, expiry blocks release, the 24h default late
window, and exactly-once release across a simulated restart.
"""

import pytest

from muse_agent_social import scheduler
from muse_agent_social.scheduler import (
    AlreadyReleasedError,
    InvalidSchedulerTransition,
    ScheduledIdConflictError,
    SchedulerError,
    UnknownScheduledIdError,
)
from muse_agent_social.store import db


NOW = "2026-09-15T20:00:00Z"
ENVELOPE = b'{"protected": {"event_id": "evt-inner-1"}}'


# ---------------------------------------------------------------------------
# helpers


@pytest.fixture
def outbox(conn):
    conn.execute(
        "CREATE TABLE test_outbox ("
        " scheduled_id TEXT PRIMARY KEY,"
        " envelope BLOB NOT NULL,"
        " late_by INTEGER NOT NULL)"
    )
    return "test_outbox"


def make_releaser(calls, fail_first=False):
    state = {"calls": 0}

    def release_fn(conn, *, scheduled_id, sealed_event_envelope, late_by_seconds):
        state["calls"] += 1
        calls.append(
            {
                "scheduled_id": scheduled_id,
                "late_by_seconds": late_by_seconds,
                "bytes": sealed_event_envelope,
            }
        )
        if fail_first and state["calls"] == 1:
            raise RuntimeError("boom: transport down")
        conn.execute(
            "INSERT INTO test_outbox (scheduled_id, envelope, late_by)"
            " VALUES (?, ?, ?)",
            (scheduled_id, sealed_event_envelope, late_by_seconds),
        )

    return release_fn


def outbox_rows(conn):
    return conn.execute(
        "SELECT scheduled_id, late_by FROM test_outbox ORDER BY scheduled_id"
    ).fetchall()


# ---------------------------------------------------------------------------
# schedule


class TestSchedule:
    def test_schedule_stores_locally(self, conn):
        sid = scheduler.schedule(
            conn, ENVELOPE, "2026-09-16T20:00:00Z", None
        )
        row = scheduler.get_scheduled(conn, sid)
        assert row["scheduled_id"] == sid
        assert row["inner_event"] == ENVELOPE
        assert row["deliver_at"] == "2026-09-16T20:00:00Z"
        assert row["expires_at"] is None
        assert row["state"] == "scheduled"

    def test_schedule_is_idempotent_on_id(self, conn):
        sid = scheduler.schedule(
            conn, ENVELOPE, "2026-09-16T20:00:00Z", None,
            scheduled_id="11111111-1111-1111-1111-111111111111",
        )
        again = scheduler.schedule(
            conn, ENVELOPE, "2026-09-16T20:00:00Z", None,
            scheduled_id="11111111-1111-1111-1111-111111111111",
        )
        assert again == sid
        assert len(scheduler.list_scheduled(conn)) == 1

    def test_schedule_conflicting_bytes_rejected(self, conn):
        sid = "22222222-2222-2222-2222-222222222222"
        scheduler.schedule(conn, ENVELOPE, "2026-09-16T20:00:00Z", None,
                           scheduled_id=sid)
        with pytest.raises(ScheduledIdConflictError) as excinfo:
            scheduler.schedule(
                conn, b"different", "2026-09-16T20:00:00Z", None,
                scheduled_id=sid,
            )
        assert excinfo.value.code == "scheduled_id_conflict"

    def test_schedule_rejects_bad_envelope(self, conn):
        with pytest.raises(SchedulerError):
            scheduler.schedule(conn, b"", "2026-09-16T20:00:00Z", None)
        with pytest.raises(SchedulerError):
            scheduler.schedule(
                conn, b"x" * (262144 + 1), "2026-09-16T20:00:00Z", None
            )
        with pytest.raises(SchedulerError):
            scheduler.schedule(
                conn, "not-bytes", "2026-09-16T20:00:00Z", None
            )

    def test_schedule_rejects_bad_timestamps(self, conn):
        with pytest.raises(SchedulerError) as excinfo:
            scheduler.schedule(conn, ENVELOPE, "tomorrow", None)
        assert excinfo.value.code == "invalid_timestamp"
        with pytest.raises(SchedulerError):
            scheduler.schedule(
                conn, ENVELOPE, "2026-09-16T20:00:00Z", "yesterday"
            )

    def test_schedule_rejects_expires_not_after_deliver_at(self, conn):
        with pytest.raises(SchedulerError) as excinfo:
            scheduler.schedule(
                conn,
                ENVELOPE,
                "2026-09-16T20:00:00Z",
                "2026-09-16T20:00:00Z",
            )
        assert excinfo.value.code == "expires_not_after_deliver_at"

    def test_schedule_rejects_invalid_provided_id(self, conn):
        with pytest.raises(SchedulerError):
            scheduler.schedule(
                conn, ENVELOPE, "2026-09-16T20:00:00Z", None,
                scheduled_id="NOT-A-UUID",
            )

    def test_schedule_blocked_by_clock_skew(self, conn):
        with pytest.raises(SchedulerError) as excinfo:
            scheduler.schedule(
                conn, ENVELOPE, "2026-09-16T20:00:00Z", None,
                clock_skew_seconds=301,
            )
        assert excinfo.value.code == "clock_skew_blocks_scheduled_send"
        assert scheduler.list_scheduled(conn) == []

    def test_get_unknown_returns_none(self, conn):
        assert scheduler.get_scheduled(conn, "33333333-3333-3333-3333-333333333333") is None

    def test_list_filter(self, conn):
        scheduler.schedule(conn, ENVELOPE, "2026-09-16T20:00:00Z", None,
                           scheduled_id="44444444-4444-4444-4444-444444444444")
        sid2 = scheduler.schedule(conn, ENVELOPE, "2026-09-17T20:00:00Z", None)
        scheduler.cancel(conn, sid2)
        assert len(scheduler.list_scheduled(conn)) == 2
        assert len(scheduler.list_scheduled(conn, "scheduled")) == 1
        assert len(scheduler.list_scheduled(conn, "canceled")) == 1
        with pytest.raises(SchedulerError):
            scheduler.list_scheduled(conn, "bogus")


# ---------------------------------------------------------------------------
# cancel


class TestCancel:
    def test_cancel_before_release_is_final(self, conn, outbox):
        sid = scheduler.schedule(conn, ENVELOPE, "2026-09-16T20:00:00Z", None)
        assert scheduler.cancel(conn, sid) == "canceled"
        assert scheduler.get_scheduled(conn, sid)["state"] == "canceled"
        calls = []
        summary = scheduler.run_due(conn, "2026-09-17T20:00:00Z",
                                    make_releaser(calls))
        assert summary["released"] == []
        assert calls == []
        assert outbox_rows(conn) == []

    def test_cancel_is_idempotent(self, conn):
        sid = scheduler.schedule(conn, ENVELOPE, "2026-09-16T20:00:00Z", None)
        assert scheduler.cancel(conn, sid) == "canceled"
        assert scheduler.cancel(conn, sid) == "canceled"

    def test_cancel_unknown_raises(self, conn):
        with pytest.raises(UnknownScheduledIdError) as excinfo:
            scheduler.cancel(conn, "55555555-5555-5555-5555-555555555555")
        assert excinfo.value.code == "unknown_scheduled_id"

    def test_cancel_after_release_raises(self, conn, outbox):
        sid = scheduler.schedule(conn, ENVELOPE, "2026-09-15T19:00:00Z", None)
        scheduler.run_due(conn, NOW, make_releaser([]))
        with pytest.raises(AlreadyReleasedError) as excinfo:
            scheduler.cancel(conn, sid)
        assert excinfo.value.code == "already_released"
        assert excinfo.value.scheduled_id == sid

    def test_cancel_expired_raises(self, conn):
        sid = scheduler.schedule(
            conn, ENVELOPE, "2026-09-15T18:00:00Z", "2026-09-15T19:00:00Z"
        )
        scheduler.run_due(conn, NOW, make_releaser([]))
        assert scheduler.get_scheduled(conn, sid)["state"] == "expired"
        with pytest.raises(InvalidSchedulerTransition):
            scheduler.cancel(conn, sid)


# ---------------------------------------------------------------------------
# retraction after release


class TestRetractionAfterRelease:
    def test_request_retraction_after_release(self, conn, outbox):
        sid = scheduler.schedule(conn, ENVELOPE, "2026-09-15T19:00:00Z", None)
        scheduler.run_due(conn, NOW, make_releaser([]))
        note = scheduler.request_retraction_after_release(conn, sid)
        assert note["action"] == "request_retraction"
        assert note["scheduled_id"] == sid
        assert note["sealed_event_envelope"] == ENVELOPE
        assert note["state"] == "released"
        assert "signed retraction" in note["note"]

    def test_request_retraction_before_release_raises(self, conn):
        sid = scheduler.schedule(conn, ENVELOPE, "2026-09-16T20:00:00Z", None)
        with pytest.raises(InvalidSchedulerTransition):
            scheduler.request_retraction_after_release(conn, sid)

    def test_request_retraction_unknown_raises(self, conn):
        with pytest.raises(UnknownScheduledIdError):
            scheduler.request_retraction_after_release(
                conn, "66666666-6666-6666-6666-666666666666"
            )


# ---------------------------------------------------------------------------
# run_due


class TestRunDue:
    def test_releases_due_event(self, conn, outbox):
        sid = scheduler.schedule(conn, ENVELOPE, "2026-09-15T19:00:00Z", None)
        calls = []
        summary = scheduler.run_due(conn, NOW, make_releaser(calls))
        assert summary["released"] == [sid]
        assert summary["expired"] == []
        assert summary["late"] == {sid: 3600}
        assert scheduler.get_scheduled(conn, sid)["state"] == "released"
        assert len(calls) == 1
        assert calls[0]["late_by_seconds"] == 3600
        assert calls[0]["bytes"] == ENVELOPE
        rows = outbox_rows(conn)
        assert len(rows) == 1
        assert rows[0]["late_by"] == 3600

    def test_on_time_release_has_zero_late_by(self, conn, outbox):
        sid = scheduler.schedule(conn, ENVELOPE, NOW, None)
        calls = []
        summary = scheduler.run_due(conn, NOW, make_releaser(calls))
        assert summary["released"] == [sid]
        assert summary["late"] == {}
        assert calls[0]["late_by_seconds"] == 0

    def test_not_due_not_released(self, conn, outbox):
        sid = scheduler.schedule(conn, ENVELOPE, "2026-09-16T20:00:00Z", None)
        calls = []
        summary = scheduler.run_due(conn, NOW, make_releaser(calls))
        assert summary["released"] == []
        assert calls == []
        assert scheduler.get_scheduled(conn, sid)["state"] == "scheduled"

    def test_exactly_once_across_restart(self, conn, db_path, outbox):
        sid = scheduler.schedule(conn, ENVELOPE, "2026-09-15T19:00:00Z", None)
        calls = []
        first = scheduler.run_due(conn, NOW, make_releaser(calls))
        assert first["released"] == [sid]
        conn.close()
        restarted = db.connect(db_path)
        try:
            calls2 = []
            second = scheduler.run_due(restarted, NOW, make_releaser(calls2))
            assert second["released"] == []
            assert second["expired"] == []
            assert calls2 == []
            rows = restarted.execute(
                "SELECT scheduled_id FROM test_outbox"
            ).fetchall()
            assert len(rows) == 1
            assert restarted.execute(
                "SELECT state FROM scheduler_queue WHERE scheduled_id = ?",
                (sid,),
            ).fetchone()["state"] == "released"
        finally:
            restarted.close()

    def test_release_fn_failure_rolls_back(self, conn, outbox):
        sid = scheduler.schedule(conn, ENVELOPE, "2026-09-15T19:00:00Z", None)
        calls = []
        # Per-row isolation (H6): the release_fn exception is contained
        # and recorded against the row, never propagated.
        summary = scheduler.run_due(conn, NOW, make_releaser(calls, fail_first=True))
        assert summary["released"] == []
        assert summary["failed"] == [sid]
        assert scheduler.get_scheduled(conn, sid)["state"] == "scheduled"
        assert outbox_rows(conn) == []
        summary = scheduler.run_due(conn, NOW, make_releaser(calls))
        assert summary["released"] == [sid]
        assert len(outbox_rows(conn)) == 1

    def test_late_release_marks_late_by_seconds(self, conn, outbox):
        sid = scheduler.schedule(
            conn, ENVELOPE, "2026-09-15T17:00:00Z", "2026-09-16T20:00:00Z"
        )
        calls = []
        summary = scheduler.run_due(conn, NOW, make_releaser(calls))
        assert summary["released"] == [sid]
        assert summary["late"][sid] == 3 * 3600
        assert calls[0]["late_by_seconds"] == 3 * 3600

    def test_expiry_blocks_release(self, conn, outbox):
        sid = scheduler.schedule(
            conn, ENVELOPE, "2026-09-15T18:00:00Z", "2026-09-15T19:00:00Z"
        )
        calls = []
        summary = scheduler.run_due(conn, NOW, make_releaser(calls))
        assert summary["released"] == []
        assert summary["expired"] == [sid]
        assert calls == []
        assert outbox_rows(conn) == []
        assert scheduler.get_scheduled(conn, sid)["state"] == "expired"

    def test_default_24h_late_window(self, conn, outbox):
        old = scheduler.schedule(conn, ENVELOPE, "2026-09-14T19:00:00Z", None)
        recent = scheduler.schedule(conn, ENVELOPE, "2026-09-14T21:00:00Z", None)
        calls = []
        summary = scheduler.run_due(conn, NOW, make_releaser(calls))
        assert summary["expired"] == [old]
        assert summary["released"] == [recent]
        assert summary["late"][recent] == 23 * 3600
        assert scheduler.get_scheduled(conn, old)["state"] == "expired"
        assert scheduler.get_scheduled(conn, recent)["state"] == "released"

    def test_run_due_blocked_by_clock_skew(self, conn, outbox):
        scheduler.schedule(conn, ENVELOPE, "2026-09-15T19:00:00Z", None)
        with pytest.raises(SchedulerError) as excinfo:
            scheduler.run_due(conn, NOW, make_releaser([]),
                               clock_skew_seconds=300)
        assert excinfo.value.code == "clock_skew_blocks_scheduled_send"

    def test_run_due_rejects_bad_now(self, conn):
        with pytest.raises(SchedulerError):
            scheduler.run_due(conn, "not-a-time", make_releaser([]))

    def test_releases_in_deliver_at_order(self, conn, outbox):
        first = scheduler.schedule(conn, ENVELOPE, "2026-09-15T18:00:00Z", None)
        second = scheduler.schedule(conn, ENVELOPE, "2026-09-15T19:00:00Z", None)
        calls = []
        summary = scheduler.run_due(conn, NOW, make_releaser(calls))
        assert summary["released"] == [first, second]


# ---------------------------------------------------------------------------
# schedule() same-ID concurrency
# ---------------------------------------------------------------------------


class TestScheduleConcurrency:
    def test_concurrent_same_id_same_bytes_is_idempotent(self, db_path):
        """Two threads racing schedule() with the same id and bytes.

        The dedup check and INSERT share one BEGIN IMMEDIATE transaction,
        so exactly one row exists and both callers get the id back (no
        leaked sqlite3.IntegrityError, no duplicate row).
        """
        import threading

        from muse_agent_social.store import migrations

        seed = db.connect(db_path)
        migrations.migrate(seed)
        seed.close()

        sid = "11111111-1111-4111-8111-111111111111"
        deliver = "2026-09-15T21:00:00Z"
        results = []
        barrier = threading.Barrier(2)

        def worker():
            c = db.connect(db_path)
            try:
                barrier.wait(timeout=10)
                rid = scheduler.schedule(c, ENVELOPE, deliver, None, scheduled_id=sid)
                results.append(("ok", rid))
            except Exception as exc:  # noqa: BLE001
                results.append(("error", type(exc).__name__, getattr(exc, "code", "")))
            finally:
                c.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(results) == 2
        assert all(r[0] == "ok" and r[1] == sid for r in results), results
        check = db.connect(db_path)
        try:
            rows = check.execute(
                "SELECT COUNT(*) FROM scheduler_queue WHERE scheduled_id = ?;",
                (sid,),
            ).fetchone()[0]
            assert rows == 1
        finally:
            check.close()

    def test_concurrent_same_id_conflicting_bytes_rejected(self, db_path):
        """Same id, different bytes: exactly one caller wins; the loser
        gets ScheduledIdConflictError, never a raw IntegrityError."""
        import threading

        from muse_agent_social.store import migrations

        seed = db.connect(db_path)
        migrations.migrate(seed)
        seed.close()

        sid = "22222222-2222-4222-8222-222222222222"
        deliver = "2026-09-15T21:00:00Z"
        other = b'{"protected": {"event_id": "evt-inner-2"}}'
        results = []
        barrier = threading.Barrier(2)

        def worker(payload):
            c = db.connect(db_path)
            try:
                barrier.wait(timeout=10)
                rid = scheduler.schedule(c, payload, deliver, None, scheduled_id=sid)
                results.append(("ok", rid))
            except ScheduledIdConflictError as exc:
                results.append(("conflict", exc.code))
            except Exception as exc:  # noqa: BLE001
                results.append(("error", type(exc).__name__, getattr(exc, "code", "")))
            finally:
                c.close()

        threads = [
            threading.Thread(target=worker, args=(ENVELOPE,)),
            threading.Thread(target=worker, args=(other,)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        kinds = sorted(r[0] for r in results)
        assert kinds == ["conflict", "ok"], results
        check = db.connect(db_path)
        try:
            rows = check.execute(
                "SELECT COUNT(*) FROM scheduler_queue WHERE scheduled_id = ?;",
                (sid,),
            ).fetchone()[0]
            assert rows == 1
        finally:
            check.close()

    def test_ensure_dead_letter_schema_concurrent_first_run(self, db_path):
        """Four threads racing the first-ever _ensure_dead_letter_schema on
        a fresh DB: the check-then-ALTER must converge instead of losers
        dying with 'duplicate column name'. (SQLite has no ADD COLUMN IF
        NOT EXISTS, so the race is absorbed in code.)"""
        import threading

        from muse_agent_social.store import migrations

        seed = db.connect(db_path)
        migrations.migrate(seed)
        seed.close()

        barrier = threading.Barrier(8)
        errors = []

        def worker():
            c = db.connect(db_path)
            try:
                barrier.wait(timeout=10)
                scheduler._ensure_dead_letter_schema(c)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
            finally:
                c.close()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors, [str(e) for e in errors]
        check = db.connect(db_path)
        try:
            cols = [
                r["name"]
                for r in check.execute("PRAGMA table_info(scheduler_queue);")
            ]
            assert "release_failures" in cols
        finally:
            check.close()
