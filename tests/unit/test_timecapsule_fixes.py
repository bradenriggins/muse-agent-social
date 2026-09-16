"""Regression tests for scheduler/time-capsule findings S1-S6 and S8-S11.

S7 (receiver-side delivery idempotency and cancel authorization) is
covered in tests/unit/test_projections.py.
"""

from types import SimpleNamespace

import pytest

from muse_agent_social import cli as cli_mod
from muse_agent_social import scheduler
from muse_agent_social.policy.limits import add_seconds
from muse_agent_social.scheduler import (
    RevokedRelationshipError,
    SchedulerError,
    SendPausedError,
)
from muse_agent_social.store import db

NOW = "2026-09-15T20:00:00Z"
ENVELOPE = b'{"protected": {"event_id": "evt-inner-1"}}'
SENDER = "did:key:zTestSender000"


def _insert_event(conn, event_id, rid):
    conn.execute(
        "INSERT OR IGNORE INTO conversations (conversation_id) VALUES (?)",
        (rid,),
    )
    conn.execute(
        "INSERT INTO events (event_id, relationship_id, conversation_id,"
        " sender, sender_seq, created_at, key_epoch, event_type,"
        " replay_nonce, sealed_envelope)"
        " VALUES (?, ?, ?, ?, 1, ?, 1, 'message.created', ?, ?)",
        (event_id, rid, rid, SENDER, NOW, f"nonce-{event_id}", b"sealed"),
    )


def _fake_ctx(conn, tmp_path):
    return SimpleNamespace(conn=conn, keys_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# S1: revoked relationship must block release


class TestS1RevokedRelationshipBlocksRelease:
    def test_release_fn_refuses_revoked_relationship(
        self, conn, make_relationship, tmp_path
    ):
        rid = make_relationship(consent_state="revoked")
        sid = "11111111-1111-1111-1111-111111111111"
        _insert_event(conn, sid, rid)
        release_fn = cli_mod._release_fn(_fake_ctx(conn, tmp_path))
        with pytest.raises(RevokedRelationshipError):
            release_fn(
                conn,
                scheduled_id=sid,
                sealed_event_envelope=ENVELOPE,
                late_by_seconds=0,
            )

    def test_run_due_reports_skipped_revoked(self, conn):
        calls = []

        def gated(conn, *, scheduled_id, sealed_event_envelope, late_by_seconds):
            calls.append(scheduled_id)
            raise RevokedRelationshipError(scheduled_id)

        sid = scheduler.schedule(conn, ENVELOPE, NOW, None)
        summary = scheduler.run_due(conn, NOW, gated)
        assert summary["skipped_revoked"] == [sid]
        assert summary["released"] == []
        assert calls == [sid]
        row = scheduler.get_scheduled(conn, sid)
        assert row["state"] == "scheduled"
        assert row["release_failures"] == 0


# ---------------------------------------------------------------------------
# S2: rotation-deadline pause must gate release


class TestS2SendPausedGatesRelease:
    def _pause_rotation(self, conn, rid):
        conn.execute(
            "INSERT INTO key_rotations (relationship_id, epoch, role, phase,"
            " prepared_at, deadline)"
            " VALUES (?, 2, 'acking', 'acknowledged', ?, ?)",
            (rid, "2026-09-14T20:00:00Z", "2026-09-15T19:00:00Z"),
        )

    def test_release_fn_refuses_when_send_paused(
        self, conn, make_relationship, tmp_path
    ):
        rid = make_relationship()
        self._pause_rotation(conn, rid)
        sid = "22222222-2222-2222-2222-222222222222"
        _insert_event(conn, sid, rid)
        release_fn = cli_mod._release_fn(_fake_ctx(conn, tmp_path))
        with pytest.raises(SendPausedError):
            release_fn(
                conn,
                scheduled_id=sid,
                sealed_event_envelope=ENVELOPE,
                late_by_seconds=0,
            )

    def test_run_due_reports_skipped_paused(self, conn):
        def gated(conn, *, scheduled_id, sealed_event_envelope, late_by_seconds):
            raise SendPausedError(scheduled_id, "send_paused_acknowledged")

        sid = scheduler.schedule(conn, ENVELOPE, NOW, None)
        summary = scheduler.run_due(conn, NOW, gated)
        assert summary["skipped_paused"] == [sid]
        assert summary["released"] == []
        row = scheduler.get_scheduled(conn, sid)
        assert row["state"] == "scheduled"
        assert row["release_failures"] == 0


# ---------------------------------------------------------------------------
# S3/S4/S5: schedule-time delivery-window validation


class TestDeliveryWindowValidation:
    def test_s3_refuses_deliver_at_beyond_retention_horizon(self):
        with pytest.raises(cli_mod.CliError) as excinfo:
            cli_mod._validate_delivery_window(
                "2026-09-16T21:00:00Z", None, now=NOW
            )
        assert excinfo.value.code == "deliver_at_beyond_retention_horizon"

    def test_s4_scheduler_refuses_deliver_at_beyond_accept_window(self, conn):
        far = add_seconds(db.utcnow(), 8 * 24 * 3600)
        with pytest.raises(SchedulerError) as excinfo:
            scheduler.schedule(conn, ENVELOPE, far, None)
        assert excinfo.value.code == "deliver_at_beyond_accept_window"

    def test_s5_refuses_expires_not_after_deliver_at(self):
        with pytest.raises(cli_mod.CliError) as excinfo:
            cli_mod._validate_delivery_window(
                "2026-09-15T21:00:00Z", "2026-09-15T21:00:00Z", now=NOW
            )
        assert excinfo.value.code == "expires_not_after_deliver_at"

    def test_valid_window_passes(self):
        cli_mod._validate_delivery_window(
            "2026-09-15T21:00:00Z", "2026-09-15T22:00:00Z", now=NOW
        )
        cli_mod._validate_delivery_window(None, None, now=NOW)


# ---------------------------------------------------------------------------
# S6: late_by_seconds is observability, not a payload mutation


class TestS6LateIsObservabilityOnly:
    def test_late_release_reports_without_mutating_payload(self, conn):
        seen = {}

        def release_fn(conn, *, scheduled_id, sealed_event_envelope, late_by_seconds):
            seen["bytes"] = sealed_event_envelope
            seen["late"] = late_by_seconds

        sid = scheduler.schedule(conn, ENVELOPE, "2026-09-15T19:00:00Z", None)
        summary = scheduler.run_due(conn, NOW, release_fn)
        assert summary["released"] == [sid]
        assert summary["late"][sid] == 3600
        # The sealed bytes reach release_fn byte-identical: the scheduler
        # never amends the payload, so late_by_seconds lives only in the
        # run summary (and the receiver's deliveries projection).
        assert seen["bytes"] == ENVELOPE
        assert seen["late"] == 3600


# ---------------------------------------------------------------------------
# S8: dead-letter/expiry restores the approval and notifies


def _consumed_approval(conn, approval_id, rid):
    # Times are live: approval restoration checks the TTL against the
    # real clock, so the fixture approval must be unexpired right now.
    created = add_seconds(db.utcnow(), -1800)
    expires = add_seconds(db.utcnow(), 3600)
    consumed = add_seconds(db.utcnow(), -600)
    conn.execute(
        "INSERT INTO human_approvals (approval_id, relationship_id,"
        " subject_type, subject_id, answer, approved, created_at,"
        " expires_at, consumed_at)"
        " VALUES (?, ?, 'poll', 'poll-1', 'yes', 1, ?, ?, ?)",
        (approval_id, rid, created, expires, consumed),
    )


class TestS8ApprovalRestoration:
    def test_expiry_restores_approval_and_notifies(
        self, conn, make_relationship
    ):
        rid = make_relationship()
        sid = "33333333-3333-3333-3333-333333333333"
        _insert_event(conn, sid, rid)
        scheduler.schedule(
            conn,
            ENVELOPE,
            "2026-09-15T18:00:00Z",
            "2026-09-15T19:00:00Z",
            scheduled_id=sid,
        )
        approval_id = "approval-s8-expiry"
        _consumed_approval(conn, approval_id, rid)
        conn.execute(
            "UPDATE scheduler_queue SET approval_id = ? WHERE scheduled_id = ?",
            (approval_id, sid),
        )
        summary = scheduler.run_due(conn, NOW, lambda **kwargs: None)
        assert summary["expired"] == [sid]
        consumed = conn.execute(
            "SELECT consumed_at FROM human_approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()["consumed_at"]
        assert consumed is None
        note = conn.execute(
            "SELECT policy_snapshot FROM surface_queue WHERE event_id = ?",
            (sid,),
        ).fetchone()
        assert note is not None
        assert "approval_restored" in note["policy_snapshot"]

    def test_dead_letter_restores_approval_and_notifies(
        self, conn, make_relationship
    ):
        rid = make_relationship()
        sid = "44444444-4444-4444-4444-444444444444"
        _insert_event(conn, sid, rid)
        scheduler.schedule(conn, ENVELOPE, NOW, None, scheduled_id=sid)
        approval_id = "approval-s8-dead"
        _consumed_approval(conn, approval_id, rid)
        conn.execute(
            "UPDATE scheduler_queue SET approval_id = ? WHERE scheduled_id = ?",
            (approval_id, sid),
        )

        def failing(conn, *, scheduled_id, sealed_event_envelope, late_by_seconds):
            raise RuntimeError("transport down")

        for _ in range(3):
            summary = scheduler.run_due(conn, NOW, failing)
        assert summary["dead"] == [sid]
        consumed = conn.execute(
            "SELECT consumed_at FROM human_approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()["consumed_at"]
        assert consumed is None
        note = conn.execute(
            "SELECT policy_snapshot FROM surface_queue WHERE event_id = ?",
            (sid,),
        ).fetchone()
        assert note is not None
        assert "approval_restored" in note["policy_snapshot"]


# ---------------------------------------------------------------------------
# S9: semantic dry-run rejects before persist/approval claim


class TestS9SemanticDryRun:
    def test_rejects_invalid_event_before_persist(self, conn, make_relationship):
        import uuid

        rid = make_relationship()
        poll_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO polls (poll_id, relationship_id, conversation_id,"
            " sender, created_at, question, choices, closes_at, multi_select)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (
                poll_id, rid, rid, SENDER, NOW, "q?",
                '["a", "b"]', "2026-09-16T20:00:00Z",
            ),
        )
        event_id = str(uuid.uuid4())
        protected = {
            "event_id": event_id,
            "relationship_id": rid,
            "conversation_id": rid,
            "thread_id": None,
            "sender": SENDER,
            "created_at": NOW,
            "key_epoch": 1,
        }
        payload = {"poll_id": poll_id, "choice_ids": ["zzz"]}
        ctx = SimpleNamespace(conn=conn)
        with pytest.raises(cli_mod.CliError) as excinfo:
            cli_mod._semantic_dry_run(
                ctx, protected, "poll.responded", payload, None
            )
        assert "semantic validation failed before persist" in excinfo.value.message
        # Nothing was persisted: no staged payload, no poll response, and
        # the savepoint was rolled back (no open transaction).
        assert (
            conn.execute(
                "SELECT 1 FROM event_payloads WHERE event_id = ?", (event_id,)
            ).fetchone()
            is None
        )
        assert (
            conn.execute(
                "SELECT 1 FROM poll_responses WHERE poll_id = ?", (poll_id,)
            ).fetchone()
            is None
        )
        assert not conn.in_transaction


# ---------------------------------------------------------------------------
# S11: expiry transitions are warned about


class TestS11ExpiryWarning:
    def test_run_due_reports_newly_expired(self, conn):
        sid = scheduler.schedule(
            conn, ENVELOPE, "2026-09-15T18:00:00Z", "2026-09-15T19:00:00Z"
        )
        summary = scheduler.run_due(conn, NOW, lambda **kwargs: None)
        assert summary["expired"] == [sid]

    def test_warn_expired_by_run_due_prints(self, capsys):
        cli_mod._warn_expired_by_run_due(
            {"expired": ["sid-1", "sid-2"], "released": []}
        )
        err = capsys.readouterr().err
        assert "2 scheduled event(s) expired without delivery" in err

    def test_warn_expired_by_run_due_quiet_when_none(self, capsys):
        cli_mod._warn_expired_by_run_due({"expired": [], "released": []})
        assert capsys.readouterr().err == ""
