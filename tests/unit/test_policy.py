"""Unit tests for delivery policy, retention policy, and limits.

Covers: every delivery mode's surface behavior, receiver-only policy
mutation (remote attempts rejected), seen-receipt default off, plaintext
opt-in periods and immediate delete, expiry honor/ignore/shorten, and
the limits constants and checkers.
"""

import json
import os

import pytest

from muse_agent_social.policy import delivery, limits, retention
from muse_agent_social.policy.delivery import (
    DeliveryPolicy,
    ExpiryDecision,
    PolicyError,
    RemotePolicyChangeRejected,
    UnknownRelationshipError,
)
from muse_agent_social.policy.retention import RetentionError
from muse_agent_social.store import db


# ---------------------------------------------------------------------------
# helpers


def make_event(conn, relationship_id, event_id, sender="did:key:zSender", seq=1):
    conn.execute(
        "INSERT OR IGNORE INTO conversations (conversation_id) VALUES ('conv-1')"
    )
    conn.execute(
        "INSERT INTO events (event_id, relationship_id, conversation_id,"
        " thread_id, sender, sender_seq, created_at, key_epoch, event_type,"
        " replay_nonce, sealed_envelope)"
        " VALUES (?, ?, 'conv-1', NULL, ?, ?, ?, 1, 'message.created', ?, ?)",
        (
            event_id,
            relationship_id,
            sender,
            seq,
            "2026-09-15T19:00:00Z",
            f"nonce-{event_id}",
            b"sealed-bytes",
        ),
    )
    return event_id


NOW = "2026-09-15T20:00:00Z"


# ---------------------------------------------------------------------------
# delivery defaults


class TestDeliveryDefaults:
    def test_default_policy_is_silent_version_zero(self, conn, make_relationship):
        rid = make_relationship()
        policy = delivery.get_policy(conn, rid)
        assert isinstance(policy, DeliveryPolicy)
        assert policy.mode == "silent"
        assert policy.version == 0
        assert policy.updated_at is None
        assert policy.seen_receipts_enabled is False
        assert policy.accepted_receipts_enabled is True
        assert policy.expiry_handling == "honor"

    def test_unknown_relationship_raises(self, conn):
        with pytest.raises(UnknownRelationshipError) as excinfo:
            delivery.get_policy(conn, "rel-nope")
        assert excinfo.value.code == "unknown_relationship"

    def test_set_policy_unknown_relationship_raises(self, conn):
        with pytest.raises(UnknownRelationshipError):
            delivery.set_policy(conn, "rel-nope", "alert")


# ---------------------------------------------------------------------------
# set_policy


class TestSetPolicy:
    @pytest.mark.parametrize(
        "mode", ["silent", "digest", "alert", "feed_eligible"]
    )
    def test_set_each_mode(self, conn, make_relationship, mode):
        rid = make_relationship()
        updated = delivery.set_policy(conn, rid, mode)
        assert updated.mode == mode
        assert updated.version == 1
        assert updated.updated_at is not None
        assert delivery.get_policy(conn, rid).mode == mode

    def test_version_increments(self, conn, make_relationship):
        rid = make_relationship()
        assert delivery.set_policy(conn, rid, "alert").version == 1
        assert delivery.set_policy(conn, rid, "digest").version == 2
        assert delivery.get_policy(conn, rid).version == 2

    def test_invalid_mode_rejected(self, conn, make_relationship):
        rid = make_relationship()
        with pytest.raises(PolicyError) as excinfo:
            delivery.set_policy(conn, rid, "loud")
        assert excinfo.value.code == "invalid_delivery_mode"
        assert delivery.get_policy(conn, rid).mode == "silent"

    def test_seen_and_accepted_toggles_bump_version(self, conn, make_relationship):
        rid = make_relationship()
        assert delivery.set_seen_receipts_enabled(conn, rid, True).version == 1
        assert delivery.get_policy(conn, rid).seen_receipts_enabled is True
        assert delivery.set_accepted_receipts_enabled(conn, rid, False).version == 2
        assert delivery.accepted_receipt_permitted(conn, rid) is False

    def test_set_expiry_policy_validation(self, conn, make_relationship):
        rid = make_relationship()
        updated = delivery.set_expiry_policy(conn, rid, "shorten", 3600)
        assert updated.expiry_handling == "shorten"
        assert updated.expiry_shorten_after_seconds == 3600
        with pytest.raises(PolicyError):
            delivery.set_expiry_policy(conn, rid, "shorten", 0)
        with pytest.raises(PolicyError):
            delivery.set_expiry_policy(conn, rid, "shorten", None)
        with pytest.raises(PolicyError):
            delivery.set_expiry_policy(conn, rid, "honor", 60)
        with pytest.raises(PolicyError):
            delivery.set_expiry_policy(conn, rid, "eventually")


# ---------------------------------------------------------------------------
# surface behavior per mode


class TestSurfaceBehavior:
    EXPECTED = {
        "silent": "persist_only",
        "digest": "queue_digest",
        "alert": "surface_promptly",
        "feed_eligible": "consider_feed",
    }

    @pytest.mark.parametrize("mode,action", list(EXPECTED.items()))
    def test_surface_action_mapping(self, mode, action):
        assert delivery.surface_action(mode) == action

    def test_surface_action_invalid_mode(self):
        with pytest.raises(PolicyError) as excinfo:
            delivery.surface_action("party")
        assert excinfo.value.code == "invalid_delivery_mode"

    @pytest.mark.parametrize("mode,action", list(EXPECTED.items()))
    def test_snapshot_round_trip_carries_version(
        self, conn, make_relationship, mode, action
    ):
        rid = make_relationship()
        delivery.set_policy(conn, rid, mode)
        delivery.set_policy(conn, rid, mode)
        snapshot = delivery.policy_snapshot(conn, rid)
        assert snapshot["mode"] == mode
        assert snapshot["version"] == 2
        assert delivery.snapshot_to_action(snapshot) == action

    def test_snapshot_is_json_serializable(self, conn, make_relationship):
        rid = make_relationship()
        delivery.set_policy(conn, rid, "digest")
        json.dumps(delivery.policy_snapshot(conn, rid))

    def test_corrupt_snapshot_fails_closed(self):
        assert delivery.snapshot_to_action({}) == "persist_only"
        assert delivery.snapshot_to_action({"mode": "bogus"}) == "persist_only"
        assert delivery.snapshot_to_action({"mode": None}) == "persist_only"


# ---------------------------------------------------------------------------
# receiver ownership


class TestReceiverOwnership:
    def test_remote_change_always_rejected(self, conn, make_relationship):
        rid = make_relationship()
        delivery.set_policy(conn, rid, "alert")
        with pytest.raises(RemotePolicyChangeRejected) as excinfo:
            delivery.apply_remote_policy_request(conn, rid, "evt-1", "silent")
        assert excinfo.value.code == "remote_policy_mutation_rejected"
        assert excinfo.value.relationship_id == rid
        assert excinfo.value.event_id == "evt-1"
        policy = delivery.get_policy(conn, rid)
        assert policy.mode == "alert"
        assert policy.version == 1

    def test_remote_change_rejected_on_default_policy(
        self, conn, make_relationship
    ):
        rid = make_relationship()
        with pytest.raises(RemotePolicyChangeRejected):
            delivery.apply_remote_policy_request(
                conn, rid, "evt-1", "feed_eligible"
            )
        assert delivery.get_policy(conn, rid).mode == "silent"


# ---------------------------------------------------------------------------
# seen receipts


class TestSeenReceipts:
    def test_seen_defaults_off(self, conn, make_relationship):
        rid = make_relationship()
        make_event(conn, rid, "evt-seen-1")
        assert (
            delivery.should_send_seen_receipt(
                conn, rid, "evt-seen-1", human_visible_view_opened=True
            )
            is False
        )

    def test_seen_sent_when_enabled_and_view_opened(
        self, conn, make_relationship
    ):
        rid = make_relationship()
        make_event(conn, rid, "evt-seen-2")
        delivery.set_seen_receipts_enabled(conn, rid, True)
        assert (
            delivery.should_send_seen_receipt(
                conn, rid, "evt-seen-2", human_visible_view_opened=True
            )
            is True
        )

    def test_seen_not_sent_without_visible_view(self, conn, make_relationship):
        rid = make_relationship()
        make_event(conn, rid, "evt-seen-3")
        delivery.set_seen_receipts_enabled(conn, rid, True)
        assert (
            delivery.should_send_seen_receipt(
                conn, rid, "evt-seen-3", human_visible_view_opened=False
            )
            is False
        )

    def test_seen_not_sent_for_unknown_event(self, conn, make_relationship):
        rid = make_relationship()
        delivery.set_seen_receipts_enabled(conn, rid, True)
        assert (
            delivery.should_send_seen_receipt(
                conn, rid, "evt-missing", human_visible_view_opened=True
            )
            is False
        )

    def test_seen_not_sent_for_other_relationship_event(
        self, conn, make_relationship
    ):
        rid_a = make_relationship("rel-a")
        rid_b = make_relationship("rel-b")
        make_event(conn, rid_b, "evt-seen-4")
        delivery.set_seen_receipts_enabled(conn, rid_a, True)
        delivery.set_seen_receipts_enabled(conn, rid_b, True)
        assert (
            delivery.should_send_seen_receipt(
                conn, rid_a, "evt-seen-4", human_visible_view_opened=True
            )
            is False
        )


# ---------------------------------------------------------------------------
# expiry


class TestExpiry:
    def test_honor_suppresses_after_sender_expiry(
        self, conn, make_relationship
    ):
        rid = make_relationship()
        event = {
            "created_at": "2026-09-15T18:00:00Z",
            "expires_at": "2026-09-15T19:00:00Z",
        }
        before = delivery.apply_expiry(
            conn, rid, event, "2026-09-15T18:30:00Z"
        )
        assert isinstance(before, ExpiryDecision)
        assert before.suppress is False
        assert before.reason == "not_yet_expired"
        assert before.retain_envelope is True
        after = delivery.apply_expiry(conn, rid, event, NOW)
        assert after.suppress is True
        assert after.effective_expires_at == "2026-09-15T19:00:00Z"
        assert after.reason == "expired_sender_request_honored"
        assert after.retain_envelope is True

    def test_honor_with_no_sender_expiry_never_suppresses(
        self, conn, make_relationship
    ):
        rid = make_relationship()
        decision = delivery.apply_expiry(
            conn, rid, {"created_at": "2026-09-15T18:00:00Z"}, NOW
        )
        assert decision.suppress is False
        assert decision.reason == "no_effective_expiry"

    def test_ignore_never_suppresses(self, conn, make_relationship):
        rid = make_relationship()
        delivery.set_expiry_policy(conn, rid, "ignore")
        decision = delivery.apply_expiry(
            conn,
            rid,
            {
                "created_at": "2026-09-15T18:00:00Z",
                "expires_at": "2026-09-15T19:00:00Z",
            },
            NOW,
        )
        assert decision.suppress is False
        assert decision.reason == "expiry_ignored_by_receiver_policy"
        assert decision.effective_expires_at is None

    def test_shorten_caps_at_window(self, conn, make_relationship):
        rid = make_relationship()
        delivery.set_expiry_policy(conn, rid, "shorten", 3600)
        event = {
            "created_at": "2026-09-15T18:00:00Z",
            "expires_at": "2026-09-16T18:00:00Z",
        }
        decision = delivery.apply_expiry(
            conn, rid, event, "2026-09-15T19:00:01Z"
        )
        assert decision.suppress is True
        assert decision.effective_expires_at == "2026-09-15T19:00:00Z"
        assert decision.reason == "expired_shortened_window"

    def test_shorten_without_sender_expiry_uses_window(
        self, conn, make_relationship
    ):
        rid = make_relationship()
        delivery.set_expiry_policy(conn, rid, "shorten", 3600)
        event = {"created_at": "2026-09-15T18:00:00Z", "expires_at": None}
        assert (
            delivery.apply_expiry(conn, rid, event, "2026-09-15T18:30:00Z")
        ).suppress is False
        decision = delivery.apply_expiry(conn, rid, event, NOW)
        assert decision.suppress is True
        assert decision.effective_expires_at == "2026-09-15T19:00:00Z"

    def test_shorten_never_extends_sender_window(
        self, conn, make_relationship
    ):
        rid = make_relationship()
        delivery.set_expiry_policy(conn, rid, "shorten", 24 * 3600)
        event = {
            "created_at": "2026-09-15T18:00:00Z",
            "expires_at": "2026-09-15T19:00:00Z",
        }
        decision = delivery.apply_expiry(conn, rid, event, NOW)
        assert decision.suppress is True
        assert decision.effective_expires_at == "2026-09-15T19:00:00Z"

    def test_decision_carries_policy_version(self, conn, make_relationship):
        rid = make_relationship()
        delivery.set_policy(conn, rid, "alert")
        delivery.set_expiry_policy(conn, rid, "ignore")
        decision = delivery.apply_expiry(
            conn, rid, {"created_at": "2026-09-15T18:00:00Z"}, NOW
        )
        assert decision.policy_version == 2

    def test_invalid_timestamp_raises(self, conn, make_relationship):
        rid = make_relationship()
        with pytest.raises(PolicyError) as excinfo:
            delivery.apply_expiry(
                conn, rid, {"created_at": "not-a-time"}, NOW
            )
        assert excinfo.value.code == "invalid_timestamp"
        with pytest.raises(PolicyError):
            delivery.apply_expiry(
                conn,
                rid,
                {"created_at": "2026-09-15T18:00:00Z"},
                "tomorrow",
            )

    def test_unknown_relationship_raises(self, conn):
        with pytest.raises(UnknownRelationshipError):
            delivery.apply_expiry(
                conn,
                "rel-nope",
                {"created_at": "2026-09-15T18:00:00Z"},
                NOW,
            )


# ---------------------------------------------------------------------------
# limits


class TestLimitsConstants:
    def test_values(self):
        assert limits.MAX_ENVELOPE_BYTES == 262144
        assert limits.MAX_PUSHES_PER_MINUTE == 6
        assert limits.SOFT_PUSH_TARGET_PER_MINUTE == 1
        assert limits.MIN_POLL_SECONDS == 30
        assert limits.REPO_SIZE_WARN_BYTES == 100 * 1024 * 1024
        assert limits.REPO_SIZE_BLOCK_BYTES == 250 * 1024 * 1024
        assert limits.REPO_SIZE_ROTATE_BYTES == 500 * 1024 * 1024
        assert limits.ACCEPT_WINDOW_DAYS == 7
        assert limits.FUTURE_TOLERANCE_SECONDS == 300
        assert limits.CLOCK_WARN_SECONDS == 60


class TestCheckSendRate:
    def test_empty_history_ok(self):
        assert limits.check_send_rate([], now=1_000_000.0) == "ok"

    def test_below_ceiling_ok(self):
        history = [1_000_000.0 - i for i in range(5)]
        assert limits.check_send_rate(history, now=1_000_000.0) == "ok"

    def test_at_ceiling_rate_limited(self):
        history = [1_000_000.0 - i for i in range(6)]
        assert limits.check_send_rate(history, now=1_000_000.0) == "rate_limited"

    def test_rolling_window_ignores_old_entries(self):
        history = [1_000_000.0 - 61 - i for i in range(10)]
        assert limits.check_send_rate(history, now=1_000_000.0) == "ok"

    def test_canonical_text_entries(self):
        history = ["2026-09-15T19:59:30Z"] * 6
        assert (
            limits.check_send_rate(history, now=1789502400.0)
            == "rate_limited"
        )

    def test_soft_target(self):
        assert (
            limits.soft_push_target_exceeded([1_000_000.0], now=1_000_000.0)
            is False
        )
        assert (
            limits.soft_push_target_exceeded(
                [1_000_000.0, 999_990.0], now=1_000_000.0
            )
            is True
        )


class TestCheckRepoSize:
    @pytest.mark.parametrize(
        "size,expected",
        [
            (0, "ok"),
            (100 * 1024 * 1024 - 1, "ok"),
            (100 * 1024 * 1024, "warn"),
            (250 * 1024 * 1024 - 1, "warn"),
            (250 * 1024 * 1024, "block"),
            (500 * 1024 * 1024 - 1, "block"),
            (500 * 1024 * 1024, "rotate"),
            (10 * 1024 * 1024 * 1024, "rotate"),
        ],
    )
    def test_thresholds(self, size, expected):
        assert limits.check_repo_size(size) == expected

    def test_negative_rejected(self):
        with pytest.raises(ValueError):
            limits.check_repo_size(-1)


class TestClockAndWindow:
    def test_poll_interval(self):
        assert limits.check_poll_interval(30) is True
        assert limits.check_poll_interval(29) is False

    def test_clock_skew(self):
        assert limits.check_clock_skew(30) == "ok"
        assert limits.check_clock_skew(60) == "warn"
        assert limits.check_clock_skew(299) == "warn"
        assert limits.check_clock_skew(300) == "block"
        assert limits.check_clock_skew(-400) == "block"

    def test_within_accept_window(self):
        assert (
            limits.within_accept_window("2026-09-15T20:00:00Z", NOW) is True
        )
        assert (
            limits.within_accept_window("2026-09-08T20:00:01Z", NOW) is True
        )
        assert (
            limits.within_accept_window("2026-09-08T19:59:59Z", NOW) is False
        )
        assert (
            limits.within_accept_window("2026-09-15T20:05:00Z", NOW) is True
        )
        assert (
            limits.within_accept_window("2026-09-15T20:05:01Z", NOW) is False
        )

    def test_canonical_round_trip(self):
        assert limits.format_canonical_utc(limits.parse_canonical_utc(NOW)) == NOW

    def test_bad_timestamp_rejected(self):
        with pytest.raises(ValueError):
            limits.parse_canonical_utc("2026-09-15 20:00:00")
        with pytest.raises(ValueError):
            limits.parse_canonical_utc("2026-13-45T99:99:99Z")


# ---------------------------------------------------------------------------
# retention


class TestPlaintextOptIn:
    @pytest.mark.parametrize(
        "period,expected",
        [("1d", "1d"), ("7d", "7d"), ("30d", "30d"), ("indefinite", "indefinite")],
    )
    def test_named_periods(self, conn, make_relationship, period, expected):
        rid = make_relationship()
        record = retention.set_plaintext_cache(conn, rid, period)
        assert record["period"] == expected
        assert record["relationship_id"] == rid
        status = retention.plaintext_cache_status(conn, rid)
        assert status["enabled"] is True
        assert status["period"] == expected
        if expected == "indefinite":
            assert status["expires_at"] is None
        else:
            assert status["expires_at"] is not None

    def test_aliases_normalized(self, conn, make_relationship):
        rid = make_relationship()
        assert retention.set_plaintext_cache(conn, rid, "week")["period"] == "7d"
        assert retention.set_plaintext_cache(conn, rid, "month")["period"] == "30d"

    def test_invalid_period_rejected(self, conn, make_relationship):
        rid = make_relationship()
        with pytest.raises(RetentionError) as excinfo:
            retention.set_plaintext_cache(conn, rid, "90d")
        assert excinfo.value.code == "invalid_period"

    def test_unknown_relationship_rejected(self, conn):
        with pytest.raises(UnknownRelationshipError):
            retention.set_plaintext_cache(conn, "rel-nope", "7d")

    def test_default_is_encrypted_only(self, conn, make_relationship):
        rid = make_relationship()
        status = retention.plaintext_cache_status(conn, rid)
        assert status["enabled"] is False
        assert status["period"] is None


class TestPlaintextCacheIO:
    def test_write_read_round_trip(self, conn, make_relationship):
        rid = make_relationship()
        retention.set_plaintext_cache(conn, rid, "7d")
        payload = b'{"body": "hello"}'
        path = retention.write_plaintext_cache(conn, rid, "evt-1", payload)
        assert path.is_file()
        assert retention.read_plaintext_cache(conn, rid, "evt-1") == payload

    def test_write_without_optin_raises(self, conn, make_relationship):
        rid = make_relationship()
        with pytest.raises(RetentionError) as excinfo:
            retention.write_plaintext_cache(conn, rid, "evt-1", b"x")
        assert excinfo.value.code == "plaintext_cache_not_enabled"

    def test_read_without_optin_returns_none(self, conn, make_relationship):
        rid = make_relationship()
        assert retention.read_plaintext_cache(conn, rid, "evt-1") is None

    def test_delete_is_immediate(self, conn, make_relationship, tmp_path):
        rid = make_relationship()
        retention.set_plaintext_cache(conn, rid, "7d")
        retention.write_plaintext_cache(conn, rid, "evt-1", b"one")
        retention.write_plaintext_cache(conn, rid, "evt-2", b"two")
        removed = retention.delete_plaintext_cache(conn, rid)
        assert removed == 3  # two payloads plus the optin manifest
        cache_dir = tmp_path / "plaintext_cache" / rid
        assert not cache_dir.exists()
        status = retention.plaintext_cache_status(conn, rid)
        assert status["enabled"] is False
        assert retention.read_plaintext_cache(conn, rid, "evt-1") is None

    def test_expired_optin_disables(self, conn, make_relationship):
        rid = make_relationship()
        record = retention.set_plaintext_cache(conn, rid, "1d")
        later = limits.add_seconds(record["set_at"], 2 * 24 * 3600)
        status = retention.plaintext_cache_status(conn, rid, now=later)
        assert status["enabled"] is False
        assert retention.read_plaintext_cache(conn, rid, "evt-1", now=later) is None


class TestPurge:
    def test_purge_removes_expired_optin_cache(
        self, conn, make_relationship, tmp_path
    ):
        rid = make_relationship()
        record = retention.set_plaintext_cache(conn, rid, "1d")
        retention.write_plaintext_cache(conn, rid, "evt-1", b"one")
        later = limits.add_seconds(record["set_at"], 2 * 24 * 3600)
        removed = retention.purge_expired_plaintext_cache(conn, tmp_path, now=later)
        assert removed == 2
        assert not (tmp_path / "plaintext_cache" / rid).exists()

    def test_purge_keeps_indefinite_cache(self, conn, make_relationship, tmp_path):
        rid = make_relationship()
        retention.set_plaintext_cache(conn, rid, "indefinite")
        retention.write_plaintext_cache(conn, rid, "evt-1", b"one")
        removed = retention.purge_expired_plaintext_cache(conn, tmp_path)
        assert removed == 0
        assert retention.read_plaintext_cache(conn, rid, "evt-1") == b"one"

    def test_purge_removes_stale_timed_files(
        self, conn, make_relationship, tmp_path
    ):
        rid = make_relationship()
        retention.set_plaintext_cache(conn, rid, "7d")
        path = retention.write_plaintext_cache(conn, rid, "evt-1", b"one")
        old = limits.parse_canonical_utc(db.utcnow()).timestamp() - 8 * 86400
        os.utime(path, (old, old))
        removed = retention.purge_expired_plaintext_cache(conn, tmp_path)
        assert removed == 1
        assert not path.exists()


class TestRetentionScan:
    def test_clean_state_dir_scans_empty(self, tmp_path):
        assert retention.retention_scan(tmp_path) == []

    def test_inbox_and_outbox_always_unexpected(self, tmp_path):
        (tmp_path / "inbox").mkdir()
        (tmp_path / "outbox").mkdir()
        (tmp_path / "inbox" / "evt.json").write_text("{}")
        (tmp_path / "outbox" / "evt.json").write_text("{}")
        findings = retention.retention_scan(tmp_path)
        reasons = {item["reason"] for item in findings}
        assert reasons == {"plaintext_inbox_forbidden", "plaintext_outbox_forbidden"}
        assert len(findings) == 2

    def test_valid_cache_not_flagged(self, conn, make_relationship, tmp_path):
        rid = make_relationship()
        retention.set_plaintext_cache(conn, rid, "indefinite")
        retention.write_plaintext_cache(conn, rid, "evt-1", b"one")
        assert retention.retention_scan(tmp_path) == []

    def test_stale_cache_without_manifest_flagged(self, tmp_path):
        cache_dir = tmp_path / "plaintext_cache" / "rel-x"
        cache_dir.mkdir(parents=True)
        (cache_dir / "evt-1.json").write_text("{}")
        findings = retention.retention_scan(tmp_path)
        assert len(findings) == 1
        assert findings[0]["reason"] == "stale_or_unauthorized_plaintext_cache"

    def test_expired_manifest_flagged(self, tmp_path):
        cache_dir = tmp_path / "plaintext_cache" / "rel-x"
        cache_dir.mkdir(parents=True)
        manifest = {
            "relationship_id": "rel-x",
            "period": "1d",
            "set_at": "2026-09-10T00:00:00Z",
            "expires_at": "2026-09-11T00:00:00Z",
        }
        (cache_dir / "optin.json").write_text(json.dumps(manifest))
        (cache_dir / "evt-1.json").write_text("{}")
        findings = retention.retention_scan(tmp_path, now=NOW)
        assert len(findings) == 1
        assert findings[0]["reason"] == "expired_optin_plaintext_cache"

    def test_file_older_than_period_flagged(self, tmp_path):
        cache_dir = tmp_path / "plaintext_cache" / "rel-x"
        cache_dir.mkdir(parents=True)
        manifest = {
            "relationship_id": "rel-x",
            "period": "1d",
            "set_at": "2026-09-15T00:00:00Z",
            "expires_at": "2026-09-16T00:00:00Z",
        }
        (cache_dir / "optin.json").write_text(json.dumps(manifest))
        target = cache_dir / "evt-1.json"
        target.write_text("{}")
        old = limits.parse_canonical_utc(NOW).timestamp() - 2 * 86400
        os.utime(target, (old, old))
        findings = retention.retention_scan(tmp_path, now=NOW)
        assert len(findings) == 1
        assert findings[0]["reason"] == "cache_file_older_than_period"

    def test_legacy_patterns_flagged(self, tmp_path):
        (tmp_path / "inbox-backup.json").write_text("{}")
        (tmp_path / "note.plaintext").write_text("hi")
        findings = retention.retention_scan(tmp_path)
        assert {item["reason"] for item in findings} == {
            "legacy_plaintext_pattern"
        }
        assert len(findings) == 2

    def test_post_teardown_scan_is_clean(self, conn, make_relationship, tmp_path):
        rid = make_relationship()
        retention.set_plaintext_cache(conn, rid, "7d")
        retention.write_plaintext_cache(conn, rid, "evt-1", b"one")
        (tmp_path / "inbox").mkdir()
        (tmp_path / "inbox" / "evt.json").write_text("{}")
        assert retention.retention_scan(tmp_path) != []
        retention.delete_plaintext_cache(conn, rid)
        for item in retention.retention_scan(tmp_path):
            os.unlink(item["path"])
        assert retention.retention_scan(tmp_path) == []
