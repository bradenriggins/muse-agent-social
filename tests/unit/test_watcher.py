"""Unit tests for the watcher contract.

Uses the local transport adapter (no network). Exit-code semantics:
0 scan complete, 20 retryable, 21 permanent, 22 lock busy, 23 partial
after timeout.
"""

import json
import subprocess
import sys
import time

import pytest

from muse_agent_social.transports.base import OBJECT_MAX_BYTES, TransportError
from muse_agent_social.transports.local import LocalTransport
from muse_agent_social.watcher import (
    EXIT_LOCK_BUSY,
    EXIT_OK,
    EXIT_PARTIAL_TIMEOUT,
    EXIT_PERMANENT,
    EXIT_RETRYABLE,
    load_watcher_state,
    run_once,
    save_watcher_state,
)

REL = "rel-test"


@pytest.fixture()
def setup(tmp_path):
    state_dir = tmp_path / "state"
    transport = LocalTransport(tmp_path / "relay")
    return state_dir, transport


def accept_all(relationship_id, object_name, data):
    return {"outcome": "accepted", "surfaces": 1, "receipts_queued": 1}


def _checkpoint(state_dir):
    return load_watcher_state(state_dir, REL)["last_successful_head"]


class TestWatcherContract:
    def test_exit_0_advances_checkpoint(self, setup):
        state_dir, transport = setup
        name = "A" * 32 + ".json"
        transport.upload(name, b"sealed")
        code, result = run_once(transport, REL, accept_all, state_dir=state_dir,
                                min_poll_interval=0)
        assert code == EXIT_OK
        assert result["accepted"] == 1
        assert result["surfaces"] == 1
        assert result["receipts_queued"] == 1
        assert result["checkpoint_advanced"] is True
        assert _checkpoint(state_dir) == transport.head()

    def test_second_run_is_quiet(self, setup):
        state_dir, transport = setup
        transport.upload("B" * 32 + ".json", b"sealed")
        run_once(transport, REL, accept_all, state_dir=state_dir,
                 min_poll_interval=0)
        code, result = run_once(transport, REL, accept_all, state_dir=state_dir,
                                min_poll_interval=0)
        assert code == EXIT_OK
        assert result["accepted"] == 0
        assert result["checkpoint_advanced"] is False

    def test_exit_20_does_not_advance_checkpoint(self, setup):
        state_dir, transport = setup

        class FlakyFlush(LocalTransport):
            def flush(self):
                raise TransportError("push_failed", "boom", retryable=True)

        flaky = FlakyFlush(transport.root)
        flaky.upload("C" * 32 + ".json", b"sealed")
        code, result = run_once(flaky, REL, accept_all, state_dir=state_dir,
                                min_poll_interval=0)
        assert code == EXIT_RETRYABLE
        assert result["reason"] == "push_failed"
        assert result["accepted"] == 1  # receive work still counted
        assert result["checkpoint_advanced"] is False
        assert _checkpoint(state_dir) == ""

    def test_quarantined_input_does_not_fail_run(self, setup):
        state_dir, transport = setup
        transport.upload("D" * 32 + ".json", b"junk-bytes")

        def receive(rid, name, data):
            return {"outcome": "quarantined"}

        code, result = run_once(transport, REL, receive, state_dir=state_dir,
                                min_poll_interval=0)
        assert code == EXIT_OK
        assert result["quarantined"] == 1
        assert result["checkpoint_advanced"] is True
        # Consumed, so it is never presented again.
        assert dict(transport.fetch_new("")) == {}

    def test_oversized_object_quarantined(self, setup):
        state_dir, transport = setup
        name = "E" * 32 + ".json"
        (transport.incoming / name).write_bytes(b"x" * (OBJECT_MAX_BYTES + 1))
        code, result = run_once(transport, REL, accept_all, state_dir=state_dir,
                                min_poll_interval=0)
        assert code == EXIT_OK
        assert result["quarantined"] == 1
        assert result["quarantine_reasons"]["object_too_large"] == 1
        assert dict(transport.fetch_new("")) == {}

    def test_retry_pending_then_success(self, setup):
        state_dir, transport = setup
        transport.upload("F" * 32 + ".json", b"sealed")
        calls = {"n": 0}

        def receive(rid, name, data):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"outcome": "retry_pending"}
            return {"outcome": "accepted"}

        code, result = run_once(transport, REL, receive, state_dir=state_dir,
                                min_poll_interval=0)
        assert code == EXIT_RETRYABLE
        assert result["reason"] == "retry_pending"
        assert result["retry_pending"] == 1
        assert result["checkpoint_advanced"] is False
        assert _checkpoint(state_dir) == ""
        assert load_watcher_state(state_dir, REL)["retry_pending"] == 1

        # Remote head did not move, but retry_pending forces another receive.
        code, result = run_once(transport, REL, receive, state_dir=state_dir,
                                min_poll_interval=0)
        assert code == EXIT_OK
        assert result["accepted"] == 1
        assert result["checkpoint_advanced"] is True
        assert _checkpoint(state_dir) == transport.head()

    def test_bad_receive_outcome_is_permanent(self, setup):
        state_dir, transport = setup
        transport.upload("G" * 32 + ".json", b"sealed")

        def receive(rid, name, data):
            return {"outcome": "nonsense"}

        code, result = run_once(transport, REL, receive, state_dir=state_dir,
                                min_poll_interval=0)
        assert code == EXIT_PERMANENT
        assert result["reason"] == "bad_receive_outcome"
        assert _checkpoint(state_dir) == ""

    def test_transport_head_failure_maps_to_20(self, setup):
        state_dir, transport = setup

        class DeadHead(LocalTransport):
            def head(self):
                raise TransportError("ls_remote_failed", "net down",
                                     retryable=True)

        code, result = run_once(DeadHead(transport.root), REL, accept_all,
                                state_dir=state_dir, min_poll_interval=0)
        assert code == EXIT_RETRYABLE
        assert result["reason"] == "ls_remote_failed"

    def test_poll_throttled(self, setup):
        state_dir, transport = setup
        code, result = run_once(transport, REL, accept_all, state_dir=state_dir)
        assert code == EXIT_OK
        code, result = run_once(transport, REL, accept_all, state_dir=state_dir)
        assert code == EXIT_OK
        assert result.get("poll_skipped") is True
        assert result["reason"] == "poll_throttled"

    def test_muted_relationship_still_receives(self, setup):
        state_dir, transport = setup
        transport.upload("H" * 32 + ".json", b"sealed")

        def silent_policy(rid):
            return {"delivery_mode": "silent", "muted": True}

        code, result = run_once(transport, REL, accept_all, state_dir=state_dir,
                                min_poll_interval=0,
                                policy_callback=silent_policy)
        assert code == EXIT_OK
        assert result["accepted"] == 1
        assert result["delivery_mode"] == "silent"

    def test_lock_contention_returns_22(self, setup):
        state_dir, transport = setup
        lock_path = state_dir / "locks" / f"{REL}.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        holder = subprocess.Popen(
            [sys.executable, "-c",
             "import fcntl, time, sys; "
             "fh = open(sys.argv[1], 'w'); "
             "fcntl.flock(fh, fcntl.LOCK_EX); "
             "time.sleep(8)",
             str(lock_path)],
        )
        try:
            time.sleep(0.7)  # let the holder take the lock
            code, result = run_once(transport, REL, accept_all,
                                    state_dir=state_dir, min_poll_interval=0)
            assert code == EXIT_LOCK_BUSY
            assert result["reason"] == "lock_busy"
        finally:
            holder.terminate()
            holder.wait()

    def test_exit_23_on_time_budget(self, setup):
        state_dir, transport = setup
        transport.upload("I" * 32 + ".json", b"one")
        transport.upload("K" * 32 + ".json", b"two")
        calls = {"n": 0}
        t0 = 1000.0

        def jumping_clock():
            # First three reads see t0; afterwards the clock jumps far ahead,
            # tripping the budget while retry-pending work remains.
            calls["n"] += 1
            return t0 if calls["n"] <= 3 else t0 + 1000.0

        def receive(rid, name, data):
            return {"outcome": "retry_pending"}

        code, result = run_once(transport, REL, receive, state_dir=state_dir,
                                min_poll_interval=0, time_budget=10.0,
                                clock=jumping_clock)
        assert code == EXIT_PARTIAL_TIMEOUT
        assert result["reason"] == "time_budget_exceeded"
        assert result["checkpoint_advanced"] is False
        assert _checkpoint(state_dir) == ""

    def test_watcher_state_roundtrip(self, tmp_path):
        state = {"last_successful_head": "abc", "retry_pending": 2,
                 "consecutive_failures": 1, "next_retry_at": None,
                 "last_poll_at": 5.0}
        save_watcher_state(tmp_path, REL, state)
        loaded = load_watcher_state(tmp_path, REL)
        assert loaded["last_successful_head"] == "abc"
        assert loaded["retry_pending"] == 2
        # Atomic write: no tmp files left behind.
        assert list((tmp_path / "watcher").glob("*.tmp")) == []

    def test_result_json_serializable(self, setup):
        state_dir, transport = setup
        transport.upload("J" * 32 + ".json", b"sealed")
        code, result = run_once(transport, REL, accept_all, state_dir=state_dir,
                                min_poll_interval=0)
        json.dumps(result)  # must not raise
        assert set(result) >= {"accepted", "quarantined", "retry_pending",
                               "surfaces", "receipts_queued"}
