"""Regression tests for the K2 streaming-fetch bounds.

- The aggregate byte cap allows an exact-cap total; only exceeding it
  truncates (``>``, not ``>=``).
- Oversize placeholders (``OBJECT_MAX_BYTES + 1``) count toward the
  aggregate bound.
- The object cap truncates with reason ``object_cap``; a caller stop
  reports ``caller_stopped``.
- A truncated stream never advances the watcher checkpoint, even when
  nothing is pending, and yields a non-zero status; the next poll resumes
  from the old checkpoint and converges.
- A spent time budget never checkpoints, even when every visited object
  reached a terminal state.
"""

import pytest

import muse_agent_social.transports.local as local_mod
from muse_agent_social.transports.base import OBJECT_MAX_BYTES
from muse_agent_social.transports.local import LocalTransport
from muse_agent_social.watcher import (
    EXIT_OK,
    EXIT_PARTIAL_TIMEOUT,
    EXIT_RETRYABLE,
    load_watcher_state,
    run_once,
)

REL = "rel-k2"


def _upload(transport, tag, size):
    name = f"{tag:032d}.json"
    transport.upload(name, b"x" * size)
    return name


def _plant_oversize(transport, tag, size):
    """Write an over-cap object straight into incoming/, bypassing the
    upload size gate, to simulate a hostile relay."""
    path = transport.incoming / f"{tag:032d}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    return path.name


def _collect(since=""):
    seen = []

    def visit(name, data):
        seen.append((name, len(data)))
        return True

    return seen, visit
    seen = []

    def visit(name, data):
        seen.append((name, len(data)))
        return True

    return seen, visit


def test_aggregate_bound_allows_exact_cap(tmp_path, monkeypatch):
    transport = LocalTransport(tmp_path / "relay")
    monkeypatch.setattr(local_mod, "FETCH_MAX_AGGREGATE_BYTES", 100)
    _upload(transport, 1, 60)
    _upload(transport, 2, 40)  # total exactly 100: allowed
    seen, visit = _collect()
    stats = transport.fetch_new_stream("", visit)
    assert stats["truncated"] is False
    assert stats["bytes_streamed"] == 100
    assert len(seen) == 2


def test_aggregate_bound_truncates_on_excess(tmp_path, monkeypatch):
    transport = LocalTransport(tmp_path / "relay")
    monkeypatch.setattr(local_mod, "FETCH_MAX_AGGREGATE_BYTES", 100)
    _upload(transport, 1, 60)
    _upload(transport, 2, 41)  # total 101 > 100: second object not delivered
    seen, visit = _collect()
    stats = transport.fetch_new_stream("", visit)
    assert stats["truncated"] is True
    assert stats["truncation_reason"] == "aggregate_bytes_cap"
    assert stats["bytes_streamed"] == 60
    assert len(seen) == 1


def test_object_cap_truncates(tmp_path, monkeypatch):
    transport = LocalTransport(tmp_path / "relay")
    monkeypatch.setattr(local_mod, "FETCH_MAX_OBJECTS", 3)
    for i in range(5):
        _upload(transport, i, 10)
    seen, visit = _collect()
    stats = transport.fetch_new_stream("", visit)
    assert stats["truncated"] is True
    assert stats["truncation_reason"] == "object_cap"
    assert stats["objects_streamed"] == 3
    assert len(seen) == 3


def test_oversize_placeholder_counts_toward_aggregate(tmp_path, monkeypatch):
    transport = LocalTransport(tmp_path / "relay")
    # Cap below a single placeholder: the oversize object alone truncates.
    monkeypatch.setattr(local_mod, "FETCH_MAX_AGGREGATE_BYTES", OBJECT_MAX_BYTES)
    _plant_oversize(transport, 1, OBJECT_MAX_BYTES + 500)
    seen, visit = _collect()
    stats = transport.fetch_new_stream("", visit)
    assert stats["truncated"] is True
    assert stats["truncation_reason"] == "aggregate_bytes_cap"
    assert stats["objects_streamed"] == 0
    assert seen == []


def test_oversize_placeholder_after_small_object(tmp_path, monkeypatch):
    transport = LocalTransport(tmp_path / "relay")
    monkeypatch.setattr(
        local_mod, "FETCH_MAX_AGGREGATE_BYTES", OBJECT_MAX_BYTES + 10
    )
    _upload(transport, 1, 10)
    _plant_oversize(transport, 2, OBJECT_MAX_BYTES + 500)
    seen, visit = _collect()
    stats = transport.fetch_new_stream("", visit)
    # 10 + (OBJECT_MAX_BYTES + 1) > cap: placeholder is the truncator.
    assert stats["truncated"] is True
    assert stats["truncation_reason"] == "aggregate_bytes_cap"
    assert stats["objects_streamed"] == 1
    assert [s for _, s in seen] == [10]


def test_caller_stop_reports_truncation(tmp_path):
    transport = LocalTransport(tmp_path / "relay")
    for i in range(3):
        _upload(transport, i, 10)

    seen = []

    def visit(name, data):
        seen.append(name)
        return False  # stop after the first object

    stats = transport.fetch_new_stream("", visit)
    assert stats["truncated"] is True
    assert stats["truncation_reason"] == "caller_stopped"
    assert len(seen) == 1


def _accept_all(relationship_id, object_name, data):
    return {"outcome": "accepted"}


def test_truncation_prevents_checkpoint_and_resumes(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    transport = LocalTransport(tmp_path / "relay")
    monkeypatch.setattr(local_mod, "FETCH_MAX_OBJECTS", 2)
    for i in range(4):
        _upload(transport, i, 10)

    code, result = run_once(
        transport, REL, _accept_all, state_dir=state_dir, min_poll_interval=0
    )
    assert code == EXIT_RETRYABLE
    assert result["reason"] == "object_cap"
    assert result["fetch_truncated"] is True
    assert result.get("checkpoint_advanced", False) is False
    assert result["accepted"] == 2
    # Checkpoint did not move: nothing was checkpointed past.
    assert load_watcher_state(state_dir, REL)["last_successful_head"] == ""

    # Next poll resumes from the old checkpoint and drains the rest.
    monkeypatch.setattr(local_mod, "FETCH_MAX_OBJECTS", 5000)
    code, result = run_once(
        transport, REL, _accept_all, state_dir=state_dir, min_poll_interval=0
    )
    assert code == EXIT_OK
    assert result["accepted"] == 2
    assert result["checkpoint_advanced"] is True


def test_budget_hit_with_nothing_pending_still_no_checkpoint(tmp_path):
    state_dir = tmp_path / "state"
    transport = LocalTransport(tmp_path / "relay")
    _upload(transport, 1, 10)

    ticks = iter([100.0, 100.0, 200.0, 200.0, 200.0, 200.0])

    def clock():
        return next(ticks, 200.0)

    code, result = run_once(
        transport,
        REL,
        _accept_all,
        state_dir=state_dir,
        min_poll_interval=0,
        time_budget=0,
        clock=clock,
    )
    # Budget spent before the first object was visited: partial status,
    # no checkpoint, even though nothing is pending.
    assert code == EXIT_PARTIAL_TIMEOUT
    assert result["reason"] == "time_budget_exceeded"
    assert result.get("checkpoint_advanced", False) is False
    assert load_watcher_state(state_dir, REL)["last_successful_head"] == ""
