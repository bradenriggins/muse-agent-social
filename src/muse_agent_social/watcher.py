"""Watcher: poll loop per the WATCHER CONTRACT.

run_once(transport, relationship_id, receive_fn) performs a single poll
cycle and returns (exit_code, result_json).

Exit codes:
    0   scan complete, all objects reached a terminal local state
    20  retryable transport/push failure, retry-pending work remains, or
        the fetch stream truncated at a documented aggregate bound (more
        objects remain on the relay); do not checkpoint; back off with
        jitter
    21  permanent local config/schema error; do not checkpoint; alert
    22  mirror lock busy; retry after 5-15 seconds
    23  partial work remains queued after the time budget; do not
        checkpoint; the caller retries once immediately

Quarantined hostile/malformed input is a terminal processed outcome and
does not fail the run.

Checkpoint rule (exactly per plan): only advance last_successful_head
after rc == 0 and retry_pending == 0 (and no queued outgoing mutations
remain). Watcher state writes are atomic rename + fsync. Single-watcher
enforcement uses the same mirror lock file as the git transport.

receive_fn contract (implemented by the receive track):
    receive_fn(relationship_id, object_name, data) -> dict with keys:
        outcome: "accepted" | "quarantined" | "retry_pending"
        surfaces: int (optional, default 0)
        receipts_queued: int (optional, default 0)
    Unknown outcomes and exceptions are permanent local errors (exit 21).

policy_callback contract (watcher-defined):
    policy_callback(relationship_id) -> {"delivery_mode": str, "muted": bool}
    Muted/silent relationships still receive and validate; only surface
    behavior changes, which is the receive track's decision. The watcher
    reports the delivery mode in the result JSON.

Metrics carry IDs, counts, durations, and reason codes only, never content
or keys.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .config import resolve_state_dir
from .transports.base import (
    OBJECT_MAX_BYTES,
    POLL_INTERVAL_SECONDS,
    Transport,
    TransportError,
    mirror_lock,
)
from .transports.github import WATCHER_RETRY_CAP_SECONDS, full_jitter_delay

EXIT_OK = 0
EXIT_RETRYABLE = 20
EXIT_PERMANENT = 21
EXIT_LOCK_BUSY = 22
EXIT_PARTIAL_TIMEOUT = 23

DEFAULT_TIME_BUDGET_SECONDS = 120.0
LOCK_RETRY_DELAY_RANGE = (5.0, 15.0)  # exit 22: caller retries after 5-15s

_VALID_OUTCOMES = ("accepted", "quarantined", "retry_pending")


def default_policy_callback(relationship_id: str) -> dict[str, Any]:
    """Fallback policy: alert mode, not muted."""
    return {"delivery_mode": "alert", "muted": False}


def _utc_text(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _watcher_state_path(state_dir: Path, relationship_id: str) -> Path:
    return state_dir / "watcher" / f"{relationship_id}.json"


def _default_watcher_state() -> dict[str, Any]:
    return {
        "last_successful_head": "",
        "retry_pending": 0,
        "consecutive_failures": 0,
        "next_retry_at": None,
        "last_poll_at": 0.0,
    }


def load_watcher_state(state_dir: str | Path, relationship_id: str) -> dict[str, Any]:
    """Read watcher state; missing or corrupt files yield defaults."""
    state = _default_watcher_state()
    path = _watcher_state_path(Path(state_dir), relationship_id)
    try:
        raw = path.read_bytes()
    except OSError:
        return state
    try:
        loaded = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return state
    if isinstance(loaded, dict):
        for key, value in loaded.items():
            if key in state:
                state[key] = value
    return state


def save_watcher_state(
    state_dir: str | Path, relationship_id: str, state: dict[str, Any]
) -> None:
    """Persist watcher state with atomic rename + fsync."""
    path = _watcher_state_path(Path(state_dir), relationship_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _result(relationship_id: str) -> dict[str, Any]:
    return {
        "relationship_id": relationship_id,
        "remote_head": None,
        "accepted": 0,
        "quarantined": 0,
        "retry_pending": 0,
        "surfaces": 0,
        "receipts_queued": 0,
        "quarantine_reasons": {},
        "delivery_mode": None,
        "checkpoint_advanced": False,
        "push": None,
        "duration_ms": 0,
        "reason": None,
    }


def run_once(
    transport: Transport,
    relationship_id: str,
    receive_fn: Callable[[str, str, bytes], dict[str, Any]],
    *,
    state_dir: str | Path | None = None,
    min_poll_interval: float = POLL_INTERVAL_SECONDS,
    time_budget: float = DEFAULT_TIME_BUDGET_SECONDS,
    policy_callback: Callable[[str], dict[str, Any]] | None = None,
    clock: Callable[[], float] | None = None,
    maintenance_callback: Callable[[], None] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Run one watcher poll cycle. Returns (exit_code, result_json).

    maintenance_callback is run once per clean cycle, after object
    processing and before returning EXIT_OK. It is the hook for
    housekeeping such as rotation sweeps; a raising callback is recorded
    in result["maintenance_error"] and never fails the cycle.
    """
    now_fn = clock or time.time
    t_start = now_fn()
    if state_dir is not None:
        resolved = Path(state_dir).resolve()
    else:
        resolved = resolve_state_dir().resolve()
    result = _result(relationship_id)

    def finish(code: int, reason: str | None = None) -> tuple[int, dict[str, Any]]:
        result["duration_ms"] = int((now_fn() - t_start) * 1000)
        if reason is not None:
            result["reason"] = reason
        return code, result

    try:
        with mirror_lock(resolved, relationship_id, timeout=0):
            return _run_once_locked(
                transport, relationship_id, receive_fn, resolved,
                min_poll_interval, time_budget,
                policy_callback or default_policy_callback,
                now_fn, t_start, result, finish,
                maintenance_callback,
            )
    except TransportError as exc:
        if exc.code == "lock_timeout":
            # Exit 22: another watcher/process owns the mirror. The caller
            # retries after 5-15 seconds (LOCK_RETRY_DELAY_RANGE).
            return finish(EXIT_LOCK_BUSY, "lock_busy")
        raise


def _receive_stream(
    transport: Transport,
    relationship_id: str,
    receive_fn: Callable[[str, str, bytes], dict[str, Any]],
    state_dir: Path,
    last_head: str,
    time_budget: float,
    now_fn: Callable[[], float],
    t_start: float,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Run the receive phase over a streaming fetch.

    Returns ``{"budget_hit": bool, "fatal": (code, reason) | None,
    "stats": stream stats dict}``. ``fatal`` carries a ``(code, reason)``
    pair when the run must abort outright (the old inline loop's ``return
    finish(...)`` paths); the caller saves watcher state and finishes with
    it.
    """
    budget_hit = False
    fatal: tuple[int, str | None] | None = None

    def visit(object_name: str, data: bytes) -> bool:
        nonlocal budget_hit, fatal
        if now_fn() - t_start > time_budget:
            # Time budget is enforced INSIDE the retrieval loop: returning
            # False tells the transport to stop fetching immediately, so
            # no more objects are buffered after the budget is spent.
            budget_hit = True
            return False
        if len(data) > OBJECT_MAX_BYTES:
            # Terminal: quarantined hostile/oversized input never fails the run.
            result["quarantined"] += 1
            reasons = result["quarantine_reasons"]
            reasons["object_too_large"] = reasons.get("object_too_large", 0) + 1
            try:
                transport.consume(object_name)
            except TransportError as exc:
                fatal = (exc.exit_code, exc.code)
                return False
            return True
        try:
            outcome_doc = receive_fn(relationship_id, object_name, data)
        except Exception as exc:
            fatal = (EXIT_PERMANENT, f"receive_error: {type(exc).__name__}")
            return False
        outcome = outcome_doc.get("outcome") if isinstance(outcome_doc, dict) else None
        if outcome not in _VALID_OUTCOMES:
            fatal = (EXIT_PERMANENT, "bad_receive_outcome")
            return False
        try:
            result["surfaces"] += int(outcome_doc.get("surfaces", 0) or 0)
            result["receipts_queued"] += int(outcome_doc.get("receipts_queued", 0) or 0)
        except (TypeError, ValueError):
            fatal = (EXIT_PERMANENT, "bad_receive_outcome")
            return False
        if outcome == "retry_pending":
            result["retry_pending"] += 1
            return True  # do not consume; retried on a later poll
        if outcome == "accepted":
            result["accepted"] += 1
        else:
            result["quarantined"] += 1
            reasons = result["quarantine_reasons"]
            reasons["receiver_quarantined"] = reasons.get("receiver_quarantined", 0) + 1
        try:
            transport.consume(object_name)
        except TransportError as exc:
            fatal = (exc.exit_code, exc.code)
            return False
        return True

    stats = transport.fetch_new_stream(last_head, visit)
    return {"budget_hit": budget_hit, "fatal": fatal, "stats": stats}


def _run_once_locked(
    transport: Transport,
    relationship_id: str,
    receive_fn: Callable[[str, str, bytes], dict[str, Any]],
    state_dir: Path,
    min_poll_interval: float,
    time_budget: float,
    policy_callback: Callable[[str], dict[str, Any]],
    now_fn: Callable[[], float],
    t_start: float,
    result: dict[str, Any],
    finish: Callable[[int, str | None], tuple[int, dict[str, Any]]],
    maintenance_callback: Callable[[], None] | None = None,
) -> tuple[int, dict[str, Any]]:
    state = load_watcher_state(state_dir, relationship_id)
    now = now_fn()

    def finish_ok(reason: str | None = None):
        # Maintenance runs on every clean cycle; a failing callback is
        # recorded but never fails the poll.
        if maintenance_callback is not None:
            try:
                maintenance_callback()
            except Exception as exc:
                result["maintenance_error"] = f"{type(exc).__name__}: {exc}"
        return finish(EXIT_OK, reason)

    # Poll throttle: never scan faster than the plan interval.
    if now - float(state.get("last_poll_at", 0.0)) < min_poll_interval:
        result["poll_skipped"] = True
        return finish(EXIT_OK, "poll_throttled")

    # Retry backoff (Medium 1): a cycle that ended retryable or partial
    # asked to wait until next_retry_at. Honor it instead of polling
    # straight through the backoff.
    if int(state.get("retry_pending", 0) or 0) > 0:
        next_retry = state.get("next_retry_at")
        if next_retry:
            try:
                retry_at = (
                    datetime.strptime(next_retry, "%Y-%m-%dT%H:%M:%SZ")
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                )
            except (TypeError, ValueError):
                retry_at = 0.0
            # Whole-second comparison: next_retry_at is stored truncated
            # to whole seconds, so a sub-second jitter draw still defers
            # the poll to the next whole second.
            if retry_at >= int(now):
                result["poll_skipped"] = True
                save_watcher_state(state_dir, relationship_id, state)
                return finish(EXIT_OK, "retry_backoff")
    state["last_poll_at"] = now

    try:
        policy = policy_callback(relationship_id)
    except Exception as exc:
        save_watcher_state(state_dir, relationship_id, state)
        return finish(EXIT_PERMANENT, f"policy_error: {exc}")
    if not isinstance(policy, dict):
        save_watcher_state(state_dir, relationship_id, state)
        return finish(EXIT_PERMANENT, "policy_error: not a mapping")
    result["delivery_mode"] = policy.get("delivery_mode", "alert")

    try:
        remote = transport.head()
    except TransportError as exc:
        save_watcher_state(state_dir, relationship_id, state)
        return finish(exc.exit_code, exc.code)
    result["remote_head"] = remote

    retry_pending = int(state.get("retry_pending", 0) or 0)
    last_head = state.get("last_successful_head", "") or ""
    needs_work = (
        remote != last_head
        or retry_pending > 0
        or transport.pending_outgoing() > 0
    )
    if not needs_work:
        save_watcher_state(state_dir, relationship_id, state)
        return finish_ok()

    # -- receive phase (streamed) ------------------------------------------
    # The transport calls visit() per object AS it is fetched: the watcher
    # processes each object (replay/signature checks, receive) before the
    # next one is buffered, so a relay stuffed with legal-size objects can
    # no longer force the watcher to buffer gigabytes. The time budget is
    # enforced inside the retrieval loop: when it is spent, visit() returns
    # False and the transport stops fetching immediately.
    try:
        stream_info = _receive_stream(
            transport, relationship_id, receive_fn, state_dir, last_head,
            time_budget, now_fn, t_start, result,
        )
    except TransportError as exc:
        save_watcher_state(state_dir, relationship_id, state)
        return finish(exc.exit_code, exc.code)
    if stream_info["fatal"] is not None:
        save_watcher_state(state_dir, relationship_id, state)
        code, reason = stream_info["fatal"]
        return finish(code, reason)
    budget_hit = stream_info["budget_hit"]
    # Loud truncation report: the stream stopped before exhausting the
    # relay (documented aggregate bounds hit, or the caller's budget).
    result["fetch_stream"] = stream_info["stats"]
    if stream_info["stats"]["truncated"]:
        result["fetch_truncated"] = True

    # -- push phase: flush queued outgoing mutations (receipts, consumes) --
    try:
        push_result = transport.flush()
    except TransportError as exc:
        save_watcher_state(state_dir, relationship_id, state)
        return finish(exc.exit_code, exc.code)
    result["push"] = push_result

    # -- checkpoint decision ---------------------------------------------
    try:
        new_remote = transport.head()
    except TransportError as exc:
        save_watcher_state(state_dir, relationship_id, state)
        return finish(exc.exit_code, exc.code)
    result["remote_head"] = new_remote

    pending = result["retry_pending"] + transport.pending_outgoing()
    truncated = bool(stream_info["stats"]["truncated"])
    if budget_hit or truncated:
        # Never checkpoint a truncated scan: objects the stream never
        # visited are still on the relay, and both transports list "newer
        # than checkpoint" by diffing against it, so advancing past them
        # would silently drop them. The next poll resumes from the old
        # checkpoint. Partial work gets a partial/retryable status, never
        # exit 0.
        state["retry_pending"] = result["retry_pending"]
        state["consecutive_failures"] = int(state.get("consecutive_failures", 0)) + 1
        state["next_retry_at"] = _utc_text(now_fn())
        save_watcher_state(state_dir, relationship_id, state)
        if budget_hit:
            return finish(EXIT_PARTIAL_TIMEOUT, "time_budget_exceeded")
        return finish(
            EXIT_RETRYABLE,
            stream_info["stats"]["truncation_reason"] or "fetch_truncated",
        )

    if pending == 0:
        # rc == 0 and retry_pending == 0: advance the checkpoint.
        state["last_successful_head"] = new_remote
        state["retry_pending"] = 0
        state["consecutive_failures"] = 0
        state["next_retry_at"] = None
        save_watcher_state(state_dir, relationship_id, state)
        result["checkpoint_advanced"] = True
        return finish_ok()

    # Retryable remainder: do not checkpoint; schedule backoff with jitter.
    failures = int(state.get("consecutive_failures", 0)) + 1
    state["retry_pending"] = result["retry_pending"]
    state["consecutive_failures"] = failures
    state["next_retry_at"] = _utc_text(
        now_fn() + full_jitter_delay(failures, 1.0, WATCHER_RETRY_CAP_SECONDS)
    )
    save_watcher_state(state_dir, relationship_id, state)
    return finish(EXIT_RETRYABLE, "retry_pending")
