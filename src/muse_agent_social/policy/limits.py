"""Quotas, guardrails, and clock-contract helpers for Muse Agent Social v0.2.

Every constant is locked by the implementation plan. Checkers are pure
functions: they take explicit inputs and return stable string verdicts so
callers (transport, watcher, scheduler) can map them to exit codes or
alerts without branching on magic numbers.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from typing import Iterable, Union

from muse_agent_social.validation import MAX_ENVELOPE_BYTES

__all__ = [
    "MAX_ENVELOPE_BYTES",
    "MAX_PUSHES_PER_MINUTE",
    "SOFT_PUSH_TARGET_PER_MINUTE",
    "MIN_POLL_SECONDS",
    "REPO_SIZE_WARN_BYTES",
    "REPO_SIZE_BLOCK_BYTES",
    "REPO_SIZE_ROTATE_BYTES",
    "ACCEPT_WINDOW_DAYS",
    "FUTURE_TOLERANCE_SECONDS",
    "CLOCK_WARN_SECONDS",
    "LATE_WINDOW_SECONDS",
    "parse_canonical_utc",
    "format_canonical_utc",
    "check_send_rate",
    "soft_push_target_exceeded",
    "check_repo_size",
    "check_poll_interval",
    "check_clock_skew",
    "within_accept_window",
    "add_seconds",
]

# Whole sealed envelope, UTF-8 encoded, is at most 262,144 bytes.
# Re-exported from validation so policy code has one import point.
MAX_ENVELOPE_BYTES = MAX_ENVELOPE_BYTES

# Hard client ceiling: at most six pushes per minute per side.
MAX_PUSHES_PER_MINUTE = 6
# Batching target: at most one push per minute per side under normal use.
SOFT_PUSH_TARGET_PER_MINUTE = 1
# Watcher/transport change detection must not poll faster than this.
MIN_POLL_SECONDS = 30

# Relay repository size alarms (bytes).
REPO_SIZE_WARN_BYTES = 100 * 1024 * 1024
REPO_SIZE_BLOCK_BYTES = 250 * 1024 * 1024
REPO_SIZE_ROTATE_BYTES = 500 * 1024 * 1024

# Incoming events older than this are outside the acceptance window.
ACCEPT_WINDOW_DAYS = 7
# Ordinary events may arrive up to 5 minutes early by the sender clock.
FUTURE_TOLERANCE_SECONDS = 300
# Clock skew warning threshold; skew at or above FUTURE_TOLERANCE_SECONDS
# blocks new pairing and scheduled sends.
CLOCK_WARN_SECONDS = 60
# Default late window for scheduled delivery: a scheduled event with no
# explicit expires_at expires 24h after deliver_at.
LATE_WINDOW_SECONDS = 24 * 3600
# Reaction flood bound: a single sender may hold at most this many active
# distinct emoji reactions on one target event. Distinct emoji are
# unbounded in principle, so without a cap a peer can bloat the reactions
# table one 32-byte row at a time.
MAX_ACTIVE_REACTIONS_PER_SENDER_TARGET = 8

_CANONICAL_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_CANONICAL_UTC_FMT = "%Y-%m-%dT%H:%M:%SZ"


def parse_canonical_utc(text: str) -> datetime:
    """Parse canonical UTC text (YYYY-MM-DDTHH:MM:SSZ) to an aware datetime.

    Raises:
        ValueError: when *text* is not canonical UTC text.
    """
    if not isinstance(text, str) or not _CANONICAL_UTC_RE.match(text):
        raise ValueError(f"not canonical UTC text: {text!r}")
    try:
        parsed = datetime.strptime(text, _CANONICAL_UTC_FMT)
    except ValueError as exc:
        raise ValueError(f"not canonical UTC text: {text!r}") from exc
    return parsed.replace(tzinfo=timezone.utc)


def format_canonical_utc(moment: datetime) -> str:
    """Format a datetime as canonical UTC text (whole seconds, Z suffix)."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (
        moment.astimezone(timezone.utc)
        .replace(microsecond=0)
        .strftime(_CANONICAL_UTC_FMT)
    )


Timestamp = Union[int, float, str]


def _to_epoch_seconds(value: Timestamp) -> float:
    if isinstance(value, bool):
        raise ValueError(f"invalid history timestamp: {value!r}")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return parse_canonical_utc(value).timestamp()
    raise ValueError(f"invalid history timestamp: {value!r}")


def _pushes_in_window(history: Iterable[Timestamp], now: float) -> int:
    count = 0
    for entry in history:
        stamp = _to_epoch_seconds(entry)
        if now - 60.0 < stamp <= now:
            count += 1
    return count


def check_send_rate(
    history: Iterable[Timestamp], now: float | None = None
) -> str:
    """Apply the hard push ceiling to recent push history.

    *history* holds timestamps (epoch seconds or canonical UTC text) of
    recent pushes. The window is rolling: a new push is rate limited when
    MAX_PUSHES_PER_MINUTE pushes already landed in the trailing 60 seconds.

    Returns:
        "ok" when another push may go out, "rate_limited" otherwise.

    Raises:
        ValueError: on an unparseable history entry.
    """
    moment = time.time() if now is None else float(now)
    if _pushes_in_window(history, moment) >= MAX_PUSHES_PER_MINUTE:
        return "rate_limited"
    return "ok"


def soft_push_target_exceeded(
    history: Iterable[Timestamp], now: float | None = None
) -> bool:
    """True when recent pushes exceed the one-per-minute batching target."""
    moment = time.time() if now is None else float(now)
    return _pushes_in_window(history, moment) > SOFT_PUSH_TARGET_PER_MINUTE


def check_repo_size(num_bytes: int) -> str:
    """Map a relay repository size to its alarm level.

    Returns:
        "rotate" at or above 500 MiB, "block" at or above 250 MiB,
        "warn" at or above 100 MiB, otherwise "ok".

    Raises:
        ValueError: on a negative size.
    """
    if not isinstance(num_bytes, int) or isinstance(num_bytes, bool):
        raise ValueError(f"repo size must be an int of bytes: {num_bytes!r}")
    if num_bytes < 0:
        raise ValueError(f"repo size must be non-negative: {num_bytes!r}")
    if num_bytes >= REPO_SIZE_ROTATE_BYTES:
        return "rotate"
    if num_bytes >= REPO_SIZE_BLOCK_BYTES:
        return "block"
    if num_bytes >= REPO_SIZE_WARN_BYTES:
        return "warn"
    return "ok"


def check_poll_interval(seconds: int | float) -> bool:
    """True when a poll interval respects the 30 second floor."""
    return seconds >= MIN_POLL_SECONDS


def check_clock_skew(skew_seconds: float) -> str:
    """Map observed clock skew to the plan's clock contract.

    Returns:
        "block" at 300 seconds or more (blocks new pairing and scheduled
        sends), "warn" at 60 seconds or more, otherwise "ok".
    """
    skew = abs(float(skew_seconds))
    if skew >= FUTURE_TOLERANCE_SECONDS:
        return "block"
    if skew >= CLOCK_WARN_SECONDS:
        return "warn"
    return "ok"


def within_accept_window(created_at: str, now: str) -> bool:
    """True when an event timestamp is inside the acceptance window.

    Accepts timestamps up to FUTURE_TOLERANCE_SECONDS early and up to
    ACCEPT_WINDOW_DAYS old. Anything else is outside the window.
    """
    created = parse_canonical_utc(created_at)
    moment = parse_canonical_utc(now)
    age = (moment - created).total_seconds()
    return -FUTURE_TOLERANCE_SECONDS <= age <= ACCEPT_WINDOW_DAYS * 86400


def add_seconds(text: str, seconds: int) -> str:
    """Return canonical UTC text for *text* plus *seconds*."""
    return format_canonical_utc(parse_canonical_utc(text) + timedelta(seconds=seconds))
