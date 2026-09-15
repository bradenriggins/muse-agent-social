"""Sender-side scheduler for delivery.scheduled events.

State machine (locked by the plan):

    scheduled -> released | canceled | expired

* schedule() stores the sealed-to-be inner event LOCALLY in the
  scheduler_queue table. It is never uploaded before deliver_at.
* cancel() before release is final. After release, cancel() raises
  AlreadyReleasedError: cancellation becomes a signed retraction request,
  built via request_retraction_after_release(), and unread delivery cannot
  be guaranteed.
* run_due() releases due events through the same transactional outgoing
  queue as immediate sends, with PER-ROW isolation: every due row is
  processed in its own transaction inside its own try/except, so one
  poison row (a release_fn that raises, e.g. a broken relay config) can
  never wedge releases for other rows or relationships. A row whose
  release_fn raises MAX_RELEASE_ATTEMPTS times (3) moves to the
  dead-letter state "dead" and is never attempted again; dead-lettered
  rows are visible through list_scheduled(conn, "dead") and the
  `mas inspect scheduler` command.
* A due event whose effective expiry has passed transitions to expired and
  is never released. With no explicit expires_at, the effective expiry is
  deliver_at plus the default 24h late window. A late but unexpired
  release passes late_by_seconds to release_fn so the send path can mark
  it in the payload.

release_fn contract::

    release_fn(conn, *, scheduled_id, sealed_event_envelope, late_by_seconds)

* conn is inside the scheduler's transaction: enqueue with plain
  statements, do not BEGIN/COMMIT yourself.
* Enqueue into the same transactional outgoing queue as immediate sends,
  keyed idempotently on scheduled_id.
* Record late_by_seconds in the released payload when it is greater than
  zero (the plan's "mark late_by_seconds in the payload").
* Durably finish before returning; run_due commits the transaction right
  after release_fn returns.
"""

from __future__ import annotations

import re
import sqlite3
import uuid
from typing import Any, Callable

from muse_agent_social.policy.limits import (
    FUTURE_TOLERANCE_SECONDS,
    LATE_WINDOW_SECONDS,
    MAX_ENVELOPE_BYTES,
    add_seconds,
    check_clock_skew,
    parse_canonical_utc,
)
from muse_agent_social.store.db import transaction

__all__ = [
    "SCHEDULER_STATES",
    "DEFAULT_LATE_WINDOW_SECONDS",
    "MAX_RELEASE_ATTEMPTS",
    "SchedulerError",
    "UnknownScheduledIdError",
    "AlreadyReleasedError",
    "InvalidSchedulerTransition",
    "ScheduledIdConflictError",
    "schedule",
    "get_scheduled",
    "list_scheduled",
    "cancel",
    "request_retraction_after_release",
    "run_due",
]

SCHEDULER_STATES = ("scheduled", "released", "canceled", "expired", "dead")
DEFAULT_LATE_WINDOW_SECONDS = LATE_WINDOW_SECONDS
# A due row whose release_fn raises this many times is dead-lettered: it
# moves to state "dead" and run_due never attempts it again. Three strikes
# absorbs transient relay outages while bounding how long one poison row
# can churn; the row stays inspectable via list_scheduled(conn, "dead").
MAX_RELEASE_ATTEMPTS = 3

# Idempotent dead-letter schema fragment. The owning module applies its
# own fragment directly (the same pattern as rotation._ensure_tables()):
# the release_failures counter is added with ALTER TABLE, and the state
# CHECK is widened with 'dead' via a table rebuild because SQLite cannot
# alter a CHECK constraint in place. Safe to run on every call; a no-op
# once applied.
_V3_TABLE_SQL = """CREATE TABLE scheduler_queue_new (
    scheduled_id TEXT PRIMARY KEY,
    inner_event  BLOB NOT NULL,
    deliver_at   TEXT NOT NULL CHECK(deliver_at GLOB '????-??-??T??:??:??Z'),
    expires_at   TEXT CHECK(expires_at IS NULL
        OR expires_at GLOB '????-??-??T??:??:??Z'),
    state        TEXT NOT NULL
        CHECK(state IN ('scheduled', 'released', 'canceled', 'expired',
                        'dead')),
    release_failures INTEGER NOT NULL DEFAULT 0
)"""


def _ensure_dead_letter_schema(conn: sqlite3.Connection) -> None:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' "
        "AND name = 'scheduler_queue'"
    ).fetchone()
    if row is None:
        return  # migrate() owns initial creation; nothing to widen yet
    sql = row["sql"] or ""
    if "release_failures" not in sql:
        conn.execute(
            "ALTER TABLE scheduler_queue ADD COLUMN release_failures "
            "INTEGER NOT NULL DEFAULT 0"
        )
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' "
            "AND name = 'scheduler_queue'"
        ).fetchone()
        sql = row["sql"] or ""
    if "'dead'" not in sql:
        # The rebuild runs in one transaction so a crash can never leave
        # the table half-migrated; a stale scheduler_queue_new from a
        # crashed attempt is dropped first.
        with transaction(conn):
            conn.execute("DROP TABLE IF EXISTS scheduler_queue_new")
            conn.execute(_V3_TABLE_SQL)
            conn.execute(
                "INSERT INTO scheduler_queue_new "
                "(scheduled_id, inner_event, deliver_at, expires_at, state, "
                "release_failures) SELECT scheduled_id, inner_event, "
                "deliver_at, expires_at, state, release_failures "
                "FROM scheduler_queue"
            )
            conn.execute("DROP TABLE scheduler_queue")
            conn.execute(
                "ALTER TABLE scheduler_queue_new RENAME TO scheduler_queue"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scheduler_deliver "
                "ON scheduler_queue(deliver_at, state)"
            )

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class SchedulerError(Exception):
    """Base error for scheduler failures. Carries a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class UnknownScheduledIdError(SchedulerError):
    def __init__(self, scheduled_id: str) -> None:
        super().__init__("unknown_scheduled_id", scheduled_id)


class AlreadyReleasedError(SchedulerError):
    """The event already released; cancel is no longer possible."""

    def __init__(self, scheduled_id: str) -> None:
        super().__init__(
            "already_released",
            f"{scheduled_id}: cancellation after release is a signed "
            "retraction request; use request_retraction_after_release()",
        )
        self.scheduled_id = scheduled_id


class InvalidSchedulerTransition(SchedulerError):
    def __init__(self, scheduled_id: str, detail: str) -> None:
        super().__init__("invalid_transition", f"{scheduled_id}: {detail}")


class ScheduledIdConflictError(SchedulerError):
    def __init__(self, scheduled_id: str) -> None:
        super().__init__(
            "scheduled_id_conflict",
            f"{scheduled_id}: id already scheduled with different bytes",
        )


def _validate_scheduled_id(scheduled_id: str) -> str:
    if not isinstance(scheduled_id, str) or not _UUID_RE.match(scheduled_id):
        raise SchedulerError("invalid_scheduled_id", str(scheduled_id))
    return scheduled_id


def _validate_moment(value: str, field: str) -> str:
    try:
        parse_canonical_utc(value)
    except (ValueError, TypeError) as exc:
        raise SchedulerError("invalid_timestamp", f"{field}={value!r}") from exc
    return value


def _check_clock(clock_skew_seconds: float | None, action: str) -> None:
    if clock_skew_seconds is None:
        return
    if check_clock_skew(clock_skew_seconds) == "block":
        raise SchedulerError(
            "clock_skew_blocks_scheduled_send",
            f"{action}: skew {clock_skew_seconds}s at or above "
            f"{FUTURE_TOLERANCE_SECONDS}s",
        )


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "scheduled_id": row["scheduled_id"],
        "inner_event": bytes(row["inner_event"]),
        "deliver_at": row["deliver_at"],
        "expires_at": row["expires_at"],
        "state": row["state"],
        "release_failures": int(row["release_failures"] or 0),
    }


def _effective_expires_at(deliver_at: str, expires_at: str | None) -> str:
    if expires_at is not None:
        return expires_at
    return add_seconds(deliver_at, DEFAULT_LATE_WINDOW_SECONDS)


def schedule(
    conn: sqlite3.Connection,
    sealed_event_envelope: bytes,
    deliver_at: str,
    expires_at: str | None,
    scheduled_id: str | None = None,
    *,
    clock_skew_seconds: float | None = None,
) -> str:
    """Store a sealed-to-be event for future delivery.

    The bytes are stored LOCALLY in scheduler_queue and are never uploaded
    before deliver_at. schedule() is idempotent on scheduled_id: repeating
    the call with the same id and identical bytes returns the id without
    creating a second row.

    Raises:
        SchedulerError: on oversize/empty bytes, bad timestamps,
            expires_at not after deliver_at, a conflicting scheduled_id,
            or clock skew that blocks scheduled sends.
    """
    _ensure_dead_letter_schema(conn)
    _check_clock(clock_skew_seconds, "schedule")
    if not isinstance(sealed_event_envelope, (bytes, bytearray)):
        raise SchedulerError("invalid_envelope", "envelope must be bytes")
    if len(sealed_event_envelope) == 0:
        raise SchedulerError("invalid_envelope", "envelope must not be empty")
    if len(sealed_event_envelope) > MAX_ENVELOPE_BYTES:
        raise SchedulerError("envelope_too_large", str(len(sealed_event_envelope)))
    _validate_moment(deliver_at, "deliver_at")
    if expires_at is not None:
        _validate_moment(expires_at, "expires_at")
        if parse_canonical_utc(expires_at) <= parse_canonical_utc(deliver_at):
            raise SchedulerError(
                "expires_not_after_deliver_at",
                f"expires_at={expires_at} deliver_at={deliver_at}",
            )
    sid = str(uuid.uuid4()) if scheduled_id is None else _validate_scheduled_id(
        scheduled_id
    )
    existing = conn.execute(
        "SELECT scheduled_id, inner_event FROM scheduler_queue "
        "WHERE scheduled_id = ?",
        (sid,),
    ).fetchone()
    if existing is not None:
        if bytes(existing["inner_event"]) != bytes(sealed_event_envelope):
            raise ScheduledIdConflictError(sid)
        return sid
    with transaction(conn):
        conn.execute(
            "INSERT INTO scheduler_queue "
            "(scheduled_id, inner_event, deliver_at, expires_at, state) "
            "VALUES (?, ?, ?, ?, 'scheduled')",
            (sid, bytes(sealed_event_envelope), deliver_at, expires_at),
        )
    return sid


def get_scheduled(
    conn: sqlite3.Connection, scheduled_id: str
) -> dict[str, Any] | None:
    """Return one scheduler row as a dict, or None when unknown."""
    _ensure_dead_letter_schema(conn)
    row = conn.execute(
        "SELECT scheduled_id, inner_event, deliver_at, expires_at, state, "
        "release_failures FROM scheduler_queue WHERE scheduled_id = ?",
        (scheduled_id,),
    ).fetchone()
    return _row_to_dict(row) if row is not None else None


def list_scheduled(
    conn: sqlite3.Connection, state: str | None = None
) -> list[dict[str, Any]]:
    """List scheduler rows, optionally filtered by state, by deliver_at."""
    _ensure_dead_letter_schema(conn)
    if state is not None and state not in SCHEDULER_STATES:
        raise SchedulerError("invalid_state", str(state))
    if state is None:
        rows = conn.execute(
            "SELECT scheduled_id, inner_event, deliver_at, expires_at, state, "
            "release_failures FROM scheduler_queue "
            "ORDER BY deliver_at, scheduled_id;"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT scheduled_id, inner_event, deliver_at, expires_at, state, "
            "release_failures FROM scheduler_queue WHERE state = ? "
            "ORDER BY deliver_at, scheduled_id;",
            (state,),
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def cancel(conn: sqlite3.Connection, scheduled_id: str) -> str:
    """Cancel a scheduled event before release. Final.

    scheduled -> canceled. Canceling an already-canceled row is idempotent.
    Canceling a released row raises AlreadyReleasedError: after release,
    cancellation becomes a signed retraction request (see
    request_retraction_after_release()) and cannot guarantee unread
    delivery. Canceling an expired or unknown row raises.

    Returns:
        The terminal state ("canceled").
    """
    _ensure_dead_letter_schema(conn)
    row = get_scheduled(conn, scheduled_id)
    if row is None:
        raise UnknownScheduledIdError(scheduled_id)
    state = row["state"]
    if state == "scheduled":
        with transaction(conn):
            cursor = conn.execute(
                "UPDATE scheduler_queue SET state = 'canceled' "
                "WHERE scheduled_id = ? AND state = 'scheduled'",
                (scheduled_id,),
            )
            if cursor.rowcount != 1:
                raise InvalidSchedulerTransition(
                    scheduled_id, "row changed state concurrently"
                )
        return "canceled"
    if state == "canceled":
        return "canceled"
    if state == "released":
        raise AlreadyReleasedError(scheduled_id)
    raise InvalidSchedulerTransition(
        scheduled_id, f"cannot cancel from state {state!r}"
    )


def request_retraction_after_release(
    conn: sqlite3.Connection, scheduled_id: str
) -> dict[str, Any]:
    """Build the interface note for a post-release retraction request.

    Cancellation after release is a signed retraction request, not a
    recall: the event already left through the outgoing queue, so unread
    delivery cannot be guaranteed. The send path consumes this note: it
    parses protected.event_id from the sealed envelope and emits a signed
    retraction event for the original.

    Returns:
        {"action": "request_retraction", "scheduled_id": ...,
         "sealed_event_envelope": bytes, "state": "released", "note": ...}

    Raises:
        SchedulerError: when the row is unknown or not released.
    """
    row = get_scheduled(conn, scheduled_id)
    if row is None:
        raise UnknownScheduledIdError(scheduled_id)
    if row["state"] != "released":
        raise InvalidSchedulerTransition(
            scheduled_id,
            f"retraction request requires state 'released', "
            f"found {row['state']!r}",
        )
    return {
        "action": "request_retraction",
        "scheduled_id": scheduled_id,
        "sealed_event_envelope": row["inner_event"],
        "state": "released",
        "note": (
            "Cancellation after release is a signed retraction request. "
            "The send path must parse protected.event_id from "
            "sealed_event_envelope and emit a signed retraction event; "
            "unread delivery cannot be guaranteed."
        ),
    }


ReleaseFn = Callable[..., None]


def _release_one_row(
    conn: sqlite3.Connection,
    now_dt: Any,
    release_fn: ReleaseFn,
    row: dict[str, Any],
) -> tuple[str, int]:
    """Process one due row inside its own transaction.

    Returns (status, late_by_seconds) where status is one of "released",
    "expired", "not_due", "skipped" (row left 'scheduled' by a concurrent
    writer), or "skipped_canceled" (the row was canceled before the claim;
    a stable no-op, never a delivery).

    Raises:
        Whatever release_fn raises (the caller records it per row), or
        InvalidSchedulerTransition on a concurrent state change.
    """
    sid = row["scheduled_id"]
    with transaction(conn):
        current = conn.execute(
            "SELECT state FROM scheduler_queue WHERE scheduled_id = ?",
            (sid,),
        ).fetchone()
        if current is None:
            return ("skipped", 0)
        if current["state"] == "canceled":
            # Cancel wins over release: a cancel that landed between the
            # due-row scan and this claim is honored inside the release
            # transaction, so a canceled row is never delivered.
            return ("skipped_canceled", 0)
        if current["state"] != "scheduled":
            return ("skipped", 0)
        effective = _effective_expires_at(row["deliver_at"], row["expires_at"])
        if now_dt >= parse_canonical_utc(effective):
            conn.execute(
                "UPDATE scheduler_queue SET state = 'expired' "
                "WHERE scheduled_id = ? AND state = 'scheduled'",
                (sid,),
            )
            return ("expired", 0)
        deliver_dt = parse_canonical_utc(row["deliver_at"])
        if now_dt < deliver_dt:
            return ("not_due", 0)
        late_by = max(0, int((now_dt - deliver_dt).total_seconds()))
        cursor = conn.execute(
            "UPDATE scheduler_queue SET state = 'released' "
            "WHERE scheduled_id = ? AND state = 'scheduled'",
            (sid,),
        )
        if cursor.rowcount != 1:
            raise InvalidSchedulerTransition(
                sid, "row changed state concurrently"
            )
        release_fn(
            conn,
            scheduled_id=sid,
            sealed_event_envelope=row["inner_event"],
            late_by_seconds=late_by,
        )
    return ("released", late_by)


def _record_release_failure(conn: sqlite3.Connection, scheduled_id: str) -> int:
    """Count one release failure against a row; dead-letter at the limit.

    Returns the new failure count. When the count reaches
    MAX_RELEASE_ATTEMPTS the row moves to state "dead" and run_due stops
    attempting it.
    """
    with transaction(conn):
        conn.execute(
            "UPDATE scheduler_queue SET release_failures = release_failures + 1 "
            "WHERE scheduled_id = ?",
            (scheduled_id,),
        )
        failures = int(
            conn.execute(
                "SELECT release_failures FROM scheduler_queue "
                "WHERE scheduled_id = ?",
                (scheduled_id,),
            ).fetchone()[0]
        )
        if failures >= MAX_RELEASE_ATTEMPTS:
            conn.execute(
                "UPDATE scheduler_queue SET state = 'dead' "
                "WHERE scheduled_id = ? AND state = 'scheduled'",
                (scheduled_id,),
            )
    return failures


def run_due(
    conn: sqlite3.Connection,
    now: str,
    release_fn: ReleaseFn,
    *,
    clock_skew_seconds: float | None = None,
) -> dict[str, Any]:
    """Release due scheduled events through the transactional outgoing queue.

    PER-ROW ISOLATION: every due row is processed in its own transaction
    inside its own try/except. A release_fn exception rolls back only
    that row's claim and is recorded against the row; it never propagates
    and never blocks other rows or relationships. A row whose release_fn
    raises MAX_RELEASE_ATTEMPTS times (3) moves to the dead-letter state
    "dead" and is never attempted again.

    For each scheduled row with deliver_at <= now: rows past their
    effective expiry (explicit expires_at, else deliver_at plus the 24h
    default late window) transition to expired and are never released;
    the rest transition to released and are handed to release_fn inside
    the same transaction.

    Releasing a canceled row is a stable no-op, never a delivery: the
    row's state is re-checked inside the release transaction, so a cancel
    that lands between the due-row scan and the claim is honored.

    release_fn(conn, *, scheduled_id, sealed_event_envelope,
    late_by_seconds) must enqueue the sealed event into the same
    transactional outgoing queue as immediate sends, keyed idempotently on
    scheduled_id, and record late_by_seconds in the payload when positive.
    It must use plain statements on the given connection (no nested
    transaction) and finish durably before returning.

    Restart safety: the claim (scheduled -> released) and the enqueue
    commit atomically. A crash before commit leaves the row scheduled for
    a later run; a crash after commit leaves exactly one released row and
    one enqueued event, and release_fn's idempotency key absorbs any
    retried call.

    Returns:
        {"released": [scheduled_id...], "expired": [scheduled_id...],
         "late": {scheduled_id: late_by_seconds, ...},
         "failed": [scheduled_id...], "dead": [scheduled_id...],
         "skipped_canceled": [scheduled_id...]}

    Raises:
        SchedulerError: on a bad *now* timestamp or blocking clock skew.
        release_fn exceptions are contained per row and never propagate.
    """
    _ensure_dead_letter_schema(conn)
    _validate_moment(now, "now")
    _check_clock(clock_skew_seconds, "run_due")
    now_dt = parse_canonical_utc(now)
    summary: dict[str, Any] = {
        "released": [],
        "expired": [],
        "late": {},
        "failed": [],
        "dead": [],
        "skipped_canceled": [],
    }
    rows = conn.execute(
        "SELECT scheduled_id, inner_event, deliver_at, expires_at, state, "
        "release_failures FROM scheduler_queue "
        "WHERE state = 'scheduled' AND release_failures < ? "
        "ORDER BY deliver_at, scheduled_id;",
        (MAX_RELEASE_ATTEMPTS,),
    ).fetchall()
    for db_row in rows:
        row = _row_to_dict(db_row)
        sid = row["scheduled_id"]
        try:
            status, late_by = _release_one_row(conn, now_dt, release_fn, row)
        except Exception:
            # Per-row isolation: record the failure against this row only
            # and continue with the next due row.
            failures = _record_release_failure(conn, sid)
            if failures >= MAX_RELEASE_ATTEMPTS:
                summary["dead"].append(sid)
            else:
                summary["failed"].append(sid)
            continue
        if status == "released":
            summary["released"].append(sid)
            if late_by > 0:
                summary["late"][sid] = late_by
        elif status == "expired":
            summary["expired"].append(sid)
        elif status == "skipped_canceled":
            summary["skipped_canceled"].append(sid)
    return summary
