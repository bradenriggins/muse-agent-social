"""Deterministic conversation projections over the append-only event log.

This module rebuilds every queryable conversation view (messages, edits,
retractions, reactions, receipts, polls, tasks, human requests, deliveries,
key-event stream) from the immutable ``events`` table plus the validated
decrypted payloads staged in ``event_payloads``. The event log is the only
source of truth; every projection table can be wiped and rebuilt in one
transaction with byte-identical results.

Input contract (receive-path seam)
----------------------------------
The receive path decrypts and validates each sealed envelope once, at commit
time, then calls :func:`record_projection_input` inside the same atomic
transaction that inserts the ``events`` row. The payload stored there is the
single source the projection logic reads, so :func:`rebuild_projections`
never needs key material and is fully deterministic.

Incremental apply (:func:`apply_event`) runs the exact same per-event logic
as a rebuild, so the receive path (or a projection worker draining
``projection_queue``) can project one event at a time. ``apply_event`` does
not open its own transaction; call it inside the caller's transaction, or
let each statement auto-commit.

Ordering
--------
Within one sender, ``sender_seq`` is authoritative. Across senders, events
order by ``(created_at, sender identity bytes, sender_seq)``. ``created_at``
is canonical UTC text, so lexicographic order is chronological order, and
``sender`` is compared with SQLite BINARY collation (byte order). A final
``event_id`` tiebreak keeps iteration total and deterministic.

Errors
------
Semantic rejections raise :class:`ProjectionError` carrying a stable
``code`` (never payload content). Sequence forks are quarantined, never
projected. Unknown event types known to the protocol but without a
projection rule (relationship.ready, migration.*) are no-ops.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from muse_agent_social.canonical import restricted_jcs, strict_parse
from muse_agent_social.policy.limits import (
    FUTURE_TOLERANCE_SECONDS,
    MAX_ACTIVE_REACTIONS_PER_SENDER_TARGET,
    add_seconds,
)
from muse_agent_social.store.db import get_user_version, transaction, utcnow
from muse_agent_social.validation import PAYLOAD_DISPATCH, validate_payload

__all__ = [
    "PROJECTIONS_SCHEMA_VERSION",
    "ProjectionError",
    "apply_event",
    "expire_pending_refs",
    "get_conversation",
    "migrate_projections",
    "quarantine_event",
    "rebuild_projections",
    "record_projection_input",
]

# Schema version owned by this track. The skeleton track owns version 1;
# this migration is version 2, and the human-approval attestation column
# is version 3. See INTERFACE.md for the bump contract.
PROJECTIONS_SCHEMA_VERSION = 4

# Seven days, in seconds, before a missing projection target expires.
PENDING_TARGET_TTL_SECONDS = 7 * 24 * 60 * 60

# Event types with no projection rule. They are valid protocol events;
# projecting them is a no-op rather than a rejection.
_NO_PROJECTION_TYPES = frozenset(
    {"relationship.ready", "migration.ready", "migration.commit", "identity.rotated"}
)

_V2_DDL = """
-- Validated decrypted payload for each accepted event. Written by the
-- receive path in the same atomic transaction as the events row (see
-- record_projection_input). reply_to comes from the protected header,
-- which has no column on events.
CREATE TABLE IF NOT EXISTS event_payloads (
    event_id   TEXT PRIMARY KEY REFERENCES events(event_id),
    event_type TEXT NOT NULL,
    payload    TEXT NOT NULL,
    reply_to   TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    event_id           TEXT PRIMARY KEY,
    relationship_id    TEXT NOT NULL,
    conversation_id    TEXT NOT NULL,
    thread_id          TEXT,
    sender             TEXT NOT NULL,
    sender_seq         INTEGER NOT NULL,
    created_at         TEXT NOT NULL,
    body               TEXT NOT NULL,
    format             TEXT NOT NULL CHECK(format IN ('plain', 'markdown-safe')),
    reply_to           TEXT,
    reply_state        TEXT NOT NULL DEFAULT 'ok'
        CHECK(reply_state IN ('ok', 'pending', 'unavailable')),
    edited             INTEGER NOT NULL DEFAULT 0 CHECK(edited IN (0, 1)),
    current_body       TEXT NOT NULL,
    retracted          INTEGER NOT NULL DEFAULT 0 CHECK(retracted IN (0, 1)),
    retraction_event_id TEXT,
    retracted_at       TEXT,
    retraction_reason  TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation
    ON messages(relationship_id, conversation_id, created_at, sender, sender_seq);

-- Revision 0 is the original body; each accepted edit appends one row.
CREATE TABLE IF NOT EXISTS message_revisions (
    event_id      TEXT NOT NULL,
    revision_no   INTEGER NOT NULL CHECK(revision_no >= 0),
    body          TEXT NOT NULL,
    edited_at     TEXT NOT NULL,
    edit_event_id TEXT,
    reason        TEXT,
    PRIMARY KEY (event_id, revision_no)
);

-- One row per (target, sender, emoji). Removals deactivate, never delete.
CREATE TABLE IF NOT EXISTS reactions (
    target_event_id  TEXT NOT NULL,
    sender           TEXT NOT NULL,
    emoji            TEXT NOT NULL,
    active           INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    added_event_id   TEXT NOT NULL,
    added_at         TEXT NOT NULL,
    removed_event_id TEXT,
    removed_at       TEXT,
    PRIMARY KEY (target_event_id, sender, emoji)
);
CREATE INDEX IF NOT EXISTS idx_reactions_target
    ON reactions(target_event_id, active);

CREATE TABLE IF NOT EXISTS receipts (
    target_event_id  TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK(kind IN ('accepted', 'seen')),
    sender           TEXT NOT NULL,
    at               TEXT NOT NULL,
    receipt_event_id TEXT NOT NULL,
    PRIMARY KEY (target_event_id, kind, sender)
);
CREATE INDEX IF NOT EXISTS idx_receipts_target
    ON receipts(target_event_id);

CREATE TABLE IF NOT EXISTS polls (
    poll_id        TEXT PRIMARY KEY,
    relationship_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    thread_id      TEXT,
    sender         TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    question       TEXT NOT NULL,
    choices        TEXT NOT NULL,
    closes_at      TEXT NOT NULL,
    multi_select   INTEGER NOT NULL CHECK(multi_select IN (0, 1)),
    response_count INTEGER NOT NULL DEFAULT 0 CHECK(response_count >= 0)
);

-- Latest response per (poll, sender) wins; the event log keeps history.
CREATE TABLE IF NOT EXISTS poll_responses (
    poll_id           TEXT NOT NULL,
    sender            TEXT NOT NULL,
    choice_ids        TEXT NOT NULL,
    human_confirmed   INTEGER NOT NULL DEFAULT 0 CHECK(human_confirmed IN (0, 1)),
    approval_record_id TEXT,
    response_event_id TEXT NOT NULL,
    responded_at      TEXT NOT NULL,
    PRIMARY KEY (poll_id, sender)
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id           TEXT PRIMARY KEY,
    relationship_id   TEXT NOT NULL,
    conversation_id   TEXT NOT NULL,
    thread_id         TEXT,
    sender            TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    title             TEXT NOT NULL,
    owner_identity    TEXT NOT NULL,
    due_at            TEXT,
    status            TEXT NOT NULL DEFAULT 'open'
        CHECK(status IN ('open', 'in_progress', 'blocked', 'done', 'canceled')),
    status_event_id   TEXT,
    status_updated_at TEXT,
    note              TEXT
);

CREATE TABLE IF NOT EXISTS human_requests (
    request_id        TEXT PRIMARY KEY,
    relationship_id   TEXT NOT NULL,
    conversation_id   TEXT NOT NULL,
    thread_id         TEXT,
    sender            TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    prompt            TEXT NOT NULL,
    response_shape    TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'open'
        CHECK(state IN ('open', 'responded', 'expired')),
    answer            TEXT,
    approved          INTEGER CHECK(approved IS NULL OR approved IN (0, 1)),
    responded_at      TEXT,
    response_event_id TEXT,
    approval_record_id TEXT
);

CREATE TABLE IF NOT EXISTS deliveries (
    scheduled_event_id TEXT PRIMARY KEY,
    relationship_id    TEXT NOT NULL,
    sender             TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    inner_event_id     TEXT NOT NULL,
    deliver_at         TEXT NOT NULL,
    late_by_seconds    INTEGER CHECK(late_by_seconds IS NULL OR late_by_seconds >= 0),
    state              TEXT NOT NULL DEFAULT 'scheduled'
        CHECK(state IN ('scheduled', 'canceled')),
    canceled_at        TEXT,
    cancel_event_id    TEXT
);
CREATE INDEX IF NOT EXISTS idx_deliveries_inner
    ON deliveries(inner_event_id);

-- Projected stream of key-rotation events. The rotation track owns the
-- key_epochs table; this table is the queryable event stream only.
CREATE TABLE IF NOT EXISTS security_key_events (
    event_id        TEXT PRIMARY KEY,
    relationship_id TEXT NOT NULL,
    sender          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    key_epoch       INTEGER NOT NULL,
    action          TEXT NOT NULL CHECK(action IN ('prepare', 'ack', 'confirm', 'commit'))
);

-- Thread registry uses the skeleton threads/conversations tables. This
-- table carries the projection metadata the skeleton tables cannot hold.
CREATE TABLE IF NOT EXISTS thread_state (
    thread_id       TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    root_event_id   TEXT,
    message_count   INTEGER NOT NULL DEFAULT 0 CHECK(message_count >= 0),
    last_event_at   TEXT
);

-- References to not-yet-accepted targets. Resolved when the target is
-- projected; expired after seven days.
CREATE TABLE IF NOT EXISTS pending_refs (
    event_id        TEXT PRIMARY KEY,
    relationship_id TEXT NOT NULL,
    target_event_id TEXT NOT NULL,
    kind            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending'
        CHECK(state IN ('pending', 'expired', 'resolved'))
);
CREATE INDEX IF NOT EXISTS idx_pending_refs_target
    ON pending_refs(relationship_id, target_event_id, state);

-- Quarantined events: sequence forks and, during rebuilds, events rejected
-- with a stable code. Never projected.
CREATE TABLE IF NOT EXISTS quarantine (
    relationship_id TEXT NOT NULL,
    sender          TEXT NOT NULL,
    sender_seq      INTEGER NOT NULL,
    event_id        TEXT NOT NULL,
    reason          TEXT NOT NULL,
    quarantined_at  TEXT NOT NULL,
    PRIMARY KEY (relationship_id, sender, sender_seq, event_id)
);

-- Per-sender high-water mark, used to detect sequence gaps.
CREATE TABLE IF NOT EXISTS projection_cursors (
    relationship_id TEXT NOT NULL,
    sender          TEXT NOT NULL,
    max_seq         INTEGER NOT NULL CHECK(max_seq >= 0),
    PRIMARY KEY (relationship_id, sender)
);

-- Accepted but unresolved sequence gaps: seq numbers below the cursor that
-- never arrived.
CREATE TABLE IF NOT EXISTS sequence_gaps (
    relationship_id   TEXT NOT NULL,
    sender            TEXT NOT NULL,
    missing_seq       INTEGER NOT NULL CHECK(missing_seq >= 1),
    first_observed_at TEXT NOT NULL,
    PRIMARY KEY (relationship_id, sender, missing_seq)
);
"""

# Migration 3: human approval attestation on human_requests.
#
# A peer's fabricated approval_record_id must never be stored as locally
# verified. New human.responded events are classified by
# _human_response_attestation(); this migration backfills existing rows:
# only rows whose approval_record_id resolves to a real local
# human_approvals record become 'local'; everything else stays 'peer'.
_V3_DDL = """
-- Attestation for human.responded: 'peer' means the peer's claim (not
-- locally verifiable); 'local' means the approval record was verified
-- against the local human_approvals table.
ALTER TABLE human_requests ADD COLUMN attestation TEXT NOT NULL DEFAULT 'peer'
    CHECK(attestation IN ('local', 'peer'));
UPDATE human_requests SET attestation = 'local'
    WHERE approval_record_id IS NOT NULL
    AND EXISTS (SELECT 1 FROM human_approvals
                WHERE human_approvals.approval_id
                    = human_requests.approval_record_id);
"""


class ProjectionError(Exception):
    """A projection rule rejected an event.

    Attributes:
        code: stable machine-readable reason code, safe to surface and to
            store as a quarantine reason.
        detail: short human-readable note; never contains payload content.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------


def _exec_ddl(conn: sqlite3.Connection, ddl: str) -> None:
    """Execute multi-statement DDL inside the caller's transaction.

    ``executescript`` implicitly commits, so it cannot be used here; split
    into single statements instead. (This DDL contains no triggers and no
    string literals holding semicolons, so stripping line comments and
    splitting on semicolons is safe.)
    """
    lines = [
        line for line in ddl.splitlines()
        if not line.strip().startswith("--")
    ]
    for statement in "\n".join(lines).split(";"):
        statement = statement.strip()
        if statement:
            conn.execute(statement + ";")


def migrate_projections(conn: sqlite3.Connection) -> int:
    """Apply the projection-track migrations (schema version 4).

    Idempotent: safe to run repeatedly. Requires the skeleton migration
    (version 1) to be applied first. Refuses databases newer than version 4.
    Must be called outside any open transaction.

    Returns the schema version (4).
    """
    current = get_user_version(conn)
    if current < 1:
        raise ProjectionError(
            "skeleton_migration_missing",
            "run the skeleton migrate() (version 1) before migrate_projections()",
        )
    if current > PROJECTIONS_SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {current} is newer than supported "
            f"version {PROJECTIONS_SCHEMA_VERSION}; refusing to downgrade"
        )
    with transaction(conn):
        _exec_ddl(conn, _V2_DDL)
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(human_requests);")]
        if "attestation" not in cols:
            _exec_ddl(conn, _V3_DDL)
        # Keep the shared version counter honest: version 4 means the v4
        # column exists too. migrate_projections() used to stamp version 4
        # after only the v2/v3 DDL, which left a version-4 database missing
        # prior_peer_identity_id and made migrate() skip it forever.
        # (Lazy import: migrations.py imports this module at load time.)
        from muse_agent_social.store.migrations import _ensure_v4_column

        _ensure_v4_column(conn)
        # Same story for the approval lifecycle columns: this track also
        # stamps version 4, so it must also guarantee the columns exist.
        from muse_agent_social.model.approvals import ensure_approvals_columns

        ensure_approvals_columns(conn)
        if current < PROJECTIONS_SCHEMA_VERSION:
            conn.execute(
                f"PRAGMA user_version = {PROJECTIONS_SCHEMA_VERSION};"
            )
            conn.execute(
                "INSERT OR REPLACE INTO migration_state(key, value) "
                "VALUES ('projections_migration', '4');"
            )
    return PROJECTIONS_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Receive-path seam: payload staging
# ---------------------------------------------------------------------------


def record_projection_input(
    conn: sqlite3.Connection,
    *,
    event_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    reply_to: str | None = None,
) -> None:
    """Stage the validated decrypted payload for one accepted event.

    Call inside the same atomic transaction that inserts the ``events`` row.
    The payload is re-validated with ``validate_payload`` and stored as
    canonical JSON, so projections never see an unvalidated body. ``reply_to``
    is carried from the protected header, which has no column on ``events``.

    Idempotent: re-staging the same event is a no-op.
    """
    validate_payload(event_type, payload)
    if reply_to is not None and not isinstance(reply_to, str):
        raise ProjectionError("invalid_reply_to", "reply_to must be a string or null")
    payload_json = restricted_jcs(dict(payload)).decode("utf-8")
    conn.execute(
        "INSERT OR IGNORE INTO event_payloads(event_id, event_type, payload, reply_to)"
        " VALUES (?, ?, ?, ?);",
        (event_id, event_type, payload_json, reply_to),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _row_to_event(event_row: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize an event row mapping to the dict the handlers expect."""
    ev = dict(event_row)
    required = (
        "event_id",
        "relationship_id",
        "conversation_id",
        "sender",
        "sender_seq",
        "created_at",
        "event_type",
        "payload",
    )
    missing = [k for k in required if k not in ev]
    if missing:
        raise ProjectionError("malformed_event_row", f"missing: {','.join(missing)}")
    ev.setdefault("thread_id", None)
    ev.setdefault("reply_to", None)
    ev.setdefault("key_epoch", None)
    payload = ev["payload"]
    if isinstance(payload, (str, bytes)):
        data = payload.encode("utf-8") if isinstance(payload, str) else payload
        payload = strict_parse(data)
        ev["payload"] = payload
    if not isinstance(payload, dict):
        raise ProjectionError("malformed_event_row", "payload must be an object")
    return ev


def _mutation(
    op: str, table: str | None, key: str | None, info: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {"op": op, "table": table, "key": key, "info": info or {}}


def _target_event(
    conn: sqlite3.Connection, relationship_id: str, target_event_id: str
) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT event_id, conversation_id, thread_id, sender, event_type FROM events"
        " WHERE relationship_id = ? AND event_id = ?;",
        (relationship_id, target_event_id),
    ).fetchone()


def _target_status(
    conn: sqlite3.Connection,
    ev: Mapping[str, Any],
    target_event_id: str,
    expected_type: str,
    err_code: str,
) -> str:
    """Classify a referenced target: 'missing', 'wrong_type', or 'ok'.

    'missing' means the target is not accepted yet (projection waits).
    'wrong_type' is a stable rejection. 'ok' means the target is accepted;
    the caller still checks whether its projection row exists yet.
    """
    target = _target_event(conn, ev["relationship_id"], target_event_id)
    if target is None:
        return "missing"
    if target["event_type"] != expected_type:
        raise ProjectionError(
            err_code,
            f"expected a {expected_type} target, found {target['event_type']}",
        )
    return "ok"


def _threads_match(a: str | None, b: str | None) -> bool:
    return a == b


def _check_reply_scope(
    conn: sqlite3.Connection,
    ev: Mapping[str, Any],
    target: sqlite3.Row,
) -> None:
    """reply_to must name an accepted event in the same conversation+thread."""
    if target["conversation_id"] != ev["conversation_id"] or not _threads_match(
        target["thread_id"], ev.get("thread_id")
    ):
        raise ProjectionError(
            "reply_target_scope",
            "reply_to target is not in the same conversation and thread",
        )


def _pending_state(created_at: str, now: str) -> str:
    """'pending' or 'unavailable' for a missing target, by age."""
    created = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    current = datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    if current - created >= timedelta(seconds=PENDING_TARGET_TTL_SECONDS):
        return "unavailable"
    return "pending"


def _add_pending(
    conn: sqlite3.Connection,
    ev: Mapping[str, Any],
    target_event_id: str,
    kind: str,
) -> dict[str, Any]:
    conn.execute(
        "INSERT OR IGNORE INTO pending_refs"
        "(event_id, relationship_id, target_event_id, kind, created_at, state)"
        " VALUES (?, ?, ?, ?, ?, 'pending');",
        (
            ev["event_id"],
            ev["relationship_id"],
            target_event_id,
            kind,
            ev["created_at"],
        ),
    )
    return _mutation(
        "pending", "pending_refs", ev["event_id"],
        {"target": target_event_id, "kind": kind},
    )


def _ensure_thread(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Register the thread for a message-carrying event.

    thread_id equals the first message's event_id for a new thread. A thread
    id seen before its root message arrives is registered with a pending
    root; the root fills in when that message is projected.
    """
    mutations: list[dict[str, Any]] = []
    thread_id = ev.get("thread_id")
    if not thread_id:
        return mutations
    existing = conn.execute(
        "SELECT conversation_id FROM threads WHERE thread_id = ?;", (thread_id,)
    ).fetchone()
    if existing is not None and existing["conversation_id"] != ev["conversation_id"]:
        raise ProjectionError(
            "thread_scope_mismatch",
            "thread_id already belongs to another conversation",
        )
    conn.execute(
        "INSERT OR IGNORE INTO threads(thread_id, conversation_id) VALUES (?, ?);",
        (thread_id, ev["conversation_id"]),
    )
    conn.execute(
        "INSERT OR IGNORE INTO thread_state(thread_id, conversation_id)"
        " VALUES (?, ?);",
        (thread_id, ev["conversation_id"]),
    )
    if thread_id == ev["event_id"]:
        cur = conn.execute(
            "UPDATE thread_state SET root_event_id = ?"
            " WHERE thread_id = ? AND root_event_id IS NULL;",
            (ev["event_id"], thread_id),
        )
        if cur.rowcount:
            mutations.append(
                _mutation("update", "thread_state", thread_id, {"root_event_id": ev["event_id"]})
            )
    return mutations


def _bump_thread_message(
    conn: sqlite3.Connection, thread_id: str | None, created_at: str
) -> None:
    if not thread_id:
        return
    conn.execute(
        "UPDATE thread_state SET message_count = message_count + 1,"
        " last_event_at = CASE WHEN last_event_at IS NULL OR last_event_at < ?"
        " THEN ? ELSE last_event_at END"
        " WHERE thread_id = ?;",
        (created_at, created_at, thread_id),
    )


def _update_seq_state(
    conn: sqlite3.Connection,
    relationship_id: str,
    sender: str,
    seq: int,
    observed_at: str,
) -> list[dict[str, Any]]:
    """Track the per-sender high-water mark; mark accepted gaps unresolved."""
    mutations: list[dict[str, Any]] = []
    row = conn.execute(
        "SELECT max_seq FROM projection_cursors"
        " WHERE relationship_id = ? AND sender = ?;",
        (relationship_id, sender),
    ).fetchone()
    prev_max = int(row["max_seq"]) if row else 0
    if row is None:
        conn.execute(
            "INSERT INTO projection_cursors(relationship_id, sender, max_seq)"
            " VALUES (?, ?, ?);",
            (relationship_id, sender, seq),
        )
    elif seq > prev_max:
        conn.execute(
            "UPDATE projection_cursors SET max_seq = ?"
            " WHERE relationship_id = ? AND sender = ?;",
            (seq, relationship_id, sender),
        )
    if seq > prev_max:
        for missing in range(prev_max + 1, seq):
            cur = conn.execute(
                "INSERT OR IGNORE INTO sequence_gaps"
                "(relationship_id, sender, missing_seq, first_observed_at)"
                " VALUES (?, ?, ?, ?);",
                (relationship_id, sender, missing, observed_at),
            )
            if cur.rowcount:
                mutations.append(
                    _mutation(
                        "insert", "sequence_gaps", f"{sender}:{missing}",
                        {"state": "unresolved"},
                    )
                )
    if seq <= prev_max:
        cur = conn.execute(
            "DELETE FROM sequence_gaps"
            " WHERE relationship_id = ? AND sender = ? AND missing_seq = ?;",
            (relationship_id, sender, seq),
        )
        if cur.rowcount:
            mutations.append(
                _mutation("delete", "sequence_gaps", f"{sender}:{seq}", {"state": "resolved"})
            )
    return mutations


def quarantine_event(
    conn: sqlite3.Connection,
    relationship_id: str,
    sender: str,
    sender_seq: int,
    event_id: str,
    reason: str,
) -> dict[str, Any]:
    """Record a quarantined event. Quarantined events are never projected."""
    conn.execute(
        "INSERT OR IGNORE INTO quarantine"
        "(relationship_id, sender, sender_seq, event_id, reason, quarantined_at)"
        " VALUES (?, ?, ?, ?, ?, ?);",
        (relationship_id, sender, sender_seq, event_id, reason, utcnow()),
    )
    return _mutation("quarantine", "quarantine", event_id, {"reason": reason})


def _check_fork(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Detect a sequence fork: same (sender, seq), different event bytes.

    Returns a quarantine mutation when a different event already holds this
    sender's sequence number, else None.
    """
    clash = conn.execute(
        "SELECT event_id FROM events"
        " WHERE relationship_id = ? AND sender = ? AND sender_seq = ?"
        " AND event_id != ?;",
        (ev["relationship_id"], ev["sender"], ev["sender_seq"], ev["event_id"]),
    ).fetchone()
    if clash is not None:
        return quarantine_event(
            conn,
            ev["relationship_id"],
            ev["sender"],
            int(ev["sender_seq"]),
            ev["event_id"],
            "sequence_fork",
        )
    return None


# ---------------------------------------------------------------------------
# Per-type handlers. Each returns a list of projection mutations.
# ---------------------------------------------------------------------------


def _handle_message_created(
    conn: sqlite3.Connection, ev: Mapping[str, Any], now: str
) -> list[dict[str, Any]]:
    mutations = _ensure_thread(conn, ev)
    payload = ev["payload"]
    if (
        conn.execute(
            "SELECT 1 FROM messages WHERE event_id = ?;", (ev["event_id"],)
        ).fetchone()
        is not None
    ):
        return mutations + [
            _mutation("noop", "messages", ev["event_id"], {"reason": "already_projected"})
        ]
    reply_to = ev.get("reply_to")
    reply_state = "ok"
    if reply_to:
        target = _target_event(conn, ev["relationship_id"], reply_to)
        if target is None:
            reply_state = _pending_state(ev["created_at"], now)
            mutations.append(_add_pending(conn, ev, reply_to, "reply"))
        else:
            _check_reply_scope(conn, ev, target)
    conn.execute(
        "INSERT INTO messages(event_id, relationship_id, conversation_id, thread_id,"
        " sender, sender_seq, created_at, body, format, reply_to, reply_state,"
        " edited, current_body, retracted)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0);",
        (
            ev["event_id"],
            ev["relationship_id"],
            ev["conversation_id"],
            ev.get("thread_id"),
            ev["sender"],
            ev["sender_seq"],
            ev["created_at"],
            payload["body"],
            payload["format"],
            reply_to,
            reply_state,
            payload["body"],
        ),
    )
    conn.execute(
        "INSERT INTO message_revisions(event_id, revision_no, body, edited_at)"
        " VALUES (?, 0, ?, ?);",
        (ev["event_id"], payload["body"], ev["created_at"]),
    )
    _bump_thread_message(conn, ev.get("thread_id"), ev["created_at"])
    mutations.append(_mutation("insert", "messages", ev["event_id"], {"reply_state": reply_state}))
    return mutations


def _original_message(
    conn: sqlite3.Connection, relationship_id: str, target_event_id: str
) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT event_id, sender, retracted FROM messages"
        " WHERE event_id = ?;",
        (target_event_id,),
    ).fetchone()


def _handle_message_edited(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    payload = ev["payload"]
    target_id = payload["target_event_id"]
    if (
        conn.execute(
            "SELECT 1 FROM message_revisions"
            " WHERE event_id = ? AND edit_event_id = ?;",
            (target_id, ev["event_id"]),
        ).fetchone()
        is not None
    ):
        return [_mutation("noop", "message_revisions", target_id, {"reason": "already_projected"})]
    original = _original_message(conn, ev["relationship_id"], target_id)
    if original is None:
        # Raises edit_target_not_message when the target is accepted but is
        # not a message; otherwise the target is missing or not yet
        # projected, so projection waits.
        _target_status(
            conn, ev, target_id, "message.created", "edit_target_not_message"
        )
        return [_add_pending(conn, ev, target_id, "edit")]
    if original["sender"] != ev["sender"]:
        raise ProjectionError(
            "edit_not_sender", "only the original sender may edit a message"
        )
    if original["retracted"]:
        raise ProjectionError(
            "edit_after_retract", "cannot edit a retracted message"
        )
    row = conn.execute(
        "SELECT MAX(revision_no) AS m FROM message_revisions WHERE event_id = ?;",
        (target_id,),
    ).fetchone()
    revision_no = int(row["m"]) + 1
    conn.execute(
        "INSERT INTO message_revisions"
        "(event_id, revision_no, body, edited_at, edit_event_id, reason)"
        " VALUES (?, ?, ?, ?, ?, ?);",
        (
            target_id,
            revision_no,
            payload["body"],
            ev["created_at"],
            ev["event_id"],
            payload.get("reason"),
        ),
    )
    conn.execute(
        "UPDATE messages SET edited = 1, current_body = ? WHERE event_id = ?;",
        (payload["body"], target_id),
    )
    return [
        _mutation(
            "insert", "message_revisions", f"{target_id}#{revision_no}",
            {"edit_event_id": ev["event_id"]},
        )
    ]


def _handle_message_retracted(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    payload = ev["payload"]
    target_id = payload["target_event_id"]
    original = _original_message(conn, ev["relationship_id"], target_id)
    if original is None:
        # Raises retract_target_not_message when the target is accepted but
        # is not a message; otherwise projection waits for the target.
        _target_status(
            conn, ev, target_id, "message.created", "retract_target_not_message"
        )
        return [_add_pending(conn, ev, target_id, "retract")]
    if original["sender"] != ev["sender"]:
        raise ProjectionError(
            "retract_not_sender", "only the original sender may retract a message"
        )
    if original["retracted"]:
        return [_mutation("noop", "messages", target_id, {"reason": "already_retracted"})]
    conn.execute(
        "UPDATE messages SET retracted = 1, retraction_event_id = ?,"
        " retracted_at = ?, retraction_reason = ? WHERE event_id = ?;",
        (ev["event_id"], ev["created_at"], payload.get("reason"), target_id),
    )
    return [
        _mutation(
            "update", "messages", target_id,
            {"retracted": True, "tombstone_event_id": ev["event_id"]},
        )
    ]


def _handle_reaction_added(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    payload = ev["payload"]
    target_id = payload["target_event_id"]
    if _target_event(conn, ev["relationship_id"], target_id) is None:
        return [_add_pending(conn, ev, target_id, "reaction_add")]
    row = conn.execute(
        "SELECT active, added_event_id FROM reactions"
        " WHERE target_event_id = ? AND sender = ? AND emoji = ?;",
        (target_id, ev["sender"], payload["emoji"]),
    ).fetchone()
    if row is not None and row["active"] and row["added_event_id"] == ev["event_id"]:
        return [_mutation("noop", "reactions", target_id, {"reason": "already_projected"})]
    # Flood bound: one sender may hold at most
    # MAX_ACTIVE_REACTIONS_PER_SENDER_TARGET active distinct emoji on one
    # target. Re-adding an existing reaction is idempotent and exempt;
    # a brand-new emoji past the cap is quarantined as sender misbehavior.
    is_new = row is None or not row["active"]
    if is_new:
        active_count = conn.execute(
            "SELECT COUNT(*) FROM reactions"
            " WHERE target_event_id = ? AND sender = ? AND active = 1;",
            (target_id, ev["sender"]),
        ).fetchone()[0]
        if active_count >= MAX_ACTIVE_REACTIONS_PER_SENDER_TARGET:
            raise ProjectionError(
                "reaction_cap_exceeded",
                f"sender already holds {active_count} active reactions on"
                f" {target_id}; cap is"
                f" {MAX_ACTIVE_REACTIONS_PER_SENDER_TARGET}",
            )
    conn.execute(
        "INSERT INTO reactions(target_event_id, sender, emoji, active,"
        " added_event_id, added_at, removed_event_id, removed_at)"
        " VALUES (?, ?, ?, 1, ?, ?, NULL, NULL)"
        " ON CONFLICT(target_event_id, sender, emoji) DO UPDATE SET"
        " active = 1, added_event_id = excluded.added_event_id,"
        " added_at = excluded.added_at,"
        " removed_event_id = NULL, removed_at = NULL;",
        (target_id, ev["sender"], payload["emoji"], ev["event_id"], ev["created_at"]),
    )
    return [
        _mutation(
            "insert", "reactions", f"{target_id}:{ev['sender']}:{payload['emoji']}",
            {"active": True},
        )
    ]


def _handle_reaction_removed(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    payload = ev["payload"]
    target_id = payload["target_event_id"]
    if _target_event(conn, ev["relationship_id"], target_id) is None:
        return [_add_pending(conn, ev, target_id, "reaction_remove")]
    row = conn.execute(
        "SELECT active, removed_event_id FROM reactions"
        " WHERE target_event_id = ? AND sender = ? AND emoji = ?;",
        (target_id, ev["sender"], payload["emoji"]),
    ).fetchone()
    if row is None or not row["active"]:
        return [_mutation("noop", "reactions", target_id, {"reason": "no_active_reaction"})]
    if row["removed_event_id"] == ev["event_id"]:
        return [_mutation("noop", "reactions", target_id, {"reason": "already_projected"})]
    conn.execute(
        "UPDATE reactions SET active = 0, removed_event_id = ?, removed_at = ?"
        " WHERE target_event_id = ? AND sender = ? AND emoji = ?;",
        (ev["event_id"], ev["created_at"], target_id, ev["sender"], payload["emoji"]),
    )
    return [
        _mutation(
            "update", "reactions", f"{target_id}:{ev['sender']}:{payload['emoji']}",
            {"active": False},
        )
    ]


def _handle_receipt(
    conn: sqlite3.Connection, ev: Mapping[str, Any], kind: str
) -> list[dict[str, Any]]:
    payload = ev["payload"]
    target_id = payload["target_event_id"]
    if _target_event(conn, ev["relationship_id"], target_id) is None:
        return [_add_pending(conn, ev, target_id, "receipt")]
    at = payload["accepted_at"] if kind == "accepted" else payload["seen_at"]
    row = conn.execute(
        "SELECT receipt_event_id FROM receipts"
        " WHERE target_event_id = ? AND kind = ? AND sender = ?;",
        (target_id, kind, ev["sender"]),
    ).fetchone()
    if row is not None and row["receipt_event_id"] == ev["event_id"]:
        return [_mutation("noop", "receipts", target_id, {"reason": "already_projected"})]
    conn.execute(
        "INSERT INTO receipts(target_event_id, kind, sender, at, receipt_event_id)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(target_event_id, kind, sender) DO UPDATE SET"
        " at = excluded.at, receipt_event_id = excluded.receipt_event_id;",
        (target_id, kind, ev["sender"], at, ev["event_id"]),
    )
    return [
        _mutation(
            "insert", "receipts", f"{target_id}:{kind}:{ev['sender']}", {"kind": kind}
        )
    ]


def _handle_poll_created(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    mutations = _ensure_thread(conn, ev)
    payload = ev["payload"]
    if (
        conn.execute(
            "SELECT 1 FROM polls WHERE poll_id = ?;", (ev["event_id"],)
        ).fetchone()
        is not None
    ):
        return mutations + [
            _mutation("noop", "polls", ev["event_id"], {"reason": "already_projected"})
        ]
    # A poll that closes before (or when) it is created can never accept a
    # response; reject it instead of storing a dead poll.
    if payload["closes_at"] <= ev["created_at"]:
        raise ProjectionError(
            "poll_bad_closes_at",
            "poll closes_at is not after the poll's created_at",
        )
    conn.execute(
        "INSERT INTO polls(poll_id, relationship_id, conversation_id, thread_id,"
        " sender, created_at, question, choices, closes_at, multi_select,"
        " response_count)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0);",
        (
            ev["event_id"],
            ev["relationship_id"],
            ev["conversation_id"],
            ev.get("thread_id"),
            ev["sender"],
            ev["created_at"],
            payload["question"],
            restricted_jcs(payload["choices"]).decode("utf-8"),
            payload["closes_at"],
            1 if payload["multi_select"] else 0,
        ),
    )
    mutations.append(_mutation("insert", "polls", ev["event_id"], {}))
    return mutations


def _handle_poll_responded(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    payload = ev["payload"]
    poll_id = payload["poll_id"]
    poll_row = conn.execute(
        "SELECT choices, closes_at, multi_select FROM polls WHERE poll_id = ?;",
        (poll_id,),
    ).fetchone()
    if poll_row is None:
        _target_status(
            conn, ev, poll_id, "poll.created", "poll_response_target_not_poll"
        )
        return [_add_pending(conn, ev, poll_id, "poll_response")]
    declared = json.loads(poll_row["choices"])
    choice_ids = payload["choice_ids"]
    # Semantic validation the schema cannot express: choices must be real,
    # unique, and honor single-select; late responses are rejected.
    if not choice_ids:
        raise ProjectionError("poll_no_choice", "poll response selects no choice")
    if len(set(choice_ids)) != len(choice_ids):
        raise ProjectionError(
            "poll_duplicate_choice", "poll response repeats a choice"
        )
    unknown = [c for c in choice_ids if c not in declared]
    if unknown:
        raise ProjectionError(
            "poll_unknown_choice",
            f"poll response selects undeclared choices: {unknown}",
        )
    if not poll_row["multi_select"] and len(choice_ids) != 1:
        raise ProjectionError(
            "poll_multi_choice_single_select",
            "single-select poll response must choose exactly one choice",
        )
    if ev["created_at"] > poll_row["closes_at"]:
        raise ProjectionError(
            "poll_closed", "poll response arrived after closes_at"
        )
    conn.execute(
        "INSERT INTO poll_responses(poll_id, sender, choice_ids, human_confirmed,"
        " approval_record_id, response_event_id, responded_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(poll_id, sender) DO UPDATE SET"
        " choice_ids = excluded.choice_ids,"
        " human_confirmed = excluded.human_confirmed,"
        " approval_record_id = excluded.approval_record_id,"
        " response_event_id = excluded.response_event_id,"
        " responded_at = excluded.responded_at;",
        (
            poll_id,
            ev["sender"],
            restricted_jcs(payload["choice_ids"]).decode("utf-8"),
            1 if payload.get("human_confirmed") else 0,
            payload.get("approval_record_id"),
            ev["event_id"],
            ev["created_at"],
        ),
    )
    conn.execute(
        "UPDATE polls SET response_count ="
        " (SELECT COUNT(*) FROM poll_responses WHERE poll_id = ?)"
        " WHERE poll_id = ?;",
        (poll_id, poll_id),
    )
    return [_mutation("insert", "poll_responses", f"{poll_id}:{ev['sender']}", {})]


_TASK_TERMINAL = frozenset({"done", "canceled"})


def _handle_task_created(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    mutations = _ensure_thread(conn, ev)
    payload = ev["payload"]
    if (
        conn.execute(
            "SELECT 1 FROM tasks WHERE task_id = ?;", (ev["event_id"],)
        ).fetchone()
        is not None
    ):
        return mutations + [
            _mutation("noop", "tasks", ev["event_id"], {"reason": "already_projected"})
        ]
    conn.execute(
        "INSERT INTO tasks(task_id, relationship_id, conversation_id, thread_id,"
        " sender, created_at, title, owner_identity, due_at, status)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open');",
        (
            ev["event_id"],
            ev["relationship_id"],
            ev["conversation_id"],
            ev.get("thread_id"),
            ev["sender"],
            ev["created_at"],
            payload["title"],
            payload["owner_identity"],
            payload.get("due_at"),
        ),
    )
    mutations.append(_mutation("insert", "tasks", ev["event_id"], {"status": "open"}))
    return mutations


def _handle_task_updated(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    payload = ev["payload"]
    task_id = payload["task_id"]
    row = conn.execute(
        "SELECT status, owner_identity, sender FROM tasks WHERE task_id = ?;",
        (task_id,),
    ).fetchone()
    if row is None:
        _target_status(
            conn, ev, task_id, "task.created", "task_update_target_not_task"
        )
        return [_add_pending(conn, ev, task_id, "task_update")]
    # Authorization: only the task's owner or its creator may change its
    # status. Without this, either side could mark the other's tasks done.
    if ev["sender"] not in (row["owner_identity"], row["sender"]):
        raise ProjectionError(
            "task_not_authorized",
            "task.updated sender is neither the task owner nor its creator",
        )
    if row["status"] in _TASK_TERMINAL:
        raise ProjectionError(
            "task_transition_terminal",
            f"task is {row['status']}; terminal states accept no updates",
        )
    if payload["status"] not in ("open", "in_progress", "blocked", "done", "canceled"):
        raise ProjectionError(
            "task_bad_status",
            f"unknown task status {payload['status']!r}",
        )
    conn.execute(
        "UPDATE tasks SET status = ?, status_event_id = ?,"
        " status_updated_at = ?, note = ? WHERE task_id = ?;",
        (
            payload["status"],
            ev["event_id"],
            ev["created_at"],
            payload.get("note"),
            task_id,
        ),
    )
    return [
        _mutation("update", "tasks", task_id, {"status": payload["status"]})
    ]


def _handle_human_requested(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    mutations = _ensure_thread(conn, ev)
    payload = ev["payload"]
    if (
        conn.execute(
            "SELECT 1 FROM human_requests WHERE request_id = ?;", (ev["event_id"],)
        ).fetchone()
        is not None
    ):
        return mutations + [
            _mutation(
                "noop", "human_requests", ev["event_id"], {"reason": "already_projected"}
            )
        ]
    conn.execute(
        "INSERT INTO human_requests(request_id, relationship_id, conversation_id,"
        " thread_id, sender, created_at, prompt, response_shape, expires_at, state)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open');",
        (
            ev["event_id"],
            ev["relationship_id"],
            ev["conversation_id"],
            ev.get("thread_id"),
            ev["sender"],
            ev["created_at"],
            payload["prompt"],
            payload["response_shape"],
            payload["expires_at"],
        ),
    )
    mutations.append(_mutation("insert", "human_requests", ev["event_id"], {"state": "open"}))
    return mutations


def _human_response_attestation(
    conn: sqlite3.Connection, ev: Mapping[str, Any], payload: Mapping[str, Any]
) -> str:
    """Classify who vouches for a human.responded approval claim.

    Returns 'peer' when the event sender is the relationship's peer: the
    receiver can authenticate the peer's attestation (the envelope
    signature) but cannot audit the peer's local approval store, so a
    fabricated approval_record_id from the peer is stored as the peer's
    claim, never as locally verified.

    Returns 'local' only when the response was generated locally AND its
    approval_record_id resolves to a real row in human_approvals. Anything
    else (including a local send with no matching record, which the honest
    CLI path never produces) is 'peer': not locally verifiable, so it must
    not be presented as locally verified.
    """
    rel = conn.execute(
        "SELECT peer_identity_id FROM relationships WHERE relationship_id = ?;",
        (ev["relationship_id"],),
    ).fetchone()
    if rel is not None and ev["sender"] == rel["peer_identity_id"]:
        return "peer"
    record = conn.execute(
        "SELECT 1 FROM human_approvals WHERE approval_id = ?;",
        (payload.get("approval_record_id"),),
    ).fetchone()
    return "local" if record is not None else "peer"


def _handle_human_responded(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    payload = ev["payload"]
    request_id = payload["request_id"]
    row = conn.execute(
        "SELECT 1 FROM human_requests WHERE request_id = ?;", (request_id,)
    ).fetchone()
    if row is None:
        _target_status(
            conn, ev, request_id, "human.requested", "human_response_target_not_request"
        )
        return [_add_pending(conn, ev, request_id, "human_response")]
    conn.execute(
        "UPDATE human_requests SET state = 'responded', answer = ?, approved = ?,"
        " responded_at = ?, response_event_id = ?, approval_record_id = ?,"
        " attestation = ? WHERE request_id = ?;",
        (
            payload["answer"],
            1 if payload["approved"] else 0,
            ev["created_at"],
            ev["event_id"],
            payload["approval_record_id"],
            _human_response_attestation(conn, ev, payload),
            request_id,
        ),
    )
    return [_mutation("update", "human_requests", request_id, {"state": "responded"})]


def _handle_delivery_scheduled(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    payload = ev["payload"]
    if (
        conn.execute(
            "SELECT 1 FROM deliveries WHERE scheduled_event_id = ?;", (ev["event_id"],)
        ).fetchone()
        is not None
    ):
        return [
            _mutation("noop", "deliveries", ev["event_id"], {"reason": "already_projected"})
        ]
    conn.execute(
        "INSERT INTO deliveries(scheduled_event_id, relationship_id, sender,"
        " created_at, inner_event_id, deliver_at, late_by_seconds, state)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, 'scheduled');",
        (
            ev["event_id"],
            ev["relationship_id"],
            ev["sender"],
            ev["created_at"],
            payload["inner_event_id"],
            payload["deliver_at"],
            payload.get("late_by_seconds"),
        ),
    )
    # Out-of-order arrival: the inner event may already be stored. The
    # inner event's created_at is author time, which legitimately
    # precedes deliver_at in the author-now/deliver-later flow, so no
    # timing check is applied here. (A previous capsule_released_early
    # check compared created_at to deliver_at; it was removed as a
    # false positive: created_at is sender-controlled author time, not
    # proof of release time, and the scheduler holds the announcement,
    # not the inner event's content.)
    return [_mutation("insert", "deliveries", ev["event_id"], {"state": "scheduled"})]


def _handle_delivery_canceled(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    payload = ev["payload"]
    scheduled_id = payload["scheduled_event_id"]
    row = conn.execute(
        "SELECT state FROM deliveries WHERE scheduled_event_id = ?;", (scheduled_id,)
    ).fetchone()
    if row is None:
        _target_status(
            conn,
            ev,
            scheduled_id,
            "delivery.scheduled",
            "delivery_cancel_target_not_scheduled",
        )
        return [_add_pending(conn, ev, scheduled_id, "delivery_cancel")]
    if row["state"] == "canceled":
        return [
            _mutation("noop", "deliveries", scheduled_id, {"reason": "already_canceled"})
        ]
    conn.execute(
        "UPDATE deliveries SET state = 'canceled', canceled_at = ?,"
        " cancel_event_id = ? WHERE scheduled_event_id = ?;",
        (ev["created_at"], ev["event_id"], scheduled_id),
    )
    return [_mutation("update", "deliveries", scheduled_id, {"state": "canceled"})]


def _handle_security_key(
    conn: sqlite3.Connection, ev: Mapping[str, Any]
) -> list[dict[str, Any]]:
    action = ev["event_type"].rsplit(".", 1)[-1]
    if (
        conn.execute(
            "SELECT 1 FROM security_key_events WHERE event_id = ?;", (ev["event_id"],)
        ).fetchone()
        is not None
    ):
        return [
            _mutation(
                "noop", "security_key_events", ev["event_id"],
                {"reason": "already_projected"},
            )
        ]
    conn.execute(
        "INSERT INTO security_key_events"
        "(event_id, relationship_id, sender, created_at, key_epoch, action)"
        " VALUES (?, ?, ?, ?, ?, ?);",
        (
            ev["event_id"],
            ev["relationship_id"],
            ev["sender"],
            ev["created_at"],
            ev.get("key_epoch"),
            action,
        ),
    )
    return [_mutation("insert", "security_key_events", ev["event_id"], {"action": action})]


def _dispatch(
    conn: sqlite3.Connection, ev: Mapping[str, Any], now: str
) -> list[dict[str, Any]]:
    """Route one normalized event to its handler. No fork or cursor logic."""
    event_type = ev["event_type"]
    if event_type in _NO_PROJECTION_TYPES:
        return []
    if event_type == "message.created":
        return _handle_message_created(conn, ev, now)
    if event_type == "message.edited":
        return _handle_message_edited(conn, ev)
    if event_type == "message.retracted":
        return _handle_message_retracted(conn, ev)
    if event_type == "reaction.added":
        return _handle_reaction_added(conn, ev)
    if event_type == "reaction.removed":
        return _handle_reaction_removed(conn, ev)
    if event_type == "receipt.accepted":
        return _handle_receipt(conn, ev, "accepted")
    if event_type == "receipt.seen":
        return _handle_receipt(conn, ev, "seen")
    if event_type == "poll.created":
        return _handle_poll_created(conn, ev)
    if event_type == "poll.responded":
        return _handle_poll_responded(conn, ev)
    if event_type == "task.created":
        return _handle_task_created(conn, ev)
    if event_type == "task.updated":
        return _handle_task_updated(conn, ev)
    if event_type == "human.requested":
        return _handle_human_requested(conn, ev)
    if event_type == "human.responded":
        return _handle_human_responded(conn, ev)
    if event_type == "delivery.scheduled":
        return _handle_delivery_scheduled(conn, ev)
    if event_type == "delivery.canceled":
        return _handle_delivery_canceled(conn, ev)
    if event_type.startswith("security.key."):
        return _handle_security_key(conn, ev)
    if event_type not in PAYLOAD_DISPATCH:
        raise ProjectionError("unknown_event_type", f"no projection rule for {event_type}")
    raise ProjectionError(
        "unprojectable_event_type", f"no projection rule for {event_type}"
    )


def _resolve_pending(
    conn: sqlite3.Connection,
    relationship_id: str,
    target_event_id: str,
    now: str,
) -> list[dict[str, Any]]:
    """Resolve pending refs whose target just arrived. Returns mutations."""
    mutations: list[dict[str, Any]] = []
    refs = conn.execute(
        "SELECT event_id, kind FROM pending_refs"
        " WHERE relationship_id = ? AND target_event_id = ? AND state = 'pending';",
        (relationship_id, target_event_id),
    ).fetchall()
    for ref in refs:
        ref_id = ref["event_id"]
        kind = ref["kind"]
        conn.execute(
            "UPDATE pending_refs SET state = 'resolved' WHERE event_id = ?;", (ref_id,)
        )
        mutations.append(
            _mutation("update", "pending_refs", ref_id, {"state": "resolved"})
        )
        if kind == "reply":
            target = _target_event(conn, relationship_id, target_event_id)
            msg = conn.execute(
                "SELECT conversation_id, thread_id FROM messages WHERE event_id = ?;",
                (ref_id,),
            ).fetchone()
            if (
                target is None
                or msg is None
                or target["conversation_id"] != msg["conversation_id"]
                or not _threads_match(target["thread_id"], msg["thread_id"])
            ):
                state = "unavailable"
            else:
                state = "ok"
            conn.execute(
                "UPDATE messages SET reply_state = ? WHERE event_id = ?;",
                (state, ref_id),
            )
            mutations.append(
                _mutation("update", "messages", ref_id, {"reply_state": state})
            )
            continue
        row = conn.execute(
            "SELECT e.event_id, e.relationship_id, e.conversation_id, e.thread_id,"
            " e.sender, e.sender_seq, e.created_at, e.key_epoch, e.event_type,"
            " p.payload, p.reply_to"
            " FROM events e JOIN event_payloads p ON p.event_id = e.event_id"
            " WHERE e.event_id = ?;",
            (ref_id,),
        ).fetchone()
        if row is None:
            continue
        ref_ev = _row_to_event(dict(row))
        try:
            mutations.extend(_dispatch(conn, ref_ev, now))
        except ProjectionError as exc:
            mutations.append(
                quarantine_event(
                    conn,
                    ref_ev["relationship_id"],
                    ref_ev["sender"],
                    int(ref_ev["sender_seq"]),
                    ref_ev["event_id"],
                    exc.code,
                )
            )
    return mutations


def _apply_inner(
    conn: sqlite3.Connection, ev: Mapping[str, Any], now: str
) -> list[dict[str, Any]]:
    """Project one normalized event: fork check, dispatch, resolve, cursors."""
    fork = _check_fork(conn, ev)
    if fork is not None:
        return [fork]
    mutations = _dispatch(conn, ev, now)
    mutations.extend(
        _resolve_pending(conn, ev["relationship_id"], ev["event_id"], now)
    )
    mutations.extend(
        _update_seq_state(
            conn,
            ev["relationship_id"],
            ev["sender"],
            int(ev["sender_seq"]),
            now,
        )
    )
    return mutations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def apply_event(
    conn: sqlite3.Connection, event_row: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Project a single event row into the projection tables.

    ``event_row`` is a mapping with the ``events`` table columns plus
    ``payload`` (the validated decrypted payload, as a dict or as canonical
    JSON text) and ``reply_to`` (from the protected header, may be None).
    ``rebuild_projections`` builds these rows from ``events`` joined to
    ``event_payloads``; the receive path builds them from the staged payload.

    Sequence forks are quarantined (never projected) and reported as a
    ``quarantine`` mutation. Semantic violations raise :class:`ProjectionError`
    with a stable code. Applying an already-projected event is a ``noop``.

    Does not open its own transaction; call inside the caller's transaction.
    """
    ev = _row_to_event(event_row)
    return _apply_inner(conn, ev, utcnow())


def _iter_relationship_events(
    conn: sqlite3.Connection, relationship_id: str
) -> list[dict[str, Any]]:
    """All staged events for a relationship in deterministic display order."""
    rows = conn.execute(
        "SELECT e.event_id, e.relationship_id, e.conversation_id, e.thread_id,"
        " e.sender, e.sender_seq, e.created_at, e.key_epoch, e.event_type,"
        " p.payload, p.reply_to"
        " FROM events e JOIN event_payloads p ON p.event_id = e.event_id"
        " WHERE e.relationship_id = ?"
        " ORDER BY e.created_at ASC, e.sender ASC, e.sender_seq ASC, e.event_id ASC;",
        (relationship_id,),
    ).fetchall()
    result = []
    for row in rows:
        ev = _row_to_event(dict(row))
        result.append(ev)
    return result


_WIPES: tuple[tuple[str, str], ...] = (
    # (table, DELETE statement with one ? bound to relationship_id)
    ("messages",
     "DELETE FROM messages WHERE relationship_id = ?;"),
    ("message_revisions",
     "DELETE FROM message_revisions WHERE event_id IN"
     " (SELECT event_id FROM events WHERE relationship_id = ?);"),
    ("reactions",
     "DELETE FROM reactions WHERE added_event_id IN"
     " (SELECT event_id FROM events WHERE relationship_id = ?);"),
    ("receipts",
     "DELETE FROM receipts WHERE receipt_event_id IN"
     " (SELECT event_id FROM events WHERE relationship_id = ?);"),
    ("polls",
     "DELETE FROM polls WHERE relationship_id = ?;"),
    ("poll_responses",
     "DELETE FROM poll_responses WHERE response_event_id IN"
     " (SELECT event_id FROM events WHERE relationship_id = ?);"),
    ("tasks",
     "DELETE FROM tasks WHERE relationship_id = ?;"),
    ("human_requests",
     "DELETE FROM human_requests WHERE relationship_id = ?;"),
    ("deliveries",
     "DELETE FROM deliveries WHERE relationship_id = ?;"),
    ("security_key_events",
     "DELETE FROM security_key_events WHERE relationship_id = ?;"),
    ("thread_state",
     "DELETE FROM thread_state WHERE thread_id IN"
     " (SELECT t.thread_id FROM threads t"
     " JOIN events e ON e.thread_id = t.thread_id"
     " WHERE e.relationship_id = ?);"),
    ("pending_refs",
     "DELETE FROM pending_refs WHERE relationship_id = ?;"),
    ("projection_cursors",
     "DELETE FROM projection_cursors WHERE relationship_id = ?;"),
    ("sequence_gaps",
     "DELETE FROM sequence_gaps WHERE relationship_id = ?;"),
)


def rebuild_projections(conn: sqlite3.Connection, relationship_id: str) -> None:
    """Wipe and rebuild all projection tables for one relationship.

    Runs inside ONE transaction: every projection table row for the
    relationship is deleted, then each staged event is projected in
    deterministic order ``(created_at, sender, sender_seq)``. Sequence forks
    and semantically rejected events are quarantined with stable codes
    instead of aborting the rebuild. ``event_payloads`` are input evidence,
    not derived state, and are never wiped.

    ``quarantine`` rows for events present in the log are re-derived: the
    rebuild deletes them first and re-quarantines only what still fails in
    deterministic order, so a quarantine entry recorded under one arrival
    order cannot survive a rebuild that now projects the same event cleanly.
    Quarantine rows for events absent from the log (true orphans) are kept
    as evidence.

    Rebuilds run at the same wall-clock second are byte-identical.
    """
    now = utcnow()
    with transaction(conn):
        unstaged = conn.execute(
            "SELECT COUNT(*) AS c FROM events e"
            " LEFT JOIN event_payloads p ON p.event_id = e.event_id"
            " WHERE e.relationship_id = ? AND p.event_id IS NULL;",
            (relationship_id,),
        ).fetchone()["c"]
        if unstaged:
            raise ProjectionError(
                "payload_missing",
                f"{unstaged} event(s) have no staged payload; "
                "the receive path must call record_projection_input for every event",
            )
        for _table, wipe_sql in _WIPES:
            conn.execute(wipe_sql, (relationship_id,))
        # Re-derive quarantine for logged events: drop rows the rebuild is
        # about to re-evaluate, so stale arrival-order entries cannot linger.
        conn.execute(
            "DELETE FROM quarantine WHERE relationship_id = ? AND event_id IN"
            " (SELECT event_id FROM events WHERE relationship_id = ?);",
            (relationship_id, relationship_id),
        )
        for ev in _iter_relationship_events(conn, relationship_id):
            try:
                _apply_inner(conn, ev, now)
            except ProjectionError as exc:
                quarantine_event(
                    conn,
                    ev["relationship_id"],
                    ev["sender"],
                    int(ev["sender_seq"]),
                    ev["event_id"],
                    exc.code,
                )


def expire_pending_refs(
    conn: sqlite3.Connection, relationship_id: str, now: str | None = None
) -> int:
    """Expire pending target refs older than seven days.

    Missing reply targets flip to the ``unavailable`` context marker; other
    pending kinds simply stop waiting. Returns the number of refs expired.
    """
    now = now or utcnow()
    threshold = (
        datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        - timedelta(seconds=PENDING_TARGET_TTL_SECONDS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    refs = conn.execute(
        "SELECT event_id, kind FROM pending_refs"
        " WHERE relationship_id = ? AND state = 'pending' AND created_at < ?;",
        (relationship_id, threshold),
    ).fetchall()
    for ref in refs:
        conn.execute(
            "UPDATE pending_refs SET state = 'expired' WHERE event_id = ?;",
            (ref["event_id"],),
        )
        if ref["kind"] == "reply":
            conn.execute(
                "UPDATE messages SET reply_state = 'unavailable' WHERE event_id = ?;",
                (ref["event_id"],),
            )
    return len(refs)


def _message_view(
    conn: sqlite3.Connection, msg: sqlite3.Row
) -> dict[str, Any]:
    retracted = bool(msg["retracted"])
    reactions: dict[str, dict[str, Any]] = {}
    for r in conn.execute(
        "SELECT emoji, sender FROM reactions"
        " WHERE target_event_id = ? AND active = 1 ORDER BY emoji, sender;",
        (msg["event_id"],),
    ).fetchall():
        entry = reactions.setdefault(
            r["emoji"], {"emoji": r["emoji"], "count": 0, "senders": []}
        )
        entry["count"] += 1
        entry["senders"].append(r["sender"])
    receipts = [
        {"kind": r["kind"], "sender": r["sender"], "at": r["at"]}
        for r in conn.execute(
            "SELECT kind, sender, at FROM receipts"
            " WHERE target_event_id = ? ORDER BY kind, sender;",
            (msg["event_id"],),
        ).fetchall()
    ]
    revision_count = conn.execute(
        "SELECT COUNT(*) AS c FROM message_revisions WHERE event_id = ?;",
        (msg["event_id"],),
    ).fetchone()["c"]
    view: dict[str, Any] = {
        "event_id": msg["event_id"],
        "conversation_id": msg["conversation_id"],
        "thread_id": msg["thread_id"],
        "sender": msg["sender"],
        "sender_seq": msg["sender_seq"],
        "created_at": msg["created_at"],
        "body": None if retracted else msg["current_body"],
        "format": msg["format"],
        "reply_to": msg["reply_to"],
        "reply_state": msg["reply_state"],
        "edited": bool(msg["edited"]),
        "revision_count": revision_count,
        "retracted": retracted,
        "retraction": None,
        "reactions": sorted(reactions.values(), key=lambda e: e["emoji"].encode("utf-8")),
        "receipts": receipts,
    }
    if retracted:
        view["retraction"] = {
            "event_id": msg["retraction_event_id"],
            "retracted_at": msg["retracted_at"],
            "reason": msg["retraction_reason"],
        }
    return view


def get_conversation(
    conn: sqlite3.Connection,
    relationship_id: str,
    conversation_id: str,
    limit: int | None = None,
    before: str | None = None,
) -> list[dict[str, Any]]:
    """Return ordered message views for a conversation.

    Messages come back in deterministic display order
    ``(created_at, sender, sender_seq)``, oldest first, with edits applied,
    retracted bodies hidden behind a tombstone flag, reactions aggregated,
    and receipts attached.

    ``before`` is an exclusive cursor: an event_id; only messages ordered
    before it are returned. ``limit`` caps the count, keeping the most
    recent messages of the selected range.
    """
    params: list[Any] = [relationship_id, conversation_id]
    cursor_clause = ""
    if before is not None:
        anchor = conn.execute(
            "SELECT created_at, sender, sender_seq FROM messages"
            " WHERE relationship_id = ? AND conversation_id = ? AND event_id = ?;",
            (relationship_id, conversation_id, before),
        ).fetchone()
        if anchor is None:
            raise ProjectionError("unknown_cursor", "before cursor names no message")
        cursor_clause = (
            " AND (created_at, sender, sender_seq) < (?, ?, ?)"
        )
        params.extend([anchor["created_at"], anchor["sender"], anchor["sender_seq"]])
    order = "ASC"
    limit_clause = ""
    if limit is not None:
        if limit < 0:
            raise ProjectionError("invalid_limit", "limit must be non-negative")
        order = "DESC"
        limit_clause = f" LIMIT {int(limit)}"
    rows = conn.execute(
        "SELECT event_id, conversation_id, thread_id, sender, sender_seq,"
        " created_at, format, reply_to, reply_state, edited, current_body,"
        " retracted, retraction_event_id, retracted_at, retraction_reason"
        f" FROM messages WHERE relationship_id = ? AND conversation_id = ?"
        f"{cursor_clause}"
        f" ORDER BY created_at {order}, sender {order}, sender_seq {order}"
        f"{limit_clause};",
        params,
    ).fetchall()
    if order == "DESC":
        rows = rows[::-1]
    return [_message_view(conn, row) for row in rows]


def get_poll(
    conn: sqlite3.Connection, poll_id: str
) -> dict[str, Any] | None:
    """Return a poll with its current responses, or None."""
    poll = conn.execute("SELECT * FROM polls WHERE poll_id = ?;", (poll_id,)).fetchone()
    if poll is None:
        return None
    responses = [
        {
            "sender": r["sender"],
            "choice_ids": json.loads(r["choice_ids"]),
            "human_confirmed": bool(r["human_confirmed"]),
            "response_event_id": r["response_event_id"],
            "responded_at": r["responded_at"],
        }
        for r in conn.execute(
            "SELECT * FROM poll_responses WHERE poll_id = ? ORDER BY sender;",
            (poll_id,),
        ).fetchall()
    ]
    return {
        "poll_id": poll["poll_id"],
        "relationship_id": poll["relationship_id"],
        "conversation_id": poll["conversation_id"],
        "thread_id": poll["thread_id"],
        "sender": poll["sender"],
        "created_at": poll["created_at"],
        "question": poll["question"],
        "choices": json.loads(poll["choices"]),
        "closes_at": poll["closes_at"],
        "multi_select": bool(poll["multi_select"]),
        "response_count": poll["response_count"],
        "responses": responses,
    }


def get_task(conn: sqlite3.Connection, task_id: str) -> dict[str, Any] | None:
    """Return a task's current state, or None."""
    row = conn.execute("SELECT * FROM tasks WHERE task_id = ?;", (task_id,)).fetchone()
    return dict(row) if row is not None else None


def get_human_request(
    conn: sqlite3.Connection, request_id: str
) -> dict[str, Any] | None:
    """Return a human request's current state, or None."""
    row = conn.execute(
        "SELECT * FROM human_requests WHERE request_id = ?;", (request_id,)
    ).fetchone()
    return dict(row) if row is not None else None
