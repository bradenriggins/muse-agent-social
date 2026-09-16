"""Local human-approval records.

The plan's ask-my-human rule: ``human.responded`` (and ``poll.responded``
with ``human_confirmed=true``) requires a local human-approval record ID,
never a bare sender assertion. This module owns the local-only table; rows
are created exclusively by the human-facing command (``mas human respond``)
and are never transmitted. The send path looks the record up and embeds its
ID in the payload; the receive path schema-requires the ID.

A malicious peer can still invent an ID, but an honest installation cannot
send an approval its human never gave, and every approval is auditable on
the sender's side.
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any, Mapping

__all__ = [
    "APPROVALS_DDL",
    "APPROVAL_TTL_SECONDS",
    "ApprovalError",
    "consume_approval",
    "create_approval",
    "ensure_approvals_columns",
    "get_approval",
]

APPROVALS_DDL = """
CREATE TABLE IF NOT EXISTS human_approvals (
    approval_id     TEXT PRIMARY KEY,
    relationship_id TEXT NOT NULL,
    subject_type    TEXT NOT NULL
        CHECK(subject_type IN ('human_request', 'poll')),
    subject_id      TEXT NOT NULL,
    answer          TEXT NOT NULL,
    approved        INTEGER NOT NULL CHECK(approved IN (0, 1)),
    created_at      TEXT NOT NULL,
    -- Approvals are single-use and time-boxed: a record authorizes exactly
    -- one send and dies APPROVAL_TTL_SECONDS after creation. Without this,
    -- a leaked or observed approval_record_id could be replayed forever.
    expires_at      TEXT NOT NULL,
    consumed_at     TEXT,
    note            TEXT
);
CREATE INDEX IF NOT EXISTS idx_human_approvals_subject
    ON human_approvals(relationship_id, subject_type, subject_id);
"""

#: How long a human-approval record stays usable (24 hours).
APPROVAL_TTL_SECONDS = 24 * 3600


def ensure_approvals_columns(conn: sqlite3.Connection) -> None:
    """Idempotently add the lifecycle columns to existing databases.

    Fresh databases get them from APPROVALS_DDL; databases created before
    the single-use/expiry hardening need the ALTERs. Column-existence is
    checked first so this is safe to run on every migrate.
    """
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(human_approvals);")]
    if "expires_at" not in cols:
        conn.execute("ALTER TABLE human_approvals ADD COLUMN expires_at TEXT;")
        # Backfill: pre-hardening rows get the full TTL from creation.
        # G7: use the canonical T...Z form (not SQLite datetime()'s
        # space-separated form) so lexical expiry comparisons work.
        conn.execute(
            "UPDATE human_approvals SET expires_at ="
            " strftime('%Y-%m-%dT%H:%M:%SZ', datetime(created_at, '+24 hours'))"
            " WHERE expires_at IS NULL;"
        )
    # G7: normalize rows backfilled by older versions of this function in
    # the space-separated form. The GLOB only matches "YYYY-MM-DD
    # HH:MM:SS" rows, never canonical ones.
    conn.execute(
        "UPDATE human_approvals SET expires_at ="
        " strftime('%Y-%m-%dT%H:%M:%SZ', expires_at)"
        " WHERE expires_at GLOB '????-??-?? ??:??:??';"
    )
    if "consumed_at" not in cols:
        conn.execute("ALTER TABLE human_approvals ADD COLUMN consumed_at TEXT;")


def _expiry_for(created_at: str, expires_at: str | None) -> str:
    if expires_at is not None:
        return expires_at
    from datetime import datetime, timedelta, timezone

    created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    return (
        (created + timedelta(seconds=APPROVAL_TTL_SECONDS))
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


class ApprovalError(Exception):
    """Stable-coded local approval failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def create_approval(
    conn: sqlite3.Connection,
    *,
    relationship_id: str,
    subject_type: str,
    subject_id: str,
    answer: str,
    approved: bool,
    created_at: str,
    note: str | None = None,
    expires_at: str | None = None,
) -> str:
    """Record the human's explicit response. Returns the approval ID.

    The record expires APPROVAL_TTL_SECONDS after ``created_at`` unless an
    explicit ``expires_at`` is given, and is single-use (see
    :func:`consume_approval`).
    """
    if subject_type not in ("human_request", "poll"):
        raise ApprovalError("bad_subject_type", f"unknown {subject_type}")
    approval_id = uuid.uuid4().hex
    conn.execute(
        "INSERT INTO human_approvals(approval_id, relationship_id,"
        " subject_type, subject_id, answer, approved, created_at,"
        " expires_at, consumed_at, note)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
        (
            approval_id,
            relationship_id,
            subject_type,
            subject_id,
            answer,
            1 if approved else 0,
            created_at,
            _expiry_for(created_at, expires_at),
            note,
        ),
    )
    return approval_id


def consume_approval(
    conn: sqlite3.Connection,
    approval_id: str,
    now: str,
    *,
    relationship_id: str | None = None,
    subject_type: str | None = None,
    subject_id: str | None = None,
    answer: str | None = None,
    approved: bool | None = None,
) -> bool:
    """Atomically mark an approval consumed iff it is live. Returns True on success.

    The UPDATE only fires when the row is unconsumed and unexpired, so two
    racing sends cannot both claim the same approval: exactly one wins.

    G12: when the binding parameters are given, the UPDATE additionally
    requires the record's relationship_id, subject_type, subject_id,
    answer, and approved flag to match the send being authorized. The
    claim then binds the approval to the exact response it authorized: a
    concurrent or buggy caller cannot redirect an approval for request A
    to a send answering request B. ``approved`` is stored as INTEGER 0/1.
    """
    sql = (
        "UPDATE human_approvals SET consumed_at = ?"
        " WHERE approval_id = ? AND consumed_at IS NULL AND expires_at > ?"
    )
    params: list = [now, approval_id, now]
    if relationship_id is not None:
        sql += " AND relationship_id = ?"
        params.append(relationship_id)
    if subject_type is not None:
        sql += " AND subject_type = ?"
        params.append(subject_type)
    if subject_id is not None:
        sql += " AND subject_id = ?"
        params.append(subject_id)
    if answer is not None:
        sql += " AND answer = ?"
        params.append(answer)
    if approved is not None:
        sql += " AND approved = ?"
        params.append(1 if approved else 0)
    sql += ";"
    cur = conn.execute(sql, params)
    return cur.rowcount == 1


def get_approval(
    conn: sqlite3.Connection, approval_id: str
) -> Mapping[str, Any] | None:
    """Fetch a local approval record by ID, or None."""
    row = conn.execute(
        "SELECT * FROM human_approvals WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    return row
