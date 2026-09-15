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
    "ApprovalError",
    "create_approval",
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
    note            TEXT
);
CREATE INDEX IF NOT EXISTS idx_human_approvals_subject
    ON human_approvals(relationship_id, subject_type, subject_id);
"""


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
) -> str:
    """Record the human's explicit response. Returns the approval ID."""
    if subject_type not in ("human_request", "poll"):
        raise ApprovalError("bad_subject_type", f"unknown {subject_type}")
    approval_id = uuid.uuid4().hex
    conn.execute(
        "INSERT INTO human_approvals(approval_id, relationship_id,"
        " subject_type, subject_id, answer, approved, created_at, note)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            approval_id,
            relationship_id,
            subject_type,
            subject_id,
            answer,
            1 if approved else 0,
            created_at,
            note,
        ),
    )
    return approval_id


def get_approval(
    conn: sqlite3.Connection, approval_id: str
) -> Mapping[str, Any] | None:
    """Fetch a local approval record by ID, or None."""
    row = conn.execute(
        "SELECT * FROM human_approvals WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    return row
