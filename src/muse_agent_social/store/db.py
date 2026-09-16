"""SQLite connection management for the event store.

Every connection is opened with WAL journal mode, foreign key enforcement,
and a 30 second busy timeout. Callers that need atomic multi-statement
work should use transaction().
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

DEFAULT_DB_FILENAME = "state.db"
_BUSY_TIMEOUT_MS = 30_000


class DbError(Exception):
    """SQLite store setup or operation failed."""


def utcnow() -> str:
    """Current time as canonical UTC text: YYYY-MM-DDTHH:MM:SSZ."""
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def default_db_path(state_dir: str | Path) -> Path:
    """Database file path inside a state directory."""
    return Path(state_dir) / DEFAULT_DB_FILENAME


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode and foreign keys enforced.

    Raises DbError if WAL mode cannot be engaged: the rest of the design
    (30s busy timeout, BEGIN IMMEDIATE everywhere) assumes WAL's
    reader/writer behavior, and a silent fallback to rollback journal would
    change contention semantics invisibly.
    """
    conn = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    mode = conn.execute("PRAGMA journal_mode=WAL;").fetchone()
    engaged = (mode[0] if mode else "").lower()
    if engaged != "wal" and str(db_path) != ":memory:":
        conn.close()
        raise DbError(
            f"could not engage WAL journal mode on {db_path} (got {engaged!r}); "
            "refusing to run with rollback-journal contention semantics"
        )
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS};")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def open_db(state_dir: str | Path) -> sqlite3.Connection:
    """Create the state directory if needed and connect to its database."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    return connect(default_db_path(state_dir))


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run work inside BEGIN IMMEDIATE; commit on success, roll back on error."""
    conn.execute("BEGIN IMMEDIATE;")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK;")
        raise
    else:
        conn.execute("COMMIT;")


def get_user_version(conn: sqlite3.Connection) -> int:
    """Return the current schema version (PRAGMA user_version)."""
    return int(conn.execute("PRAGMA user_version;").fetchone()[0])


def set_user_version(conn: sqlite3.Connection, version: int) -> None:
    """Set the schema version (PRAGMA user_version). Prefer migrate()."""
    if version < 0:
        raise ValueError("schema version must be non-negative")
    conn.execute(f"PRAGMA user_version = {int(version)};")
