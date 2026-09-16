"""SQLite connection management for the event store.

Every connection is opened with WAL journal mode, foreign key enforcement,
and a 30 second busy timeout. Callers that need atomic multi-statement
work should use transaction().
"""

from __future__ import annotations

import os
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

DEFAULT_DB_FILENAME = "state.db"
_BUSY_TIMEOUT_MS = 30_000

#: Set to a truthy value (1/true/yes) to let connect() proceed without WAL
#: on filesystems where WAL cannot engage (NFS without byte-range locks,
#: some FUSE mounts, read-only media). The escape hatch is loud: every
#: affected open prints a stderr warning. Concurrency and crash-recovery
#: semantics are degraded without WAL; only use it where WAL truly cannot
#: engage.
_NO_WAL_ENV_VAR = "MAS_ALLOW_NO_WAL"


class DbError(Exception):
    """SQLite store setup or operation failed."""


class CorruptDatabaseError(DbError):
    """The database file failed integrity checking or is unreadable.

    Recovery: restore state.db from a backup. Do NOT delete state.db while
    -wal/-shm files remain: SQLite silently discards the stale WAL and the
    installation then looks like a fresh, empty database.
    """


class SchemaTooNewError(DbError):
    """The database schema version is newer than this code supports."""


def _no_wal_allowed() -> bool:
    return os.environ.get(_NO_WAL_ENV_VAR, "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def _corruption_error(db_path: str, detail: str) -> CorruptDatabaseError:
    return CorruptDatabaseError(
        f"database-corrupt: {detail} ({db_path}); restore state.db from a "
        "backup. Do not delete state.db while -wal/-shm files remain: "
        "SQLite would discard the stale WAL and the installation would "
        "look like a fresh, empty database."
    )


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

    Runs PRAGMA quick_check on open: a corrupt file raises
    CorruptDatabaseError (labeled, with recovery guidance) instead of
    surfacing raw sqlite3.DatabaseError tracebacks from later calls.

    Raises DbError if WAL mode cannot be engaged, unless MAS_ALLOW_NO_WAL
    is set to a truthy value (1/true/yes), in which case the connection
    proceeds with a loud stderr warning. The rest of the design (30s busy
    timeout, BEGIN IMMEDIATE everywhere) assumes WAL's reader/writer
    behavior, and a silent fallback to rollback journal would change
    contention semantics invisibly.
    """
    label = str(db_path)
    try:
        conn = sqlite3.connect(label, timeout=30.0, isolation_level=None)
    except sqlite3.DatabaseError as exc:
        raise _corruption_error(label, f"cannot open: {exc}") from exc
    conn.row_factory = sqlite3.Row
    try:
        check = conn.execute("PRAGMA quick_check;").fetchone()
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise _corruption_error(
            label, f"integrity check failed: {exc}"
        ) from exc
    if check is None or str(check[0]).lower() != "ok":
        detail = check[0] if check else "no result"
        conn.close()
        raise _corruption_error(
            label, f"PRAGMA quick_check reported: {detail}"
        )
    try:
        mode = conn.execute("PRAGMA journal_mode=WAL;").fetchone()
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise _corruption_error(
            label, f"cannot set journal mode: {exc}"
        ) from exc
    engaged = (mode[0] if mode else "").lower()
    if engaged != "wal" and label != ":memory:":
        if _no_wal_allowed():
            print(
                f"WARNING: {_NO_WAL_ENV_VAR} is set: running {label} without "
                f"WAL (journal mode {engaged!r}). Concurrency and "
                "crash-recovery semantics are degraded; use this only on "
                "filesystems where WAL cannot engage.",
                file=sys.stderr,
            )
        else:
            conn.close()
            raise DbError(
                f"could not engage WAL journal mode on {label} (got {engaged!r}); "
                "refusing to run with rollback-journal contention semantics "
                f"(set {_NO_WAL_ENV_VAR}=1 to override on filesystems where "
                "WAL cannot engage)"
            )
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS};")
        # FULL, not NORMAL: with NORMAL a power loss can roll back recently
        # committed transactions (the WAL is not fsynced per commit), while
        # key files and watcher state are fsynced. Under WAL mode FULL only
        # fsyncs the WAL per commit, so the cost is small and durability is
        # uniform across the state dir.
        conn.execute("PRAGMA synchronous=FULL;")
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise _corruption_error(
            label, f"cannot configure connection: {exc}"
        ) from exc
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
