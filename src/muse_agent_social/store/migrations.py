"""Versioned, idempotent SQLite migrations.

The schema version is tracked in PRAGMA user_version. migrate() applies
every pending migration in order, each inside its own BEGIN IMMEDIATE
transaction (DDL plus the version bump commit atomically), and is safe to
run repeatedly and concurrently: a second run is a no-op, and a concurrent
first run blocks on the write lock, then sees the bumped version and skips.
"""

from __future__ import annotations

import sqlite3

from muse_agent_social.store.db import (
    DbError,
    SchemaTooNewError,
    transaction,
)

SCHEMA_VERSION = 5

# Migration 2 gathers the auxiliary DDL owned by feature modules so that a
# single migrate() call brings a fresh database to the full v0.2 schema.
# Each fragment is CREATE TABLE / INDEX IF NOT EXISTS and therefore
# idempotent; the owning modules may also apply their own fragments
# directly (migrate_projections(), rotation._ensure_tables(), the github
# transport's table setup) with identical results.
from muse_agent_social.crypto.rotation import _ROTATION_TABLES
from muse_agent_social.model.approvals import APPROVALS_DDL, ensure_approvals_columns
from muse_agent_social.store.projections import _V2_DDL as _PROJECTIONS_V2_DDL
from muse_agent_social.store.projections import _V3_DDL as _PROJECTIONS_V3_DDL

# Migration 4: remember the peer's previous identity id across an
# identity rotation, so delayed pre-rotation events and redelivered
# rotation announcements from the old identity are still attributable
# instead of being rejected as unknown_sender.
_V4_COLUMN = "prior_peer_identity_id"


# Migration 3: attestation column on human_requests. The backfill UPDATE is
# naturally idempotent, so it always runs; the ADD COLUMN is guarded like
# migration 4's, because a crash between a bare ALTER and the version bump
# used to wedge the retry on "duplicate column name".
_V3_COLUMN = "attestation"


def _ensure_v3_attestation(conn: sqlite3.Connection) -> None:
    """Idempotently add the migration-3 column to ``human_requests``.

    A bare ALTER TABLE ... ADD COLUMN is not re-runnable: a crash between
    the ALTER and the version bump used to leave the column present with
    the version still at 2, and the retry died with "duplicate column
    name". Checking PRAGMA table_info first makes the migration genuinely
    idempotent, so both crash-recovery (including a user_version reset to
    0 on an already-migrated database) and concurrent first-run migrate()
    calls converge instead of wedging.
    """
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(human_requests);")]
    if _V3_COLUMN not in cols:
        conn.execute(
            "ALTER TABLE human_requests ADD COLUMN attestation TEXT NOT NULL "
            "DEFAULT 'peer' CHECK(attestation IN ('local', 'peer'));"
        )
    conn.execute(
        "UPDATE human_requests SET attestation = 'local' "
        "WHERE approval_record_id IS NOT NULL "
        "AND EXISTS (SELECT 1 FROM human_approvals "
        "WHERE human_approvals.approval_id "
        "= human_requests.approval_record_id);"
    )


def _ensure_v4_column(conn: sqlite3.Connection) -> None:
    """Idempotently add the migration-4 column to ``relationships``.

    A bare ALTER TABLE ... ADD COLUMN is not re-runnable: a crash between
    the ALTER and the version bump used to leave the column present with the
    version still at 3, and the retry died with "duplicate column name".
    Checking PRAGMA table_info first makes the migration genuinely
    idempotent, so both crash-recovery and concurrent first-run migrate()
    calls converge instead of wedging.
    """
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(relationships);")]
    if _V4_COLUMN not in cols:
        conn.execute(
            f"ALTER TABLE relationships ADD COLUMN {_V4_COLUMN} TEXT;"
        )


_V4_DDL = f"""
ALTER TABLE relationships ADD COLUMN {_V4_COLUMN} TEXT;
"""


# Post-v4 hardening columns. Added idempotently (no version bump), the
# same way _ensure_v4_column works: PRAGMA table_info first, so crash
# recovery and concurrent first-run migrate() calls converge.
#
# - replay_guard.event_id / replay_guard.envelope_digest: bind each replay
#   record to the exact event it guarded, so a reused nonce with different
#   bytes is quarantined instead of silently reported "accepted".
# - relationships.prior_identity_grace_until: expiry bound on accepting
#   events signed by the peer's retired identity after a rotation.
_V5_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("replay_guard", "event_id", "TEXT"),
    ("replay_guard", "envelope_digest", "TEXT"),
    ("relationships", "prior_identity_grace_until", "TEXT"),
)


def _ensure_v5_columns(conn: sqlite3.Connection) -> None:
    """Idempotently add the post-v4 hardening columns (see _V5_COLUMNS)."""
    for table, column, coltype in _V5_COLUMNS:
        cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table});")]
        if column not in cols:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {coltype};"
            )
from muse_agent_social.transports.tables import TRANSPORT_DDL

_V2_DDL = "\n".join(
    [_PROJECTIONS_V2_DDL, _ROTATION_TABLES, TRANSPORT_DDL, APPROVALS_DDL]
)

_V1_DDL = """
-- Conversations and threads exist so the plan's required foreign keys on
-- conversation and thread have concrete targets.
CREATE TABLE IF NOT EXISTS conversations (
    conversation_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS threads (
    thread_id       TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id)
);

CREATE TABLE IF NOT EXISTS relationships (
    relationship_id    TEXT PRIMARY KEY,
    peer_identity_id   TEXT NOT NULL,
    peer_display_name  TEXT,
    peer_agreement_key TEXT,
    consent_state      TEXT NOT NULL
        CHECK(consent_state IN ('pending', 'active', 'revoked')),
    policy             TEXT NOT NULL,
    key_epoch          INTEGER NOT NULL DEFAULT 1 CHECK(key_epoch >= 1),
    created_at         TEXT NOT NULL CHECK(created_at GLOB '????-??-??T??:??:??Z')
);

-- private_key_ref is a reference or filesystem path only, never key material.
CREATE TABLE IF NOT EXISTS key_epochs (
    relationship_id TEXT NOT NULL REFERENCES relationships(relationship_id),
    epoch           INTEGER NOT NULL CHECK(epoch >= 1),
    public_key      TEXT NOT NULL,
    private_key_ref TEXT NOT NULL,
    state           TEXT NOT NULL
        CHECK(state IN ('candidate', 'acknowledged', 'confirmed', 'active', 'retired')),
    PRIMARY KEY (relationship_id, epoch)
);

-- Append-only sealed event log. Corrections are new events, never updates;
-- the triggers below reject UPDATE and DELETE.
CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    relationship_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
    thread_id       TEXT REFERENCES threads(thread_id),
    sender          TEXT NOT NULL,
    sender_seq      INTEGER NOT NULL CHECK(sender_seq >= 1),
    created_at      TEXT NOT NULL CHECK(created_at GLOB '????-??-??T??:??:??Z'),
    key_epoch       INTEGER NOT NULL,
    event_type      TEXT NOT NULL,
    replay_nonce    TEXT NOT NULL UNIQUE,
    sealed_envelope BLOB NOT NULL,
    UNIQUE (relationship_id, sender, sender_seq),
    FOREIGN KEY (relationship_id) REFERENCES relationships(relationship_id),
    FOREIGN KEY (relationship_id, key_epoch)
        REFERENCES key_epochs(relationship_id, epoch)
);

CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only');
END;

CREATE TABLE IF NOT EXISTS replay_guard (
    replay_nonce TEXT PRIMARY KEY,
    expires_at   TEXT NOT NULL CHECK(expires_at GLOB '????-??-??T??:??:??Z')
);

CREATE TABLE IF NOT EXISTS sender_sequence (
    relationship_id TEXT NOT NULL REFERENCES relationships(relationship_id),
    sender          TEXT NOT NULL,
    last_seq        INTEGER NOT NULL DEFAULT 0 CHECK(last_seq >= 0),
    PRIMARY KEY (relationship_id, sender)
);

CREATE TABLE IF NOT EXISTS projection_queue (
    event_id  TEXT PRIMARY KEY REFERENCES events(event_id),
    queued_at TEXT NOT NULL CHECK(queued_at GLOB '????-??-??T??:??:??Z')
);

CREATE TABLE IF NOT EXISTS receipt_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_event_id TEXT NOT NULL REFERENCES events(event_id),
    kind            TEXT NOT NULL CHECK(kind IN ('accepted', 'seen')),
    queued_at       TEXT NOT NULL CHECK(queued_at GLOB '????-??-??T??:??:??Z'),
    UNIQUE (target_event_id, kind)
);

CREATE TABLE IF NOT EXISTS surface_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE REFERENCES events(event_id),
    policy_snapshot TEXT NOT NULL,
    queued_at       TEXT NOT NULL CHECK(queued_at GLOB '????-??-??T??:??:??Z')
);

CREATE TABLE IF NOT EXISTS invites (
    invite_id  TEXT PRIMARY KEY,
    state      TEXT NOT NULL
        CHECK(state IN ('issued', 'accepted', 'committed', 'expired', 'canceled')),
    issued_at  TEXT NOT NULL CHECK(issued_at GLOB '????-??-??T??:??:??Z'),
    expires_at TEXT NOT NULL CHECK(expires_at GLOB '????-??-??T??:??:??Z')
);

CREATE TABLE IF NOT EXISTS scheduler_queue (
    scheduled_id TEXT PRIMARY KEY,
    inner_event  BLOB NOT NULL,
    deliver_at   TEXT NOT NULL CHECK(deliver_at GLOB '????-??-??T??:??:??Z'),
    expires_at   TEXT CHECK(expires_at IS NULL
        OR expires_at GLOB '????-??-??T??:??:??Z'),
    state        TEXT NOT NULL
        CHECK(state IN ('scheduled', 'released', 'canceled', 'expired'))
);

CREATE TABLE IF NOT EXISTS migration_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_relationship_sender
    ON events(relationship_id, sender, sender_seq);
CREATE INDEX IF NOT EXISTS idx_replay_guard_expires
    ON replay_guard(expires_at);
CREATE INDEX IF NOT EXISTS idx_scheduler_deliver
    ON scheduler_queue(deliver_at, state);
"""

# (version, name, ddl). Versions are strictly increasing and never reused.
_V5_DDL = """
-- Attachment metadata for message.created events carrying a file.
-- The bytes themselves live on disk under <state_dir>/attachments/
-- (materialized by the receive path); this table tracks what arrived,
-- its integrity hash, and where it was written. stored_path is NULL
-- until materialization succeeds, so a crash between projection and
-- materialization is recoverable: the next receive retries the write.
CREATE TABLE IF NOT EXISTS attachments (
    event_id        TEXT PRIMARY KEY,
    relationship_id TEXT NOT NULL,
    filename        TEXT NOT NULL,
    size            INTEGER NOT NULL,
    content_type    TEXT,
    sha256          TEXT NOT NULL,
    stored_path     TEXT,
    received_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attachments_relationship
    ON attachments(relationship_id);
"""


def _ensure_v5_attachments(conn: sqlite3.Connection) -> None:
    """Idempotently create the attachments metadata table (v5).

    Runs the two v5 statements individually (never executescript(), which
    would implicitly commit the caller's transaction).
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attachments (
            event_id        TEXT PRIMARY KEY,
            relationship_id TEXT NOT NULL,
            filename        TEXT NOT NULL,
            size            INTEGER NOT NULL,
            content_type    TEXT,
            sha256          TEXT NOT NULL,
            stored_path     TEXT,
            received_at     TEXT NOT NULL
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attachments_relationship"
        " ON attachments(relationship_id);"
    )


MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "v1_initial_schema", _V1_DDL),
    (2, "v2_projections_rotation_transport", _V2_DDL),
    (3, "v3_human_approval_attestation", _PROJECTIONS_V3_DDL),
    (4, "v4_prior_peer_identity", _V4_DDL),
    (5, "v5_attachments", _V5_DDL),
]


def _split_ddl(ddl: str) -> list[str]:
    """Split multi-statement DDL into single complete statements.

    ``executescript`` implicitly commits, so it must never run inside our
    explicit per-migration transaction. ``sqlite3.complete_statement``
    parses real SQLite syntax, so trigger bodies (which contain
    semicolons) survive the split intact. Comment-only lines are
    stripped from each statement (a statement that merely *starts* with
    a comment is still a statement).
    """
    statements: list[str] = []
    buf: list[str] = []
    for line in ddl.splitlines(keepends=True):
        buf.append(line)
        if sqlite3.complete_statement("".join(buf)):
            code = "\n".join(
                ln for ln in "".join(buf).splitlines()
                if not ln.strip().startswith("--")
            )
            stmt = code.strip().rstrip(";").strip()
            if stmt:
                statements.append(stmt)
            buf = []
    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def _exec_ddl_in_txn(conn: sqlite3.Connection, ddl: str) -> None:
    """Run migration DDL inside the caller's explicit transaction."""
    for stmt in _split_ddl(ddl):
        conn.execute(stmt)


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations in order. Idempotent; returns the version.

    Each migration runs inside its own BEGIN IMMEDIATE transaction covering
    both the DDL and the user_version bump, so a crash can never leave a
    half-applied migration behind. Concurrent migrate() calls serialize on
    the write lock; the loser re-reads the version inside its transaction
    and skips what the winner already applied.
    """
    current = conn.execute("PRAGMA user_version;").fetchone()[0]
    if current > SCHEMA_VERSION:
        raise SchemaTooNewError(
            f"database schema version {current} is newer than supported "
            f"version {SCHEMA_VERSION}; refusing to downgrade"
        )
    for version, name, ddl in MIGRATIONS:
        if version <= current:
            continue
        with transaction(conn):
            # Re-check inside the write transaction: a concurrent migrate()
            # may have applied this version while we waited for the lock.
            now = conn.execute("PRAGMA user_version;").fetchone()[0]
            if version <= now:
                continue
            if version == 4:
                _ensure_v4_column(conn)
            elif version == 3:
                _ensure_v3_attestation(conn)
            else:
                # Never executescript() here: it implicitly commits and
                # would break the per-migration atomic transaction.
                _exec_ddl_in_txn(conn, ddl)
            conn.execute(f"PRAGMA user_version = {version};")
    # Lifecycle columns for human_approvals (single-use + expiry) may be
    # missing on databases created before that hardening; backfill them.
    # Same for the G13 receiver acceptance timestamp on event_payloads.
    with transaction(conn):
        ensure_approvals_columns(conn)
        _ensure_v5_columns(conn)
        from muse_agent_social.store.projections import (
            _ensure_event_payloads_received_at,
        )

        _ensure_event_payloads_received_at(conn)
    _verify_append_only_triggers(conn)
    return conn.execute("PRAGMA user_version;").fetchone()[0]


#: The append-only triggers the audit model rests on. Teardown drops and
#: recreates them inside a single transaction, so a crash can never leave
#: them missing; a missing trigger therefore means tampering or an older
#: buggy teardown ran, and the database must not be used.
_APPEND_ONLY_TRIGGERS = ("events_no_update", "events_no_delete")


def _verify_append_only_triggers(conn: sqlite3.Connection) -> None:
    """Refuse to run when the append-only triggers on ``events`` are missing.

    Without these triggers, ``events`` rows could be UPDATEd or DELETEd
    silently and the append-only guarantee the audit model rests on would
    be gone without a word. Refusing loudly is the only safe behavior.
    """
    tables = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    if "events" not in tables:
        return
    triggers = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        )
    }
    missing = [t for t in _APPEND_ONLY_TRIGGERS if t not in triggers]
    if missing:
        raise DbError(
            "schema-integrity: append-only trigger(s) missing on events: "
            + ", ".join(missing)
            + "; refusing to run without the append-only guarantee "
            "(restore the triggers or the database from backup)"
        )
