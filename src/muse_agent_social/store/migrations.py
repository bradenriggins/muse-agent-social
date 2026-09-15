"""Versioned, idempotent SQLite migrations.

The schema version is tracked in PRAGMA user_version. migrate() applies
every pending migration in order inside its own transaction and is safe to
run repeatedly: a second run is a no-op.
"""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 4

# Migration 2 gathers the auxiliary DDL owned by feature modules so that a
# single migrate() call brings a fresh database to the full v0.2 schema.
# Each fragment is CREATE TABLE / INDEX IF NOT EXISTS and therefore
# idempotent; the owning modules may also apply their own fragments
# directly (migrate_projections(), rotation._ensure_tables(), the github
# transport's table setup) with identical results.
from muse_agent_social.crypto.rotation import _ROTATION_TABLES
from muse_agent_social.model.approvals import APPROVALS_DDL
from muse_agent_social.store.projections import _V2_DDL as _PROJECTIONS_V2_DDL
from muse_agent_social.store.projections import _V3_DDL as _PROJECTIONS_V3_DDL

# Migration 4: remember the peer's previous identity id across an
# identity rotation, so delayed pre-rotation events and redelivered
# rotation announcements from the old identity are still attributable
# instead of being rejected as unknown_sender.
_V4_DDL = """
ALTER TABLE relationships ADD COLUMN prior_peer_identity_id TEXT;
"""
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
MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "v1_initial_schema", _V1_DDL),
    (2, "v2_projections_rotation_transport", _V2_DDL),
    (3, "v3_human_approval_attestation", _PROJECTIONS_V3_DDL),
    (4, "v4_prior_peer_identity", _V4_DDL),
]


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations in order. Idempotent; returns the version."""
    current = conn.execute("PRAGMA user_version;").fetchone()[0]
    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {current} is newer than supported "
            f"version {SCHEMA_VERSION}; refusing to downgrade"
        )
    for version, name, ddl in MIGRATIONS:
        if version <= current:
            continue
        with conn:
            conn.executescript(ddl)
            conn.execute(f"PRAGMA user_version = {version};")
    return conn.execute("PRAGMA user_version;").fetchone()[0]
