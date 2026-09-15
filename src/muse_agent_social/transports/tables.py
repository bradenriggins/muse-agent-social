"""Transport state-table DDL.

This module intentionally imports nothing from the ``muse_agent_social``
package: ``store/migrations.py`` applies this DDL as part of the versioned
schema, and importing it through ``transports.github`` would create a
package import cycle (github -> base -> policy -> store -> migrations ->
github). Both ``transports.github`` and ``store/migrations.py`` import the
single definition here.
"""

from __future__ import annotations

TRANSPORT_DDL = """
CREATE TABLE IF NOT EXISTS transport_mutations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mutation_id     TEXT NOT NULL UNIQUE,
    relationship_id TEXT NOT NULL,
    op              TEXT NOT NULL CHECK(op IN ('upload', 'consume')),
    object_name     TEXT NOT NULL,
    data            BLOB,
    state           TEXT NOT NULL DEFAULT 'queued'
        CHECK(state IN ('queued', 'done', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    CHECK((op = 'upload' AND data IS NOT NULL)
       OR (op = 'consume' AND data IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_transport_mutations_rel_state
    ON transport_mutations(relationship_id, state);
CREATE TABLE IF NOT EXISTS transport_push_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    relationship_id TEXT NOT NULL,
    pushed_at       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transport_push_log_rel_time
    ON transport_push_log(relationship_id, pushed_at);
"""
