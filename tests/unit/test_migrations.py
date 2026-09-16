"""Unit tests for schema migration atomicity and version correctness.

Covers: fresh migration reaches version 4 with all artifacts, re-running
is a no-op, a failed migration rolls back to the prior version (no
half-applied DDL), concurrent first-run migrations converge, and the
projection track guarantees the v4 relationship column and the approval
lifecycle columns before stamping version 4.
"""

from __future__ import annotations

import sqlite3
import threading

import pytest

from muse_agent_social.store import db
from muse_agent_social.store import migrations
from muse_agent_social.store import projections
from muse_agent_social.store.db import get_user_version


@pytest.fixture()
def fresh(tmp_path):
    c = db.connect(tmp_path / "m.db")
    yield c
    c.close()


def _columns(conn, table):
    return [r["name"] for r in conn.execute(f"PRAGMA table_info({table});")]


def test_fresh_migrate_reaches_v4(fresh):
    assert migrations.migrate(fresh) == 4
    assert get_user_version(fresh) == 4
    assert "prior_peer_identity_id" in _columns(fresh, "relationships")
    for col in ("expires_at", "consumed_at"):
        assert col in _columns(fresh, "human_approvals"), col
    triggers = {
        r[0]
        for r in fresh.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger';"
        ).fetchall()
    }
    assert "events_no_update" in triggers
    assert "events_no_delete" in triggers


def test_migrate_is_idempotent(fresh):
    assert migrations.migrate(fresh) == 4
    assert migrations.migrate(fresh) == 4
    assert get_user_version(fresh) == 4


def test_failed_migration_rolls_back_to_prior_version(tmp_path, monkeypatch):
    c = db.connect(tmp_path / "m.db")
    try:
        # Bring the DB to v3 by hand, then sabotage the v4 step.
        c.execute("PRAGMA user_version = 0;")
        for version, name, ddl in migrations.MIGRATIONS:
            if version >= 4:
                break
            migrations._exec_ddl_in_txn(c, ddl)
            c.execute(f"PRAGMA user_version = {version};")
        c.commit()
        assert get_user_version(c) == 3

        def _boom(conn):
            raise RuntimeError("simulated v4 DDL failure")

        monkeypatch.setattr(migrations, "_ensure_v4_column", _boom)
        with pytest.raises(RuntimeError, match="simulated v4 DDL failure"):
            migrations.migrate(c)
        # The failed migration left no trace: still v3, no v4 column.
        assert get_user_version(c) == 3
        assert "prior_peer_identity_id" not in _columns(c, "relationships")
        monkeypatch.undo()
    finally:
        c.close()

    # Retry after the sabotage is gone converges to v4.
    c2 = db.connect(tmp_path / "m.db")
    try:
        assert migrations.migrate(c2) == 4
        assert "prior_peer_identity_id" in _columns(c2, "relationships")
    finally:
        c2.close()


def test_concurrent_migrate_converges(tmp_path):
    path = tmp_path / "m.db"
    seed = db.connect(path)
    seed.close()
    results = []
    barrier = threading.Barrier(4)

    def worker():
        c = db.connect(path)
        try:
            barrier.wait(timeout=15)
            results.append(migrations.migrate(c))
        finally:
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert results == [4, 4, 4, 4]
    check = db.connect(path)
    try:
        assert get_user_version(check) == 4
        assert "prior_peer_identity_id" in _columns(check, "relationships")
    finally:
        check.close()


def test_migrate_projections_repeatable_and_backfills_v4(tmp_path):
    c = db.connect(tmp_path / "m.db")
    try:
        migrations.migrate(c)
        assert projections.migrate_projections(c) == 4
        assert projections.migrate_projections(c) == 4
        assert get_user_version(c) == 4
        assert "prior_peer_identity_id" in _columns(c, "relationships")
        for col in ("expires_at", "consumed_at"):
            assert col in _columns(c, "human_approvals"), col
    finally:
        c.close()


def test_migrate_projections_adds_missing_v4_column(tmp_path):
    # Simulate the old bug's aftermath: version stamped 4 but the v4
    # column missing. migrate_projections() must repair it.
    c = db.connect(tmp_path / "m.db")
    try:
        migrations.migrate(c)
        c.execute("ALTER TABLE relationships DROP COLUMN prior_peer_identity_id;")
        c.commit()
        assert "prior_peer_identity_id" not in _columns(c, "relationships")
        assert projections.migrate_projections(c) == 4
        assert "prior_peer_identity_id" in _columns(c, "relationships")
    finally:
        c.close()


def test_split_ddl_preserves_trigger_bodies():
    ddl = """
CREATE TRIGGER trg_no_update BEFORE UPDATE ON events BEGIN
    SELECT RAISE(ABORT, 'events are append-only; updates are forbidden');
END;
CREATE TABLE t2 (id INTEGER PRIMARY KEY);
"""
    stmts = migrations._split_ddl(ddl)
    assert len(stmts) == 2
    assert "RAISE(ABORT" in stmts[0]
    assert stmts[1].startswith("CREATE TABLE t2")
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE events (event_id TEXT PRIMARY KEY);")
    try:
        for stmt in stmts:
            c.execute(stmt)
        assert (
            c.execute(
                "SELECT 1 FROM sqlite_master WHERE type='trigger'"
                " AND name='trg_no_update';"
            ).fetchone()
            is not None
        )
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Regression tests for finding D4 (startup migration hardening).
# ---------------------------------------------------------------------------


def test_migrate_recovers_from_reset_user_version(tmp_path):
    """D4: a user_version reset to 0 on an already-migrated database (the
    old crash wedge) re-runs idempotently instead of dying on
    'duplicate column name'."""
    from muse_agent_social.store import migrations as mig

    c = db.connect(tmp_path / "m.db")
    try:
        assert mig.migrate(c) == 4
        # Simulate the wedge: column present, version reset.
        assert "attestation" in _columns(c, "human_requests")
        c.execute("PRAGMA user_version = 0;")
        assert mig.migrate(c) == 4
        assert "attestation" in _columns(c, "human_requests")
        # And repeated runs stay clean.
        assert mig.migrate(c) == 4
    finally:
        c.close()


def test_migrate_refuses_missing_append_only_trigger(tmp_path):
    """D4: a missing append-only trigger fails startup loudly instead of
    running without the append-only guarantee."""
    from muse_agent_social.store import migrations as mig

    c = db.connect(tmp_path / "m.db")
    try:
        assert mig.migrate(c) == 4
        c.execute("DROP TRIGGER events_no_update;")
        with pytest.raises(db.DbError, match="append-only trigger"):
            mig.migrate(c)
    finally:
        c.close()


def test_migrate_schema_too_new_is_labeled(tmp_path):
    """D4: a database newer than this code raises SchemaTooNewError, a
    DbError the CLI maps to a labeled error."""
    from muse_agent_social.store import migrations as mig

    c = db.connect(tmp_path / "m.db")
    try:
        assert mig.migrate(c) == 4
        c.execute("PRAGMA user_version = 999;")
        with pytest.raises(db.SchemaTooNewError, match="newer than supported"):
            mig.migrate(c)
    finally:
        c.close()


def test_migrate_projections_schema_too_new_is_labeled(tmp_path):
    """D4: migrate_projections maps schema-too-new to SchemaTooNewError
    (not a raw RuntimeError), so Ctx reports schema_too_new."""
    c = db.connect(tmp_path / "m.db")
    try:
        from muse_agent_social.store import migrations as mig

        mig.migrate(c)
        c.execute("PRAGMA user_version = 999;")
        with pytest.raises(
            db.SchemaTooNewError, match="newer than supported"
        ):
            projections.migrate_projections(c)
    finally:
        c.close()


def test_migrate_projections_v3_column_idempotent(tmp_path):
    """D4: the projections track tolerates a pre-existing v3 attestation
    column (e.g. left by the skeleton track) without wedging."""
    from muse_agent_social.store import migrations as mig

    c = db.connect(tmp_path / "m.db")
    try:
        # Skeleton track first: v3 column present via _ensure_v3_attestation.
        assert mig.migrate(c) == 4
        c.execute("PRAGMA user_version = 1;")
        assert projections.migrate_projections(c) == 4
        assert projections.migrate_projections(c) == 4
        assert "attestation" in _columns(c, "human_requests")
    finally:
        c.close()
