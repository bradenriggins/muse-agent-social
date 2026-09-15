"""Unit tests for the SQLite store: WAL mode, constraints, FKs, migrations."""

from __future__ import annotations

import sqlite3

import pytest

from muse_agent_social.store import db
from muse_agent_social.store import migrations

NOW = "2026-09-15T20:00:00Z"
LATER = "2026-09-22T20:00:00Z"


def make_db(tmp_path):
    conn = db.connect(tmp_path / "test.db")
    migrations.migrate(conn)
    return conn


def seed_relationship(conn, rel_id="rel-1"):
    conn.execute(
        "INSERT INTO relationships "
        "(relationship_id, peer_identity_id, peer_display_name, "
        " peer_agreement_key, consent_state, policy, key_epoch, created_at) "
        "VALUES (?, ?, ?, ?, 'active', ?, 1, ?)",
        (rel_id, "did:key:zPeer", "Peer", "zAgreePeer", '{"version": 1}', NOW),
    )
    conn.execute(
        "INSERT INTO key_epochs "
        "(relationship_id, epoch, public_key, private_key_ref, state) "
        "VALUES (?, 1, 'zRelPub', 'keys/rel-1-epoch-1.key', 'active')",
        (rel_id,),
    )
    conn.execute(
        "INSERT INTO conversations (conversation_id) VALUES ('conv-1')"
    )
    conn.execute(
        "INSERT INTO threads (thread_id, conversation_id) VALUES ('thread-1', 'conv-1')"
    )


def insert_event(
    conn,
    event_id="evt-1",
    rel_id="rel-1",
    sender="did:key:zPeer",
    seq=1,
    nonce="bm9uY2UtMQ",
):
    conn.execute(
        "INSERT INTO events (event_id, relationship_id, conversation_id, thread_id,"
        " sender, sender_seq, created_at, key_epoch, event_type, replay_nonce,"
        " sealed_envelope)"
        " VALUES (?, ?, 'conv-1', 'thread-1', ?, ?, ?, 1, 'message.created', ?, ?)",
        (event_id, rel_id, sender, seq, NOW, nonce, b"sealed-bytes"),
    )


def test_wal_mode(tmp_path):
    conn = make_db(tmp_path)
    mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
    assert mode == "wal"
    conn.close()


def test_foreign_keys_enforced_on_connect(tmp_path):
    conn = make_db(tmp_path)
    assert conn.execute("PRAGMA foreign_keys;").fetchone()[0] == 1
    conn.close()


def test_duplicate_event_id_rejected(tmp_path):
    conn = make_db(tmp_path)
    seed_relationship(conn)
    insert_event(conn, event_id="evt-1", nonce="bm9uY2UtMQ")
    with pytest.raises(sqlite3.IntegrityError):
        insert_event(conn, event_id="evt-1", nonce="bm9uY2UtMg")
    conn.close()


def test_duplicate_relationship_sender_seq_rejected(tmp_path):
    conn = make_db(tmp_path)
    seed_relationship(conn)
    insert_event(conn, event_id="evt-1", sender="did:key:zPeer", seq=1, nonce="bm9uY2UtMQ")
    with pytest.raises(sqlite3.IntegrityError):
        insert_event(
            conn, event_id="evt-2", sender="did:key:zPeer", seq=1, nonce="bm9uY2UtMg"
        )
    # Same seq from a different sender is fine.
    insert_event(conn, event_id="evt-2", sender="did:key:zSelf", seq=1, nonce="bm9uY2UtMg")
    conn.close()


def test_duplicate_replay_nonce_rejected(tmp_path):
    conn = make_db(tmp_path)
    seed_relationship(conn)
    insert_event(conn, event_id="evt-1", seq=1, nonce="bm9uY2UtMQ")
    with pytest.raises(sqlite3.IntegrityError):
        insert_event(conn, event_id="evt-2", seq=2, nonce="bm9uY2UtMQ")
    conn.execute(
        "INSERT INTO replay_guard (replay_nonce, expires_at) VALUES (?, ?)",
        ("bm9uY2UtMQ", LATER),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO replay_guard (replay_nonce, expires_at) VALUES (?, ?)",
            ("bm9uY2UtMQ", LATER),
        )
    conn.close()


def test_foreign_keys_enforced(tmp_path):
    conn = make_db(tmp_path)
    seed_relationship(conn)
    # Unknown relationship.
    with pytest.raises(sqlite3.IntegrityError):
        insert_event(conn, event_id="evt-x", rel_id="nope", nonce="bm9uY2UteA")
    # Unknown key epoch (composite FK on relationship + epoch).
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO events (event_id, relationship_id, conversation_id,"
            " sender, sender_seq, created_at, key_epoch, event_type,"
            " replay_nonce, sealed_envelope)"
            " VALUES ('evt-y', 'rel-1', 'conv-1', 'did:key:zPeer', 9, ?, 99,"
            " 'message.created', 'bm9uY2UteQ', ?)",
            (NOW, b"sealed-bytes"),
        )
    # receipt_queue target must reference a committed event.
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO receipt_queue (target_event_id, kind, queued_at)"
            " VALUES ('ghost', 'accepted', ?)",
            (NOW,),
        )
    # projection_queue event must reference a committed event.
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO projection_queue (event_id, queued_at) VALUES ('ghost', ?)",
            (NOW,),
        )
    conn.close()


def test_events_append_only(tmp_path):
    conn = make_db(tmp_path)
    seed_relationship(conn)
    insert_event(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE events SET event_type = 'x' WHERE event_id = 'evt-1'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM events WHERE event_id = 'evt-1'")
    conn.close()


def test_migration_idempotent(tmp_path):
    conn = make_db(tmp_path)
    seed_relationship(conn)
    insert_event(conn)
    first = migrations.migrate(conn)
    assert first == migrations.SCHEMA_VERSION == 1
    second = migrations.migrate(conn)
    assert second == 1
    assert db.get_user_version(conn) == 1
    # Rows survive the no-op second run.
    row = conn.execute(
        "SELECT event_id FROM events WHERE event_id = 'evt-1'"
    ).fetchone()
    assert row is not None
    conn.close()


def test_atomic_receive_pipeline_shape(tmp_path):
    # Mirrors the plan's receive transaction: event + replay + sequence +
    # projection + receipt + surface commit together or not at all.
    conn = make_db(tmp_path)
    seed_relationship(conn)
    with db.transaction(conn):
        insert_event(conn)
        conn.execute(
            "INSERT INTO replay_guard (replay_nonce, expires_at) VALUES (?, ?)",
            ("bm9uY2UtMQ", LATER),
        )
        conn.execute(
            "INSERT INTO sender_sequence (relationship_id, sender, last_seq)"
            " VALUES ('rel-1', 'did:key:zPeer', 1)"
            " ON CONFLICT(relationship_id, sender)"
            " DO UPDATE SET last_seq = excluded.last_seq"
        )
        conn.execute(
            "INSERT INTO projection_queue (event_id, queued_at) VALUES ('evt-1', ?)",
            (NOW,),
        )
        conn.execute(
            "INSERT INTO receipt_queue (target_event_id, kind, queued_at)"
            " VALUES ('evt-1', 'accepted', ?)",
            (NOW,),
        )
        conn.execute(
            "INSERT INTO surface_queue (event_id, policy_snapshot, queued_at)"
            " VALUES ('evt-1', ?, ?)",
            ('{"mode": "silent"}', NOW),
        )
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM replay_guard").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM projection_queue").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM receipt_queue").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM surface_queue").fetchone()[0] == 1
    conn.close()


def test_transaction_rolls_back(tmp_path):
    conn = make_db(tmp_path)
    seed_relationship(conn)
    with pytest.raises(sqlite3.IntegrityError):
        with db.transaction(conn):
            insert_event(conn)
            insert_event(conn, event_id="evt-1", nonce="bm9uY2UtMg")
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    conn.close()


def test_scheduler_queue_states(tmp_path):
    conn = make_db(tmp_path)
    conn.execute(
        "INSERT INTO scheduler_queue"
        " (scheduled_id, inner_event, deliver_at, expires_at, state)"
        " VALUES ('sched-1', ?, ?, ?, 'scheduled')",
        (b"sealed-inner", NOW, LATER),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO scheduler_queue"
            " (scheduled_id, inner_event, deliver_at, state)"
            " VALUES ('sched-2', ?, ?, 'bogus')",
            (b"sealed-inner", NOW),
        )
    conn.close()


def test_invite_state_machine_values(tmp_path):
    conn = make_db(tmp_path)
    conn.execute(
        "INSERT INTO invites (invite_id, state, issued_at, expires_at)"
        " VALUES ('inv-1', 'issued', ?, ?)",
        (NOW, LATER),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO invites (invite_id, state, issued_at, expires_at)"
            " VALUES ('inv-2', 'bogus', ?, ?)",
            (NOW, LATER),
        )
    conn.close()


def test_utcnow_format():
    import re

    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", db.utcnow())
