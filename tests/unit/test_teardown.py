"""Unit tests for relationship teardown.

No network. All identities are fictional; all key material is generated
fresh per test. Remote actions (deploy key revocation, relay repo deletion)
go through injected fake hooks.
"""

import json
import os
import stat

import pytest

from muse_agent_social.store.db import open_db, utcnow
from muse_agent_social.store.migrations import migrate as migrate_schema
from muse_agent_social.teardown import (
    TeardownError,
    TeardownHooks,
    postcheck_scan,
    secure_unlink,
    teardown_relationship,
)

REL = "rel-teardown-fixture-01"
REL2 = "rel-teardown-fixture-02"
PEER_LABEL = "teardown-peer"


class FakeHooks(TeardownHooks):
    def __init__(self):
        super().__init__(
            revoke_deploy_key=self._revoke,
            delete_relay_repo=self._delete_repo,
        )
        self.revoked = []
        self.deleted_repos = []

    def _revoke(self, dk):
        self.revoked.append((dk.repo, dk.label))

    def _delete_repo(self, repo):
        self.deleted_repos.append(repo.repo)


def _build_state(tmp_path):
    """Populate a v0.2 state dir with two relationships; REL is torn down."""
    state_dir = tmp_path / "state"
    conn = open_db(state_dir)
    migrate_schema(conn)

    keys_dir = state_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    key_files = {}
    for name in ("rel.key", "rel-rot.key", "rel2.key"):
        p = keys_dir / name
        p.write_bytes(os.urandom(32))
        os.chmod(p, 0o600)
        key_files[name] = str(p)

    conn.execute(
        "INSERT INTO relationships (relationship_id, peer_identity_id,"
        " peer_display_name, peer_agreement_key, consent_state, policy,"
        " key_epoch, created_at) VALUES (?, 'did:key:zpeer1', ?, 'agree1',"
        " 'active', '{}', 2, ?)",
        (REL, PEER_LABEL, utcnow()),
    )
    conn.execute(
        "INSERT INTO relationships (relationship_id, peer_identity_id,"
        " consent_state, policy, key_epoch, created_at)"
        " VALUES (?, 'did:key:zpeer2', 'active', '{}', 1, ?)",
        (REL2, utcnow()),
    )
    conn.execute(
        "INSERT INTO key_epochs (relationship_id, epoch, public_key,"
        " private_key_ref, state) VALUES (?, 1, 'pub1', ?, 'retired'),"
        " (?, 2, 'pub2', ?, 'active')",
        (REL, key_files["rel.key"], REL, key_files["rel-rot.key"]),
    )
    conn.execute(
        "INSERT INTO key_epochs (relationship_id, epoch, public_key,"
        " private_key_ref, state) VALUES (?, 1, 'pub9', ?, 'active')",
        (REL2, key_files["rel2.key"]),
    )
    for rel in (REL, REL2):
        conn.execute(
            "INSERT INTO conversations (conversation_id) VALUES (?)", (rel,)
        )
        conn.execute(
            "INSERT INTO threads (thread_id, conversation_id) VALUES (?, ?)",
            (rel + ":t", rel),
        )
    events = [("ev-1", REL, 1, "n1"), ("ev-2", REL, 2, "n2"), ("ev-9", REL2, 1, "n9")]
    for eid, rel, seq, nonce in events:
        conn.execute(
            "INSERT INTO events (event_id, relationship_id, conversation_id,"
            " thread_id, sender, sender_seq, created_at, key_epoch,"
            " event_type, replay_nonce, sealed_envelope)"
            " VALUES (?, ?, ?, ?, 'sender', ?, ?, 1, 'message.created', ?, ?)",
            (eid, rel, rel, rel + ":t", seq, utcnow(), nonce, b"sealed"),
        )
    for eid in ("ev-1", "ev-2"):
        conn.execute(
            "INSERT INTO projection_queue (event_id, queued_at) VALUES (?, ?)",
            (eid, utcnow()),
        )
        conn.execute(
            "INSERT INTO surface_queue (event_id, policy_snapshot, queued_at)"
            " VALUES (?, '{}', ?)",
            (eid, utcnow()),
        )
        conn.execute(
            "INSERT INTO receipt_queue (target_event_id, kind, queued_at)"
            " VALUES (?, 'accepted', ?)",
            (eid, utcnow()),
        )
    for nonce in ("n1", "n2", "n9"):
        conn.execute(
            "INSERT INTO replay_guard (replay_nonce, expires_at)"
            " VALUES (?, ?)",
            (nonce, utcnow()),
        )
    conn.execute(
        "INSERT INTO sender_sequence (relationship_id, sender, last_seq)"
        " VALUES (?, 'sender', 2)",
        (REL,),
    )
    conn.execute(
        "INSERT INTO invites (invite_id, state, issued_at, expires_at)"
        " VALUES ('inv-1', 'issued', ?, ?)",
        (utcnow(), utcnow()),
    )
    conn.execute(
        "INSERT INTO migration_state (key, value) VALUES"
        " ('migration.phase', '\"idle\"'),"
        " (?, ?),"
        " ('migration.note', ?)",
        (
            f"migration.{REL}.invite_id",
            json.dumps("inv-1"),
            json.dumps({"for": REL}),
        ),
    )

    # Operational files, some containing the pair id or peer label.
    for dirname in ("bundles", "mirror", "cache", "inbox", "outbox", "retry"):
        d = state_dir / dirname
        d.mkdir(parents=True, exist_ok=True)
        (d / "blob.json").write_text(json.dumps({"rel": REL}))
    (state_dir / f"{REL}.stray").write_text(f"label={PEER_LABEL}")
    (state_dir / "relay.json").write_text(
        json.dumps(
            {
                "deploy_keys": [
                    {"repo": "relay-repo", "label": "old-key", "key_id": "k1"}
                ],
                "repos": ["relay-repo"],
            }
        )
    )
    conn.commit()
    return conn, state_dir, key_files


def _count(conn, table, where="", params=()):
    q = f"SELECT COUNT(*) FROM {table}" + (f" WHERE {where}" if where else "")
    return conn.execute(q, params).fetchone()[0]


# ---------------------------------------------------------------------------


def test_teardown_full(tmp_path):
    conn, state_dir, key_files = _build_state(tmp_path)
    hooks = FakeHooks()
    report = teardown_relationship(
        conn,
        state_dir,
        REL,
        hooks=hooks,
        reason_code="test",
        peer_label=PEER_LABEL,
    )

    # Database rows for REL are gone; REL2 is untouched.
    assert _count(conn, "relationships", "relationship_id = ?", (REL,)) == 0
    assert _count(conn, "key_epochs", "relationship_id = ?", (REL,)) == 0
    assert _count(conn, "events", "relationship_id = ?", (REL,)) == 0
    assert _count(conn, "projection_queue") == 0
    assert _count(conn, "surface_queue") == 0
    assert _count(conn, "receipt_queue") == 0
    assert _count(conn, "replay_guard", "replay_nonce IN ('n1','n2')") == 0
    assert _count(conn, "sender_sequence", "relationship_id = ?", (REL,)) == 0
    assert _count(conn, "invites", "invite_id = 'inv-1'") == 0
    assert _count(conn, "relationships", "relationship_id = ?", (REL2,)) == 1
    assert _count(conn, "events", "relationship_id = ?", (REL2,)) == 1
    # Global migration phase record is preserved.
    row = conn.execute(
        "SELECT value FROM migration_state WHERE key = 'migration.phase'"
    ).fetchone()
    assert json.loads(row["value"]) == "idle"
    # Relationship-scoped migration state is gone.
    assert (
        _count(
            conn,
            "migration_state",
            "value LIKE ?",
            (f"%{REL}%",),
        )
        == 0
    )

    # Key material destroyed first; other key file survives.
    assert not os.path.exists(key_files["rel.key"])
    assert not os.path.exists(key_files["rel-rot.key"])
    assert os.path.exists(key_files["rel2.key"])
    assert report.crypto_erasure_before_bulk is True
    assert report.step_log.index("destroy-private-keys") < report.step_log.index(
        "delete-state"
    )

    # Operational state removed.
    for dirname in ("bundles", "mirror", "cache", "inbox", "outbox", "retry"):
        assert not (state_dir / dirname).exists(), dirname
    assert not (state_dir / "relay.json").exists()
    assert not (state_dir / f"{REL}.stray").exists()

    # Hooks were called in plan order (revoke before repo delete).
    assert hooks.revoked == [("relay-repo", "old-key")]
    assert hooks.deleted_repos == ["relay-repo"]
    assert report.deploy_keys_revoked == ["relay-repo:old-key"]
    assert report.relay_repos_deleted == ["relay-repo"]

    # Only the tombstone remains.
    tomb = json.loads(open(report.tombstone_path, encoding="utf-8").read())
    assert set(tomb.keys()) == {
        "relationship_id_sha256",
        "revoked_at",
        "reason_code",
    }
    assert tomb["reason_code"] == "test"
    assert PEER_LABEL not in json.dumps(tomb)
    assert REL not in json.dumps(tomb)
    assert stat.S_IMODE(os.stat(report.tombstone_path).st_mode) == 0o600

    # Post-check is clean and the append-only triggers were restored.
    assert report.postcheck_hits == []
    assert report.postcheck_scanned > 0
    triggers = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
    }
    assert {"events_no_update", "events_no_delete"} <= triggers
    conn.close()


def test_teardown_dry_run_changes_nothing(tmp_path):
    conn, state_dir, key_files = _build_state(tmp_path)
    report = teardown_relationship(
        conn, state_dir, REL, hooks=None, peer_label=PEER_LABEL, dry_run=True
    )
    assert report.dry_run is True
    assert _count(conn, "relationships", "relationship_id = ?", (REL,)) == 1
    assert _count(conn, "events", "relationship_id = ?", (REL,)) == 2
    assert os.path.exists(key_files["rel.key"])
    assert (state_dir / "bundles").exists()
    assert (state_dir / "relay.json").exists()
    assert not os.path.exists(report.tombstone_path)
    conn.close()


def test_teardown_unknown_relationship(tmp_path):
    conn, state_dir, _ = _build_state(tmp_path)
    with pytest.raises(TeardownError) as exc_info:
        teardown_relationship(conn, state_dir, "rel-nope", hooks=FakeHooks())
    assert exc_info.value.code == "unknown-relationship"
    conn.close()


def test_teardown_missing_hooks_fails_fast(tmp_path):
    conn, state_dir, _ = _build_state(tmp_path)
    with pytest.raises(TeardownError) as exc_info:
        teardown_relationship(conn, state_dir, REL, hooks=TeardownHooks())
    assert exc_info.value.code == "hook-required"
    # Failed fast: the relationship was NOT marked revoked.
    row = conn.execute(
        "SELECT consent_state FROM relationships WHERE relationship_id = ?",
        (REL,),
    ).fetchone()
    assert row["consent_state"] == "active"
    conn.close()


def test_postcheck_scan_finds_planted_artifacts(tmp_path):
    root = tmp_path / "scan"
    root.mkdir()
    (root / "content.txt").write_text(f"something {REL} something")
    (root / f"{PEER_LABEL}.txt").write_text("label in filename")
    (root / "rel.key").write_text("key filename")
    (root / "clean.txt").write_text("nothing here")
    tomb = root / "tombstones"
    tomb.mkdir()
    (tomb / "abc123.json").write_text(json.dumps({"h": "x"}))
    result = postcheck_scan(root, REL, PEER_LABEL, ("rel.key",))
    assert result["scanned"] == 4
    assert sorted(result["hits"]) == sorted(
        [str(root / "content.txt"), str(root / f"{PEER_LABEL}.txt"), str(root / "rel.key")]
    )


def test_secure_unlink(tmp_path):
    p = tmp_path / "secret.bin"
    p.write_bytes(os.urandom(64))
    assert secure_unlink(p) is True
    assert not p.exists()
    assert secure_unlink(tmp_path / "missing") is False
