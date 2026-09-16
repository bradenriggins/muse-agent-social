"""Unit tests for relationship teardown.

No network. All identities are fictional; all key material is generated
fresh per test. Remote actions (deploy key revocation, relay repo deletion)
go through injected fake hooks.
"""

import json
import os
import stat
import uuid

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
    # Relay metadata is attributed to REL (title prefix + relay_config
    # row), so the hardened discovery treats it as REL's even with REL2
    # present in the database.
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS relay_config (
            relationship_id TEXT PRIMARY KEY,
            provider        TEXT NOT NULL,
            repo_url        TEXT,
            created_at      TEXT NOT NULL
        );
        """
    )
    conn.execute(
        "INSERT INTO relay_config (relationship_id, provider, repo_url,"
        " created_at) VALUES (?, 'github',"
        " 'https://github.com/org/relay-repo.git', ?)",
        (REL, utcnow()),
    )
    (state_dir / "relay.json").write_text(
        json.dumps(
            {
                "deploy_keys": [
                    {
                        "repo": "org/relay-repo",
                        "title": f"mas-pair-{REL}",
                        "key_id": "k1",
                    }
                ],
                "repos": ["org/relay-repo"],
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
    assert hooks.revoked == [("org/relay-repo", f"mas-pair-{REL}")]
    assert hooks.deleted_repos == ["org/relay-repo"]
    assert report.deploy_keys_revoked == [f"org/relay-repo:mas-pair-{REL}"]
    assert report.relay_repos_deleted == ["org/relay-repo"]

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


# ---------------------------------------------------------------------------
# Two-relationship scoping regressions.
#
# A and B share one relay repo ("org/shared-relay"), one relay.json, one
# keys dir, and the same queue/pairing/policy tables. Tearing down A must
# revoke/delete only A's relay entries and rows, wipe only A's key
# subtrees, and leave B fully operational. A second teardown of A is a
# no-op (tombstone idempotency).
# ---------------------------------------------------------------------------


def _two_rel_state(tmp_path):
    """Build a state dir with two relationships; A is the teardown target."""
    from muse_agent_social.model.approvals import APPROVALS_DDL
    from muse_agent_social.model.invites import _ensure_pairing_tables

    state_dir = tmp_path / "tworel"
    conn = open_db(state_dir)
    migrate_schema(conn)
    _ensure_pairing_tables(conn)
    conn.executescript(APPROVALS_DDL)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS relay_config (
            relationship_id TEXT PRIMARY KEY,
            provider        TEXT NOT NULL,
            repo_url        TEXT,
            created_at      TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS quarantine (
            relationship_id TEXT NOT NULL,
            sender          TEXT NOT NULL,
            sender_seq      INTEGER NOT NULL,
            event_id        TEXT NOT NULL,
            reason          TEXT NOT NULL,
            quarantined_at  TEXT NOT NULL,
            PRIMARY KEY (relationship_id, sender, sender_seq, event_id)
        );
        CREATE TABLE IF NOT EXISTS receive_quarantine (
            relationship_id TEXT NOT NULL,
            object_name     TEXT NOT NULL,
            reason          TEXT NOT NULL,
            detail          TEXT,
            quarantined_at  TEXT NOT NULL,
            PRIMARY KEY (relationship_id, object_name)
        );
        CREATE TABLE IF NOT EXISTS sent_objects (
            scheduled_id  TEXT PRIMARY KEY,
            object_name   TEXT NOT NULL,
            queued_at     TEXT NOT NULL
        );
        """
    )
    a = str(uuid.uuid4())
    b = str(uuid.uuid4())
    pubs, inv, ev = {}, {}, {}
    keys_dir = state_dir / "keys"
    for rid, tag in ((a, "a"), (b, "b")):
        conn.execute(
            "INSERT INTO relationships (relationship_id, peer_identity_id,"
            " peer_display_name, peer_agreement_key, consent_state, policy,"
            " key_epoch, created_at)"
            " VALUES (?, 'did:key:zpeer', ?, 'agree', 'active', '{}', 1, ?)",
            (rid, f"peer-{tag}", utcnow()),
        )
        conn.execute(
            "INSERT INTO conversations (conversation_id) VALUES (?)", (rid,)
        )
        conn.execute(
            "INSERT INTO threads (thread_id, conversation_id) VALUES (?, ?)",
            (rid + ":t", rid),
        )
        eid = f"ev-{tag}-{rid[:8]}"
        ev[rid] = eid
        # Per-relationship key subtree, production basename layout. The
        # key_epochs row must exist before events (FK on (rid, key_epoch)).
        key_path = keys_dir / rid / "epoch1.key"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(os.urandom(32))
        os.chmod(key_path, 0o600)
        conn.execute(
            "INSERT INTO key_epochs (relationship_id, epoch, public_key,"
            " private_key_ref, state) VALUES (?, 1, ?, ?, 'active')",
            (rid, f"pub-{tag}", str(key_path)),
        )
        conn.execute(
            "INSERT INTO events (event_id, relationship_id, conversation_id,"
            " thread_id, sender, sender_seq, created_at, key_epoch,"
            " event_type, replay_nonce, sealed_envelope)"
            " VALUES (?, ?, ?, ?, 'sender', 1, ?, 1, 'message.created', ?, ?)",
            (eid, rid, rid, rid + ":t", utcnow(), f"n-{tag}", b"sealed"),
        )
        # Queue rows for this relationship's event.
        conn.execute(
            "INSERT INTO scheduler_queue (scheduled_id, inner_event,"
            " deliver_at, state) VALUES (?, ?, ?, 'scheduled')",
            (eid, b"sealed", utcnow()),
        )
        conn.execute(
            "INSERT INTO receipt_queue (target_event_id, kind, queued_at)"
            " VALUES (?, 'accepted', ?)",
            (eid, utcnow()),
        )
        conn.execute(
            "INSERT INTO surface_queue (event_id, policy_snapshot, queued_at)"
            " VALUES (?, '{}', ?)",
            (eid, utcnow()),
        )
        conn.execute(
            "INSERT INTO sent_objects (scheduled_id, object_name, queued_at)"
            " VALUES (?, ?, ?)",
            (eid, f"obj-{tag}", utcnow()),
        )
        # Pairing ceremony rows, linked via migration_state.
        iid = f"inv-{tag}"
        inv[rid] = iid
        conn.execute(
            "INSERT INTO invites (invite_id, state, issued_at, expires_at)"
            " VALUES (?, 'issued', ?, ?)",
            (iid, utcnow(), utcnow()),
        )
        conn.execute(
            "INSERT INTO invite_bodies (invite_id, invite_json)"
            " VALUES (?, '{}')",
            (iid,),
        )
        conn.execute(
            "INSERT INTO pairing_acceptances (invite_id, invite_json,"
            " acceptance_json, accepted_at) VALUES (?, '{}', '{}', ?)",
            (iid, utcnow()),
        )
        conn.execute(
            "INSERT INTO pairing_verifications (invite_id,"
            " inviter_card_fingerprint, acceptor_card_fingerprint, verified_at,"
            " human_approved) VALUES (?, 'fp1', 'fp2', ?, 0)",
            (iid, utcnow()),
        )
        conn.execute(
            "INSERT INTO migration_state (key, value) VALUES (?, ?)",
            (f"migration.{rid}.invite_id", json.dumps(iid)),
        )
        # Policy / moderation rows.
        conn.execute(
            "INSERT INTO human_approvals (approval_id, relationship_id,"
            " subject_type, subject_id, answer, approved, created_at,"
            " expires_at) VALUES (?, ?, 'human_request', 'sub', 'yes', 1,"
            " ?, ?)",
            (f"appr-{tag}", rid, utcnow(), utcnow()),
        )
        conn.execute(
            "INSERT INTO quarantine (relationship_id, sender, sender_seq,"
            " event_id, reason, quarantined_at)"
            " VALUES (?, 'peer', 7, ?, 'fork', ?)",
            (rid, eid, utcnow()),
        )
        conn.execute(
            "INSERT INTO receive_quarantine (relationship_id, object_name,"
            " reason, quarantined_at) VALUES (?, ?, 'bad', ?)",
            (rid, f"obj-{tag}", utcnow()),
        )
        # Deploy-key registry + relay config: both relationships share one
        # relay repo, each with its own attributed deploy key.
        pub = f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{'A' * 40}{tag} fake-{tag}"
        pubs[rid] = pub
        conn.execute(
            "INSERT INTO deploy_key_registry (deploy_public_key,"
            " relationship_id, registered_at) VALUES (?, ?, ?)",
            (pub, rid, utcnow()),
        )
        conn.execute(
            "INSERT INTO relay_config (relationship_id, provider, repo_url,"
            " created_at) VALUES (?, 'github',"
            " 'https://github.com/org/shared-relay.git', ?)",
            (rid, utcnow()),
        )
        # Pairing-ephemeral key material for this relationship's invite.
        eph = keys_dir / "invites" / iid / "ephemeral.key"
        eph.parent.mkdir(parents=True, exist_ok=True)
        eph.write_bytes(os.urandom(32))
        os.chmod(eph, 0o600)
        (keys_dir / "pairing" / iid).mkdir(parents=True, exist_ok=True)
    (state_dir / "relay.json").write_text(
        json.dumps(
            {
                "deploy_keys": [
                    {
                        "id": f"key-{tag}",
                        "title": f"mas-pair-{rid}",
                        "key": pubs[rid],
                    }
                    for rid, tag in ((a, "a"), (b, "b"))
                ],
                "repos": ["org/shared-relay"],
            },
            indent=2,
        )
        + "\n"
    )
    conn.commit()
    return {
        "conn": conn,
        "state_dir": state_dir,
        "a": a,
        "b": b,
        "ev": ev,
        "inv": inv,
        "pubs": pubs,
        "keys_dir": keys_dir,
    }


def _teardown_a(fx, hooks=None):
    return teardown_relationship(
        fx["conn"],
        fx["state_dir"],
        fx["a"],
        hooks=hooks if hooks is not None else FakeHooks(),
        reason_code="test",
        peer_label="peer-a",
    )


def test_teardown_shared_relay_revokes_only_target(tmp_path):
    """Shared relay.json: A's deploy key revoked and pruned; B's kept.

    The shared repo is NOT deleted while B's relay_config still
    references it; B's relay_config row and registry entry survive.
    """
    fx = _two_rel_state(tmp_path)
    hooks = FakeHooks()
    report = _teardown_a(fx, hooks)

    assert hooks.revoked == [("org/shared-relay", f"mas-pair-{fx['a']}")]
    assert hooks.deleted_repos == []
    assert report.deploy_keys_revoked == [
        f"org/shared-relay:mas-pair-{fx['a']}"
    ]
    assert report.relay_repos_deleted == []

    cfg = json.loads((fx["state_dir"] / "relay.json").read_text())
    assert [k["title"] for k in cfg["deploy_keys"]] == [f"mas-pair-{fx['b']}"]
    assert cfg["repos"] == ["org/shared-relay"]

    conn = fx["conn"]
    assert {
        r[0] for r in conn.execute("SELECT relationship_id FROM relay_config")
    } == {fx["b"]}
    assert {
        r[0]
        for r in conn.execute(
            "SELECT deploy_public_key FROM deploy_key_registry"
        )
    } == {fx["pubs"][fx["b"]]}
    conn.close()


def test_teardown_removes_only_target_queue_rows(tmp_path):
    """Queue tables lose A's event rows; B's rows survive."""
    fx = _two_rel_state(tmp_path)
    _teardown_a(fx)
    conn = fx["conn"]
    assert [r[0] for r in conn.execute("SELECT scheduled_id FROM scheduler_queue")] == [
        fx["ev"][fx["b"]]
    ]
    assert [
        r[0] for r in conn.execute("SELECT target_event_id FROM receipt_queue")
    ] == [fx["ev"][fx["b"]]]
    assert [r[0] for r in conn.execute("SELECT event_id FROM surface_queue")] == [
        fx["ev"][fx["b"]]
    ]
    assert [r[0] for r in conn.execute("SELECT scheduled_id FROM sent_objects")] == [
        fx["ev"][fx["b"]]
    ]
    conn.close()


def test_teardown_removes_only_target_pairing_and_policy_rows(tmp_path):
    """Invites, pairing, approvals, quarantine, registry: A gone, B kept."""
    fx = _two_rel_state(tmp_path)
    _teardown_a(fx)
    conn = fx["conn"]
    assert {r[0] for r in conn.execute("SELECT invite_id FROM invites")} == {
        fx["inv"][fx["b"]]
    }
    assert {r[0] for r in conn.execute("SELECT invite_id FROM invite_bodies")} == {
        fx["inv"][fx["b"]]
    }
    assert {
        r[0] for r in conn.execute("SELECT invite_id FROM pairing_acceptances")
    } == {fx["inv"][fx["b"]]}
    assert {
        r[0] for r in conn.execute("SELECT invite_id FROM pairing_verifications")
    } == {fx["inv"][fx["b"]]}
    for table in ("human_approvals", "quarantine", "receive_quarantine"):
        assert {
            r[0]
            for r in conn.execute(
                f"SELECT DISTINCT relationship_id FROM {table}"
            )
        } == {fx["b"]}, table
    # A's relationship-scoped migration state is gone; B's invite link kept.
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM migration_state WHERE key = ?",
            (f"migration.{fx['a']}.invite_id",),
        ).fetchone()[0]
        == 0
    )
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM migration_state WHERE key = ?",
            (f"migration.{fx['b']}.invite_id",),
        ).fetchone()[0]
        == 1
    )
    conn.close()


def test_teardown_removes_only_target_key_subtree(tmp_path):
    """Only <keys_dir>/<A> (securely wiped) and A's invite material go.

    Sibling subtrees, the shared keys dir, and B's invite material stay.
    Both relationships use the production "epoch1.key" basename, which
    must not trip the postcheck for the surviving sibling.
    """
    fx = _two_rel_state(tmp_path)
    hooks = FakeHooks()
    report = _teardown_a(fx, hooks)
    assert report.postcheck_hits == []

    kd = fx["keys_dir"]
    assert not (kd / fx["a"]).exists()
    assert (kd / fx["b"] / "epoch1.key").is_file()
    assert kd.is_dir()
    assert not (kd / "invites" / fx["inv"][fx["a"]]).exists()
    assert (kd / "invites" / fx["inv"][fx["b"]] / "ephemeral.key").is_file()
    assert not (kd / "pairing" / fx["inv"][fx["a"]]).exists()
    assert (kd / "pairing" / fx["inv"][fx["b"]]).is_dir()
    fx["conn"].close()


def test_teardown_second_run_is_idempotent_noop(tmp_path):
    """A second teardown of A returns already_torn_down without hooks."""
    fx = _two_rel_state(tmp_path)
    hooks = FakeHooks()
    first = _teardown_a(fx, hooks)
    assert first.already_torn_down is False
    assert len(hooks.revoked) == 1

    second = teardown_relationship(
        fx["conn"],
        fx["state_dir"],
        fx["a"],
        hooks=hooks,
        reason_code="test",
        peer_label="peer-a",
    )
    assert second.already_torn_down is True
    assert second.postcheck_hits == []
    # No further remote calls on the repeat run.
    assert len(hooks.revoked) == 1
    assert hooks.deleted_repos == []
    fx["conn"].close()


def test_teardown_keeps_unattributed_relay_entries_when_ambiguous(tmp_path):
    """Unattributed relay.json entries survive when ownership is ambiguous.

    With two relationships in the DB, an entry carrying no attribution
    could belong to either one: it is preserved and no hook fires.
    """
    fx = _two_rel_state(tmp_path)
    # Append unattributed legacy entries alongside the attributed ones.
    cfg_path = fx["state_dir"] / "relay.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["deploy_keys"].append(
        {"id": "legacy-1", "title": "legacy-key", "key": "ssh-x"}
    )
    cfg["repos"].append("org/legacy-repo")
    cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")
    hooks = FakeHooks()
    report = _teardown_a(fx, hooks)
    # A's attributed key was still revoked; the unattributed legacy
    # entries were preserved and no repo was deleted.
    assert hooks.revoked == [("org/shared-relay", f"mas-pair-{fx['a']}")]
    assert hooks.deleted_repos == []
    assert report.deploy_keys_revoked == [
        f"org/shared-relay:mas-pair-{fx['a']}"
    ]
    cfg = json.loads((fx["state_dir"] / "relay.json").read_text())
    assert [k["title"] for k in cfg["deploy_keys"]] == [
        f"mas-pair-{fx['b']}",
        "legacy-key",
    ]
    assert cfg["repos"] == ["org/shared-relay", "org/legacy-repo"]
    fx["conn"].close()
