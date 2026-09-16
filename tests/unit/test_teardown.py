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
    _teardown_journal_path,
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

    # Only the minimal-spec tombstone remains.
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
    # The transient journal is deleted on success.
    journal = _teardown_journal_path(state_dir, REL)
    assert not journal.exists()

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


# ---------------------------------------------------------------------------
# Regression tests for findings D1, D3, D5, D8, D9.
# ---------------------------------------------------------------------------


def test_chunks_splits_and_bounds():
    from muse_agent_social.teardown import _chunks

    assert list(_chunks([])) == []
    assert list(_chunks([1, 2, 3], size=2)) == [[1, 2], [3]]
    big = list(range(1200))
    parts = list(_chunks(big))
    assert len(parts) == 3
    assert all(len(p) <= 500 for p in parts)
    assert [x for p in parts for x in p] == big


def test_teardown_trigger_drop_is_atomic_on_mid_txn_failure(
    tmp_path, monkeypatch
):
    """D1: a failure inside the teardown transaction rolls everything back.

    The append-only triggers must still exist and no relationship-scoped
    row may be left partially deleted; a retry then converges.
    """
    import muse_agent_social.teardown as td_mod

    fx = _two_rel_state(tmp_path)

    def boom(conn, relationship_id):
        raise RuntimeError("simulated crash inside teardown transaction")

    monkeypatch.setattr(td_mod, "_delete_relationship_mstate", boom)
    with pytest.raises(RuntimeError):
        _teardown_a(fx)
    conn = fx["conn"]
    # The trigger drops were rolled back: the append-only guarantee is
    # intact and observable.
    triggers = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
    }
    assert {"events_no_update", "events_no_delete"} <= triggers
    # Nothing was partially deleted.
    assert _count(conn, "relationships", "relationship_id = ?", (fx["a"],)) == 1
    assert _count(conn, "events", "relationship_id = ?", (fx["a"],)) == 1
    assert _count(conn, "key_epochs", "relationship_id = ?", (fx["a"],)) == 1
    # A retry converges fully.
    monkeypatch.undo()
    report = _teardown_a(fx)
    assert report.postcheck_hits == []
    assert _count(conn, "relationships", "relationship_id = ?", (fx["a"],)) == 0
    conn.close()


def test_teardown_completed_hooks_not_repeated_after_crash(
    tmp_path, monkeypatch
):
    """D3: hooks recorded complete are never repeated by a resumed run."""
    import muse_agent_social.teardown as td_mod

    fx = _two_rel_state(tmp_path)
    hooks = FakeHooks()

    def boom(*args, **kwargs):
        raise RuntimeError("simulated crash before tombstone")

    monkeypatch.setattr(td_mod, "_write_tombstone", boom)
    with pytest.raises(RuntimeError):
        _teardown_a(fx, hooks)
    # The remote action completed and its completion was recorded.
    assert len(hooks.revoked) == 1
    conn = fx["conn"]
    logged = conn.execute(
        "SELECT hook, target FROM teardown_hook_log WHERE relationship_id = ?",
        (fx["a"],),
    ).fetchall()
    # Only the deploy-key revoke: the shared relay repo is kept while B
    # still references it, so no repo hook fired.
    assert [r[0] for r in logged] == ["revoke_deploy_key"]
    # Resume: the completed hook is skipped, teardown converges.
    monkeypatch.undo()
    report = _teardown_a(fx, hooks)
    assert len(hooks.revoked) == 1
    assert hooks.deleted_repos == []
    assert report.postcheck_hits == []
    conn.close()


def test_teardown_tombstone_path_rewipes_leftover_files(tmp_path):
    """D3: the tombstone path re-drives the file wipe instead of wedging.

    A stray created after the first run's wipe is cleaned by the second
    run; the postcheck stays clean and the run reports already_torn_down.
    """
    fx = _two_rel_state(tmp_path)
    first = _teardown_a(fx)
    assert first.already_torn_down is False
    stray = fx["state_dir"] / "bundles" / "late-arrival.json"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_text(json.dumps({"rel": fx["a"]}))
    second = _teardown_a(fx)
    assert second.already_torn_down is True
    assert second.postcheck_hits == []
    assert not stray.exists()
    fx["conn"].close()


def test_teardown_tombstone_path_still_dirty_raises(tmp_path, monkeypatch):
    """D3: a postcheck that is STILL dirty after a fresh re-wipe raises
    instead of silently succeeding."""
    import muse_agent_social.teardown as td_mod

    fx = _two_rel_state(tmp_path)
    _teardown_a(fx)
    stray = fx["state_dir"] / "bundles" / "late-arrival.json"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_text(json.dumps({"rel": fx["a"]}))
    # Break the re-wipe so the stray survives it.
    monkeypatch.setattr(
        td_mod, "_wipe_relationship_files", lambda *a, **k: None
    )
    with pytest.raises(TeardownError) as exc_info:
        _teardown_a(fx)
    assert exc_info.value.code == "postcheck-dirty"
    fx["conn"].close()


def test_teardown_key_wipe_failure_is_hard_error(tmp_path, monkeypatch):
    """D5: a failed private-key wipe aborts teardown loudly and attests
    nothing: no keys_destroyed entry, no tombstone, row still present."""
    import muse_agent_social.teardown as td_mod

    fx = _two_rel_state(tmp_path)
    monkeypatch.setattr(td_mod, "delete_private_key", lambda ref: False)
    with pytest.raises(TeardownError) as exc_info:
        _teardown_a(fx)
    assert exc_info.value.code == "key-destruction-failed"
    conn = fx["conn"]
    assert _count(conn, "relationships", "relationship_id = ?", (fx["a"],)) == 1
    assert not td_mod._tombstone_path(fx["state_dir"], fx["a"]).is_file()
    conn.close()


def test_teardown_chunked_deletes_handle_large_history(tmp_path):
    """D8: histories larger than the SQLite bound-variable limit are
    deleted through chunked IN lists; the survivor is untouched."""
    fx = _two_rel_state(tmp_path)
    conn = fx["conn"]
    rid = fx["a"]
    for i in range(1200):
        eid = f"bulk-{i:05d}"
        conn.execute(
            "INSERT INTO events (event_id, relationship_id, conversation_id,"
            " thread_id, sender, sender_seq, created_at, key_epoch,"
            " event_type, replay_nonce, sealed_envelope)"
            " VALUES (?, ?, ?, ?, 'sender', ?, ?, 1, 'message.created', ?, ?)",
            (
                eid,
                rid,
                rid,
                rid + ":t",
                100 + i,
                utcnow(),
                f"bulk-nonce-{i}",
                b"sealed",
            ),
        )
        conn.execute(
            "INSERT INTO projection_queue (event_id, queued_at)"
            " VALUES (?, ?)",
            (eid, utcnow()),
        )
        conn.execute(
            "INSERT INTO receipt_queue (target_event_id, kind, queued_at)"
            " VALUES (?, 'accepted', ?)",
            (eid, utcnow()),
        )
        conn.execute(
            "INSERT INTO scheduler_queue (scheduled_id, inner_event,"
            " deliver_at, state) VALUES (?, ?, ?, 'scheduled')",
            (eid, b"sealed", utcnow()),
        )
    conn.commit()
    report = _teardown_a(fx)
    assert report.postcheck_hits == []
    assert _count(conn, "events", "relationship_id = ?", (rid,)) == 0
    assert _count(conn, "projection_queue") == 0
    assert _count(conn, "receipt_queue") == 1
    assert _count(conn, "scheduler_queue") == 1
    # The surviving relationship is untouched.
    assert _count(conn, "events", "relationship_id = ?", (fx["b"],)) == 1
    conn.close()


def test_teardown_tombstone_written_before_row_delete(tmp_path, monkeypatch):
    """D9: a crash between the tombstone write and the relationship-row
    delete leaves a resumable state (tombstone present, row present), and
    a retry converges."""
    import muse_agent_social.teardown as td_mod

    fx = _two_rel_state(tmp_path)
    real_transaction = td_mod.transaction
    calls = []

    def crash_on_entry(conn):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("simulated crash before main transaction")
        return real_transaction(conn)

    monkeypatch.setattr(td_mod, "transaction", crash_on_entry)
    with pytest.raises(RuntimeError):
        _teardown_a(fx)
    conn = fx["conn"]
    tombstone = td_mod._tombstone_path(fx["state_dir"], fx["a"])
    assert tombstone.is_file()
    assert _count(conn, "relationships", "relationship_id = ?", (fx["a"],)) == 1
    # The journal already carries the invite ids for the resume wipe;
    # the tombstone keeps the minimal spec contract.
    journal = _teardown_journal_path(fx["state_dir"], fx["a"])
    assert journal.is_file()
    journal_data = json.loads(journal.read_text(encoding="utf-8"))
    assert journal_data["invite_ids"] == [fx["inv"][fx["a"]]]
    tomb = json.loads(tombstone.read_text(encoding="utf-8"))
    assert set(tomb.keys()) == {
        "relationship_id_sha256",
        "revoked_at",
        "reason_code",
    }
    # Retry converges.
    monkeypatch.undo()
    report = _teardown_a(fx)
    assert report.postcheck_hits == []
    assert _count(conn, "relationships", "relationship_id = ?", (fx["a"],)) == 0
    conn.close()


# ---------------------------------------------------------------------------
# Regression test for finding D10.
# ---------------------------------------------------------------------------


def test_revoke_keeps_relay_config_for_discovery(tmp_path, monkeypatch):
    """D10: cmd_revoke must not delete relay_config before teardown.

    A's relay repo is claimed only by A's relay_config row. The old
    pre-deletion blinded _discover_relay_refs: the repo looked unclaimed
    while B still existed, so it was kept forever. Now the repo-delete
    hook fires for A's repo and B's repo is untouched.
    """
    from pathlib import Path
    from types import SimpleNamespace

    import muse_agent_social.cli as cli_mod

    fx = _two_rel_state(tmp_path)
    conn = fx["conn"]
    # Distinct peer ids: cmd_revoke derives the postcheck peer-label
    # needle from the real peer_identity_id, and B's surviving row must
    # not trip it.
    conn.execute(
        "UPDATE relationships SET peer_identity_id = 'did:key:zpeerA'"
        " WHERE relationship_id = ?",
        (fx["a"],),
    )
    conn.execute(
        "UPDATE relay_config SET repo_url = ? WHERE relationship_id = ?",
        ("https://github.com/org/a-relay.git", fx["a"]),
    )
    conn.execute(
        "UPDATE relay_config SET repo_url = ? WHERE relationship_id = ?",
        ("https://github.com/org/b-relay.git", fx["b"]),
    )
    conn.commit()
    (fx["state_dir"] / "relay.json").write_text(
        json.dumps({"deploy_keys": [], "repos": ["org/a-relay", "org/b-relay"]})
    )

    fired = []

    class FakeRevokeHooks:
        def __init__(self, state_dir, token, delete_remote):
            pass

        def revoke_deploy_key(self, ref):
            fired.append(("revoke-deploy-key", ref.label))

        def delete_relay_repo(self, ref):
            fired.append(("delete-relay-repo", ref.repo))

    class FakeCtx:
        def __init__(self, state_dir):
            self.state_dir = Path(state_dir)
            self.conn = conn

        def close(self):
            pass

    monkeypatch.setattr(cli_mod, "_RevokeHooks", FakeRevokeHooks)
    monkeypatch.setattr(cli_mod, "Ctx", FakeCtx)
    args = SimpleNamespace(
        state_dir=str(fx["state_dir"]),
        relationship=fx["a"],
        yes=True,
        reason="test",
        token=None,
        delete_remote=False,
    )
    assert cli_mod.cmd_revoke(args) == 0
    assert ("delete-relay-repo", "org/a-relay") in fired
    assert ("delete-relay-repo", "org/b-relay") not in fired
    conn.close()
