"""Crash-window tests for relationship teardown (findings D1, D3, D9).

Each test kills the teardown once at one fault boundary, then re-runs it
and proves convergence: exactly one terminal result, a fully torn-down
relationship with a clean postcheck. No wedged tombstone paths, no missing
append-only triggers, no repeated remote hook calls.

Fault boundaries:
  * commit of the main DB transaction -> SQLite atomic commit; the kill
    lands before COMMIT executes, so the transaction helper rolls back.
  * file wipe after the DB commit      -> the tombstone path re-drives the
    idempotent file wipe before its postcheck.
  * key destruction (step 3)          -> the re-run recaptures key rows;
    delete_private_key treats a missing file as done.
  * postcheck scan                    -> the resume path re-wipes (no-op)
    and re-scans clean.
"""

import sqlite3

import pytest

import muse_agent_social.teardown as td_mod
from unit.test_teardown import FakeHooks, _count, _teardown_a, _two_rel_state


class FaultInjected(Exception):
    """Simulated crash at a fault boundary."""


class CrashConn:
    """sqlite3 connection proxy that raises FaultInjected once when an
    execute() contains the kill substring.

    A kill at COMMIT rolls the real connection back before raising: that
    is what the OS does to the hot journal when the process dies, and it
    is the same pattern the receive crash tests use.
    """

    def __init__(self, real: sqlite3.Connection, kill_sql: str):
        self._real = real
        self._kill_sql = kill_sql
        self._armed = True

    def execute(self, sql, params=()):
        if self._armed and self._kill_sql in sql:
            self._armed = False
            if self._kill_sql == "COMMIT;":
                self._real.execute("ROLLBACK;")
            raise FaultInjected(f"crash at: {sql[:60]}")
        return self._real.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _triggers(conn):
    return {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
    }


def test_crash_at_commit_rolls_back_and_retries(tmp_path):
    """Kill at the main transaction's COMMIT: the whole DB step rolls
    back (triggers intact, rows intact); a retry converges."""
    fx = _two_rel_state(tmp_path)
    hooks = FakeHooks()
    crashing = CrashConn(fx["conn"], "COMMIT;")
    with pytest.raises(FaultInjected):
        td_mod.teardown_relationship(
            crashing,
            fx["state_dir"],
            fx["a"],
            hooks=hooks,
            reason_code="test",
            peer_label="peer-a",
        )
    conn = fx["conn"]
    # The transaction helper rolled back: triggers present, rows intact.
    assert {"events_no_update", "events_no_delete"} <= _triggers(conn)
    assert _count(conn, "relationships", "relationship_id = ?", (fx["a"],)) == 1
    assert _count(conn, "events", "relationship_id = ?", (fx["a"],)) == 1
    # The deploy-key hook fired before the crash; the retry must not
    # repeat it.
    assert len(hooks.revoked) == 1
    report = _teardown_a(fx, hooks)
    assert len(hooks.revoked) == 1
    assert report.postcheck_hits == []
    assert _count(conn, "relationships", "relationship_id = ?", (fx["a"],)) == 0
    assert {"events_no_update", "events_no_delete"} <= _triggers(conn)
    conn.close()


def test_crash_during_file_wipe_resumes(tmp_path, monkeypatch):
    """Kill during the file wipe (DB commit already durable): the resume
    path re-drives the idempotent wipe and the postcheck is clean."""
    fx = _two_rel_state(tmp_path)
    real_wipe = td_mod._secure_wipe_subtree
    calls = []

    def crash_once(target, report, dry_run):
        calls.append(1)
        if len(calls) == 1:
            raise FaultInjected("crash during file wipe")
        return real_wipe(target, report, dry_run)

    monkeypatch.setattr(td_mod, "_secure_wipe_subtree", crash_once)
    with pytest.raises(FaultInjected):
        _teardown_a(fx)
    conn = fx["conn"]
    # The DB work committed: the relationship row is gone and the
    # tombstone is durable.
    assert _count(conn, "relationships", "relationship_id = ?", (fx["a"],)) == 0
    assert td_mod._tombstone_path(fx["state_dir"], fx["a"]).is_file()
    # Resume converges with a clean postcheck.
    monkeypatch.undo()
    report = _teardown_a(fx)
    assert report.already_torn_down is True
    assert report.postcheck_hits == []
    conn.close()


def test_crash_during_key_destruction_retries(tmp_path, monkeypatch):
    """Kill during step 3's key destruction: the retry recaptures the key
    rows (already-wiped files count as done) and converges."""
    fx = _two_rel_state(tmp_path)
    real_delete = td_mod.delete_private_key
    calls = []

    def crash_once(ref):
        calls.append(1)
        if len(calls) == 1:
            raise FaultInjected("crash during key destruction")
        return real_delete(ref)

    monkeypatch.setattr(td_mod, "delete_private_key", crash_once)
    with pytest.raises(FaultInjected):
        _teardown_a(fx)
    conn = fx["conn"]
    # Nothing committed: the relationship row is still there and no
    # tombstone was written.
    assert _count(conn, "relationships", "relationship_id = ?", (fx["a"],)) == 1
    assert not td_mod._tombstone_path(fx["state_dir"], fx["a"]).is_file()
    # Retry converges; every key file is attested destroyed.
    monkeypatch.undo()
    report = _teardown_a(fx)
    assert report.postcheck_hits == []
    assert len(report.keys_destroyed) == 1
    assert _count(conn, "relationships", "relationship_id = ?", (fx["a"],)) == 0
    conn.close()


def test_crash_during_postcheck_resumes_clean(tmp_path, monkeypatch):
    """Kill during the postcheck scan: the resume path re-wipes (a no-op)
    and re-scans clean instead of wedging on the tombstone."""
    fx = _two_rel_state(tmp_path)
    real_scan = td_mod.postcheck_scan
    calls = []

    def crash_once(state_dir, relationship_id, peer_label=None, key_refs=()):
        calls.append(1)
        if len(calls) == 1:
            raise FaultInjected("crash during postcheck")
        return real_scan(state_dir, relationship_id, peer_label, key_refs)

    monkeypatch.setattr(td_mod, "postcheck_scan", crash_once)
    with pytest.raises(FaultInjected):
        _teardown_a(fx)
    # Resume: the wipe is a no-op, the scan runs clean.
    monkeypatch.undo()
    report = _teardown_a(fx)
    assert report.already_torn_down is True
    assert report.postcheck_hits == []
    assert report.postcheck_scanned > 0
    fx["conn"].close()


def _add_third_relationship(fx):
    """Add a third relationship C on the shared relay, so that after A is
    torn down two relationships remain (single_relationship is False)."""
    import json
    import os
    import uuid

    from muse_agent_social.store.db import utcnow

    conn, state_dir, keys_dir = fx["conn"], fx["state_dir"], fx["keys_dir"]
    c = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO relationships (relationship_id, peer_identity_id,"
        " peer_display_name, peer_agreement_key, consent_state, policy,"
        " key_epoch, created_at)"
        " VALUES (?, 'did:key:zpeer', 'peer-c', 'agree', 'active', '{}', 1, ?)",
        (c, utcnow()),
    )
    pub = f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{'A' * 40}c fake-c"
    conn.execute(
        "INSERT INTO deploy_key_registry (deploy_public_key,"
        " relationship_id, registered_at) VALUES (?, ?, ?)",
        (pub, c, utcnow()),
    )
    conn.execute(
        "INSERT INTO relay_config (relationship_id, provider, repo_url,"
        " created_at) VALUES (?, 'github',"
        " 'https://github.com/org/shared-relay.git', ?)",
        (c, utcnow()),
    )
    key_path = keys_dir / c / "epoch1.key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(os.urandom(32))
    os.chmod(key_path, 0o600)
    conn.execute(
        "INSERT INTO key_epochs (relationship_id, epoch, public_key,"
        " private_key_ref, state) VALUES (?, 1, ?, ?, 'active')",
        (c, "pub-c", str(key_path)),
    )
    cfg_path = state_dir / "relay.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["deploy_keys"].append(
        {"id": "key-c", "title": f"mas-pair-{c}", "key": pub}
    )
    cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    conn.commit()
    return c


def test_crash_after_commit_resumes_with_journal_refs(tmp_path, monkeypatch):
    """D9: crash after the DB commit but before the file wipe, with A on a
    dedicated relay repo and two other relationships surviving. The resume
    must prune A's relay.json entries from the journal's ownership
    picture: re-discovering after the relay_config rows are gone would see
    A's repo as unclaimed while other relationships exist and keep its
    entry forever."""
    import json

    fx = _two_rel_state(tmp_path)
    c = _add_third_relationship(fx)
    conn = fx["conn"]
    # Move A to a dedicated repo.
    conn.execute(
        "UPDATE relay_config SET repo_url="
        "'https://github.com/org/a-relay.git' WHERE relationship_id=?",
        (fx["a"],),
    )
    cfg_path = fx["state_dir"] / "relay.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["repos"] = ["org/a-relay", "org/shared-relay"]
    cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    conn.commit()

    hooks = FakeHooks()
    real_wipe = td_mod._wipe_relationship_files
    calls = []

    def crash_once(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise FaultInjected("crash after DB commit, before file wipe")
        return real_wipe(*args, **kwargs)

    monkeypatch.setattr(td_mod, "_wipe_relationship_files", crash_once)
    with pytest.raises(FaultInjected):
        _teardown_a(fx, hooks)
    # The DB work committed: the relationship row and its relay_config
    # row are gone, but the tombstone and journal survive.
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM relationships WHERE relationship_id=?",
            (fx["a"],),
        ).fetchone()[0]
        == 0
    )
    assert td_mod._tombstone_path(fx["state_dir"], fx["a"]).is_file()
    journal = td_mod._teardown_journal_path(fx["state_dir"], fx["a"])
    assert journal.is_file()
    # The first run revoked A's key and deleted A's repo via the hooks.
    assert hooks.revoked == [(f"org/a-relay", f"mas-pair-{fx['a']}")]
    assert hooks.deleted_repos == ["org/a-relay"]

    # Resume: hooks are not repeated (durable log), and the file wipe
    # prunes A's relay.json entries from the journal's refs.
    monkeypatch.undo()
    report = _teardown_a(fx, hooks)
    assert report.already_torn_down is True
    assert hooks.revoked == [(f"org/a-relay", f"mas-pair-{fx['a']}")]
    assert hooks.deleted_repos == ["org/a-relay"]
    pruned = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert [k["title"] for k in pruned["deploy_keys"]] == [
        f"mas-pair-{fx['b']}",
        f"mas-pair-{c}",
    ]
    assert pruned["repos"] == ["org/shared-relay"]
    assert report.postcheck_hits == []
    # The journal is gone after success; the tombstone remains.
    assert not journal.exists()
    assert td_mod._tombstone_path(fx["state_dir"], fx["a"]).is_file()
    conn.close()
