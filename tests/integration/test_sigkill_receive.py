"""Gate: real SIGKILL crash tests through actual subprocesses.

A worker subprocess performs the real receive loop over a local relay
directory. The parent kills it with SIGKILL at a chosen point, then a
fresh worker run completes the receive. The tests prove:

- exactly-once terminal state: every sealed event appears exactly once
  in ``events`` (kill during fetch, kill during commit),
- the database survives a kill mid-write: ``PRAGMA integrity_check``
  passes on reopen (WAL/journal recovery) before the restart run.

No in-process fault injection is used anywhere here.
"""

import json
import os
import signal
import sqlite3
import subprocess
import sys
import time

import pytest

N_ENVELOPES = 40

WORKER = r'''
import json
import os
import sys
import time

sys.path.insert(0, "@@SRC@@")
sys.path.insert(0, "@@TESTS@@")


def run_setup(db_path, relay_dir, keys_dir, manifest_path, n):
    from support.harness import (
        fresh_db,
        make_agent,
        make_sealed,
        new_conversation,
        provision_receive_side,
    )
    from muse_agent_social.transports.local import LocalTransport

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(db_path)
    rid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    provision_receive_side(conn, rid, bob, alice, keys_dir=keys_dir)
    conv = new_conversation(conn)
    transport = LocalTransport(relay_dir)
    event_ids = []
    for i in range(1, n + 1):
        envelope, raw = make_sealed(
            alice, bob, rid, conv, "message.created",
            {"body": "crash test message %d" % i, "format": "plain"},
            seq=i,
        )
        event_ids.append(envelope["protected"]["event_id"])
        transport.upload("env%029d.json" % i, raw)
    conn.close()
    with open(manifest_path, "w") as fh:
        json.dump(
            {
                "relationship_id": rid,
                "conversation_id": conv,
                "own_identity_id": bob["identity_id"],
                "event_ids": event_ids,
            },
            fh,
        )
    print("SETUP_DONE", flush=True)


def run_receive(db_path, relay_dir, keys_dir, manifest_path, delay_ms,
                progress_path):
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )
    from support.harness import ReceiveHarness
    from muse_agent_social.store import db as db_mod
    from muse_agent_social.transports.local import LocalTransport

    with open(manifest_path) as fh:
        manifest = json.load(fh)
    rid = manifest["relationship_id"]
    key_path = os.path.join(keys_dir, "%s-e1.key" % rid)
    with open(key_path, "rb") as fh:
        rel_priv = X25519PrivateKey.from_private_bytes(fh.read())
    conn = db_mod.connect(db_path)
    transport = LocalTransport(relay_dir)
    harness = ReceiveHarness(
        conn,
        relationship_id=rid,
        own_identity_id=manifest["own_identity_id"],
        own_rel_priv=rel_priv,
        transport=transport,
    )
    incoming = os.path.join(relay_dir, "incoming")
    done = 0
    for name in sorted(os.listdir(incoming)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(incoming, name), "rb") as fh:
            data = fh.read()
        harness.receive_object(name, data)
        done += 1
        with open(progress_path, "w") as fh:
            fh.write(str(done))
        if delay_ms:
            time.sleep(delay_ms / 1000.0)
    conn.close()
    print("RECEIVE_DONE done=%d" % done, flush=True)


mode = sys.argv[1]
if mode == "setup":
    run_setup(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
              int(sys.argv[6]))
elif mode == "receive":
    run_receive(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
                int(sys.argv[6]), sys.argv[7])
'''


@pytest.fixture()
def worker(tmp_path):
    """Write the worker script and return its path plus shared dirs."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # tests/integration -> repo root; src and tests live under the repo.
    root = os.path.dirname(repo)
    script = (
        WORKER.replace("@@SRC@@", os.path.join(root, "src"))
        .replace("@@TESTS@@", os.path.join(root, "tests"))
    )
    path = tmp_path / "receive_worker.py"
    path.write_text(script)
    return {
        "script": str(path),
        "db": str(tmp_path / "state.db"),
        "relay": str(tmp_path / "relay"),
        "keys": str(tmp_path / "keys"),
        "manifest": str(tmp_path / "manifest.json"),
    }


def _run_setup(worker):
    proc = subprocess.run(
        [sys.executable, worker["script"], "setup", worker["db"],
         worker["relay"], worker["keys"], worker["manifest"],
         str(N_ENVELOPES)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "SETUP_DONE" in proc.stdout
    with open(worker["manifest"]) as fh:
        return json.load(fh)


def _start_receive(worker, delay_ms, progress_path):
    return subprocess.Popen(
        [sys.executable, worker["script"], "receive", worker["db"],
         worker["relay"], worker["keys"], worker["manifest"],
         str(delay_ms), progress_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def _wait_for_progress(progress_path, target, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(progress_path) as fh:
                if int(fh.read().strip() or "0") >= target:
                    return
        except (FileNotFoundError, ValueError):
            pass
        time.sleep(0.02)
    raise TimeoutError("worker never reached progress %d" % target)


def _sigkill(proc):
    os.kill(proc.pid, signal.SIGKILL)
    _, status = os.waitpid(proc.pid, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL


def _integrity_ok(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def _verify_exactly_once(worker, manifest):
    from muse_agent_social.store import db as db_mod

    conn = db_mod.connect(worker["db"])
    try:
        events = conn.execute("SELECT event_id FROM events").fetchall()
        assert len(events) == N_ENVELOPES
        assert sorted(r[0] for r in events) == sorted(manifest["event_ids"])
        dupes = conn.execute(
            "SELECT event_id, COUNT(*) c FROM events "
            "GROUP BY event_id HAVING c > 1"
        ).fetchall()
        assert dupes == []
        assert conn.execute("SELECT COUNT(*) FROM replay_guard").fetchone()[0] \
            == N_ENVELOPES
        leftovers = [
            n for n in os.listdir(os.path.join(worker["relay"], "incoming"))
            if n.endswith(".json")
        ]
        assert leftovers == []
    finally:
        conn.close()


def _crash_and_recover(worker, manifest, delay_ms, kill_at):
    """Kill a receiving worker at ``kill_at`` objects, restart to
    completion, and prove exactly-once terminal state."""
    progress = os.path.join(os.path.dirname(worker["db"]), "progress.txt")
    proc = _start_receive(worker, delay_ms, progress)
    try:
        _wait_for_progress(progress, kill_at)
        _sigkill(proc)
    finally:
        proc.stdout.close()
        proc.stderr.close()
    # WAL/journal recovery must hold before the restart even runs.
    assert _integrity_ok(worker["db"])
    proc2 = _start_receive(worker, 0, progress + ".2")
    try:
        stdout, _ = proc2.communicate(timeout=120)
    finally:
        proc2.stdout.close()
        proc2.stderr.close()
    assert proc2.returncode == 0
    assert "RECEIVE_DONE" in stdout
    _verify_exactly_once(worker, manifest)


def test_sigkill_during_fetch(worker):
    """SIGKILL between objects (fetch phase): restart proves exactly-once."""
    manifest = _run_setup(worker)
    _crash_and_recover(worker, manifest, delay_ms=30, kill_at=3)


def test_sigkill_during_commit(worker):
    """SIGKILL with no pacing (inside write transactions): restart proves
    exactly-once."""
    manifest = _run_setup(worker)
    _crash_and_recover(worker, manifest, delay_ms=0, kill_at=20)


def test_sigkill_wal_recovery_before_restart(worker):
    """A kill mid-write leaves the database recoverable: integrity_check
    passes on the next open, before any restart run touches it."""
    manifest = _run_setup(worker)
    progress = os.path.join(os.path.dirname(worker["db"]), "progress.txt")
    proc = _start_receive(worker, 0, progress)
    try:
        _wait_for_progress(progress, 25)
        _sigkill(proc)
    finally:
        proc.stdout.close()
        proc.stderr.close()
    assert _integrity_ok(worker["db"])
    # And the restart still converges to exactly-once.
    proc2 = _start_receive(worker, 0, progress + ".2")
    try:
        stdout, _ = proc2.communicate(timeout=120)
    finally:
        proc2.stdout.close()
        proc2.stderr.close()
    assert proc2.returncode == 0
    _verify_exactly_once(worker, manifest)
