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


def run_receive_phase(db_path, relay_dir, keys_dir, manifest_path, phase,
                      block_at, marker_path, progress_path):
    """Receive, but block inside a chosen pipeline phase so the parent can
    deliver a real SIGKILL at that exact point.

    ``phase`` is one of:

    * ``fetch``: block after the relay listing, before reading the object
      bytes of object index ``block_at`` (0-based).
    * ``commit``: block inside the commit transaction, right after the
      ``events`` insert (via the harness ``during_commit_after_events``
      hook point), on the ``block_at``-th accepted object (1-based).
    * ``projection``: block inside ``apply_event`` (projection runs inside
      the commit transaction), on the ``block_at``-th call (1-based).
    * ``write_txn``: block inside the commit transaction after the
      projection writes (via ``during_commit_after_project``), on the
      ``block_at``-th accepted object (1-based). The write transaction
      is open with uncommitted pages when the kill lands.

    Blocking writes ``phase`` to ``marker_path`` first so the parent
    knows the worker is parked inside the phase. The ``.go`` escape is
    a backstop so a missed kill fails the test instead of hanging it.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )
    from support import harness as harness_mod
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
    state = {"commits": 0, "projections": 0}

    def mark_and_block():
        with open(marker_path, "w") as fh:
            fh.write(phase)
            fh.flush()
            os.fsync(fh.fileno())
        deadline = time.time() + 120
        go_path = marker_path + ".go"
        while time.time() < deadline:
            if os.path.exists(go_path):
                return
            time.sleep(0.05)
        print("BLOCK_TIMEOUT phase=%s" % phase, flush=True)
        os._exit(3)

    if phase in ("commit", "write_txn"):
        point = ("during_commit_after_events" if phase == "commit"
                 else "during_commit_after_project")
        orig_fault = harness._maybe_fault

        def hooked_fault(fault_point):
            # harness.fault_at stays None, so this never raises; it only
            # parks the worker inside the commit transaction.
            if fault_point == point:
                state["commits"] += 1
                if state["commits"] == block_at:
                    mark_and_block()
            return orig_fault(fault_point)

        harness._maybe_fault = hooked_fault
    elif phase == "projection":
        orig_apply = harness_mod.apply_event

        def hooked_apply(proj_conn, event_row):
            state["projections"] += 1
            if state["projections"] == block_at:
                mark_and_block()
            return orig_apply(proj_conn, event_row)

        harness_mod.apply_event = hooked_apply

    incoming = os.path.join(relay_dir, "incoming")
    done = 0
    for name in sorted(os.listdir(incoming)):
        if not name.endswith(".json"):
            continue
        if phase == "fetch" and done == block_at:
            # Parked after the relay listing, before the object bytes are
            # read: squarely inside the fetch phase.
            mark_and_block()
        with open(os.path.join(incoming, name), "rb") as fh:
            data = fh.read()
        harness.receive_object(name, data)
        done += 1
        with open(progress_path, "w") as fh:
            fh.write(str(done))
    conn.close()
    print("RECEIVE_DONE done=%d" % done, flush=True)


mode = sys.argv[1]
if mode == "setup":
    run_setup(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
              int(sys.argv[6]))
elif mode == "receive":
    run_receive(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
                int(sys.argv[6]), sys.argv[7])
elif mode == "receive_phase":
    run_receive_phase(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
                      sys.argv[6], int(sys.argv[7]), sys.argv[8],
                      sys.argv[9])
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


# -- phase-synchronized SIGKILL -------------------------------------------
#
# The tests above pace the worker and hope the kill lands mid-write. The
# tests below park the worker *inside* a named pipeline phase (fetch,
# commit, projection, open write transaction) and only then deliver
# SIGKILL, so the kill point is exact rather than probabilistic.


def _start_receive_phase(worker, phase, block_at, marker_path, progress_path):
    return subprocess.Popen(
        [sys.executable, worker["script"], "receive_phase", worker["db"],
         worker["relay"], worker["keys"], worker["manifest"], phase,
         str(block_at), marker_path, progress_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def _wait_for_marker(marker_path, phase, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(marker_path) as fh:
                if fh.read().strip() == phase:
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.02)
    raise TimeoutError("worker never parked in phase %s" % phase)


def _kill_parked_worker(proc):
    _sigkill(proc)
    proc.stdout.close()
    proc.stderr.close()


def _restart_to_completion(worker, manifest):
    progress = os.path.join(
        os.path.dirname(worker["db"]), "progress-restart.txt")
    proc = _start_receive(worker, 0, progress)
    try:
        stdout, _ = proc.communicate(timeout=180)
    finally:
        proc.stdout.close()
        proc.stderr.close()
    assert proc.returncode == 0, "restart run failed"
    assert "RECEIVE_DONE" in stdout
    _verify_exactly_once(worker, manifest)


def _verify_projections_exactly_once(worker, manifest):
    """No duplicate or partial projections, no lost queued work, no
    double surface after a crash-restart."""
    from muse_agent_social.store import db as db_mod

    conn = db_mod.connect(worker["db"])
    try:
        messages = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        assert messages == N_ENVELOPES, messages
        dupes = conn.execute(
            "SELECT event_id, COUNT(*) c FROM messages "
            "GROUP BY event_id HAVING c > 1"
        ).fetchall()
        assert dupes == []
        assert conn.execute(
            "SELECT COUNT(*) FROM surface_queue").fetchone()[0] == 0
        surfaced = conn.execute(
            "SELECT COUNT(DISTINCT event_id) FROM surface_log").fetchone()[0]
        assert surfaced == N_ENVELOPES, surfaced
        receipts = conn.execute(
            "SELECT COUNT(*) FROM receipt_queue").fetchone()[0]
        assert receipts == N_ENVELOPES, receipts
    finally:
        conn.close()


def test_sigkill_during_fetch_phase(worker):
    """SIGKILL while the worker is parked between the relay listing and
    the object read: the unread object is never consumed, and the
    restart converges to exactly-once."""
    manifest = _run_setup(worker)
    base = os.path.dirname(worker["db"])
    marker = os.path.join(base, "marker.txt")
    progress = os.path.join(base, "progress-fetch.txt")
    proc = _start_receive_phase(worker, "fetch", 3, marker, progress)
    try:
        _wait_for_marker(marker, "fetch")
        _kill_parked_worker(proc)
    except BaseException:
        proc.stdout.close()
        proc.stderr.close()
        raise
    assert _integrity_ok(worker["db"])
    # The parked object was never read, so it must still be waiting.
    leftovers = sorted(
        n for n in os.listdir(os.path.join(worker["relay"], "incoming"))
        if n.endswith(".json"))
    assert len(leftovers) == N_ENVELOPES - 3, leftovers
    _restart_to_completion(worker, manifest)
    _verify_projections_exactly_once(worker, manifest)


def test_sigkill_during_commit_phase(worker):
    """SIGKILL parked inside the commit transaction, right after the
    ``events`` insert: the open transaction rolls back, the restart
    reprocesses the object, and the event lands exactly once."""
    manifest = _run_setup(worker)
    base = os.path.dirname(worker["db"])
    marker = os.path.join(base, "marker.txt")
    progress = os.path.join(base, "progress-commit.txt")
    proc = _start_receive_phase(worker, "commit", 5, marker, progress)
    try:
        _wait_for_marker(marker, "commit")
        _kill_parked_worker(proc)
    except BaseException:
        proc.stdout.close()
        proc.stderr.close()
        raise
    assert _integrity_ok(worker["db"])
    _restart_to_completion(worker, manifest)
    _verify_projections_exactly_once(worker, manifest)


def test_sigkill_during_projection_phase(worker):
    """SIGKILL parked inside ``apply_event`` (projection runs inside the
    commit transaction): no partial projection survives, and the restart
    projects every event exactly once."""
    manifest = _run_setup(worker)
    base = os.path.dirname(worker["db"])
    marker = os.path.join(base, "marker.txt")
    progress = os.path.join(base, "progress-projection.txt")
    proc = _start_receive_phase(worker, "projection", 5, marker, progress)
    try:
        _wait_for_marker(marker, "projection")
        _kill_parked_worker(proc)
    except BaseException:
        proc.stdout.close()
        proc.stderr.close()
        raise
    assert _integrity_ok(worker["db"])
    _restart_to_completion(worker, manifest)
    _verify_projections_exactly_once(worker, manifest)


def test_sigkill_during_write_transaction_wal_recovery(worker):
    """SIGKILL with a write transaction open and uncommitted pages in the
    WAL: the next open recovers cleanly (integrity_check ok), the
    in-flight event is absent (rolled back, not half-written), and the
    restart converges to exactly-once."""
    from muse_agent_social.store import db as db_mod

    manifest = _run_setup(worker)
    base = os.path.dirname(worker["db"])
    marker = os.path.join(base, "marker.txt")
    progress = os.path.join(base, "progress-writetxn.txt")
    proc = _start_receive_phase(worker, "write_txn", 5, marker, progress)
    try:
        _wait_for_marker(marker, "write_txn")
        _kill_parked_worker(proc)
    except BaseException:
        proc.stdout.close()
        proc.stderr.close()
        raise
    # Recovery proof before any restart run touches the database.
    assert _integrity_ok(worker["db"])
    conn = db_mod.connect(worker["db"])
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal", mode
        # Four objects fully committed; the fifth died with its write
        # transaction open and must be entirely absent, not partial.
        committed = conn.execute(
            "SELECT COUNT(*) FROM events").fetchone()[0]
        assert committed == 4, committed
        guard = conn.execute(
            "SELECT COUNT(*) FROM replay_guard").fetchone()[0]
        assert guard == 4, guard
    finally:
        conn.close()
    _restart_to_completion(worker, manifest)
    _verify_projections_exactly_once(worker, manifest)
