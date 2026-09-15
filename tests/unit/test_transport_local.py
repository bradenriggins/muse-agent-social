"""Unit tests for transports: local adapter and git adapter.

All git tests run against local bare repositories; no network is used.
"""

import os
import re
import subprocess
import threading

import pytest

from muse_agent_social.store.db import open_db
from muse_agent_social.transports import github as gh
from muse_agent_social.transports.base import (
    OBJECT_MAX_BYTES,
    TransportError,
    mirror_lock,
)
from muse_agent_social.transports.github import (
    GitHubTransport,
    GitRunner,
    RotationRequired,
    check_repo_size,
    count_queued,
    mark_mutations_done,
    new_object_name,
    queue_mutation,
    replay_queued,
)
from muse_agent_social.transports.local import LocalTransport

NOOP_SLEEP = lambda s: None  # noqa: E731


def _git(*args, cwd):
    cp = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, timeout=60
    )
    assert cp.returncode == 0, cp.stderr.decode()
    return cp


def _init_bare(path):
    subprocess.run(
        ["git", "init", "--bare", "-q", str(path)],
        check=True, capture_output=True, timeout=60,
    )
    return str(path)


# ---------------------------------------------------------------------------
# LocalTransport
# ---------------------------------------------------------------------------
class TestLocalTransport:
    def test_round_trip(self, tmp_path):
        t = LocalTransport(tmp_path / "relay")
        name = "A" * 32 + ".json"
        t.upload(name, b'{"sealed": true}')
        assert t.changed("")
        assert t.head() != ""
        items = dict(t.fetch_new(""))
        assert items[name] == b'{"sealed": true}'
        head = t.head()
        assert not t.changed(head)
        assert t.fetch_new(head) == []
        t.consume(name)
        assert dict(t.fetch_new("")) == {}
        assert (t.consumed / name).read_bytes() == b'{"sealed": true}'

    def test_consume_idempotent(self, tmp_path):
        t = LocalTransport(tmp_path / "relay")
        t.consume("B" * 32 + ".json")  # missing -> success

    def test_upload_rejects_oversize(self, tmp_path):
        t = LocalTransport(tmp_path / "relay")
        with pytest.raises(TransportError) as ei:
            t.upload("C" * 32 + ".json", b"x" * (OBJECT_MAX_BYTES + 1))
        assert ei.value.code == "object_too_large"

    def test_upload_rejects_bad_name(self, tmp_path):
        t = LocalTransport(tmp_path / "relay")
        with pytest.raises(TransportError):
            t.upload("../evil.json", b"x")
        with pytest.raises(TransportError):
            t.upload("short.json", b"x")

    def test_quarantine_helper(self, tmp_path):
        t = LocalTransport(tmp_path / "relay")
        name = "D" * 32 + ".json"
        t.upload(name, b"junk")
        t.quarantine(name, b"junk")
        assert (t.quarantine_dir / name).read_bytes() == b"junk"
        assert dict(t.fetch_new("")) == {}


class TestConcurrentBidirectional:
    """Two transports on one shared relay, interleaved uploads from threads.

    No object may be lost or duplicated.
    """

    def test_no_lost_object(self, tmp_path):
        relay = tmp_path / "relay"
        producers = [LocalTransport(relay) for _ in range(4)]
        per_thread, received, lock = 25, {}, threading.Lock()
        barrier = threading.Barrier(5)

        def produce(idx):
            t = producers[idx]
            barrier.wait()
            for n in range(per_thread):
                name = f"{idx:02d}{n:02d}" + "E" * 28 + ".json"
                t.upload(name, f"payload-{idx}-{n}".encode())

        threads = [threading.Thread(target=produce, args=(i,)) for i in range(4)]
        for th in threads:
            th.start()
        consumer = LocalTransport(relay)
        barrier.wait()
        # Drain until all 100 objects are consumed exactly once.
        deadline = __import__("time").monotonic() + 30
        while len(received) < 100 and __import__("time").monotonic() < deadline:
            for name, data in consumer.fetch_new(""):
                with lock:
                    assert name not in received, f"duplicate {name}"
                    received[name] = data
                consumer.consume(name)
        for th in threads:
            th.join()
        assert len(received) == 100
        assert {v.decode() for v in received.values()} == {
            f"payload-{i}-{n}" for i in range(4) for n in range(25)
        }
        assert dict(consumer.fetch_new("")) == {}


# ---------------------------------------------------------------------------
# GitHubTransport against local bare repos
# ---------------------------------------------------------------------------
@pytest.fixture()
def bare_repo(tmp_path):
    return _init_bare(tmp_path / "relay.git")


@pytest.fixture()
def transport_factory(tmp_path, bare_repo):
    made = []

    def make(rel="rel1"):
        state = tmp_path / f"state-{rel}-{len(made)}"
        t = GitHubTransport(state, rel, bare_repo, sleeper=NOOP_SLEEP)
        made.append(t)
        return t

    yield make
    for t in made:
        t.close()


def _peer_push(bare_repo, workdir, name, data):
    """Simulate the peer pushing an object directly to the relay."""
    workdir.mkdir(parents=True, exist_ok=True)
    _git("clone", "-q", bare_repo, ".", cwd=workdir)
    cp = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "origin/main"],
        cwd=str(workdir), capture_output=True, timeout=60,
    )
    if cp.returncode == 0:
        _git("checkout", "-q", "-B", "main", "origin/main", cwd=workdir)
    else:
        _git("checkout", "-q", "-B", "main", cwd=workdir)
    (workdir / "incoming").mkdir(exist_ok=True)
    (workdir / "incoming" / name).write_bytes(data)
    _git("-c", "user.name=peer", "-c", "user.email=peer@x",
         "add", "-A", cwd=workdir)
    _git("-c", "user.name=peer", "-c", "user.email=peer@x",
         "commit", "-q", "-m", "peer object", cwd=workdir)
    _git("push", "-q", "origin", "main", cwd=workdir)


class TestGitHubTransport:
    def test_round_trip(self, transport_factory, tmp_path):
        t = transport_factory()
        assert t.head() == ""  # empty relay
        name = new_object_name()
        t.upload(name, b"sealed-bytes")
        assert t.pending_outgoing() == 1
        result = t.flush()
        assert result["status"] == "pushed"
        assert result["mutations"] == 1
        assert t.pending_outgoing() == 0
        assert t.changed("")  # remote moved

        t2 = transport_factory("rel1")
        items = dict(t2.fetch_new(""))
        assert items[name] == b"sealed-bytes"
        t2.consume(name)
        r2 = t2.flush()
        assert r2["status"] == "pushed"
        assert dict(t2.fetch_new(t2.head())) == {}

    def test_commit_batches_mutations(self, transport_factory, tmp_path):
        t = transport_factory()
        t.upload(new_object_name(), b"one")
        t.upload(new_object_name(), b"two")
        result = t.flush()
        assert result["status"] == "pushed"
        assert result["mutations"] == 2
        cp = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=str(t.mirror_path), capture_output=True, timeout=60,
        )
        assert cp.stdout.decode().strip() == "1"  # exactly one commit

    def test_push_conflict_drill(self, transport_factory, tmp_path, bare_repo):
        """Real non-fast-forward: a racing peer commit lands mid-push.

        The transport must refetch, abort any rebase, reset hard, replay the
        queued mutation, and succeed on retry with nothing lost.
        """
        t = transport_factory()
        first = new_object_name()
        t.upload(first, b"first")
        assert t.flush()["status"] == "pushed"

        peer_name = new_object_name()
        _peer_push(bare_repo, tmp_path / "peer1", peer_name, b"peer-data")

        third = new_object_name()
        t.upload(third, b"third")

        raced = new_object_name()
        hook_calls = []

        def race_once():
            if not hook_calls:
                hook_calls.append(1)
                _peer_push(bare_repo, tmp_path / "peer2", raced, b"race-data")

        t._pre_push_hook = race_once
        # Simulate >60s passing so the soft 1-push/min limit does not defer.
        t._db().execute(
            "DELETE FROM transport_push_log WHERE relationship_id = 'rel1'")
        result = t.flush()
        assert result["status"] == "pushed", result
        assert hook_calls == [1]
        assert t.pending_outgoing() == 0

        # Every object from every side is present exactly once.
        t2 = transport_factory("rel1")
        items = dict(t2.fetch_new(""))
        assert set(items) == {first, peer_name, third, raced}
        assert items[first] == b"first"
        assert items[peer_name] == b"peer-data"
        assert items[third] == b"third"
        assert items[raced] == b"race-data"

    def test_push_conflict_exhaustion_preserves_queue(
        self, transport_factory, tmp_path, bare_repo
    ):
        """Stubbed runner: push always non-fast-forward -> exit 20, queue kept."""

        class AlwaysConflictRunner(GitRunner):
            def __init__(self):
                super().__init__()
                self.pushes = 0

            def run(self, args, cwd, timeout):
                if args and args[0] == "push":
                    self.pushes += 1
                    return subprocess.CompletedProcess(
                        args, 1, b"",
                        b" ! [rejected] main -> main (non-fast-forward)\n",
                    )
                return super().run(args, cwd, timeout)

        state = tmp_path / "state-conflict"
        runner = AlwaysConflictRunner()
        t = GitHubTransport(state, "rel1", bare_repo, runner=runner,
                            sleeper=NOOP_SLEEP)
        try:
            t.upload(new_object_name(), b"doomed")
            with pytest.raises(TransportError) as ei:
                t.flush()
            # Final attempt still non-fast-forward: specific code, retryable,
            # watcher exit 20, queue preserved.
            assert ei.value.code == "push_non_fast_forward"
            assert ei.value.retryable is True
            assert ei.value.exit_code == 20
            assert runner.pushes == 3  # max attempts, then give up
            assert t.pending_outgoing() == 1  # queue preserved
        finally:
            t.close()

    def test_push_rate_soft_limit_defers(self, transport_factory):
        t = transport_factory()
        t.upload(new_object_name(), b"a")
        assert t.flush()["status"] == "pushed"
        t.upload(new_object_name(), b"b")
        result = t.flush()
        assert result["status"] == "deferred"
        assert result["reason"] == "push_soft_interval"
        assert t.pending_outgoing() == 1

    def test_push_hard_ceiling(self, transport_factory):
        t = transport_factory()
        conn = t._db()
        now = __import__("time").time()
        for i in range(6):
            conn.execute(
                "INSERT INTO transport_push_log (relationship_id, pushed_at)"
                " VALUES (?, ?)",
                ("rel1", now - i),
            )
        t.upload(new_object_name(), b"a")
        with pytest.raises(TransportError) as ei:
            t.flush()
        assert ei.value.code == "push_rate_limited"
        assert ei.value.exit_code == 20

    def test_new_object_name_format(self):
        for _ in range(50):
            name = new_object_name()
            assert re.fullmatch(r"[A-Za-z0-9_-]{32}\.json", name), name

    def test_upload_rejects_oversize(self, transport_factory):
        t = transport_factory()
        with pytest.raises(TransportError) as ei:
            t.upload(new_object_name(), b"x" * (OBJECT_MAX_BYTES + 1))
        assert ei.value.code == "object_too_large"
        assert t.pending_outgoing() == 0

    def test_mirror_origin_mismatch_is_config_error(self, transport_factory,
                                                   tmp_path, bare_repo):
        other = _init_bare(tmp_path / "other.git")
        t = transport_factory()
        t.upload(new_object_name(), b"x")
        assert t.flush()["status"] == "pushed"
        # Point a new transport at a different repo but reuse the state dir.
        t2 = GitHubTransport(t.state_dir, "rel1", other, sleeper=NOOP_SLEEP)
        try:
            with pytest.raises(TransportError) as ei:
                t2.flush()
            assert ei.value.code == "config_error"
            assert ei.value.exit_code == 21
        finally:
            t2.close()


class TestQueuedMutations:
    def test_queue_and_replay(self, tmp_path):
        conn = open_db(tmp_path / "state")
        try:
            name = new_object_name()
            mid = queue_mutation(conn, "rel1", "upload", name, b"data")
            assert isinstance(mid, str) and mid
            assert count_queued(conn, "rel1") == 1
            applied = replay_queued(conn, "rel1", tmp_path / "work")
            assert len(applied) == 1
            assert (tmp_path / "work" / "incoming" / name).read_bytes() == b"data"
            # Not done until marked: replay again is harmless (overwrite).
            assert count_queued(conn, "rel1") == 1
            mark_mutations_done(conn, applied)
            assert count_queued(conn, "rel1") == 0
        finally:
            conn.close()

    def test_consume_replay_idempotent(self, tmp_path):
        conn = open_db(tmp_path / "state")
        try:
            name = new_object_name()
            queue_mutation(conn, "rel1", "consume", name)
            applied = replay_queued(conn, "rel1", tmp_path / "work")
            assert applied  # no error for missing file
        finally:
            conn.close()

    def test_mutation_id_unique(self, tmp_path):
        conn = open_db(tmp_path / "state")
        try:
            ids = {
                queue_mutation(conn, "r", "upload", new_object_name(), b"x")
                for _ in range(20)
            }
            assert len(ids) == 20
        finally:
            conn.close()


class TestSizeAlarms:
    def test_warn(self):
        assert check_repo_size(100 * 1024 * 1024, True) == "warn"
        assert check_repo_size(99 * 1024 * 1024, True) is None

    def test_block_new_objects(self):
        with pytest.raises(TransportError) as ei:
            check_repo_size(250 * 1024 * 1024, True)
        assert ei.value.code == "repo_size_blocked"
        assert ei.value.exit_code == 21
        # Consume-only pushes still allowed past 250 MiB.
        assert check_repo_size(300 * 1024 * 1024, False) == "warn"

    def test_rotation_required(self):
        with pytest.raises(RotationRequired):
            check_repo_size(500 * 1024 * 1024, False)
        with pytest.raises(RotationRequired):
            check_repo_size(600 * 1024 * 1024, True)


class TestMirrorLock:
    def test_reentrant_same_thread(self, tmp_path):
        with mirror_lock(tmp_path, "rel1", timeout=1):
            with mirror_lock(tmp_path, "rel1", timeout=1):
                pass

    def test_timeout_zero_raises_when_busy(self, tmp_path):
        with mirror_lock(tmp_path, "rel1", timeout=5):
            def try_lock(results):
                try:
                    with mirror_lock(tmp_path, "rel1", timeout=0):
                        results.append("acquired")
                except TransportError as exc:
                    results.append(exc.code)

            results = []
            th = threading.Thread(target=try_lock, args=(results,))
            th.start()
            th.join()
            assert results == ["lock_timeout"]
