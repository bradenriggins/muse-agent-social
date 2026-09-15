"""Gate: concurrent send through the real transports.

- Local transport: two threads seal and upload concurrently (barrier
  synchronized) into one relay directory; a single receive pass must
  commit every event exactly once (no lost objects).
- Git transport: two separate state directories (separate clones) push
  to one local bare repository concurrently; both flushes must succeed,
  all objects must be fetchable, and neither mirror may wedge (a
  follow-up upload+flush from each still works).
"""

import os
import subprocess
import threading

import pytest

from muse_agent_social.transports.base import TransportError
from muse_agent_social.transports.github import GitHubTransport
from muse_agent_social.transports.local import LocalTransport

from support.harness import (
    ReceiveHarness,
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)

N_PER_SENDER = 25


def _oname(tag: str, i: int) -> str:
    stem = "%s%06d" % (tag, i)
    return (stem + "0" * 32)[:32] + ".json"


@pytest.fixture()
def pair(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "cccccccc-dddd-4eee-8fff-000000000000"
    provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    relay = tmp_path / "relay"
    harness = ReceiveHarness(
        conn,
        relationship_id=rid,
        own_identity_id=bob["identity_id"],
        own_rel_priv=bob["rel_priv"],
        transport=LocalTransport(relay),
    )
    return {
        "alice": alice, "bob": bob, "rid": rid, "conv": conv,
        "harness": harness, "relay": relay,
    }


def test_concurrent_local_upload_no_lost_objects(pair):
    """Two threads really uploading at the same time: every sealed event
    is committed exactly once."""
    transport = LocalTransport(pair["relay"])
    barrier = threading.Barrier(2)
    errors = []

    def sender(seq_start, tag):
        try:
            barrier.wait(timeout=30)
            for i in range(N_PER_SENDER):
                seq = seq_start + i
                _, raw = make_sealed(
                    pair["alice"], pair["bob"], pair["rid"], pair["conv"],
                    "message.created",
                    {"body": "concurrent %s %d" % (tag, i), "format": "plain"},
                    seq=seq,
                )
                transport.upload(_oname(tag, seq), raw)
        except Exception as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [
        threading.Thread(target=sender, args=(1, "aa")),
        threading.Thread(target=sender, args=(N_PER_SENDER + 1, "bb")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert errors == []

    harness = pair["harness"]
    incoming = pair["relay"] / "incoming"
    names = sorted(n for n in os.listdir(incoming) if n.endswith(".json"))
    assert len(names) == 2 * N_PER_SENDER
    for name in names:
        outcome = harness.receive_object(name, (incoming / name).read_bytes())
        assert outcome["outcome"] == "accepted", (name, outcome)

    conn = harness.conn
    total = 2 * N_PER_SENDER
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == total
    dupes = conn.execute(
        "SELECT event_id, COUNT(*) c FROM events GROUP BY event_id HAVING c > 1"
    ).fetchall()
    assert dupes == []
    assert conn.execute("SELECT COUNT(*) FROM replay_guard").fetchone()[0] \
        == total


def _init_bare_repo(path):
    subprocess.run(
        ["git", "init", "--bare", "-b", "main", str(path)],
        check=True, capture_output=True,
    )
    return str(path)


def _git_transport(tmp_path, rid, repo_url, tag):
    return GitHubTransport(
        tmp_path / ("gstate_" + tag), rid, repo_url,
        sleeper=lambda s: None,  # no real sleeps in tests
    )


def test_concurrent_git_push_no_lost_objects(tmp_path, monkeypatch):
    """Two separate clones push to one bare repo at the same time: both
    flushes succeed, every object is fetchable, and both mirrors keep
    working afterwards.

    Two timing protections are neutralized for determinism (the same
    spirit as the existing ``sleeper`` override): the 60s soft push
    interval, and, in the test driver only, a bounded re-flush loop for
    the ref-lock race. That race (``[remote rejected] ... cannot lock
    ref``) is not the non-fast-forward the transport retries internally;
    the failure is retryable, the queue is preserved, and the documented
    recovery is a later flush, which the loop exercises."""
    import muse_agent_social.transports.github as github_mod

    monkeypatch.setattr(github_mod, "PUSH_SOFT_INTERVAL_SECONDS", 0)

    rid = "dddddddd-eeee-4fff-8000-111111111111"
    repo = _init_bare_repo(tmp_path / "relay.git")
    barrier = threading.Barrier(2)
    errors = []
    results = {}

    def pusher(tag, transport):
        # All use of one transport instance stays on this thread: the
        # instance caches a single SQLite connection and is not
        # thread-safe across threads (one instance per thread is the
        # supported pattern).
        def flush_until_pushed():
            for _ in range(10):
                try:
                    return transport.flush()
                except TransportError as exc:
                    if not exc.retryable:
                        raise
            raise AssertionError("flush never succeeded for " + tag)

        try:
            for i in range(10):
                transport.upload(
                    _oname("g" + tag, i), b'{"tag": "%s", "i": %d}' % (
                        tag.encode(), i))
            barrier.wait(timeout=60)
            results[tag] = flush_until_pushed()
            # Follow-up on the same thread: the mirror is not wedged.
            transport.upload(_oname("g" + tag, 99), b'{"again": true}')
            results[tag + "_again"] = flush_until_pushed()
        except Exception as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    ta = _git_transport(tmp_path, rid, repo, "a")
    tb = _git_transport(tmp_path, rid, repo, "b")
    threads = [
        threading.Thread(target=pusher, args=("a", ta)),
        threading.Thread(target=pusher, args=("b", tb)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=180)
    assert errors == []
    assert results["a"]["status"] == "pushed"
    assert results["b"]["status"] == "pushed"
    assert results["a_again"]["status"] == "pushed"
    assert results["b_again"]["status"] == "pushed"

    receiver = _git_transport(tmp_path, rid, repo, "c")
    got = {n: d for n, d in receiver.fetch_new("")}
    for tag in ("a", "b"):
        for i in list(range(10)) + [99]:
            name = _oname("g" + tag, i)
            assert name in got, name
    assert got[_oname("ga", 99)] == b'{"again": true}'
    assert got[_oname("gb", 99)] == b'{"again": true}'
