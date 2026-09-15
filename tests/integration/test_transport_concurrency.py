"""Gate: Transport concurrency.

Local relay: concurrent double-receive of one object (two watchers, one
DB) projects and surfaces exactly once; concurrent consume is idempotent;
object names reject path traversal. Git relay over a local bare repo:
round trip, and non-fast-forward push retries exactly once against a
racing peer commit injected via _pre_push_hook.
"""

import subprocess
import threading

import pytest

from muse_agent_social.store.db import connect as db_connect
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


def _oname(tag: str) -> str:
    return (tag + "0" * 32)[:32] + ".json"


@pytest.fixture()
def pair(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    db_path = tmp_path / "state.db"
    conn = fresh_db(db_path)
    rid = "88888888-9999-4000-8111-222222222222"
    provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    conn.close()
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "race me", "format": "plain"}, seq=1,
    )
    return {
        "alice": alice, "bob": bob, "rid": rid,
        "db_path": db_path, "raw": raw,
        "relay": tmp_path / "relay",
    }


def _harness_for(pair, db_path, transport=None):
    conn = db_connect(str(db_path))
    return ReceiveHarness(
        conn,
        relationship_id=pair["rid"],
        own_identity_id=pair["bob"]["identity_id"],
        own_rel_priv=pair["bob"]["rel_priv"],
        transport=transport or LocalTransport(pair["relay"]),
    )


# -- local transport --------------------------------------------------------------


def test_concurrent_double_receive_projects_exactly_once(pair):
    """Two watchers racing on the same object bytes and the same DB: one
    accepted, one accepted_duplicate, one projection, one notification."""
    name = _oname("race")
    transport = LocalTransport(pair["relay"])
    transport.upload(name, pair["raw"])
    # Both watchers race on the same bytes; the DB decides exactly-once.
    # They share one transport instance (production serializes pollers for
    # a relationship with mirror_lock; the DB race is what this proves).
    data = pair["raw"]
    barrier = threading.Barrier(2)
    outcomes = {}
    errors = {}

    def run(slot):
        h = _harness_for(pair, pair["db_path"], transport)
        try:
            barrier.wait(timeout=10)
            outcomes[slot] = h.receive_object(name, data)["outcome"]
        except Exception as exc:  # noqa: BLE001
            errors[slot] = repr(exc)
        finally:
            h.conn.close()

    threads = [threading.Thread(target=run, args=(i,)) for i in (0, 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert errors == {}, errors
    # The loser takes whichever idempotent path the uniqueness race
    # resolves to (identical bytes or duplicate nonce): both are
    # consume-only, never a second projection.
    assert sorted(outcomes.values())[0] == "accepted"
    assert sorted(outcomes.values())[1] in (
        "accepted_duplicate", "duplicate_ignored",
    )

    check = db_connect(str(pair["db_path"]))
    try:
        assert check.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert check.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 1
        assert check.execute(
            "SELECT COUNT(*) FROM surface_queue").fetchone()[0] == 0
        assert check.execute(
            "SELECT COUNT(*) FROM surface_log").fetchone()[0] == 1
        notified = check.execute(
            "SELECT COUNT(*) FROM surface_suppression").fetchone()[0]
        assert notified == 1
    finally:
        check.close()


def test_concurrent_consume_is_idempotent(pair):
    transport = LocalTransport(pair["relay"])
    name = _oname("consume")
    transport.upload(name, b"{}")
    barrier = threading.Barrier(2)
    errors = []

    def run():
        try:
            barrier.wait(timeout=10)
            transport.consume(name)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert errors == []
    assert list((pair["relay"] / "incoming").glob("*.json")) == []
    assert len(list((pair["relay"] / "consumed").glob("*.json"))) == 1


def test_object_name_rejects_path_traversal(tmp_path):
    transport = LocalTransport(tmp_path / "relay")
    for bad in ("../evil.json", "a/b.json", ".json", "x" * 33 + ".json",
                "has space 000000000000000000000.json"):
        with pytest.raises(TransportError) as exc:
            transport.upload(bad, b"{}")
        assert exc.value.code == "config_error"
    # Uppercase is allowed by the name grammar (32 chars exactly).
    transport.upload("UPPERCASE-0000000000000000000001.json", b"{}")


def test_head_changes_on_upload_and_consume(pair):
    transport = LocalTransport(pair["relay"])
    h0 = transport.head()
    name = _oname("head")
    transport.upload(name, b"{}")
    assert transport.changed(h0)
    assert transport.fetch_new(h0) == [(name, b"{}")]
    h1 = transport.head()
    assert transport.fetch_new(h1) == []
    transport.consume(name)
    assert transport.changed(h1)
    assert transport.fetch_new(transport.head()) == []


# -- git relay over a local bare repo -------------------------------------------------


def _init_bare_repo(path):
    subprocess.run(
        ["git", "init", "--bare", "-b", "main", str(path)],
        check=True, capture_output=True,
    )
    return str(path)


def _git_transport(tmp_path, rid, repo_url, tag):
    return GitHubTransport(
        tmp_path / f"state_{tag}", rid, repo_url,
        sleeper=lambda s: None,  # no real sleeps in tests
    )


def test_git_round_trip_over_local_bare_repo(tmp_path):
    rid = "99999999-0000-4111-8222-333333333333"
    repo = _init_bare_repo(tmp_path / "relay.git")
    sender = _git_transport(tmp_path, rid, repo, "a")
    name = _oname("gitobj")
    sender.upload(name, b'{"hello": "relay"}')
    assert sender.pending_outgoing() == 1
    result = sender.flush()
    assert result["status"] == "pushed"
    assert result["pushed"] == 1

    receiver = _git_transport(tmp_path, rid, repo, "b")
    items = receiver.fetch_new("")
    assert (name, b'{"hello": "relay"}') in items


def test_non_fast_forward_retries_and_succeeds(tmp_path):
    """A racing peer commit injected right before push forces exactly one
    non-fast-forward; flush retries and the queued mutation still lands."""
    rid = "aaaaaaaa-1111-4222-8333-444444444444"
    repo = _init_bare_repo(tmp_path / "relay.git")
    sender = _git_transport(tmp_path, rid, repo, "a")
    name = _oname("raceobj")
    sender.upload(name, b'{"racer": 1}')
    assert sender.flush()["status"] == "pushed"

    sender2 = _git_transport(tmp_path, rid, repo, "c")
    name2 = _oname("raceobj2")
    sender2.upload(name2, b'{"racer": 2}')

    fired = []

    def racing_peer_commit():
        # Simulate the peer pushing between our fetch and our push.
        if fired:
            return
        fired.append(True)
        work = tmp_path / "peerwork"
        subprocess.run(
            ["git", "clone", "-q", repo, str(work)],
            check=True, capture_output=True,
        )
        (work / "peer.txt").write_text("peer was here")
        subprocess.run(
            ["git", "-C", str(work), "add", "peer.txt"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(work), "-c", "user.name=t", "-c",
             "user.email=t@t", "commit", "-qm", "peer"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(work), "push", "-q", "origin", "main"],
            check=True, capture_output=True,
        )

    sender2._pre_push_hook = racing_peer_commit
    result = sender2.flush()
    assert fired == [True]
    assert result["status"] == "pushed"

    receiver = _git_transport(tmp_path, rid, repo, "b")
    names = [n for n, _ in receiver.fetch_new("")]
    assert name in names and name2 in names
    peer_files = [n for n, _ in receiver.fetch_new("")]
    assert "peer.txt" not in peer_files  # peer.txt is not a relay object


def test_git_failed_push_keeps_queue_for_later_flush(tmp_path):
    """When the peer keeps racing us past max attempts, the mutation stays
    queued in SQLite for a later flush instead of being lost."""
    from muse_agent_social.transports.github import PUSH_MAX_ATTEMPTS

    rid = "bbbbbbbb-2222-4333-8444-555555555555"
    repo = _init_bare_repo(tmp_path / "relay.git")
    sender = _git_transport(tmp_path, rid, repo, "a")
    name = _oname("keptobj")
    sender.upload(name, b'{"keep": "me"}')

    # Race on every attempt: all PUSH_MAX_ATTEMPTS attempts fail.
    attempts = []

    def counting_race():
        attempts.append(1)
        work = tmp_path / f"peerwork_n{len(attempts)}"
        subprocess.run(["git", "clone", "-q", repo, str(work)],
                       check=True, capture_output=True)
        # Unique content per attempt so each racing commit is non-empty.
        (work / "p.txt").write_text(f"race-{len(attempts)}")
        subprocess.run(["git", "-C", str(work), "add", "p.txt"],
                       check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(work), "-c", "user.name=t", "-c",
             "user.email=t@t", "commit", "-qm", "p"],
            check=True, capture_output=True)
        subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"],
                       check=True, capture_output=True)

    sender._pre_push_hook = counting_race
    with pytest.raises(TransportError) as exc:
        sender.flush()
    assert exc.value.code == "push_non_fast_forward"
    assert len(attempts) == PUSH_MAX_ATTEMPTS
    # Nothing lost: the mutation is still queued for a later flush.
    assert sender.pending_outgoing() == 1
    sender._pre_push_hook = None
    result = sender.flush()
    assert result["status"] == "pushed"
    assert sender.pending_outgoing() == 0
