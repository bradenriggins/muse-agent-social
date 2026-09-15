"""Gate: H1 - teardown removes every per-relationship state directory.

Regression test for the incomplete-teardown finding: teardown_relationship
used to wipe a fixed list of operational dirs but left the git relay mirror
(mirrors/<rid>/), the transport lock (locks/<rid>.lock), and watcher state
(watcher/<rid>.json) behind, which tripped the postcheck (TeardownError
"postcheck-dirty") AFTER the private keys had already been destroyed.
"""

import json

import pytest

from muse_agent_social.teardown import (
    TeardownError,
    postcheck_scan,
    teardown_relationship,
)
from muse_agent_social.watcher import save_watcher_state

from support.harness import fresh_db, make_agent, provision_receive_side


@pytest.fixture()
def ctx(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    conn = fresh_db(state_dir / "state.db")
    rid = "aaaaaaaa-1111-4111-8111-111111111111"
    provision_receive_side(conn, rid, bob, alice)
    return {"conn": conn, "rid": rid, "state_dir": state_dir}


def _plant_transport_state(state_dir, rid):
    """Plant every per-relationship on-disk artifact the transports and
    the watcher create: git mirror, mirror lock, watcher state."""
    mirror = state_dir / "mirrors" / rid
    (mirror / ".git" / "objects").mkdir(parents=True)
    (mirror / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (mirror / "incoming").mkdir(parents=True)
    # A file whose content mentions the relationship id, like a real
    # mirror config would.
    (mirror / "config-note.txt").write_text(f"relay for {rid}\n")
    lock = state_dir / "locks" / f"{rid}.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("")
    save_watcher_state(state_dir, rid, {"last_head": "deadbeef", "rid": rid})
    return mirror, lock


def test_teardown_removes_mirror_lock_and_watcher_state(ctx):
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    mirror, lock = _plant_transport_state(state_dir, rid)
    watcher_path = state_dir / "watcher" / f"{rid}.json"
    assert watcher_path.is_file()

    # Must not raise: the old code died here with postcheck-dirty after
    # already destroying the private keys.
    report = teardown_relationship(conn, state_dir, rid, peer_label="Bob")

    assert mirror.exists() is False
    assert not (state_dir / "mirrors" / rid).exists()
    assert lock.exists() is False
    assert watcher_path.exists() is False
    assert report.postcheck_hits == []

    # The private key files are gone too (crypto-erasure boundary kept).
    assert list((state_dir / "keys").glob(f"{rid}*")) == []

    # Post-check over the whole state dir finds no trace of the id.
    scan = postcheck_scan(state_dir, rid, peer_label="Bob")
    assert scan["hits"] == []


def test_teardown_postcheck_catches_leftover_lock(ctx):
    """Sanity: if the lock file were left behind, the postcheck flags it.

    This proves the test above is not vacuous: the lock filename contains
    the relationship id, so a leftover lock is a postcheck hit.
    """
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    lock = state_dir / "locks" / f"{rid}.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("")
    scan = postcheck_scan(state_dir, rid)
    assert any(str(lock) == hit for hit in scan["hits"])


def test_teardown_with_all_operational_dirs_present(ctx):
    """Every wiped dir present at once still yields a clean postcheck."""
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    _plant_transport_state(state_dir, rid)
    for name in (
        "bundles", "mirror", "cache", "inbox", "outbox", "retry",
        "plaintext_cache",
    ):
        d = state_dir / name
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{rid}.txt").write_text(f"trace of {rid}\n")
    report = teardown_relationship(conn, state_dir, rid, peer_label="Bob")
    assert report.postcheck_hits == []
    for name in (
        "bundles", "mirror", "cache", "inbox", "outbox", "retry",
        "plaintext_cache",
    ):
        assert not (state_dir / name).exists()
    assert not (state_dir / "mirrors" / rid).exists()
    assert not (state_dir / "locks" / f"{rid}.lock").exists()
    assert not (state_dir / "watcher" / f"{rid}.json").exists()
