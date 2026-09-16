"""Gate: v0.1 replay persistence, replay pruning, retry timing (Medium 1).

  * The v0.1 receive path must use a persistent replay store
    (StoreReplayGuard over the v0.2 replay_guard table) instead of a
    per-object MemoryReplayStore, and must record verified objects, so a
    replayed v0.1 object is rejected across objects.
  * Expired replay entries must be pruned after successful receive.
  * The watcher must honor next_retry_at instead of polling through the
    backoff.
"""

import hashlib
import hmac
import json
import os
from types import SimpleNamespace

import pytest

from muse_agent_social.compatibility.v01 import (
    LegacyPolicy,
    StoreReplayGuard,
    vault_store,
    verify_v01,
)
from muse_agent_social.migrate import mstate_set
from muse_agent_social.transports.local import LocalTransport
from muse_agent_social.watcher import (
    EXIT_OK,
    load_watcher_state,
    run_once,
    save_watcher_state,
)
from tests.support.harness import (
    fresh_db,
    make_agent,
    provision_receive_side,
)

REL = "rel-v01replay"
ALICE = "agent:test-alice:fixture"
BOB = "agent:test-bob:fixture"
PAIR = "pair-test-fixture-0001"


def _envelope(key: bytes) -> dict:
    env = {
        "v": 1,
        "id": "legacy-fixed-id-1",
        "from": BOB,
        "to": ALICE,
        "pair": PAIR,
        "type": "note",
        "title": "hello",
        "body": "world",
        "url": "",
        "created_at": "2026-09-15T12:00:00Z",
        "nonce": "fixednonce001",
    }
    canonical = json.dumps(
        {k: v for k, v in env.items() if k != "sig"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    env["sig"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return env


@pytest.fixture()
def v01_ctx(tmp_path):
    from muse_agent_social import cli as cli_mod

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    keys_dir = state_dir / "keys"
    keys_dir.mkdir()
    conn = fresh_db(state_dir / "state.db")
    agent_self = make_agent("Self")
    agent_peer = make_agent("Peer")
    provision_receive_side(
        conn, REL, agent_self, agent_peer, keys_dir=str(keys_dir)
    )
    pair_key = os.urandom(32)
    mstate_set(conn, "migration.phase", "staged")
    # G1: the drain is migration state (legacy_read_open + drain_until),
    # not a phase lookup.
    mstate_set(conn, "migration.legacy_read_open", True)
    mstate_set(conn, "migration.pair_id", PAIR)
    mstate_set(conn, "migration.peer_legacy_id", BOB)
    mstate_set(conn, "migration.my_legacy_id", ALICE)
    vault_store(state_dir / "migration-vault", PAIR, pair_key.hex())
    # CLI-owned tables (quarantine etc.) that a real Ctx would ensure.
    cli_mod._ensure_cli_tables(conn)
    ctx = SimpleNamespace(conn=conn, state_dir=state_dir)
    data = json.dumps(_envelope(pair_key)).encode("utf-8")
    return cli_mod, ctx, data


class TestV01PersistentReplay:
    def test_replayed_v01_object_rejected_across_objects(self, v01_ctx):
        cli_mod, ctx, data = v01_ctx
        first = cli_mod._receive_v01(ctx, REL, "obj1.json", data, {})
        assert first["outcome"] == "accepted"
        second = cli_mod._receive_v01(ctx, REL, "obj2.json", data, {})
        assert second["outcome"] == "quarantined", (
            "a replayed v0.1 object must be rejected, "
            f"got {second}"
        )

    def test_replay_store_is_persistent_not_memory(self, v01_ctx):
        cli_mod, ctx, data = v01_ctx
        cli_mod._receive_v01(ctx, REL, "obj1.json", data, {})
        # The nonce must live in the shared replay_guard table, not in a
        # per-object memory store.
        guard = StoreReplayGuard(ctx.conn)
        assert guard.has_seen("fixednonce001")
        assert guard.has_seen("v01id:legacy-fixed-id-1")


class TestReplayPruning:
    def test_prune_removes_expired_entries(self, v01_ctx):
        from muse_agent_social import cli as cli_mod

        _, ctx, _ = v01_ctx
        guard = StoreReplayGuard(ctx.conn)
        guard.record("old-nonce", "2020-01-01T00:00:00Z")
        guard.record("fresh-nonce", "2999-01-01T00:00:00Z")
        removed = cli_mod.prune_replay_entries(ctx)
        assert removed >= 1
        assert not guard.has_seen("old-nonce")
        assert guard.has_seen("fresh-nonce")


def _accept_all(relationship_id, object_name, data):
    return {"outcome": "accepted", "surfaces": 1, "receipts_queued": 1}


class TestRetryBackoff:
    def _setup(self, tmp_path):
        state_dir = tmp_path / "state"
        transport = LocalTransport(tmp_path / "relay")
        return state_dir, transport

    def test_next_retry_at_skips_poll_during_backoff(self, tmp_path):
        from datetime import datetime, timedelta, timezone

        state_dir, transport = self._setup(tmp_path)
        name = "C" * 32 + ".json"
        transport.upload(name, b"sealed")
        future = (
            datetime.now(timezone.utc) + timedelta(seconds=600)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        state = load_watcher_state(state_dir, REL)
        state["retry_pending"] = 1
        state["next_retry_at"] = future
        save_watcher_state(state_dir, REL, state)

        code, result = run_once(
            transport, REL, _accept_all, state_dir=state_dir,
        )
        assert code == EXIT_OK
        assert result.get("poll_skipped") is True
        # The object is untouched: no work happened during backoff.
        assert result["accepted"] == 0
        assert load_watcher_state(
            state_dir, REL)["last_successful_head"] == ""

    def test_next_retry_at_past_allows_poll(self, tmp_path):
        from datetime import datetime, timedelta, timezone

        state_dir, transport = self._setup(tmp_path)
        name = "D" * 32 + ".json"
        transport.upload(name, b"sealed")
        past = (
            datetime.now(timezone.utc) - timedelta(seconds=600)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        state = load_watcher_state(state_dir, REL)
        state["retry_pending"] = 1
        state["next_retry_at"] = past
        save_watcher_state(state_dir, REL, state)

        code, result = run_once(
            transport, REL, _accept_all, state_dir=state_dir,
        )
        assert code == EXIT_OK
        assert result["accepted"] == 1
