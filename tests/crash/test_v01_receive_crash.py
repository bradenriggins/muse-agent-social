"""V7 regression: the v0.1 drain-window receive path must persist
atomically.

Before the fix, _receive_v01 committed the seq-assigner state first, then
ran the event/payload/queue inserts each in autocommit, and recorded the
legacy replay nonce after another no-op ``with ctx.conn:`` block. A crash
between the INSERTs left the event stored but never projected; redelivery
then hit an IntegrityError on the deterministic event_id (silent loss
plus a bogus quarantine), or the replay record went missing and the
object could be replayed.
"""

import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

import muse_agent_social.migrate as mig
from muse_agent_social import cli as cli_mod
from muse_agent_social.compatibility.v01 import (
    SeqAssigner,
    vault_store,
)
from muse_agent_social.migrate import MigrationContext
from muse_agent_social.store.migrations import migrate
from muse_agent_social.migrate import mstate_get, mstate_set
from tests.support.harness import (
    fresh_db,
    make_agent,
    new_conversation,
    provision_receive_side,
)

ALICE = "agent:test-alice"
BOB = "agent:test-bob"


class FaultInjected(Exception):
    """Raised when a kill-point fault fires."""


class FaultConn:
    """sqlite3 connection proxy that raises FaultInjected once on the
    first execute() containing ``kill_sql``."""

    def __init__(self, real: sqlite3.Connection, *, kill_sql: str) -> None:
        self._real = real
        self._kill_sql = kill_sql
        self._armed = True

    def execute(self, sql, params=()):
        if self._armed and self._kill_sql in sql:
            self._armed = False
            raise FaultInjected(f"kill at {self._kill_sql}")
        return self._real.execute(sql, params)

    def executemany(self, sql, seq_of_params):
        return self._real.executemany(sql, seq_of_params)

    def executescript(self, sql):
        return self._real.executescript(sql)

    def __enter__(self):
        self._real.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._real.__exit__(exc_type, exc, tb)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _v01_envelope(key, pair_id, sender, recipient, nonce):
    env = {
        "v": 1,
        "id": f"legacy-{nonce}",
        "from": sender,
        "to": recipient,
        "pair": pair_id,
        "type": "note",
        "title": "hello",
        "body": "world",
        "url": "",
        "created_at": "2026-09-15T12:00:00Z",
        "nonce": nonce,
    }
    import hashlib
    import hmac

    canonical = json.dumps(
        {k: v for k, v in env.items() if k != "sig"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    env["sig"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return json.dumps(env).encode("utf-8")


@pytest.fixture()
def drain(tmp_path):
    """A CLI state dir in the migration drain window with a sealed vault."""
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    pair_id = "pair-v01crash-" + os.urandom(4).hex()
    pair_key = os.urandom(32)
    rid = "rel-v01crash-" + os.urandom(4).hex()
    state_dir = tmp_path / "cli-state"
    (state_dir / "keys").mkdir(parents=True)
    conn = fresh_db(state_dir / "state.db")
    provision_receive_side(conn, rid, bob, alice)
    mstate_set(conn, "migration.phase", "staged")
    # G1: the drain is migration state (legacy_read_open + drain_until),
    # not a phase lookup.
    mstate_set(conn, "migration.legacy_read_open", True)
    mstate_set(conn, "migration.pair_id", pair_id)
    mstate_set(conn, "migration.peer_legacy_id", BOB)
    mstate_set(conn, "migration.my_legacy_id", ALICE)
    vault_dir = state_dir / "migration-vault"
    mctx = MigrationContext(
        state_dir=state_dir,
        legacy_state_dir=state_dir,
        vault_dir=vault_dir,
        pair_id=pair_id,
        my_agent_id=ALICE,
        peer_agent_id=BOB,
    )
    mig._migration_identity_priv(mctx)
    enc = mig.ceremony_vault_key(state_dir, pair_id)
    vault_store(vault_dir, pair_id, pair_key.hex(), enc_key=enc)
    cli_mod._ensure_cli_tables(conn)
    data = _v01_envelope(pair_key, pair_id, BOB, ALICE, "nonce-v01crash")
    return {
        "conn": conn,
        "rid": rid,
        "pair_id": pair_id,
        "data": data,
        "state_dir": state_dir,
        "identity_id": bob["identity_id"],
    }


def _ctx(drain, conn):
    return SimpleNamespace(
        conn=conn,
        state_dir=drain["state_dir"],
        keys_dir=drain["state_dir"] / "keys",
        identity_id=drain["identity_id"],
    )


def _counts(drain):
    conn = drain["conn"]
    return {
        "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "payloads": conn.execute(
            "SELECT COUNT(*) FROM event_payloads").fetchone()[0],
        "queue": conn.execute(
            "SELECT COUNT(*) FROM projection_queue").fetchone()[0],
    }


def test_kill_at_v01_event_insert_rolls_back_everything(drain):
    """Kill during the v0.1 events INSERT: the whole persist block rolls
    back, the seq-assigner state is not burned, and the replay nonce is
    not recorded."""
    rid = drain["rid"]
    killer = FaultConn(drain["conn"], kill_sql="INSERT INTO events")
    with pytest.raises(FaultInjected):
        cli_mod._receive_v01(_ctx(drain, killer), rid, "v01a.json",
                             drain["data"], {})
    assert _counts(drain) == {"events": 0, "payloads": 0, "queue": 0}
    # The seq-assigner state was never durably advanced: no row at all.
    assert mstate_get(drain["conn"], "migration.seq_assigner") in (None, {})


def test_kill_at_v01_queue_insert_resumes_exactly_once(drain):
    """Kill at the projection_queue INSERT (after the event row): rollback,
    then resume stores and projects exactly once."""
    rid = drain["rid"]
    killer = FaultConn(drain["conn"], kill_sql="INSERT INTO projection_queue")
    with pytest.raises(FaultInjected):
        cli_mod._receive_v01(_ctx(drain, killer), rid, "v01b.json",
                             drain["data"], {})
    assert _counts(drain) == {"events": 0, "payloads": 0, "queue": 0}

    out = cli_mod._receive_v01(
        _ctx(drain, drain["conn"]), rid, "v01b.json", drain["data"], {}
    )
    assert out["outcome"] == "accepted"
    assert _counts(drain) == {"events": 1, "payloads": 1, "queue": 1}

    # The sequence number was not burned by the killed attempt: the
    # assigner state reflects exactly one assignment.
    assigner = SeqAssigner.from_dict(
        {k: int(v) for k, v in
         mstate_get(drain["conn"], "migration.seq_assigner").items()}
    )
    assert assigner.to_dict()  # non-empty after the successful receive

    # Redelivery is a replay, not a duplicate event.
    out = cli_mod._receive_v01(
        _ctx(drain, drain["conn"]), rid, "v01b.json", drain["data"], {}
    )
    assert out["outcome"] == "quarantined"
    assert _counts(drain) == {"events": 1, "payloads": 1, "queue": 1}


def test_v01_accepted_event_rebuilds_cleanly(drain):
    """The accepted v0.1 event projects without payload_missing: the
    projection input was staged inside the same transaction."""
    from muse_agent_social.store.projections import rebuild_projections

    rid = drain["rid"]
    out = cli_mod._receive_v01(
        _ctx(drain, drain["conn"]), rid, "v01c.json", drain["data"], {}
    )
    assert out["outcome"] == "accepted"
    rebuild_projections(drain["conn"], rid)
