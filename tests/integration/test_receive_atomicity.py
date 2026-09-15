"""Lane A C1: the shipped receive path commits atomically.

Kill-point tests against ``cli._receive_object_inner`` (the real receive
path, not the reference harness in tests/support): a crash between the
``events`` INSERT and the ``projection_queue`` INSERT must leave no partial
state behind, and redelivery of the same bytes must surface the message
exactly once. A forged envelope with a bogus ``key_epoch`` must not grow
``rotation_quarantine`` without bound.

Run the kill-point child with:
    python -m tests.integration.test_receive_atomicity child
(manifest JSON on stdin; see _child_main).
"""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from muse_agent_social.cli import _receive_object_inner
from muse_agent_social.crypto.rotation import (
    RotationError,
    RotationManager,
)
from muse_agent_social.policy.delivery import set_policy
from muse_agent_social.store import db as db_mod

from support.harness import (
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)

WORKTREE = Path(__file__).resolve().parent.parent.parent
SRC_DIR = WORKTREE / "src"


class CrashSimulated(Exception):
    """Fault-injection stand-in for a process crash inside the commit."""


class FaultConn:
    """sqlite3 connection proxy that fires a fault before matching SQL.

    Forwards everything else to the wrapped connection, including the
    context-manager protocol (needed while the receive path still uses
    ``with conn:`` anywhere).
    """

    def __init__(self, conn, *, sql_prefix=None, action=None):
        self._conn = conn
        self.sql_prefix = sql_prefix
        self.action = action
        self.armed = sql_prefix is not None and action is not None

    def disarm(self):
        self.armed = False

    def execute(self, sql, params=()):
        if (
            self.armed
            and isinstance(sql, str)
            and sql.lstrip().startswith(self.sql_prefix)
        ):
            self.armed = False
            self.action()
        return self._conn.execute(sql, params)

    def executemany(self, sql, seq):
        return self._conn.executemany(sql, seq)

    def executescript(self, sql):
        return self._conn.executescript(sql)

    def __enter__(self):
        return self._conn.__enter__()

    def __exit__(self, *args):
        return self._conn.__exit__(*args)

    def __getattr__(self, name):
        return getattr(self._conn, name)


@pytest.fixture()
def setup(tmp_path):
    """Receiver-side DB, sealed envelope, and a minimal ctx for the real
    receive path."""
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    rid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    db_path = tmp_path / "recv.db"
    keys_dir = tmp_path / "keys"
    conn = fresh_db(str(db_path))
    provision_receive_side(conn, rid, bob, alice, keys_dir=str(keys_dir))
    set_policy(conn, rid, "alert")
    conn.commit()
    conv = new_conversation(conn)
    _envelope, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "atomic me", "format": "plain"}, seq=1,
    )
    conn.close()
    return {
        "alice": alice, "bob": bob, "rid": rid,
        "db_path": db_path, "keys_dir": keys_dir,
        "raw": raw, "tmp_path": tmp_path,
    }


def _open_conn(setup):
    return db_mod.connect(str(setup["db_path"]))


def _make_ctx(conn, setup, *, fault=None):
    if fault is not None:
        conn = FaultConn(conn, **fault)
    bob = setup["bob"]
    return SimpleNamespace(
        conn=conn,
        state_dir=setup["tmp_path"],
        identity_id=bob["identity_id"],
        hierarchy=SimpleNamespace(ed25519_private=bob["ed_priv"]),
    )


def _count(conn, table, where="", params=()):
    return conn.execute(
        f"SELECT COUNT(*) FROM {table} {where}", params
    ).fetchone()[0]


# -- kill point: between the events INSERT and the projection_queue INSERT --


def test_crash_between_event_and_projection_queue_leaves_no_partial_state(
    setup,
):
    """Fault between the events INSERT and the projection_queue INSERT:
    the whole receive commit rolls back; redelivery surfaces exactly once."""
    conn = _open_conn(setup)
    fault = {
        "sql_prefix": "INSERT INTO projection_queue",
        "action": lambda: (_ for _ in ()).throw(CrashSimulated("kill")),
    }
    ctx = _make_ctx(conn, setup, fault=fault)
    acc = {"surfaces": 0, "receipts_queued": 0}
    with pytest.raises(CrashSimulated):
        _receive_object_inner(ctx, setup["rid"], "crash1.json", setup["raw"], acc)

    # No partial state survived the crash: not the event row, not the
    # replay guard, not the staged payload, not the surface queue row.
    assert _count(conn, "events") == 0
    assert _count(conn, "replay_guard") == 0
    assert _count(conn, "event_payloads") == 0
    assert _count(conn, "projection_queue") == 0
    assert _count(conn, "surface_queue") == 0
    assert _count(conn, "sender_sequence") == 0

    # Resume: redelivering the same bytes is a clean retry, exactly once.
    ctx.conn.disarm()
    outcome = _receive_object_inner(
        ctx, setup["rid"], "crash1.json", setup["raw"], acc
    )
    assert outcome["outcome"] == "accepted"
    assert outcome["surfaces"] == 1
    assert outcome["receipts_queued"] == 1
    # One message event plus the accepted receipt it queued; each projected
    # and surfaced exactly once.
    assert _count(conn, "events", "WHERE event_type = 'message.created'") == 1
    assert _count(conn, "events", "WHERE event_type = 'receipt.accepted'") == 1
    assert _count(conn, "messages") == 1
    assert _count(conn, "projection_queue") == 2
    assert _count(conn, "surface_queue") == 1

    # A second redelivery is byte-identical dedup, not a second surface.
    outcome2 = _receive_object_inner(
        ctx, setup["rid"], "crash1.json", setup["raw"], acc
    )
    assert outcome2["surfaces"] == 0
    assert _count(conn, "events", "WHERE event_type = 'message.created'") == 1
    assert _count(conn, "messages") == 1
    conn.close()


def test_sigkill_between_event_and_projection_queue_is_atomic(setup):
    """Real SIGKILL in a subprocess running the real receive path: after
    the kill, the message is either fully stored or not stored at all,
    never partially; redelivery then surfaces it exactly once."""
    manifest = {
        "db_path": str(setup["db_path"]),
        "state_dir": str(setup["tmp_path"]),
        "rid": setup["rid"],
        "object_name": "sigkill1.json",
        "envelope_hex": setup["raw"].hex(),
        "identity_id": setup["bob"]["identity_id"],
        "ed_priv_hex": setup["bob"]["ed_priv"].private_bytes_raw().hex(),
    }
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-m", "tests.integration.test_receive_atomicity",
         "child"],
        input=json.dumps(manifest).encode("utf-8"),
        capture_output=True,
        cwd=str(WORKTREE),
        env=env,
        timeout=180,
    )
    assert proc.returncode == -signal.SIGKILL, (
        f"child did not die by SIGKILL: rc={proc.returncode} "
        f"stderr={proc.stderr.decode(errors='replace')[-2000:]}"
    )

    # After the kill: no partial commit survived.
    conn = _open_conn(setup)
    assert _count(conn, "events") == 0
    assert _count(conn, "projection_queue") == 0
    assert _count(conn, "surface_queue") == 0

    # Resume in this process: the message is cleanly retryable, exactly once.
    ctx = _make_ctx(conn, setup)
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = _receive_object_inner(
        ctx, setup["rid"], "sigkill1.json", setup["raw"], acc
    )
    assert outcome["outcome"] == "accepted"
    assert outcome["surfaces"] == 1
    assert _count(conn, "events", "WHERE event_type = 'message.created'") == 1
    assert _count(conn, "events", "WHERE event_type = 'receipt.accepted'") == 1
    assert _count(conn, "messages") == 1
    assert _count(conn, "surface_queue") == 1
    conn.close()


# -- forged key_epoch values must not grow rotation_quarantine unboundedly --


def test_forged_bogus_epochs_do_not_grow_quarantine_unboundedly(setup):
    """Envelopes with bogus key_epoch values are quarantined before any
    signature check; the quarantine table must stay bounded per
    relationship."""
    from muse_agent_social.crypto.rotation import ROTATION_QUARANTINE_CAP

    conn = _open_conn(setup)
    mgr = RotationManager(conn, str(setup["keys_dir"]))
    for epoch in range(2, 2 + 3 * ROTATION_QUARANTINE_CAP):
        with pytest.raises(RotationError) as exc:
            mgr.on_data_event_epoch(setup["rid"], epoch)
        assert exc.value.code == "unknown_future_epoch"
    count = _count(
        conn, "rotation_quarantine", "WHERE relationship_id = ?",
        (setup["rid"],),
    )
    assert 0 < count <= ROTATION_QUARANTINE_CAP
    conn.close()


# -- subprocess child --------------------------------------------------------


def _child_main():
    manifest = json.loads(sys.stdin.read())
    conn = db_mod.connect(manifest["db_path"])

    def _kill():
        os.kill(os.getpid(), signal.SIGKILL)

    proxy = FaultConn(
        conn,
        sql_prefix="INSERT INTO projection_queue",
        action=_kill,
    )
    ctx = SimpleNamespace(
        conn=proxy,
        state_dir=Path(manifest["state_dir"]),
        identity_id=manifest["identity_id"],
        hierarchy=SimpleNamespace(
            ed25519_private=Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(manifest["ed_priv_hex"])
            )
        ),
    )
    acc = {"surfaces": 0, "receipts_queued": 0}
    _receive_object_inner(
        ctx,
        manifest["rid"],
        manifest["object_name"],
        bytes.fromhex(manifest["envelope_hex"]),
        acc,
    )
    # If the fault never fired, exit nonzero so the test fails loudly.
    sys.exit(3)


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "child":
    _child_main()
