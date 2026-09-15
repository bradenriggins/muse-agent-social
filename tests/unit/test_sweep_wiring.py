"""Gate: production rotation sweeps (H8).

RotationManager.sweep() exists and is correct, but nothing calls it in
production: a lost rotation ack wedges the relationship forever (every
begin_rotation raises rotation_in_flight), and old private keys are never
retired. These tests prove:
  * a stale candidate (deadline past, ack never arrived) is discarded by
    sweep(), which raises NoAckTimeout loudly, and a fresh rotation can
    then begin (superseding),
  * sweep() retires the prior private key after a committed rotation
    (old key file deleted, key_epochs row removed),
  * the watcher poll cycle runs a maintenance callback on clean cycles,
    and a failing callback is recorded without failing the cycle,
  * the CLI sweep helper survives NoAckTimeout: it warns loudly and
    never raises.
"""

import pytest
from types import SimpleNamespace

from muse_agent_social.crypto.rotation import (
    NoAckTimeout,
    RotationError,
    RotationManager,
)
from muse_agent_social.transports.local import LocalTransport
from muse_agent_social.watcher import EXIT_OK, run_once
from tests.support.harness import (
    fresh_db,
    make_agent,
    provision_receive_side,
)

REL = "rel-sweep"


@pytest.fixture()
def store(tmp_path):
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
    return state_dir, conn


def expire_candidate(conn):
    conn.execute(
        "UPDATE key_rotations SET deadline = '2020-01-01T00:00:00Z' "
        "WHERE relationship_id = ?",
        (REL,),
    )
    conn.commit()


def accept_all(relationship_id, object_name, data):
    return {"outcome": "accepted", "surfaces": 1, "receipts_queued": 1}


class TestLostAck:
    def test_stale_candidate_discarded_and_rotation_can_restart(
        self, store
    ):
        state_dir, conn = store
        mgr = RotationManager(conn, state_dir / "keys")
        mgr.begin_rotation(REL)

        # The wedge: a second rotation is refused while the first is
        # in flight.
        with pytest.raises(RotationError) as exc_info:
            mgr.begin_rotation(REL)
        assert exc_info.value.code == "rotation_in_flight"

        # The ack never arrived. Sweep discards the stale candidate and
        # raises loudly ...
        expire_candidate(conn)
        with pytest.raises(NoAckTimeout):
            mgr.sweep()

        # ... and a fresh rotation may now begin (superseding).
        mgr.begin_rotation(REL)

    def test_sweep_retires_old_private_key(self, store):
        state_dir, conn = store
        mgr = RotationManager(conn, state_dir / "keys")
        old_key = state_dir / "keys" / f"{REL}-e1.key"
        assert old_key.exists()
        conn.execute(
            "INSERT INTO key_rotations("
            "relationship_id, epoch, role, phase, prior_epoch, prepared_at,"
            " committed_at, deadline"
            ") VALUES (?,?,?,?,?,?,?,?)",
            (REL, 2, "rotating", "committed", 1,
             "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z",
             "2020-01-02T00:00:00Z"),
        )
        conn.commit()
        mgr.sweep()
        assert not old_key.exists()
        remaining = conn.execute(
            "SELECT COUNT(*) FROM key_epochs "
            "WHERE relationship_id = ? AND epoch = 1",
            (REL,),
        ).fetchone()[0]
        assert remaining == 0


class TestWatcherMaintenance:
    def _setup(self, tmp_path):
        state_dir = tmp_path / "state"
        transport = LocalTransport(tmp_path / "relay")
        return state_dir, transport

    def test_runs_maintenance_callback_on_clean_cycle(self, tmp_path):
        state_dir, transport = self._setup(tmp_path)
        calls = []
        name = "A" * 32 + ".json"
        transport.upload(name, b"sealed")
        code, result = run_once(
            transport, REL, accept_all, state_dir=state_dir,
            maintenance_callback=lambda: calls.append(1),
        )
        assert code == EXIT_OK
        assert calls == [1]
        assert "maintenance_error" not in result

    def test_callback_error_recorded_without_failing_cycle(self, tmp_path):
        state_dir, transport = self._setup(tmp_path)
        name = "B" * 32 + ".json"
        transport.upload(name, b"sealed")

        def boom():
            raise RuntimeError("sweep blew up")

        code, result = run_once(
            transport, REL, accept_all, state_dir=state_dir,
            maintenance_callback=boom,
        )
        assert code == EXIT_OK
        assert result["maintenance_error"].startswith("RuntimeError")


class TestCliSweepHelper:
    def test_sweep_helper_warns_loudly_without_raising(
        self, store, capsys
    ):
        from muse_agent_social.cli import _sweep_rotations

        state_dir, conn = store
        mgr = RotationManager(conn, state_dir / "keys")
        mgr.begin_rotation(REL)
        expire_candidate(conn)

        ctx = SimpleNamespace(conn=conn, keys_dir=state_dir / "keys")
        _sweep_rotations(ctx)  # must not raise

        err = capsys.readouterr().err
        assert "warning" in err
        assert "no_ack_timeout" in err

        # The stale candidate is gone: a new rotation can begin.
        mgr.begin_rotation(REL)
