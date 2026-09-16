"""Randomized migration-ceremony property tests (seeded stdlib random).

- Step guards: each step rejects wrong phases with ``MigrationError``;
  phases only move forward (``idle -> staged -> verified -> committed ->
  complete``).
- Crash redrive: ``stage`` accepts ``idle``/``rolled_back``/``freezing``
  (a crash between freeze and staged is redrivable); ``verify``,
  ``cutover`` accept only their exact phase; ``observe`` re-runs while
  ``committed``.
- Rollback restoration: rollback from ``freezing``/``staged``/``verified``
  lands on ``rolled_back`` with the legacy pair key intact in the vault;
  ``stage`` works again afterwards. Rollback after commit and from
  ``idle`` is refused.
"""

import random

import pytest

from muse_agent_social import migrate as mig
from muse_agent_social.compatibility.v01 import vault_load
from muse_agent_social.migrate import (
    MigrationError,
    _vault_key,
    cutover,
    mstate_set,
    observe,
    rollback,
    stage,
    verify,
)
from muse_agent_social.store.db import open_db
from tests.unit.test_migration_ceremony import PeerSim, make_ctx, make_hooks


def _phase_of(ctx):
    """Phase, treating a missing state DB as idle (pre-stage)."""
    conn = open_db(ctx.state_dir)
    try:
        try:
            return mig.mstate_get(conn, "migration.phase", "idle")
        except Exception:
            return "idle"
    finally:
        conn.close()


def _fresh(tmp_path, tag):
    pair_id = f"pair-prop-{tag}"
    peer = PeerSim(pair_id, "agent:test-bob", tmp_path / f"peer-{tag}")
    hooks = make_hooks(peer, pair_id)
    ctx, legacy_key = make_ctx(tmp_path, tag, hooks, pair_id=pair_id)
    return ctx, legacy_key


def _set_phase_raw(ctx, phase):
    conn = open_db(ctx.state_dir)
    try:
        mstate_set(conn, "migration.phase", phase)
    finally:
        conn.close()


def _vault_has_key(ctx, legacy_key):
    """The sealed vault still yields the legacy pair key (raw bytes)."""
    try:
        loaded = vault_load(
            ctx.vault_dir, ctx.pair_id, enc_key=_vault_key(ctx, create=False)
        )
    except (KeyError, Exception):
        return False
    if isinstance(loaded, str):
        loaded = loaded.encode()
    return bytes(loaded) == bytes(legacy_key)


@pytest.mark.parametrize("seed", range(5))
def test_step_guards_and_forward_walk(tmp_path, seed):
    """Wrong-phase calls raise; the happy path moves the phase forward
    one step at a time and never backwards."""
    ctx, _ = _fresh(tmp_path, f"guards-{seed}")
    assert _phase_of(ctx) == "idle"

    # Every step rejects the idle phase (rollback has its own refusal).
    for fn in (verify, cutover, observe):
        with pytest.raises(MigrationError):
            fn(ctx)
    with pytest.raises(MigrationError) as ei:
        rollback(ctx, "nothing to do")
    assert ei.value.code == "nothing-to-roll-back"

    expected = [
        (stage, "staged"),
        (verify, "verified"),
        (cutover, "committed"),
    ]
    for fn, phase in expected:
        fn(ctx)
        assert _phase_of(ctx) == phase

    # Forward-only: earlier steps now reject the advanced phase.
    with pytest.raises(MigrationError) as ei:
        stage(ctx)
    assert ei.value.code == "bad-phase"
    with pytest.raises(MigrationError):
        verify(ctx)
    with pytest.raises(MigrationError):
        cutover(ctx)

    # Observe during the drain window reports and stays committed.
    report = observe(ctx)
    assert _phase_of(ctx) == "committed"
    assert report["drain_open"] is True
    # Re-running observe while committed is a supported redrive.
    observe(ctx)
    assert _phase_of(ctx) == "committed"

    # Rollback after commit is refused: roll forward only.
    with pytest.raises(MigrationError) as ei:
        rollback(ctx, "too late")
    assert ei.value.code == "rollback-after-commit-refused"


@pytest.mark.parametrize("seed", range(7))
def test_randomized_crash_redrive(tmp_path, seed):
    """Random sequences of supported redrives and refusals keep the
    phase machine consistent."""
    rng = random.Random(6000 + seed)
    ctx, _ = _fresh(tmp_path, f"redrive-{seed}")

    for _ in range(rng.randrange(6, 14)):
        phase = _phase_of(ctx)
        action = rng.randrange(6)
        if action == 0:
            # Stage: supported from idle/rolled_back/freezing.
            if phase in ("idle", "rolled_back", "freezing"):
                stage(ctx)
                assert _phase_of(ctx) == "staged"
            else:
                with pytest.raises(MigrationError):
                    stage(ctx)
                assert _phase_of(ctx) == phase
        elif action == 1:
            # Simulated crash mid-stage: force the freezing marker, then
            # redrive stage (must succeed from any pre-commit phase).
            if phase in ("idle", "rolled_back", "staged", "verified"):
                _set_phase_raw(ctx, "freezing")
                stage(ctx)
                assert _phase_of(ctx) == "staged"
        elif action == 2:
            if phase == "staged":
                verify(ctx)
                assert _phase_of(ctx) == "verified"
            else:
                with pytest.raises(MigrationError):
                    verify(ctx)
        elif action == 3:
            if phase == "verified":
                cutover(ctx)
                assert _phase_of(ctx) == "committed"
            else:
                with pytest.raises(MigrationError):
                    cutover(ctx)
        elif action == 4:
            if phase == "committed":
                observe(ctx)
                assert _phase_of(ctx) == "committed"
            else:
                with pytest.raises(MigrationError):
                    observe(ctx)
        else:
            # Rollback: pre-commit phases roll back; rolled_back re-rolls
            # back idempotently; committed/idle refuse.
            if phase in ("freezing", "staged", "verified", "rolled_back"):
                result = rollback(ctx, "property test")
                assert _phase_of(ctx) == "rolled_back"
                assert result["legacy_key_in_vault"] is True
            else:
                with pytest.raises(MigrationError):
                    rollback(ctx, "property test")
                assert _phase_of(ctx) == phase


@pytest.mark.parametrize("seed", range(5))
def test_rollback_restores_and_redrives(tmp_path, seed):
    """Rollback from each pre-commit phase restores v0.1, keeps the
    legacy key in the vault, and the ceremony can stage again."""
    rng = random.Random(6100 + seed)
    ctx, legacy_key = _fresh(tmp_path, f"rb-{seed}")

    stop_at = rng.choice(["freezing", "staged", "verified"])
    if stop_at == "freezing":
        _set_phase_raw(ctx, "freezing")
    else:
        stage(ctx)
        if stop_at == "verified":
            verify(ctx)
    assert _phase_of(ctx) == stop_at

    result = rollback(ctx, "property test rollback")
    assert _phase_of(ctx) == "rolled_back"
    assert result["restored_v01_sends"] is True
    assert _vault_has_key(ctx, legacy_key)

    # The ceremony redrives cleanly after rollback.
    stage(ctx)
    assert _phase_of(ctx) == "staged"
    verify(ctx)
    assert _phase_of(ctx) == "verified"
    assert _vault_has_key(ctx, legacy_key)
