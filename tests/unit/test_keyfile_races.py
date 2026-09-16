"""Regression tests for the K1 concurrent key-staging races.

- A `stage` that loses the concurrent-create race adopts the winner's key
  file (same bytes), after mode-checking it.
- A winner file with the wrong mode is a hard error, not a silent
  adoption.
- A winner file that vanishes between the failed create and the read is
  retried once; a persistently vanishing file raises a clear
  MigrationError instead of a bare FileNotFoundError.
"""

import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from muse_agent_social import migrate as mig
from muse_agent_social.migrate import (
    MigrationContext,
    MigrationError,
    _keys_dir,
)


def _ctx(tmp_path):
    return MigrationContext(
        state_dir=tmp_path / "v02",
        legacy_state_dir=tmp_path / "legacy",
        vault_dir=tmp_path / "vault",
        pair_id="pair-k1-race",
        my_agent_id="agent:test-a",
        peer_agent_id="agent:test-b",
    )


def _identity_path(ctx):
    return _keys_dir(ctx) / f"{ctx.pair_id}.{mig._MIGRATION_IDENTITY_KEY_NAME}"


def _relationship_path(ctx):
    return (
        _keys_dir(ctx) / f"{ctx.pair_id}.{mig._MIGRATION_RELATIONSHIP_KEY_NAME}"
    )


def _race_loser(monkeypatch):
    """Make atomic_write_no_overwrite always lose the create race."""

    def fake(path, data, mode):
        raise FileExistsError("simulated concurrent stage")

    monkeypatch.setattr(mig, "atomic_write_no_overwrite", fake)


def test_loser_adopts_winner_identity_key(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    winner = Ed25519PrivateKey.generate()
    path = _identity_path(ctx)
    path.write_bytes(
        winner.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    _race_loser(monkeypatch)
    got = mig._migration_identity_priv(ctx, create=True)
    assert got.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ) == path.read_bytes()


def test_loser_adopts_winner_relationship_key(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    winner = X25519PrivateKey.generate()
    path = _relationship_path(ctx)
    path.write_bytes(winner.private_bytes_raw())
    os.chmod(path, 0o600)
    _race_loser(monkeypatch)
    got = mig._relationship_priv(ctx)
    assert got.private_bytes_raw() == winner.private_bytes_raw()


def test_loser_rejects_wrong_mode_winner(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    path = _identity_path(ctx)
    path.write_bytes(b"w" * 32)
    os.chmod(path, 0o644)  # winner left a group-readable file: hard error
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    _race_loser(monkeypatch)
    with pytest.raises(MigrationError) as ei:
        mig._migration_identity_priv(ctx, create=True)
    assert ei.value.code == "key-file-mode"


def test_disappearing_winner_retries_then_raises(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    _race_loser(monkeypatch)
    # Winner's file always vanishes: the loser must not crash on a bare
    # FileNotFoundError; after the retry budget it raises MigrationError.
    monkeypatch.setattr(mig, "_read_race_winner", lambda path: None)
    with pytest.raises(MigrationError) as ei:
        mig._migration_identity_priv(ctx, create=True)
    assert ei.value.code == "identity-key-store"


def test_disappearing_winner_eventual_success(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    _race_loser(monkeypatch)
    calls = {"n": 0}
    real = mig._read_race_winner

    def flaky(path):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # vanished on the first attempt
        # Winner re-appears (re-created by the retried create... but the
        # create is faked to lose; plant the file instead).
        path.write_bytes(b"v" * 32)
        os.chmod(path, 0o600)
        return real(path)

    monkeypatch.setattr(mig, "_read_race_winner", flaky)
    got = mig._migration_identity_priv(ctx, create=True)
    assert got.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ) == b"v" * 32
    assert calls["n"] == 2
