"""Unit tests for state directory resolution and config.yaml handling."""

from __future__ import annotations

import pytest

from muse_agent_social import config


def test_resolve_state_dir_mas_home(monkeypatch, tmp_path):
    monkeypatch.setenv("MAS_HOME", str(tmp_path / "custom"))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert config.resolve_state_dir() == tmp_path / "custom"


def test_resolve_state_dir_xdg(monkeypatch, tmp_path):
    monkeypatch.delenv("MAS_HOME", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert config.resolve_state_dir() == tmp_path / "xdg" / "muse-agent-social"


def test_resolve_state_dir_home_fallback(monkeypatch, tmp_path):
    import pathlib

    monkeypatch.delenv("MAS_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
    assert config.resolve_state_dir() == (
        tmp_path / ".local" / "share" / "muse-agent-social"
    )


def test_config_round_trip(tmp_path):
    path = tmp_path / "config.yaml"
    obj = config.default_config()
    obj["identity_ref"] = "identity/card.json"
    obj["relay"]["poll_interval_seconds"] = 45
    config.save_config(path, obj)
    loaded = config.load_config(path)
    assert loaded == obj
    assert loaded["relay"]["poll_interval_seconds"] == 45
    assert loaded["relay"]["push_ceiling_per_minute"] == 6


def test_config_yaml_subset_types(tmp_path):
    path = tmp_path / "config.yaml"
    obj = {
        "name": "with: colon and # hash",
        "count": 3,
        "enabled": True,
        "missing": None,
        "items": ["a", "b c", "12"],
        "nested": {"deep": {"flag": False}},
    }
    config.save_config(path, obj)
    assert config.load_config(path) == obj


def test_save_config_rejects_secrets(tmp_path):
    path = tmp_path / "config.yaml"
    with pytest.raises(ValueError):
        config.save_config(path, {"master_seed": "deadbeef"})
    with pytest.raises(ValueError):
        config.save_config(path, {"relay": {"api_token": "abc"}})
    with pytest.raises(ValueError):
        config.save_config(path, {"private_key": "xyz"})
    # References and paths are allowed.
    config.save_config(
        path,
        {
            "identity_ref": "identity/card.json",
            "keys": {"relationship_key_ref": "keys/rel-1.key"},
        },
    )
    assert config.load_config(path)["keys"]["relationship_key_ref"] == "keys/rel-1.key"


def test_load_config_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        config.load_config(tmp_path / "nope.yaml")


def test_load_config_validates_relay(tmp_path):
    path = tmp_path / "config.yaml"
    obj = config.default_config()
    obj["relay"]["poll_interval_seconds"] = -5
    config.save_config(path, obj)
    with pytest.raises(ValueError):
        config.load_config(path)


def test_default_poll_and_push_ceiling():
    assert config.DEFAULT_POLL_INTERVAL_SECONDS == 30
    assert config.DEFAULT_PUSH_CEILING_PER_MINUTE == 6


def test_load_config_rejects_inline_secrets(tmp_path):
    """load_config must enforce the no-inline-secrets invariant too."""
    path = tmp_path / "config.yaml"
    path.write_text("master_seed: deadbeef\n", encoding="utf-8")
    with pytest.raises(ValueError, match="secret"):
        config.load_config(path)
    path.write_text("relay:\n  api_token: abc\n", encoding="utf-8")
    with pytest.raises(ValueError, match="secret"):
        config.load_config(path)


def test_save_config_mode_0600_and_allows_updates(tmp_path):
    import stat

    path = tmp_path / "config.yaml"
    obj = config.default_config()
    config.save_config(path, obj)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # Updates to an existing config must work (atomic replace).
    obj["relay"]["poll_interval_seconds"] = 60
    config.save_config(path, obj)
    assert config.load_config(path)["relay"]["poll_interval_seconds"] == 60


# ---------------------------------------------------------------------------
# Regression test for finding D12 (config permission degradation).
# ---------------------------------------------------------------------------


def test_save_config_warns_not_raises_when_parent_mode_unenforceable(
    tmp_path, monkeypatch, capsys
):
    """D12: on a filesystem where the 0700 parent-dir mode cannot be
    enforced, save_config degrades to a loud stderr warning (config holds
    no secrets), while key material keeps the hard error."""
    import os

    from muse_agent_social import config as config_mod
    from muse_agent_social._keyfiles import KeyFileError, store_private_key

    def denied_chmod(p, m):
        raise OSError("chmod denied by filesystem")

    monkeypatch.setattr(os, "chmod", denied_chmod)
    path = tmp_path / "sub" / "config.yaml"
    obj = config_mod.default_config()
    # Config: warns loudly, still writes.
    config_mod.save_config(path, obj)
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "degraded" in err
    assert config_mod.load_config(path) == obj
    # Key material: still fail-closed under the same conditions.
    with pytest.raises(KeyFileError):
        store_private_key(tmp_path / "keys" / "k.key", os.urandom(32))
