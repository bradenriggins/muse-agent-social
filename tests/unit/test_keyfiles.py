"""Regression tests for private-key file storage hardening.

Covers the adversarial findings on ``muse_agent_social._keyfiles``:
- deletion overwrites key bytes before unlinking (no forensic recovery),
- writes are atomic and never overwrite (no partial key files),
- an unsecurable parent directory is a hard error, never silent.
"""

from __future__ import annotations

import os
import stat

import pytest

from muse_agent_social._keyfiles import (
    KeyFileError,
    atomic_write_no_overwrite,
    delete_private_key,
    store_private_key,
)


def test_delete_overwrites_before_unlink(tmp_path, monkeypatch):
    """Key bytes must be wiped even if the unlink itself is blocked."""
    path = tmp_path / "keys" / "a.key"
    secret = os.urandom(64)
    store_private_key(path, secret)
    assert path.read_bytes() == secret

    # Block the unlink: capture the bytes that were written before it.
    written = {}

    real_unlink = os.unlink

    def failing_unlink(p):
        with open(p, "rb") as fh:
            written["bytes"] = fh.read()
        raise OSError("simulated unlink failure")

    monkeypatch.setattr(os, "unlink", failing_unlink)
    try:
        assert delete_private_key(path) is False
    finally:
        monkeypatch.setattr(os, "unlink", real_unlink)

    assert written["bytes"] != secret
    assert len(written["bytes"]) == len(secret)
    # Clean up for real.
    assert delete_private_key(path) is True
    assert not path.exists()


def test_delete_missing_file_reports_gone(tmp_path):
    assert delete_private_key(tmp_path / "nope.key") is True


def test_delete_does_not_wipe_through_symlink(tmp_path):
    target = tmp_path / "real.key"
    target.write_bytes(os.urandom(32))
    link = tmp_path / "link.key"
    link.symlink_to(target)
    assert delete_private_key(link) is True
    # The link is gone; the target bytes are untouched.
    assert not link.exists() or not link.is_symlink()
    assert len(target.read_bytes()) == 32


def test_store_is_atomic_no_partial_file(tmp_path, monkeypatch):
    """A crash mid-write must not leave a partial file at the destination."""
    path = tmp_path / "keys" / "b.key"

    real_link = os.link

    def crashing_link(src, dst):
        raise OSError("simulated crash before link")

    monkeypatch.setattr(os, "link", crashing_link)
    with pytest.raises(OSError):
        store_private_key(path, os.urandom(48))
    monkeypatch.setattr(os, "link", real_link)

    assert not path.exists()
    # And no temp files are left behind either.
    assert list((tmp_path / "keys").glob(".tmp-key-*")) == []


def test_store_refuses_overwrite_atomically(tmp_path):
    path = tmp_path / "keys" / "c.key"
    first = os.urandom(32)
    store_private_key(path, first)
    with pytest.raises(FileExistsError):
        store_private_key(path, os.urandom(32))
    assert path.read_bytes() == first
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_store_fails_loudly_when_parent_cannot_be_secured(tmp_path, monkeypatch):
    """A chmod that does not take effect must raise, not pass silently."""
    path = tmp_path / "keys" / "d.key"
    monkeypatch.setattr(os, "chmod", lambda p, m: (_ for _ in ()).throw(OSError("denied")))
    with pytest.raises(KeyFileError):
        store_private_key(path, os.urandom(32))
    assert not path.exists()


def test_atomic_write_no_overwrite_used_by_seed_helper(tmp_path):
    from muse_agent_social.crypto.identity import store_master_seed

    seed_path = tmp_path / "master.seed"
    seed = os.urandom(32)
    store_master_seed(seed_path, seed)
    assert seed_path.read_bytes() == seed
    with pytest.raises(FileExistsError):
        store_master_seed(seed_path, os.urandom(32))
