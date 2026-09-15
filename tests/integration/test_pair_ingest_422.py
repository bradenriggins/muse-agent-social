"""Regression: `mas pair ingest` must not blanket-accept a 422
"already in use" deploy-key response (MEDIUM 3).

The old code treated ANY 422/already-in-use as success with id None. The
fix fetches the repo's existing deploy keys and only accepts when an
existing key's SHA256 fingerprint matches the attempted key, returning the
real existing key id; a mismatched fingerprint fails loudly.
"""

import argparse
import io
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PY = sys.executable
SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC))

from muse_agent_social.cli import CliError, cmd_pair_commit, cmd_pair_ingest


def run_cli(state_dir, *args, stdin_text=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    proc = subprocess.run(
        [PY, "-m", "muse_agent_social.cli", "--state-dir", str(state_dir),
         *args],
        capture_output=True, text=True, env=env, timeout=120,
        input=stdin_text,
    )
    return proc.returncode, proc.stdout, proc.stderr


class _FakeHTTPResponse:
    def __init__(self, payload: bytes, status: int = 200):
        self._payload = payload
        self.status = status

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen_factory(script, calls):
    def _fake(req, *args, **kwargs):
        method = req.get_method()
        url = req.full_url
        calls.append((method, url))
        for i, (sm, spath, status, payload) in enumerate(script):
            if method == sm and url.endswith(spath):
                script.pop(i)
                if status >= 400:
                    raise urllib.error.HTTPError(
                        url, status, "error", {}, io.BytesIO(payload)
                    )
                return _FakeHTTPResponse(payload, status)
        raise AssertionError(f"unexpected API call: {method} {url}")
    return _fake


def _setup(tmp_path, monkeypatch):
    """Two inited agents; acceptor has accepted. Returns (a, b, accept_json,
    commit_json path, acceptor deploy pub)."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert run_cli(a, "init", "--display-name", "Alice")[0] == 0
    assert run_cli(b, "init", "--display-name", "Bob")[0] == 0
    invite_txt = tmp_path / "invite.txt"
    assert run_cli(a, "pair", "invite", "--out", str(invite_txt))[0] == 0
    accept_json = tmp_path / "accept.json"
    assert run_cli(
        b, "pair", "accept",
        "--invite-file", str(invite_txt),
        "--i-compared-phrase",
        "--out", str(accept_json),
    )[0] == 0
    # Real commit against the (mocked) GitHub API.
    calls = []
    script = [
        ("POST", "/repos/owner/pair-relay/keys", 201,
         json.dumps({"id": 111, "key": "k", "title": "t"}).encode()),
        ("POST", "/repos/owner/pair-relay/keys", 201,
         json.dumps({"id": 222, "key": "k", "title": "t"}).encode()),
    ]
    monkeypatch.setattr(urllib.request, "urlopen",
                        _fake_urlopen_factory(script, calls))
    commit_json = tmp_path / "commit.json"
    rc = cmd_pair_commit(argparse.Namespace(
        state_dir=str(a),
        acceptance_file=str(accept_json),
        relay="https://github.com/owner/pair-relay.git",
        transport=None,
        local_relay_dir=None,
        token="test-token",
        capability=None,
        i_compared_phrase=True,
        out=str(commit_json),
    ))
    assert rc == 0
    pair_dirs = list((b / "keys" / "pairing").iterdir())
    assert len(pair_dirs) == 1
    meta = json.loads((pair_dirs[0] / "pairing.json").read_text(encoding="utf-8"))
    deploy_pub = Path(meta["deploy_pub_path"]).read_text(encoding="utf-8").strip()
    return b, commit_json, deploy_pub


def _ingest_args(b, commit_json):
    return argparse.Namespace(
        state_dir=str(b),
        commit_file=str(commit_json),
        transport=None,
        local_relay_dir=None,
        token="test-token",
    )


def _relayed_deploy_keys(b):
    return json.loads((b / "relay.json").read_text(encoding="utf-8"))["deploy_keys"]


def _other_openssh_pub():
    priv = Ed25519PrivateKey.generate()
    return priv.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii").strip()


def test_ingest_422_with_matching_key_returns_real_id(tmp_path, monkeypatch):
    """422/already-in-use where the repo already holds THIS key: success,
    with the real existing key id (not None)."""
    b, commit_json, deploy_pub = _setup(tmp_path, monkeypatch)
    calls = []
    script = [
        ("POST", "/repos/owner/pair-relay/keys", 422,
         json.dumps({"message": "Validation Failed",
                     "errors": [{"message": "key is already in use"}]}).encode()),
        ("GET", "/repos/owner/pair-relay/keys", 200,
         json.dumps([{"id": 999, "key": deploy_pub,
                      "title": "mas-pair-<x>", "read_only": False}]).encode()),
    ]
    monkeypatch.setattr(urllib.request, "urlopen",
                        _fake_urlopen_factory(script, calls))
    rc = cmd_pair_ingest(_ingest_args(b, commit_json))
    assert rc == 0
    assert ("GET", "https://api.github.com/repos/owner/pair-relay/keys") in calls
    deploy_keys = _relayed_deploy_keys(b)
    assert deploy_keys[0]["id"] == 999
    assert deploy_keys[0]["key"] == deploy_pub


def test_ingest_422_with_different_key_fails_loudly(tmp_path, monkeypatch):
    """422/already-in-use where the existing key is a DIFFERENT key: the
    ingest must fail, not silently claim success."""
    b, commit_json, deploy_pub = _setup(tmp_path, monkeypatch)
    calls = []
    script = [
        ("POST", "/repos/owner/pair-relay/keys", 422,
         json.dumps({"message": "Validation Failed",
                     "errors": [{"message": "key is already in use"}]}).encode()),
        ("GET", "/repos/owner/pair-relay/keys", 200,
         json.dumps([{"id": 123, "key": _other_openssh_pub(),
                      "title": "mas-pair-<y>", "read_only": False}]).encode()),
    ]
    monkeypatch.setattr(urllib.request, "urlopen",
                        _fake_urlopen_factory(script, calls))
    with pytest.raises(CliError) as exc_info:
        cmd_pair_ingest(_ingest_args(b, commit_json))
    assert exc_info.value.code == "provisioning_error"
    # The local relationship was already ingested before provisioning, but
    # the failure is loud and relay.json was not written with a fake id.
    assert not (b / "relay.json").exists() or \
        all(k["id"] is not None for k in _relayed_deploy_keys(b))
