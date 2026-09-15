"""Regression: `mas pair commit` must provision the relay BEFORE committing
local state, and must roll back on provisioning failure (H9).

Failing the second deploy-key registration after the local commit left a
committed relationship row (and private keys) pointing at a relay the
operator cannot use. The fix provisions both deploy keys first; on any
registration failure it deletes keys already registered, removes the
locally generated deploy private key, and leaves no relationship row, so
the invite can be retried.
"""

import argparse
import io
import json
import os
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC))

from muse_agent_social.cli import CliError, cmd_pair_commit


def run_cli(state_dir, *args, stdin_text=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    proc = subprocess.run(
        [sys.executable, "-m", "muse_agent_social.cli", "--state-dir",
         str(state_dir), *args],
        capture_output=True, text=True, env=env, timeout=120,
        input=stdin_text,
    )
    return proc.returncode, proc.stdout, proc.stderr


class _FakeHTTPResponse:
    def __init__(self, status: int, payload: bytes):
        self.status = status
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _setup_paired(tmp_path, monkeypatch):
    a = tmp_path / "a"
    b = tmp_path / "b"
    for d in (a, b):
        d.mkdir()
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
    return a, str(accept_json)


def _fake_urlopen_factory(script, calls):
    """script: list of (method, path_suffix, status, payload); unmatched -> fail."""
    def _fake(req, *args, **kwargs):
        method = req.get_method()
        url = req.full_url
        calls.append((method, url))
        for i, (sm, spath, status, payload) in enumerate(script):
            if method == sm and url.endswith(spath):
                script.pop(i)
                if status >= 400:
                    raise urllib.error.HTTPError(url, status, "error", {}, io.BytesIO(payload))
                return _FakeHTTPResponse(status, payload)
        raise AssertionError(f"unexpected API call: {method} {url}")
    return _fake


def _commit_args(a, accept_json, out_path, token="test-token"):
    return argparse.Namespace(
        state_dir=str(a),
        acceptance_file=accept_json,
        relay="https://github.com/owner/pair-relay.git",
        transport=None,
        local_relay_dir=None,
        token=token,
        capability=None,
        i_compared_phrase=True,
        out=str(out_path),
    )


def _relationships(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT relationship_id FROM relationships").fetchall()
    finally:
        conn.close()


def test_commit_rolls_back_second_key_registration_failure(tmp_path, monkeypatch):
    """Second deploy-key registration fails: no relationship committed,
    first key deleted from GitHub, local deploy key removed, invite usable."""
    a, accept_json = _setup_paired(tmp_path, monkeypatch)
    out_path = tmp_path / "commit.json"
    calls = []
    script = [
        ("POST", "/repos/owner/pair-relay/keys", 201,
         json.dumps({"id": 111, "key": "peer-pub", "title": "t"}).encode()),
        ("POST", "/repos/owner/pair-relay/keys", 422,
         json.dumps({"message": "Validation Failed",
                     "errors": [{"message": "key is already in use"}]}).encode()),
        ("DELETE", "/repos/owner/pair-relay/keys/111", 204, b""),
    ]
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen_factory(script, calls))

    with pytest.raises(CliError) as exc_info:
        cmd_pair_commit(_commit_args(a, accept_json, out_path))
    assert exc_info.value.code == "provisioning_error"

    # No relationship row was committed.
    assert _relationships(str(a / "state.db")) == []

    # The first (already registered) key was rolled back via DELETE.
    assert ("DELETE", "https://api.github.com/repos/owner/pair-relay/keys/111") in calls

    # The locally generated inviter deploy private key was removed.
    inviter_keys = list((a / "keys" / "pairing").rglob("deploy-inviter"))
    assert inviter_keys == []

    # The invite is still usable for a retry: still in 'accepted' state,
    # not burned or marked committed.
    conn = sqlite3.connect(str(a / "state.db"))
    try:
        state = conn.execute("SELECT state FROM invites").fetchone()[0]
    finally:
        conn.close()
    assert state == "accepted"


def test_commit_provisions_before_local_commit_and_succeeds(tmp_path, monkeypatch):
    """Happy path: both keys registered first, then the local commit lands."""
    a, accept_json = _setup_paired(tmp_path, monkeypatch)
    out_path = tmp_path / "commit.json"
    calls = []
    script = [
        ("POST", "/repos/owner/pair-relay/keys", 201,
         json.dumps({"id": 111, "key": "peer-pub", "title": "t"}).encode()),
        ("POST", "/repos/owner/pair-relay/keys", 201,
         json.dumps({"id": 222, "key": "self-pub", "title": "t"}).encode()),
    ]
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen_factory(script, calls))

    rc = cmd_pair_commit(_commit_args(a, accept_json, out_path))
    assert rc == 0

    # Both registrations happened before anything was committed.
    methods = [c[0] for c in calls]
    assert methods == ["POST", "POST"]
    assert all(c[1].endswith("/repos/owner/pair-relay/keys") for c in calls)

    rows = _relationships(str(a / "state.db"))
    assert len(rows) == 1
    commit = json.loads(out_path.read_text(encoding="utf-8"))
    assert commit["relationship_id"] == rows[0][0]


def test_commit_local_failure_rolls_back_provisioned_keys(tmp_path, monkeypatch):
    """Both keys registered, then the local commit fails: both keys deleted,
    no relationship row."""
    a, accept_json = _setup_paired(tmp_path, monkeypatch)
    out_path = tmp_path / "commit.json"
    calls = []
    script = [
        ("POST", "/repos/owner/pair-relay/keys", 201,
         json.dumps({"id": 111, "key": "peer-pub", "title": "t"}).encode()),
        ("POST", "/repos/owner/pair-relay/keys", 201,
         json.dumps({"id": 222, "key": "self-pub", "title": "t"}).encode()),
        ("DELETE", "/repos/owner/pair-relay/keys/111", 204, b""),
        ("DELETE", "/repos/owner/pair-relay/keys/222", 204, b""),
    ]
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen_factory(script, calls))

    # Corrupt the acceptance so the local commit fails after provisioning.
    bad = json.loads(open(accept_json, encoding="utf-8").read())
    bad["signature"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    bad_path = tmp_path / "accept-bad.json"
    bad_path.write_text(json.dumps(bad), encoding="utf-8")

    with pytest.raises(CliError) as exc_info:
        cmd_pair_commit(_commit_args(a, bad_path, out_path))
    assert exc_info.value.code == "pairing_error"

    assert _relationships(str(a / "state.db")) == []
    deletes = [c for c in calls if c[0] == "DELETE"]
    assert len(deletes) == 2
