"""Regression: private key material must live under <state>/keys/, never in
the state root (MEDIUM 2).

Three cli.py call sites built RotationManager(ctx.conn, ctx.state_dir),
so rotation candidate keys (<rid>-e<epoch>.key) were written directly
into the state directory root. They must go to ctx.keys_dir.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

PY = sys.executable
SRC = Path(__file__).resolve().parents[2] / "src"


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


@pytest.fixture()
def paired(tmp_path):
    root = tmp_path
    a = root / "a"
    b = root / "b"
    relay = root / "relay"
    for d in (a, b, relay):
        d.mkdir()
    assert run_cli(a, "init", "--display-name", "Alice")[0] == 0
    assert run_cli(b, "init", "--display-name", "Bob")[0] == 0
    invite_txt = root / "invite.txt"
    assert run_cli(a, "pair", "invite", "--out", str(invite_txt))[0] == 0
    accept_json = root / "accept.json"
    assert run_cli(
        b, "pair", "accept",
        "--invite-file", str(invite_txt),
        "--i-compared-phrase",
        "--out", str(accept_json),
    )[0] == 0
    commit_json = root / "commit.json"
    rc, out, err = run_cli(
        a, "pair", "commit",
        "--acceptance-file", str(accept_json),
        "--relay", "https://example.invalid/relay",
        "--transport", "local",
        "--local-relay-dir", str(relay),
        "--i-compared-phrase",
        "--out", str(commit_json),
    )
    assert rc == 0, err
    assert run_cli(
        b, "pair", "ingest",
        "--commit-file", str(commit_json),
        "--local-relay-dir", str(relay),
    )[0] == 0
    rid = None
    import json as _json
    rid = _json.loads(commit_json.read_text(encoding="utf-8"))["relationship_id"]
    return a, b, rid


def _root_key_files(state_dir):
    return [
        p for p in Path(state_dir).iterdir()
        if p.is_file() and p.suffix == ".key"
    ]


def test_rotation_candidate_keys_live_under_keys_dir(paired):
    """`mas rotate --prepare` writes the candidate private key under
    <state>/keys/, not in the state root."""
    a, b, rid = paired
    rc, out, err = run_cli(a, "rotate", "--relationship", rid, "--prepare")
    assert rc == 0, err
    expected = Path(a) / "keys" / f"{rid}-e2.key"
    assert expected.exists(), f"candidate key missing at {expected}"
    assert (expected.stat().st_mode & 0o777) == 0o600
    assert _root_key_files(a) == []


def test_no_key_files_in_state_root_after_pairing(paired):
    """The full pairing flow leaves no private key files in the state root."""
    a, b, rid = paired
    assert _root_key_files(a) == []
    assert _root_key_files(b) == []
