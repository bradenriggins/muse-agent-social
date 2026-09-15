"""Regression: `mas pair accept` must validate the acceptance BEFORE writing
any key material to disk (MEDIUM 1).

The old order generated and stored relationship.key, the deploy private
key, and deploy.pub, and only then ran create_acceptance(). A rejected
acceptance (bad signature, expired invite) left orphaned private key files
on disk with no database record pointing at them.
"""

import base64
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

PY = sys.executable
SRC = Path(__file__).resolve().parents[2] / "src"


def _tamper_signature(text):
    """Flip the first byte of the invite signature inside the pair URI."""
    scheme, frag = text.strip().split("#", 1)
    raw = base64.urlsafe_b64decode(frag + "=" * (-len(frag) % 4))
    invite = json.loads(raw)
    sig = invite["signature"]
    invite["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    new_frag = base64.urlsafe_b64encode(
        json.dumps(invite, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    return scheme + "#" + new_frag


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
def two_agents(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert run_cli(a, "init", "--display-name", "Alice")[0] == 0
    assert run_cli(b, "init", "--display-name", "Bob")[0] == 0
    invite_txt = tmp_path / "invite.txt"
    assert run_cli(a, "pair", "invite", "--out", str(invite_txt))[0] == 0
    return a, b, invite_txt


def _key_files(b):
    return list((b / "keys").rglob("*")) if (b / "keys").exists() else []


def _acceptance_rows(b):
    conn = sqlite3.connect(str(b / "state.db"))
    try:
        return conn.execute("SELECT COUNT(*) FROM pairing_acceptances").fetchone()[0]
    finally:
        conn.close()


def test_rejected_acceptance_leaves_no_key_files(two_agents, tmp_path):
    """A tampered invite signature fails create_acceptance; no private key
    files may be left on disk and no acceptance row may linger."""
    a, b, invite_txt = two_agents
    bad = tmp_path / "invite-bad.txt"
    bad.write_text(
        _tamper_signature(invite_txt.read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    rc, out, err = run_cli(
        b, "pair", "accept",
        "--invite-file", str(bad),
        "--i-compared-phrase",
        "--out", str(tmp_path / "accept.json"),
    )
    assert rc != 0
    # No key material was written.
    leftovers = [p for p in _key_files(b) if "pairing" in str(p)]
    assert leftovers == []
    # No half-written acceptance record either.
    assert _acceptance_rows(b) == 0


def test_retry_after_rejection_succeeds_cleanly(two_agents, tmp_path):
    """After a rejected attempt, a corrected accept succeeds and writes the
    expected key files exactly once."""
    a, b, invite_txt = two_agents
    bad = tmp_path / "invite-bad.txt"
    bad.write_text(
        _tamper_signature(invite_txt.read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    assert run_cli(
        b, "pair", "accept",
        "--invite-file", str(bad),
        "--i-compared-phrase",
        "--out", str(tmp_path / "accept-bad.json"),
    )[0] != 0

    accept_json = tmp_path / "accept.json"
    rc, out, err = run_cli(
        b, "pair", "accept",
        "--invite-file", str(invite_txt),
        "--i-compared-phrase",
        "--out", str(accept_json),
    )
    assert rc == 0, err
    assert _acceptance_rows(b) == 1
    acceptance = json.loads(accept_json.read_text(encoding="utf-8"))
    pair_dir = b / "keys" / "pairing" / acceptance["invite_id"]
    assert (pair_dir / "relationship.key").exists()
    assert (pair_dir / "deploy").exists()
    assert (pair_dir / "deploy.pub").exists()
    assert (pair_dir / "pairing.json").exists()
