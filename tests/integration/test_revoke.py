"""Gate: H5 - `mas revoke` is explicit, exact, and renders its summary.

- Revoking requires an explicit confirmation prompt (or --yes): declining
  performs zero destructive actions.
- The relationship must be given by its exact id: prefixes and peer
  labels are rejected.
- The post-teardown summary uses real TeardownReport attributes (the old
  code crashed with AttributeError after the keys were already destroyed).
"""

import json
import os
import sqlite3
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


def db_row(state_dir, rid):
    conn = sqlite3.connect(str(Path(state_dir) / "state.db"))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM relationships WHERE relationship_id = ?", (rid,)
        ).fetchone()
    finally:
        conn.close()


@pytest.fixture()
def paired(tmp_path):
    """Two inited agents with one live local-transport relationship."""
    root = tmp_path
    a = root / "a"
    b = root / "b"
    relay = root / "relay"
    for d in (a, b, relay):
        d.mkdir(parents=True)

    def cli(d, *args, **kw):
        code, out, err = run_cli(d, *args, **kw)
        assert code == 0, f"cli {' '.join(args)} failed: {err}"
        return out

    cli(a, "init", "--display-name", "Alice")
    cli(b, "init", "--display-name", "Bob")
    invite = root / "invite.txt"
    cli(a, "pair", "invite", "--out", str(invite))
    accept = root / "accept.json"
    cli(b, "pair", "accept", "--invite-file", str(invite),
        "--i-compared-phrase", "--out", str(accept))
    commit = root / "commit.json"
    cli(a, "pair", "commit", "--acceptance-file", str(accept),
        "--relay", "https://example.com/relay", "--transport", "local",
        "--local-relay-dir", str(relay),
        "--i-compared-phrase", "--out", str(commit))
    out = cli(b, "pair", "ingest", "--commit-file", str(commit),
              "--local-relay-dir", str(relay))
    rid = out.strip().splitlines()[0]
    assert rid
    return {"a": a, "b": b, "rid": rid}


def _key_files(state_dir):
    keys = Path(state_dir) / "keys"
    return [p for p in keys.rglob("*") if p.is_file()] if keys.exists() else []


def test_revoke_declined_prompt_performs_nothing(paired):
    rid = paired["rid"]
    keys_before = sorted(str(p) for p in _key_files(paired["a"]))
    assert keys_before, "expected key files before revoke"

    code, out, err = run_cli(
        paired["a"], "revoke", "--relationship", rid, stdin_text="no\n"
    )
    assert code != 0
    assert "abort" in err.lower()

    # Zero destructive actions: row intact, keys intact, no tombstone.
    row = db_row(paired["a"], rid)
    assert row is not None
    assert row["consent_state"] != "revoked"
    assert sorted(str(p) for p in _key_files(paired["a"])) == keys_before
    assert list((paired["a"] / "tombstones").glob("*")) == []


def test_revoke_rejects_prefix(paired):
    rid = paired["rid"]
    code, out, err = run_cli(
        paired["a"], "revoke", "--relationship", rid[:8], "--yes"
    )
    assert code != 0
    assert "unknown_relationship" in err
    # Nothing was torn down.
    assert db_row(paired["a"], rid) is not None


def test_revoke_rejects_peer_label(paired):
    rid = paired["rid"]
    code, out, err = run_cli(
        paired["a"], "revoke", "--relationship", "Bob", "--yes"
    )
    assert code != 0
    assert "unknown_relationship" in err
    assert db_row(paired["a"], rid) is not None


def test_revoke_confirmed_summary_renders_without_crash(paired):
    rid = paired["rid"]
    code, out, err = run_cli(
        paired["a"], "revoke", "--relationship", rid, "--yes"
    )
    assert code == 0, f"revoke failed: {err}"
    assert "Traceback" not in err
    summary = json.loads(out)
    # Real TeardownReport attributes, not the phantom cleanup/key_deletion.
    assert summary["reason_code"] == "operator"
    assert summary["tombstone_path"]
    assert summary["keys_destroyed"]
    assert summary["postcheck_hits"] == []
    assert "cleanup" not in summary
    # The relationship is gone.
    assert db_row(paired["a"], rid) is None


def test_revoke_revokes_remote_deploy_keys_by_id(paired, monkeypatch):
    """relay.json stores deploy key ids under "id"; revoke must DELETE the
    real key ids from the relay repo instead of falling back to manual."""
    import argparse

    sys.path.insert(0, str(SRC))
    from muse_agent_social import cli as cli_mod

    a = paired["a"]
    rid = paired["rid"]
    (a / "relay.json").write_text(
        json.dumps(
            {
                "deploy_keys": [
                    {
                        "id": 4242,
                        "title": f"mas-pair-{rid}",
                        "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest",
                        "role": "peer",
                    }
                ],
                "repos": [{"repo": "owner/pair-relay", "transport": "github"}],
            }
        ),
        encoding="utf-8",
    )
    calls = []

    def fake_api(self, method, path, payload=None):
        calls.append((method, path))
        return 204

    monkeypatch.setattr(cli_mod._RevokeHooks, "_api", fake_api)
    rc = cli_mod.cmd_revoke(
        argparse.Namespace(
            state_dir=str(a),
            relationship=rid,
            reason=None,
            token="test-token",
            delete_remote=False,
            yes=True,
        )
    )
    assert rc == 0
    assert ("DELETE", "/repos/owner/pair-relay/keys/4242") in calls
