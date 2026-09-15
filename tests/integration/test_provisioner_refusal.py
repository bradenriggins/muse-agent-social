"""Gate: H3 - legacy provisioners cannot generate or persist peer private keys.

The v0.1 provisioners generated BOTH sides' deploy keys/credentials and
wrote the peer's private key into a pairing bundle. The v0.2 pairing model
forbids this: each side generates its own keypair through the `mas pair`
ceremony. bin/relay-setup-gh.py is now a thin repo-creation wrapper around
that ceremony and bin/relay-setup.py (R2, a transport v0.2 does not ship)
refuses to run. The stale v0.1 crypto scripts are deleted.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BIN = REPO / "bin"
PY = sys.executable

_PRIVATE_MARKERS = (b"PRIVATE KEY", b"openssh-key-v1")
_PRIVATE_FILENAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
}


def _run(script, *args, home):
    env = dict(os.environ, HOME=str(home))
    return subprocess.run(
        [PY, str(BIN / script), *args],
        capture_output=True, text=True, env=env, timeout=60,
    )


def _scan_for_private_material(root: Path):
    """Return paths under root that look like private key material."""
    hits = []
    if not root.exists():
        return hits
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name in _PRIVATE_FILENAMES or path.suffix in {".pem", ".key"}:
            # .key files are only suspicious when they hold key material;
            # check content below.
            pass
        try:
            head = path.read_bytes()[:4096]
        except OSError:
            continue
        if any(m in head for m in _PRIVATE_MARKERS):
            hits.append(path)
    return hits


def test_relay_setup_gh_dry_run_writes_no_private_material(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    proc = _run("relay-setup-gh.py", "--dry-run",
                "--repo-name", "test-relay-h3", home=home)
    assert proc.returncode == 0, proc.stderr
    assert _scan_for_private_material(home) == []
    assert "PRIVATE KEY" not in proc.stdout
    assert "deploy_private_key" not in proc.stdout
    # It hands off to the new ceremony instead of generating keys.
    assert "mas pair" in proc.stdout


def test_relay_setup_gh_refuses_legacy_peer_key_flags(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    proc = _run(
        "relay-setup-gh.py", "--dry-run",
        "--pair-id", "pair-deadbeef1234",
        "--peer", "someone", "--peer-agent-id", "agent:x",
        "--my-slot", "a", "--peer-slot", "b",
        home=home,
    )
    assert proc.returncode != 0
    combined = proc.stdout + proc.stderr
    assert "peer" in combined.lower() and "private" in combined.lower()
    # Nothing was generated or persisted anywhere.
    assert _scan_for_private_material(home) == []
    assert list(home.rglob("pairing-bundle-*")) == []


def test_relay_setup_gh_source_has_no_peer_key_generation():
    src = (BIN / "relay-setup-gh.py").read_text(encoding="utf-8")
    assert "deploy_private_key" not in src
    assert "ssh-keygen" not in src
    assert "pairing-bundle" not in src


def test_relay_setup_r2_refuses_to_provision(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    proc = _run(
        "relay-setup.py", "--dry-run",
        "--pair-id", "pair-deadbeef1234",
        "--peer", "someone", "--peer-agent-id", "agent:x",
        "--my-slot", "a", "--peer-slot", "b",
        home=home,
    )
    assert proc.returncode != 0
    combined = proc.stdout + proc.stderr
    assert "refus" in combined.lower()
    assert _scan_for_private_material(home) == []
    # No bundle, no relay config, nothing persisted.
    assert list(home.rglob("*")) == [] or all(
        p.is_dir() for p in home.rglob("*")
    )


def test_relay_setup_r2_teardown_also_refuses(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    proc = _run("relay-setup.py", "--teardown",
                "--pair-id", "pair-deadbeef1234", home=home)
    assert proc.returncode != 0


def test_stale_v01_crypto_scripts_deleted():
    for name in ("envelope_crypto.py", "gh_backend.py", "r2_backend.py"):
        assert not (BIN / name).exists(), f"bin/{name} must be deleted"


def test_nothing_imports_deleted_scripts():
    import re

    pattern = re.compile(r"envelope_crypto|gh_backend|r2_backend")
    offenders = []
    for root in (REPO / "src", REPO / "bin", REPO / "tests"):
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if pattern.search(text):
                # This test file itself names them; allow that.
                if path.name == "test_provisioner_refusal.py":
                    continue
                offenders.append(str(path.relative_to(REPO)))
    assert offenders == []
