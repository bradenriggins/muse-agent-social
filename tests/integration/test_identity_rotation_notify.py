"""Send side: `mas rotate --identity` notifies active peers in-protocol.

_rotate_identity must queue a signed identity.rotated event for each
active relationship BEFORE switching the local identity, so the event is
sealed and signed as the OLD identity (the one the peer still has
pinned). After the switch the local card and identity id change.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

PY = sys.executable
SRC = Path(__file__).resolve().parents[2] / "src"


def run_cli(state_dir, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    proc = subprocess.run(
        [PY, "-m", "muse_agent_social.cli", "--state-dir", str(state_dir), *args],
        capture_output=True, text=True, env=env, timeout=120,
    )
    return proc.returncode, proc.stdout, proc.stderr


@pytest.fixture()
def alice_state(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    code, out, err = run_cli(a, "init", "--display-name", "Alice")
    assert code == 0, err
    return a


def test_rotate_identity_notifies_active_peers(alice_state):
    sys.path.insert(0, str(SRC))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        import muse_agent_social.cli as cli_mod
        from muse_agent_social.crypto.identity import (
            agreement_key_multibase_from_pubkey,
        )
        from support.harness import make_agent, provision_receive_side
        from types import SimpleNamespace

        ctx = cli_mod.Ctx(alice_state)
        old_id = ctx.identity_id
        bob = make_agent("Bob", "PrincipalB")
        # Alice's side of the relationship: fresh relationship keypair.
        alice_rel_priv = X25519PrivateKey.generate()
        alice_agent = {
            "identity_id": old_id,
            "rel_priv": alice_rel_priv,
            "rel_pub_mb": agreement_key_multibase_from_pubkey(
                alice_rel_priv.public_key().public_bytes_raw()
            ),
            "card": ctx.card,
        }
        rid = "bbbbbbbb-cccc-4ddd-8eee-000000000002"
        provision_receive_side(
            ctx.conn, rid, alice_agent, bob, keys_dir=str(ctx.keys_dir)
        )

        args = SimpleNamespace(confirm_identity=True)
        assert cli_mod._rotate_identity(ctx, args) == 0

        # An identity.rotated event was queued, sent as the OLD identity.
        rows = ctx.conn.execute(
            "SELECT event_id, sender, event_type FROM events "
            "WHERE event_type = 'identity.rotated'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["sender"] == old_id

        # The staged payload is the rotation announcement for the new identity.
        payload_row = ctx.conn.execute(
            "SELECT payload FROM event_payloads WHERE event_id = ?",
            (rows[0]["event_id"],),
        ).fetchone()
        announcement = json.loads(payload_row["payload"])
        new_id = announcement["new_card"]["identity_id"]
        assert new_id != old_id

        # The local identity actually switched to the announced new identity.
        card = json.loads((alice_state / "agent-card.json").read_text())
        assert card["identity_id"] == new_id
    finally:
        sys.path.remove(str(SRC))
        sys.path.remove(str(Path(__file__).resolve().parents[1]))
