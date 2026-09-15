"""Gate: identity-key rotation CLI (H11).

`mas rotate --identity` must rotate the identity signing key with the
existing crypto (rotate_identity_key / verify_identity_rotation),
reissue the local agent card, persist a verifiable announcement, and
notify each active peer with a signed identity.rotated event sent as
the old identity before the local switch.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PY = sys.executable
SRC = Path(__file__).resolve().parents[2] / "src"


def run_cli(state_dir, *args):
    """Run the worktree CLI in a subprocess. Never touches mas-release."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    env["MAS_RELEASE_SRC"] = str(SRC)
    proc = subprocess.run(
        [PY, "-m", "muse_agent_social.cli", "--state-dir", str(state_dir), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
    )
    return proc.returncode, proc.stdout, proc.stderr


class RotateIdentityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.a = self.root / "a"
        self.a.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_rotate_identity(self):
        code, out, err = run_cli(self.a, "init", "--display-name", "Alice")
        self.assertEqual(code, 0, err)
        old_identity_id = [
            line.split("identity ", 1)[1]
            for line in out.splitlines()
            if line.startswith("identity ")
        ][0]
        old_card = json.loads((self.a / "agent-card.json").read_text())

        # Destructive action: requires explicit confirmation.
        # Destructive action: requires explicit confirmation.
        code, out, err = run_cli(self.a, "rotate", "--identity")
        self.assertNotEqual(code, 0)

        code, out, err = run_cli(self.a, "rotate", "--identity", "--confirm-identity")
        self.assertEqual(code, 0, (out, err))

        # The card is reissued under a new identity id.
        new_card = json.loads((self.a / "agent-card.json").read_text())
        new_identity_id = new_card["identity_id"]
        self.assertNotEqual(new_identity_id, old_identity_id)
        self.assertIn(old_identity_id, out)
        self.assertIn(new_identity_id, out)

        # The old seed and card are backed up, not destroyed.
        seed_backups = list((self.a / "keys").glob("master.seed.backup-*"))
        card_backups = list(self.a.glob("agent-card.json.backup-*"))
        self.assertEqual(len(seed_backups), 1)
        self.assertEqual(len(card_backups), 1)
        self.assertEqual(
            json.loads(card_backups[0].read_text())["identity_id"],
            old_identity_id,
        )

        # The announcement is persisted and self-verifies against the
        # old card with the shipped verifier.
        ann_files = list((self.a / "identity-rotations").glob("*.json"))
        self.assertEqual(len(ann_files), 1)
        self.assertIn(str(ann_files[0]), out)
        announcement = json.loads(ann_files[0].read_text())
        self.assertEqual(announcement["new_card"]["identity_id"],
                         new_identity_id)

        sys.path.insert(0, str(SRC))
        try:
            from muse_agent_social.crypto.rotation import (
                verify_identity_rotation,
            )
        finally:
            sys.path.remove(str(SRC))
        self.assertTrue(verify_identity_rotation(announcement, old_card))

        # The announcement is also delivered in-protocol: with no active
        # relationships here, the fallback note about out-of-band delivery
        # must still be present.
        self.assertIn("out-of-band", out.lower() + err.lower())

        # The install still opens and works under the new identity.
        code, out, err = run_cli(self.a, "inspect", "relationships")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
