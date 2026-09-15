"""Gate: delivery policy CLI (H10).

`mas policy set <relationship> <key> <value>` must wire each key to the
real delivery-policy setter with validation (booleans, expiry window),
and `mas policy get` must read the policy back. The end-to-end proof:
switching mode from alert to silent suppresses surfacing of a newly
received message (surfaces drops to 0) while the event is still
persisted.
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


class PolicyCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.a = self.root / "a"
        self.b = self.root / "b"
        self.relay = self.root / "relay"
        for d in (self.a, self.b, self.relay):
            d.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def pair_active(self):
        code, out, err = run_cli(self.a, "init", "--display-name", "Alice")
        self.assertEqual(code, 0, err)
        code, out, err = run_cli(self.b, "init", "--display-name", "Bob")
        self.assertEqual(code, 0, err)
        invite = self.root / "invite.txt"
        code, out, err = run_cli(self.a, "pair", "invite", "--out", str(invite))
        self.assertEqual(code, 0, err)
        accept = self.root / "accept.json"
        code, out, err = run_cli(
            self.b, "pair", "accept", "--invite-file", str(invite),
            "--i-compared-phrase", "--out", str(accept),
        )
        self.assertEqual(code, 0, err)
        commit = self.root / "commit.json"
        code, out, err = run_cli(
            self.a, "pair", "commit", "--acceptance-file", str(accept),
            "--relay", "https://example.com/relay", "--transport", "local",
            "--local-relay-dir", str(self.relay),
            "--i-compared-phrase", "--out", str(commit),
        )
        self.assertEqual(code, 0, err)
        code, out, err = run_cli(
            self.b, "pair", "ingest", "--commit-file", str(commit),
            "--local-relay-dir", str(self.relay),
        )
        self.assertEqual(code, 0, err)
        rid = out.strip()
        assert rid
        for d in (self.a, self.b):
            code, out, err = run_cli(
                d, "send", "--relationship", rid,
                "--type", "relationship.ready",
            )
            self.assertEqual(code, 0, err)
        for _ in range(4):
            run_cli(self.a, "receive", "--json")
            run_cli(self.b, "receive", "--json")
        return rid

    def b_surfaces(self):
        code, out, err = run_cli(self.b, "receive", "--json")
        self.assertEqual(code, 0, err)
        return json.loads(out)["totals"]["surfaces"]

    def test_policy_set_get_and_surface_suppression(self):
        rid = self.pair_active()

        # Default mode is silent; switch B to alert so messages surface.
        code, out, err = run_cli(
            self.b, "policy", "set", rid, "mode", "alert")
        self.assertEqual(code, 0, (out, err))

        code, out, err = run_cli(
            self.a, "send", "--relationship", rid,
            "--type", "message.created", "--body", "hello one")
        self.assertEqual(code, 0, err)
        self.assertGreater(self.b_surfaces(), 0,
                           "alert mode must surface the message")

        # Get reads the policy back.
        code, out, err = run_cli(self.b, "policy", "get", rid, "mode")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), "alert")

        # Switch back to silent: the next message is persisted but never
        # surfaced.
        code, out, err = run_cli(
            self.b, "policy", "set", rid, "mode", "silent")
        self.assertEqual(code, 0, (out, err))
        code, out, err = run_cli(
            self.a, "send", "--relationship", rid,
            "--type", "message.created", "--body", "hello two")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.b_surfaces(), 0,
                         "silent mode must suppress surfacing")

    def test_policy_set_booleans(self):
        rid = self.pair_active()
        code, out, err = run_cli(
            self.b, "policy", "set", rid, "seen_receipts", "true")
        self.assertEqual(code, 0, (out, err))
        code, out, err = run_cli(
            self.b, "policy", "get", rid, "seen_receipts_enabled")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), "true")

        code, out, err = run_cli(
            self.b, "policy", "set", rid, "accepted_receipts", "off")
        self.assertEqual(code, 0, (out, err))
        code, out, err = run_cli(
            self.b, "policy", "get", rid, "accepted_receipts_enabled")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), "false")

    def test_policy_set_validation(self):
        rid = self.pair_active()

        code, out, err = run_cli(
            self.b, "policy", "set", rid, "bogus_key", "x")
        self.assertNotEqual(code, 0)
        self.assertIn("mode", err + out)

        code, out, err = run_cli(
            self.b, "policy", "set", rid, "mode", "shouty")
        self.assertNotEqual(code, 0)

        code, out, err = run_cli(
            self.b, "policy", "set", rid, "seen_receipts", "maybe")
        self.assertNotEqual(code, 0)

        # shorten requires a positive window.
        code, out, err = run_cli(
            self.b, "policy", "set", rid, "expiry_handling", "shorten")
        self.assertNotEqual(code, 0)
        code, out, err = run_cli(
            self.b, "policy", "set", rid,
            "expiry_shorten_after_seconds", "3600")
        self.assertEqual(code, 0, (out, err))
        code, out, err = run_cli(
            self.b, "policy", "get", rid, "expiry_handling")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), "shorten")
        code, out, err = run_cli(
            self.b, "policy", "set", rid, "expiry_handling", "honor")
        self.assertEqual(code, 0, (out, err))
        code, out, err = run_cli(
            self.b, "policy", "set", rid,
            "expiry_shorten_after_seconds", "-5")
        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
