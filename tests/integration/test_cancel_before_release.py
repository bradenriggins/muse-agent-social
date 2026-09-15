"""Gate: cancel-before-release (H7).

Scenario: the user schedules a capsule for 09:00 and cancels at 08:59.
The cancel send must claim the cancellation BEFORE run_due() can
release the row; otherwise the cancel triggers the very release it was
meant to prevent, the CLI reports success, and the user believes the
capsule was canceled when it was delivered.

The test simulates time passing by moving the row's deliver_at into the
past while the row is still unreleased (an idle install only releases
on send/receive), then cancels and proves:
  * the cancel command exits 0 and reports the cancellation truthfully,
  * the scheduler row ends in state "canceled", never "released",
  * a later run_due (another send) still does not release it,
  * the peer never receives the delivery.scheduled payload, while the
    delivery.canceled notice itself does arrive.
"""

import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

PY = sys.executable
SRC = Path(__file__).resolve().parents[2] / "src"
UTC = timezone.utc


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


def db(state_dir):
    conn = sqlite3.connect(str(Path(state_dir) / "state.db"))
    conn.row_factory = sqlite3.Row
    return conn


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class CancelBeforeReleaseTest(unittest.TestCase):
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

    def test_cancel_before_deliver_at_wins(self):
        rid = self.pair_active()
        now = datetime.now(UTC).replace(microsecond=0)

        # A sends a message to reference as the capsule's inner event.
        code, out, err = run_cli(
            self.a, "send", "--relationship", rid,
            "--type", "message.created", "--body", "capsule payload",
        )
        self.assertEqual(code, 0, err)
        inner_id = out.strip().split()[1]

        # A schedules a capsule one hour out. Its own send must not
        # release it (not due yet).
        code, out, err = run_cli(
            self.a, "send", "--relationship", rid,
            "--type", "delivery.scheduled",
            "--inner-event-id", inner_id,
            "--deliver-at", ts(now + timedelta(hours=1)),
        )
        self.assertEqual(code, 0, err)
        sched_id = out.strip().split()[1]
        with db(self.a) as conn:
            state = conn.execute(
                "SELECT state FROM scheduler_queue WHERE scheduled_id = ?",
                (sched_id,),
            ).fetchone()["state"]
        self.assertEqual(state, "scheduled")

        # Time passes with the install idle: the row is now due but was
        # never released.
        with db(self.a) as conn:
            conn.execute(
                "UPDATE scheduler_queue SET deliver_at = ? "
                "WHERE scheduled_id = ?",
                (ts(now - timedelta(minutes=1)), sched_id),
            )

        # The user cancels. The cancel must win over the pending release.
        code, out, err = run_cli(
            self.a, "send", "--relationship", rid,
            "--type", "delivery.canceled",
            "--scheduled-event-id", sched_id,
        )
        self.assertEqual(code, 0, err)
        self.assertIn("canceled", out.lower(),
                      f"cancel must report truthfully: stdout={out!r}")

        # The row is canceled, never released ...
        with db(self.a) as conn:
            state = conn.execute(
                "SELECT state FROM scheduler_queue WHERE scheduled_id = ?",
                (sched_id,),
            ).fetchone()["state"]
        self.assertEqual(state, "canceled")

        # ... and a later send (which runs run_due again) still does not
        # release it.
        code, out, err = run_cli(
            self.a, "send", "--relationship", rid,
            "--type", "message.created", "--body", "after cancel",
        )
        self.assertEqual(code, 0, err)
        with db(self.a) as conn:
            state = conn.execute(
                "SELECT state FROM scheduler_queue WHERE scheduled_id = ?",
                (sched_id,),
            ).fetchone()["state"]
        self.assertEqual(state, "canceled")

        # The peer never receives the capsule payload, but does receive
        # the cancel notice.
        for _ in range(4):
            run_cli(self.a, "receive", "--json")
            run_cli(self.b, "receive", "--json")
        with db(self.b) as conn:
            types = [
                r[0] for r in conn.execute(
                    "SELECT event_type FROM events WHERE relationship_id = ?",
                    (rid,),
                ).fetchall()
            ]
        self.assertNotIn("delivery.scheduled", types,
                         "the capsule payload must never be delivered")
        self.assertIn("delivery.canceled", types,
                      "the cancel notice itself must arrive")


if __name__ == "__main__":
    unittest.main()
