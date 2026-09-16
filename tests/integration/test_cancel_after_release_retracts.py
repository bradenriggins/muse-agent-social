"""Gate: cancel-after-release emits a signed retraction (S10).

Scenario: the user schedules a capsule, it gets released, and only then
does the user cancel. The CLI has always promised that the cancel "became
a signed retraction request", but production never emitted anything: the
delivery.canceled event traveled while the peer kept the payload with no
retraction in flight.

The test releases a capsule first (by moving deliver_at into the past and
triggering run_due with another send), then cancels and proves:
  * the cancel command exits 0 and reports the retraction truthfully,
  * a real message.retracted event is persisted locally targeting the
    INNER message (the capsule payload), not the announcement,
  * the retraction is queued for upload to the peer.
"""

import json
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


class CancelAfterReleaseRetractsTest(unittest.TestCase):
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
        # Sticky verification flow: run 1 displays the phrase and exits 1
        # by design (phrase_confirmation_required); run 2 confirms it.
        code, out, err = run_cli(
            self.b, "pair", "accept", "--invite-file", str(invite),
            "--out", str(accept),
        )
        self.assertEqual(code, 1, err)
        self.assertIn("phrase_confirmation_required", err)
        code, out, err = run_cli(
            self.b, "pair", "accept", "--invite-file", str(invite),
            "--i-compared-phrase", "--out", str(accept),
        )
        self.assertEqual(code, 0, err)
        commit = self.root / "commit.json"
        # Commit run 1 displays the phrase and exits 1 by design
        # (phrase_confirmation_required); run 2 confirms it.
        code, out, err = run_cli(
            self.a, "pair", "commit", "--acceptance-file", str(accept),
            "--relay", "https://example.com/relay", "--transport", "local",
            "--local-relay-dir", str(self.relay),
            "--out", str(commit),
        )
        self.assertEqual(code, 1, err)
        self.assertIn("phrase_confirmation_required", err)
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

    def test_cancel_after_release_emits_retraction(self):
        rid = self.pair_active()
        now = datetime.now(UTC).replace(microsecond=0)

        # A sends the inner message that will become the capsule payload.
        code, out, err = run_cli(
            self.a, "send", "--relationship", rid,
            "--type", "message.created", "--body", "capsule payload",
        )
        self.assertEqual(code, 0, err)
        inner_id = out.strip().split()[1]

        # A schedules the capsule one hour out.
        code, out, err = run_cli(
            self.a, "send", "--relationship", rid,
            "--type", "delivery.scheduled",
            "--inner-event-id", inner_id,
            "--deliver-at", ts(now + timedelta(hours=1)),
        )
        self.assertEqual(code, 0, err)
        sched_id = out.strip().split()[1]

        # Time passes with the install idle, then another send triggers
        # run_due and releases the capsule.
        with db(self.a) as conn:
            conn.execute(
                "UPDATE scheduler_queue SET deliver_at = ? "
                "WHERE scheduled_id = ?",
                (ts(now - timedelta(minutes=1)), sched_id),
            )
        code, out, err = run_cli(
            self.a, "send", "--relationship", rid,
            "--type", "message.created", "--body", "trigger release",
        )
        self.assertEqual(code, 0, err)
        with db(self.a) as conn:
            state = conn.execute(
                "SELECT state FROM scheduler_queue WHERE scheduled_id = ?",
                (sched_id,),
            ).fetchone()["state"]
        self.assertEqual(state, "released")

        # The user cancels after release. The CLI must emit a real signed
        # retraction request, not just say it did.
        code, out, err = run_cli(
            self.a, "send", "--relationship", rid,
            "--type", "delivery.canceled",
            "--scheduled-event-id", sched_id,
        )
        self.assertEqual(code, 0, err)
        self.assertIn(
            "retract", out.lower(),
            f"cancel must report the retraction truthfully: stdout={out!r}",
        )

        # A message.retracted event exists locally and targets the INNER
        # message (the capsule payload), not the announcement.
        with db(self.a) as conn:
            rows = conn.execute(
                "SELECT e.event_id, p.payload FROM events e"
                " JOIN event_payloads p ON p.event_id = e.event_id"
                " WHERE e.event_type = 'message.retracted'",
            ).fetchall()
        self.assertEqual(len(rows), 1)
        payload = json.loads(rows[0]["payload"])
        self.assertEqual(payload["target_event_id"], inner_id)

        # The retraction is queued for upload to the peer: after a
        # receive round-trip, B sees the retraction and marks the inner
        # message retracted.
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
            retracted = conn.execute(
                "SELECT retracted FROM messages WHERE event_id = ?",
                (inner_id,),
            ).fetchone()
        self.assertIn("message.retracted", types,
                      "the retraction must reach the peer")
        self.assertIsNotNone(retracted)
        self.assertEqual(retracted["retracted"], 1)


if __name__ == "__main__":
    unittest.main()
