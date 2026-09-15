"""H6 completion: `mas inspect scheduled` exposes dead-letter rows.

Dead-lettered scheduler rows (state "dead") must be inspectable from the
CLI, not just the Python API. This test drives the real CLI in-process:
init an installation, schedule a row, fail its release three times, then
prove `inspect scheduled --state dead` lists it and a bogus state errors.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from muse_agent_social.cli import main
from muse_agent_social.scheduler import MAX_RELEASE_ATTEMPTS, run_due, schedule
from muse_agent_social.store.db import open_db


def _past():
    return (
        datetime.now(timezone.utc) - timedelta(minutes=5)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _init(state_dir: Path) -> None:
    code = main(
        ["--state-dir", str(state_dir), "init", "--display-name", "InspectTest"]
    )
    assert code == 0


def _dead_letter_one(state_dir: Path) -> str:
    conn = open_db(state_dir)
    try:
        scheduled_id = schedule(conn, b"fake-sealed-bytes", _past(), None)

        def boom(*, scheduled_id, sealed_event_envelope, late_by_seconds):
            raise RuntimeError("release exploded")

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for _ in range(MAX_RELEASE_ATTEMPTS):
            run_due(conn, now, boom)
        row = conn.execute(
            "SELECT state FROM scheduler_queue WHERE scheduled_id = ?",
            (scheduled_id,),
        ).fetchone()
        assert row["state"] == "dead"
        return scheduled_id
    finally:
        conn.close()


def test_inspect_scheduled_dead_lists_dead_rows(tmp_path, capsys):
    state_dir = tmp_path / "agent"
    _init(state_dir)
    capsys.readouterr()  # drain init chatter
    dead_id = _dead_letter_one(state_dir)

    code = main(
        ["--state-dir", str(state_dir), "inspect", "scheduled",
         "--state", "dead"]
    )
    assert code == 0
    rows = json.loads(capsys.readouterr().out)
    assert any(
        r["scheduled_id"] == dead_id and r["state"] == "dead" for r in rows
    ), rows


def test_inspect_scheduled_all_lists_every_state(tmp_path, capsys):
    state_dir = tmp_path / "agent"
    _init(state_dir)
    capsys.readouterr()  # drain init chatter
    dead_id = _dead_letter_one(state_dir)
    conn = open_db(state_dir)
    try:
        live_id = schedule(conn, b"fake-sealed-bytes", _past(), None)
    finally:
        conn.close()

    code = main(["--state-dir", str(state_dir), "inspect", "scheduled"])
    assert code == 0
    rows = json.loads(capsys.readouterr().out)
    by_id = {r["scheduled_id"]: r["state"] for r in rows}
    assert by_id.get(dead_id) == "dead"
    assert by_id.get(live_id) == "scheduled"


def test_inspect_scheduled_bogus_state_errors(tmp_path, capsys):
    state_dir = tmp_path / "agent"
    _init(state_dir)
    capsys.readouterr()  # drain init chatter
    code = main(
        ["--state-dir", str(state_dir), "inspect", "scheduled",
         "--state", "bogus"]
    )
    assert code != 0
    assert "invalid_state" in capsys.readouterr().err
