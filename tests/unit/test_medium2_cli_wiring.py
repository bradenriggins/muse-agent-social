"""Medium 2a/2b: direct tests for the scheduler CLI wiring.

_warn_overdue_scheduled must warn loudly on stderr when scheduled rows
are past deliver_at and stay silent otherwise. --clock-skew-seconds
must be accepted on the send and receive parsers and arrive as a float.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import muse_agent_social.cli as cli_mod
from muse_agent_social.scheduler import schedule
from support.harness import fresh_db


def _past():
    return (
        datetime.now(timezone.utc) - timedelta(minutes=5)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_warn_overdue_scheduled_warns(tmp_path, capsys):
    conn = fresh_db(tmp_path / "state.db")
    schedule(conn, b"x", _past(), None)
    cli_mod._warn_overdue_scheduled(SimpleNamespace(conn=conn))
    err = capsys.readouterr().err
    assert "past deliver_at" in err
    assert "1 scheduled event(s)" in err


def test_warn_overdue_scheduled_quiet_when_none(tmp_path, capsys):
    conn = fresh_db(tmp_path / "state.db")
    cli_mod._warn_overdue_scheduled(SimpleNamespace(conn=conn))
    assert capsys.readouterr().err == ""


def test_send_parser_accepts_clock_skew_seconds():
    args = cli_mod.build_parser().parse_args(
        ["send", "--type", "message.created", "--clock-skew-seconds", "300"]
    )
    assert args.clock_skew_seconds == 300.0


def test_receive_parser_accepts_clock_skew_seconds():
    args = cli_mod.build_parser().parse_args(
        ["receive", "--clock-skew-seconds", "45"]
    )
    assert args.clock_skew_seconds == 45.0
