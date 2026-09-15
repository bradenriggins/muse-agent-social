"""Medium 2d: post-receive hook failures are logged loudly, never fatal.

A failing hook (rotation ceremony step, activation, bookkeeping) must not
wedge or roll back the receive: the event is already durably accepted and
surfaced. The failure is reported on stderr with the exception attached.
"""

from types import SimpleNamespace

import muse_agent_social.cli as cli_mod
from muse_agent_social.policy.delivery import set_accepted_receipts_enabled
from support.harness import (
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)


def _oname(tag: str) -> str:
    return (tag + "0" * 32)[:32] + ".json"


def test_hook_failure_warns_and_receive_still_accepted(tmp_path, capsys, monkeypatch):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    provision_receive_side(conn, rid, bob, alice)
    # Keep the receipt path out of the test; the hook block runs anyway.
    set_accepted_receipts_enabled(conn, rid, False)
    conv = new_conversation(conn)
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "hello", "format": "plain"}, seq=1,
    )
    cli_mod._ensure_cli_tables(conn)
    ctx = SimpleNamespace(conn=conn, state_dir=tmp_path, identity_id=bob["identity_id"])

    def boom(*args, **kwargs):
        raise RuntimeError("hook exploded")

    monkeypatch.setattr(cli_mod, "_post_receive_hooks", boom)

    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object_inner(ctx, rid, _oname("hookfail"), raw, acc)

    assert outcome["outcome"] == "accepted"
    err = capsys.readouterr().err
    assert "warning: post-receive hook failed" in err
    assert "hook exploded" in err
    # The event is fully persisted despite the hook failure.
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM replay_guard").fetchone()[0] == 1
