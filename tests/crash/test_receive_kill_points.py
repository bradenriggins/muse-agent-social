"""Crash tests: kill points across the receive pipeline.

For each kill point the test crashes the receive once (FaultInjected),
asserts the durable state left behind, then resumes by re-delivering the
same bytes and asserts exactly-once projection and exactly-once
human-visible surface.

Resume outcomes:
  * kill before the commit transaction finishes -> full reprocess,
    outcome "accepted";
  * kill after the commit transaction finishes -> idempotent resume,
    outcome "accepted_duplicate".

In every case the final state is: one event row, one projected message,
one receipt, one surface_log row, an empty surface queue, and exactly one
notification.
"""

import pytest

from muse_agent_social.transports.local import LocalTransport

from support.harness import (
    FaultInjected,
    ReceiveHarness,
    deliver,
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)


def _oname(tag: str) -> str:
    return (tag + "0" * 32)[:32] + ".json"


@pytest.fixture()
def setup(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "44444444-5555-4666-8777-888888888888"
    provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    harness = ReceiveHarness(
        conn,
        relationship_id=rid,
        own_identity_id=bob["identity_id"],
        own_rel_priv=bob["rel_priv"],
        transport=LocalTransport(tmp_path / "relay"),
    )
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "crash me", "format": "plain"}, seq=1,
    )
    return {"harness": harness, "raw": raw}


# Kill points where the commit transaction never finished: everything
# rolled back, resume reprocesses fully.
ROLLBACK_POINTS = [
    "after_inbox_stage",
    "during_commit_after_events",
    "during_commit_after_guard",
    "during_commit_after_project",
    "during_commit_after_receipt",
    "during_commit_after_surface_enqueue",
]

# Kill points where the commit transaction finished: resume is idempotent.
COMMITTED_POINTS = [
    "after_commit",
    "before_consume",
    "after_consume_before_surface",
    "during_surface_mark",
]


def _crash_and_resume(setup, point: str) -> dict:
    h = setup["harness"]
    name = _oname(point.replace("_", "")[:24])
    h.fault_at = point
    with pytest.raises(FaultInjected):
        deliver(h, setup["raw"], name)
    return {"harness": h, "name": name}


@pytest.mark.parametrize("point", ROLLBACK_POINTS)
def test_kill_before_commit_rolls_back_and_resumes_exactly_once(
    setup, point
):
    """Crash inside (or before) the commit transaction: no partial state
    survives; resume reprocesses the event exactly once."""
    ctx = _crash_and_resume(setup, point)
    h = ctx["harness"]
    assert h.count("events") == 0
    assert h.count("messages") == 0
    assert h.count("replay_guard") == 0
    assert h.count("surface_queue") == 0
    assert h.count("receipt_queue") == 0
    assert h.notified == []

    outcome = deliver(h, setup["raw"], ctx["name"])
    assert outcome["outcome"] == "accepted"
    assert h.count("events") == 1
    assert h.count("messages") == 1
    assert h.count("receipt_queue") == 1
    assert h.count("surface_queue") == 0
    assert h.count("surface_log") == 1
    assert len(h.notified) == 1


@pytest.mark.parametrize("point", COMMITTED_POINTS)
def test_kill_after_commit_resumes_idempotent_and_surfaces_once(
    setup, point
):
    """Crash after the commit transaction: the event is durable; resume is
    an idempotent no-op that still drains the surface exactly once."""
    ctx = _crash_and_resume(setup, point)
    h = ctx["harness"]
    assert h.count("events") == 1
    assert h.count("messages") == 1
    assert h.notified == []

    outcome = deliver(h, setup["raw"], ctx["name"])
    assert outcome["outcome"] == "accepted_duplicate"
    assert h.count("events") == 1
    assert h.count("messages") == 1
    assert h.count("receipt_queue") == 1
    assert h.count("surface_queue") == 0
    assert h.count("surface_log") == 1
    assert len(h.notified) == 1


def test_kill_during_surface_mark_preserves_queue_row(setup):
    """The during_surface_mark fault fires inside the marking transaction:
    the queue row survives the rollback and resume surfaces exactly once."""
    h = setup["harness"]
    name = _oname("surfacemark")
    h.fault_at = "during_surface_mark"
    with pytest.raises(FaultInjected):
        deliver(h, setup["raw"], name)
    # Mark rolled back: queue row preserved, nothing logged or notified.
    assert h.count("surface_queue") == 1
    assert h.count("surface_log") == 0
    assert h.notified == []

    outcome = deliver(h, setup["raw"], name)
    assert outcome["outcome"] == "accepted_duplicate"
    assert h.count("surface_queue") == 0
    assert h.count("surface_log") == 1
    assert len(h.notified) == 1


def test_crash_between_two_events_keeps_order_and_exactly_once(tmp_path):
    """A crash mid-commit on the second of two events: after resume both
    events are projected once, surfaced once, in sender order."""
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "55555555-6666-4777-8888-999999999999"
    provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    h = ReceiveHarness(
        conn,
        relationship_id=rid,
        own_identity_id=bob["identity_id"],
        own_rel_priv=bob["rel_priv"],
        transport=LocalTransport(tmp_path / "relay"),
    )
    _, raw1 = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "first", "format": "plain"}, seq=1,
    )
    _, raw2 = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "second", "format": "plain"}, seq=2,
    )
    assert deliver(h, raw1, _oname("e1"))["outcome"] == "accepted"

    h.fault_at = "during_commit_after_project"
    with pytest.raises(FaultInjected):
        deliver(h, raw2, _oname("e2"))

    outcome = deliver(h, raw2, _oname("e2"))
    assert outcome["outcome"] == "accepted"
    assert h.count("events") == 2
    assert h.count("messages") == 2
    assert h.count("surface_queue") == 0
    bodies = [
        r[0]
        for r in conn.execute(
            "SELECT body FROM messages ORDER BY sender_seq"
        ).fetchall()
    ]
    assert bodies == ["first", "second"]
    assert len(h.notified) == 2


def test_repeated_crash_same_kill_point_still_exactly_once(setup):
    """Two crashes at the same kill point before a successful resume:
    still exactly one projection and one notification."""
    h = setup["harness"]
    name = _oname("repeat")
    for _ in range(2):
        h.fault_at = "during_commit_after_receipt"
        with pytest.raises(FaultInjected):
            deliver(h, setup["raw"], name)
        assert h.count("events") == 0
    outcome = deliver(h, setup["raw"], name)
    assert outcome["outcome"] == "accepted"
    assert h.count("events") == 1
    assert h.count("messages") == 1
    assert len(h.notified) == 1
