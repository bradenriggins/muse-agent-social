"""Gate: Replay.

Duplicate event ID, duplicate replay nonce, duplicate
(relationship, sender, seq), and late replay after the 7-day window each
produce exactly one projection and one surface. Replays never re-decrypt
and never re-project.
"""

from datetime import datetime, timedelta, timezone

import pytest

from muse_agent_social.canonical import restricted_jcs
from muse_agent_social.transports.local import LocalTransport

from support.harness import (
    UTC,
    ReceiveHarness,
    deliver,
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
    random_object_name,
)


def oname(tag: str) -> str:
    """A relay-valid object name: exactly 32 word chars + .json."""
    base = (tag + "0" * 32)[:32]
    return base + ".json"


@pytest.fixture()
def setup(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "33333333-4444-4555-8666-777777777777"
    ctx = provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    transport = LocalTransport(tmp_path / "relay")
    harness = ReceiveHarness(
        conn,
        relationship_id=rid,
        own_identity_id=bob["identity_id"],
        own_rel_priv=bob["rel_priv"],
        transport=transport,
    )
    return {
        "alice": alice, "bob": bob, "conn": conn, "rid": rid,
        "conv": conv, "harness": harness, "transport": transport,
    }


def _seal(setup, seq, **kw):
    return make_sealed(
        setup["alice"], setup["bob"], setup["rid"], setup["conv"],
        "message.created", {"body": f"msg-{seq}", "format": "plain"},
        seq=seq, **kw,
    )


def _assert_single(setup, event_count=1):
    h = setup["harness"]
    assert h.count("events") == event_count
    assert h.count("messages") == event_count
    assert len(h.notified) == event_count
    assert h.count("surface_queue") == 0


def test_duplicate_event_id_same_bytes_idempotent(setup):
    h = setup["harness"]
    _, raw = _seal(setup, 1)
    first = deliver(h, raw, oname("a"))
    assert first["outcome"] == "accepted"
    second = deliver(h, raw, oname("b"))
    assert second["outcome"] in ("accepted_duplicate", "duplicate_ignored")
    _assert_single(setup)
    # The replay never reached decrypt: only the first object unsealed.
    assert h.unseal_attempts == [oname("a")]


def test_duplicate_event_id_arrives_late_after_replay_window(setup):
    """Late replay after the 7-day window: still exactly one projection and
    one surface, and no clock rejection for an already-accepted event."""
    h = setup["harness"]
    _, raw = _seal(setup, 1)
    assert deliver(h, raw, oname("a"))["outcome"] == "accepted"
    # Move the clock 30 days forward and shrink the guard artificially by
    # expiring the replay row, as the 7d+1h retention would.
    h.conn.execute("DELETE FROM replay_guard")
    h.conn.commit()
    h.now_fn = lambda: datetime.now(UTC) + timedelta(days=30)
    outcome = deliver(h, raw, oname("replay"))
    assert outcome["outcome"] in ("accepted_duplicate", "duplicate_ignored")
    _assert_single(setup)


def test_duplicate_nonce_different_event_id_ignored(setup):
    """Same replay nonce under a different event id: idempotent ignore, no
    second projection, no quarantine."""
    h = setup["harness"]
    env1, raw1 = _seal(setup, 1)
    assert deliver(h, raw1, oname("a"))["outcome"] == "accepted"
    # A buggy or malicious sender reuses the first event's replay nonce in
    # a fresh envelope. Transplant the nonce, then re-sign with the sender
    # key we hold in-test (nonce is inside the signed bytes).
    import copy
    env2, _ = _seal(setup, 2)
    env2 = copy.deepcopy(env2)
    env2["protected"]["replay_nonce"] = env1["protected"]["replay_nonce"]
    from muse_agent_social.crypto.identity import b64url_encode
    from muse_agent_social.canonical import restricted_jcs
    unsigned = {k: v for k, v in env2.items() if k != "signature"}
    env2["signature"] = b64url_encode(
        setup["alice"]["ed_priv"].sign(restricted_jcs(unsigned))
    )
    raw2 = restricted_jcs(env2)
    outcome = deliver(h, raw2, oname("b"))
    assert outcome["outcome"] == "duplicate_ignored"
    _assert_single(setup)
    assert h.count("quarantine") == 0


def test_duplicate_sequence_different_bytes_quarantined(setup):
    """Same (relationship, sender, seq) with different event bytes is a
    sequence fork: quarantined, never projected."""
    h = setup["harness"]
    _, raw1 = _seal(setup, 1)
    assert deliver(h, raw1, oname("a"))["outcome"] == "accepted"
    _, raw2 = _seal(setup, 1)  # same seq, fresh event id + nonce
    assert raw1 != raw2
    outcome = deliver(h, raw2, oname("b"))
    assert outcome["outcome"] == "quarantined"
    assert outcome["code"] == "sequence_fork"
    _assert_single(setup)
    rows = h.conn.execute(
        "SELECT reason FROM quarantine WHERE event_id != ''"
    ).fetchall()
    assert any(r[0] == "sequence_fork" for r in rows)


def test_replay_guard_expires_by_time_not_count(setup):
    """Replay rows carry expires_at = max(created+7d+1h, accepted+7d): the
    retention is time-based, never count-based."""
    h = setup["harness"]
    _, raw = _seal(setup, 1)
    assert deliver(h, raw)["outcome"] == "accepted"
    row = h.conn.execute(
        "SELECT expires_at FROM replay_guard"
    ).fetchone()
    assert row is not None
    from muse_agent_social.policy.limits import parse_canonical_utc
    expires = parse_canonical_utc(row[0])
    created = parse_canonical_utc(
        h.conn.execute("SELECT created_at FROM events").fetchone()[0]
    )
    assert expires >= created + timedelta(days=7, hours=1)


def test_many_replays_stay_single(setup):
    h = setup["harness"]
    _, raw = _seal(setup, 1)
    assert deliver(h, raw, oname("m0"))["outcome"] == "accepted"
    for i in range(1, 25):
        outcome = deliver(h, raw, oname(f"i{i}"))
        assert outcome["outcome"] in ("accepted_duplicate", "duplicate_ignored")
    _assert_single(setup)
    assert h.count("receipt_queue") == 1


def test_interleaved_sequences_both_sides_single(setup):
    """A sends seq 1..3, each replayed once: three projections, three
    surfaces, nothing more."""
    h = setup["harness"]
    raws = []
    for seq in (1, 2, 3):
        _, raw = _seal(setup, seq)
        raws.append(raw)
        assert deliver(h, raw, oname(f"s{seq}"))["outcome"] == "accepted"
    for seq, raw in enumerate(raws, start=1):
        outcome = deliver(h, raw, oname(f"r{seq}"))
        assert outcome["outcome"] in ("accepted_duplicate", "duplicate_ignored")
    _assert_single(setup, event_count=3)
    assert h.count("receipt_queue") == 3
