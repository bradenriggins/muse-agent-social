"""Property-style invariants (deterministic seeded generation, no Hypothesis).

- canonical(): idempotent, insertion-order invariant, rejects floats.
- restricted_jcs(): byte-identical for equal values regardless of build order.
- Receive: delivering the same sealed objects twice is idempotent
  (no double projections, no double receipts, no double surfaces).
- Replay guard: same nonce under a new event id is consume-only
  duplicate_ignored, never double-projected.
- Projections: rebuild_projections from the event log reproduces the
  live-applied state exactly, including out-of-order edits/reactions
  resolved through pending refs.
"""

import json
import random
import uuid

import pytest

from muse_agent_social.canonical import (
    CanonicalizationError,
    restricted_jcs,
    strict_parse,
)
from muse_agent_social.store.projections import rebuild_projections
from muse_agent_social.transports.local import LocalTransport

from support.harness import (
    ReceiveHarness,
    deliver,
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)


def _utcnow():
    from datetime import datetime, timezone

    from muse_agent_social.policy.limits import format_canonical_utc

    return format_canonical_utc(datetime.now(timezone.utc))


# -- canonicalization properties ------------------------------------------------------------


def _rand_value(rng, depth=0):
    if depth > 3:
        return rng.choice([None, True, 1, "leaf"])
    kind = rng.randrange(7)
    if kind == 0:
        return None
    if kind == 1:
        return rng.choice([True, False])
    if kind == 2:
        return rng.randrange(-10**12, 10**12)
    if kind == 3:
        return "".join(
            rng.choice("abcXYZ019 \t") for _ in range(rng.randrange(0, 12))
        )
    if kind == 4:
        return [_rand_value(rng, depth + 1) for _ in range(rng.randrange(0, 4))]
    if kind == 5:
        keys = random.sample(
            ["a", "b", "c", "d", "e", "f", "g"], rng.randrange(0, 5)
        )
        return {k: _rand_value(rng, depth + 1) for k in keys}
    return rng.randrange(0, 100)


def _shuffled(obj, rng):
    """Rebuild dicts with keys in a different insertion order."""
    if isinstance(obj, dict):
        keys = list(obj.keys())
        rng.shuffle(keys)
        return {k: _shuffled(obj[k], rng) for k in keys}
    if isinstance(obj, list):
        return [_shuffled(v, rng) for v in obj]
    return obj


@pytest.mark.parametrize("seed", range(25))
def test_canonical_idempotent_and_order_invariant(seed):
    rng = random.Random(seed)
    value = _rand_value(rng)
    first = restricted_jcs(value)
    # Re-parse and re-canonicalize: idempotent.
    assert restricted_jcs(strict_parse(first)) == first
    # Different insertion order: byte-identical.
    assert restricted_jcs(_shuffled(value, rng)) == first


@pytest.mark.parametrize("seed", range(10))
def test_canonical_rejects_floats_anywhere(seed):
    rng = random.Random(1000 + seed)
    value = _rand_value(rng)
    if isinstance(value, dict):
        value["injected"] = 1.5
    else:
        value = {"wrap": [value, float("nan")]}
    with pytest.raises(CanonicalizationError):
        restricted_jcs(value)


# -- receive idempotence properties -------------------------------------------------------------


@pytest.fixture()
def pair(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "ffffffff-1111-4222-8333-444444444444"
    provision_receive_side(conn, rid, bob, alice)
    conv = new_conversation(conn)
    harness = ReceiveHarness(
        conn,
        relationship_id=rid,
        own_identity_id=bob["identity_id"],
        own_rel_priv=bob["rel_priv"],
        transport=LocalTransport(tmp_path / "relay"),
    )
    return {
        "alice": alice, "bob": bob, "conn": conn, "rid": rid,
        "conv": conv, "harness": harness,
    }


def _snapshot(h):
    return {
        table: h.count(table)
        for table in (
            "events", "messages", "reactions", "replay_guard",
            "receipt_queue", "surface_queue", "surface_log",
        )
    }


def test_double_delivery_is_idempotent(pair):
    """Delivering the same sealed objects twice changes nothing the
    second time: no double projection, receipt, or surface."""
    h = pair["harness"]
    raws = []
    for seq in range(1, 11):
        _, raw = make_sealed(
            pair["alice"], pair["bob"], pair["rid"], pair["conv"],
            "message.created", {"body": f"msg {seq}", "format": "plain"},
            seq=seq,
        )
        raws.append(raw)
    first = [deliver(h, raw)["outcome"] for raw in raws]
    assert first == ["accepted"] * 10
    before = _snapshot(h)
    second = [deliver(h, raw) for raw in raws]
    # Byte-identical redelivery is idempotent resume, not reprocessing.
    assert {o["outcome"] for o in second} <= {
        "accepted_duplicate", "already_committed",
    }
    assert _snapshot(h) == before


def _reseal_with_nonce(pair, env, nonce):
    """Transplant a replay nonce into a fresh envelope and re-sign with
    the sender key held in-test (nonce is inside the signed bytes)."""
    import copy

    from muse_agent_social.canonical import restricted_jcs
    from muse_agent_social.crypto.identity import b64url_encode

    env2 = copy.deepcopy(env)
    env2["protected"]["replay_nonce"] = nonce
    unsigned = {k: v for k, v in env2.items() if k != "signature"}
    env2["signature"] = b64url_encode(
        pair["alice"]["ed_priv"].sign(restricted_jcs(unsigned))
    )
    return restricted_jcs(env2)


def test_nonce_reuse_under_new_event_id_never_double_projects(pair):
    """The same replay nonce sealed under a fresh event id is consumed
    as duplicate_ignored: nothing is projected twice."""
    h = pair["harness"]
    env, raw = make_sealed(
        pair["alice"], pair["bob"], pair["rid"], pair["conv"],
        "message.created", {"body": "one", "format": "plain"}, seq=1,
    )
    assert deliver(h, raw)["outcome"] == "accepted"
    env2, _ = make_sealed(
        pair["alice"], pair["bob"], pair["rid"], pair["conv"],
        "message.created", {"body": "one again", "format": "plain"}, seq=2,
    )
    assert env2["protected"]["event_id"] != env["protected"]["event_id"]
    raw2 = _reseal_with_nonce(
        pair, env2, env["protected"]["replay_nonce"]
    )
    outcome = deliver(h, raw2)
    assert outcome["outcome"] == "duplicate_ignored"
    assert h.count("messages") == 1
    assert h.count("events") == 1


@pytest.mark.parametrize("seed", range(5))
def test_random_event_storm_is_idempotent(pair, seed):
    """A seeded storm of messages, reactions, and edits delivered twice
    yields identical DB state after each pass."""
    rng = random.Random(5000 + seed)
    h = pair["harness"]
    raws = []
    seq = 0
    msg_event_ids = []
    for _ in range(rng.randrange(15, 30)):
        seq += 1
        kind = rng.randrange(4)
        if kind == 0 or not msg_event_ids:
            env, raw = make_sealed(
                pair["alice"], pair["bob"], pair["rid"], pair["conv"],
                "message.created",
                {"body": f"storm {seq}", "format": "plain"}, seq=seq,
            )
            msg_event_ids.append(env["protected"]["event_id"])
        elif kind == 1:
            env, raw = make_sealed(
                pair["alice"], pair["bob"], pair["rid"], pair["conv"],
                "reaction.added",
                {"target_event_id": rng.choice(msg_event_ids), "emoji": "👍"},
                seq=seq,
            )
        elif kind == 2:
            env, raw = make_sealed(
                pair["alice"], pair["bob"], pair["rid"], pair["conv"],
                "message.edited",
                {"target_event_id": rng.choice(msg_event_ids),
                 "body": f"edited {seq}"}, seq=seq,
            )
        else:
            env, raw = make_sealed(
                pair["alice"], pair["bob"], pair["rid"], pair["conv"],
                "receipt.accepted",
                {"target_event_id": rng.choice(msg_event_ids),
                 "accepted_at": _utcnow()}, seq=seq,
            )
        raws.append(raw)
    for raw in raws:
        assert deliver(h, raw)["outcome"] == "accepted"
    first = _snapshot(h)
    for raw in raws:
        outcome = deliver(h, raw)["outcome"]
        assert outcome in (
            "accepted_duplicate", "already_committed", "duplicate_ignored",
        )
    assert _snapshot(h) == first


# -- rebuild determinism ----------------------------------------------------------------------------


def _projection_dump(conn, rid):
    dump = {}
    for table in (
        "messages", "message_revisions", "reactions", "threads",
        "conversations", "polls", "tasks", "human_requests", "receipts",
    ):
        try:
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        except Exception:
            continue
        dump[table] = sorted(
            [tuple(row) for row in rows], key=repr
        )
    return dump


def test_rebuild_reproduces_live_state_with_out_of_order_mutations(pair):
    """Edits, reactions, and receipts arriving before their target resolve
    through pending refs; a full rebuild from the event log reproduces
    the live-applied projection state exactly."""
    h = pair["harness"]
    conn = pair["conn"]
    rid = pair["rid"]
    conv = pair["conv"]

    # Seal the target first, but deliver its edit/reaction/receipt first.
    target_env, target_raw = make_sealed(
        pair["alice"], pair["bob"], rid, conv,
        "message.created", {"body": "original", "format": "plain"}, seq=1,
    )
    target_id = target_env["protected"]["event_id"]
    _, edit_raw = make_sealed(
        pair["alice"], pair["bob"], rid, conv,
        "message.edited",
        {"target_event_id": target_id, "body": "edited"}, seq=2,
    )
    _, react_raw = make_sealed(
        pair["alice"], pair["bob"], rid, conv,
        "reaction.added",
        {"target_event_id": target_id, "emoji": "👍"}, seq=3,
    )
    _, receipt_raw = make_sealed(
        pair["alice"], pair["bob"], rid, conv,
        "receipt.accepted",
        {"target_event_id": target_id, "accepted_at": _utcnow()}, seq=4,
    )
    for raw in (edit_raw, react_raw, receipt_raw, target_raw):
        assert deliver(h, raw)["outcome"] == "accepted"

    live = _projection_dump(conn, rid)
    # The out-of-order mutations must have resolved against the target.
    row = conn.execute(
        "SELECT current_body, edited FROM messages WHERE event_id = ?",
        (target_id,),
    ).fetchone()
    assert row[0] == "edited" and row[1] == 1
    revs = conn.execute(
        "SELECT revision_no, body FROM message_revisions"
        " WHERE event_id = ? ORDER BY revision_no",
        (target_id,),
    ).fetchall()
    # revision 0 is the original; the out-of-order edit resolved as rev 1.
    assert [(r[0], r[1]) for r in revs] == [(0, "original"), (1, "edited")]
    assert conn.execute(
        "SELECT COUNT(*) FROM reactions WHERE target_event_id = ?",
        (target_id,),
    ).fetchone()[0] == 1

    rebuild_projections(conn, rid)
    rebuilt = _projection_dump(conn, rid)
    assert rebuilt == live


def test_rebuild_is_repeatable(pair):
    """Two consecutive rebuilds of the same log are byte-identical."""
    h = pair["harness"]
    conn = pair["conn"]
    rid = pair["rid"]
    for seq in range(1, 6):
        _, raw = make_sealed(
            pair["alice"], pair["bob"], rid, pair["conv"],
            "message.created", {"body": f"m{seq}", "format": "plain"},
            seq=seq,
        )
        assert deliver(h, raw)["outcome"] == "accepted"
    rebuild_projections(conn, rid)
    first = _projection_dump(conn, rid)
    rebuild_projections(conn, rid)
    assert _projection_dump(conn, rid) == first
