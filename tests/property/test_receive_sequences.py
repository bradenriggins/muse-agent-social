"""Randomized receive-sequence property tests (seeded stdlib random).

- Randomized scripts of messages, multiple edit revisions, retractions,
  reactions, and receipts are delivered out of order with duplicates.
  Live projections always match ``rebuild_projections`` output.
- Delivery respects one real ordering rule of the projection engine:
  mutations of the same message are applied in arrival order (the last
  applied revision wins), so the shuffle keeps each message's mutation
  chain (created -> edits -> retract) in creation order while everything
  else (other messages, cross-message mutations, target-after-mutation
  references, duplicates) is freely interleaved.
- Re-delivering every object is idempotent: all outcomes are
  ``accepted_duplicate`` and the projection dump is unchanged.
"""

import random
from datetime import datetime, timedelta, timezone

import pytest

from muse_agent_social.policy.limits import format_canonical_utc
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


def _ts(base, offset_seconds):
    return format_canonical_utc(base + timedelta(seconds=offset_seconds))


@pytest.fixture()
def pair(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "ffffffff-2222-4222-8333-555555555555"
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


def _projection_dump(conn):
    dump = {}
    for table in (
        "messages", "message_revisions", "reactions", "threads",
        "conversations", "polls", "tasks", "human_requests", "receipts",
    ):
        try:
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        except Exception:
            continue
        dump[table] = sorted([tuple(row) for row in rows], key=repr)
    return dump


def _build_script(rng, pair):
    """Generate a randomized event script.

    Returns (events, expectations) where each event is a dict with the
    sealed bytes, message index, chain order, and creation order; and
    expectations maps message index -> expected final body/flags.
    """
    alice, bob = pair["alice"], pair["bob"]
    rid, conv = pair["rid"], pair["conv"]
    base = datetime.now(timezone.utc)
    events = []
    expectations = {}
    seq = 0
    creation = 0

    def seal(event_type, payload, target_chain=None, chain_pos=0):
        nonlocal seq, creation
        seq += 1
        creation += 1
        env, raw = make_sealed(
            alice, bob, rid, conv, event_type, payload, seq=seq,
            created_at=_ts(base, creation * 5),
        )
        events.append(
            {
                "raw": raw,
                "event_id": env["protected"]["event_id"],
                "chain": target_chain,
                "chain_pos": chain_pos,
            }
        )
        return env["protected"]["event_id"]

    n_messages = 2 + rng.randrange(5)  # 2..6 messages
    for m in range(n_messages):
        body = f"msg{m}-v0"
        target_id = seal(
            "message.created", {"body": body, "format": "plain"},
            target_chain=m, chain_pos=0,
        )
        expected_body = body
        n_edits = rng.randrange(0, 4)
        for e in range(1, n_edits + 1):
            expected_body = f"msg{m}-v{e}"
            seal(
                "message.edited",
                {"target_event_id": target_id, "body": expected_body},
                target_chain=m, chain_pos=e,
            )
        retracted = rng.randrange(4) == 0
        if retracted:
            seal(
                "message.retracted",
                {"target_event_id": target_id, "reason": "cleanup"},
                target_chain=m, chain_pos=n_edits + 1,
            )
        # Reactions: distinct emoji per target. Re-adding the same
        # (target, sender, emoji) is last-write-wins by APPLICATION order,
        # so two adds of the same emoji would legitimately diverge between
        # live (arrival order) and rebuild (created_at order); that race is
        # a separate semantic from the convergence property tested here.
        emojis = rng.sample(["👍", "❤️", "😂"], rng.randrange(0, 3))
        for emoji in emojis:
            seal(
                "reaction.added",
                {"target_event_id": target_id, "emoji": emoji},
            )
        if rng.randrange(2) == 0:
            seal(
                "receipt.accepted",
                {
                    "target_event_id": target_id,
                    "accepted_at": _ts(base, creation * 5 + 1),
                },
            )
        expectations[m] = {
            "target_id": target_id,
            "body": expected_body,
            "edited": 1 if n_edits else 0,
            "retracted": 1 if retracted else 0,
        }
    return events, expectations


def _constrained_shuffle(rng, events, n_duplicates):
    """Random delivery order preserving each message chain's creation
    order; duplicates of already-delivered objects are interleaved."""
    remaining = list(events)
    delivered = []
    order = []
    available = [e for e in remaining if e["chain"] is None or e["chain_pos"] == 0]
    # chain_pos > 0 events become available once their predecessor delivered.
    chains = {}
    for e in remaining:
        if e["chain"] is not None:
            chains.setdefault(e["chain"], []).append(e)
    for c in chains:
        chains[c].sort(key=lambda e: e["chain_pos"])

    pending_chain = {c: 0 for c in chains}
    pool = list(available)
    rng.shuffle(pool)

    delivered_ids = set()
    while pool or any(
        pending_chain[c] < len(chains[c]) for c in chains
    ):
        # Refresh: chain events whose predecessor was delivered join the pool.
        for c, lst in chains.items():
            idx = pending_chain[c]
            if idx < len(lst) and (
                idx == 0 or lst[idx - 1]["event_id"] in delivered_ids
            ):
                # idx==0 events started in the pool already; skip re-adding.
                if idx > 0 and lst[idx] not in pool:
                    # Insert at a random pool position for interleaving.
                    pool.insert(rng.randrange(len(pool) + 1), lst[idx])
                pending_chain[c] += 1
        if not pool:
            break
        pick = rng.randrange(len(pool))
        nxt = pool.pop(pick)
        order.append(nxt)
        delivered_ids.add(nxt["event_id"])
        delivered.append(nxt)

    # Interleave duplicates of already-delivered objects. A duplicate is a
    # re-delivery of the same bytes, so it may only appear AFTER the
    # event's first delivery in the order (receiving a "duplicate" of X
    # before X itself is physically meaningless: the first arrival IS
    # the first delivery). Insert each duplicate at a random position
    # at or after the victim's first-delivery index.
    for _ in range(n_duplicates):
        victim = rng.choice(delivered)
        first = order.index(victim)
        pos = rng.randrange(first + 1, len(order) + 1)
        order.insert(pos, victim)
    return order


@pytest.mark.parametrize("seed", range(10))
def test_shuffled_sequences_match_rebuild(pair, seed):
    """Out-of-order delivery with duplicates: live projections always
    equal a full rebuild from the event log."""
    rng = random.Random(3000 + seed)
    h, conn = pair["harness"], pair["conn"]
    events, expectations = _build_script(rng, pair)
    order = _constrained_shuffle(rng, events, n_duplicates=rng.randrange(0, 8))

    for item in order:
        outcome = deliver(h, item["raw"])["outcome"]
        assert outcome in ("accepted", "accepted_duplicate"), outcome

    # Per-message expectations: last applied revision wins.
    for m, exp in expectations.items():
        row = conn.execute(
            "SELECT current_body, edited, retracted FROM messages"
            " WHERE event_id = ?",
            (exp["target_id"],),
        ).fetchone()
        assert row is not None, f"message {m} was not projected"
        assert row[0] == exp["body"], f"message {m} body"
        assert row[1] == exp["edited"], f"message {m} edited flag"
        assert row[2] == exp["retracted"], f"message {m} retracted flag"

    live = _projection_dump(conn)
    rebuild_projections(conn, pair["rid"])
    rebuilt = _projection_dump(conn)
    assert rebuilt == live


@pytest.mark.parametrize("seed", range(5))
def test_redelivery_is_idempotent(pair, seed):
    """Re-delivering every object changes nothing: all outcomes are
    accepted_duplicate and the projection dump is unchanged."""
    rng = random.Random(3100 + seed)
    h, conn = pair["harness"], pair["conn"]
    events, _ = _build_script(rng, pair)
    order = _constrained_shuffle(rng, events, n_duplicates=0)
    for item in order:
        assert deliver(h, item["raw"])["outcome"] == "accepted"

    before = _projection_dump(conn)
    again = list(events)
    rng.shuffle(again)
    for item in again:
        outcome = deliver(h, item["raw"])["outcome"]
        assert outcome == "accepted_duplicate", outcome
    assert _projection_dump(conn) == before
