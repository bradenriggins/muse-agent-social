"""Randomized approval-lifecycle property tests (seeded stdlib random).

- Randomized create/consume sequences: each approval is consumed at most
  once successfully; re-consumption returns False; consuming an unknown id
  returns False; expired approvals cannot be consumed.
- Expiry boundary: consumption succeeds strictly before ``expires_at``
  and fails exactly at (and after) it.
- Binding: consuming with mismatched binding parameters fails and leaves
  the approval live; consuming with the correct binding then succeeds.
- ``get_approval`` reflects the lifecycle: ``consumed_at`` is set exactly
  once, on the winning claim.
"""

import random
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from muse_agent_social.model.approvals import (
    APPROVAL_TTL_SECONDS,
    consume_approval,
    create_approval,
    get_approval,
)
from muse_agent_social.store import db
from muse_agent_social.store import migrations

RID = "rel-approval-prop"
BASE = datetime(2026, 9, 15, 20, 0, 0, tzinfo=timezone.utc)


def _ts(dt):
    return dt.isoformat().replace("+00:00", "Z")


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(tmp_path / "approvals.db")
    migrations.migrate(c)
    c.execute(
        "INSERT INTO relationships(relationship_id, peer_identity_id,"
        " consent_state, policy, key_epoch, created_at)"
        " VALUES (?, ?, 'active', '{}', 1, ?);",
        (RID, "did:key:zPeerApprovalProp", _ts(BASE)),
    )
    yield c
    c.close()


def _make(conn, rng, created_at, **over):
    kw = dict(
        relationship_id=RID,
        subject_type=rng.choice(["human_request", "poll"]),
        subject_id=f"req-{rng.randrange(1000)}",
        answer=rng.choice(["yes", "no", "maybe"]),
        approved=rng.choice([True, False]),
        created_at=_ts(created_at),
    )
    kw.update(over)
    return create_approval(conn, **kw), kw


@pytest.mark.parametrize("seed", range(10))
def test_randomized_create_consume_sequences(conn, seed):
    """Random interleavings of creates and consumes: single-use holds,
    unknown ids fail, expired approvals never consume."""
    rng = random.Random(4000 + seed)
    live = {}  # approval_id -> {"consumed": bool, "expired": bool}
    ids = []
    now = BASE + timedelta(hours=1)

    for step in range(rng.randrange(5, 15)):
        action = rng.randrange(4)
        if action == 0 or not ids:
            # Create: sometimes already expired.
            expired = rng.randrange(3) == 0
            created = (
                BASE - timedelta(seconds=APPROVAL_TTL_SECONDS + 3600)
                if expired
                else BASE
            )
            aid, _ = _make(conn, rng, created)
            live[aid] = {"consumed": False, "expired": expired}
            ids.append(aid)
        elif action == 1:
            # Consume a random approval 1..3 times.
            aid = rng.choice(ids)
            for _ in range(rng.randrange(1, 4)):
                won = consume_approval(conn, aid, _ts(now))
                st = live[aid]
                if not st["consumed"] and not st["expired"]:
                    assert won is True
                    st["consumed"] = True
                else:
                    assert won is False
        elif action == 2:
            # Consume an unknown id: always fails.
            assert consume_approval(conn, "deadbeef" * 8, _ts(now)) is False
        else:
            # get_approval reflects the tracked state.
            aid = rng.choice(ids)
            row = get_approval(conn, aid)
            assert row is not None
            assert (row["consumed_at"] is not None) == live[aid]["consumed"]

    # Final sweep: every live unconsumed approval consumes exactly once;
    # everything else fails.
    for aid, st in live.items():
        won = consume_approval(conn, aid, _ts(now))
        assert won == (not st["consumed"] and not st["expired"])
        assert consume_approval(conn, aid, _ts(now)) is False


@pytest.mark.parametrize("seed", range(5))
def test_expiry_boundary(conn, seed):
    """Consumption succeeds strictly before expires_at; at exactly
    expires_at (and after) it fails."""
    rng = random.Random(4100 + seed)
    created = BASE
    expires = created + timedelta(seconds=APPROVAL_TTL_SECONDS)

    aid_ok, _ = _make(conn, rng, created)
    assert (
        consume_approval(conn, aid_ok, _ts(expires - timedelta(seconds=1)))
        is True
    )

    aid_edge, _ = _make(conn, rng, created)
    assert consume_approval(conn, aid_edge, _ts(expires)) is False
    assert get_approval(conn, aid_edge)["consumed_at"] is None

    aid_late, _ = _make(conn, rng, created)
    assert (
        consume_approval(conn, aid_late, _ts(expires + timedelta(seconds=1)))
        is False
    )


def test_binding_mismatch_does_not_consume(conn):
    """A consume with wrong binding parameters fails and leaves the
    approval live for the correctly-bound claim."""
    rng = random.Random(4200)
    aid, kw = _make(conn, rng, BASE)
    assert (
        consume_approval(
            conn,
            aid,
            _ts(BASE + timedelta(minutes=1)),
            relationship_id=RID,
            subject_type=kw["subject_type"],
            subject_id="req-WRONG",
            answer=kw["answer"],
            approved=kw["approved"],
        )
        is False
    )
    assert get_approval(conn, aid)["consumed_at"] is None
    assert (
        consume_approval(
            conn,
            aid,
            _ts(BASE + timedelta(minutes=1)),
            relationship_id=RID,
            subject_type=kw["subject_type"],
            subject_id=kw["subject_id"],
            answer=kw["answer"],
            approved=kw["approved"],
        )
        is True
    )


def test_get_approval_unknown_returns_none(conn):
    assert get_approval(conn, "missing" * 8) is None
