"""V2 regression: the epoch gate must authenticate before mutating
rotation state, and unknown-future-epoch storms must terminate.

Before the fix, cli called manager.on_data_event_epoch before _try_unseal:
every bogus future epoch inserted a rotation_quarantine row (capped at 50
by evicting the oldest, which reset the 24h rejection timer), the outcome
retry_pending was never consumed, and the watcher never advanced
last_successful_head. Perpetual unauthenticated availability drain.
"""

import json
from datetime import timedelta

import pytest

import muse_agent_social.cli as cli_mod
from muse_agent_social.canonical import restricted_jcs, strict_parse
from muse_agent_social.crypto.rotation import RotationError, RotationManager
from muse_agent_social.policy.delivery import set_accepted_receipts_enabled
from muse_agent_social.policy.limits import (
    MAX_UNKNOWN_EPOCH_SIGHTINGS,
    add_seconds,
)
from muse_agent_social.store.db import utcnow
from support.harness import (
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)

RID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def _oname(tag: str) -> str:
    return (tag + "0" * 32)[:32] + ".json"


def _ctx(tmp_path):
    from types import SimpleNamespace

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    provision_receive_side(conn, RID, bob, alice)
    set_accepted_receipts_enabled(conn, RID, False)
    cli_mod._ensure_cli_tables(conn)
    ctx = SimpleNamespace(
        conn=conn,
        state_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        identity_id=bob["identity_id"],
    )
    return ctx, conn, alice, bob


def _sealed_with_epoch(alice, bob, rid, conv, epoch, seq=1):
    _, raw = make_sealed(
        alice, bob, rid, conv,
        "message.created", {"body": "epoch probe", "format": "plain"},
        seq=seq, key_epoch=epoch,
    )
    return raw


def test_unauthenticated_future_epoch_mutates_no_rotation_state(tmp_path):
    """A forged envelope (bad signature) with a future epoch is rejected
    at unseal: no rotation_quarantine row, no first-seen record."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    raw = _sealed_with_epoch(alice, bob, RID, conv, 99)
    # Break the signature without touching the schema-valid shape.
    parsed = strict_parse(raw)
    parsed["signature"] = "AA" + parsed["signature"][2:]
    raw = restricted_jcs(parsed)
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, RID, _oname("forged"), raw, acc)
    assert outcome["outcome"] == "quarantined"
    reason = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()["reason"]
    assert reason.startswith("unseal_")
    assert conn.execute(
        "SELECT COUNT(*) FROM rotation_quarantine").fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM unknown_epoch_first_seen").fetchone()[0] == 0


def test_authenticated_future_epoch_is_retryable_then_sighting_capped(tmp_path):
    """A genuinely signed future-epoch event is retry_pending (the rotation
    handshake may be in flight), but each re-sighting is counted and the
    object is terminally quarantined past the ceiling."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    raw = _sealed_with_epoch(alice, bob, RID, conv, 99)
    acc = {"surfaces": 0, "receipts_queued": 0}
    first = cli_mod._receive_object(ctx, RID, _oname("storm"), raw, acc)
    assert first["outcome"] == "retry_pending"
    # The durable first-seen record exists.
    row = conn.execute(
        "SELECT first_seen_at FROM unknown_epoch_first_seen"
        " WHERE relationship_id = ? AND epoch = 99",
        (RID,),
    ).fetchone()
    assert row is not None
    # Sightings 2..MAX_UNKNOWN_EPOCH_SIGHTINGS stay retryable; the next
    # one crosses the ceiling and quarantines the object.
    for _ in range(MAX_UNKNOWN_EPOCH_SIGHTINGS - 1):
        out = cli_mod._receive_object(ctx, RID, _oname("storm"), raw, acc)
        assert out["outcome"] == "retry_pending"
    out = cli_mod._receive_object(ctx, RID, _oname("storm"), raw, acc)
    assert out["outcome"] == "quarantined"
    reason = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()["reason"]
    assert reason == "epoch_rejected"


def test_cap_eviction_cannot_resurrect_a_rejected_epoch(tmp_path):
    """Filling unknown_epoch_first_seen past its 1000-row cap evicts the
    oldest non-rejected rows, but a rejected epoch's tombstone is never
    evicted: rejection is permanent and the 24h timer cannot reset."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    manager = RotationManager(conn, tmp_path / "keys")
    old = add_seconds(utcnow(), -25 * 3600)
    conn.execute(
        "INSERT INTO unknown_epoch_first_seen(relationship_id, epoch,"
        " first_seen_at) VALUES (?, 4242, ?)",
        (RID, old),
    )
    # 24h have elapsed: this sighting rejects the epoch for good.
    with pytest.raises(RotationError) as excinfo:
        manager.on_data_event_epoch(RID, 4242)
    assert excinfo.value.code == "unknown_future_epoch_rejected"
    row = conn.execute(
        "SELECT rejected FROM unknown_epoch_first_seen"
        " WHERE relationship_id = ? AND epoch = 4242",
        (RID,),
    ).fetchone()
    assert row["rejected"] == 1
    # Storm of 1200 distinct future epochs to force cap eviction.
    for epoch in range(5000, 6200):
        try:
            manager.on_data_event_epoch(RID, epoch)
        except RotationError:
            pass
    conn.commit()
    assert conn.execute(
        "SELECT COUNT(*) FROM rotation_quarantine").fetchone()[0] <= 50
    non_rejected = conn.execute(
        "SELECT COUNT(*) FROM unknown_epoch_first_seen"
        " WHERE relationship_id = ? AND rejected = 0",
        (RID,),
    ).fetchone()[0]
    assert non_rejected <= 1000
    # The rejected tombstone survived eviction.
    assert conn.execute(
        "SELECT COUNT(*) FROM unknown_epoch_first_seen"
        " WHERE relationship_id = ? AND epoch = 4242 AND rejected = 1",
        (RID,),
    ).fetchone()[0] == 1
    # And the epoch is still rejected, not retryable again.
    with pytest.raises(RotationError) as excinfo:
        manager.on_data_event_epoch(RID, 4242)
    assert excinfo.value.code == "unknown_future_epoch_rejected"


def test_rejected_column_backfilled_on_old_databases(tmp_path):
    """Databases whose unknown_epoch_first_seen predates the tombstone
    column get it from the idempotent backfill in _ensure_tables."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    RotationManager(conn, tmp_path / "keys")
    conn.execute("ALTER TABLE unknown_epoch_first_seen DROP COLUMN rejected;")
    conn.commit()
    cols = [r[1] for r in conn.execute(
        "PRAGMA table_info(unknown_epoch_first_seen);"
    ).fetchall()]
    assert "rejected" not in cols
    RotationManager(conn, tmp_path / "keys")
    cols = [r[1] for r in conn.execute(
        "PRAGMA table_info(unknown_epoch_first_seen);"
    ).fetchall()]
    assert "rejected" in cols


def test_known_epoch_still_passes_and_clears_first_seen_on_prepare(tmp_path):
    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    raw = _sealed_with_epoch(alice, bob, RID, conv, 1)
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, RID, _oname("okepoch"), raw, acc)
    assert outcome["outcome"] == "accepted"
