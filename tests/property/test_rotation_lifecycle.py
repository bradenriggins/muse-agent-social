"""Randomized rotation-lifecycle property tests (seeded stdlib random).

The rotating/acking key-rotation state machine is driven through full
round trips with randomized re-drives, crash-and-resume (fresh
RotationManager on the same conn/keys_dir), and no-ack timeouts:

- Full round trip converges: both sides agree on the new epoch, the new
  key is active, the prior key is retired, and the rotation row is
  committed.
- Randomized interleavings of idempotent re-drives (repeated ack,
  confirm, commit, decrypt signals) and randomized wrap-signal timing
  (before or after the ack) always converge to the same committed state.
- Crash-and-resume after every step is safe: a fresh manager on the same
  store continues the lifecycle without wedging.
- A prepare never acked raises NoAckTimeout from sweep after the
  24-hour deadline; the candidate is discarded, a later sweep is quiet,
  and a fresh rotation can be started and completed.
- A second begin_rotation while one is in flight is rejected; after the
  rotation commits, a new rotation to the next epoch can start.
"""

import os
import random
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from muse_agent_social._keyfiles import store_private_key
from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
)
from muse_agent_social.crypto.rotation import (
    NoAckTimeout,
    RotationError,
    RotationManager,
)
from muse_agent_social.store.migrations import migrate

T0 = datetime(2026, 9, 15, 20, 0, 0, tzinfo=timezone.utc)
DAY = timedelta(hours=24)


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    migrate(conn)
    return conn


def seed_pair(tmp_path, tag):
    """Seed a committed epoch-1 relationship on two sides; return context."""
    conn_i, conn_a = make_db(), make_db()
    rid = f"rel-{tag}-{uuid.uuid4().hex[:8]}"
    keys_i = tmp_path / f"keys_i_{tag}"
    keys_a = tmp_path / f"keys_a_{tag}"

    def add(conn, keys_dir):
        os.makedirs(keys_dir, exist_ok=True)
        priv = X25519PrivateKey.generate()
        pub = agreement_key_multibase_from_pubkey(
            priv.public_key().public_bytes_raw()
        )
        path = os.path.join(str(keys_dir), "e1.key")
        store_private_key(path, priv.private_bytes_raw())
        conn.execute(
            "INSERT INTO relationships (relationship_id, peer_identity_id,"
            " peer_display_name, peer_agreement_key, consent_state, policy,"
            " key_epoch, created_at)"
            " VALUES (?, ?, ?, ?, 'active', '{}', 1, ?)",
            (rid, "id:test:peer", "Peer", pub, T0.isoformat().replace("+00:00", "Z")),
        )
        conn.execute(
            "INSERT INTO key_epochs (relationship_id, epoch, public_key,"
            " private_key_ref, state) VALUES (?, 1, ?, ?, 'active')",
            (rid, pub, path),
        )
        return priv, pub

    priv_i, pub_i = add(conn_i, keys_i)
    priv_a, pub_a = add(conn_a, keys_a)
    # Each side's stored peer key is the other side's actual epoch-1 key.
    conn_i.execute(
        "UPDATE relationships SET peer_agreement_key=? WHERE relationship_id=?",
        (pub_a, rid),
    )
    conn_a.execute(
        "UPDATE relationships SET peer_agreement_key=? WHERE relationship_id=?",
        (pub_i, rid),
    )
    return {
        "conn_i": conn_i,
        "conn_a": conn_a,
        "rid": rid,
        "keys_i": keys_i,
        "keys_a": keys_a,
        "pub_i": pub_i,
    }


def mgr(ctx, side, now=None):
    return RotationManager(ctx[f"conn_{side}"], ctx[f"keys_{side}"], now=now)


def phase(ctx, side, epoch, role):
    row = ctx[f"conn_{side}"].execute(
        "SELECT phase FROM key_rotations WHERE relationship_id=? AND epoch=?"
        " AND role=? ORDER BY CASE phase WHEN 'discarded' THEN 1 ELSE 0 END",
        (ctx["rid"], epoch, role),
    ).fetchone()
    return row["phase"] if row else None


def key_state(ctx, side, epoch):
    rows = ctx[f"conn_{side}"].execute(
        "SELECT state FROM key_epochs WHERE relationship_id=? AND epoch=?"
        " AND private_key_ref != 'peer'",
        (ctx["rid"], epoch),
    ).fetchall()
    return {r["state"] for r in rows}


def rel_epoch(ctx, side):
    return ctx[f"conn_{side}"].execute(
        "SELECT key_epoch FROM relationships WHERE relationship_id=?",
        (ctx["rid"],),
    ).fetchone()["key_epoch"]


def drive_full(ctx, redrives=0, wrap_first=False, rng=None, resume=False,
              begun=None, prep_event=None):
    """Drive the canonical lifecycle to completion.

    *redrives*: extra idempotent re-drives of each step (randomized when
    rng is given, exactly *redrives* each otherwise).
    *wrap_first*: note the new-wrap decrypt signal before the ack arrives.
    *resume*: rebuild both managers after every step (crash simulation).
    *begun*/*prep_event*: an already-started rotation to continue instead
    of beginning a new one.
    """
    rng = rng or random.Random(0)
    rid = ctx["rid"]
    mi, ma = mgr(ctx, "i"), mgr(ctx, "a")
    now = T0

    def fresh():
        nonlocal mi, ma
        mi, ma = mgr(ctx, "i"), mgr(ctx, "a")

    # 1. Rotating side begins (unless the caller already began).
    if begun is None:
        prep_event = str(uuid.uuid4())
        begun = mi.begin_rotation(rid, now=now, prepare_event_id=prep_event)
    epoch = begun["epoch"]
    if resume:
        fresh()
    # 2. Acking side processes the prepare.
    ack = ma.on_prepare(rid, begun["prepare"], prep_event, now=now)
    if resume:
        fresh()
    # 3/4. Decrypt signal and ack, in randomized order, with re-drives.
    extra_notes = rng.randrange(0, 3) if rng else redrives
    if wrap_first:
        for _ in range(1 + extra_notes):
            mi.note_decrypted_new_wrap(rid, epoch, now=now)
        mi.on_ack(rid, ack, now=now)
    else:
        mi.on_ack(rid, ack, now=now)
        if resume:
            fresh()
        for _ in range(rng.randrange(0, 3) if rng else redrives):
            mi.on_ack(rid, ack, now=now)  # idempotent re-drive
        for _ in range(1 + extra_notes):
            mi.note_decrypted_new_wrap(rid, epoch, now=now)
    if resume:
        fresh()
    # 5. Confirm (idempotent re-emit is part of the contract).
    confirm = mi.confirm_rotation(rid, now=now)
    for _ in range(rng.randrange(0, 2) if rng else redrives):
        assert mi.confirm_rotation(rid, now=now)["epoch"] == confirm["epoch"]
    if resume:
        fresh()
    # 6. Acking side confirms, then builds/marks the commit.
    ma.on_confirm(rid, confirm, now=now)
    if resume:
        fresh()
    for _ in range(rng.randrange(0, 2) if rng else redrives):
        ma.on_confirm(rid, confirm, now=now)  # idempotent re-drive
    commit = ma.build_commit_payload(rid, now=now)
    ma.mark_committed(rid, now=now)
    if resume:
        fresh()
    for _ in range(rng.randrange(0, 2) if rng else redrives):
        ma.mark_committed(rid, now=now)  # idempotent re-drive
    # 7. Rotating side processes the commit.
    mi.on_commit(rid, commit, now=now)
    if resume:
        fresh()
    for _ in range(rng.randrange(0, 2) if rng else redrives):
        mi.on_commit(rid, commit, now=now)  # idempotent re-drive
    return epoch


def assert_converged(ctx, epoch):
    rid = ctx["rid"]
    # Both sides agree on the new epoch.
    assert rel_epoch(ctx, "i") == epoch
    assert rel_epoch(ctx, "a") == epoch
    # The acking side wraps future sends to the rotating side's new key.
    new_peer = ctx["conn_a"].execute(
        "SELECT peer_agreement_key FROM relationships WHERE relationship_id=?",
        (rid,),
    ).fetchone()["peer_agreement_key"]
    rotating_new_pub = ctx["conn_i"].execute(
        "SELECT public_key FROM key_epochs WHERE relationship_id=? AND epoch=?",
        (rid, epoch),
    ).fetchone()["public_key"]
    assert new_peer == rotating_new_pub
    # Rotation rows are committed on both sides.
    assert phase(ctx, "i", epoch, "rotating") == "committed"
    assert phase(ctx, "a", epoch, "acking") == "committed"
    # New epoch key active, prior retired, on both sides' own rows.
    assert key_state(ctx, "i", epoch) == {"active"}
    assert key_state(ctx, "i", epoch - 1) == {"retired"}
    assert key_state(ctx, "a", 1) == {"active"}


def test_full_round_trip_converges(tmp_path):
    ctx = seed_pair(tmp_path, "rt")
    epoch = drive_full(ctx)
    assert_converged(ctx, epoch)


@pytest.mark.parametrize("seed", range(10))
def test_randomized_redrives_and_wrap_timing_converge(tmp_path, seed):
    rng = random.Random(2000 + seed)
    ctx = seed_pair(tmp_path, f"rr{seed}")
    epoch = drive_full(
        ctx, wrap_first=rng.choice([True, False]), rng=rng
    )
    assert_converged(ctx, epoch)


@pytest.mark.parametrize("seed", range(5))
def test_crash_resume_after_every_step_converges(tmp_path, seed):
    ctx = seed_pair(tmp_path, f"cr{seed}")
    rng = random.Random(2100 + seed)
    epoch = drive_full(
        ctx, resume=True, wrap_first=rng.choice([True, False]), rng=rng
    )
    assert_converged(ctx, epoch)


@pytest.mark.parametrize("seed", range(3))
def test_no_ack_timeout_discards_and_retry_succeeds(tmp_path, seed):
    ctx = seed_pair(tmp_path, f"to{seed}")
    rid = ctx["rid"]
    mi = mgr(ctx, "i")
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=str(uuid.uuid4()))
    epoch = begun["epoch"]
    assert phase(ctx, "i", epoch, "rotating") == "candidate"
    # No ack ever arrives: sweep past the deadline discards the candidate.
    with pytest.raises(NoAckTimeout):
        mi.sweep(now=T0 + DAY + timedelta(minutes=1))
    assert phase(ctx, "i", epoch, "rotating") == "discarded"
    # A later sweep is quiet: the discarded row is not re-reported.
    mi.sweep(now=T0 + 2 * DAY)
    # The old epoch key file is untouched by the discard.
    assert key_state(ctx, "i", 1) == {"active"}
    # A fresh rotation can be started and driven to completion.
    epoch2 = drive_full(ctx)
    assert epoch2 == epoch
    assert_converged(ctx, epoch2)


def test_second_begin_rejected_then_new_rotation_after_commit(tmp_path):
    ctx = seed_pair(tmp_path, "db")
    rid = ctx["rid"]
    mi = mgr(ctx, "i")
    # Complete one rotation canonically first.
    epoch = drive_full(ctx)
    assert epoch == 2
    assert_converged(ctx, epoch)
    # A new rotation can start on the next epoch...
    prep_event = str(uuid.uuid4())
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=prep_event)
    assert begun["epoch"] == 3
    # ...but not while it is still in flight.
    with pytest.raises(RotationError) as excinfo:
        mi.begin_rotation(rid, now=T0, prepare_event_id=str(uuid.uuid4()))
    assert excinfo.value.code == "rotation_in_flight"
    # Drive the in-flight rotation to completion too.
    epoch3 = drive_full(ctx, begun=begun, prep_event=prep_event)
    assert epoch3 == 3
    assert_converged(ctx, epoch3)
