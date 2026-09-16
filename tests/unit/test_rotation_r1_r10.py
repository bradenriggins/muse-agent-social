"""Regression tests for the R1-R10 identity-rotation state machine fixes.

Each test maps to one finding from the adversarial review of the Agent
Social Layer v0.2 identity rotation:

- R1: sweep vs concurrent ack race; keyless timeout still reported.
- R2: new-wrap decrypt signal during candidate phase (park + consume).
- R3: multi-write transitions are real transactions (rollback + guards).
- R4: build/send/mark split; payloads re-emit idempotently.
- R5: orphan key-file reconciliation (rotation begin + pairing commit).
- R6: redelivered prepare heals a missing rotation row.
- R7: own-key-without-row is conflicting_prepare, not stale_epoch.
- R8: hook idempotency + reconciler convergence (manager and CLI).
- R9: teardown recaptures key rows inserted after the step-3 capture.
- R10: accepted-event counter follows the live epoch; retired rows are deleted.
"""

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from muse_agent_social._keyfiles import store_private_key
from muse_agent_social.crypto.identity import agreement_key_multibase_from_pubkey
from muse_agent_social.crypto.rotation import (
    ConfirmRejected,
    NoAckTimeout,
    RotationError,
    RotationManager,
)
from muse_agent_social.store.migrations import migrate

T0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)


def make_db():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    migrate(conn)
    return conn


def seed_relationship(keys_i, keys_a):
    """Seed a committed epoch-1 relationship on both sides; return context."""
    conn_i, conn_a = make_db(), make_db()
    rid = str(uuid.uuid4())

    def add(conn, keys_dir):
        os.makedirs(keys_dir, exist_ok=True)
        priv = X25519PrivateKey.generate()
        pub = agreement_key_multibase_from_pubkey(priv.public_key().public_bytes_raw())
        path = os.path.join(keys_dir, "e1.key")
        store_private_key(path, priv.private_bytes_raw())
        conn.execute(
            "INSERT INTO relationships (relationship_id, peer_identity_id, "
            "peer_display_name, peer_agreement_key, consent_state, policy, "
            "key_epoch, created_at) "
            "VALUES (?, ?, ?, ?, 'active', '{}', 1, ?)",
            (rid, "id:test:peer", "Peer", pub,
             T0.isoformat().replace("+00:00", "Z")),
        )
        conn.execute(
            "INSERT INTO key_epochs (relationship_id, epoch, public_key, "
            "private_key_ref, state) VALUES (?, 1, ?, ?, 'active')",
            (rid, pub, path),
        )
        return priv, pub, path

    priv_i, pub_i, path_i = add(conn_i, keys_i)
    priv_a, pub_a, path_a = add(conn_a, keys_a)
    conn_i.execute(
        "UPDATE relationships SET peer_agreement_key=? WHERE relationship_id=?",
        (pub_a, rid),
    )
    conn_a.execute(
        "UPDATE relationships SET peer_agreement_key=? WHERE relationship_id=?",
        (pub_i, rid),
    )
    return {
        "conn_i": conn_i, "conn_a": conn_a, "rid": rid,
        "priv_i": priv_i, "pub_i": pub_i, "path_i": path_i,
        "priv_a": priv_a, "pub_a": pub_a, "path_a": path_a,
    }


def fresh_keys(tmp_path):
    keys_i, keys_a = tmp_path / "ki", tmp_path / "ka"
    ctx = seed_relationship(str(keys_i), str(keys_a))
    mi = RotationManager(ctx["conn_i"], keys_i)
    ma = RotationManager(ctx["conn_a"], keys_a)
    return ctx, mi, ma


def rotation_row(conn, rid, epoch):
    return conn.execute(
        "SELECT * FROM key_rotations WHERE relationship_id=? AND epoch=? "
        "AND role='rotating'",
        (rid, epoch),
    ).fetchone()


def acking_row(conn, rid, epoch):
    return conn.execute(
        "SELECT * FROM key_rotations WHERE relationship_id=? AND epoch=? "
        "AND role='acking'",
        (rid, epoch),
    ).fetchone()


def keyrow(conn, rid, epoch):
    return conn.execute(
        "SELECT * FROM key_epochs WHERE relationship_id=? AND epoch=?",
        (rid, epoch),
    ).fetchone()


def _run_to_acknowledged(ctx, mi, ma, now=T0, with_wrap_seen=True):
    rid = ctx["rid"]
    prepare_event_id = str(uuid.uuid4())
    begun = mi.begin_rotation(rid, now=now, prepare_event_id=prepare_event_id)
    ack = ma.on_prepare(rid, begun["prepare"], prepare_event_id, now=now)
    if with_wrap_seen:
        mi.note_decrypted_new_wrap(rid, begun["epoch"], now=now)
    mi.on_ack(rid, ack, now=now)
    return begun, ack


def _run_to_commit(ctx, mi, ma, now=T0):
    rid = ctx["rid"]
    begun, ack = _run_to_acknowledged(ctx, mi, ma, now=now)
    confirm = mi.confirm_rotation(rid, now=now)
    ma.on_confirm(rid, confirm, now=now)
    commit = ma.build_commit_payload(rid, now=now)
    ma.mark_committed(rid, now=now)
    mi.on_commit(rid, commit, now=now)
    return begun, ack, confirm, commit


# ---------------------------------------------------------------------------
# R1: timeout sweep vs concurrent ack; keyless timeout still reported
# ---------------------------------------------------------------------------

def test_r1_late_ack_cannot_resurrect_discarded_candidate(tmp_path):
    """The R1 race: sweep discards a candidate, then the ack arrives late.

    The unguarded UPDATE used to flip the discarded row back to
    acknowledged after its key file was deleted. Now the ack is rejected
    and the row stays discarded.
    """
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    begun, ack = _run_to_acknowledged(ctx, mi, ma)
    # Rewind: put the rotation back in candidate phase for the timeout.
    ctx["conn_i"].execute(
        "UPDATE key_rotations SET phase='candidate' WHERE relationship_id=? "
        "AND epoch=2 AND role='rotating'",
        (rid,),
    )
    with pytest.raises(NoAckTimeout):
        mi.sweep(now=T0 + timedelta(hours=25))
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "discarded"
    # The late ack must not resurrect the row.
    with pytest.raises(ConfirmRejected):
        mi.on_ack(rid, ack, now=T0 + timedelta(hours=26))
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "discarded"


def test_r1_keyless_candidate_still_discarded_and_reported(tmp_path):
    """A timed-out candidate whose key row is already gone must still be
    discarded AND raise NoAckTimeout. The old code returned None for both
    'guard refused' and 'claimed but keyless', so the sweep silently
    swallowed the timeout."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    begun = mi.begin_rotation(rid, now=T0)
    # The key row is lost (disk incident, manual cleanup).
    ctx["conn_i"].execute(
        "DELETE FROM key_epochs WHERE relationship_id=? AND epoch=2", (rid,)
    )
    with pytest.raises(NoAckTimeout):
        mi.sweep(now=T0 + timedelta(hours=25))
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "discarded"


def test_r1_sweep_does_not_touch_acknowledged_row(tmp_path):
    """The guarded discard's phase predicate: a candidate that became
    acknowledged before the sweep (the lost ack race) is left alone."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    _run_to_acknowledged(ctx, mi, ma)
    # The ack landed; sweep runs with a stale view of a candidate.
    mi.sweep(now=T0 + timedelta(hours=25))
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "acknowledged"
    assert keyrow(ctx["conn_i"], rid, 2) is not None


# ---------------------------------------------------------------------------
# R2: new-wrap decrypt signal survives the candidate phase
# ---------------------------------------------------------------------------

def test_r2_wrap_signal_parked_before_rotation_row_exists(tmp_path):
    """A new-epoch data event decrypted before the rotation row exists
    parks the signal instead of raising. The ack then consumes it, so
    confirm_rotation does not fail with no_new_wrap_seen."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    mi.note_decrypted_new_wrap(rid, 2, now=T0)
    pending = ctx["conn_i"].execute(
        "SELECT * FROM rotation_wrap_seen_pending "
        "WHERE relationship_id=? AND epoch=2",
        (rid,),
    ).fetchone()
    assert pending is not None
    begun, ack = _run_to_acknowledged(ctx, mi, ma, with_wrap_seen=False)
    # The ack consumed the parked signal.
    assert rotation_row(ctx["conn_i"], rid, 2)["new_wrap_seen"] == 1
    assert ctx["conn_i"].execute(
        "SELECT COUNT(*) FROM rotation_wrap_seen_pending"
    ).fetchone()[0] == 0
    assert mi.confirm_rotation(rid, now=T0) == {"epoch": 2}


def test_r2_wrap_signal_during_candidate_does_not_raise(tmp_path):
    """The exact reported failure: a new-wrap decrypt during the candidate
    phase used to raise no_acknowledged_rotation, then the later confirm
    failed with no_new_wrap_seen. Now the signal is recorded directly."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    mi.begin_rotation(rid, now=T0)
    mi.note_decrypted_new_wrap(rid, 2, now=T0)  # must not raise
    assert rotation_row(ctx["conn_i"], rid, 2)["new_wrap_seen"] == 1


# ---------------------------------------------------------------------------
# R3: multi-write transitions are real transactions
# ---------------------------------------------------------------------------

def test_r3_no_bare_with_conn_in_rotation_module():
    """Structural guard: in production autocommit a bare ``with self.conn:``
    is not a transaction. Every multi-write path must use _txn."""
    import inspect

    import muse_agent_social.crypto.rotation as rotation_mod

    assert "with self.conn:" not in inspect.getsource(rotation_mod)


def test_r3_failed_multi_write_rolls_back(tmp_path):
    """A failure inside a rotation transaction leaves no partial rows."""
    import muse_agent_social.crypto.rotation as rotation_mod

    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    with pytest.raises(RuntimeError, match="boom"):
        with rotation_mod._txn(ctx["conn_i"]):
            ctx["conn_i"].execute(
                "INSERT INTO key_rotations (relationship_id, role, epoch, "
                "prior_epoch, phase, prepare_event_id, prepared_at, deadline) "
                "VALUES (?, 'rotating', 99, 1, 'candidate', 'x', "
                "'2026-09-15T12:00:00Z', '2026-09-16T12:00:00Z')",
                (rid,),
            )
            raise RuntimeError("boom")
    assert ctx["conn_i"].execute(
        "SELECT COUNT(*) FROM key_rotations WHERE epoch=99"
    ).fetchone()[0] == 0


def test_r3_concurrent_discard_wins_over_late_ack(tmp_path):
    """If the row was discarded before the ack is processed, the guarded
    on_ack rejects the ack instead of resurrecting the row (the write that
    used to follow the sweep SELECT in autocommit)."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    begun, ack = _run_to_acknowledged(ctx, mi, ma)
    ctx["conn_i"].execute(
        "UPDATE key_rotations SET phase='discarded' WHERE relationship_id=? "
        "AND epoch=2 AND role='rotating'",
        (rid,),
    )
    with pytest.raises(ConfirmRejected):
        mi.on_ack(rid, ack, now=T0)
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "discarded"


# ---------------------------------------------------------------------------
# R4: build/send/mark split; payloads re-emit idempotently
# ---------------------------------------------------------------------------

def test_r4_confirm_payload_reemit_after_failed_send(tmp_path):
    """Building a payload must not change phase: a failed send leaves the
    rotation retryable, and the payload re-emits byte-identically."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    _run_to_acknowledged(ctx, mi, ma)
    p1 = mi.build_confirm_payload(rid, now=T0)
    assert p1 == {"epoch": 2}
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "acknowledged"
    # The send "fails"; retry re-emits the same payload, phase unchanged.
    p2 = mi.build_confirm_payload(rid, now=T0)
    assert p2 == p1
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "acknowledged"


def test_r4_confirm_mark_is_idempotent_and_reemittable(tmp_path):
    """After the send succeeds and the mark is persisted, a crashed caller
    re-emits the same payload and the mark is a no-op."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    _run_to_acknowledged(ctx, mi, ma)
    p1 = mi.build_confirm_payload(rid, now=T0)
    mi.mark_confirmed(rid, now=T0)
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "confirmed"
    # Crash between send and mark: re-emit, then mark again, both no-ops.
    p2 = mi.build_confirm_payload(rid, now=T0)
    assert p2 == p1
    mi.mark_confirmed(rid, now=T0)
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "confirmed"


def test_r4_confirm_rotation_combined_form_stays_idempotent(tmp_path):
    """The single-call compatibility path stays idempotent for callers
    that already sent the payload."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    _run_to_acknowledged(ctx, mi, ma)
    first = mi.confirm_rotation(rid, now=T0)
    second = mi.confirm_rotation(rid, now=T0)
    assert first == second == {"epoch": 2}


def test_r4_commit_payload_reemit_and_mark_idempotent(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    _run_to_acknowledged(ctx, mi, ma)
    confirm = mi.confirm_rotation(rid, now=T0)
    ma.on_confirm(rid, confirm, now=T0)
    c1 = ma.build_commit_payload(rid, now=T0)
    assert c1 == {"epoch": 2}
    assert acking_row(ctx["conn_a"], rid, 2)["phase"] == "confirmed"
    c2 = ma.build_commit_payload(rid, now=T0)
    assert c2 == c1
    ma.mark_committed(rid, now=T0)
    assert acking_row(ctx["conn_a"], rid, 2)["phase"] == "committed"
    c3 = ma.build_commit_payload(rid, now=T0)
    assert c3 == c1
    ma.mark_committed(rid, now=T0)  # idempotent no-op
    assert acking_row(ctx["conn_a"], rid, 2)["phase"] == "committed"


# ---------------------------------------------------------------------------
# R5: orphan key-file reconciliation (rotation + pairing)
# ---------------------------------------------------------------------------

def test_r5_begin_rotation_recovers_orphan_key_file(tmp_path):
    """A crashed begin_rotation that stored the key file but never wrote
    the DB rows used to wedge every later rotation with FileExistsError.
    Now the orphan is reconciled and the rotation proceeds."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    orphan_path = os.path.join(str(tmp_path / "ki"), f"{rid}-e2.key")
    store_private_key(orphan_path, os.urandom(32))
    begun = mi.begin_rotation(rid, now=T0)  # must not raise
    assert begun["epoch"] == 2
    assert keyrow(ctx["conn_i"], rid, 2) is not None
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "candidate"


def test_r5_begin_rotation_refuses_to_overwrite_live_key(tmp_path):
    """Reconciliation must never destroy a live key: when the DB holds a
    live relationship/key row for the id, the FileExistsError stands."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    mi.begin_rotation(rid, now=T0)  # live rows + live file
    live_path = os.path.join(str(tmp_path / "ki"), f"{rid}-e2.key")
    assert os.path.exists(live_path)
    with pytest.raises(FileExistsError):
        mi._reconcile_orphan_key_file(rid, 2, live_path)
    assert os.path.exists(live_path)  # untouched


def test_r5_pairing_commit_recovers_orphan_epoch1_key(tmp_path):
    """The pairing half of R5: a crashed commit_pairing that stored
    epoch1.key but never committed leaves an orphan; the retry must
    delete it and proceed, while a live-owned file is never touched."""
    from muse_agent_social.model.invites import _reconcile_orphan_pairing_key

    conn = make_db()
    keys_dir = tmp_path / "pairkeys"
    keys_dir.mkdir()
    rid = "pair-orphan-rid"
    key_path = os.path.join(str(keys_dir), "epoch1.key")
    with open(key_path, "wb") as fh:
        fh.write(os.urandom(32))
    # No relationship and no key rows: genuinely orphaned.
    _reconcile_orphan_pairing_key(conn, rid, key_path)
    assert not os.path.exists(key_path)
    # Now a live relationship owns the id: the file must survive.
    with open(key_path, "wb") as fh:
        fh.write(os.urandom(32))
    conn.execute(
        "INSERT INTO relationships (relationship_id, peer_identity_id, "
        "peer_display_name, peer_agreement_key, consent_state, policy, "
        "key_epoch, created_at) VALUES (?, 'x', 'Peer', 'k', 'active', "
        "'{}', 1, ?)",
        (rid, T0.isoformat().replace("+00:00", "Z")),
    )
    with pytest.raises(FileExistsError):
        _reconcile_orphan_pairing_key(conn, rid, key_path)
    assert os.path.exists(key_path)


# ---------------------------------------------------------------------------
# R6: redelivered prepare heals a missing rotation row
# ---------------------------------------------------------------------------

def test_r6_prepare_redelivery_heals_missing_rotation_row(tmp_path):
    """The R6 crash: the peer key row was stored but the acking rotation
    row was lost before commit. The old code returned an ACK while leaving
    the transport's dual_wrap_keys broken (no_acknowledged_rotation).
    Redelivery must repair the row."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    prepare_event_id = str(uuid.uuid4())
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=prepare_event_id)
    prepare = begun["prepare"]
    # Simulate the crash: peer key row stored, rotation row never written.
    ctx["conn_a"].execute(
        "INSERT INTO key_epochs (relationship_id, epoch, public_key, "
        "private_key_ref, state) VALUES (?, 2, ?, 'peer', 'acknowledged')",
        (rid, prepare["new_agreement_key"]),
    )
    assert ctx["conn_a"].execute(
        "SELECT COUNT(*) FROM key_rotations WHERE relationship_id=? "
        "AND epoch=2 AND role='acking'",
        (rid,),
    ).fetchone()[0] == 0
    # Redelivered prepare: ack is returned AND the rotation row is healed.
    ack = ma.on_prepare(rid, prepare, prepare_event_id, now=T0)
    assert ack == {"epoch": 2, "prepare_event_id": prepare_event_id}
    row = ctx["conn_a"].execute(
        "SELECT * FROM key_rotations WHERE relationship_id=? AND epoch=2 "
        "AND role='acking'",
        (rid,),
    ).fetchone()
    assert row is not None
    assert row["phase"] == "acknowledged"
    # dual_wrap_keys works now (previously raised no_acknowledged_rotation).
    keys = ma.dual_wrap_keys(rid)
    assert set(keys) == {1, 2}
    assert keys[2] == prepare["new_agreement_key"]


# ---------------------------------------------------------------------------
# R7: own-key-without-row is a conflict, not a stale epoch
# ---------------------------------------------------------------------------

def test_r7_own_key_without_rotation_row_is_conflicting_prepare(tmp_path):
    """A peer prepare for an epoch where I hold a key row but no rotation
    row used to be misclassified as stale_epoch. It is a genuine conflict
    for human resolution: both sides may have generated the epoch."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    ctx["conn_a"].execute(
        "INSERT INTO key_epochs (relationship_id, epoch, public_key, "
        "private_key_ref, state) VALUES (?, 2, 'zQ3sfake', ?, 'candidate')",
        (rid, os.path.join(str(tmp_path / "ka"), "ka-e2.key")),
    )
    prepare_event_id = str(uuid.uuid4())
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=prepare_event_id)
    with pytest.raises(RotationError) as excinfo:
        ma.on_prepare(rid, begun["prepare"], prepare_event_id, now=T0)
    assert excinfo.value.code == "conflicting_prepare"
    entries = ma.list_quarantine(rid)
    assert len(entries) == 1
    assert entries[0]["reason"] == "conflicting_prepare"


# ---------------------------------------------------------------------------
# R8: hook idempotency + reconciler convergence
# ---------------------------------------------------------------------------

def test_r8_on_ack_idempotent_redrive(tmp_path):
    """A redelivered ack after acknowledgment is a no-op, not an error."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    begun, ack = _run_to_acknowledged(ctx, mi, ma)
    mi.on_ack(rid, ack, now=T0)  # redrive
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "acknowledged"


def test_r8_on_confirm_idempotent_redrive(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    _run_to_acknowledged(ctx, mi, ma)
    confirm = mi.confirm_rotation(rid, now=T0)
    ma.on_confirm(rid, confirm, now=T0)
    ma.on_confirm(rid, confirm, now=T0)  # redrive
    assert acking_row(ctx["conn_a"], rid, 2)["phase"] == "confirmed"


def test_r8_on_commit_idempotent_redrive(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    begun, ack, confirm, commit = _run_to_commit(ctx, mi, ma)
    mi.on_commit(rid, commit, now=T0)  # redrive after commit
    rel = ctx["conn_i"].execute(
        "SELECT key_epoch FROM relationships WHERE relationship_id=?", (rid,)
    ).fetchone()
    assert rel["key_epoch"] == 2
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "committed"


def test_r8_reconciler_redrives_unprocessed_event_once(tmp_path, monkeypatch):
    """CLI: an accepted rotation event whose post-receive hooks never ran
    (crash between the receive commit and the hooks) is re-driven exactly
    once, then marked so later polls skip it."""
    from types import SimpleNamespace

    import muse_agent_social.cli as cli_mod
    from support.harness import (
        fresh_db,
        make_agent,
        new_conversation,
        provision_receive_side,
    )

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    provision_receive_side(conn, rid, bob, alice)
    cli_mod._ensure_cli_tables(conn)
    conv = new_conversation(conn)
    event_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO events (event_id, relationship_id, conversation_id, "
        "sender, sender_seq, created_at, key_epoch, event_type, "
        "replay_nonce, sealed_envelope) "
        "VALUES (?, ?, ?, ?, 1, '2026-09-15T12:00:00Z', 1, "
        "'security.key.ack', ?, ?)",
        (event_id, rid, conv, alice["identity_id"], str(uuid.uuid4()),
         b"sealed"),
    )
    conn.execute(
        "INSERT INTO event_payloads (event_id, event_type, payload) "
        "VALUES (?, ?, ?)",
        (event_id, "security.key.ack",
         json.dumps({"epoch": 2, "prepare_event_id": "x"})),
    )
    ctx = SimpleNamespace(
        conn=conn,
        state_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        identity_id=bob["identity_id"],
    )
    calls = []

    def spy(ctx_, rid_, manager_, event_type_, payload_, event_id_, key_epoch_):
        calls.append((event_type_, event_id_))

    monkeypatch.setattr(cli_mod, "_post_receive_hooks", spy)
    assert cli_mod._reconcile_rotation_events(ctx) == 1
    assert calls == [("security.key.ack", event_id)]
    # Marked: the next poll does not re-drive.
    assert cli_mod._reconcile_rotation_events(ctx) == 0
    assert calls == [("security.key.ack", event_id)]


def test_r8_reconciler_marks_deterministic_rejections(tmp_path, monkeypatch):
    """CLI: when the state machine deterministically rejects the event
    (its answer is final), the reconciler marks it processed instead of
    retrying forever and duplicating quarantine rows."""
    from types import SimpleNamespace

    import muse_agent_social.cli as cli_mod
    from support.harness import (
        fresh_db,
        make_agent,
        new_conversation,
        provision_receive_side,
    )

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    provision_receive_side(conn, rid, bob, alice)
    cli_mod._ensure_cli_tables(conn)
    conv = new_conversation(conn)
    event_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO events (event_id, relationship_id, conversation_id, "
        "sender, sender_seq, created_at, key_epoch, event_type, "
        "replay_nonce, sealed_envelope) "
        "VALUES (?, ?, ?, ?, 1, '2026-09-15T12:00:00Z', 1, "
        "'security.key.prepare', ?, ?)",
        (event_id, rid, conv, alice["identity_id"], str(uuid.uuid4()),
         b"sealed"),
    )
    conn.execute(
        "INSERT INTO event_payloads (event_id, event_type, payload) "
        "VALUES (?, ?, ?)",
        (event_id, "security.key.prepare", json.dumps({"epoch": 9})),
    )
    ctx = SimpleNamespace(
        conn=conn,
        state_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        identity_id=bob["identity_id"],
    )

    def reject(*args, **kwargs):
        raise RotationError("conflicting_prepare", "conflict")

    monkeypatch.setattr(cli_mod, "_post_receive_hooks", reject)
    assert cli_mod._reconcile_rotation_events(ctx) == 1
    # Marked as processed: no infinite retry loop.
    assert cli_mod._reconcile_rotation_events(ctx) == 0


def test_r8_reconciler_retries_transient_failures(tmp_path, monkeypatch):
    """CLI: a transient hook failure stays unmarked so a later poll
    retries it; the marker is written only after success."""
    from types import SimpleNamespace

    import muse_agent_social.cli as cli_mod
    from support.harness import (
        fresh_db,
        make_agent,
        new_conversation,
        provision_receive_side,
    )

    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    rid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    provision_receive_side(conn, rid, bob, alice)
    cli_mod._ensure_cli_tables(conn)
    conv = new_conversation(conn)
    event_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO events (event_id, relationship_id, conversation_id, "
        "sender, sender_seq, created_at, key_epoch, event_type, "
        "replay_nonce, sealed_envelope) "
        "VALUES (?, ?, ?, ?, 1, '2026-09-15T12:00:00Z', 1, "
        "'security.key.ack', ?, ?)",
        (event_id, rid, conv, alice["identity_id"], str(uuid.uuid4()),
         b"sealed"),
    )
    conn.execute(
        "INSERT INTO event_payloads (event_id, event_type, payload) "
        "VALUES (?, ?, ?)",
        (event_id, "security.key.ack",
         json.dumps({"epoch": 2, "prepare_event_id": "x"})),
    )
    ctx = SimpleNamespace(
        conn=conn,
        state_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        identity_id=bob["identity_id"],
    )
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("transient infra failure")

    monkeypatch.setattr(cli_mod, "_post_receive_hooks", flaky)
    cli_mod._reconcile_rotation_events(ctx)
    assert len(calls) == 1
    marked = conn.execute(
        "SELECT COUNT(*) FROM rotation_processed_events WHERE event_id=?",
        (event_id,),
    ).fetchone()[0]
    assert marked == 0  # not marked after the transient failure
    cli_mod._reconcile_rotation_events(ctx)  # retry succeeds
    assert len(calls) == 2
    marked = conn.execute(
        "SELECT COUNT(*) FROM rotation_processed_events WHERE event_id=?",
        (event_id,),
    ).fetchone()[0]
    assert marked == 1


# ---------------------------------------------------------------------------
# R9: teardown recaptures key rows inserted after the step-3 capture
# ---------------------------------------------------------------------------

def test_r9_teardown_recaptures_late_key_row(tmp_path, monkeypatch):
    """A rotation that slips a key row in after step 3's capture (before
    the key_epochs DELETE in step 4) must not leave its private key file
    on disk: step 4 recaptures and destroys it."""
    import muse_agent_social.teardown as teardown_mod
    from muse_agent_social.teardown import teardown_relationship
    from unit.test_teardown import REL, FakeHooks, _build_state

    conn, state_dir, key_files = _build_state(tmp_path)
    keys_dir = state_dir / "keys"
    late_path = keys_dir / "late-rot.key"
    late_path.write_bytes(os.urandom(32))
    os.chmod(late_path, 0o600)
    real_delete = teardown_mod.delete_private_key
    inserted = []

    def spy_delete(ref):
        if not inserted:
            # Simulate the concurrent rotation: the row lands while step 3
            # is destroying the files it captured.
            conn.execute(
                "INSERT INTO key_epochs (relationship_id, epoch, public_key, "
                "private_key_ref, state) VALUES (?, 3, 'pub3', ?, 'candidate')",
                (REL, str(late_path)),
            )
            inserted.append(True)
        return real_delete(ref)

    monkeypatch.setattr(teardown_mod, "delete_private_key", spy_delete)
    report = teardown_relationship(
        conn, state_dir, REL, hooks=FakeHooks(), reason_code="test",
        peer_label="teardown-peer",
    )
    assert not late_path.exists()
    assert str(late_path) in report.keys_destroyed
    assert conn.execute(
        "SELECT COUNT(*) FROM key_epochs WHERE relationship_id=?", (REL,)
    ).fetchone()[0] == 0


# ---------------------------------------------------------------------------
# R10: accepted-event counter follows the live epoch; retired rows die
# ---------------------------------------------------------------------------

def test_r10_accepted_event_counts_current_epoch_only(tmp_path):
    """One event increments exactly one rotation: the committed row for
    the relationship's CURRENT key_epoch. Delayed traffic under an older
    envelope epoch must not bump a historical row."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    _run_to_commit(ctx, mi, ma, now=T0)
    _run_to_commit(ctx, mi, ma, now=T0 + timedelta(minutes=5))
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "committed"
    assert rotation_row(ctx["conn_i"], rid, 3)["phase"] == "committed"
    rel = ctx["conn_i"].execute(
        "SELECT key_epoch FROM relationships WHERE relationship_id=?", (rid,)
    ).fetchone()
    assert rel["key_epoch"] == 3
    mi.note_accepted_event(rid, now=T0)
    c2 = rotation_row(ctx["conn_i"], rid, 2)["accepted_events_since_commit"]
    c3 = rotation_row(ctx["conn_i"], rid, 3)["accepted_events_since_commit"]
    assert (c2, c3) == (0, 1)


def test_r10_sweep_deletes_fully_retired_rotation_row(tmp_path):
    """Once the old key is retired, the committed rotation row itself is
    deleted (it used to accumulate forever). A redelivered commit
    afterwards is a benign no-op, not a rejection."""
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    begun, ack, confirm, commit = _run_to_commit(ctx, mi, ma, now=T0)
    mi.sweep(now=T0 + timedelta(hours=25))
    assert rotation_row(ctx["conn_i"], rid, 2) is None
    assert keyrow(ctx["conn_i"], rid, 1) is None
    assert not os.path.exists(ctx["path_i"])
    # Redelivered commit: no-op (relationship already at epoch 2).
    mi.on_commit(rid, commit, now=T0 + timedelta(hours=26))
    rel = ctx["conn_i"].execute(
        "SELECT key_epoch FROM relationships WHERE relationship_id=?", (rid,)
    ).fetchone()
    assert rel["key_epoch"] == 2
