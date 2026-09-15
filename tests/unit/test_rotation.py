"""Unit tests for key rotation (checkpoint 8).

Covers: payload shapes, the full rotating/acking round trip, the no-ack
timeout, the acknowledged-but-unconfirmed send pause, conflicting prepares
(quarantine + human resolution), unknown future epochs (quarantine then
rejection), dual-wrap CEK decryption on both epochs, old-key deletion after
commit (time and event-count triggers), and identity signing-key rotation
with cross-signatures.
"""

import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.expanduser("~/workspace/mas-release/src"))
sys.path.insert(0, os.path.expanduser("~/workspace/mas-build/track-pairing/src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from muse_agent_social._keyfiles import store_private_key
from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
    derive_identity_hierarchy,
    generate_master_seed,
)
from muse_agent_social.crypto.rotation import (
    ConfirmRejected,
    IdentityRotationError,
    NoAckTimeout,
    RotationError,
    RotationManager,
    agreement_fingerprint,
    build_ack,
    build_commit,
    build_confirm,
    build_prepare,
    rotate_identity_key,
    unwrap_cek,
    verify_identity_rotation,
    wrap_cek,
)
from muse_agent_social.model.cards import create_card, verify_card
from muse_agent_social.store.migrations import migrate
from muse_agent_social.validation import ValidationError

T0 = datetime(2026, 9, 15, 20, 0, 0, tzinfo=timezone.utc)
CAPS = ["events/0.2", "threads/1"]


def make_db():
    conn = sqlite3.connect(":memory:")
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
        "conn_i": conn_i, "conn_a": conn_a, "rid": rid,
        "priv_i": priv_i, "pub_i": pub_i, "path_i": path_i,
        "priv_a": priv_a, "pub_a": pub_a, "path_a": path_a,
    }


def keyrow(conn, rid, epoch):
    return conn.execute(
        "SELECT * FROM key_epochs WHERE relationship_id=? AND epoch=?",
        (rid, epoch),
    ).fetchone()


def rotation_row(conn, rid, epoch):
    return conn.execute(
        "SELECT * FROM key_rotations WHERE relationship_id=? AND epoch=?",
        (rid, epoch),
    ).fetchone()


def fresh_keys(tmp_path):
    keys_i = str(tmp_path / "ki")
    keys_a = str(tmp_path / "ka")
    ctx = seed_relationship(keys_i, keys_a)
    mi = RotationManager(ctx["conn_i"], keys_i)
    ma = RotationManager(ctx["conn_a"], keys_a)
    return ctx, mi, ma


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def test_payload_builders_match_landed_schema():
    deadline = T0 + timedelta(hours=24)
    pub = agreement_key_multibase_from_pubkey(
        X25519PrivateKey.generate().public_key().public_bytes_raw()
    )
    prepare = build_prepare(pub, "a" * 43, deadline)
    assert set(prepare) == {"deadline", "new_agreement_key", "prior_fingerprint"}
    assert prepare["deadline"] == "2026-09-16T20:00:00Z"
    event_id = str(uuid.uuid4())
    ack = build_ack(2, event_id)
    assert ack == {"epoch": 2, "prepare_event_id": event_id}
    assert build_confirm(2) == {"epoch": 2}
    assert build_commit(2) == {"epoch": 2}


def test_payload_builders_reject_garbage():
    with pytest.raises(ValidationError):
        build_prepare("not-a-key", "a" * 43, T0 + timedelta(hours=24))
    with pytest.raises(ValidationError):
        build_ack(0, str(uuid.uuid4()))
    with pytest.raises(ValidationError):
        build_ack(2, "not-a-uuid")
    with pytest.raises(ValidationError):
        build_confirm(-1)


def test_agreement_fingerprint_is_stable():
    raw = X25519PrivateKey.generate().public_key().public_bytes_raw()
    pub = agreement_key_multibase_from_pubkey(raw)
    assert agreement_fingerprint(pub) == agreement_fingerprint(pub)
    assert len(agreement_fingerprint(pub)) == 43  # b64url, no padding


# ---------------------------------------------------------------------------
# Full round trip (rotating side + acking side)
# ---------------------------------------------------------------------------

def test_full_rotation_round_trip(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    prepare_event_id = str(uuid.uuid4())

    # 1. Prepare: rotating side generates epoch 2.
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=prepare_event_id)
    assert begun["epoch"] == 2
    prepare = begun["prepare"]
    assert keyrow(ctx["conn_i"], rid, 2)["state"] == "candidate"
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "candidate"

    # 2. Acknowledge: peer stores the candidate, returns the ack.
    ack = ma.on_prepare(rid, prepare, prepare_event_id, now=T0)
    assert ack == {"epoch": 2, "prepare_event_id": prepare_event_id}
    peer_row = keyrow(ctx["conn_a"], rid, 2)
    assert peer_row["state"] == "acknowledged"
    assert peer_row["private_key_ref"] == "peer"
    assert peer_row["public_key"] == prepare["new_agreement_key"]

    mi.on_ack(rid, ack, now=T0)
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "acknowledged"

    # 3. Dual-wrap: the peer wraps to both the old and new keys.
    keys = ma.dual_wrap_keys(rid)
    assert set(keys) == {1, 2}
    assert keys[1] == ctx["pub_i"] and keys[2] == prepare["new_agreement_key"]
    cek = os.urandom(32)
    wraps = wrap_cek(cek, keys)

    # The rotating side decrypts the new-epoch wrap with its new key.
    new_priv = X25519PrivateKey.from_private_bytes(
        open(keyrow(ctx["conn_i"], rid, 2)["private_key_ref"], "rb").read()
    )
    assert unwrap_cek(wraps, 2, new_priv) == cek
    # ... and the old-epoch wrap with its old key.
    assert unwrap_cek(wraps, 1, ctx["priv_i"]) == cek
    mi.note_decrypted_new_wrap(rid, 2, now=T0)

    # 4. Confirm.
    confirm = mi.confirm_rotation(rid, now=T0)
    assert confirm == {"epoch": 2}
    ma.on_confirm(rid, confirm, now=T0)
    assert rotation_row(ctx["conn_a"], rid, 2)["phase"] == "confirmed"

    # 5. Commit: the peer stops writing old wraps.
    commit = ma.build_commit_payload(rid, now=T0)
    assert commit == {"epoch": 2}
    assert keyrow(ctx["conn_a"], rid, 2)["state"] == "active"
    mi.on_commit(rid, commit, now=T0)
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "committed"
    assert keyrow(ctx["conn_i"], rid, 2)["state"] == "active"
    assert keyrow(ctx["conn_i"], rid, 1)["state"] == "retired"
    rel = ctx["conn_i"].execute(
        "SELECT key_epoch FROM relationships WHERE relationship_id=?", (rid,)
    ).fetchone()
    assert rel["key_epoch"] == 2

    # The old private key is retained until the retention condition fires.
    assert os.path.exists(ctx["path_i"])


def test_begin_rotation_rejects_in_flight(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    mi.begin_rotation(ctx["rid"], now=T0)
    with pytest.raises(RotationError) as excinfo:
        mi.begin_rotation(ctx["rid"], now=T0)
    assert excinfo.value.code == "rotation_in_flight"


def test_on_prepare_rejects_unknown_prior(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    prepare = build_prepare(
        agreement_key_multibase_from_pubkey(
            X25519PrivateKey.generate().public_key().public_bytes_raw()
        ),
        "z" * 43,
        T0 + timedelta(hours=24),
    )
    with pytest.raises(RotationError) as excinfo:
        ma.on_prepare(ctx["rid"], prepare, str(uuid.uuid4()), now=T0)
    assert excinfo.value.code == "unknown_prior_fingerprint"


def test_on_prepare_is_idempotent_on_redelivery(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    event_id = str(uuid.uuid4())
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=event_id)
    ack1 = ma.on_prepare(rid, begun["prepare"], event_id, now=T0)
    ack2 = ma.on_prepare(rid, begun["prepare"], event_id, now=T0)
    assert ack1 == ack2


def test_on_ack_rejects_wrong_prepare_event_id(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=str(uuid.uuid4()))
    ack = ma.on_prepare(rid, begun["prepare"], str(uuid.uuid4()), now=T0)
    ack = dict(ack)
    ack["prepare_event_id"] = str(uuid.uuid4())  # forged binding
    with pytest.raises(ConfirmRejected):
        mi.on_ack(rid, ack, now=T0)


def test_confirm_requires_decrypted_new_wrap(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    event_id = str(uuid.uuid4())
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=event_id)
    ack = ma.on_prepare(rid, begun["prepare"], event_id, now=T0)
    mi.on_ack(rid, ack, now=T0)
    with pytest.raises(RotationError) as excinfo:
        mi.confirm_rotation(rid, now=T0)
    assert excinfo.value.code == "no_new_wrap_seen"


def test_on_commit_requires_confirm_first(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    event_id = str(uuid.uuid4())
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=event_id)
    ack = ma.on_prepare(rid, begun["prepare"], event_id, now=T0)
    mi.on_ack(rid, ack, now=T0)
    # Peer jumps the gun and commits before any confirm.
    with pytest.raises(RotationError):
        ma.build_commit_payload(rid, now=T0)
    with pytest.raises(ConfirmRejected):
        mi.on_commit(rid, build_commit(2), now=T0)


# ---------------------------------------------------------------------------
# Failure behavior
# ---------------------------------------------------------------------------

def test_no_ack_timeout_discards_candidate(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    begun = mi.begin_rotation(rid, now=T0)
    new_key_path = keyrow(ctx["conn_i"], rid, 2)["private_key_ref"]
    assert os.path.exists(new_key_path)
    with pytest.raises(NoAckTimeout) as excinfo:
        mi.sweep(now=T0 + timedelta(hours=25))
    assert excinfo.value.epoch == 2
    assert keyrow(ctx["conn_i"], rid, 2) is None
    assert not os.path.exists(new_key_path)
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "discarded"
    rel = ctx["conn_i"].execute(
        "SELECT key_epoch FROM relationships WHERE relationship_id=?", (rid,)
    ).fetchone()
    assert rel["key_epoch"] == 1


def test_acknowledged_but_unconfirmed_pauses_sends(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    event_id = str(uuid.uuid4())
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=event_id)
    ack = ma.on_prepare(rid, begun["prepare"], event_id, now=T0)
    mi.on_ack(rid, ack, now=T0)
    # Before the deadline, sends are fine.
    ma.may_send(rid, now=T0 + timedelta(hours=23))
    # After the deadline with no confirm: pause and alert.
    with pytest.raises(RotationError) as excinfo:
        ma.may_send(rid, now=T0 + timedelta(hours=25))
    assert excinfo.value.code == "send_paused_acknowledged"


def _run_to_commit(ctx, mi, ma, now=T0):
    """Drive a rotation to commit; return (prepare, ack, confirm, commit)."""
    rid = ctx["rid"]
    event_id = str(uuid.uuid4())
    begun = mi.begin_rotation(rid, now=now, prepare_event_id=event_id)
    ack = ma.on_prepare(rid, begun["prepare"], event_id, now=now)
    mi.on_ack(rid, ack, now=now)
    mi.note_decrypted_new_wrap(rid, 2, now=now)
    confirm = mi.confirm_rotation(rid, now=now)
    ma.on_confirm(rid, confirm, now=now)
    commit = ma.build_commit_payload(rid, now=now)
    mi.on_commit(rid, commit, now=now)
    return begun["prepare"], ack, confirm, commit


def test_conflicting_prepares_quarantine_and_resolve(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]

    # Both sides rotate into epoch 2 within the same window.
    event_a = str(uuid.uuid4())
    event_b = str(uuid.uuid4())
    begun_a = mi.begin_rotation(rid, now=T0, prepare_event_id=event_a)
    begun_b = ma.begin_rotation(rid, now=T0, prepare_event_id=event_b)

    # A's prepare arrives at B: conflict, quarantined.
    with pytest.raises(RotationError) as excinfo:
        ma.on_prepare(rid, begun_a["prepare"], event_a, now=T0)
    assert excinfo.value.code == "conflicting_prepare"
    assert len(ma.list_quarantine(rid)) == 1

    # B's prepare arrives at A: conflict, quarantined.
    with pytest.raises(RotationError) as excinfo:
        mi.on_prepare(rid, begun_b["prepare"], event_b, now=T0)
    assert excinfo.value.code == "conflicting_prepare"

    # Human review picks B's key on both sides.
    assert ma.resolve_quarantine(rid, 0, "mine") is None
    assert len(ma.list_quarantine(rid)) == 0
    # A discards its candidate and processes B's prepare as the acker.
    ack_from_a = mi.resolve_quarantine(rid, 0, "theirs", now=T0)
    assert ack_from_a["epoch"] == 2
    assert keyrow(ctx["conn_i"], rid, 2)["private_key_ref"] == "peer"

    # The rotation now completes with B as the rotating side.
    ma.on_ack(rid, ack_from_a, now=T0)
    ma.note_decrypted_new_wrap(rid, 2, now=T0)
    confirm = ma.confirm_rotation(rid, now=T0)
    mi.on_confirm(rid, confirm, now=T0)
    commit = mi.build_commit_payload(rid, now=T0)
    ma.on_commit(rid, commit, now=T0)
    assert rotation_row(ctx["conn_a"], rid, 2)["phase"] == "committed"
    assert rotation_row(ctx["conn_i"], rid, 2)["phase"] == "committed"


def test_resolve_quarantine_bad_choice(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    begun_a = mi.begin_rotation(rid, now=T0)
    begun_b = ma.begin_rotation(rid, now=T0)
    with pytest.raises(RotationError):
        ma.on_prepare(rid, begun_a["prepare"], str(uuid.uuid4()), now=T0)
    with pytest.raises(RotationError) as excinfo:
        ma.resolve_quarantine(rid, 0, "both")
    assert excinfo.value.code == "bad_choice"
    with pytest.raises(RotationError) as excinfo:
        ma.resolve_quarantine(rid, 5, "mine")
    assert excinfo.value.code == "bad_quarantine_index"


def test_unknown_future_epoch_quarantine_then_reject(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    with pytest.raises(RotationError) as excinfo:
        ma.on_data_event_epoch(rid, 5, now=T0)
    assert excinfo.value.code == "unknown_future_epoch"
    assert len(ma.list_quarantine(rid)) == 1
    # Redelivery inside the window: still quarantined, still retryable.
    with pytest.raises(RotationError) as excinfo:
        ma.on_data_event_epoch(rid, 5, now=T0 + timedelta(hours=12))
    assert excinfo.value.code == "unknown_future_epoch"
    # After 24h with no legitimate epoch: rejected.
    with pytest.raises(RotationError) as excinfo:
        ma.on_data_event_epoch(rid, 5, now=T0 + timedelta(hours=25))
    assert excinfo.value.code == "unknown_future_epoch_rejected"
    # And it stays rejected.
    with pytest.raises(RotationError) as excinfo:
        ma.on_data_event_epoch(rid, 5, now=T0 + timedelta(hours=26))
    assert excinfo.value.code == "unknown_future_epoch_rejected"


def test_prepare_resolves_future_epoch_quarantine(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    with pytest.raises(RotationError):
        ma.on_data_event_epoch(rid, 2, now=T0)
    assert len(ma.list_quarantine(rid)) == 1
    event_id = str(uuid.uuid4())
    begun = mi.begin_rotation(rid, now=T0, prepare_event_id=event_id)
    ma.on_prepare(rid, begun["prepare"], event_id, now=T0)
    # The legitimate prepare cleared the queued future-epoch entry.
    assert ma.list_quarantine(rid) == []
    assert ma.on_data_event_epoch(rid, 2, now=T0) == "ok"


def test_known_epochs_pass_the_gate(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    assert ma.on_data_event_epoch(ctx["rid"], 1, now=T0) == "ok"


# ---------------------------------------------------------------------------
# Old-key retention
# ---------------------------------------------------------------------------

def test_old_key_deleted_after_24h(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    _run_to_commit(ctx, mi, ma, now=T0)
    assert os.path.exists(ctx["path_i"])
    mi.sweep(now=T0 + timedelta(hours=23))
    assert os.path.exists(ctx["path_i"])
    mi.sweep(now=T0 + timedelta(hours=25))
    assert not os.path.exists(ctx["path_i"])
    assert keyrow(ctx["conn_i"], rid, 1) is None
    rel = ctx["conn_i"].execute(
        "SELECT key_epoch FROM relationships WHERE relationship_id=?", (rid,)
    ).fetchone()
    assert rel["key_epoch"] == 2


def test_old_key_deleted_after_100_events(tmp_path):
    ctx, mi, ma = fresh_keys(tmp_path)
    rid = ctx["rid"]
    _run_to_commit(ctx, mi, ma, now=T0)
    for _ in range(99):
        mi.note_accepted_event(rid, now=T0)
        mi.sweep(now=T0)
        assert os.path.exists(ctx["path_i"])
    mi.note_accepted_event(rid, now=T0)
    mi.sweep(now=T0)
    assert not os.path.exists(ctx["path_i"])
    assert keyrow(ctx["conn_i"], rid, 1) is None


# ---------------------------------------------------------------------------
# CEK wrap primitives
# ---------------------------------------------------------------------------

def test_wrap_cek_round_trip_single_epoch():
    priv = X25519PrivateKey.generate()
    pub = agreement_key_multibase_from_pubkey(priv.public_key().public_bytes_raw())
    cek = os.urandom(32)
    wraps = wrap_cek(cek, {1: pub})
    assert set(wraps) == {"1"}
    assert unwrap_cek(wraps, 1, priv) == cek


def test_wrap_cek_rejects_bad_inputs():
    priv = X25519PrivateKey.generate()
    pub = agreement_key_multibase_from_pubkey(priv.public_key().public_bytes_raw())
    with pytest.raises(RotationError):
        wrap_cek(b"short", {1: pub})
    with pytest.raises(RotationError):
        wrap_cek(os.urandom(32), {})
    with pytest.raises(RotationError):
        unwrap_cek({"1": {"ephemeral_public_key": "zz", "wrapped_cek": "e30"}}, 1, priv)
    with pytest.raises(RotationError):
        unwrap_cek({}, 9, priv)


# ---------------------------------------------------------------------------
# Identity signing-key rotation
# ---------------------------------------------------------------------------

def make_card_holder(name="Holder"):
    ident = derive_identity_hierarchy(generate_master_seed())
    card = create_card(
        ident.ed25519_private, name, "Test Principal",
        ident.agreement_key_multibase, CAPS, T0, T0 + timedelta(days=30),
    )
    assert verify_card(card, T0).ok
    return ident, card


def test_identity_rotation_cross_signed_announcement():
    ident, card = make_card_holder()
    new_priv = Ed25519PrivateKey.generate()
    announcement = rotate_identity_key(card, ident.ed25519_private, new_priv, T0)
    assert announcement["rotation_version"] == 1
    assert len(announcement["prior_card_fingerprint"]) == 64
    new_card = announcement["new_card"]
    # The identity ID changes because it is key-derived.
    assert new_card["identity_id"] != card["identity_id"]
    assert verify_card(new_card, T0).ok
    # Display labels and agreement key carry over.
    assert new_card["display_name"] == card["display_name"]
    assert new_card["bootstrap_agreement_key"] == card["bootstrap_agreement_key"]
    assert verify_identity_rotation(announcement, card, T0)


def test_identity_rotation_requires_old_key():
    _, card = make_card_holder()
    with pytest.raises(IdentityRotationError) as excinfo:
        rotate_identity_key(card, None, Ed25519PrivateKey.generate(), T0)
    assert excinfo.value.code == "old_key_unavailable"


def test_identity_rotation_rejects_tampered_cross_signature():
    ident, card = make_card_holder()
    announcement = rotate_identity_key(
        card, ident.ed25519_private, Ed25519PrivateKey.generate(), T0
    )
    announcement["cross_signatures"][0]["signature"] = b64url_sig("A")
    assert not verify_identity_rotation(announcement, card, T0)


def b64url_sig(char):
    from muse_agent_social.crypto.identity import b64url_encode
    return b64url_encode((char * 64).encode("latin1"))


def test_identity_rotation_rejects_wrong_prior_card():
    ident, card = make_card_holder()
    _, other_card = make_card_holder("Other")
    announcement = rotate_identity_key(
        card, ident.ed25519_private, Ed25519PrivateKey.generate(), T0
    )
    assert not verify_identity_rotation(announcement, other_card, T0)


def test_identity_rotation_rejects_tampered_new_card():
    ident, card = make_card_holder()
    announcement = rotate_identity_key(
        card, ident.ed25519_private, Ed25519PrivateKey.generate(), T0
    )
    announcement["new_card"]["display_name"] = "Mallory"
    assert not verify_identity_rotation(announcement, card, T0)


def test_identity_rotation_rejects_key_mismatch():
    ident, card = make_card_holder()
    other_ident, _ = make_card_holder("Other")
    with pytest.raises(IdentityRotationError) as excinfo:
        rotate_identity_key(
            card, other_ident.ed25519_private, Ed25519PrivateKey.generate(), T0
        )
    assert excinfo.value.code == "key_mismatch"
