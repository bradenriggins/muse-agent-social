"""Gate: Rotation.

Two-sided rotation handshake (prepare/ack/confirm/commit), ack timeout
(NoAckTimeout + candidate discard), dual-wrap sends during the transition
window, conflicting-prepare quarantine with human resolution, future-epoch
data-event quarantine with 24h rejection, send pausing after the ack
deadline, and epoch-1 preservation. Fresh random keys per run.
"""

import uuid

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from muse_agent_social.crypto.identity import parse_agreement_key
from muse_agent_social.crypto.rotation import (
    NoAckTimeout,
    RotationError,
    RotationManager,
    build_ack,
)

from support.harness import (
    fresh_db,
    make_agent,
    provision_receive_side,
)

UTC = timezone.utc


@pytest.fixture()
def two_sides(tmp_path):
    """Two independent stores, one per agent, with a shared relationship."""
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    rid = "66666666-7777-4888-8999-000000000000"
    conn_a = fresh_db(tmp_path / "alice.db")
    conn_b = fresh_db(tmp_path / "bob.db")
    keys_a = tmp_path / "keys_a"
    keys_b = tmp_path / "keys_b"
    provision_receive_side(conn_a, rid, alice, bob, keys_dir=str(keys_a))
    provision_receive_side(conn_b, rid, bob, alice, keys_dir=str(keys_b))
    mgr_a = RotationManager(conn_a, str(keys_a))
    mgr_b = RotationManager(conn_b, str(keys_b))
    t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
    return {
        "alice": alice, "bob": bob, "rid": rid,
        "conn_a": conn_a, "conn_b": conn_b,
        "mgr_a": mgr_a, "mgr_b": mgr_b, "t0": t0,
        "keys_a": keys_a, "keys_b": keys_b,
    }


def _load_priv(keys_dir, rid, epoch):
    raw = open(keys_dir / f"{rid}-e{epoch}.key", "rb").read()
    return X25519PrivateKey.from_private_bytes(raw)


def _full_handshake(two_sides):
    """Run prepare/ack/confirm/commit between the sides. Bob rotates."""
    t0 = two_sides["t0"]
    rid = two_sides["rid"]
    mgr_a, mgr_b = two_sides["mgr_a"], two_sides["mgr_b"]
    begun = mgr_b.begin_rotation(rid, now=t0)
    assert begun["epoch"] == 2
    ack = mgr_a.on_prepare(rid, begun["prepare"], str(uuid.uuid4()), now=t0)
    mgr_b.on_ack(rid, ack, now=t0)
    mgr_b.note_decrypted_new_wrap(rid, 2, now=t0)
    confirm = mgr_b.confirm_rotation(rid, now=t0)
    mgr_a.on_confirm(rid, confirm, now=t0)
    commit = mgr_a.build_commit_payload(rid, now=t0)
    mgr_a.mark_committed(rid, now=t0)
    mgr_b.on_commit(rid, commit, now=t0)
    return begun


def _own_epochs(conn, rid):
    return {
        r["epoch"]: dict(r)
        for r in conn.execute(
            "SELECT * FROM key_epochs WHERE relationship_id = ?"
            " AND private_key_ref != 'peer'",
            (rid,),
        ).fetchall()
    }


# -- handshake -----------------------------------------------------------------


def test_full_handshake_reaches_epoch_2(two_sides):
    rid = two_sides["rid"]
    _full_handshake(two_sides)
    for conn in (two_sides["conn_a"], two_sides["conn_b"]):
        epoch = conn.execute(
            "SELECT key_epoch FROM relationships WHERE relationship_id = ?",
            (rid,),
        ).fetchone()[0]
        assert epoch == 2
    own_b = _own_epochs(two_sides["conn_b"], rid)
    assert own_b[2]["state"] == "active"
    assert own_b[1]["state"] == "retired"


def test_epoch_1_key_never_replaced(two_sides):
    rid = two_sides["rid"]
    before = _own_epochs(two_sides["conn_b"], rid)[1]
    _full_handshake(two_sides)
    after = _own_epochs(two_sides["conn_b"], rid)
    assert after[1]["public_key"] == before["public_key"]
    assert after[1]["private_key_ref"] == before["private_key_ref"]
    assert after[1]["private_key_ref"] != "peer"
    # The peer's epoch-1 key still comes from the relationships row.
    peer_key = two_sides["conn_b"].execute(
        "SELECT peer_agreement_key FROM relationships WHERE relationship_id = ?",
        (rid,),
    ).fetchone()[0]
    assert peer_key == two_sides["alice"]["rel_pub_mb"]


def test_confirm_requires_new_wrap_seen(two_sides):
    t0 = two_sides["t0"]
    rid = two_sides["rid"]
    begun = two_sides["mgr_b"].begin_rotation(rid, now=t0)
    ack = two_sides["mgr_a"].on_prepare(rid, begun["prepare"], str(uuid.uuid4()), now=t0)
    two_sides["mgr_b"].on_ack(rid, ack, now=t0)
    with pytest.raises(RotationError) as exc:
        two_sides["mgr_b"].confirm_rotation(rid, now=t0)
    assert exc.value.code == "no_new_wrap_seen"


def test_double_begin_rejected(two_sides):
    two_sides["mgr_b"].begin_rotation(two_sides["rid"], now=two_sides["t0"])
    with pytest.raises(RotationError) as exc:
        two_sides["mgr_b"].begin_rotation(two_sides["rid"], now=two_sides["t0"])
    assert exc.value.code == "rotation_in_flight"


# -- timeout --------------------------------------------------------------------


def test_no_ack_timeout_discards_candidate(two_sides):
    t0 = two_sides["t0"]
    rid = two_sides["rid"]
    mgr_b = two_sides["mgr_b"]
    mgr_b.begin_rotation(rid, now=t0)
    with pytest.raises(NoAckTimeout):
        mgr_b.sweep(now=t0 + timedelta(hours=25))
    # Candidate discarded: no epoch-2 own row, relationship stays epoch 1.
    assert 2 not in _own_epochs(two_sides["conn_b"], rid)
    epoch = two_sides["conn_b"].execute(
        "SELECT key_epoch FROM relationships WHERE relationship_id = ?",
        (rid,),
    ).fetchone()[0]
    assert epoch == 1
    phase = two_sides["conn_b"].execute(
        "SELECT phase FROM key_rotations WHERE relationship_id = ? AND epoch = 2",
        (rid,),
    ).fetchone()[0]
    assert phase == "discarded"


def test_sweep_before_deadline_keeps_candidate(two_sides):
    t0 = two_sides["t0"]
    rid = two_sides["rid"]
    mgr_b = two_sides["mgr_b"]
    mgr_b.begin_rotation(rid, now=t0)
    mgr_b.sweep(now=t0 + timedelta(hours=23))  # no raise
    assert 2 in _own_epochs(two_sides["conn_b"], rid)


# -- dual wrap ---------------------------------------------------------------------


def test_dual_wrap_during_transition(two_sides):
    """After ack, the acking side dual-wraps to the peer's prior and new
    keys; the rotating side can unseal with either key during the window."""
    from muse_agent_social.crypto.sealing import seal_envelope, unseal_envelope
    from muse_agent_social.model.events import build_protected

    t0 = two_sides["t0"]
    rid = two_sides["rid"]
    alice, bob = two_sides["alice"], two_sides["bob"]
    mgr_a, mgr_b = two_sides["mgr_a"], two_sides["mgr_b"]

    begun = mgr_b.begin_rotation(rid, now=t0)
    ack = mgr_a.on_prepare(rid, begun["prepare"], str(uuid.uuid4()), now=t0)
    mgr_b.on_ack(rid, ack, now=t0)

    # Alice (acking side) dual-wraps to Bob's epoch-1 and epoch-2 keys.
    wraps = mgr_a.dual_wrap_keys(rid)
    assert set(wraps) == {1, 2}
    bob_e2_priv = _load_priv(two_sides["keys_b"], rid, 2)
    bob_e2_pub_mb = mgr_b._own_epochs(rid)[2]["public_key"]
    assert wraps[2] == bob_e2_pub_mb

    protected = build_protected(
        relationship_id=rid,
        conversation_id="12345678-1234-4234-8234-123456789012",
        sender_id=alice["identity_id"],
        event_type="message.created",
        thread_id=None,
        reply_to=None,
        key_epoch=2,
    )
    protected["sender_seq"] = 1
    recipients = [
        {
            "recipient": bob["identity_id"],
            "agreement_key": wraps[1],
            "relationship_pub": parse_agreement_key(wraps[1]),
        },
        {
            "recipient": bob["identity_id"],
            "agreement_key": wraps[2],
            "relationship_pub": parse_agreement_key(wraps[2]),
        },
    ]
    env = seal_envelope(
        protected, {"body": "dual", "format": "plain"},
        alice["ed_priv"], recipients,
    )
    from muse_agent_social.canonical import restricted_jcs
    raw = restricted_jcs(env)

    # New key works.
    _, payload = unseal_envelope(raw, bob_e2_priv, bob["identity_id"])
    assert payload["body"] == "dual"
    # Old key still works during the transition window.
    _, payload = unseal_envelope(raw, bob["rel_priv"], bob["identity_id"])
    assert payload["body"] == "dual"


def test_dual_wrap_requires_acknowledged_rotation(two_sides):
    with pytest.raises(RotationError) as exc:
        two_sides["mgr_a"].dual_wrap_keys(two_sides["rid"])
    assert exc.value.code == "no_acknowledged_rotation"


# -- conflicting prepare --------------------------------------------------------------


def test_conflicting_prepare_quarantined_for_human(two_sides):
    """Both sides rotate into epoch 2: the second prepare is quarantined,
    never auto-resolved."""
    t0 = two_sides["t0"]
    rid = two_sides["rid"]
    mgr_a, mgr_b = two_sides["mgr_a"], two_sides["mgr_b"]
    mgr_a.begin_rotation(rid, now=t0)
    other = mgr_b.begin_rotation(rid, now=t0)
    with pytest.raises(RotationError) as exc:
        mgr_a.on_prepare(rid, other["prepare"], str(uuid.uuid4()), now=t0)
    assert exc.value.code == "conflicting_prepare"
    entries = mgr_a.list_quarantine(rid)
    assert len(entries) == 1
    assert entries[0]["reason"] == "conflicting_prepare"
    # Human resolution clears it.
    mgr_a.resolve_quarantine(rid, 0, "mine", now=t0)
    assert mgr_a.list_quarantine(rid) == []


# -- future epoch data events -----------------------------------------------------------------


def test_future_epoch_quarantined_retryable_then_rejected(two_sides):
    rid = two_sides["rid"]
    t0 = two_sides["t0"]
    mgr_a = two_sides["mgr_a"]
    with pytest.raises(RotationError) as exc:
        mgr_a.on_data_event_epoch(rid, 5, now=t0)
    assert exc.value.code == "unknown_future_epoch"
    # Still retryable inside 24h.
    with pytest.raises(RotationError) as exc:
        mgr_a.on_data_event_epoch(rid, 5, now=t0 + timedelta(hours=23))
    assert exc.value.code == "unknown_future_epoch"
    # After 24h it is rejected, not retried forever.
    with pytest.raises(RotationError) as exc:
        mgr_a.on_data_event_epoch(rid, 5, now=t0 + timedelta(hours=25))
    assert exc.value.code == "unknown_future_epoch_rejected"


def test_real_prepare_resolves_future_epoch_quarantine(two_sides):
    rid = two_sides["rid"]
    t0 = two_sides["t0"]
    mgr_a, mgr_b = two_sides["mgr_a"], two_sides["mgr_b"]
    with pytest.raises(RotationError):
        mgr_a.on_data_event_epoch(rid, 2, now=t0)
    assert len(mgr_a.list_quarantine(rid)) == 1
    begun = mgr_b.begin_rotation(rid, now=t0)
    mgr_a.on_prepare(rid, begun["prepare"], str(uuid.uuid4()), now=t0)
    assert mgr_a.list_quarantine(rid) == []


# -- send pausing ------------------------------------------------------------------------


def test_send_paused_after_ack_deadline_without_confirm(two_sides):
    t0 = two_sides["t0"]
    rid = two_sides["rid"]
    begun = two_sides["mgr_b"].begin_rotation(rid, now=t0)
    two_sides["mgr_a"].on_prepare(rid, begun["prepare"], str(uuid.uuid4()), now=t0)
    # Before the deadline, sends are allowed.
    two_sides["mgr_a"].may_send(rid, now=t0 + timedelta(hours=23))
    with pytest.raises(RotationError) as exc:
        two_sides["mgr_a"].may_send(rid, now=t0 + timedelta(hours=25))
    assert exc.value.code == "send_paused_acknowledged"
