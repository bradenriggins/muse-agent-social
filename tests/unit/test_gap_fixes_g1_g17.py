"""Regression tests for the G1-G17 adversarial fix wave.

One focused test per fix. Each test fails on the pre-fix code (or locks a
security property the fix establishes) and passes on the fixed tree.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.expanduser("~/workspace/mas-release/src"))

from muse_agent_social import cli as cli_mod  # noqa: E402
from muse_agent_social.compatibility.v01 import (  # noqa: E402
    LegacyError,
    LegacyPolicy,
    MemoryReplayStore,
    vault_store,
    verify_v01,
)
from muse_agent_social.config import _assert_no_secrets  # noqa: E402
from muse_agent_social.crypto import identity as identity_mod  # noqa: E402
from muse_agent_social.crypto import rotation as rotation_mod  # noqa: E402
from muse_agent_social.crypto.identity import (  # noqa: E402
    agreement_key_multibase_from_pubkey,
    derive_identity_hierarchy,
    generate_master_seed,
)
from muse_agent_social.crypto.sealing import SealingError, seal_envelope  # noqa: E402
from muse_agent_social.migrate import (  # noqa: E402
    AwaitingPeer,
    MigrationContext,
    MigrationError,
    _queue_depths,
    drain_open,
    mstate_get,
    mstate_set,
    read_rollback_bundle,
    stage,
    v01_sends_allowed,
)
from muse_agent_social.model.approvals import (  # noqa: E402
    consume_approval,
    create_approval,
    ensure_approvals_columns,
)
from muse_agent_social.model.cards import create_card, verify_card  # noqa: E402
from muse_agent_social.model.invites import (  # noqa: E402
    MAX_INVITE_FILE_BYTES,
    MAX_INVITE_URI_BYTES,
    PairingError,
    commit_pairing,
    confirm_verification,
    create_acceptance,
    create_invite,
    generate_deploy_keypair,
    generate_relationship_keypair,
    parse_invite_uri,
    preview_invite,
    read_invite_file,
    record_displayed_phrase,
)
from muse_agent_social.store import projections  # noqa: E402
from muse_agent_social.store.db import connect, default_db_path, utcnow  # noqa: E402
from muse_agent_social.store.migrations import migrate  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey,
)

CAPS = ["events/0.2", "threads/1"]
T0 = datetime(2026, 9, 15, 20, 0, 0, tzinfo=timezone.utc)


def fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_db():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.row_factory = sqlite3.Row
    migrate(conn)
    projections.migrate_projections(conn)
    return conn


def make_agent(display_name):
    ident = derive_identity_hierarchy(generate_master_seed())
    card = create_card(
        ident.ed25519_private,
        display_name,
        "Test Principal",
        ident.agreement_key_multibase,
        CAPS,
        T0,
        T0 + timedelta(days=30),
    )
    assert verify_card(card, T0).ok
    return ident, card


# ---------------------------------------------------------------------------
# G1: migration drain state, not phase-derived
# ---------------------------------------------------------------------------


def test_g1_drain_open_gates_on_migration_state_not_phase():
    c = sqlite3.connect(":memory:", isolation_level=None)
    c.row_factory = sqlite3.Row
    migrate(c)
    try:
        # Never staged: closed.
        assert drain_open(c, now=T0) is False
        mstate_set(c, "migration.legacy_read_open", True)
        # Open with no drain clock: open.
        assert drain_open(c, now=T0) is True
        # Future drain clock: open even when the phase says committed (the
        # old code derived the drain from fictional phase names).
        mstate_set(c, "migration.phase", "committed")
        mstate_set(c, "migration.drain_until", fmt(T0 + timedelta(hours=1)))
        assert drain_open(c, now=T0) is True
        # Expired drain clock: closed.
        mstate_set(c, "migration.drain_until", fmt(T0 - timedelta(hours=1)))
        assert drain_open(c, now=T0) is False
        # Flag cleared: closed regardless of the clock.
        mstate_set(c, "migration.drain_until", fmt(T0 + timedelta(hours=1)))
        mstate_set(c, "migration.legacy_read_open", False)
        assert drain_open(c, now=T0) is False
    finally:
        c.close()


# ---------------------------------------------------------------------------
# G2: queue-depth gate counts only real pending work
# ---------------------------------------------------------------------------


def test_g2_queue_depths_ignore_historical_and_report_only_queues():
    c = make_db()
    now = utcnow()
    # One live scheduled row plus historical released/canceled/expired rows.
    for sid, state in (
        ("s-live", "scheduled"),
        ("s-rel", "released"),
        ("s-can", "canceled"),
        ("s-exp", "expired"),
    ):
        c.execute(
            "INSERT INTO scheduler_queue(scheduled_id, inner_event, deliver_at,"
            " state) VALUES (?, x'00', ?, ?)",
            (sid, now, state),
        )
    # Report-only queues: nonempty, but must never gate.
    c.execute(
        "INSERT INTO receipt_queue(target_event_id, kind, queued_at)"
        " VALUES ('e1', 'accepted', ?)",
        (now,),
    )
    c.execute(
        "INSERT INTO surface_queue(event_id, policy_snapshot, queued_at)"
        " VALUES ('e1', '{}', ?)",
        (now,),
    )
    try:
        depths = _queue_depths(c)
        assert depths["projection_queue"] == 0
        # Only the row still in 'scheduled' state counts.
        assert depths["scheduler_queue"] == 1
        assert depths["receipt_queue_total"] == 1
        assert depths["surface_queue_total"] == 1
    finally:
        c.close()


# ---------------------------------------------------------------------------
# G3: v0.1 send kill switch is DB-backed
# ---------------------------------------------------------------------------


def test_g3_v01_sends_allowed_reads_db_flag(tmp_path):
    state_dir = tmp_path / "g3state"
    state_dir.mkdir()
    c = connect(default_db_path(state_dir))
    migrate(c)
    c.close()
    # Default (fresh migration): sends allowed.
    assert v01_sends_allowed(state_dir) is True
    # Commit flips the flag; the helper must observe it.
    c = connect(default_db_path(state_dir))
    mstate_set(c, "migration.v01_sends_allowed", False)
    c.close()
    assert v01_sends_allowed(state_dir) is False


# ---------------------------------------------------------------------------
# G4: old migration backlog is not subject to the 7-day live window
# ---------------------------------------------------------------------------


def _v01_bytes(key: bytes, created_at: str, eid: str = "g4-1") -> bytes:
    env = {
        "v": 1,
        "id": eid,
        "from": "agent:old-a",
        "to": "agent:old-b",
        "pair": "pair-g4",
        "type": "note",
        "title": "t",
        "body": "b",
        "url": "",
        "created_at": created_at,
        "nonce": "nonce-g4",
    }
    canonical = json.dumps(
        {k: v for k, v in env.items() if k != "sig"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    env["sig"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return json.dumps(env).encode("utf-8")


def _g4_policy(**over):
    kw = dict(
        pair_id="pair-g4",
        expected_sender="agent:old-a",
        my_agent_id="agent:old-b",
        replay_store=MemoryReplayStore(),
    )
    kw.update(over)
    return LegacyPolicy(**kw)


def test_g4_unlimited_backlog_accepts_ancient_objects():
    key = os.urandom(32)
    # An object far older than the 7-day live window. Pre-fix this raised
    # OverflowError: timedelta(days=float("inf")) is not constructible.
    raw = _v01_bytes(key, "2020-01-01T00:00:00Z")
    verified = verify_v01(
        raw, key, policy=_g4_policy(max_age_days=float("inf")), filename="old.json"
    )
    assert verified.envelope["id"] == "g4-1"
    # The live drain still enforces the 7-day default: same object rejected.
    with pytest.raises(LegacyError) as excinfo:
        verify_v01(raw, key, policy=_g4_policy(), filename="old.json")
    assert excinfo.value.code == "V01_STALE"


# ---------------------------------------------------------------------------
# G5: prevalidation before remote provisioning; no silent cleanup
# ---------------------------------------------------------------------------


def test_g5_preview_invite_rejects_expired_without_consuming():
    c = make_db()
    ident, card = make_agent("Inviter")
    invite = create_invite(
        c,
        card,
        ident.ed25519_private,
        X25519PrivateKey.generate(),
        CAPS,
        {"accepted_receipts": True},
        now=T0,
    )
    # An hour later the 15-minute invite is expired. Preview must fail
    # BEFORE any remote deploy-key registration, and must not consume the
    # one-use ledger (it marks the terminal 'expired' state instead).
    with pytest.raises(PairingError) as excinfo:
        preview_invite(c, invite, now=T0 + timedelta(hours=1))
    assert excinfo.value.code == "expired"
    row = c.execute(
        "SELECT state FROM invites WHERE invite_id = ?", (invite["invite_id"],)
    ).fetchone()
    assert row["state"] == "expired"
    c.close()


# ---------------------------------------------------------------------------
# G6: sticky phrase verification binds display to confirmation
# ---------------------------------------------------------------------------


def _g6_invite(c):
    ident, card = make_agent("Inviter")
    invite = create_invite(
        c,
        card,
        ident.ed25519_private,
        X25519PrivateKey.generate(),
        CAPS,
        {"accepted_receipts": True},
        now=T0,
    )
    return invite["invite_id"]


def test_g6_two_run_phrase_flow_and_substitution_refusal():
    c = make_db()
    iid = _g6_invite(c)
    fps = ("fp-inviter-aaa", "fp-acceptor-bbb")
    # Run 1: records the displayed fingerprints WITHOUT approving.
    first = record_displayed_phrase(c, iid, fps, now=T0)
    assert first["human_approved"] is False
    # Direct confirmation with no run 1 is refused.
    iid2 = _g6_invite(c)
    with pytest.raises(PairingError) as excinfo:
        confirm_verification(c, iid2, fps, now=T0)
    assert excinfo.value.code == "no_phrase_displayed"
    # Run 2 with matching fingerprints approves.
    second = confirm_verification(c, iid, fps, now=T0)
    assert second["human_approved"] is True
    # A swapped acceptor card between display and confirmation is refused
    # (and does NOT burn the invite: the human can re-run run 1).
    record_displayed_phrase(c, iid, fps, now=T0)
    with pytest.raises(PairingError) as excinfo:
        confirm_verification(c, iid, ("fp-inviter-aaa", "fp-EVIL"), now=T0)
    assert excinfo.value.code == "phrase_record_mismatch"
    row = c.execute(
        "SELECT state FROM invites WHERE invite_id = ?", (iid,)
    ).fetchone()
    assert row["state"] == "issued"
    c.close()


# ---------------------------------------------------------------------------
# G7: canonical approval expiry (no space-separated timestamps)
# ---------------------------------------------------------------------------


def test_g7_approval_expiry_backfill_is_canonical():
    c = sqlite3.connect(":memory:", isolation_level=None)
    c.row_factory = sqlite3.Row
    # Simulate a pre-hardening table: no expires_at column.
    c.execute(
        """CREATE TABLE human_approvals (
            approval_id TEXT PRIMARY KEY, relationship_id TEXT NOT NULL,
            subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
            answer TEXT NOT NULL, approved INTEGER NOT NULL,
            created_at TEXT NOT NULL, consumed_at TEXT, note TEXT)"""
    )
    c.execute(
        "INSERT INTO human_approvals VALUES (?,?,?,?,?,?,?,NULL,NULL)",
        ("a1", "rel", "poll", "p1", "yes", 1, "2026-09-15T20:00:00Z"),
    )
    ensure_approvals_columns(c)
    row = c.execute(
        "SELECT expires_at FROM human_approvals WHERE approval_id = 'a1'"
    ).fetchone()
    # Backfill uses the canonical T...Z form (+24h TTL), never SQLite
    # datetime()'s space-separated form (which breaks lexical compare).
    assert row["expires_at"] == "2026-09-16T20:00:00Z"
    # A row backfilled by an older version in the legacy space-separated
    # form is normalized on the next migrate.
    c.execute(
        "UPDATE human_approvals SET expires_at = '2026-09-16 20:00:00'"
        " WHERE approval_id = 'a1'"
    )
    ensure_approvals_columns(c)
    row = c.execute(
        "SELECT expires_at FROM human_approvals WHERE approval_id = 'a1'"
    ).fetchone()
    assert row["expires_at"] == "2026-09-16T20:00:00Z"
    c.close()


# ---------------------------------------------------------------------------
# G8: atomic invite claim and commit (claim rolls back with the commit)
# ---------------------------------------------------------------------------


def _g8_ceremony(tmp_path):
    """Invite + acceptance, but NO verification record and NO commit."""
    c = make_db()
    inviter = make_agent("Inviter")
    acceptor = make_agent("Acceptor")
    keys_a = tmp_path / "keys_a"
    keys_a.mkdir(parents=True, exist_ok=True)
    ident_i, card_i = inviter
    ident_a, card_a = acceptor
    invite = create_invite(
        c,
        card_i,
        ident_i.ed25519_private,
        X25519PrivateKey.generate(),
        CAPS,
        {"accepted_receipts": True},
        now=T0,
    )
    rel_priv, rel_pub = generate_relationship_keypair()
    deploy_pub = generate_deploy_keypair(str(tmp_path / "deploy_key"))
    acceptance = create_acceptance(
        c,
        invite,
        card_a,
        ident_a.ed25519_private,
        rel_pub,
        deploy_pub,
        now=T0 + timedelta(seconds=30),
    )
    return c, invite, acceptance, inviter


def _invite_state(c, invite_id):
    return c.execute(
        "SELECT state FROM invites WHERE invite_id = ?", (invite_id,)
    ).fetchone()["state"]


def test_g8_claim_mode_rollback_leaves_invite_issued(tmp_path):
    c, invite, acceptance, inviter = _g8_ceremony(tmp_path)
    keys_i = tmp_path / "keys_i"
    keys_i.mkdir(parents=True, exist_ok=True)
    # Claim mode with no human verification record: the claim (issued ->
    # accepted) happens inside the commit transaction, then the commit
    # fails on the missing verification. The whole transaction must roll
    # back, leaving the invite 'issued' (no accepted-but-uncommitted
    # window, no reset race, no CLI retry reset).
    with pytest.raises(PairingError) as excinfo:
        commit_pairing(
            c,
            acceptance,
            inviter[0].ed25519_private,
            "https://example.com/relay",
            {"inviter_send_slot": "slot-a", "inviter_receive_slot": "slot-b"},
            CAPS,
            now=T0 + timedelta(seconds=90),
            keys_dir=str(keys_i),
            claim_invite=True,
        )
    assert excinfo.value.code == "unverified"
    assert _invite_state(c, invite["invite_id"]) == "issued"
    # And the claim is still single-use: a concurrent second claim of the
    # same invite cannot slip through.
    with pytest.raises(PairingError):
        commit_pairing(
            c,
            acceptance,
            inviter[0].ed25519_private,
            "https://example.com/relay",
            {"inviter_send_slot": "slot-a", "inviter_receive_slot": "slot-b"},
            CAPS,
            now=T0 + timedelta(seconds=90),
            keys_dir=str(keys_i),
            claim_invite=True,
        )
    assert _invite_state(c, invite["invite_id"]) == "issued"
    c.close()


def test_g8_legacy_mode_rechecks_expiry_at_commit(tmp_path):
    # Legacy path (claim_invite=False): the invite was validated earlier
    # via validate_invite, but expires before commit_pairing runs. The
    # commit-time expiry check (TOCTOU guard) must fire.
    from muse_agent_social.model.invites import validate_invite

    c, invite, acceptance, inviter = _g8_ceremony(tmp_path)
    keys_i = tmp_path / "keys_i"
    keys_i.mkdir(parents=True, exist_ok=True)
    validate_invite(c, invite, now=T0 + timedelta(seconds=60))
    assert _invite_state(c, invite["invite_id"]) == "accepted"
    with pytest.raises(PairingError) as excinfo:
        commit_pairing(
            c,
            acceptance,
            inviter[0].ed25519_private,
            "https://example.com/relay",
            {"inviter_send_slot": "slot-a", "inviter_receive_slot": "slot-b"},
            CAPS,
            now=T0 + timedelta(hours=1),  # past the 15-minute invite expiry
            keys_dir=str(keys_i),
            claim_invite=False,
        )
    assert excinfo.value.code == "expired"
    c.close()


# ---------------------------------------------------------------------------
# G9: bounded pairing input (read once, capped, URI checked pre-decode)
# ---------------------------------------------------------------------------


def test_g9_oversized_invite_file_and_uri_rejected(tmp_path):
    big = tmp_path / "big-invite.json"
    big.write_bytes(b"x" * (MAX_INVITE_FILE_BYTES + 1))
    with pytest.raises(PairingError) as excinfo:
        read_invite_file(big)
    assert excinfo.value.code == "invite_too_large"
    # Oversized URI text is rejected BEFORE base64url decoding.
    with pytest.raises(PairingError) as excinfo:
        parse_invite_uri(
            "muse-agent-social://pair/v1#" + "A" * (MAX_INVITE_URI_BYTES + 1)
        )
    assert excinfo.value.code == "invite_too_large"


# ---------------------------------------------------------------------------
# G10: the PRK wipe targets the live buffer, not a throwaway copy
# ---------------------------------------------------------------------------


def test_g10_prk_wipe_targets_live_buffer():
    calls: list = []
    orig_zero = identity_mod._zero

    def spy(buf):
        calls.append(buf)
        if len(calls) == 3:
            # The third wipe is the PRK (after ed25519_seed and
            # x25519_bootstrap). Raise instead of wiping so the frame stays
            # alive in the traceback for the identity check below.
            raise RuntimeError("g10-probe")
        return orig_zero(buf)

    identity_mod._zero = spy
    try:
        try:
            derive_identity_hierarchy(generate_master_seed())
        except RuntimeError as exc:
            assert str(exc) == "g10-probe"
            tb = exc.__traceback__
        else:
            pytest.fail("g10 probe never fired")
    finally:
        identity_mod._zero = orig_zero
    frame = None
    while tb is not None:
        if tb.tb_frame.f_code.co_name == "derive_identity_hierarchy":
            frame = tb.tb_frame
            break
        tb = tb.tb_next
    assert frame is not None, "derive_identity_hierarchy frame not found"
    prk_local = frame.f_locals["prk"]
    assert isinstance(prk_local, bytearray)
    # Pre-fix this was `_zero(bytearray(prk))`: the wipe landed on a
    # throwaway copy while the real PRK bytes stayed in memory. Now the
    # wipe must receive the live buffer itself.
    assert calls[2] is prk_local


# ---------------------------------------------------------------------------
# G11: nested secrets are still scanned under _ref/_path keys
# ---------------------------------------------------------------------------


def test_g11_ref_path_keys_still_scan_nested_values():
    # Scalar references stay allowed...
    _assert_no_secrets({"token_ref": "keys/api.token"})
    _assert_no_secrets({"ca_path": "/etc/ssl/ca.pem"})
    # ...but a nested secret under a _ref/_path key must still be caught.
    # The old code `continue`d past the recursion too.
    with pytest.raises(ValueError, match="offending key"):
        _assert_no_secrets({"token_ref": {"token": "hunter2"}})
    with pytest.raises(ValueError, match="offending key"):
        _assert_no_secrets({"creds_path": [{"password": "hunter2"}]})
    # And the plain key-name denial still works.
    with pytest.raises(ValueError, match="offending key"):
        _assert_no_secrets({"api_token": "hunter2"})


# ---------------------------------------------------------------------------
# G12: approval consumption binds the exact send it authorizes
# ---------------------------------------------------------------------------


def test_g12_consume_approval_binds_relationship_subject_answer():
    c = make_db()
    now = fmt(T0)
    aid = create_approval(
        c,
        relationship_id="rel-ok",
        subject_type="poll",
        subject_id="poll-1",
        answer="tacos",
        approved=True,
        created_at=now,
    )
    # Wrong relationship: the UPDATE must not fire.
    assert (
        consume_approval(
            c,
            aid,
            now,
            relationship_id="rel-EVIL",
            subject_type="poll",
            subject_id="poll-1",
            answer="tacos",
            approved=True,
        )
        is False
    )
    # Wrong subject: must not fire.
    assert (
        consume_approval(
            c,
            aid,
            now,
            relationship_id="rel-ok",
            subject_type="poll",
            subject_id="poll-2",
            answer="tacos",
            approved=True,
        )
        is False
    )
    # Wrong answer: must not fire.
    assert (
        consume_approval(
            c,
            aid,
            now,
            relationship_id="rel-ok",
            subject_type="poll",
            subject_id="poll-1",
            answer="sushi",
            approved=True,
        )
        is False
    )
    # Exact bindings: fires exactly once.
    assert (
        consume_approval(
            c,
            aid,
            now,
            relationship_id="rel-ok",
            subject_type="poll",
            subject_id="poll-1",
            answer="tacos",
            approved=True,
        )
        is True
    )
    row = c.execute(
        "SELECT consumed_at FROM human_approvals WHERE approval_id = ?", (aid,)
    ).fetchone()
    assert row["consumed_at"] is not None
    c.close()


# ---------------------------------------------------------------------------
# G13: receiver-time poll closure (never sender created_at)
# ---------------------------------------------------------------------------


class _G13Log:
    def __init__(self, conn, base):
        self.conn = conn
        self.base = base
        self.seq = 0

    def add(self, event_type, payload, sender, created, received):
        self.seq += 1
        event_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO events(event_id, relationship_id, conversation_id,"
            " thread_id, sender, sender_seq, created_at, key_epoch, event_type,"
            " replay_nonce, sealed_envelope)"
            " VALUES (?, 'rel-g13', 'conv', 'thr', ?, ?, ?, 1, ?, ?, ?);",
            (
                event_id,
                sender,
                self.seq,
                fmt(created),
                event_type,
                str(uuid.uuid4()),
                b"sealed",
            ),
        )
        projections.record_projection_input(
            self.conn,
            event_id=event_id,
            event_type=event_type,
            payload=payload,
            reply_to=None,
            received_at=fmt(received),
        )
        return {
            "event_id": event_id,
            "relationship_id": "rel-g13",
            "conversation_id": "conv",
            "thread_id": "thr",
            "sender": sender,
            "sender_seq": self.seq,
            "created_at": fmt(created),
            "key_epoch": 1,
            "event_type": event_type,
            "payload": payload,
            "reply_to": None,
            "received_at": fmt(received),
        }

    def apply(self, row):
        return projections.apply_event(self.conn, row)


def _g13_poll(log, closes_at):
    return log.add(
        "poll.created",
        {
            "question": "lunch?",
            "choices": ["tacos", "sushi"],
            "closes_at": fmt(closes_at),
            "multi_select": False,
        },
        sender="did:key:a",
        created=log.base,
        received=log.base,
    )


def test_g13_backdated_response_after_close_is_rejected():
    c = make_db()
    log = _G13Log(c, T0)
    poll = _g13_poll(log, T0 + timedelta(hours=1))
    log.apply(poll)
    # Sender backdates created_at to before closes_at, but the receiver
    # accepted it after the close: the RECEIVER's clock decides.
    resp = log.add(
        "poll.responded",
        {"poll_id": poll["event_id"], "choice_ids": ["tacos"]},
        sender="did:key:b",
        created=T0 + timedelta(minutes=30),  # before close (sender's claim)
        received=T0 + timedelta(hours=2),  # after close (receiver's truth)
    )
    with pytest.raises(projections.ProjectionError) as excinfo:
        log.apply(resp)
    assert excinfo.value.code == "poll_closed"
    c.close()


def test_g13_exact_boundary_rejected_and_ontime_stores_receiver_time():
    c = make_db()
    log = _G13Log(c, T0)
    closes = T0 + timedelta(hours=1)
    poll = _g13_poll(log, closes)
    log.apply(poll)
    # Acceptance exactly at closes_at is late (>=).
    resp = log.add(
        "poll.responded",
        {"poll_id": poll["event_id"], "choice_ids": ["tacos"]},
        sender="did:key:b",
        created=T0,
        received=closes,
    )
    with pytest.raises(projections.ProjectionError) as excinfo:
        log.apply(resp)
    assert excinfo.value.code == "poll_closed"
    # An on-time response stores the receiver acceptance time, not the
    # sender's created_at, as responded_at.
    resp2 = log.add(
        "poll.responded",
        {"poll_id": poll["event_id"], "choice_ids": ["sushi"]},
        sender="did:key:c",
        created=T0 - timedelta(days=1),  # sender backdated; irrelevant
        received=T0 + timedelta(minutes=59),
    )
    log.apply(resp2)
    row = c.execute(
        "SELECT responded_at FROM poll_responses WHERE poll_id = ? AND sender = ?",
        (poll["event_id"], "did:key:c"),
    ).fetchone()
    assert row["responded_at"] == fmt(T0 + timedelta(minutes=59))
    c.close()


# ---------------------------------------------------------------------------
# G14: recipient bounds (max 2) and receiver-side key order
# ---------------------------------------------------------------------------


def _g14_pair():
    h = derive_identity_hierarchy(generate_master_seed())
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return h, priv, pub


def _g14_protected(sender_did):
    from muse_agent_social.model.events import build_protected

    p = build_protected(
        relationship_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        conversation_id="12345678-1234-4234-8234-1234567890ab",
        sender_id=sender_did,
        event_type="message.created",
        thread_id="11111111-2222-4333-8444-555555555555",
        reply_to=None,
        key_epoch=1,
        created_at="2026-09-15T20:00:00Z",
    )
    p["sender_seq"] = 1
    return p


def test_g14_seal_rejects_more_than_two_recipients():
    sender_h, _, _ = _g14_pair()
    recips = []
    for _ in range(3):
        _, _, pub = _g14_pair()
        recips.append(
            {
                "recipient": "did:key:z" + "1" * 10,
                "agreement_key": agreement_key_multibase_from_pubkey(pub),
                "relationship_pub": pub,
            }
        )
    with pytest.raises(SealingError) as excinfo:
        seal_envelope(
            _g14_protected(sender_h.identity_id),
            {"body": "hi", "format": "plain"},
            sender_h.ed25519_private,
            recips,
        )
    assert excinfo.value.code == "too_many_recipients"
    # The schema enforces the same bound.
    schema = json.loads(
        Path(
            os.path.expanduser(
                "~/workspace/mas-release/src/muse_agent_social"
                "/schemas/event-envelope.schema.json"
            )
        ).read_text(encoding="utf-8")
    )
    assert schema["properties"]["recipients"]["maxItems"] == 2
    assert schema["properties"]["recipients"]["uniqueItems"] is True


# ---------------------------------------------------------------------------
# G15: queue acknowledgement, quarantine bounds, ingress quota
# ---------------------------------------------------------------------------


def test_g15_surface_ack_deletes_notification():
    c = make_db()
    now = utcnow()
    c.execute(
        "INSERT INTO surface_queue(event_id, policy_snapshot, queued_at)"
        " VALUES ('e-ack-1', '{}', ?)",
        (now,),
    )
    assert cli_mod.ack_surface_notification(c, "e-ack-1") is True
    assert (
        c.execute("SELECT COUNT(*) FROM surface_queue").fetchone()[0] == 0
    )
    # Already acked: False, not an error.
    assert cli_mod.ack_surface_notification(c, "e-ack-1") is False
    c.close()


def test_g15_quarantine_ttl_and_per_relationship_cap(monkeypatch):
    c = sqlite3.connect(":memory:", isolation_level=None)
    c.row_factory = sqlite3.Row
    cli_mod._ensure_cli_tables(c)
    monkeypatch.setattr(cli_mod, "RECEIVE_QUARANTINE_MAX_PER_RELATIONSHIP", 2)
    ctx = SimpleNamespace(conn=c)
    now = datetime.now(timezone.utc)
    # A row older than the 30-day TTL is pruned on the next quarantine write.
    c.execute(
        "INSERT INTO receive_quarantine(relationship_id, object_name, reason,"
        " quarantined_at) VALUES ('rel-q', 'old-obj', 'r', ?)",
        (fmt(now - timedelta(days=31)),),
    )
    cli_mod._record_quarantine(ctx, "rel-q", "obj-a", "r")
    cli_mod._record_quarantine(ctx, "rel-q", "obj-b", "r")
    cli_mod._record_quarantine(ctx, "rel-q", "obj-c", "r")
    names = [
        r[0]
        for r in c.execute(
            "SELECT object_name FROM receive_quarantine WHERE relationship_id='rel-q'"
        ).fetchall()
    ]
    assert "old-obj" not in names, "TTL-expired quarantine rows must be pruned"
    assert len(names) == 2, f"per-relationship cap not enforced: {names}"
    # The cap keeps the newest rows.
    assert set(names) == {"obj-b", "obj-c"}
    c.close()


def test_g15_ingress_quota_counts_receiver_time(monkeypatch):
    monkeypatch.setattr(cli_mod, "INGRESS_MAX_EVENTS_PER_DAY", 3)
    c = make_db()
    now = datetime.now(timezone.utc)
    # Three events whose sender backdated created_at a month ago but that
    # the receiver accepted just now: they count toward the quota.
    for i in range(3):
        eid = f"g15-{i}"
        c.execute(
            "INSERT INTO events(event_id, relationship_id, conversation_id,"
            " thread_id, sender, sender_seq, created_at, key_epoch, event_type,"
            " replay_nonce, sealed_envelope)"
            " VALUES (?, 'rel-q', 'c', 't', 's', ?, ?, 1, 'message.created', ?, ?)",
            (eid, i + 1, fmt(now - timedelta(days=30)), f"n{i}", b"x"),
        )
        c.execute(
            "INSERT INTO event_payloads(event_id, event_type, payload,"
            " reply_to, received_at) VALUES (?, 'message.created', '{}', NULL, ?)",
            (eid, fmt(now)),
        )
    ctx = SimpleNamespace(conn=c)
    out = cli_mod._check_ingress_quota(ctx, "rel-q", fmt(now))
    assert out is not None
    assert out["outcome"] == "retry_pending"
    assert out["retry_reason"] == "ingress_quota_exceeded"
    # A sender-postdated event (created now, accepted a month ago) must NOT
    # burn quota: only receiver acceptance time counts.
    monkeypatch.setattr(cli_mod, "INGRESS_MAX_EVENTS_PER_DAY", 1)
    c2 = make_db()
    c2.execute(
        "INSERT INTO events(event_id, relationship_id, conversation_id,"
        " thread_id, sender, sender_seq, created_at, key_epoch, event_type,"
        " replay_nonce, sealed_envelope)"
        " VALUES ('g15-old', 'rel-q', 'c', 't', 's', 1, ?, 1, 'message.created',"
        " 'n', ?)",
        (fmt(now), b"x"),
    )
    c2.execute(
        "INSERT INTO event_payloads(event_id, event_type, payload, reply_to,"
        " received_at) VALUES ('g15-old', 'message.created', '{}', NULL, ?)",
        (fmt(now - timedelta(days=30)),),
    )
    ctx2 = SimpleNamespace(conn=c2)
    assert cli_mod._check_ingress_quota(ctx2, "rel-q", fmt(now)) is None
    c.close()
    c2.close()


# ---------------------------------------------------------------------------
# G16: rotation retention bounds
# ---------------------------------------------------------------------------


def _g16_mgr(tmp_path):
    c = sqlite3.connect(":memory:", isolation_level=None)
    c.row_factory = sqlite3.Row
    migrate(c)
    projections.migrate_projections(c)
    rotation_mod._ensure_tables(c)
    return rotation_mod.RotationManager(c, str(tmp_path)), c


def test_g16_sweep_compacts_but_keeps_newest_and_replay_keys(tmp_path):
    mgr, c = _g16_mgr(tmp_path)
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=60)
    # Committed rotations at epochs 2-5, all past the 30-day retention.
    # The newest committed row per (relationship, role) must survive.
    for epoch in (2, 3, 4, 5):
        c.execute(
            "INSERT INTO key_rotations(relationship_id, epoch, role, phase,"
            " prepared_at, committed_at, deadline)"
            " VALUES ('rel-g16', ?, 'rotating', 'committed', ?, ?, ?)",
            (epoch, fmt(old), fmt(old), fmt(now)),
        )
    # A committed row with NULL committed_at is never deleted (fail-safe).
    c.execute(
        "INSERT INTO key_rotations(relationship_id, epoch, role, phase,"
        " prepared_at, committed_at, deadline)"
        " VALUES ('rel-g16', 1, 'rotating', 'committed', ?, NULL, ?)",
        (fmt(old), fmt(now)),
    )
    mgr._compact_committed_rotations(now)
    epochs = sorted(
        r[0] for r in c.execute("SELECT epoch FROM key_rotations").fetchall()
    )
    assert epochs == [1, 5]
    # Peer agreement keys: keep the two newest per relationship.
    for epoch in (1, 2, 3, 4):
        c.execute(
            "INSERT INTO key_epochs(relationship_id, epoch, public_key,"
            " private_key_ref, state) VALUES ('rel-g16', ?, 'pk', 'peer', 'active')",
            (epoch,),
        )
    # An own private key must be untouched by peer compaction.
    c.execute(
        "INSERT INTO key_epochs(relationship_id, epoch, public_key,"
        " private_key_ref, state) VALUES ('rel-g16', 5, 'pk', 'keys/e5.key',"
        " 'retired')"
    )
    mgr._compact_peer_key_epochs()
    peer_epochs = sorted(
        r[0]
        for r in c.execute(
            "SELECT epoch FROM key_epochs WHERE private_key_ref = 'peer'"
        ).fetchall()
    )
    assert peer_epochs == [3, 4]
    assert (
        c.execute(
            "SELECT COUNT(*) FROM key_epochs WHERE private_key_ref != 'peer'"
        ).fetchone()[0]
        == 1
    )
    # Projected security-key ceremony index: compacted past 90 days by
    # RECEIVER acceptance time only, never sender created_at.
    ancient = now - timedelta(days=120)
    recent = now - timedelta(days=1)
    c.execute(
        "INSERT INTO security_key_events(event_id, relationship_id, sender,"
        " created_at, key_epoch, action)"
        " VALUES ('sk-old', 'rel-g16', 's', ?, 2, 'prepare')",
        (fmt(recent),),  # sender claims it is recent: must not save it
    )
    c.execute(
        "INSERT INTO event_payloads(event_id, event_type, payload, reply_to,"
        " received_at) VALUES ('sk-old', 'security.key.prepare', '{}', NULL, ?)",
        (fmt(ancient),),
    )
    c.execute(
        "INSERT INTO security_key_events(event_id, relationship_id, sender,"
        " created_at, key_epoch, action)"
        " VALUES ('sk-new', 'rel-g16', 's', ?, 2, 'prepare')",
        (fmt(ancient),),  # sender backdates: must not condemn it
    )
    c.execute(
        "INSERT INTO event_payloads(event_id, event_type, payload, reply_to,"
        " received_at) VALUES ('sk-new', 'security.key.prepare', '{}', NULL, ?)",
        (fmt(recent),),
    )
    c.execute(
        "INSERT INTO security_key_events(event_id, relationship_id, sender,"
        " created_at, key_epoch, action)"
        " VALUES ('sk-norts', 'rel-g16', 's', ?, 2, 'prepare')",
        (fmt(ancient),),  # no receiver timestamp: retained (fail-safe)
    )
    mgr._compact_security_key_events(now)
    remaining = sorted(
        r[0] for r in c.execute("SELECT event_id FROM security_key_events").fetchall()
    )
    assert remaining == ["sk-new", "sk-norts"]
    c.close()


# ---------------------------------------------------------------------------
# G17: rollback bundle retry destroys the prior bundle; corrupt vault is
# a stable MigrationError, never a raw exception
# ---------------------------------------------------------------------------


def _g17_ctx(tmp_path):
    base = tmp_path / "g17"
    legacy = base / "legacy"
    legacy.mkdir(parents=True)
    return MigrationContext(
        state_dir=str(base / "state"),
        legacy_state_dir=str(legacy),
        vault_dir=str(base / "vault"),
        pair_id="pair-g17",
        my_agent_id="agent:test-a",
        peer_agent_id="agent:test-b",
    )


def test_g17_stage_retry_destroys_prior_bundle(tmp_path):
    import time

    ctx = _g17_ctx(tmp_path)
    # Seed the migration vault with the legacy pair key (stage step 2).
    vault_store(ctx.vault_dir, ctx.pair_id, os.urandom(32).hex())
    # Default hooks: stage() runs steps 1-2, then raises AwaitingPeer at
    # step 4 (card exchange needs the human channel).
    with pytest.raises(AwaitingPeer):
        stage(ctx)
    c = connect(default_db_path(ctx.state_dir))
    bundle1 = mstate_get(c, "migration.bundle_path")
    c.close()
    assert bundle1 and Path(bundle1).is_file()
    # Bundle names are timestamped: wait for the clock to tick so the
    # retry mints a distinct bundle.
    time.sleep(1.1)
    with pytest.raises(AwaitingPeer):
        stage(ctx)
    c = connect(default_db_path(ctx.state_dir))
    bundle2 = mstate_get(c, "migration.bundle_path")
    c.close()
    assert bundle2 and bundle2 != bundle1
    # The old bundle file is gone (pre-fix it lingered, undecryptable,
    # because the retry overwrote the single bundle DEK).
    assert not Path(bundle1).exists()
    assert Path(bundle2).is_file()
    leftovers = [
        p.name for p in (Path(ctx.state_dir) / "backups").glob("rollback-*.bin")
    ]
    assert leftovers == [Path(bundle2).name]
    # The replacement bundle decrypts under the current DEK.
    restored = read_rollback_bundle(ctx, bundle2)
    assert isinstance(restored, dict) and restored


def test_g17_corrupt_vault_is_stable_migration_error(tmp_path):
    from muse_agent_social.compatibility.v01 import _vault_path

    ctx = _g17_ctx(tmp_path)
    vault_store(ctx.vault_dir, ctx.pair_id, os.urandom(32).hex())
    vault_file = _vault_path(ctx.vault_dir, ctx.pair_id)
    vault_file.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(MigrationError) as excinfo:
        stage(ctx)
    # Pre-fix this escaped as a raw ValueError from json.loads.
    assert excinfo.value.code == "vault-corrupt"
