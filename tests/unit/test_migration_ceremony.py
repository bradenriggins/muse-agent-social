"""Regression tests for the hardened v0.1 -> v0.2 migration ceremony.

Covers the adversarial-review findings fixed in migrate.py:

(a) a tampered or unsigned peer card is rejected at step 4;
(b) the verification phrase cannot fall back to locally generated values:
    a missing peer card is a hard failure, not a fallback;
(c) ready / round-trip proof messages with bad signatures are rejected;
(d) a cutover failure leaves rollback key material intact, retry works,
    and explicit rollback still works;
(e) observe refuses to complete with a non-empty retry queue or unmatched
    sent/received counts;
(f) the generated deploy key is a valid OpenSSH public key;
(g) the migration vault round-trips through encryption (ciphertext at
    rest, never plaintext JSON).
"""

import os
import stat
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from muse_agent_social import migrate as mig
from muse_agent_social.compatibility.v01 import (
    VaultError,
    _set_test_clock,
    vault_load,
    vault_store,
)
from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
    b64url_encode,
    identity_id_from_pubkey,
)
from muse_agent_social.migrate import (
    DRAIN_WINDOW,
    MigrationContext,
    MigrationError,
    MigrationHooks,
    _vault_key,
    _write_legacy_backlog,
    cutover,
    mstate_get,
    mstate_set,
    observe,
    rollback,
    stage,
    verify,
)
from muse_agent_social.model.cards import create_card
from muse_agent_social.model.invites import generate_deploy_keypair
from muse_agent_social.store.db import open_db
from muse_agent_social.store.migrations import migrate as migrate_schema

ALICE = "agent:test-alice"
BOB = "agent:test-bob"
BACKLOG = 2


# ---------------------------------------------------------------------------
# Simulated peer (Bob) with real signed ceremony material
# ---------------------------------------------------------------------------


class PeerSim:
    """Bob: fresh identity key, real signed card, real OpenSSH deploy key."""

    def __init__(self, pair_id, agent_id, work_dir):
        self.ident = Ed25519PrivateKey.generate()
        rel = X25519PrivateKey.generate()
        now = datetime.now(timezone.utc)
        self.card = create_card(
            identity_priv=self.ident,
            display_name=agent_id,
            principal_label="migration:peer",
            agreement_pub_multibase=agreement_key_multibase_from_pubkey(
                rel.public_key().public_bytes_raw()
            ),
            capabilities=["migration/0.2"],
            issued_at=now,
            expires_at=now + timedelta(days=30),
        )
        self.deploy_pub = generate_deploy_keypair(
            str(work_dir / "peer-keys" / "deploy.key")
        )
        self.identity_id = identity_id_from_pubkey(
            self.ident.public_key().public_bytes_raw()
        )
        self.agent_id = agent_id
        self.pair_id = pair_id

    def card_envelope(self):
        return mig._sign_card_exchange(
            self.ident,
            self.card,
            {
                "pair_id": self.pair_id,
                "agent_id": self.agent_id,
                "deploy_pub": self.deploy_pub,
                "role": "peer",
            },
        )

    def ready(self):
        return mig._sign_ceremony_msg(
            self.ident,
            "migration.ready",
            self.pair_id,
            {"pair_id": self.pair_id, "agent_id": self.agent_id,
             "at": mig.utcnow()},
        )

    def proof(self, adapted):
        return mig._sign_ceremony_msg(
            self.ident,
            "migration.proof",
            self.pair_id,
            {
                "relationship.ready": True,
                "message": True,
                "reaction": True,
                "receipt.accepted": True,
                "receipt.seen": True,
                "edit": True,
                "retraction": True,
                "legacy_adapted": adapted,
            },
        )

    def commit(self):
        return mig._sign_ceremony_msg(
            self.ident,
            "migration.commit",
            self.pair_id,
            {"pair_id": self.pair_id, "at": mig.utcnow()},
        )


def make_hooks(peer, pair_id, faults=None, proof_adapted=BACKLOG):
    """Two-party hook fakes with optional fault injection.

    faults keys: "card" in {"unsigned", "tampered", "missing"},
    "ready" in {"unsigned", "bad-sig", "wrong-key"},
    "proof" in {"unsigned", "bad-sig", "wrong-key"},
    "commit" in {"bad-sig"}, "revoke" in {"boom"}.
    """
    faults = faults or {}

    def exchange_card(my_envelope):
        fault = faults.get("card")
        if fault == "missing":
            return None
        env = peer.card_envelope()
        if fault == "unsigned":
            env = dict(env)
            env.pop("signature", None)
        elif fault == "tampered":
            env = dict(env)
            env["migration"] = dict(env["migration"])
            env["migration"]["deploy_pub"] = "ssh-ed25519 AAAATAMPERED"
        return env

    def compare_phrase(mine, theirs):
        return True

    def provision_deploy_key(new_key):
        return None

    def sign_ready():
        return {"pair_id": pair_id, "agent_id": ALICE, "at": mig.utcnow()}

    def _spoof(msg, fault, kind):
        if fault == "unsigned":
            msg = dict(msg)
            msg.pop("signature", None)
        elif fault == "bad-sig":
            msg = dict(msg)
            msg["signature"] = b64url_encode(os.urandom(64))
        elif fault == "wrong-key":
            # Signed by a third party but claiming Bob's card-bound identity:
            # the signature must not verify against the pinned card key.
            attacker = Ed25519PrivateKey.generate()
            msg = mig._sign_ceremony_msg(
                attacker, kind, pair_id, msg["body"]
            )
            msg["identity_id"] = peer.identity_id
        return msg

    def await_peer_ready():
        return _spoof(peer.ready(), faults.get("ready"), "migration.ready")

    def prove_roundtrip():
        return _spoof(
            peer.proof(proof_adapted), faults.get("proof"), "migration.proof"
        )

    def exchange_commit(my_commit):
        msg = peer.commit()
        if faults.get("commit") == "bad-sig":
            msg = dict(msg)
            msg["signature"] = b64url_encode(os.urandom(64))
        return msg

    def revoke_old_deploy_key(old):
        if faults.get("revoke") == "boom":
            raise RuntimeError("simulated revocation failure")
        return None

    def delete_peer_key_copy():
        return None

    return MigrationHooks(
        record_relay_head=lambda: "test-head",
        drain_legacy_incoming=None,
        set_v01_sends=None,
        exchange_card=exchange_card,
        compare_phrase=compare_phrase,
        provision_deploy_key=provision_deploy_key,
        sign_ready=sign_ready,
        await_peer_ready=await_peer_ready,
        prove_roundtrip=prove_roundtrip,
        exchange_commit=exchange_commit,
        revoke_old_deploy_key=revoke_old_deploy_key,
        delete_peer_key_copy=delete_peer_key_copy,
    )


def make_ctx(tmp_path, name, hooks, pair_id=None, backlog=BACKLOG):
    """Build a disposable migration context; returns (ctx, legacy_key)."""
    pair_id = pair_id or f"pair-test-{name}-" + os.urandom(4).hex()
    base = tmp_path / name
    legacy_dir = base / "legacy"
    state_dir = base / "v02"
    vault_dir = base / "vault"
    key = os.urandom(32)
    # Operator handoff: the legacy key starts as a plaintext vault entry;
    # stage() must seal it.
    vault_store(vault_dir, pair_id, key.hex())
    _write_legacy_backlog(legacy_dir, key, BOB, ALICE, pair_id, backlog)
    ctx = MigrationContext(
        state_dir=state_dir,
        legacy_state_dir=legacy_dir,
        vault_dir=vault_dir,
        pair_id=pair_id,
        my_agent_id=ALICE,
        peer_agent_id=BOB,
        role="initiator",
        hooks=hooks,
        legacy_snapshot={"relay_repo": "test-relay"},
    )
    return ctx, key


def _phase_of(ctx):
    conn = open_db(ctx.state_dir)
    try:
        return mstate_get(conn, "migration.phase")
    finally:
        conn.close()


def _state_has(ctx, key):
    conn = open_db(ctx.state_dir)
    try:
        return mstate_get(conn, key) is not None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# (a) tampered / unsigned cards are rejected
# ---------------------------------------------------------------------------


def test_tampered_card_signature_rejected(tmp_path):
    pair_id = f"pair-test-a1-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "a1")
    ctx, _ = make_ctx(
        tmp_path, "a1", make_hooks(peer, pair_id, {"card": "tampered"}),
        pair_id=pair_id,
    )
    with pytest.raises(MigrationError) as excinfo:
        stage(ctx)
    assert excinfo.value.code == "card-bad-signature"
    assert _phase_of(ctx) != "staged"
    assert not _state_has(ctx, "migration.consent")


def test_unsigned_card_rejected(tmp_path):
    pair_id = f"pair-test-a2-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "a2")
    ctx, _ = make_ctx(
        tmp_path, "a2", make_hooks(peer, pair_id, {"card": "unsigned"}),
        pair_id=pair_id,
    )
    with pytest.raises(MigrationError) as excinfo:
        stage(ctx)
    assert excinfo.value.code == "card-malformed"
    assert _phase_of(ctx) != "staged"


def test_good_card_exchange_verifies(tmp_path):
    pair_id = f"pair-test-a3-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "a3")
    ctx, _ = make_ctx(
        tmp_path, "a3", make_hooks(peer, pair_id), pair_id=pair_id
    )
    summary = stage(ctx)
    assert summary["cards"] == "exchanged and signature-verified"
    assert _phase_of(ctx) == "staged"
    conn = open_db(ctx.state_dir)
    try:
        consent = mstate_get(conn, "migration.consent")
    finally:
        conn.close()
    assert consent["peer_identity_id"] == peer.identity_id
    assert consent["my_identity_id"] == mig._migration_identity_id(ctx)


# ---------------------------------------------------------------------------
# (b) no phrase fallback: missing peer card is a hard failure
# ---------------------------------------------------------------------------


def test_missing_peer_card_is_hard_failure_not_fallback(tmp_path):
    pair_id = f"pair-test-b1-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "b1")
    ctx, _ = make_ctx(
        tmp_path, "b1", make_hooks(peer, pair_id, {"card": "missing"}),
        pair_id=pair_id,
    )
    with pytest.raises(MigrationError) as excinfo:
        stage(ctx)
    # Hard failure at card exchange: the ceremony never reaches the phrase
    # step, so no locally generated fallback phrase can be used.
    assert excinfo.value.code == "card-malformed"
    assert _phase_of(ctx) == "freezing"
    assert not _state_has(ctx, "migration.consent")
    assert not _state_has(ctx, "migration.peer_card_exchange")


# ---------------------------------------------------------------------------
# (c) ready / proof with bad signatures are rejected
# ---------------------------------------------------------------------------


def test_ready_bad_signature_rejected(tmp_path):
    pair_id = f"pair-test-c1-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "c1")
    ctx, _ = make_ctx(
        tmp_path, "c1", make_hooks(peer, pair_id), pair_id=pair_id
    )
    stage(ctx)
    ctx.hooks = make_hooks(peer, pair_id, {"ready": "bad-sig"})
    with pytest.raises(MigrationError) as excinfo:
        verify(ctx)
    assert excinfo.value.code == "migration.ready-bad-signature"
    assert _phase_of(ctx) == "staged"


def test_ready_unsigned_rejected(tmp_path):
    pair_id = f"pair-test-c2-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "c2")
    ctx, _ = make_ctx(
        tmp_path, "c2", make_hooks(peer, pair_id), pair_id=pair_id
    )
    stage(ctx)
    ctx.hooks = make_hooks(peer, pair_id, {"ready": "unsigned"})
    with pytest.raises(MigrationError) as excinfo:
        verify(ctx)
    assert excinfo.value.code == "migration.ready-malformed"


def test_proof_signed_by_wrong_key_rejected(tmp_path):
    pair_id = f"pair-test-c3-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "c3")
    ctx, _ = make_ctx(
        tmp_path, "c3", make_hooks(peer, pair_id), pair_id=pair_id
    )
    stage(ctx)
    # Ready is fine; the proof claims Bob's card-bound identity but is
    # signed by a third-party key.
    ctx.hooks = make_hooks(peer, pair_id, {"proof": "wrong-key"})
    with pytest.raises(MigrationError) as excinfo:
        verify(ctx)
    assert excinfo.value.code == "migration.proof-bad-signature"
    assert _phase_of(ctx) == "staged"


def test_proof_bad_signature_rejected(tmp_path):
    pair_id = f"pair-test-c4-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "c4")
    ctx, _ = make_ctx(
        tmp_path, "c4", make_hooks(peer, pair_id), pair_id=pair_id
    )
    stage(ctx)
    ctx.hooks = make_hooks(peer, pair_id, {"proof": "bad-sig"})
    with pytest.raises(MigrationError) as excinfo:
        verify(ctx)
    assert excinfo.value.code == "migration.proof-bad-signature"


def test_good_ready_and_proof_verify(tmp_path):
    pair_id = f"pair-test-c5-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "c5")
    ctx, _ = make_ctx(
        tmp_path, "c5", make_hooks(peer, pair_id), pair_id=pair_id
    )
    stage(ctx)
    summary = verify(ctx)
    assert "round trip ok" in summary["prove"]
    assert _phase_of(ctx) == "verified"


# ---------------------------------------------------------------------------
# (d) cutover failure: rollback material intact, retry and rollback work
# ---------------------------------------------------------------------------


def test_cutover_failure_preserves_rollback_material(tmp_path):
    pair_id = f"pair-test-d1-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "d1")
    ctx, legacy_key = make_ctx(
        tmp_path, "d1", make_hooks(peer, pair_id), pair_id=pair_id
    )
    stage(ctx)
    verify(ctx)

    ctx.hooks = make_hooks(peer, pair_id, {"revoke": "boom"})
    with pytest.raises(RuntimeError, match="simulated revocation failure"):
        cutover(ctx)

    # Nothing destructive may have happened: phase is still verified, the
    # vault key decrypts, and the rollback bundle is on disk.
    assert _phase_of(ctx) == "verified"
    assert vault_load(ctx.vault_dir, ctx.pair_id,
                       enc_key=_vault_key(ctx)) == legacy_key
    conn = open_db(ctx.state_dir)
    try:
        bundle_path = mstate_get(conn, "migration.bundle_path")
    finally:
        conn.close()
    assert bundle_path and os.path.isfile(bundle_path)

    # Explicit rollback still works after the failed cutover.
    result = rollback(ctx, reason="cutover coordination failed")
    assert result["restored_v01_sends"] is True
    assert result["legacy_key_in_vault"] is True
    assert _phase_of(ctx) == "rolled_back"


def test_cutover_retry_after_failure_succeeds(tmp_path):
    pair_id = f"pair-test-d2-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "d2")
    ctx, legacy_key = make_ctx(
        tmp_path, "d2", make_hooks(peer, pair_id), pair_id=pair_id
    )
    stage(ctx)
    verify(ctx)

    ctx.hooks = make_hooks(peer, pair_id, {"revoke": "boom"})
    with pytest.raises(RuntimeError, match="simulated revocation failure"):
        cutover(ctx)
    assert _phase_of(ctx) == "verified"

    # Retry with working hooks: converges to committed, key material gone.
    ctx.hooks = make_hooks(peer, pair_id)
    summary = cutover(ctx)
    assert _phase_of(ctx) == "committed"
    assert summary["drain_until"]
    with pytest.raises(KeyError):
        vault_load(ctx.vault_dir, ctx.pair_id, enc_key=_vault_key(ctx))
    # Rollback is now refused: roll forward only.
    with pytest.raises(MigrationError) as excinfo:
        rollback(ctx, reason="too late")
    assert excinfo.value.code == "rollback-after-commit-refused"


# ---------------------------------------------------------------------------
# (e) observe gates: queues and counts
# ---------------------------------------------------------------------------


def _past_drain():
    t0 = datetime.now(timezone.utc)
    _set_test_clock(lambda: t0 + DRAIN_WINDOW + timedelta(hours=1))


def _committed_ctx(tmp_path, name):
    pair_id = f"pair-test-{name}-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / name)
    ctx, _ = make_ctx(
        tmp_path, name, make_hooks(peer, pair_id), pair_id=pair_id
    )
    stage(ctx)
    verify(ctx)
    cutover(ctx)
    assert _phase_of(ctx) == "committed"
    return ctx


def test_observe_refuses_nonempty_retry_queue(tmp_path):
    ctx = _committed_ctx(tmp_path, "e1")
    conn = open_db(ctx.state_dir)
    try:
        migrate_schema(conn)
        conn.execute(
            "INSERT INTO scheduler_queue (scheduled_id, inner_event,"
            " deliver_at, expires_at, state) VALUES (?, ?, ?, ?, ?)",
            ("sched-1", b"{}", "2026-09-16T00:00:00Z", None, "scheduled"),
        )
    finally:
        conn.close()
    _past_drain()
    try:
        with pytest.raises(MigrationError) as excinfo:
            observe(ctx)
    finally:
        _set_test_clock(None)
    assert excinfo.value.code == "observe-queues-nonempty"
    assert "scheduler_queue=1" in excinfo.value.detail
    assert _phase_of(ctx) == "committed"
    # The mismatch is surfaced in the stored report too.
    conn = open_db(ctx.state_dir)
    try:
        report = mstate_get(conn, "migration.observe_report")
    finally:
        conn.close()
    assert report["queues"]["scheduler_queue"] == 1


def test_observe_refuses_unmatched_counts(tmp_path):
    ctx = _committed_ctx(tmp_path, "e2")
    conn = open_db(ctx.state_dir)
    try:
        proof = dict(mstate_get(conn, "migration.proof"))
        proof["legacy_adapted"] = BACKLOG + 5
        mstate_set(conn, "migration.proof", proof)
    finally:
        conn.close()
    _past_drain()
    try:
        with pytest.raises(MigrationError) as excinfo:
            observe(ctx)
    finally:
        _set_test_clock(None)
    assert excinfo.value.code == "observe-count-mismatch"
    assert _phase_of(ctx) == "committed"


def test_observe_completes_when_queues_empty_and_counts_match(tmp_path):
    ctx = _committed_ctx(tmp_path, "e3")
    _past_drain()
    try:
        report = observe(ctx)
    finally:
        _set_test_clock(None)
    assert report["legacy_read"] == "closed (V01_DRAIN_CLOSED)"
    assert report["counts_match"] is True
    assert _phase_of(ctx) == "complete"


# ---------------------------------------------------------------------------
# (f) deploy key is a real OpenSSH public key
# ---------------------------------------------------------------------------


def test_deploy_key_is_valid_openssh_public_key(tmp_path):
    pair_id = f"pair-test-f1-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "f1")
    ctx, _ = make_ctx(
        tmp_path, "f1", make_hooks(peer, pair_id), pair_id=pair_id
    )
    stage(ctx)
    conn = open_db(ctx.state_dir)
    try:
        new_key = mstate_get(conn, "migration.new_deploy_key")
    finally:
        conn.close()
    pub = new_key["public_key"]
    assert pub.startswith("ssh-ed25519 "), pub
    # Parses as a real OpenSSH public key.
    loaded = serialization.load_ssh_public_key(pub.encode("ascii"))
    assert loaded is not None
    # The private half is stored OpenSSH-format at mode 0600.
    priv_path = tmp_path / "f1" / "v02" / "keys" / f"{pair_id}.deploy.key"
    assert priv_path.is_file()
    assert stat.S_IMODE(priv_path.stat().st_mode) == 0o600
    assert b"OPENSSH PRIVATE KEY" in priv_path.read_bytes()
    # The provisioned key is the OpenSSH key, not raw key material.
    assert "AAAA" in pub


# ---------------------------------------------------------------------------
# (g) vault encrypts at rest
# ---------------------------------------------------------------------------


def test_vault_round_trips_through_encryption(tmp_path):
    vault_dir = tmp_path / "vault-g"
    key = os.urandom(32)
    enc = os.urandom(32)
    path = vault_store(vault_dir, "pair-g", key.hex(), enc_key=enc)
    raw = path.read_bytes()
    # Ciphertext at rest: no plaintext JSON key material visible.
    assert b"key_b64" not in raw
    assert key.hex().encode("ascii") not in raw
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # Round trip with the key.
    assert vault_load(vault_dir, "pair-g", enc_key=enc) == key
    # Fail closed without the key.
    with pytest.raises(VaultError):
        vault_load(vault_dir, "pair-g")
    # Wrong key fails closed.
    with pytest.raises(VaultError):
        vault_load(vault_dir, "pair-g", enc_key=os.urandom(32))


def test_vault_legacy_plaintext_still_loads(tmp_path):
    vault_dir = tmp_path / "vault-g2"
    key = os.urandom(32)
    vault_store(vault_dir, "pair-g2", key.hex())
    assert vault_load(vault_dir, "pair-g2") == key


def test_migration_seals_operator_handoff_entry(tmp_path):
    """stage() encrypts the operator's plaintext vault handoff in place."""
    pair_id = f"pair-test-g3-" + os.urandom(4).hex()
    peer = PeerSim(pair_id, BOB, tmp_path / "g3")
    ctx, legacy_key = make_ctx(
        tmp_path, "g3", make_hooks(peer, pair_id), pair_id=pair_id
    )
    stage(ctx)
    # The vault file no longer contains plaintext key material ...
    from muse_agent_social.compatibility.v01 import _vault_path
    raw = _vault_path(ctx.vault_dir, pair_id).read_bytes()
    assert b"key_b64" not in raw
    # ... but the migration can still decrypt it for rollback.
    assert vault_load(ctx.vault_dir, pair_id,
                       enc_key=_vault_key(ctx)) == legacy_key
    result = rollback(ctx, reason="test")
    assert result["legacy_key_in_vault"] is True


# ---------------------------------------------------------------------------
# Drain-window receive: the CLI decrypts the sealed vault entry
# ---------------------------------------------------------------------------


def _v01_envelope(key, pair_id, sender, recipient, nonce):
    env = {
        "v": 1,
        "id": f"legacy-{nonce}",
        "from": sender,
        "to": recipient,
        "pair": pair_id,
        "type": "note",
        "title": "hello",
        "body": "world",
        "url": "",
        "created_at": "2026-09-15T12:00:00Z",
        "nonce": nonce,
    }
    canonical = json.dumps(
        {k: v for k, v in env.items() if k != "sig"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    env["sig"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return json.dumps(env).encode("utf-8")


def _cli_drain_ctx(tmp_path, name, pair_id, pair_key, sealed,
                   with_identity_key):
    """Mimic the CLI receive path during the migration drain window."""
    from muse_agent_social import cli as cli_mod
    from tests.support.harness import (
        fresh_db,
        make_agent,
        provision_receive_side,
    )

    state_dir = tmp_path / name / "cli-state"
    (state_dir / "keys").mkdir(parents=True)
    conn = fresh_db(state_dir / "state.db")
    provision_receive_side(
        conn, f"rel-{name}", make_agent("Self"), make_agent("Peer"),
        keys_dir=str(state_dir / "keys"),
    )
    mstate_set(conn, "migration.phase", "staged")
    # G1: the drain is migration state (legacy_read_open + drain_until),
    # not a phase lookup.
    mstate_set(conn, "migration.legacy_read_open", True)
    mstate_set(conn, "migration.pair_id", pair_id)
    mstate_set(conn, "migration.peer_legacy_id", BOB)
    mstate_set(conn, "migration.my_legacy_id", ALICE)
    vault_dir = state_dir / "migration-vault"
    if sealed:
        if with_identity_key:
            mctx = MigrationContext(
                state_dir=state_dir,
                legacy_state_dir=state_dir,
                vault_dir=vault_dir,
                pair_id=pair_id,
                my_agent_id=ALICE,
                peer_agent_id=BOB,
            )
            # Persist the ceremony identity key, as stage() would.
            mig._migration_identity_priv(mctx)
            enc = mig.ceremony_vault_key(state_dir, pair_id)
        else:
            # Sealed under a ceremony identity this state dir cannot see.
            enc = os.urandom(32)
        vault_store(vault_dir, pair_id, pair_key.hex(), enc_key=enc)
    else:
        # Operator's plaintext handoff entry (pre-stage).
        vault_store(vault_dir, pair_id, pair_key.hex())
    cli_mod._ensure_cli_tables(conn)
    return cli_mod, SimpleNamespace(conn=conn, state_dir=state_dir)


def test_receive_v01_accepts_sealed_vault_entry(tmp_path):
    """After stage() seals the vault, the drain-window receive path
    decrypts it with the ceremony vault key instead of quarantining."""
    pair_id = "pair-test-h1-" + os.urandom(4).hex()
    pair_key = os.urandom(32)
    cli_mod, ctx = _cli_drain_ctx(
        tmp_path, "h1", pair_id, pair_key,
        sealed=True, with_identity_key=True,
    )
    data = _v01_envelope(pair_key, pair_id, BOB, ALICE, "nonce-h1")
    out = cli_mod._receive_v01(ctx, "rel-h1", "obj1.json", data, {})
    assert out["outcome"] == "accepted"


def test_receive_v01_quarantines_sealed_entry_without_identity_key(tmp_path):
    """A sealed vault entry with no ceremony identity key in this state
    dir fails closed: quarantined, never decrypted, no crash."""
    pair_id = "pair-test-h2-" + os.urandom(4).hex()
    pair_key = os.urandom(32)
    cli_mod, ctx = _cli_drain_ctx(
        tmp_path, "h2", pair_id, pair_key,
        sealed=True, with_identity_key=False,
    )
    data = _v01_envelope(pair_key, pair_id, BOB, ALICE, "nonce-h2")
    out = cli_mod._receive_v01(ctx, "rel-h2", "obj2.json", data, {})
    assert out["outcome"] == "quarantined"


def test_receive_v01_still_accepts_plaintext_handoff(tmp_path):
    """The pre-stage operator handoff entry (plaintext) still works."""
    pair_id = "pair-test-h3-" + os.urandom(4).hex()
    pair_key = os.urandom(32)
    cli_mod, ctx = _cli_drain_ctx(
        tmp_path, "h3", pair_id, pair_key,
        sealed=False, with_identity_key=False,
    )
    data = _v01_envelope(pair_key, pair_id, BOB, ALICE, "nonce-h3")
    out = cli_mod._receive_v01(ctx, "rel-h3", "obj3.json", data, {})
    assert out["outcome"] == "accepted"


def test_ceremony_vault_key_missing_without_stage(tmp_path):
    """ceremony_vault_key fails closed when stage never ran here."""
    with pytest.raises(MigrationError) as excinfo:
        mig.ceremony_vault_key(tmp_path / "empty-state", "pair-nope")
    assert excinfo.value.code == "identity-key-missing"
