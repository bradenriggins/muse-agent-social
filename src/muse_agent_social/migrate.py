"""Live v0.1 to v0.2 migration protocol (lifecycle track).

Implements the implementation plan's LIVE MIGRATION section as an executable
checklist with two-party coordination. The 10 steps are encoded as data
(STEPS) with preconditions, actions, verification, and rollback triggers;
stage(), verify(), cutover(), observe(), and rollback() walk them against a
``migration_state`` table in the v0.2 database.

Two-party coordination: steps that need the peer (card exchange, phrase
compare, migration.ready, migration.commit, deploy key changes) go through
injected MigrationHooks. Without a hook the step raises AwaitingPeer, which
the CLI surfaces to the operator; the rehearsal harness injects in-memory
fakes that simulate both sides.

Rollback: before commit, rollback() restores v0.1 sends. After commit it
refuses: roll forward only, never resurrect deleted keys.

The rehearsal harness (rehearse()) migrates a DISPOSABLE local pair and
rolls back, proving counts match. It never touches live state.

No em dashes are used anywhere in this module, per project convention.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical import restricted_jcs
from .crypto.identity import (
    agreement_key_multibase_from_pubkey,
    b64url_decode,
    b64url_encode,
    identity_id_from_pubkey,
    parse_identity_id,
)
from .crypto.words import load_wordlist, verification_phrase
from .model.cards import card_fingerprint, create_card, verify_card
from .model.invites import generate_deploy_keypair

from .compatibility.v01 import (
    LegacyPolicy,
    MemoryReplayStore,
    SeqAssigner,
    _now as _v01_now,
    _set_test_clock,
    adapt_v01,
    assert_legacy_sends_allowed,
    detect_v01,
    vault_delete,
    vault_load,
    vault_store,
    verify_v01,
    LegacyError,
)
from .store.db import open_db, utcnow
from .store.migrations import SCHEMA_VERSION, migrate as migrate_schema

__all__ = [
    "STEPS",
    "MigrationStep",
    "MigrationContext",
    "MigrationHooks",
    "MigrationError",
    "AwaitingPeer",
    "DryRunResult",
    "CheckResult",
    "run_dry_run",
    "stage",
    "verify",
    "cutover",
    "observe",
    "rollback",
    "rehearse",
    "mstate_get",
    "mstate_set",
    "DRAIN_WINDOW",
]

#: 24-hour read-only drain window after cutover commit.
DRAIN_WINDOW = timedelta(hours=24)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class MigrationError(Exception):
    """A migration step failed or was refused.

    Attributes: code (stable), detail (human-readable, no secrets).
    """

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class AwaitingPeer(MigrationError):
    """A two-party step is waiting on the peer; the operator must drive it."""

    def __init__(self, step: int, detail: str = "") -> None:
        self.step = step
        super().__init__("awaiting-peer", f"step {step}: {detail}")


# ---------------------------------------------------------------------------
# The 10-step checklist (executable data)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MigrationStep:
    n: int
    name: str
    preconditions: tuple[str, ...]
    actions: tuple[str, ...]
    verification: tuple[str, ...]
    rollback_trigger: str


STEPS: tuple[MigrationStep, ...] = (
    MigrationStep(
        1,
        "freeze",
        ("phase is idle", "legacy state directory exists"),
        (
            "both sides stop v0.1 sends",
            "drain v0.1 incoming",
            "record old relay HEAD and local event counts",
        ),
        ("freeze record in migration_state", "v0.1 sends flag is frozen"),
        "any failure before commit: rollback restores v0.1 sends",
    ),
    MigrationStep(
        2,
        "backup",
        ("freeze record present", "legacy pair key in migration vault"),
        (
            "create encrypted local rollback bundle (config, legacy key, "
            "counts, relay HEAD); never send it",
            "store bundle data-encryption key in the migration vault",
        ),
        ("bundle decrypts locally", "bundle file is mode 0600"),
        "missing or unrestorable bundle blocks install (step 3)",
    ),
    MigrationStep(
        3,
        "install",
        ("backup present", "state dir is separate from legacy state dir"),
        (
            "deploy v0.2 in a separate state directory",
            "run schema, crypto, local transport, and migration dry-run tests",
        ),
        ("schema version matches", "dry-run checks all green"),
        "dry-run failure: fix and re-run; no peer coordination needed yet",
    ),
    MigrationStep(
        4,
        "exchange-cards",
        ("install verified",),
        (
            "each peer generates its own relationship and deploy keypairs",
            "send signed cards and acceptances over the existing trusted "
            "human channel",
        ),
        ("both cards present with matching pair id", "acceptances recorded"),
        "signature mismatch on card or acceptance: abort to rollback",
    ),
    MigrationStep(
        5,
        "verify-phrase",
        ("cards exchanged",),
        (
            "both humans compare the eight-word phrase over the trusted channel",
            "both agents store local consent records",
        ),
        ("phrase match recorded on both sides",),
        "phrase mismatch: abort to rollback, burn the pairing attempt",
    ),
    MigrationStep(
        6,
        "provision",
        ("phrase verified",),
        (
            "add new public deploy keys to the existing renamed relay "
            "repository",
            "keep old deploy keys during the drain window",
        ),
        ("new deploy key confirmed on the relay",),
        "provisioning failure: retry; old keys still in place",
    ),
    MigrationStep(
        7,
        "dual-read",
        ("phase is staged", "new deploy keys provisioned"),
        (
            "both sides read v0.1 and v0.2",
            "v0.2 writes allowed only after a mutually signed migration.ready",
        ),
        ("both migration.ready records present and matching",),
        "missing or mismatched ready: stay read-only, do not cut over",
    ),
    MigrationStep(
        8,
        "prove",
        ("dual-read active",),
        (
            "exchange relationship.ready, message, reaction, accepted "
            "receipt, seen receipt (if enabled), edit, and retraction",
            "adapt the legacy backlog; adapted count must equal freeze count",
        ),
        ("all seven proof types round-tripped", "counts match"),
        "lost event, duplicate surface, sequence fork, or failed receipt "
        "round trip: abort to rollback",
    ),
    MigrationStep(
        9,
        "commit",
        ("phase is verified", "both sides exchanged migration.commit"),
        (
            "exchange migration.commit",
            "remove old deploy keys, legacy pair key, peer private key copy, "
            "and bundle on both sides",
            "reject local v0.1 sends; start the 24h drain clock",
        ),
        ("vault key deleted", "v0.1 sends disabled", "drain clock recorded"),
        "after commit there is no rollback: roll forward only, never "
        "resurrect deleted keys",
    ),
    MigrationStep(
        10,
        "observe",
        ("phase is committed",),
        (
            "keep the v0.1 read adapter for 24 hours",
            "compare event counts and confirm no retry queue remains",
            "after the drain window, disable legacy acceptance "
            "(V01_DRAIN_CLOSED)",
        ),
        ("counts match", "retry queues empty", "drain closed on schedule"),
        "post-commit issues are fixed with a corrective v0.2 release",
    ),
)


# ---------------------------------------------------------------------------
# Context and hooks
# ---------------------------------------------------------------------------


@dataclass
class MigrationHooks:
    """Injected two-party and remote actions. None means the step raises
    AwaitingPeer (live runs) unless the step has a local default."""

    record_relay_head: Callable[[], str] | None = None
    drain_legacy_incoming: Callable[[], list[str]] | None = None
    set_v01_sends: Callable[[bool], None] | None = None
    exchange_card: Callable[[dict], dict] | None = None
    compare_phrase: Callable[[str, str], bool] | None = None
    provision_deploy_key: Callable[[dict], None] | None = None
    sign_ready: Callable[[], dict] | None = None
    await_peer_ready: Callable[[], dict] | None = None
    prove_roundtrip: Callable[[], dict] | None = None
    exchange_commit: Callable[[], dict] | None = None
    revoke_old_deploy_key: Callable[[dict], None] | None = None
    delete_peer_key_copy: Callable[[], None] | None = None


@dataclass
class MigrationContext:
    state_dir: str | Path  # v0.2 state dir (separate from legacy)
    legacy_state_dir: str | Path  # v0.1 state, read-only source of backlog
    vault_dir: str | Path  # migration vault (legacy pair key custody)
    pair_id: str  # legacy pair id
    my_agent_id: str
    peer_agent_id: str
    role: str = "initiator"  # or "peer"
    hooks: MigrationHooks = field(default_factory=MigrationHooks)
    legacy_snapshot: dict = field(default_factory=dict)  # config snapshot
    identity_priv: Any = None  # optional Ed25519 migration identity key;
    # when None it is loaded from (or generated into) the keys directory,
    # so separate CLI invocations share one ceremony identity.


# ---------------------------------------------------------------------------
# migration_state table access
# ---------------------------------------------------------------------------


def mstate_set(conn: Any, key: str, value: Any) -> None:
    conn.execute(
        "INSERT INTO migration_state (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, json.dumps(value)),
    )


def mstate_get(conn: Any, key: str, default: Any = None) -> Any:
    row = conn.execute(
        "SELECT value FROM migration_state WHERE key = ?", (key,)
    ).fetchone()
    return json.loads(row["value"]) if row else default


def _phase(conn: Any) -> str:
    return mstate_get(conn, "migration.phase", "idle")


def _set_phase(conn: Any, phase: str) -> None:
    mstate_set(conn, "migration.phase", phase)
    mstate_set(conn, f"migration.phase_at.{phase}", utcnow())


def _record_step(conn: Any, n: int, status: str, detail: Any = None) -> None:
    mstate_set(
        conn,
        f"migration.step.{n}",
        {"status": status, "at": utcnow(), "detail": detail or {}},
    )


# ---------------------------------------------------------------------------
# Migration ceremony keys and signed messages
#
# Every two-party migration message (card exchange, migration.ready,
# migration.proof, migration.commit) is Ed25519-signed by the sender's
# migration identity key and verified on receipt against the identity id
# pinned in the peer's verified card. Verification is fail-closed: a
# missing or invalid signature, or a sender identity that does not match
# the verified card, aborts the ceremony. There are no fallbacks.
# ---------------------------------------------------------------------------

_MIGRATION_IDENTITY_KEY_NAME = "migration-identity.key"
_MIGRATION_RELATIONSHIP_KEY_NAME = "relationship.key"
_MIGRATION_DEPLOY_KEY_NAME = "deploy.key"


def _keys_dir(ctx: MigrationContext) -> Path:
    keys_dir = Path(ctx.state_dir) / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    return keys_dir


def _check_key_mode(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise MigrationError(
            "key-file-mode",
            f"key file has wrong mode {oct(mode)}: {path}",
        )


def _migration_identity_priv(
    ctx: MigrationContext, create: bool = True
) -> Ed25519PrivateKey:
    """The side's Ed25519 migration identity key (load or generate, 0600).

    The same key signs the migration card, ready/proof/commit messages,
    and derives the migration vault encryption key, so it is persisted in
    the keys directory and shared across the stage/verify/cutover CLI
    invocations. Fail-closed on a wrong-mode or corrupt key file. With
    create=False (verify/cutover/rollback/observe paths) a missing key
    file is a hard error instead of silently minting a new identity.
    """
    if ctx.identity_priv is not None:
        if not isinstance(ctx.identity_priv, Ed25519PrivateKey):
            raise MigrationError(
                "identity-key-type",
                "ctx.identity_priv must be an Ed25519PrivateKey",
            )
        return ctx.identity_priv
    path = _keys_dir(ctx) / f"{ctx.pair_id}.{_MIGRATION_IDENTITY_KEY_NAME}"
    if path.is_file():
        _check_key_mode(path)
        raw = path.read_bytes()
        if len(raw) != 32:
            raise MigrationError(
                "identity-key-corrupt",
                f"identity key file has wrong length: {path}",
            )
        return Ed25519PrivateKey.from_private_bytes(raw)
    if not create:
        raise MigrationError(
            "identity-key-missing",
            f"no migration identity key at {path}; stage must run first",
        )
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(raw)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return priv


def _migration_identity_id(ctx: MigrationContext, create: bool = True) -> str:
    return identity_id_from_pubkey(
        _migration_identity_priv(ctx, create=create)
        .public_key()
        .public_bytes_raw()
    )


def _assert_identity_matches(conn: Any, ctx: MigrationContext) -> None:
    """Fail closed if the loaded ceremony identity differs from the one
    recorded at stage time (protects against a swapped key file between
    CLI invocations)."""
    recorded = mstate_get(conn, "migration.my_identity_id")
    if recorded is None:
        return
    if _migration_identity_id(ctx, create=False) != recorded:
        raise MigrationError(
            "identity-key-changed",
            "migration identity key does not match the one recorded at stage",
        )


def _vault_key(ctx: MigrationContext, create: bool = True) -> bytes:
    """Derive the migration vault encryption key from the ceremony identity.

    HKDF-SHA256 over the identity private key bytes with the migration
    vault info string (the same derivation style as crypto/identity.py).
    The vault can only be decrypted by the holder of the ceremony identity
    key, which is also what makes rollback decryption possible.
    """
    priv = _migration_identity_priv(ctx, create=create)
    raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"muse-agent-social/v1",
        info=b"muse-agent-social/v1/migration-vault/"
        + ctx.pair_id.encode("utf-8"),
    ).derive(raw)


def ceremony_vault_key(state_dir: str | Path, pair_id: str) -> bytes:
    """Derive the migration vault encryption key for a staged ceremony.

    Loads the ceremony identity key persisted by ``stage()`` (never
    creating one) and derives the vault key from it. Used by the CLI's
    v0.1 receive path during the drain window, after stage() has sealed
    the operator's plaintext vault handoff in place.

    Raises MigrationError if no ceremony identity key exists in this
    state dir (stage has not run here): callers should treat that as
    "only a plaintext handoff entry could exist".
    """
    ctx = MigrationContext(
        state_dir=state_dir,
        legacy_state_dir=state_dir,
        vault_dir=state_dir,
        pair_id=pair_id,
        my_agent_id="",
        peer_agent_id="",
    )
    return _vault_key(ctx, create=False)


def _relationship_priv(ctx: MigrationContext) -> X25519PrivateKey:
    """Load-or-generate the X25519 relationship keypair (raw, 0600).

    Reused across stage retries so a retried ceremony keeps one identity.
    """
    path = _keys_dir(ctx) / f"{ctx.pair_id}.{_MIGRATION_RELATIONSHIP_KEY_NAME}"
    if path.is_file():
        _check_key_mode(path)
        raw = path.read_bytes()
        if len(raw) != 32:
            raise MigrationError(
                "relationship-key-corrupt",
                f"relationship key file has wrong length: {path}",
            )
        return X25519PrivateKey.from_private_bytes(raw)
    priv = X25519PrivateKey.generate()
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(priv.private_bytes_raw())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return priv


def _deploy_keypair(ctx: MigrationContext) -> str:
    """Return this side's OpenSSH deploy public key (``ssh-ed25519 ...``).

    Generates a real OpenSSH Ed25519 keypair on first use via
    model.invites.generate_deploy_keypair (the same approach as the
    pairing ceremony): the private half is stored OpenSSH-format at mode
    0600 and never overwritten, the public half is what gets provisioned
    as the GitHub deploy key. Reused across stage retries.
    """
    keys_dir = _keys_dir(ctx)
    priv_path = keys_dir / f"{ctx.pair_id}.{_MIGRATION_DEPLOY_KEY_NAME}"
    if priv_path.is_file():
        _check_key_mode(priv_path)
        try:
            loaded = serialization.load_ssh_private_key(
                priv_path.read_bytes(), password=None
            )
        except ValueError as exc:
            raise MigrationError(
                "deploy-key-corrupt",
                f"deploy key file is not a valid OpenSSH private key: {priv_path}",
            ) from exc
        if not isinstance(loaded, Ed25519PrivateKey):
            raise MigrationError(
                "deploy-key-corrupt",
                f"deploy key file is not an Ed25519 key: {priv_path}",
            )
        return (
            loaded.public_key()
            .public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH,
            )
            .decode("ascii")
            .strip()
        )
    return generate_deploy_keypair(str(priv_path))


def _sign_card_exchange(
    ident_priv: Ed25519PrivateKey, card: dict, migration: dict
) -> dict:
    """Wrap a signed card plus the migration section in a signed envelope.

    The card is already self-signed by the identity key (create_card); the
    outer signature binds the migration section (pair id, deploy key, role)
    to the same identity.
    """
    payload = {"card": card, "migration": migration}
    signature = b64url_encode(ident_priv.sign(restricted_jcs(payload)))
    return {"card": card, "migration": migration, "signature": signature}


def _verify_card_exchange(envelope: Any, ctx: MigrationContext) -> tuple:
    """Verify a received card exchange envelope. Fail-closed.

    Checks the envelope shape, the card's self-signature and schema via
    verify_card, the outer envelope signature against the card's identity
    key, and the pair id binding. Returns (card, migration section).
    """
    if not isinstance(envelope, dict):
        raise MigrationError(
            "card-malformed", "peer card exchange is not an object"
        )
    card = envelope.get("card")
    migration = envelope.get("migration")
    signature = envelope.get("signature")
    if (
        not isinstance(card, dict)
        or not isinstance(migration, dict)
        or not isinstance(signature, str)
    ):
        raise MigrationError(
            "card-malformed",
            "peer card exchange must carry card, migration, and signature",
        )
    vr = verify_card(card)
    if not vr.ok:
        raise MigrationError(
            "card-invalid", f"peer card rejected: {vr.reason_code}"
        )
    try:
        peer_pub = parse_identity_id(card["identity_id"])
    except ValueError as exc:
        raise MigrationError("card-invalid", f"peer identity id: {exc}")
    try:
        raw_sig = b64url_decode(signature)
    except ValueError:
        raise MigrationError(
            "card-bad-signature", "signature is not valid base64url"
        )
    if len(raw_sig) != 64:
        raise MigrationError(
            "card-bad-signature", "signature must decode to 64 bytes"
        )
    try:
        Ed25519PublicKey.from_public_bytes(peer_pub).verify(
            raw_sig, restricted_jcs({"card": card, "migration": migration})
        )
    except Exception:
        raise MigrationError(
            "card-bad-signature",
            "exchange signature does not verify against the card identity key",
        )
    if migration.get("pair_id") != ctx.pair_id:
        raise MigrationError(
            "card-pair-mismatch", "peer card pair id differs"
        )
    deploy_pub = migration.get("deploy_pub")
    if not isinstance(deploy_pub, str) or not deploy_pub.startswith("ssh-"):
        raise MigrationError(
            "card-bad-deploy-key",
            "peer deploy key is not an OpenSSH public key",
        )
    return card, migration


def _peer_identity_id(conn: Any, ctx: MigrationContext) -> str:
    """The peer identity id pinned by the verified card exchange.

    Fail-closed: without a verified peer card on record there is nothing
    to verify subsequent ceremony messages against.
    """
    envelope = mstate_get(conn, "migration.peer_card_exchange")
    if not isinstance(envelope, dict):
        raise MigrationError(
            "peer-card-missing",
            "no verified peer card exchange on record; "
            "stage step 4 must complete first",
        )
    card = envelope.get("card") or {}
    identity_id = card.get("identity_id")
    if not isinstance(identity_id, str) or not identity_id:
        raise MigrationError(
            "peer-card-missing", "verified peer card has no identity id"
        )
    return identity_id


def _sign_ceremony_msg(
    ident_priv: Ed25519PrivateKey, kind: str, pair_id: str, body: dict
) -> dict:
    """Sign a ceremony message (migration.ready/proof/commit) with the
    sender's identity key. The signature covers kind, pair id, sender
    identity id, timestamp, and body."""
    if not isinstance(body, dict):
        raise MigrationError(
            f"{kind}-malformed", "ceremony message body is not an object"
        )
    msg = {
        "kind": kind,
        "pair_id": pair_id,
        "identity_id": identity_id_from_pubkey(
            ident_priv.public_key().public_bytes_raw()
        ),
        "at": utcnow(),
        "body": body,
    }
    msg["signature"] = b64url_encode(
        ident_priv.sign(
            restricted_jcs({k: v for k, v in msg.items() if k != "signature"})
        )
    )
    return msg


def _verify_ceremony_msg(
    msg: Any, expected_identity_id: str, pair_id: str, kind: str
) -> dict:
    """Verify a received ceremony message. Fail-closed.

    Requires the message shape, the expected kind, the pair id, card
    binding (the sender identity id must equal the identity pinned in the
    verified peer card), and a valid Ed25519 signature by that identity.
    Returns the verified message.
    """
    if not isinstance(msg, dict):
        raise MigrationError(
            f"{kind}-malformed", "ceremony message is not an object"
        )
    for field_name in ("kind", "pair_id", "identity_id", "at", "body", "signature"):
        if field_name not in msg:
            raise MigrationError(
                f"{kind}-malformed", f"ceremony message missing {field_name}"
            )
    if msg["kind"] != kind:
        raise MigrationError(
            f"{kind}-kind-mismatch",
            f"expected kind {kind}, got {msg['kind']!r}",
        )
    if msg["pair_id"] != pair_id:
        raise MigrationError(
            f"{kind}-pair-mismatch", "ceremony message pair id differs"
        )
    if msg["identity_id"] != expected_identity_id:
        raise MigrationError(
            f"{kind}-binding-mismatch",
            "sender identity does not match the verified peer card",
        )
    try:
        sender_pub = parse_identity_id(msg["identity_id"])
    except ValueError as exc:
        raise MigrationError(f"{kind}-bad-identity", str(exc))
    signature = msg["signature"]
    if not isinstance(signature, str):
        raise MigrationError(
            f"{kind}-bad-signature", "signature must be a string"
        )
    try:
        raw_sig = b64url_decode(signature)
    except ValueError:
        raise MigrationError(
            f"{kind}-bad-signature", "signature is not valid base64url"
        )
    if len(raw_sig) != 64:
        raise MigrationError(
            f"{kind}-bad-signature", "signature must decode to 64 bytes"
        )
    unsigned = {k: v for k, v in msg.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(sender_pub).verify(
            raw_sig, restricted_jcs(unsigned)
        )
    except Exception:
        raise MigrationError(
            f"{kind}-bad-signature", "ceremony signature does not verify"
        )
    return msg


# ---------------------------------------------------------------------------
# Encrypted local rollback bundle (never sent)
# ---------------------------------------------------------------------------


def _bundle_dek_id(pair_id: str) -> str:
    return pair_id + "/bundle-dek"


def _write_bundle_key(ctx: MigrationContext, dek: bytes) -> None:
    # The bundle DEK lives in the migration vault, encrypted at rest under
    # the ceremony vault key. Reuse the vault file format with a distinct
    # key id; never transmit the bundle or this key.
    vault_store(
        ctx.vault_dir, _bundle_dek_id(ctx.pair_id), dek.hex(),
        enc_key=_vault_key(ctx),
    )


def _read_bundle_key(ctx: MigrationContext) -> bytes:
    return vault_load(
        ctx.vault_dir, _bundle_dek_id(ctx.pair_id),
        enc_key=_vault_key(ctx, create=False),
    )


def create_rollback_bundle(ctx: MigrationContext, contents: dict) -> Path:
    """Encrypt the rollback bundle locally. The bundle is never transmitted;
    this module has no transport path for it."""
    dek = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = json.dumps(contents).encode("utf-8")
    blob = nonce + AESGCM(dek).encrypt(nonce, plaintext, None)
    backup_dir = Path(ctx.state_dir) / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    name = f"rollback-{utcnow().replace(':', '').replace('-', '')}.bin"
    path = backup_dir / name
    path.write_bytes(blob)
    os.chmod(path, 0o600)
    _write_bundle_key(ctx, dek)
    return path


def read_rollback_bundle(ctx: MigrationContext, path: str | Path) -> dict:
    dek = _read_bundle_key(ctx)
    blob = Path(path).read_bytes()
    nonce, ciphertext = blob[:12], blob[12:]
    plaintext = AESGCM(dek).decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def destroy_rollback_bundle(path: str | Path) -> None:
    """Single overwrite, then unlink. Used at commit (step 9)."""
    p = Path(path)
    if not p.is_file():
        return
    try:
        size = p.stat().st_size
        with open(p, "r+b") as fh:
            fh.write(b"\x00" * size)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    p.unlink()


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class DryRunResult:
    checks: list[CheckResult]
    ok: bool


def _synthetic_legacy_envelope(
    key: bytes,
    sender: str,
    recipient: str,
    pair_id: str,
    msg_type: str = "note",
) -> bytes:
    """Build a fresh, correctly signed v0.1 envelope (test/rehearsal only)."""
    import hmac as hmac_mod

    envelope = {
        "v": 1,
        "id": "legacy-" + os.urandom(4).hex(),
        "from": sender,
        "to": recipient,
        "pair": pair_id,
        "type": msg_type,
        "title": "dry run",
        "body": "dry run body",
        "url": "",
        "created_at": utcnow(),
        "nonce": os.urandom(8).hex(),
    }
    canonical = json.dumps(
        {k: v for k, v in envelope.items()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    envelope["sig"] = hmac_mod.new(key, canonical, hashlib.sha256).hexdigest()
    return json.dumps(envelope).encode("utf-8")


def run_dry_run(ctx: MigrationContext) -> DryRunResult:
    """Schema, crypto, local transport, and migration dry-run tests."""
    checks: list[CheckResult] = []

    # Schema.
    try:
        with tempfile.TemporaryDirectory() as tmp:
            conn = open_db(tmp)
            try:
                version = migrate_schema(conn)
                checks.append(
                    CheckResult(
                        "schema",
                        version == SCHEMA_VERSION,
                        f"user_version={version}",
                    )
                )
            finally:
                conn.close()
    except Exception as exc:  # noqa: BLE001
        checks.append(CheckResult("schema", False, str(exc)))

    # Crypto: HMAC round trip with a fresh key.
    try:
        key = os.urandom(32)
        msg = b"dry-run"
        sig = hmac.new(key, msg, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(
            sig, hmac.new(key, msg, hashlib.sha256).hexdigest()
        )
        checks.append(CheckResult("crypto-hmac", ok, "fresh key round trip"))
    except Exception as exc:  # noqa: BLE001
        checks.append(CheckResult("crypto-hmac", False, str(exc)))

    # Crypto: AES-GCM round trip with a fresh key.
    try:
        key = os.urandom(32)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, b"dry-run", None)
        pt = AESGCM(key).decrypt(nonce, ct, None)
        checks.append(CheckResult("crypto-aesgcm", pt == b"dry-run", ""))
    except Exception as exc:  # noqa: BLE001
        checks.append(CheckResult("crypto-aesgcm", False, str(exc)))

    # Local transport: write and read back.
    try:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "probe.json"
            p.write_bytes(b'{"ok": true}')
            ok = p.read_bytes() == b'{"ok": true}'
        checks.append(CheckResult("local-transport", ok, ""))
    except Exception as exc:  # noqa: BLE001
        checks.append(CheckResult("local-transport", False, str(exc)))

    # Migration dry run: detect, verify, adapt a synthetic legacy object.
    try:
        key = os.urandom(32)
        raw = _synthetic_legacy_envelope(
            key, ctx.peer_agent_id, ctx.my_agent_id, ctx.pair_id
        )
        policy = LegacyPolicy(
            pair_id=ctx.pair_id,
            expected_sender=ctx.peer_agent_id,
            my_agent_id=ctx.my_agent_id,
            replay_store=MemoryReplayStore(),
        )
        detected = detect_v01(raw)
        verified = verify_v01(raw, key, policy=policy, filename="dry-run.json")
        assigner = SeqAssigner()
        first = adapt_v01(verified, ctx.pair_id, assigner)
        second = adapt_v01(verified, ctx.pair_id, assigner)
        ok = (
            detected
            and first["event_id"] == second["event_id"]
            and first["sender_seq"] == second["sender_seq"]
            and first["raw_v01"] == raw
            and first["legacy_source"] == "v0.1"
        )
        checks.append(CheckResult("migration-adapter", ok, ""))
    except Exception as exc:  # noqa: BLE001
        checks.append(CheckResult("migration-adapter", False, str(exc)))

    return DryRunResult(checks=checks, ok=all(c.ok for c in checks))


# ---------------------------------------------------------------------------
# Stage: steps 1-6
# ---------------------------------------------------------------------------


def _default_drain_legacy(ctx: MigrationContext) -> list[str]:
    found: list[str] = []
    root = Path(ctx.legacy_state_dir)
    if root.is_dir():
        for p in sorted(root.rglob("*.json")):
            found.append(str(p.relative_to(root)))
    return found


def _set_v01_sends(ctx: MigrationContext, allowed: bool) -> None:
    if ctx.hooks.set_v01_sends is not None:
        ctx.hooks.set_v01_sends(allowed)
    # The flag is always recorded in migration state as the source of truth
    # for this side's cutover gating.
    conn = open_db(ctx.state_dir)
    try:
        migrate_schema(conn)
        mstate_set(conn, "migration.v01_sends_allowed", allowed)
    finally:
        conn.close()


def stage(ctx: MigrationContext) -> dict:
    """Run steps 1-6: freeze, backup, install, exchange cards, verify
    phrase, provision keys. Returns a summary; phase becomes 'staged'."""
    conn = open_db(ctx.state_dir)
    try:
        migrate_schema(conn)
        if _phase(conn) not in ("idle", "rolled_back", "freezing"):
            raise MigrationError(
                "bad-phase",
                "stage requires phase idle/rolled_back/freezing, found "
                f"{_phase(conn)}",
            )
        # "freezing" means a previous stage attempt failed partway; retrying
        # is safe because every step below is idempotent (keys and cards are
        # reused, vault entries are re-sealed, state is overwritten).
        summary: dict[str, Any] = {}

        # The ceremony identity key comes first: it signs the migration
        # card and all later ceremony messages, and derives the migration
        # vault encryption key used from step 2 on.
        _migration_identity_priv(ctx)
        _assert_identity_matches(conn, ctx)
        mstate_set(conn, "migration.my_identity_id", _migration_identity_id(ctx))

        # Step 1: freeze.
        if Path(ctx.state_dir).resolve() == Path(ctx.legacy_state_dir).resolve():
            raise MigrationError(
                "state-dir-collision",
                "v0.2 state dir must be separate from the legacy state dir",
            )
        if not Path(ctx.legacy_state_dir).is_dir():
            raise MigrationError(
                "legacy-state-missing",
                f"legacy state dir not found: {ctx.legacy_state_dir}",
            )
        _set_phase(conn, "freezing")
        relay_head = (
            ctx.hooks.record_relay_head()
            if ctx.hooks.record_relay_head
            else "local-transport"
        )
        if ctx.hooks.drain_legacy_incoming:
            drained = ctx.hooks.drain_legacy_incoming()
        else:
            drained = _default_drain_legacy(ctx)
        freeze = {
            "relay_head": relay_head,
            "backlog_files": drained,
            "backlog_count": len(drained),
        }
        mstate_set(conn, "migration.freeze", freeze)
        _set_v01_sends(ctx, False)
        _record_step(conn, 1, "ok", freeze)
        summary["freeze"] = freeze

        # Step 2: backup (encrypted local rollback bundle, never sent).
        vault_key = _vault_key(ctx)
        try:
            # Accepts the operator's plaintext handoff entry as well as an
            # already-sealed one; either way it is re-sealed below so the
            # vault is encrypted at rest from here on.
            legacy_key = vault_load(
                ctx.vault_dir, ctx.pair_id, enc_key=vault_key
            )
        except KeyError as exc:
            raise MigrationError("vault-missing", str(exc))
        vault_store(ctx.vault_dir, ctx.pair_id, legacy_key.hex(), enc_key=vault_key)
        bundle_contents = {
            "pair_id": ctx.pair_id,
            "legacy_key_hex": legacy_key.hex(),
            "legacy_snapshot": ctx.legacy_snapshot,
            "freeze": freeze,
            "created_at": utcnow(),
            "role": ctx.role,
        }
        bundle_path = create_rollback_bundle(ctx, bundle_contents)
        # Verify restorability before anything depends on it.
        restored = read_rollback_bundle(ctx, bundle_path)
        if restored["freeze"] != freeze:
            raise MigrationError("bundle-unrestorable", "round trip mismatch")
        mstate_set(conn, "migration.bundle_path", str(bundle_path))
        _record_step(conn, 2, "ok", {"bundle": str(bundle_path)})
        summary["bundle"] = str(bundle_path)

        # Step 3: install (already deployed: this state dir) + dry run.
        dry = run_dry_run(ctx)
        if not dry.ok:
            failed = [c.name for c in dry.checks if not c.ok]
            raise MigrationError("dry-run-failed", ",".join(failed))
        _record_step(
            conn, 3, "ok", {"checks": [c.name for c in dry.checks]}
        )
        summary["dry_run"] = [c.name for c in dry.checks]

        # Step 4: exchange signed cards. Each peer generates its own
        # keypairs; the card is Ed25519-signed by the side's migration
        # identity key (model/cards.create_card) and the outer exchange
        # envelope is signed again by the same key. The peer envelope is
        # fully verified on receipt: fail-closed on any missing or invalid
        # signature, with no unsigned fallback.
        ident_priv = _migration_identity_priv(ctx)
        my_identity_id = _migration_identity_id(ctx)
        rel_priv = _relationship_priv(ctx)
        rel_pub_raw = rel_priv.public_key().public_bytes_raw()
        deploy_pub = _deploy_keypair(ctx)
        now = _now_utc()
        try:
            my_card = create_card(
                identity_priv=ident_priv,
                display_name=ctx.my_agent_id,
                principal_label=f"migration:{ctx.role}",
                agreement_pub_multibase=agreement_key_multibase_from_pubkey(
                    rel_pub_raw
                ),
                capabilities=["migration/0.2"],
                issued_at=now,
                expires_at=now + timedelta(days=30),
            )
        except ValueError as exc:
            raise MigrationError("card-build-failed", str(exc))
        my_migration = {
            "pair_id": ctx.pair_id,
            "agent_id": ctx.my_agent_id,
            "deploy_pub": deploy_pub,
            "role": ctx.role,
        }
        my_envelope = _sign_card_exchange(ident_priv, my_card, my_migration)
        if ctx.hooks.exchange_card is None:
            raise AwaitingPeer(4, "exchange signed cards over the human channel")
        peer_envelope = ctx.hooks.exchange_card(my_envelope)
        peer_card, peer_migration = _verify_card_exchange(peer_envelope, ctx)
        mstate_set(conn, "migration.my_card_exchange", my_envelope)
        mstate_set(conn, "migration.peer_card_exchange", peer_envelope)
        _record_step(
            conn,
            4,
            "ok",
            {
                "peer_agent": peer_migration.get("agent_id"),
                "peer_identity_id": peer_card["identity_id"],
            },
        )
        summary["cards"] = "exchanged and signature-verified"

        # Step 5: verify the eight-word phrase. The phrase is derived ONLY
        # from the two exchanged and signature-verified cards: there is no
        # locally generated fallback. A missing or unverified card already
        # aborted step 4, so reaching this point with a usable phrase is
        # impossible without both verified cards.
        peer_identity_id = peer_card["identity_id"]
        phrase = verification_phrase(
            my_identity_id, peer_identity_id, load_wordlist()
        )
        phrase_text = " ".join(phrase)
        if ctx.hooks.compare_phrase is None:
            raise AwaitingPeer(5, "compare the eight-word phrase with the human")
        # Both sides derive the identical phrase from the same verified
        # cards; the hook is the human-channel confirmation of that value.
        if not ctx.hooks.compare_phrase(phrase_text, phrase_text):
            raise MigrationError("phrase-mismatch", "eight-word phrase differs")
        mstate_set(
            conn,
            "migration.consent",
            {
                "phrase_verified_at": utcnow(),
                "my_identity_id": my_identity_id,
                "peer_identity_id": peer_identity_id,
                "my_card_fingerprint": card_fingerprint(my_card),
                "peer_card_fingerprint": card_fingerprint(peer_card),
                "peer_agent": peer_migration.get("agent_id"),
            },
        )
        _record_step(conn, 5, "ok", {})
        summary["phrase"] = "verified"

        # Step 6: provision new public deploy keys; keep old ones for drain.
        # The provisioned key is a real OpenSSH public key
        # ("ssh-ed25519 ..."), suitable as a GitHub deploy key.
        new_key = {
            "repo": ctx.legacy_snapshot.get("relay_repo", "relay"),
            "public_key": deploy_pub,
            "label": "mas-v02",
        }
        if ctx.hooks.provision_deploy_key is None:
            raise AwaitingPeer(6, "add the new public deploy key to the relay")
        ctx.hooks.provision_deploy_key(new_key)
        mstate_set(conn, "migration.new_deploy_key", new_key)
        mstate_set(
            conn, "migration.old_deploy_keys", {"status": "kept-for-drain"}
        )
        _record_step(conn, 6, "ok", {"label": "mas-v02"})
        summary["provision"] = "new deploy key added; old keys kept"

        _set_phase(conn, "staged")
        return summary
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Verify: steps 7-8 (dual-read, prove)
# ---------------------------------------------------------------------------


def verify(ctx: MigrationContext) -> dict:
    """Run steps 7-8: dual-read and the prove round trip. Phase -> verified.

    migration.ready announcements and round-trip proofs are Ed25519-signed
    by the sender's migration identity key; anything missing a signature,
    carrying a bad signature, or not bound to the verified peer card is
    rejected (fail-closed).
    """
    conn = open_db(ctx.state_dir)
    try:
        migrate_schema(conn)
        if _phase(conn) != "staged":
            raise MigrationError(
                "bad-phase", f"verify requires phase staged, found {_phase(conn)}"
            )
        _assert_identity_matches(conn, ctx)
        peer_identity_id = _peer_identity_id(conn, ctx)
        ident_priv = _migration_identity_priv(ctx, create=False)
        summary: dict[str, Any] = {}

        # Step 7: dual-read. v0.1+v0.2 reads; v0.2 writes only after a
        # mutually signed migration.ready. Our announcement is signed here
        # with our identity key; the peer's is verified against the card.
        if ctx.hooks.sign_ready is None or ctx.hooks.await_peer_ready is None:
            raise AwaitingPeer(7, "exchange mutually signed migration.ready")
        my_ready = _sign_ceremony_msg(
            ident_priv, "migration.ready", ctx.pair_id, ctx.hooks.sign_ready()
        )
        peer_ready = _verify_ceremony_msg(
            ctx.hooks.await_peer_ready(),
            peer_identity_id,
            ctx.pair_id,
            "migration.ready",
        )
        mstate_set(
            conn,
            "migration.dual_read",
            {"v01_read": True, "v02_write": True, "at": utcnow()},
        )
        mstate_set(conn, "migration.ready.my", my_ready)
        mstate_set(conn, "migration.ready.peer", peer_ready)
        _record_step(conn, 7, "ok", {"v02_write": True})
        summary["dual_read"] = "v0.1+v0.2 reads; v0.2 writes enabled"

        # Step 8: prove round trip. The proof arrives as a peer-signed
        # ceremony message and is verified before any count is trusted.
        if ctx.hooks.prove_roundtrip is None:
            raise AwaitingPeer(
                8,
                "exchange relationship.ready, message, reaction, receipts, "
                "edit, and retraction",
            )
        proof_msg = _verify_ceremony_msg(
            ctx.hooks.prove_roundtrip(),
            peer_identity_id,
            ctx.pair_id,
            "migration.proof",
        )
        proof = proof_msg["body"]
        if not isinstance(proof, dict):
            raise MigrationError(
                "migration.proof-malformed", "proof body is not an object"
            )
        required = {
            "relationship.ready",
            "message",
            "reaction",
            "receipt.accepted",
            "edit",
            "retraction",
        }
        missing = required - set(proof.keys())
        if missing:
            raise MigrationError(
                "prove-incomplete", f"missing proof types: {sorted(missing)}"
            )
        try:
            adapted = int(proof.get("legacy_adapted", 0))
        except (TypeError, ValueError):
            raise MigrationError(
                "prove-count-mismatch",
                f"legacy_adapted is not an integer: {proof.get('legacy_adapted')!r}",
            )
        freeze = mstate_get(conn, "migration.freeze", {})
        try:
            expected = int(freeze.get("backlog_count", adapted))
        except (TypeError, ValueError):
            raise MigrationError(
                "prove-count-mismatch",
                "freeze backlog_count is not an integer",
            )
        if adapted != expected:
            raise MigrationError(
                "prove-count-mismatch",
                f"adapted {adapted} != backlog {expected}",
            )
        mstate_set(conn, "migration.proof", proof)
        mstate_set(conn, "migration.proof_signed", proof_msg)
        _record_step(conn, 8, "ok", {"legacy_adapted": adapted})
        summary["prove"] = f"round trip ok; legacy adapted {adapted}/{expected}"

        _set_phase(conn, "verified")
        return summary
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Cutover: step 9 (commit)
# ---------------------------------------------------------------------------


def cutover(ctx: MigrationContext) -> dict:
    """Run step 9: exchange migration.commit, remove legacy material, start
    the 24h drain clock. Phase becomes 'committed'. No rollback after this.

    Ordering guarantee: every fallible coordination step (commit exchange,
    key revocation, peer key-copy deletion) completes BEFORE any rollback
    key material is destroyed. The phase flips to 'committed' only after
    the destructive section succeeds, so any failure before that point
    leaves the phase at 'verified' with the vault key and rollback bundle
    intact: cutover can be retried and rollback() still works.
    """
    conn = open_db(ctx.state_dir)
    try:
        migrate_schema(conn)
        if _phase(conn) != "verified":
            raise MigrationError(
                "bad-phase",
                f"cutover requires phase verified, found {_phase(conn)}",
            )
        _assert_identity_matches(conn, ctx)
        peer_identity_id = _peer_identity_id(conn, ctx)
        ident_priv = _migration_identity_priv(ctx, create=False)
        summary: dict[str, Any] = {}

        # --- coordination (non-destructive; may raise AwaitingPeer) ---
        if ctx.hooks.exchange_commit is None:
            raise AwaitingPeer(9, "exchange migration.commit with the peer")
        my_commit = _sign_ceremony_msg(
            ident_priv, "migration.commit", ctx.pair_id, {"pair_id": ctx.pair_id}
        )
        peer_commit = _verify_ceremony_msg(
            ctx.hooks.exchange_commit(my_commit),
            peer_identity_id,
            ctx.pair_id,
            "migration.commit",
        )
        mstate_set(conn, "migration.commit", peer_commit)

        # Remove old deploy keys.
        if ctx.hooks.revoke_old_deploy_key is None:
            raise AwaitingPeer(9, "revoke the old deploy keys")
        ctx.hooks.revoke_old_deploy_key({"label": "v0.1-legacy"})
        mstate_set(conn, "migration.old_deploy_keys", {"status": "revoked"})

        # Delete the peer private key copy.
        if ctx.hooks.delete_peer_key_copy is None:
            raise AwaitingPeer(9, "delete the peer private key copy")
        ctx.hooks.delete_peer_key_copy()

        # Local v0.1 sends are rejected from here on.
        _set_v01_sends(ctx, False)

        # Start the 24h read-only drain clock.
        drain_until = _v01_now() + DRAIN_WINDOW
        mstate_set(conn, "migration.drain_until", _fmt_ts(drain_until))
        mstate_set(conn, "migration.legacy_read_open", True)

        # --- destructive section: only after everything above succeeded.
        # Each deletion tolerates an already-deleted entry so a retried
        # cutover (after a crash inside this section) still converges.
        vault_key = _vault_key(ctx, create=False)
        try:
            vault_delete(ctx.vault_dir, ctx.pair_id)
        except KeyError:
            pass
        try:
            vault_load(ctx.vault_dir, ctx.pair_id, enc_key=vault_key)
            raise MigrationError("vault-not-deleted", "legacy key still loads")
        except KeyError:
            pass

        bundle_path = mstate_get(conn, "migration.bundle_path")
        if bundle_path:
            destroy_rollback_bundle(bundle_path)
            try:
                vault_delete(ctx.vault_dir, _bundle_dek_id(ctx.pair_id))
            except KeyError:
                pass

        _record_step(conn, 9, "ok", {"drain_until": _fmt_ts(drain_until)})
        _set_phase(conn, "committed")
        summary["commit"] = "legacy material removed; drain clock started"
        summary["drain_until"] = _fmt_ts(drain_until)
        return summary
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Observe: step 10 (24h drain, then disable)
# ---------------------------------------------------------------------------


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _fmt_ts(dt: datetime) -> str:
    return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _queue_depths(conn: Any) -> dict[str, int]:
    depths = {}
    for table in (
        "projection_queue",
        "receipt_queue",
        "surface_queue",
        "scheduler_queue",
    ):
        try:
            depths[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except Exception:  # noqa: BLE001
            depths[table] = -1
    return depths


def observe(ctx: MigrationContext) -> dict:
    """Run step 10: 24h read-only drain, count comparison, empty retry
    queues. Closes legacy acceptance once the drain window expires; phase
    becomes 'complete'.

    Completion is gated: the migration is NOT marked complete while any
    retry queue is non-empty or the sent/received counts (freeze backlog
    vs. proved adapted) do not match. A gate failure raises
    MigrationError with the mismatch surfaced in both the error detail and
    the stored observation report; the phase stays 'committed' so the
    operator can investigate and re-run observe.
    """
    conn = open_db(ctx.state_dir)
    try:
        migrate_schema(conn)
        if _phase(conn) != "committed":
            raise MigrationError(
                "bad-phase",
                f"observe requires phase committed, found {_phase(conn)}",
            )
        drain_until = datetime.strptime(
            mstate_get(conn, "migration.drain_until"), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        now = _v01_now()
        depths = _queue_depths(conn)
        freeze = mstate_get(conn, "migration.freeze", {}) or {}
        proof = mstate_get(conn, "migration.proof", {}) or {}
        report: dict[str, Any] = {
            "drain_until": _fmt_ts(drain_until),
            "drain_open": now < drain_until,
            "queues": depths,
            "backlog_count": freeze.get("backlog_count"),
            "legacy_adapted": proof.get("legacy_adapted"),
        }

        if now < drain_until:
            # Drain still open: legacy reads allowed, sends stay disabled.
            # Completion is not attempted, but the report already surfaces
            # queue depths and counts for the operator.
            mstate_set(conn, "migration.legacy_read_open", True)
            mstate_set(conn, "migration.observe_report", report)
            report["legacy_read"] = "open (drain window)"
            return report

        # Drain expired: completion gates. Refuse to mark complete while any
        # retry queue is non-empty or its depth cannot be verified.
        unknown = [t for t, d in depths.items() if d < 0]
        if unknown:
            report["gate"] = "queues-unverifiable"
            mstate_set(conn, "migration.observe_report", report)
            raise MigrationError(
                "observe-queues-unverifiable",
                "could not read retry queue depths: " + ",".join(sorted(unknown)),
            )
        nonempty = {t: d for t, d in depths.items() if d != 0}
        if nonempty:
            report["gate"] = "queues-nonempty"
            mstate_set(conn, "migration.observe_report", report)
            raise MigrationError(
                "observe-queues-nonempty",
                "retry queues are not empty: "
                + ", ".join(f"{t}={d}" for t, d in sorted(nonempty.items())),
            )

        # ... or while the sent/received counts are unmatched or unverifiable.
        try:
            backlog = int(freeze["backlog_count"])
            adapted = int(proof["legacy_adapted"])
        except (KeyError, TypeError, ValueError):
            report["gate"] = "counts-unverifiable"
            mstate_set(conn, "migration.observe_report", report)
            raise MigrationError(
                "observe-counts-unverifiable",
                "cannot compare counts: freeze backlog_count="
                f"{freeze.get('backlog_count')!r}, proof legacy_adapted="
                f"{proof.get('legacy_adapted')!r}",
            )
        report["counts_match"] = backlog == adapted
        if backlog != adapted:
            report["gate"] = "count-mismatch"
            mstate_set(conn, "migration.observe_report", report)
            raise MigrationError(
                "observe-count-mismatch",
                f"backlog {backlog} != legacy adapted {adapted}; "
                "investigate before closing the drain",
            )

        # Drain expired: disable legacy acceptance permanently.
        mstate_set(conn, "migration.legacy_read_open", False)
        _record_step(conn, 10, "ok", report)
        _set_phase(conn, "complete")
        report["legacy_read"] = "closed (V01_DRAIN_CLOSED)"
        return report
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Rollback (before commit only)
# ---------------------------------------------------------------------------


def rollback(ctx: MigrationContext, reason: str = "") -> dict:
    """Roll back a pre-commit migration: restore v0.1 sends.

    Refuses after commit: roll forward only, never resurrect deleted keys.
    """
    conn = open_db(ctx.state_dir)
    try:
        migrate_schema(conn)
        phase = _phase(conn)
        if phase in ("committed", "complete"):
            raise MigrationError(
                "rollback-after-commit-refused",
                "after commit, roll forward with a corrective v0.2 release; "
                "never resurrect deleted keys",
            )
        if phase == "idle":
            raise MigrationError("nothing-to-roll-back", "phase is idle")

        # Restore v0.1 sends; the v0.1 key remains authoritative.
        _set_v01_sends(ctx, True)
        try:
            vault_load(ctx.vault_dir, ctx.pair_id,
                       enc_key=_vault_key(ctx, create=False))
            key_present = True
        except KeyError:
            key_present = False
        if not key_present:
            raise MigrationError(
                "rollback-key-missing",
                "legacy pair key is not in the vault; cannot restore v0.1",
            )

        freeze = mstate_get(conn, "migration.freeze", {})
        mstate_set(
            conn,
            "migration.rollback",
            {"at": utcnow(), "reason": reason, "freeze": freeze},
        )
        for n in range(1, 11):
            _record_step(conn, n, "rolled-back", {"reason": reason})
        _set_phase(conn, "rolled_back")
        return {
            "restored_v01_sends": True,
            "legacy_key_in_vault": True,
            "backlog_count": freeze.get("backlog_count"),
            "reason": reason,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Rehearsal harness: disposable pair, migrate, roll back, prove counts
# ---------------------------------------------------------------------------


def _write_legacy_backlog(
    legacy_dir: Path,
    key: bytes,
    sender: str,
    recipient: str,
    pair_id: str,
    count: int,
) -> list[str]:
    """Write a disposable v0.1 backlog: half plaintext, half wrapped."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

    incoming = legacy_dir / "incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    types = ["note", "link", "article", "file-ref"]
    names: list[str] = []
    for i in range(count):
        raw = _synthetic_legacy_envelope(
            key, sender, recipient, pair_id, types[i % 4]
        )
        name = f"20260915T120{i:02d}Z-msg-{i:02d}.json"
        if i % 2 == 0:
            (incoming / name).write_bytes(raw)
        else:
            nonce = os.urandom(12)
            ct = _AESGCM(key).encrypt(nonce, raw, None)
            wrapper = {
                "n": base64.b64encode(nonce).decode("ascii"),
                "c": base64.b64encode(ct).decode("ascii"),
            }
            (incoming / name).write_bytes(json.dumps(wrapper).encode("utf-8"))
        names.append(name)
    return sorted(names)


def _rehearsal_hooks(
    key: bytes,
    sender: str,
    recipient: str,
    pair_id: str,
    legacy_dir: Path,
    v01_sends_flag: dict,
    conn_factory: Callable[[], Any],
    relationship_id: str,
) -> MigrationHooks:
    """In-memory two-party fakes: both sides are simulated in-process.

    The local side is *recipient* (Alice); the simulated peer is *sender*
    (Bob). Bob's card, ready, proof, and commit messages are really signed
    with Bob's ceremony identity key so the local verification path is
    exercised end to end.
    """
    # Bob's ceremony material: a real Ed25519 identity, a real signed card,
    # and a real OpenSSH deploy keypair.
    bob_ident = Ed25519PrivateKey.generate()
    bob_rel = X25519PrivateKey.generate()
    bob_now = _now_utc()
    bob_card = create_card(
        identity_priv=bob_ident,
        display_name=sender,
        principal_label="migration:peer",
        agreement_pub_multibase=agreement_key_multibase_from_pubkey(
            bob_rel.public_key().public_bytes_raw()
        ),
        capabilities=["migration/0.2"],
        issued_at=bob_now,
        expires_at=bob_now + timedelta(days=30),
    )
    bob_deploy_pub = generate_deploy_keypair(
        str(legacy_dir.parent / "peer-keys" / "deploy.key")
    )

    def record_relay_head() -> str:
        return "rehearsal-head"

    def drain_legacy_incoming() -> list[str]:
        return sorted(
            p.name for p in (legacy_dir / "incoming").glob("*.json")
        )

    def set_v01_sends(allowed: bool) -> None:
        v01_sends_flag["allowed"] = allowed

    def exchange_card(my_envelope: dict) -> dict:
        return _sign_card_exchange(
            bob_ident,
            bob_card,
            {
                "pair_id": pair_id,
                "agent_id": sender,
                "deploy_pub": bob_deploy_pub,
                "role": "peer",
            },
        )

    def compare_phrase(mine: str, peer: str) -> bool:
        return True  # rehearsal: both sides compute the same phrase

    def provision_deploy_key(new_key: dict) -> None:
        return None

    def sign_ready() -> dict:
        # Local (Alice) side payload; the ceremony signs it with Alice's
        # identity key before storing/sending.
        return {"pair_id": pair_id, "agent_id": recipient, "at": utcnow()}

    def await_peer_ready() -> dict:
        # Bob's side, signed by Bob's identity key.
        return _sign_ceremony_msg(
            bob_ident,
            "migration.ready",
            pair_id,
            {"pair_id": pair_id, "agent_id": sender, "at": utcnow()},
        )

    def prove_roundtrip() -> dict:
        # Dual-read the legacy backlog into the v0.2 store and count.
        conn = conn_factory()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO conversations (conversation_id)"
                " VALUES (?)",
                (relationship_id,),
            )
            conn.execute(
                "INSERT OR IGNORE INTO threads (thread_id, conversation_id)"
                " VALUES (?, ?)",
                (relationship_id + ":t", relationship_id),
            )
            conn.execute(
                "INSERT OR IGNORE INTO relationships (relationship_id,"
                " peer_identity_id, consent_state, policy, key_epoch,"
                " created_at) VALUES (?, ?, 'active', '{}', 1, ?)",
                (relationship_id, recipient, utcnow()),
            )
            conn.execute(
                "INSERT OR IGNORE INTO key_epochs (relationship_id, epoch,"
                " public_key, private_key_ref, state)"
                " VALUES (?, 1, 'rehearsal', 'rehearsal', 'active')",
                (relationship_id,),
            )
            policy = LegacyPolicy(
                pair_id=pair_id,
                expected_sender=sender,
                my_agent_id=recipient,
                replay_store=MemoryReplayStore(),
            )
            assigner = SeqAssigner()
            adapted = 0
            for name in sorted((legacy_dir / "incoming").glob("*.json")):
                raw = name.read_bytes()
                verified = verify_v01(
                    raw, key, policy=policy, filename=name.name
                )
                event = adapt_v01(verified, pair_id, assigner)
                conn.execute(
                    "INSERT OR IGNORE INTO events (event_id, relationship_id,"
                    " conversation_id, thread_id, sender, sender_seq,"
                    " created_at, key_epoch, event_type, replay_nonce,"
                    " sealed_envelope) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                    (
                        event["event_id"],
                        relationship_id,
                        relationship_id,
                        relationship_id + ":t",
                        event["sender"],
                        event["sender_seq"],
                        event["created_at"],
                        event["event_type"],
                        "v01:" + verified.envelope["nonce"],
                        event["raw_v01"],
                    ),
                )
                adapted += 1
            conn.commit()
        finally:
            conn.close()
        # Bob's signed proof of the round trip.
        return _sign_ceremony_msg(
            bob_ident,
            "migration.proof",
            pair_id,
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

    def exchange_commit(payload: dict) -> dict:
        return _sign_ceremony_msg(
            bob_ident,
            "migration.commit",
            pair_id,
            {"pair_id": pair_id, "at": utcnow()},
        )

    def revoke_old_deploy_key(old: dict) -> None:
        return None

    def delete_peer_key_copy() -> None:
        return None

    return MigrationHooks(
        record_relay_head=record_relay_head,
        drain_legacy_incoming=drain_legacy_incoming,
        set_v01_sends=set_v01_sends,
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


def rehearse(work_root: str | Path) -> dict:
    """Migrate a DISPOSABLE local pair and roll back, proving counts match.

    Scenario A: stage, verify, rollback before commit; v0.1 sends restored,
    legacy key retained, freeze counts intact.
    Scenario B: stage, verify, cutover; v0.1 sends disabled, vault key
    deleted; simulated clock past the drain window; legacy reads closed.

    Uses fictional identities and fresh random keys only. Never touches
    live state.
    """
    work_root = Path(work_root)
    report: dict[str, Any] = {"scenarios": {}}

    def make_pair(tag: str) -> dict:
        base = work_root / tag
        pair_id = "pair-rehearsal-" + os.urandom(4).hex()
        alice = "agent:rehearsal-alice:" + os.urandom(4).hex()
        bob = "agent:rehearsal-bob:" + os.urandom(4).hex()
        key = os.urandom(32)
        legacy_dir = base / "legacy"
        state_dir = base / "v02"
        vault_dir = base / "vault"
        vault_store(vault_dir, pair_id, key.hex())
        backlog = _write_legacy_backlog(
            legacy_dir, key, bob, alice, pair_id, 6
        )
        return {
            "base": base,
            "pair_id": pair_id,
            "alice": alice,
            "bob": bob,
            "key": key,
            "legacy_dir": legacy_dir,
            "state_dir": state_dir,
            "vault_dir": vault_dir,
            "backlog": backlog,
        }

    def make_ctx(p: dict, v01_sends_flag: dict) -> MigrationContext:
        def conn_factory() -> Any:
            conn = open_db(p["state_dir"])
            migrate_schema(conn)
            return conn

        hooks = _rehearsal_hooks(
            p["key"],
            p["bob"],
            p["alice"],
            p["pair_id"],
            p["legacy_dir"],
            v01_sends_flag,
            conn_factory,
            "rel-" + p["pair_id"],
        )
        return MigrationContext(
            state_dir=p["state_dir"],
            legacy_state_dir=p["legacy_dir"],
            vault_dir=p["vault_dir"],
            pair_id=p["pair_id"],
            my_agent_id=p["alice"],
            peer_agent_id=p["bob"],
            role="initiator",
            hooks=hooks,
            legacy_snapshot={"relay_repo": "rehearsal-relay"},
        )

    # --- Scenario A: rollback before commit ---
    pa = make_pair("scenario-a")
    flag_a = {"allowed": True}
    ctx_a = make_ctx(pa, flag_a)
    dry = run_dry_run(ctx_a)
    assert dry.ok, f"dry run failed: {[c.name for c in dry.checks if not c.ok]}"
    stage(ctx_a)
    assert flag_a["allowed"] is False, "freeze must disable v0.1 sends"
    verify(ctx_a)
    rb = rollback(ctx_a, reason="rehearsal")
    assert flag_a["allowed"] is True, "rollback must restore v0.1 sends"
    assert rb["legacy_key_in_vault"] is True
    assert rb["backlog_count"] == 6, rb
    # Counts still match: the backlog is untouched and fully adapted.
    conn = open_db(pa["state_dir"])
    try:
        adapted = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        conn.close()
    assert adapted == 6, f"adapted {adapted} != backlog 6"
    report["scenarios"]["a_rollback"] = {
        "ok": True,
        "backlog": 6,
        "adapted": adapted,
        "v01_sends_restored": True,
    }

    # --- Scenario B: commit, drain, key deletion ---
    pb = make_pair("scenario-b")
    flag_b = {"allowed": True}
    ctx_b = make_ctx(pb, flag_b)
    stage(ctx_b)
    verify(ctx_b)
    cut = cutover(ctx_b)
    assert flag_b["allowed"] is False, "commit must disable v0.1 sends"
    try:
        vault_load(pb["vault_dir"], pb["pair_id"])
        raise AssertionError("legacy key must be deleted at commit")
    except KeyError:
        pass
    # Legacy sends are rejected now.
    pol = LegacyPolicy(
        pair_id=pb["pair_id"],
        expected_sender=pb["bob"],
        my_agent_id=pb["alice"],
        legacy_sends_allowed=False,
    )
    try:
        assert_legacy_sends_allowed(pol)
        raise AssertionError("expected V01_SENDS_DISABLED")
    except LegacyError as exc:
        assert exc.code == "V01_SENDS_DISABLED", exc.code
    # Simulated clock past the drain window: legacy reads close.
    t0 = _now_utc()
    _set_test_clock(lambda: t0)
    try:
        obs_open = observe(ctx_b)
        assert obs_open["drain_open"] is True
        _set_test_clock(lambda: t0 + DRAIN_WINDOW + timedelta(hours=1))
        obs_closed = observe(ctx_b)
        assert obs_closed["drain_open"] is False
        assert obs_closed["legacy_read"] == "closed (V01_DRAIN_CLOSED)"
    finally:
        _set_test_clock(None)
    # Any legacy verify now raises V01_DRAIN_CLOSED.
    raw = (pb["legacy_dir"] / "incoming" / pb["backlog"][0]).read_bytes()
    pol_closed = LegacyPolicy(
        pair_id=pb["pair_id"],
        expected_sender=pb["bob"],
        my_agent_id=pb["alice"],
        legacy_read_open=False,
    )
    try:
        verify_v01(raw, pb["key"], policy=pol_closed, filename="x.json")
        raise AssertionError("expected V01_DRAIN_CLOSED")
    except LegacyError as exc:
        assert exc.code == "V01_DRAIN_CLOSED", exc.code
    report["scenarios"]["b_commit_drain"] = {
        "ok": True,
        "drain_until": cut["drain_until"],
        "vault_key_deleted": True,
        "legacy_read_closed": True,
    }

    report["ok"] = True
    return report
