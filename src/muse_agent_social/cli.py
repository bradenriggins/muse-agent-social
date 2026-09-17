"""Muse Agent Social v0.2 command-line interface.

This module implements the full ``mas`` command surface for a local
installation: initialization, pairing, sending, receiving, key rotation,
v0.1 migration, revocation, and inspection.

Design notes (see INTERFACE.md for the operator-facing contract):

* Every expected failure raises :class:`CliError` with a stable,
  machine-readable ``code``. ``main()`` prints ``error <code>: <message>``
  to stderr and exits non-zero. Expected errors never produce tracebacks,
  and secrets (seeds, private keys, tokens) are never printed.
* Receive reuses :func:`watcher.run_once` for mirror locking, sequencing,
  checkpointing, and the 0/20/21/22/23 exit contract; the per-object
  pipeline (size check, parse, v0.1 detection, schema, sender, signature,
  replay, unseal, payload, atomic commit, incremental projection) is
  implemented here as the watcher's ``receive_fn`` callback.
* Transport selection is explicit: ``local`` (a shared directory, used for
  tests and same-machine pairs) or ``github`` (a provisioned relay repo).
  GitHub provisioning needs a token from ``--token`` or ``MAS_GITHUB_TOKEN``;
  the token is passed to the provisioning call only and is never logged.
* The pairing ceremony never bypasses the human 8-word phrase comparison:
  ``pair accept`` and ``pair commit`` print the phrase and require the
  explicit ``--i-compared-phrase`` flag before proceeding.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import errno
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import __version__
from ._keyfiles import (
    KeyFileError,
    atomic_write_file,
    atomic_write_pair,
    delete_private_key,
    recover_pending_pair,
    store_private_key,
)
from .canonical import CanonicalizationError, restricted_jcs, strict_parse
from .compatibility.v01 import (
    LegacyError,
    LegacyPolicy,
    MemoryReplayStore,
    SeqAssigner,
    StoreReplayGuard,
    VaultError,
    adapt_v01,
    detect_v01,
    record_legacy_replay,
    vault_load,
    verify_v01,
)
from .config import load_config, resolve_state_dir, save_config
from .crypto.identity import (
    b64url_decode,
    derive_identity_hierarchy,
    generate_master_seed,
    parse_agreement_key,
    parse_identity_id,
    store_master_seed,
)
from .crypto.rotation import (
    OLD_KEY_RETENTION,
    ConfirmRejected,
    IdentityRotationError,
    NoAckTimeout,
    RotationError,
    RotationManager,
)
from .crypto.sealing import SealingError, unseal_envelope
from .migrate import (
    AwaitingPeer,
    MigrationContext,
    MigrationError,
    ceremony_vault_key,
    cutover,
    drain_open,
    mstate_get,
    mstate_set,
    observe,
    rollback,
    run_dry_run,
    stage,
    verify,
)
from .model.cards import (
    card_fingerprint,
    create_card,
    parse_timestamp,
    verify_card,
)
from .model.events import (
    PAYLOAD_DISPATCH,
    EventStoreError,
    assign_and_persist_outgoing,
    build_protected,
    new_thread_id,
    validate_reply,
)
from .model.invites import (
    MAX_INVITE_FILE_BYTES,
    PairingError,
    commit_pairing,
    confirm_verification,
    create_acceptance,
    create_invite,
    generate_deploy_keypair,
    generate_relationship_keypair,
    get_relationship,
    ingest_commit,
    invite_uri,
    load_or_generate_deploy_keypair,
    mark_active,
    pairing_phrase,
    parse_invite_json,
    parse_invite_uri,
    preview_invite,
    record_displayed_phrase,
    record_verification,
)
from .policy.delivery import (
    DELIVERY_MODES,
    EXPIRY_HANDLINGS,
    accepted_receipt_permitted,
    get_policy,
    policy_snapshot,
    set_accepted_receipts_enabled,
    set_expiry_policy,
    set_policy,
    set_seen_receipts_enabled,
    should_send_seen_receipt,
    surface_action,
)
from .policy.limits import (
    ACCEPT_WINDOW_DAYS,
    FUTURE_TOLERANCE_SECONDS,
    INGRESS_MAX_EVENTS_PER_DAY,
    MAX_CONSECUTIVE_RECEIVE_FAILURES,
    MAX_ENVELOPE_BYTES,
    MAX_SEQ_GAP,
    MAX_UNKNOWN_EPOCH_SIGHTINGS,
    PRIOR_IDENTITY_GRACE_SECONDS,
    RECEIVE_QUARANTINE_MAX_PER_RELATIONSHIP,
    RECEIVE_QUARANTINE_TTL_DAYS,
    add_seconds,
    parse_canonical_utc,
)
from .transports.base import OBJECT_MAX_BYTES
from .store.db import (
    CorruptDatabaseError,
    SchemaTooNewError,
    DbError,
    default_db_path,
    open_db,
    transaction,
    utcnow,
)
from .store.migrations import migrate
from .store.projections import (
    ProjectionError,
    apply_event,
    migrate_projections,
    quarantine_event,
    record_projection_input,
)
from .teardown import (
    DeployKeyRef,
    RelayRef,
    TeardownError,
    teardown_relationship,
)
from .transports.base import TransportError
from .transports.github import (
    GitHubTransport,
    ensure_transport_tables,
    new_object_name,
    queue_mutation,
)
from .transports.local import LocalTransport
from .transports.provisioning import (
    ProvisioningError,
    deploy_key_title,
    register_peer_deploy_key,
)
from .validation import ValidationError as SchemaError, validate, validate_payload
from . import scheduler
from .watcher import (
    EXIT_LOCK_BUSY,
    EXIT_OK,
    EXIT_PARTIAL_TIMEOUT,
    EXIT_PERMANENT,
    EXIT_RETRYABLE,
    run_once,
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CliError(Exception):
    """An expected, operator-facing failure.

    ``code`` is a stable machine-readable string; ``message`` is human
    readable and must never contain secret material. ``exit_code`` defaults
    to 1; the receive path uses the watcher contract codes instead.
    """

    def __init__(self, code: str, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


# Receive exit codes mirror the watcher contract exactly.
EXIT_OK = 0
EXIT_PERMANENT = 20
EXIT_AUTH = 21
EXIT_LOCK_BUSY = 22
EXIT_PARTIAL_TIMEOUT = 23


def _receive_exit_precedence(codes: list[int]) -> int:
    """Aggregate per-relationship receive exit codes, worst first."""
    for code in (EXIT_AUTH, EXIT_LOCK_BUSY, EXIT_PERMANENT, EXIT_PARTIAL_TIMEOUT):
        if code in codes:
            return code
    return EXIT_OK


def _canon_text(obj: Any) -> str:
    """Canonical JSON text for machine-readable CLI output."""
    return restricted_jcs(obj).decode("utf-8")


def _new_uuid() -> str:
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# Context: one loaded installation
# ---------------------------------------------------------------------------

_CONFIG_NAME = "config.yaml"
_CARD_NAME = "agent-card.json"
_MASTER_SEED_NAME = "master.seed"
# Journal for the atomic seed+card pair publish in _rotate_identity. When a
# crash interrupts the pair, the next Ctx load re-drives it (see
# _keyfiles.recover_pending_pair) so the identity converges instead of
# staying torn.
_PENDING_IDENTITY_PAIR = ".pending-identity-pair.json"

_CLI_DDL = """
CREATE TABLE IF NOT EXISTS relay_config (
    relationship_id TEXT PRIMARY KEY,
    provider        TEXT NOT NULL,
    repo_url        TEXT,
    slots_json      TEXT,
    local_dir       TEXT,
    role            TEXT,
    ssh_key_path    TEXT,
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receive_quarantine (
    relationship_id TEXT NOT NULL,
    object_name     TEXT NOT NULL,
    reason          TEXT NOT NULL,
    detail          TEXT,
    quarantined_at  TEXT NOT NULL,
    PRIMARY KEY (relationship_id, object_name)
);
CREATE TABLE IF NOT EXISTS sent_objects (
    scheduled_id  TEXT PRIMARY KEY,
    object_name   TEXT NOT NULL,
    queued_at     TEXT NOT NULL
);
-- Per-object retryable-failure accounting for the receive path. A
-- retry_pending outcome is not free: each re-sighting of the same object
-- for the same reason is counted here, so storms (unknown future epochs)
-- and sick storage (transient errors) terminate in a quarantine instead
-- of draining availability forever. Rows are cleared when the object
-- reaches a terminal outcome.
CREATE TABLE IF NOT EXISTS receive_retry_state (
    relationship_id TEXT NOT NULL,
    object_name     TEXT NOT NULL,
    reason          TEXT NOT NULL,
    sightings       INTEGER NOT NULL DEFAULT 0,
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    PRIMARY KEY (relationship_id, object_name, reason)
);
"""


def _ensure_cli_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(_CLI_DDL)
    # Older installs predate the role column; add it idempotently.
    try:
        conn.execute("ALTER TABLE relay_config ADD COLUMN role TEXT")
    except sqlite3.OperationalError:
        pass
    # Older installs predate the ssh_key_path column; add it idempotently.
    try:
        conn.execute("ALTER TABLE relay_config ADD COLUMN ssh_key_path TEXT")
    except sqlite3.OperationalError:
        pass
    ensure_transport_tables(conn)


def _check_card(card: dict, what: str) -> None:
    """Raise CliError unless the card verifies live."""
    result = verify_card(card)
    if not result.ok:
        raise CliError(
            "card_invalid", f"{what} card invalid ({result.reason_code}): {result.message}"
        )


class Ctx:
    """A loaded local installation: state dir, config, card, keys, db."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.keys_dir = state_dir / "keys"
        config_path = state_dir / _CONFIG_NAME
        if not config_path.exists():
            raise CliError(
                "not_initialized",
                f"no installation at {state_dir}; run 'mas init' first",
            )
        try:
            self.config = load_config(config_path)
        except Exception as exc:
            raise CliError("config_error", f"cannot load config: {exc}")
        # Finish an identity seed/card pair publish interrupted by a crash.
        # This must run before the seed and card are read: it converges a
        # torn pair instead of letting the consistency check below fail.
        try:
            if recover_pending_pair(state_dir / _PENDING_IDENTITY_PAIR):
                print(
                    "recovered an interrupted identity seed/card publish",
                    file=sys.stderr,
                )
        except KeyFileError as exc:
            raise CliError("identity_error", str(exc)) from exc
        identity_ref = self.config.get("identity_ref") or {}
        seed_rel = identity_ref.get("master_seed_path") or f"keys/{_MASTER_SEED_NAME}"
        card_rel = identity_ref.get("card_path") or _CARD_NAME
        seed_path = state_dir / seed_rel
        card_path = state_dir / card_rel
        if not seed_path.exists():
            raise CliError("config_error", f"master seed missing: {seed_path}")
        if not card_path.exists():
            raise CliError("config_error", f"agent card missing: {card_path}")
        try:
            seed = seed_path.read_bytes()
        except OSError as exc:
            raise CliError("config_error", f"cannot read master seed: {exc}")
        try:
            self.hierarchy = derive_identity_hierarchy(seed)
        except Exception as exc:
            raise CliError("config_error", f"invalid master seed: {exc}")
        try:
            self.card = json.loads(card_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CliError("config_error", f"cannot load agent card: {exc}")
        _check_card(self.card, "local agent")
        self.identity_id = self.hierarchy.identity_id
        # Fail closed on a torn identity: the card must describe the same
        # identity the master seed derives. Without this, a crash between
        # the seed and card writes (or manual tampering) would silently run
        # the agent as the wrong identity.
        card_identity_id = self.card.get("identity_id")
        if card_identity_id != self.hierarchy.identity_id:
            raise CliError(
                "identity_mismatch",
                f"agent card identity_id {card_identity_id!r} does not match "
                f"the identity derived from the master seed "
                f"({self.hierarchy.identity_id!r}); refusing to run with a "
                "torn identity (after an interrupted rotation, restore the "
                ".backup-* seed and card, or re-run the rotation)",
            )
        db_path = default_db_path(state_dir)
        if not db_path.exists() or db_path.stat().st_size == 0:
            raise CliError(
                "state_error",
                f"installation at {state_dir} has config but no database "
                f"({db_path}); refusing to silently start with an empty "
                "database and lose all relationship state (restore the "
                "database from backup, or remove the installation and "
                "re-run 'mas init')",
            )
        try:
            self.conn = open_db(state_dir)
        except CorruptDatabaseError as exc:
            raise CliError("corrupt_database", str(exc)) from exc
        except (DbError, sqlite3.DatabaseError) as exc:
            raise CliError(
                "db_error", f"cannot open database at {db_path}: {exc}"
            ) from exc
        try:
            migrate(self.conn)
            migrate_projections(self.conn)
            from .transports.github import ensure_transport_tables

            ensure_transport_tables(self.conn)
            from .model.invites import _ensure_pairing_tables

            _ensure_pairing_tables(self.conn)
            from .crypto.rotation import (
                _ensure_tables as _ensure_rotation_tables,
            )

            _ensure_rotation_tables(self.conn)
            _ensure_cli_tables(self.conn)
        except SchemaTooNewError as exc:
            self.conn.close()
            raise CliError(
                "schema_too_new",
                f"{exc}; upgrade mas to open this database",
            ) from exc
        except (DbError, sqlite3.DatabaseError) as exc:
            self.conn.close()
            raise CliError(
                "db_error", f"database setup failed: {exc}"
            ) from exc

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    def relationship(self, relationship_id: str) -> dict:
        row = get_relationship(self.conn, relationship_id)
        if row is None:
            raise CliError(
                "unknown_relationship",
                f"no relationship {relationship_id} in this installation",
            )
        return row

    def resolve_relationship(self, value: str) -> dict:
        """Resolve a relationship by id or by peer identity id."""
        try:
            row = get_relationship(self.conn, value)
        except PairingError:
            row = None
        if row is not None:
            return row
        prow = self.conn.execute(
            "SELECT * FROM relationships WHERE peer_identity_id = ?",
            (value,),
        ).fetchone()
        if prow is None:
            raise CliError(
                "unknown_relationship",
                f"no relationship or peer matching {value!r} in this installation",
            )
        return prow


# NOTE: the legacy helpers _write_file_private / _atomic_write_bytes were
# removed here. They did temp+rename with a predictable tmp name, no fsync,
# and a chmod window. All private-key/seed writes MUST go through
# muse_agent_social._keyfiles (atomic_write_no_overwrite / store_private_key
# for keys, atomic_write_file for replaceable files); do not reintroduce a
# local writer.


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------


def _relay_config_row(ctx: Ctx, relationship_id: str) -> dict:
    row = ctx.conn.execute(
        "SELECT * FROM relay_config WHERE relationship_id = ?",
        (relationship_id,),
    ).fetchone()
    if row is None:
        raise CliError(
            "no_relay_config",
            f"no relay configured for relationship {relationship_id}",
        )
    return dict(row)


def _direction_slots(ctx: Ctx, relationship_id: str) -> tuple[str, str]:
    """Return (my_send_slot, my_receive_slot) for a relationship.

    The pairing commit agrees two relay slot names, one per direction.
    The inviter sends on ``inviter_send_slot`` and receives on
    ``inviter_receive_slot``; the acceptor uses them in reverse.
    """
    row = _relay_config_row(ctx, relationship_id)
    try:
        slots = json.loads(row["slots_json"]) if row["slots_json"] else {}
    except (ValueError, TypeError):
        slots = {}
    send_key = slots.get("inviter_send_slot")
    recv_key = slots.get("inviter_receive_slot")
    if not send_key or not recv_key:
        raise CliError(
            "no_relay_config",
            f"relay slots missing for relationship {relationship_id}",
        )
    if row["role"] == "acceptor":
        return recv_key, send_key
    return send_key, recv_key


def _transport_scope(relationship_id: str, direction: str) -> str:
    """Mutation-queue scope for one direction.

    The GitHub transport queues relay mutations per relationship id; the
    send and receive directions must not share a queue because each
    direction pushes to its own relay slot (branch).
    """
    return f"{relationship_id}:{direction}"


def _transport_for(ctx: Ctx, relationship_id: str, direction: str):
    """Build the transport for one direction ("send" or "receive").

    For the local transport each direction is a subdirectory named by the
    slot; for GitHub each direction is a branch named by the slot.
    """
    if direction not in ("send", "receive"):
        raise CliError("bad_args", f"bad transport direction {direction!r}")
    row = _relay_config_row(ctx, relationship_id)
    provider = row["provider"]
    send_slot, recv_slot = _direction_slots(ctx, relationship_id)
    slot = send_slot if direction == "send" else recv_slot
    if provider == "local":
        if not row["local_dir"]:
            raise CliError(
                "no_relay_config",
                f"local relay dir missing for relationship {relationship_id}",
            )
        return LocalTransport(Path(row["local_dir"]) / slot)
    if provider == "github":
        if not row["repo_url"]:
            raise CliError(
                "no_relay_config",
                f"relay repo URL missing for relationship {relationship_id}",
            )
        return GitHubTransport(
            ctx.state_dir,
            _transport_scope(relationship_id, direction),
            row["repo_url"],
            branch=slot,
            ssh_key_path=row.get("ssh_key_path"),
        )
    raise CliError("no_relay_config", f"unknown relay provider {provider!r}")


def transport_for(ctx: Ctx, relationship_id: str):
    """Legacy alias: the receive-direction transport."""
    return _transport_for(ctx, relationship_id, "receive")


def _save_relay_config(
    ctx: Ctx,
    relationship_id: str,
    provider: str,
    repo_url: Optional[str],
    slots: Optional[dict],
    local_dir: Optional[str],
    role: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
) -> None:
    ctx.conn.execute(
        "INSERT OR REPLACE INTO relay_config "
        "(relationship_id, provider, repo_url, slots_json, local_dir, role,"
        " ssh_key_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            relationship_id,
            provider,
            repo_url,
            json.dumps(slots) if slots else None,
            local_dir,
            role,
            ssh_key_path,
            utcnow(),
        ),
    )
    ctx.conn.commit()


# ---------------------------------------------------------------------------
# mas init
# ---------------------------------------------------------------------------

_DEFAULT_CAPABILITIES = ["events/0.2", "threads/1", "receipts/1"]


def cmd_init(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir) if args.state_dir else resolve_state_dir()
    keys_dir = state_dir / "keys"
    seed_path = keys_dir / _MASTER_SEED_NAME
    if seed_path.exists():
        raise CliError(
            "already_initialized",
            f"installation already exists at {state_dir}; refusing to overwrite",
        )
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)

    seed = generate_master_seed()
    store_master_seed(seed_path, seed)
    hierarchy = derive_identity_hierarchy(seed)
    capabilities = list(args.capability) if args.capability else list(_DEFAULT_CAPABILITIES)
    now = utcnow()
    card = create_card(
        hierarchy.ed25519_private,
        display_name=args.display_name or "Muse Agent",
        principal_label=args.principal or "operator",
        agreement_pub_multibase=hierarchy.agreement_key_multibase,
        capabilities=capabilities,
        issued_at=now,
        expires_at=add_seconds(now, 365 * 24 * 3600),
    )
    card_path = state_dir / _CARD_NAME
    atomic_write_file(
        card_path, (_canon_text(card) + "\n").encode("utf-8"), 0o600
    )
    save_config(
        state_dir / _CONFIG_NAME,
        {
            "identity_ref": {
                "card_path": _CARD_NAME,
                "master_seed_path": f"keys/{_MASTER_SEED_NAME}",
            },
            "relay": {"default_transport": "local"},
            "retention": {"mode": "encrypted"},
        },
    )
    conn = open_db(state_dir)
    try:
        migrate(conn)
        migrate_projections(conn)
        conn.commit()
    finally:
        conn.close()
    print(f"initialized {state_dir}")
    print(f"identity {hierarchy.identity_id}")
    return 0


# ---------------------------------------------------------------------------
# mas pair
# ---------------------------------------------------------------------------


def _read_text_capped(path, cap: int, what: str) -> str:
    """Read a text file with a hard byte cap (G9).

    Never buffers an unbounded file into memory; oversized input is
    rejected before parsing. Returns the decoded text.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read(cap + 1)
    except OSError as exc:
        raise CliError("bad_args", f"cannot read {what} file: {exc}")
    if len(raw) > cap:
        raise CliError("bad_args", f"{what} file exceeds {cap} bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CliError("bad_args", f"{what} file is not valid UTF-8: {exc}")


def _load_invite_text(args: argparse.Namespace) -> str:
    if args.invite_file:
        # G9: one bounded read path; the text is parsed once by the caller,
        # never re-read from disk.
        return _read_text_capped(args.invite_file, MAX_INVITE_FILE_BYTES, "invite")
    text = args.invite_text or ""
    if not text.strip():
        raise CliError("bad_args", "provide --invite-text or --invite-file")
    return text


def _preview_invite(invite: dict, ctx: Ctx) -> dict:
    """Structural preview of an invite before the human comparison."""
    try:
        validate("invite", invite)
    except SchemaError as exc:
        raise CliError("pairing_error", f"invite schema invalid: {exc}")
    _check_card(invite["inviter_card"], "inviter")
    if parse_timestamp(invite["expires_at"]) <= datetime.now(timezone.utc):
        raise CliError("pairing_error", "invite has expired")
    return {
        "invite_id": invite["invite_id"],
        "inviter": invite["inviter_card"].get("display_name"),
        "expires_at": invite["expires_at"],
        "requested_capabilities": invite["requested_capabilities"],
    }


def cmd_pair_invite(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        capabilities = (
            list(args.capability) if args.capability else list(ctx.card["capabilities"])
        )
        # The invite schema's requested_policy only carries accepted_receipts;
        # the full local delivery policy stays receiver-local per the plan.
        policy = {"accepted_receipts": True}
        if args.policy_json:
            try:
                loaded = json.loads(Path(args.policy_json).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise CliError("bad_args", f"cannot read policy JSON: {exc}")
            if not isinstance(loaded, dict):
                raise CliError("bad_args", "policy JSON must be an object")
            policy = loaded
        ephemeral = X25519PrivateKey.generate()
        invite = create_invite(
            ctx.conn,
            ctx.card,
            ctx.hierarchy.ed25519_private,
            ephemeral,
            capabilities,
            policy,
        )
        eph_path = ctx.keys_dir / "invites" / invite["invite_id"] / "ephemeral.key"
        store_private_key(
            eph_path,
            ephemeral.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
        )
        uri = invite_uri(invite)
        if args.out:
            Path(args.out).write_text(uri + "\n", encoding="utf-8")
            print(f"wrote invite to {args.out}", file=sys.stderr)
        print(uri)
        print(
            f"invite {invite['invite_id']} expires {invite['expires_at']}",
            file=sys.stderr,
        )
        print(
            "hand the URI to the peer out-of-band: paste the text above, "
            "use --out to write it to a file, or copy it through any "
            "handoff channel you already trust",
            file=sys.stderr,
        )
        return 0
    finally:
        ctx.close()


def cmd_pair_accept(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        text = _load_invite_text(args)
        try:
            stripped = text.strip()
            if stripped.startswith("muse-agent-social://"):
                invite = parse_invite_uri(stripped)
            else:
                # G9: the text was already read once by _load_invite_text
                # (bounded); parse it in memory instead of re-reading the
                # file from disk.
                invite = parse_invite_json(stripped)
        except (SchemaError, CanonicalizationError, ValueError, PairingError) as exc:
            raise CliError("pairing_error", f"cannot parse invite: {exc}")
        _preview_invite(invite, ctx)
        phrase = pairing_phrase(invite["inviter_card"], ctx.card)
        if not args.i_compared_phrase:
            print(" ".join(phrase), flush=True)
            print(
                "call or message the inviter out-of-band and compare all eight "
                "words, in order. When every word matches, re-run this command "
                "with --i-compared-phrase.",
                file=sys.stderr,
            )
            raise CliError(
                "phrase_confirmation_required",
                "re-run with --i-compared-phrase after comparing the phrase",
            )
        pair_dir = ctx.keys_dir / "pairing" / invite["invite_id"]
        # Generate key material in memory first. create_acceptance() runs
        # all validation (signature, expiry, one-use ledger) and must
        # succeed before anything is written to disk; otherwise a rejected
        # acceptance would leave orphaned private key files.
        rel_priv, rel_pub_mb = generate_relationship_keypair()
        rel_priv_bytes = rel_priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        deploy_priv = Ed25519PrivateKey.generate()
        deploy_pub = deploy_priv.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        ).decode("ascii").strip()
        try:
            acceptance = create_acceptance(
                ctx.conn,
                invite,
                ctx.card,
                ctx.hierarchy.ed25519_private,
                rel_pub_mb,
                deploy_pub,
            )
        except PairingError as exc:
            raise CliError("pairing_error", f"{exc.code}: {exc}")
        try:
            store_private_key(pair_dir / "relationship.key", rel_priv_bytes)
            store_private_key(
                pair_dir / "deploy",
                deploy_priv.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.OpenSSH,
                    serialization.NoEncryption(),
                ),
            )
            (pair_dir / "deploy.pub").write_text(
                deploy_pub + "\n", encoding="utf-8"
            )
            meta = {
                "invite_id": invite["invite_id"],
                "relationship_pubkey": rel_pub_mb,
                "relationship_key_path": str(pair_dir / "relationship.key"),
                "deploy_pub_path": str(pair_dir / "deploy.pub"),
                "deploy_priv_path": str(pair_dir / "deploy"),
            }
            (pair_dir / "pairing.json").write_text(
                json.dumps(meta, indent=2) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            # Persistence failed after the acceptance was recorded: remove
            # the half-written pair directory and the acceptance row so a
            # retry starts clean.
            shutil.rmtree(pair_dir, ignore_errors=True)
            with ctx.conn:
                ctx.conn.execute(
                    "DELETE FROM pairing_acceptances WHERE invite_id = ?",
                    (invite["invite_id"],),
                )
            raise CliError(
                "key_write_failed", f"cannot persist pairing keys: {exc}"
            )
        out = _canon_text(acceptance) + "\n"
        if args.out:
            Path(args.out).write_text(out, encoding="utf-8")
            print(f"wrote acceptance to {args.out}", file=sys.stderr)
        else:
            print(out, end="")
        print(
            f"acceptance for invite {invite['invite_id']}; "
            "hand it to the inviter, then wait for their signed commit",
            file=sys.stderr,
        )
        return 0
    finally:
        ctx.close()


def _read_json_file(path: str, what: str) -> dict:
    # G9: bounded read; acceptance/commit files are untrusted input.
    text = _read_text_capped(path, MAX_INVITE_FILE_BYTES, what)
    try:
        obj = json.loads(text)
    except ValueError as exc:
        raise CliError("bad_args", f"cannot read {what} file: {exc}")
    if not isinstance(obj, dict):
        raise CliError("bad_args", f"{what} file must contain a JSON object")
    return obj


def _infer_transport(args: argparse.Namespace, relay_url: str) -> str:
    if args.transport:
        if args.transport not in ("local", "github"):
            raise CliError("bad_args", "--transport must be local or github")
        return args.transport
    if args.local_relay_dir:
        return "local"
    if relay_url.startswith("https://github.com/") or relay_url.startswith(
        "git@github.com:"
    ):
        return "github"
    raise CliError(
        "bad_args",
        "cannot infer transport from relay URL; pass --transport local|github",
    )


def _github_token(args: argparse.Namespace) -> str:
    token = args.token or os.environ.get("MAS_GITHUB_TOKEN")
    if not token:
        raise CliError(
            "provisioning_no_token",
            "GitHub provisioning needs --token or the MAS_GITHUB_TOKEN "
            "environment variable",
        )
    return token


def _parse_github_repo(relay_url: str) -> str:
    if relay_url.startswith("https://github.com/"):
        rest = relay_url[len("https://github.com/") :]
    elif relay_url.startswith("git@github.com:"):
        rest = relay_url[len("git@github.com:") :]
    else:
        raise CliError("bad_args", f"not a GitHub relay URL: {relay_url}")
    if rest.endswith(".git"):
        rest = rest[: -len(".git")]
    owner, _, name = rest.partition("/")
    if not owner or not name or "/" in name:
        raise CliError("bad_args", f"cannot parse owner/name from {relay_url}")
    return f"{owner}/{name}"


def _write_relay_json(ctx: Ctx, deploy_keys: list, repos: list) -> None:
    path = ctx.state_dir / "relay.json"
    path.write_text(
        json.dumps({"deploy_keys": deploy_keys, "repos": repos}, indent=2) + "\n",
        encoding="utf-8",
    )


def _github_delete_deploy_key(repo: str, key_id, token: str) -> None:
    """DELETE a GitHub deploy key. Used to roll back a partially completed
    pair commit. A 404 is success (already gone: the desired end state).
    Raises ProvisioningError for other API failures."""
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/keys/{key_id}",
        method="DELETE",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "mas-cli/0.2",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30):
            return
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return
        raise ProvisioningError("api_error", f"GitHub API {exc.code}") from exc


def _github_list_deploy_keys(repo: str, token: str) -> list:
    """GET the repo's existing deploy keys. Raises ProvisioningError on API
    failure."""
    req = urllib.request.Request(
        "https://api.github.com/repos/" + repo + "/keys",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mas-cli/0.2",
        },
    )
    req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ProvisioningError("api_error", f"GitHub API {exc.code}") from exc
    if not isinstance(payload, list):
        raise ProvisioningError(
            "api_error", "unexpected deploy key list response from GitHub"
        )
    return payload


def _ssh_key_fingerprint(openssh_pub: str) -> str:
    """SHA256 fingerprint of an OpenSSH public key, in GitHub's
    ``SHA256:<base64>`` form (unpadded). Returns "" for unparseable input."""
    try:
        parts = (openssh_pub or "").split()
        if len(parts) < 2:
            return ""
        raw = base64.b64decode(parts[1])
        digest = hashlib.sha256(raw).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    except (ValueError, TypeError, binascii.Error):
        return ""


def _reset_invite_for_retry(conn, invite_id: str) -> None:
    """Return an ``accepted`` invite to ``issued`` after a failed commit.

    Only when the commit failed WITHOUT burning (state still
    ``accepted``): nothing was persisted externally (provisioned keys were
    deleted by the caller, no relationship row was committed), so the
    single-use invite is still unspent and the human can retry.
    Burned (``canceled``), expired, or committed invites are never
    touched: those states are terminal decisions, not retryable errors.

    NOTE (G8): this is only safe when the caller, not a concurrent actor,
    owns the claim. The CLI commit path now claims atomically inside
    ``commit_pairing(claim_invite=True)``, so it never calls this. It is
    retained for the legacy ``validate_invite`` + ``commit_pairing()``
    sequence, where the accepted-but-uncommitted window still exists.
    """
    from muse_agent_social.store.db import transaction

    with transaction(conn):
        row = conn.execute(
            "SELECT state FROM invites WHERE invite_id=?", (invite_id,)
        ).fetchone()
        if row is not None and row["state"] == "accepted":
            conn.execute(
                "UPDATE invites SET state='issued' WHERE invite_id=?", (invite_id,)
            )


def cmd_pair_commit(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        acceptance = _read_json_file(args.acceptance_file, "acceptance")
        try:
            validate("invite-acceptance", acceptance)
        except SchemaError as exc:
            raise CliError("pairing_error", f"acceptance schema invalid: {exc}")
        invite_id = acceptance["invite_id"]
        row = ctx.conn.execute(
            "SELECT invite_json FROM invite_bodies WHERE invite_id = ?",
            (invite_id,),
        ).fetchone()
        if row is None:
            raise CliError(
                "pairing_error", f"unknown invite {invite_id}; cannot commit"
            )
        invite = json.loads(row["invite_json"])
        inviter_fp = card_fingerprint(invite["inviter_card"])
        acceptor_fp = card_fingerprint(acceptance["acceptor_card"])
        phrase = pairing_phrase(invite["inviter_card"], acceptance["acceptor_card"])
        if not args.i_compared_phrase:
            # G6 run 1: record the displayed fingerprints WITHOUT approving.
            # Run 2 must present the same fingerprints before approval flips.
            try:
                record_displayed_phrase(
                    ctx.conn, invite_id, (inviter_fp, acceptor_fp)
                )
            except PairingError as exc:
                raise CliError("pairing_error", f"{exc.code}: {exc}")
            print(" ".join(phrase), flush=True)
            print(
                "compare all eight words with the acceptor out-of-band, then "
                "re-run with --i-compared-phrase.",
                file=sys.stderr,
            )
            raise CliError(
                "phrase_confirmation_required",
                "re-run with --i-compared-phrase after comparing the phrase",
            )
        # G5: non-consuming prevalidation BEFORE any remote mutation, so an
        # expired/canceled/tampered invite fails before a deploy key is
        # registered. The invite is claimed atomically inside commit_pairing
        # below (claim_invite=True), leaving no accepted-but-uncommitted
        # window.
        try:
            preview_invite(ctx.conn, invite)
        except PairingError as exc:
            raise CliError("pairing_error", f"{exc.code}: {exc}")
        # G6 run 2: the fingerprints must match the displayed record before
        # approval flips to true.
        try:
            confirm_verification(ctx.conn, invite_id, (inviter_fp, acceptor_fp))
        except PairingError as exc:
            raise CliError("pairing_error", f"{exc.code}: {exc}")
        requested = invite.get("requested_capabilities") or []
        acceptor_caps = set(acceptance["acceptor_card"].get("capabilities") or [])
        if args.capability:
            negotiated = list(args.capability)
        else:
            negotiated = sorted(set(requested) & acceptor_caps)
        relay_url = args.relay
        provider = _infer_transport(args, relay_url)
        slots = {
            "inviter_send_slot": secrets.token_urlsafe(16),
            "inviter_receive_slot": secrets.token_urlsafe(16),
        }
        commit_relay_url = relay_url
        local_dir = None
        if provider == "local":
            if not args.local_relay_dir:
                raise CliError(
                    "bad_args", "local transport needs --local-relay-dir"
                )
            local_dir = str(Path(args.local_relay_dir).resolve())
            Path(local_dir).mkdir(parents=True, exist_ok=True)
            # commit_pairing only accepts https:// or git@ relay URLs; the
            # signed commit's repository_url is informational for local mode
            # (the real pointer is --local-relay-dir on both sides).
            commit_relay_url = "https://local.invalid/relay"
        # Provision BEFORE committing: the deploy-key titles need the
        # relationship id, so it is minted here and handed to commit_pairing.
        # On any provisioning or local-commit failure, keys already
        # registered are deleted, the locally generated private key is
        # removed, and no relationship row is committed, so the invite can
        # be retried cleanly.
        relationship_id = None
        inviter_key_path = None
        repo = None
        token = None
        registered: list = []

        # G5: defined BEFORE the provisioning block that calls it: the
        # except-ProvisioningError handler below invokes this on failure,
        # so the def must have executed already or the call raises
        # NameError instead of cleaning up.
        def _delete_registered_keys() -> list:
            orphans = []
            if provider == "github":
                for key_id in registered:
                    if key_id:
                        try:
                            _github_delete_deploy_key(repo, key_id, token)
                        except ProvisioningError as exc:
                            # G5: never swallow; report the orphaned key id.
                            orphans.append(f"{key_id} ({exc.code})")
            return orphans

        if provider == "github":
            repo = _parse_github_repo(relay_url)
            token = _github_token(args)
            relationship_id = str(uuid.uuid4())
            key_title = deploy_key_title(relationship_id)
            # The inviter also needs git access: generate our own deploy
            # keypair, register the public half, keep the private half.
            # On retry the existing same-invite keypair is reused (the
            # public key is derived from the stored private key), so a
            # crashed first attempt never provisions a duplicate.
            inviter_key_path = (
                ctx.keys_dir / "pairing" / invite_id / "deploy-inviter"
            )
            inviter_pub = load_or_generate_deploy_keypair(str(inviter_key_path))
            peer_pub = acceptance["deploy_public_key"]
            try:
                # Register the acceptor's (peer) public deploy key.
                reg = register_peer_deploy_key(
                    repo, peer_pub, key_title, lambda: token
                )
                registered.append(reg.get("id"))
                reg_self = register_peer_deploy_key(
                    repo, inviter_pub, key_title, lambda: token
                )
                registered.append(reg_self.get("id"))
            except ProvisioningError as exc:
                orphans = _delete_registered_keys()
                if not delete_private_key(inviter_key_path):
                    orphans.append(
                        f"inviter deploy key file {inviter_key_path} "
                        "(secure deletion failed)"
                    )
                if orphans:
                    # G5: cleanup failure is LOUD, naming the repo and the
                    # orphaned key ids so the operator can delete them.
                    raise CliError(
                        "provisioning_cleanup_failed",
                        f"provisioning failed ({exc.code}: {exc}); rollback of "
                        f"provisioned keys on {repo} also failed; orphaned key "
                        f"id(s): {', '.join(orphans)}; delete them manually",
                    )
                raise CliError("provisioning_error", f"{exc.code}: {exc}")
        def _cleanup_provisioned() -> list:
            orphans = _delete_registered_keys()
            if inviter_key_path is not None:
                if not delete_private_key(inviter_key_path):
                    orphans.append(
                        f"inviter deploy key file {inviter_key_path} "
                        "(secure deletion failed)"
                    )
            return orphans

        try:
            # G8: claim (issued -> accepted) and commit happen in ONE
            # transaction inside commit_pairing. On any failure the claim
            # rolls back with the commit, so the invite stays 'issued' and
            # no reset is needed (there is no accepted-but-uncommitted
            # window to race in).
            commit = commit_pairing(
                ctx.conn,
                acceptance,
                ctx.hierarchy.ed25519_private,
                commit_relay_url,
                slots,
                negotiated,
                keys_dir=ctx.keys_dir,
                relationship_id=relationship_id,
                claim_invite=True,
            )
        except PairingError as exc:
            orphans = _cleanup_provisioned()
            if orphans:
                raise CliError(
                    "provisioning_cleanup_failed",
                    f"commit failed ({exc.code}: {exc}); cleanup of provisioned "
                    f"keys on {repo} also failed; orphaned key id(s): "
                    f"{', '.join(orphans)}; delete them manually",
                )
            raise CliError("pairing_error", f"{exc.code}: {exc}")
        except Exception as exc:
            # commit_pairing can also fail outside PairingError (storage
            # I/O, key-file errors). Same cleanup semantics.
            orphans = _cleanup_provisioned()
            if orphans:
                raise CliError(
                    "provisioning_cleanup_failed",
                    f"commit failed (commit_failed: {type(exc).__name__}: {exc}); "
                    f"cleanup of provisioned keys on {repo} also failed; "
                    f"orphaned key id(s): {', '.join(orphans)}; "
                    "delete them manually",
                )
            raise CliError(
                "pairing_error", f"commit_failed: {type(exc).__name__}: {exc}"
            )
        relationship_id = commit["relationship_id"]
        deploy_keys: list = []
        repos: list = []
        ssh_key_path: Optional[str] = None
        if provider == "github":
            deploy_keys.append(
                {
                    "id": registered[0],
                    "title": key_title,
                    "key": peer_pub,
                    "role": "peer",
                }
            )
            deploy_keys.append(
                {
                    "id": registered[1],
                    "title": key_title,
                    "key": inviter_pub,
                    "role": "self",
                }
            )
            ssh_key_path = str(inviter_key_path)
            repos.append({"repo": repo, "transport": "github"})
        _write_relay_json(ctx, deploy_keys, repos)
        _save_relay_config(
            ctx, relationship_id, provider, relay_url, slots, local_dir,
            role="inviter",
            ssh_key_path=ssh_key_path,
        )
        eph_path = ctx.keys_dir / "invites" / invite_id / "ephemeral.key"
        try:
            eph_path.unlink()
        except FileNotFoundError:
            pass
        out = _canon_text(commit) + "\n"
        if args.out:
            Path(args.out).write_text(out, encoding="utf-8")
            print(f"wrote commit to {args.out}", file=sys.stderr)
        else:
            print(out, end="")
        print(
            f"committed relationship {relationship_id}; hand the commit to the "
            "acceptor, then run: mas send --relationship "
            f"{relationship_id} --type relationship.ready",
            file=sys.stderr,
        )
        return 0
    finally:
        ctx.close()


def cmd_pair_ingest(args: argparse.Namespace) -> int:
    """Acceptor side: persist the inviter's signed commit."""
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        commit = _read_json_file(args.commit_file, "commit")
        for field in (
            "commit_version",
            "relationship_id",
            "invite_id",
            "repository_url",
            "slots",
            "negotiated_capabilities",
            "initial_key_epochs",
            "signature",
        ):
            if field not in commit:
                raise CliError("pairing_error", f"commit missing field {field!r}")
        invite_id = commit["invite_id"]
        row = ctx.conn.execute(
            "SELECT invite_json, acceptance_json FROM pairing_acceptances "
            "WHERE invite_id = ?",
            (invite_id,),
        ).fetchone()
        if row is None:
            raise CliError(
                "pairing_error",
                f"no acceptance for invite {invite_id}; run 'mas pair accept' first",
            )
        invite = json.loads(row["invite_json"])
        meta_path = ctx.keys_dir / "pairing" / invite_id / "pairing.json"
        if not meta_path.exists():
            raise CliError(
                "pairing_error",
                f"pairing key material missing for invite {invite_id}",
            )
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        relay_url = commit["repository_url"]
        provider = _infer_transport(args, relay_url)
        local_dir = None
        if provider == "local":
            if not args.local_relay_dir:
                raise CliError(
                    "bad_args", "local transport needs --local-relay-dir"
                )
            local_dir = str(Path(args.local_relay_dir).resolve())
            Path(local_dir).mkdir(parents=True, exist_ok=True)
        try:
            rid = ingest_commit(
                ctx.conn,
                commit,
                invite,
                own_agreement_pubkey=meta["relationship_pubkey"],
                own_private_key_ref=meta["relationship_key_path"],
                local_card=ctx.card,
            )
        except PairingError as exc:
            raise CliError("pairing_error", f"{exc.code}: {exc}")
        deploy_keys: list = []
        repos: list = []
        if provider == "github":
            repo = _parse_github_repo(relay_url)
            token = _github_token(args)
            deploy_pub = Path(meta["deploy_pub_path"]).read_text(
                encoding="utf-8"
            ).strip()
            try:
                reg = register_peer_deploy_key(
                    repo, deploy_pub, deploy_key_title(rid), lambda: token
                )
            except ProvisioningError as exc:
                # Idempotent only when the SAME key is already registered:
                # fetch the repo's existing deploy keys and compare the
                # attempted key's SHA256 fingerprint. A different key in use
                # (or any other rejection) fails loudly instead of being
                # swallowed as success.
                if exc.code == "key_rejected" and "already in use" in str(exc):
                    existing = _github_list_deploy_keys(repo, token)
                    want_fp = _ssh_key_fingerprint(deploy_pub)
                    match = next(
                        (
                            entry
                            for entry in existing
                            if isinstance(entry, dict)
                            and _ssh_key_fingerprint(entry.get("key", ""))
                            == want_fp
                        ),
                        None,
                    )
                    if match is None:
                        raise CliError(
                            "provisioning_error",
                            "GitHub reports the deploy key is already in use "
                            "but no existing deploy key matches its "
                            "fingerprint; refusing to treat this as success",
                        )
                    reg = {
                        "id": match.get("id"),
                        "title": match.get("title")
                        or deploy_key_title(rid),
                    }
                else:
                    raise CliError("provisioning_error", f"{exc.code}: {exc}")
            deploy_keys.append(
                {
                    "id": reg.get("id"),
                    "title": deploy_key_title(rid),
                    "key": deploy_pub,
                    "role": "self",
                }
            )
            repos.append({"repo": repo, "transport": "github"})
        _write_relay_json(ctx, deploy_keys, repos)
        _save_relay_config(
            ctx, rid, provider, relay_url, commit["slots"], local_dir,
            role="acceptor",
            ssh_key_path=meta["deploy_priv_path"],
        )
        print(rid)
        print(
            f"ingested relationship {rid}; exchange relationship.ready next: "
            f"mas send --relationship {rid} --type relationship.ready",
            file=sys.stderr,
        )
        return 0
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# mas send
# ---------------------------------------------------------------------------

_SEND_TYPES = sorted(PAYLOAD_DISPATCH.keys())
_LEGACY_SEND_TYPES = ("note", "link", "article", "file-ref", "file")


def _iso_now() -> str:
    return utcnow()


def _poll_answer(choice_ids) -> str:
    """Unambiguous encoding of a poll response's choice list for approvals.

    Comma-joining is ambiguous: ["a,b", "c"] and ["a", "b,c"] both encode
    to "a,b,c", so one approval record could authorize a different choice
    set than the human confirmed. Canonical JSON of the list is injective.
    """
    return restricted_jcs(list(choice_ids)).decode("utf-8")


def _require_approval_record(
    ctx: "Ctx",
    args: argparse.Namespace,
    *,
    subject_type: str,
    subject_id: str,
    answer: str,
    approved: bool,
) -> str:
    """Verify the --approval-record references a real local human-approval
    record matching this send. Returns the approval ID for the payload.

    Approval records are single-use and expire after
    APPROVAL_TTL_SECONDS. This function only VALIDATES the record
    (existence, relationship/subject/answer match, unconsumed,
    unexpired). The atomic single-use claim happens inside the send's
    persistence transaction (see persist_outgoing_in_txn): a failed send
    rolls the claim back, so a human approval is never burned without
    authorizing a durably persisted event. Dry runs validate the record
    without consuming it and without any other side effect.
    """
    from muse_agent_social.model.approvals import get_approval
    from muse_agent_social.store.db import utcnow

    dry_run = bool(getattr(args, "dry_run", False))
    rid = args._relationship_id
    if dry_run and args.approval_record == "dry_run":
        # cmd_human_respond --dry-run: validate-only, no record was created.
        return "dry_run"
    record = get_approval(ctx.conn, args.approval_record)
    if record is None:
        raise CliError(
            "unknown_approval_record",
            "no local human-approval record with that ID; the human must "
            "respond with `mas human respond` first",
        )
    if record["relationship_id"] != rid:
        raise CliError(
            "approval_record_mismatch",
            "approval record belongs to a different relationship",
        )
    if record["subject_type"] != subject_type or record["subject_id"] != subject_id:
        raise CliError(
            "approval_record_mismatch",
            "approval record does not match this request",
        )
    if record["answer"] != answer or bool(record["approved"]) != approved:
        raise CliError(
            "approval_record_mismatch",
            "approval record answer/approved does not match this send",
        )
    now = utcnow()
    if record["consumed_at"] is not None:
        raise CliError(
            "approval_consumed",
            "approval record was already used for a previous send;"
            " the human must respond again",
        )
    if record["expires_at"] is not None and record["expires_at"] <= now:
        raise CliError(
            "approval_expired",
            "approval record has expired; the human must respond again",
        )
    # NOTE: no consumption here. The claim is atomic with event
    # persistence inside _send_event -> persist_outgoing_in_txn, so a
    # send that fails after this validation leaves the approval live.
    return record["approval_id"]


def _attachment_from_file(path: str) -> dict:
    """Read a local file into a message.created attachment dict.

    Enforces the v0.2 attachment contract: at most MAX_ATTACHMENT_BYTES
    decoded bytes, bare filename (no directories), MIME type guessed from
    the name. Raises CliError on missing file, oversize, or unreadable.
    """
    import base64
    import hashlib
    import mimetypes
    import os

    from muse_agent_social.validation import MAX_ATTACHMENT_BYTES

    if not os.path.isfile(path):
        raise CliError("bad_args", f"--file not found: {path}")
    size = os.path.getsize(path)
    if size > MAX_ATTACHMENT_BYTES:
        raise CliError(
            "bad_args",
            f"--file too large: {size} bytes (max {MAX_ATTACHMENT_BYTES})",
        )
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise CliError("bad_args", f"--file unreadable: {exc}")
    if len(raw) != size or len(raw) > MAX_ATTACHMENT_BYTES:
        raise CliError("bad_args", "--file changed size during read; retry")
    filename = os.path.basename(path)
    if not filename or filename in (".", ".."):
        raise CliError("bad_args", "--file needs a real filename")
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return {
        "filename": filename,
        "size": len(raw),
        "content_type": content_type,
        "data": base64.b64encode(raw).decode("ascii"),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _build_payload(ctx: "Ctx", args: argparse.Namespace) -> dict:
    """Build and schema-validate the typed payload for ``mas send``.

    For ``human.responded`` and human-confirmed ``poll.responded``, the
    plan requires a local human-approval record ID, never a bare sender
    assertion. The record must already exist (created by the human-facing
    ``mas human respond`` command); this function verifies it and embeds
    its ID in the payload.
    """
    t = args.type
    if t == "message.created":
        attachment = _attachment_from_file(args.file) if args.file else None
        body = args.body or args.title or ""
        if not body.strip() and attachment is None:
            raise CliError("bad_args", "message.created needs --body")
        if attachment is not None and not body.strip():
            body = "File: %s" % attachment["filename"]
        payload = {
            "body": body,
            "format": args.format or "plain",
        }
        if attachment is not None:
            payload["attachment"] = attachment
    elif t == "message.edited":
        if not args.target or not args.body:
            raise CliError("bad_args", "message.edited needs --target and --body")
        payload = {
            "target_event_id": args.target,
            "body": args.body,
            "reason": args.reason,
        }
    elif t == "message.retracted":
        if not args.target:
            raise CliError("bad_args", "message.retracted needs --target")
        payload = {"target_event_id": args.target, "reason": args.reason}
    elif t == "reaction.added":
        if not args.target or not args.emoji:
            raise CliError("bad_args", "reaction.added needs --target and --emoji")
        payload = {"target_event_id": args.target, "emoji": args.emoji}
    elif t == "reaction.removed":
        if not args.target or not args.emoji:
            raise CliError("bad_args", "reaction.removed needs --target and --emoji")
        payload = {"target_event_id": args.target, "emoji": args.emoji}
    elif t == "receipt.accepted":
        if not args.target:
            raise CliError("bad_args", "receipt.accepted needs --target")
        payload = {
            "target_event_id": args.target,
            "accepted_at": args.accepted_at or _iso_now(),
        }
    elif t == "receipt.seen":
        if not args.target:
            raise CliError("bad_args", "receipt.seen needs --target")
        # The policy gate is live on the send path: seen receipts are
        # opt-in per relationship (receiver-owned policy, default off).
        # Invoking this command is the operator's human-visible assertion
        # that the target event was seen; the remaining branches (policy
        # enabled, event committed locally) are enforced here.
        relationship_id = getattr(args, "_relationship_id", None)
        if not should_send_seen_receipt(
            ctx.conn,
            relationship_id,
            args.target,
            human_visible_view_opened=True,
        ):
            raise CliError(
                "seen_receipt_not_permitted",
                "receipt.seen refused by delivery policy: enable seen "
                "receipts for this relationship and target a locally "
                "committed event",
            )
        payload = {
            "target_event_id": args.target,
            "seen_at": args.seen_at or _iso_now(),
        }
    elif t == "poll.created":
        if not args.question or not args.choices:
            raise CliError("bad_args", "poll.created needs --question and --choices")
        payload = {
            "question": args.question,
            "choices": list(args.choices),
            "closes_at": args.closes_at or _iso_now(),
            "multi_select": bool(args.multi_select),
        }
    elif t == "poll.responded":
        if not args.poll_id or not args.choice_ids:
            raise CliError("bad_args", "poll.responded needs --poll-id and --choice-ids")
        payload = {
            "poll_id": args.poll_id,
            "choice_ids": list(args.choice_ids),
            "human_confirmed": bool(args.human_confirmed),
        }
        if args.human_confirmed:
            payload["approval_record_id"] = _require_approval_record(
                ctx,
                args,
                subject_type="poll",
                subject_id=args.poll_id,
                answer=_poll_answer(args.choice_ids),
                approved=True,
            )
    elif t == "task.created":
        if not args.title:
            raise CliError("bad_args", "task.created needs --title")
        payload = {
            "title": args.title,
            "owner_identity": args.owner or "",
            "due_at": args.due_at,
        }
        if not payload["owner_identity"]:
            del payload["owner_identity"]
        if payload["due_at"] is None:
            del payload["due_at"]
    elif t == "task.updated":
        if not args.task_id or not args.status:
            raise CliError("bad_args", "task.updated needs --task-id and --status")
        payload = {
            "task_id": args.task_id,
            "status": args.status,
            "note": args.note,
        }
        if payload["note"] is None:
            del payload["note"]
    elif t == "human.requested":
        if not args.prompt:
            raise CliError("bad_args", "human.requested needs --prompt")
        payload = {
            "prompt": args.prompt,
            "response_shape": args.response_shape or "text",
            "expires_at": args.expires_at or _iso_now(),
        }
    elif t == "human.responded":
        if not args.request_id or args.answer is None:
            raise CliError("bad_args", "human.responded needs --request-id and --answer")
        if not args.approval_record:
            raise CliError(
                "bad_args",
                "human.responded needs --approval-record (create one with "
                "`mas human respond`; the CLI invocation itself is the "
                "human's approval)",
            )
        approval_id = _require_approval_record(
            ctx,
            args,
            subject_type="human_request",
            subject_id=args.request_id,
            answer=args.answer,
            approved=bool(args.approved),
        )
        payload = {
            "request_id": args.request_id,
            "answer": args.answer,
            "approved": bool(args.approved),
            "approval_record_id": approval_id,
        }
    elif t == "delivery.scheduled":
        if not args.inner_event_id or not args.deliver_at:
            raise CliError(
                "bad_args", "delivery.scheduled needs --inner-event-id and --deliver-at"
            )
        payload = {
            "inner_event_id": args.inner_event_id,
            "deliver_at": args.deliver_at,
        }
    elif t == "delivery.canceled":
        if not args.scheduled_event_id:
            raise CliError("bad_args", "delivery.canceled needs --scheduled-event-id")
        payload = {
            "scheduled_event_id": args.scheduled_event_id,
            "canceled_at": args.canceled_at or _iso_now(),
        }
    elif t == "relationship.ready":
        payload = {"relationship_id": args._relationship_id}
    elif t == "migration.ready":
        if not args.migration_id:
            raise CliError("bad_args", "migration.ready needs --migration-id")
        payload = {"migration_id": args.migration_id}
    elif t == "migration.commit":
        if not args.migration_id:
            raise CliError("bad_args", "migration.commit needs --migration-id")
        payload = {"migration_id": args.migration_id}
    elif t == "security.key.prepare":
        if not args.new_agreement_key or not args.prior_fingerprint or not args.deadline:
            raise CliError(
                "bad_args",
                "security.key.prepare needs --new-agreement-key, "
                "--prior-fingerprint and --deadline",
            )
        payload = {
            "new_agreement_key": args.new_agreement_key,
            "prior_fingerprint": args.prior_fingerprint,
            "deadline": args.deadline,
        }
    elif t == "security.key.ack":
        if not args.prepare_event_id or args.epoch is None:
            raise CliError(
                "bad_args", "security.key.ack needs --prepare-event-id and --epoch"
            )
        payload = {"prepare_event_id": args.prepare_event_id, "epoch": args.epoch}
    elif t == "security.key.confirm":
        if args.epoch is None:
            raise CliError("bad_args", "security.key.confirm needs --epoch")
        payload = {"epoch": args.epoch}
    elif t == "security.key.commit":
        if args.epoch is None:
            raise CliError("bad_args", "security.key.commit needs --epoch")
        payload = {"epoch": args.epoch}
    else:
        raise CliError("bad_args", f"unsupported event type {t!r}")
    try:
        validate_payload(t, payload)
    except SchemaError as exc:
        raise CliError("bad_args", f"payload invalid for {t}: {exc}")
    return payload


def _legacy_payload(args: argparse.Namespace) -> tuple[str, dict]:
    """Map the legacy bin/send.py surface onto message.created."""
    t = args.type
    title = args.title or ""
    body = args.body or ""
    url = args.url or ""
    if t == "note":
        text = body or title
    elif t == "link":
        text = "\n\n".join(p for p in (title, url, body) if p)
    elif t == "article":
        text = "\n\n".join(p for p in (title, body) if p)
        if url:
            text += f"\n\n{url}"
    elif t == "file":
        if not args.file:
            raise CliError("bad_args", "legacy type file needs --file <path>")
        attachment = _attachment_from_file(args.file)
        text = body or title or "File: %s" % attachment["filename"]
        payload = {"body": text, "format": "plain", "attachment": attachment}
    else:  # file-ref
        text = "\n\n".join(p for p in (title, url, body) if p)
        if not text.strip():
            raise CliError("bad_args", f"legacy type {t} needs --title/--body/--url")
        payload = {"body": text, "format": "plain"}
    validate_payload("message.created", payload)
    return "message.created", payload


def _recipients_for(
    ctx: Ctx, rel: dict, manager: RotationManager, peer_identity_id: str
) -> tuple[list[dict], int]:
    """Build seal recipients honoring the rotation dual-wrap window."""
    rid = rel["relationship_id"]
    try:
        dual = manager.dual_wrap_keys(rid)
    except RotationError as exc:
        if exc.code != "no_acknowledged_rotation":
            raise
        dual = None
    if dual is not None:
        epochs = sorted(dual)
        key_epoch = max(epochs)
        pubs = [dual[e] for e in epochs]
    else:
        key_epoch = int(rel["key_epoch"])
        peer_key = rel["peer_agreement_key"]
        if not peer_key:
            raise CliError("send_error", f"no peer agreement key on {rid}")
        pubs = [peer_key]
    recipients = []
    for pub in pubs:
        raw = parse_agreement_key(pub)  # raw 32-byte X25519 material
        recipients.append(
            {
                "recipient": peer_identity_id,
                "agreement_key": pub,
                "relationship_pub": raw,
            }
        )
    return recipients, key_epoch


def _release_fn(ctx: Ctx):
    """Build the scheduler release_fn for this installation.

    The claim (scheduled -> released) and the relay enqueue commit in one
    SQLite transaction. The function is idempotent on scheduled_id: a
    repeated call after a rollback returns the already-chosen object
    name without queueing a second mutation.
    """

    def release_fn(conn, *, scheduled_id, sealed_event_envelope, late_by_seconds):
        row = conn.execute(
            "SELECT relationship_id FROM events WHERE event_id = ?",
            (scheduled_id,),
        ).fetchone()
        if row is None:
            return None
        rid = row["relationship_id"]
        # S1: honor revocation inside the release transaction. Teardown
        # marks consent_state='revoked' in step 1 but deletes scheduler
        # rows in step 4; a concurrent run_due in between must not
        # transmit. Refusing here rolls the scheduled -> released claim
        # back, so the row stays scheduled (teardown deletes it).
        consent = conn.execute(
            "SELECT consent_state FROM relationships WHERE relationship_id = ?",
            (rid,),
        ).fetchone()
        if consent is None or consent["consent_state"] == "revoked":
            raise scheduler.RevokedRelationshipError(scheduled_id)
        # S2: honor the acking-side rotation deadline pause. _send_event
        # gates immediate sends on may_send(); the release path must too,
        # or a pre-deadline-persisted message transmits post-deadline. The
        # pause is transient, so it never counts toward dead-lettering.
        try:
            RotationManager(ctx.conn, ctx.keys_dir).may_send(rid)
        except RotationError as exc:
            raise scheduler.SendPausedError(
                scheduled_id, f"{exc.code}: {exc}"
            ) from exc
        seen = conn.execute(
            "SELECT object_name FROM sent_objects WHERE scheduled_id = ?",
            (scheduled_id,),
        ).fetchone()
        if seen is not None:
            return seen["object_name"]
        transport = _transport_for(ctx, rid, "send")
        name = new_object_name()
        sealed = sealed_event_envelope
        if isinstance(sealed, str):
            sealed = sealed.encode("utf-8")
        if isinstance(transport, LocalTransport):
            # Immediate local upload inside the scheduler transaction,
            # before the scheduled -> released claim commits. Ordering
            # note: the peer can fetch this object before this sender's
            # commit lands, and a crash between upload and commit rolls
            # the row back to scheduled, so the next run_due uploads the
            # same sealed bytes under a NEW object name (sent_objects was
            # rolled back too). The peer then sees two relay objects for
            # one event. This is contained, not just tolerated: the
            # receiver checks replay_guard for the replay_nonce (and the
            # event_id with identical bytes) before inserting, so the
            # duplicate is accepted-but-not-surfaced and the event is
            # persisted exactly once. The bytes are immutable once
            # sealed, so early visibility cannot corrupt receiver state.
            transport.upload(name, sealed)
        else:
            queue_mutation(
                conn, _transport_scope(rid, "send"), "upload", name, sealed
            )
        conn.execute(
            "INSERT OR IGNORE INTO sent_objects(scheduled_id, object_name,"
            " queued_at) VALUES (?, ?, ?)",
            (scheduled_id, name, utcnow()),
        )
        return name

    return release_fn


def _flush_send_transports(ctx: Ctx, relationship_ids) -> None:
    """Best-effort push of queued send-direction mutations.

    Failures leave the mutations queued; the next receive run flushes
    them. A push failure here does not fail the send, because the event
    is durably persisted and queued.
    """
    for rid in sorted(set(relationship_ids)):
        try:
            transport = _transport_for(ctx, rid, "send")
        except CliError:
            continue
        if isinstance(transport, GitHubTransport):
            try:
                transport.flush()
            except TransportError as exc:
                print(
                    f"warning: relay push deferred for {rid} ({exc.code}); "
                    "the event is queued and will push on the next receive",
                    file=sys.stderr,
                )


def _warn_overdue_scheduled(ctx: Ctx) -> None:
    """Warn when scheduled rows are past deliver_at and still undelivered.

    Medium 2a: run_due only fires on `mas send` / `mas receive`, so an
    idle install silently misses deliver_at. Every CLI invocation that
    can release rows warns loudly about overdue rows before releasing
    them, so the delay is visible instead of silent.
    """
    try:
        overdue = ctx.conn.execute(
            "SELECT COUNT(*) FROM scheduler_queue "
            "WHERE state = 'scheduled' AND deliver_at < ?",
            (utcnow(),),
        ).fetchone()[0]
    except Exception:
        return
    if overdue:
        print(
            f"warning: {overdue} scheduled event(s) are past deliver_at "
            "and still undelivered (this install only releases on "
            "send/receive); releasing them now, possibly late",
            file=sys.stderr,
        )


def _warn_expired_by_run_due(due: dict) -> None:
    """Warn about rows run_due just marked expired (S11).

    A clock jump (or a long-idle install) can push deliver_at rows past
    expires_at: run_due transitions them scheduled -> expired, so the
    pre-release overdue warning never sees them. The operator must know
    these events will never deliver.
    """
    expired = due.get("expired", [])
    if expired:
        shown = ", ".join(expired[:5])
        more = ", ..." if len(expired) > 5 else ""
        print(
            f"warning: {len(expired)} scheduled event(s) expired without "
            f"delivery ({shown}{more}); they will never be sent",
            file=sys.stderr,
        )


def _sweep_rotations(ctx: Ctx) -> None:
    """Run rotation maintenance: discard ack-less candidates past their
    deadline and retire old private keys after the 24h/100-event bound.

    Lost-ack semantics: sweep() discards a candidate whose ack never
    arrived once its 24h deadline passes and raises NoAckTimeout to alert
    the operator. The wedge clears itself: a later begin_rotation()
    succeeds because the stale candidate is gone (superseding), and the
    old key is retired on the normal 24h/100-event schedule. The warning
    is loud but never fails the poll or the send.
    """
    manager = RotationManager(ctx.conn, ctx.keys_dir)
    try:
        manager.sweep()
    except NoAckTimeout as exc:
        print(
            f"warning: rotation ack timeout ({exc.code}): {exc}; stale "
            "candidate discarded, a new rotation may now begin",
            file=sys.stderr,
        )


def _validate_delivery_window(
    deliver_at: Optional[str],
    expires_at: Optional[str],
    *,
    now: str,
) -> None:
    """Schedule-time delivery-window validation (S3/S4/S5). Loud failures.

    S3: deliver_at beyond the old-key retention horizon (24h) is refused.
        Sealed bytes are bound to the current key epoch; the recipient
        deletes the old private key 24h after a rotation commit (or after
        100 accepted events), after which a later-released capsule is
        undecryptable while the sender sees success. (The 100-event bound
        cannot be scheduled around; it is a documented residual risk.)
    S4: deliver_at beyond the receiver accept window (7 days) is refused.
        created_at is the schedule time and the receiver quarantines
        created_at older than the window, so a far-future capsule would
        release on time and then be quarantined.
    S5: expires_at must be after the effective deliver_at (deliver_at, or
        now for immediate sends); otherwise the row is stillborn: the
        first run_due marks it expired and it never releases.

    Raises:
        CliError: on any violation, or on a malformed timestamp.
    """
    try:
        now_dt = parse_canonical_utc(now)
        if deliver_at is not None:
            deliver_dt = parse_canonical_utc(deliver_at)
            # S3/S4: the effective horizon is the earlier of the old-key
            # retention bound and the receiver accept window. Whichever
            # binds, a schedule past it is refused loudly instead of
            # silently queued for a doomed delivery.
            horizons = (
                (
                    now_dt + OLD_KEY_RETENTION,
                    "deliver_at_beyond_retention_horizon",
                    "sealed bytes are bound to the current key epoch and "
                    "the recipient deletes the old private key "
                    f"{int(OLD_KEY_RETENTION.total_seconds() // 3600)}h "
                    "after a rotation commit (or after 100 accepted "
                    "events), which would make the released capsule "
                    "undecryptable",
                ),
                (
                    now_dt + timedelta(days=ACCEPT_WINDOW_DAYS),
                    "deliver_at_beyond_accept_window",
                    "the receiver quarantines events older than the "
                    f"{ACCEPT_WINDOW_DAYS}d accept window",
                ),
            )
            horizon_dt, code, reason = min(horizons, key=lambda h: h[0])
            if deliver_dt > horizon_dt:
                raise CliError(
                    code,
                    f"deliver_at={deliver_at} is beyond the delivery "
                    f"horizon: {reason}",
                )
        if expires_at is not None:
            effective_deliver = deliver_at if deliver_at is not None else now
            if parse_canonical_utc(expires_at) <= parse_canonical_utc(
                effective_deliver
            ):
                raise CliError(
                    "expires_not_after_deliver_at",
                    f"expires_at={expires_at} is not after deliver_at="
                    f"{effective_deliver}; the row would expire before "
                    "release",
                )
    except CliError:
        raise
    except (ValueError, TypeError) as exc:
        raise CliError(
            "bad_args", f"bad delivery timestamp: {exc}"
        ) from exc


def _semantic_dry_run(
    ctx: Ctx,
    protected: dict,
    event_type: str,
    payload: dict,
    reply_to: Optional[str],
) -> None:
    """Dry-run the local projection inside a rolled-back SAVEPOINT (S9).

    Runs record_projection_input + apply_event for the about-to-persist
    event and always rolls the SAVEPOINT back, so a semantically invalid
    event (poll_unknown_choice, poll_closed, retract_not_sender, ...) is
    rejected BEFORE anything is persisted or any human approval is
    consumed. The real projection after persist is authoritative; this is
    the pre-claim gate that keeps a failed projection from burning an
    approval and inviting a duplicate retry.

    Raises:
        CliError: when the event would fail semantic projection.
    """
    conn = ctx.conn
    conn.execute("SAVEPOINT send_semantic_dry_run")
    # The staged payload row references the not-yet-persisted events row,
    # so FK enforcement must be deferred inside the dry run. The savepoint
    # always rolls back, so the deferred checks never fire; without this,
    # every dry run fails with a spurious FOREIGN KEY constraint error.
    defer_before = conn.execute("PRAGMA defer_foreign_keys;").fetchone()[0]
    conn.execute("PRAGMA defer_foreign_keys=ON;")
    try:
        record_projection_input(
            conn,
            event_id=protected["event_id"],
            event_type=event_type,
            payload=payload,
            reply_to=reply_to,
        )
        dry_row = {
            "event_id": protected["event_id"],
            "relationship_id": protected["relationship_id"],
            "conversation_id": protected["conversation_id"],
            "thread_id": protected.get("thread_id"),
            "sender": protected["sender"],
            "sender_seq": 0,
            "created_at": protected["created_at"],
            "key_epoch": protected.get("key_epoch"),
            "event_type": event_type,
            "payload": payload,
            "reply_to": reply_to,
        }
        apply_event(conn, dry_row)
    except Exception as exc:
        code = getattr(exc, "code", "semantic_rejected")
        raise CliError(
            "send_error",
            f"semantic validation failed before persist ({code}): {exc}; "
            "nothing was persisted and no approval was consumed",
        ) from exc
    finally:
        # Always roll back: the dry run must leave no trace. The real
        # projection runs after persist.
        conn.execute("ROLLBACK TO SAVEPOINT send_semantic_dry_run")
        conn.execute("RELEASE send_semantic_dry_run")
        conn.execute(f"PRAGMA defer_foreign_keys={int(defer_before)};")


def _send_event(
    ctx: Ctx,
    rel: dict,
    event_type: str,
    payload: dict,
    *,
    conversation_id: Optional[str] = None,
    thread_id: Optional[str] = None,
    reply_to: Optional[str] = None,
    deliver_at: Optional[str] = None,
    expires_at: Optional[str] = None,
    dry_run: bool = False,
    clock_skew_seconds: Optional[float] = None,
) -> dict:
    """Persist, seal, and enqueue one outgoing event.

    Returns a summary dict with event_id, sender_seq, key_epoch and, when
    the event was released to the transport immediately, object_name.
    """
    rid = rel["relationship_id"]
    manager = RotationManager(ctx.conn, ctx.keys_dir)
    try:
        manager.may_send(rid)
    except RotationError as exc:
        raise CliError("send_error", f"{exc.code}: {exc}")
    # S3/S4/S5: schedule-time delivery-window validation, loud. A
    # stillborn or undecryptable schedule is refused here, before the
    # event is built, never silently queued.
    _validate_delivery_window(deliver_at, expires_at, now=utcnow())
    cid = conversation_id or rid
    if reply_to and thread_id is None:
        target = ctx.conn.execute(
            "SELECT conversation_id, thread_id FROM events WHERE event_id = ? "
            "AND relationship_id = ?",
            (reply_to, rid),
        ).fetchone()
        if target is None:
            raise CliError("bad_args", f"reply target {reply_to} not found")
        cid = target["conversation_id"]
        thread_id = target["thread_id"]
    recipients, key_epoch = _recipients_for(ctx, rel, manager, rel["peer_identity_id"])
    try:
        protected = build_protected(
            relationship_id=rid,
            conversation_id=cid,
            sender_id=ctx.identity_id,
            event_type=event_type,
            thread_id=thread_id or new_thread_id(),
            reply_to=reply_to,
            key_epoch=key_epoch,
            deliver_at=deliver_at,
            expires_at=expires_at,
        )
    except (SchemaError, ValueError) as exc:
        raise CliError("send_error", f"cannot build event: {exc}")
    if thread_id is None:
        # New thread: the first message's event id is the thread id.
        protected["event_id"] = protected["thread_id"]
        thread_id = protected["thread_id"]
    if reply_to:
        try:
            validate_reply(ctx.conn, reply_to, thread_id, cid)
        except EventStoreError as exc:
            raise CliError("bad_args", f"invalid reply: {exc.code}: {exc}")
    if dry_run:
        return {
            "event_id": protected["event_id"],
            "sender_seq": None,
            "key_epoch": key_epoch,
            "dry_run": True,
            "payload": payload,
        }
    # S9: semantic dry-run BEFORE claiming the approval. A semantically
    # invalid event is rejected here, before anything is persisted or any
    # approval consumed, so the operator never retries with a fresh
    # approval and duplicates the response.
    _semantic_dry_run(ctx, protected, event_type, payload, reply_to)
    try:
        # The human-approval claim is atomic with event persistence: the
        # record ID travels in the payload for the approval-gated types,
        # and persist_outgoing_in_txn claims it inside the same
        # transaction that inserts the event. A failed send rolls the
        # claim back instead of burning the human's approval.
        approval_id = (
            payload.get("approval_record_id")
            if event_type in ("human.responded", "poll.responded")
            else None
        )
        sealed = assign_and_persist_outgoing(
            ctx.conn,
            protected,
            payload,
            ctx.hierarchy.ed25519_private,
            recipients,
            approval_id=approval_id,
        )
    except Exception as exc:
        raise CliError("send_error", f"persist failed: {exc}")
    # The projection input was staged atomically with persistence inside
    # persist_outgoing_in_txn, so rebuild_projections never sees a staged
    # event without its payload. Project the sender's own event locally so
    # both sides' projections converge; the sender needs no surface
    # decision for their own event.
    #
    # S9: the semantic dry-run above already passed, so an apply_event
    # failure here means a race (state changed between dry-run and
    # persist) or an infrastructure failure. The event IS persisted and
    # queued for release and the approval IS consumed, so the failure is
    # reported with a distinct code and an explicit do-not-resend warning:
    # a blind retry with a fresh approval would duplicate the event.
    try:
        event_row = dict(
            ctx.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (protected["event_id"],)
            ).fetchone()
        )
        event_row["payload"] = payload
        event_row["reply_to"] = reply_to
        # Atomic per-event projection: a crash mid-apply must roll back the
        # whole event, never leave half-applied markers that redelivery
        # would then treat as "already done". G15: the projection_queue
        # row is acknowledged (deleted) in the same transaction, so a
        # successful projection never leaves a row behind.
        with transaction(ctx.conn):
            apply_event(ctx.conn, event_row)
            ctx.conn.execute(
                "DELETE FROM projection_queue WHERE event_id = ?;",
                (protected["event_id"],),
            )
    except ProjectionError as exc:
        raise CliError(
            "send_projection_failed",
            f"projection failed AFTER persist ({exc.code}: {exc}); event "
            f"{protected['event_id']} is persisted and queued for release "
            "and the approval was consumed: do NOT re-send (that would "
            "duplicate the event); inspect and repair local projections",
        )
    released: list[str] = []
    cancel_outcome: Optional[str] = None
    if event_type == "delivery.canceled":
        # H7: cancel-before-release. The cancel must win if it arrives
        # before deliver_at, so the cancellation is claimed BEFORE
        # run_due() can release the row. Previously run_due ran first: a
        # cancel racing a due release delivered the event while the CLI
        # still reported success.
        try:
            scheduler.cancel(ctx.conn, payload["scheduled_event_id"])
            cancel_outcome = "canceled"
        except scheduler.SchedulerError as exc:
            # already_released -> a signed retraction request is emitted
            # below (S10); unknown ids are reported honestly but do not
            # fail the send.
            cancel_outcome = exc.code
    if cancel_outcome == "already_released":
        # S10: the cancel arrived too late, but the sender asked for the
        # message back. Emit a real signed message.retracted event. The
        # retraction targets the INNER message (the capsule payload the
        # peer already holds), not the delivery.scheduled announcement:
        # retracting the announcement would be a receiver-side noop
        # (retract_target_not_message). The inner id lives in the
        # announcement's staged payload.
        sched_row = ctx.conn.execute(
            "SELECT thread_id FROM events WHERE event_id = ?",
            (payload["scheduled_event_id"],),
        ).fetchone()
        inner_id = payload["scheduled_event_id"]
        staged = ctx.conn.execute(
            "SELECT payload FROM event_payloads WHERE event_id = ?",
            (payload["scheduled_event_id"],),
        ).fetchone()
        if staged is not None:
            try:
                inner_id = json.loads(staged["payload"]).get(
                    "inner_event_id", inner_id
                )
            except (ValueError, AttributeError):
                pass
        # The retraction reads best in the inner message's own thread.
        inner_row = ctx.conn.execute(
            "SELECT thread_id FROM events WHERE event_id = ?",
            (inner_id,),
        ).fetchone()
        retraction_thread = (
            inner_row["thread_id"]
            if inner_row and inner_row["thread_id"]
            else (sched_row["thread_id"] if sched_row else thread_id)
        )
        try:
            _send_event(
                ctx,
                rel,
                "message.retracted",
                {
                    "target_event_id": inner_id,
                    "reason": "cancel after release",
                },
                conversation_id=cid,
                thread_id=retraction_thread,
                clock_skew_seconds=clock_skew_seconds,
            )
            cancel_outcome = "already_released_retracted"
        except CliError as exc:
            # Honest failure: the operator must know the retraction never
            # went out. The outer send still succeeds (the delivery.canceled
            # intent is queued); only the retraction is reported failed.
            print(
                f"warning: retraction send failed ({exc.code}): "
                f"{exc.message}; the released event was NOT retracted",
                file=sys.stderr,
            )
            cancel_outcome = "already_released_retraction_failed"
    try:
        due = scheduler.run_due(
            ctx.conn, utcnow(), _release_fn(ctx),
            clock_skew_seconds=clock_skew_seconds,
        )
    except Exception as exc:
        raise CliError("send_error", f"scheduler release failed: {exc}")
    _warn_expired_by_run_due(due)
    released.extend(due.get("released", []))
    # Push GitHub send-direction mutations now; anything left queued is
    # flushed by the next receive run.
    _flush_send_transports(ctx, [rid])
    # Rotation housekeeping after every successful send: sweep discards
    # lost-ack candidates and retires old keys.
    _sweep_rotations(ctx)
    if event_type == "relationship.ready":
        _maybe_mark_active_after_ready(ctx, rid)
    object_names = [
        r["object_name"]
        for r in ctx.conn.execute(
            "SELECT object_name FROM sent_objects WHERE scheduled_id IN "
            f"({','.join('?' for _ in released)})",
            released,
        ).fetchall()
    ] if released else []
    return {
        "event_id": protected["event_id"],
        "sender_seq": protected["sender_seq"],
        "key_epoch": key_epoch,
        "scheduled": not released,
        "object_names": object_names,
        "released": due,
        "cancel_outcome": cancel_outcome,
    }


def _maybe_mark_active_after_ready(ctx: Ctx, rid: str) -> None:
    """Mark the relationship active once both sides exchanged ready."""
    rel = get_relationship(ctx.conn, rid)
    if rel is None or rel["consent_state"] == "active":
        return
    own = ctx.conn.execute(
        "SELECT 1 FROM events WHERE relationship_id = ? AND event_type = ? "
        "AND sender = ? LIMIT 1",
        (rid, "relationship.ready", ctx.identity_id),
    ).fetchone()
    peer = ctx.conn.execute(
        "SELECT 1 FROM events WHERE relationship_id = ? AND event_type = ? "
        "AND sender = ? LIMIT 1",
        (rid, "relationship.ready", rel["peer_identity_id"]),
    ).fetchone()
    if own and peer:
        mark_active(ctx.conn, rid)
        print(f"relationship {rid} is now active", file=sys.stderr)


def cmd_send(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        _warn_overdue_scheduled(ctx)
        if args.type in _LEGACY_SEND_TYPES:
            if not args.to and not args.relationship:
                raise CliError("bad_args", "legacy send needs --to")
            rel = ctx.resolve_relationship(args.to or args.relationship)
            event_type, payload = _legacy_payload(args)
        else:
            if args.type not in _SEND_TYPES:
                raise CliError("bad_args", f"unsupported event type {args.type!r}")
            if not args.to and not args.relationship:
                raise CliError("bad_args", "send needs --to or --relationship")
            rel = ctx.resolve_relationship(args.to or args.relationship)
            args._relationship_id = rel["relationship_id"]
            event_type, payload = args.type, _build_payload(ctx, args)
        state = rel["consent_state"]
        if state == "revoked":
            raise CliError("relationship_not_active", "relationship is revoked")
        if state != "active" and event_type not in (
            "relationship.ready",
            "migration.ready",
            "migration.commit",
        ):
            raise CliError(
                "relationship_not_active",
                f"relationship is {state}; exchange relationship.ready first",
            )
        if event_type == "delivery.scheduled" and not args.deliver_at:
            raise CliError("bad_args", "delivery.scheduled needs --deliver-at")
        result = _send_event(
            ctx,
            rel,
            event_type,
            payload,
            conversation_id=args.conversation,
            thread_id=args.thread,
            reply_to=args.reply_to,
            deliver_at=args.deliver_at,
            expires_at=args.expires_at,
            dry_run=bool(args.dry_run),
            clock_skew_seconds=args.clock_skew_seconds,
        )
        if args.json:
            print(_canon_text(result))
        elif result.get("dry_run"):
            print(_canon_text(result))
        elif result.get("cancel_outcome") == "canceled":
            print(
                f"canceled {args.scheduled_event_id}; delivery.canceled "
                f"event {result['event_id']} sent"
            )
        elif result.get("cancel_outcome") == "already_released_retracted":
            print(
                f"sent {result['event_id']} seq {result['sender_seq']} "
                f"epoch {result['key_epoch']} (scheduled event "
                f"{args.scheduled_event_id} already released; emitted a "
                "signed message.retracted request)"
            )
        elif result.get("cancel_outcome") == "already_released_retraction_failed":
            print(
                f"sent {result['event_id']} seq {result['sender_seq']} "
                f"epoch {result['key_epoch']} (scheduled event "
                f"{args.scheduled_event_id} already released; the signed "
                "retraction request FAILED to send, see warning above)"
            )
        elif result.get("cancel_outcome") == "already_released":
            print(
                f"sent {result['event_id']} seq {result['sender_seq']} "
                f"epoch {result['key_epoch']} (scheduled event "
                f"{args.scheduled_event_id} already released; cancel became "
                "a signed retraction request)"
            )
        elif result.get("cancel_outcome"):
            print(
                f"sent {result['event_id']} seq {result['sender_seq']} "
                f"epoch {result['key_epoch']} "
                f"(cancel outcome: {result['cancel_outcome']})"
            )
        elif result.get("scheduled"):
            print(
                f"scheduled {result['event_id']} seq {result['sender_seq']} "
                f"(delivers {args.deliver_at})"
            )
        else:
            print(
                f"sent {result['event_id']} seq {result['sender_seq']} "
                f"epoch {result['key_epoch']}"
            )
        return 0
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# mas human respond
# ---------------------------------------------------------------------------


def _require_human_presence(action: str) -> None:
    """Best-effort check that a human is driving this approval command.

    Refuses non-interactive stdin and requires the operator to type an
    explicit confirmation naming the action. This is the technical control
    behind "the human drives this command": a non-interactive agent
    subprocess cannot pass it by accident, and a casual scripted misuse
    fails loudly instead of minting a live approval.

    It is NOT a cryptographic attestation of humanity. A fully compromised
    local process with the same OS access as the operator can allocate a
    pty and answer the prompt. The trust boundary is the operator's
    machine: if the local agent runtime itself is malicious, no in-process
    check can distinguish it from the human. This gate raises the cost of
    misuse; it does not move the trust boundary.
    """
    import sys

    if not sys.stdin.isatty():
        raise CliError(
            "human_presence_required",
            "this command approves an action as the human; it refuses to"
            " run with non-interactive stdin. Run it from a real terminal.",
        )
    print(f"Human approval requested: {action}")
    print("Type APPROVE (all caps) to confirm, anything else aborts.")
    try:
        typed = input("> ").strip()
    except EOFError:
        raise CliError("human_approval_declined", "no confirmation typed; aborted")
    if typed != "APPROVE":
        raise CliError("human_approval_declined", "confirmation not typed; aborted")


def cmd_human_respond(args: argparse.Namespace) -> int:
    """The human's explicit response to a human.requested event.

    This command IS the local human-approval step required by the plan:
    running it creates the local human-approval record, then sends the
    human.responded event carrying that record's ID. Agents must never
    send human.responded on their own; the human drives this command,
    proven best-effort by the interactive confirmation gate
    (_require_human_presence). Dry runs create no approval record.
    """
    from muse_agent_social.model.approvals import create_approval

    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        if not args.to and not args.relationship:
            raise CliError("bad_args", "human respond needs --to or --relationship")
        rel = ctx.resolve_relationship(args.to or args.relationship)
        rid = rel["relationship_id"]
        if rel["consent_state"] != "active":
            raise CliError("relationship_not_active", "relationship is not active")
        if not args.request_id or args.answer is None:
            raise CliError(
                "bad_args", "human respond needs --request-id and --answer"
            )
        if args.approved and args.rejected:
            raise CliError("bad_args", "cannot pass both --approved and --rejected")
        approved = bool(args.approved)
        dry_run = bool(args.dry_run)
        if dry_run:
            # No side effects: validate only. The payload carries a
            # placeholder record ID; nothing is persisted or consumed.
            approval_id = "dry_run"
        else:
            _require_human_presence(
                f"respond to human.requested {args.request_id} "
                f"({'approved' if approved else 'rejected'})"
            )
            with ctx.conn:
                approval_id = create_approval(
                    ctx.conn,
                    relationship_id=rid,
                    subject_type="human_request",
                    subject_id=args.request_id,
                    answer=args.answer,
                    approved=approved,
                    created_at=utcnow(),
                    note=args.note,
                )
        args._relationship_id = rid
        args.approval_record = approval_id
        args.type = "human.responded"
        args.approved = approved
        payload = _build_payload(ctx, args)
        result = _send_event(
            ctx,
            rel,
            "human.responded",
            payload,
            conversation_id=args.conversation,
            thread_id=args.thread,
            reply_to=args.reply_to,
            dry_run=dry_run,
        )
        if dry_run:
            print(f"dry run ok; no approval recorded, nothing sent")
        else:
            print(f"approval {approval_id} recorded; sent {result['event_id']}")
        return 0
    finally:
        ctx.close()


def cmd_human_poll_respond(args: argparse.Namespace) -> int:
    """The human's explicit, confirmed response to a poll.

    Creates the local human-approval record for the poll, then sends
    poll.responded with human_confirmed=true carrying that record's ID.
    This is the only honest path to a human-confirmed poll response:
    the schema requires approval_record_id when human_confirmed is true,
    and the human drives this command (interactive confirmation gate).
    The choice list is encoded as canonical JSON so the approval cannot
    authorize a different choice set than the human confirmed. Dry runs
    create no approval record.
    """
    from muse_agent_social.model.approvals import create_approval

    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        if not args.to and not args.relationship:
            raise CliError("bad_args", "human poll-respond needs --to or --relationship")
        rel = ctx.resolve_relationship(args.to or args.relationship)
        rid = rel["relationship_id"]
        if rel["consent_state"] != "active":
            raise CliError("relationship_not_active", "relationship is not active")
        choice_ids = list(args.choice_ids or [])
        if not choice_ids:
            raise CliError("bad_args", "human poll-respond needs --choice-ids")
        answer = _poll_answer(choice_ids)
        dry_run = bool(args.dry_run)
        if dry_run:
            approval_id = "dry_run"
        else:
            _require_human_presence(
                f"confirm poll response {args.poll_id} choices {choice_ids}"
            )
            with ctx.conn:
                approval_id = create_approval(
                    ctx.conn,
                    relationship_id=rid,
                    subject_type="poll",
                    subject_id=args.poll_id,
                    answer=answer,
                    approved=True,
                    created_at=utcnow(),
                    note=args.note,
                )
        args._relationship_id = rid
        args.approval_record = approval_id
        args.type = "poll.responded"
        args.poll_id = args.poll_id
        args.human_confirmed = True
        payload = _build_payload(ctx, args)
        result = _send_event(
            ctx,
            rel,
            "poll.responded",
            payload,
            conversation_id=args.conversation,
            thread_id=args.thread,
            reply_to=args.reply_to,
            dry_run=dry_run,
        )
        if dry_run:
            print("dry run ok; no approval recorded, nothing sent")
        else:
            print(f"approval {approval_id} recorded; sent {result['event_id']}")
        return 0
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# mas receive
# ---------------------------------------------------------------------------


def _record_quarantine(
    ctx: Ctx, rid: str, object_name: str, reason: str, detail: str = ""
) -> None:
    now = utcnow()
    ctx.conn.execute(
        "INSERT OR REPLACE INTO receive_quarantine "
        "(relationship_id, object_name, reason, detail, quarantined_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (rid, object_name, reason, detail[:500], now),
    )
    # G15: bound the quarantine table. Expire rows older than the TTL,
    # then enforce the per-relationship cap (oldest dropped first).
    # Quarantine is operator-visible evidence, not an unbounded log.
    cutoff = add_seconds(now, -RECEIVE_QUARANTINE_TTL_DAYS * 24 * 3600)
    ctx.conn.execute(
        "DELETE FROM receive_quarantine WHERE quarantined_at <= ?;",
        (cutoff,),
    )
    ctx.conn.execute(
        "DELETE FROM receive_quarantine WHERE (relationship_id, object_name)"
        " IN (SELECT relationship_id, object_name FROM receive_quarantine"
        " WHERE relationship_id = ? ORDER BY quarantined_at DESC,"
        " object_name DESC LIMIT -1 OFFSET ?);",
        (rid, RECEIVE_QUARANTINE_MAX_PER_RELATIONSHIP),
    )
    ctx.conn.commit()


def _quarantine_outcome(
    ctx: Ctx, rid: str, object_name: str, reason: str, detail: str = ""
) -> dict:
    _record_quarantine(ctx, rid, object_name, reason, detail)
    return {"outcome": "quarantined", "surfaces": 0, "receipts_queued": 0}


def _receive_v01(
    ctx: Ctx, rid: str, object_name: str, data: bytes, rel: dict
) -> dict:
    """Bounded v0.1 adapter path honoring the migration drain rules."""
    # G1: gate on the real migration phase names and derive the drain from
    # migration state (legacy_read_open + drain_until), never from the
    # phase alone. The fictional phases ("dual_read", "observing") never
    # existed in migrate.py, so the old gate closed legacy reads during
    # dual-read and opened them during "observing" (a phase where reads
    # must be shut).
    phase = mstate_get(ctx.conn, "migration.phase")
    if phase not in ("staged", "verified", "committed"):
        return _quarantine_outcome(ctx, rid, object_name, "v01_not_accepted")
    pair_id = mstate_get(ctx.conn, "migration.pair_id")
    vault_dir = ctx.state_dir / "migration-vault"
    if not pair_id or not vault_dir.exists():
        return _quarantine_outcome(ctx, rid, object_name, "v01_no_vault")
    try:
        # Prefer the sealed entry: stage() encrypts the operator's
        # plaintext vault handoff in place under the ceremony vault key.
        # Fall back to the plaintext handoff for a ceremony whose stage
        # has not run in this state dir yet (or a pre-seal vault).
        try:
            enc_key = ceremony_vault_key(ctx.state_dir, pair_id)
        except (MigrationError, OSError):
            enc_key = None
        if enc_key is not None:
            try:
                pair_key = vault_load(vault_dir, pair_id, enc_key=enc_key)
            except VaultError:
                pair_key = vault_load(vault_dir, pair_id)
        else:
            pair_key = vault_load(vault_dir, pair_id)
    except (LegacyError, VaultError, KeyError) as exc:
        return _quarantine_outcome(ctx, rid, object_name, "v01_no_vault", str(exc))
    # G1: the drain is migration state (legacy_read_open + drain_until),
    # not a phase lookup.
    read_open = drain_open(ctx.conn)
    policy = LegacyPolicy(
        pair_id=pair_id,
        expected_sender=mstate_get(ctx.conn, "migration.peer_legacy_id") or "*",
        my_agent_id=mstate_get(ctx.conn, "migration.my_legacy_id") or "*",
        # Persistent replay store (Medium 1): a per-object memory store
        # would forget every nonce at the next object, so replays were
        # never rejected. The v0.2 replay_guard table is shared and
        # survives across objects and restarts.
        replay_store=StoreReplayGuard(ctx.conn),
        legacy_read_open=read_open,
        legacy_sends_allowed=False,
    )
    try:
        verified = verify_v01(data, pair_key, policy=policy)
    except LegacyError as exc:
        return _quarantine_outcome(ctx, rid, object_name, "v01_verify_failed", str(exc))
    # The v0.1 persist block is ONE real transaction: the seq-assigner
    # state, the event row, the staged projection input, the projection
    # queue row, and the legacy replay record all commit or roll back
    # together. ``with ctx.conn:`` is a no-op on this autocommit
    # connection, and the old code committed the seq-assigner state before
    # the event insert: a crash between the INSERTs left the event stored
    # but never projected, and redelivery then hit an IntegrityError on
    # the deterministic event_id (silent loss plus a bogus quarantine).
    seq_state = mstate_get(ctx.conn, "migration.seq_assigner") or {}
    assigner = SeqAssigner.from_dict({k: int(v) for k, v in seq_state.items()})
    adapted = adapt_v01(verified, pair_id, assigner)
    payload = {
        "body": (
            f"{adapted['payload']['legacy_title']}\n\n{adapted['payload']['body']}"
            if adapted["payload"].get("legacy_title")
            else adapted["payload"]["body"]
        ),
        "format": "plain",
    }
    # adapt_v01 returns a flat dict (see compatibility/v01.py); legacy
    # messages land in the relationship's own conversation, mirroring the
    # migration drain in migrate.py.
    conversation_id = rid
    thread_id = rid + ":t"
    try:
        with transaction(ctx.conn):
            # Durable sequence assignment inside the same transaction: a
            # crash never burns a sender_seq without persisting its event.
            mstate_set(ctx.conn, "migration.seq_assigner", assigner.to_dict())
            ctx.conn.execute(
                "INSERT OR IGNORE INTO conversations (conversation_id) VALUES (?)",
                (conversation_id,),
            )
            ctx.conn.execute(
                "INSERT OR IGNORE INTO threads (thread_id, conversation_id) "
                "VALUES (?, ?)",
                (thread_id, conversation_id),
            )
            ctx.conn.execute(
                "INSERT INTO events (event_id, relationship_id, conversation_id, "
                "thread_id, sender, sender_seq, created_at, key_epoch, event_type, "
                "replay_nonce, sealed_envelope) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'message.created', ?, ?)",
                (
                    adapted["event_id"],
                    rid,
                    conversation_id,
                    thread_id,
                    adapted["sender"],
                    adapted["sender_seq"],
                    adapted["created_at"],
                    "v01:" + verified.envelope["nonce"],
                    data,
                ),
            )
            record_projection_input(
                ctx.conn,
                event_id=adapted["event_id"],
                event_type="message.created",
                payload=payload,
                reply_to=None,
            )
            ctx.conn.execute(
                "INSERT INTO projection_queue (event_id, queued_at) VALUES (?, ?)",
                (adapted["event_id"], utcnow()),
            )
            # Record the verified nonce/id in the persistent replay store
            # so a replayed v0.1 object is rejected on the next object.
            record_legacy_replay(policy, verified)
    except sqlite3.IntegrityError as exc:
        return _quarantine_outcome(
            ctx, rid, object_name, "v01_storage_conflict", str(exc)[:500]
        )
    return {"outcome": "accepted", "surfaces": 1, "receipts_queued": 0}


def _try_unseal(ctx: Ctx, rid: str, envelope: dict) -> tuple[dict, dict]:
    """Unseal trying the relationship's own current epoch first.

    The first key tried is the locally tracked current epoch
    (``relationships.key_epoch``), not the sender-declared envelope
    ``key_epoch``: a sender must not steer which of our keys is tried
    first. The fallback is bounded to the retained dual-wrap window: the
    seal side wraps the CEK to at most the recipient's current and
    immediately-previous agreement epochs (see the recipients schema),
    so unseal tries at most those two epochs and never walks the whole
    key history.
    """
    rel = ctx.conn.execute(
        "SELECT key_epoch FROM relationships WHERE relationship_id = ?;",
        (rid,),
    ).fetchone()
    current = int(rel["key_epoch"]) if rel is not None else None
    rows = ctx.conn.execute(
        "SELECT epoch, private_key_ref FROM key_epochs "
        "WHERE relationship_id = ? AND private_key_ref != 'peer' "
        "ORDER BY epoch DESC",
        (rid,),
    ).fetchall()
    if not rows:
        raise SealingError("unknown_recipient", "no local agreement keys")
    by_epoch = {int(r["epoch"]): r for r in rows}
    if current is not None and current in by_epoch:
        # Local truth first: the relationship's current epoch when it is
        # one of our own keys (we rotated last), then the newest older
        # own key. The seal side dual-wraps to at most our current and
        # previous keys, so two attempts bound the fallback; epochs are
        # relationship-global and rotations interleave, so "previous" is
        # the newest own epoch below current, not necessarily current-1.
        candidates = [by_epoch[current]]
        lower = [e for e in sorted(by_epoch, reverse=True) if e < current]
        if lower:
            candidates.append(by_epoch[lower[0]])
    else:
        # No authoritative current epoch, or the last rotation was the
        # peer's (relationships.key_epoch is then the peer's epoch, not
        # one of our keys): try at most the two newest retained own keys,
        # which is the same dual-wrap window.
        candidates = [by_epoch[e] for e in sorted(by_epoch, reverse=True)[:2]]
    last: Optional[SealingError] = None
    for row in candidates:
        try:
            raw = Path(row["private_key_ref"]).read_bytes()
            priv = X25519PrivateKey.from_private_bytes(raw)
        except (OSError, ValueError) as exc:
            last = SealingError("unknown_recipient", f"cannot load key: {exc}")
            continue
        try:
            return unseal_envelope(envelope, priv, ctx.identity_id)
        except SealingError as exc:
            last = exc
            continue
    raise last if last is not None else SealingError("unknown_recipient", "no key worked")


def _queue_accepted_receipt(
    ctx: Ctx,
    rid: str,
    peer_id: str,
    manager: RotationManager,
    target_event_id: str,
    now: str,
) -> None:
    """Build, seal, and persist an accepted receipt.

    Must be called inside the caller's SQLite transaction so the receipt
    is atomic with the receive commit: the receipt event row, the sender
    sequence update, the projection queue entry, and the scheduler
    outbox row all commit or roll back together. The relay upload itself
    is queued through the scheduler outbox and pushed after the commit.

    Persistence goes through the same ``persist_outgoing_in_txn`` core as
    every other send (same seq assignment, same conflict classification),
    so receipts cannot diverge from the guarded send path. Recipients go
    through the rotation send gate (``_recipients_for``) like any send.
    """
    from .model.events import persist_outgoing_in_txn

    rel = get_relationship(ctx.conn, rid)
    if rel is None:
        raise CliError("unknown_relationship", f"unknown relationship {rid}")
    recipients, key_epoch = _recipients_for(ctx, rel, manager, peer_id)
    payload = {"target_event_id": target_event_id, "accepted_at": now}
    try:
        validate_payload("receipt.accepted", payload)
    except SchemaError as exc:
        raise CliError("send_error", f"bad receipt payload: {exc}")
    try:
        rprotected = build_protected(
            relationship_id=rid,
            conversation_id=rid,
            sender_id=ctx.identity_id,
            event_type="receipt.accepted",
            thread_id=new_thread_id(),
            reply_to=None,
            key_epoch=key_epoch,
        )
    except (SchemaError, ValueError) as exc:
        raise CliError("send_error", f"cannot build receipt: {exc}")
    try:
        persist_outgoing_in_txn(
            ctx.conn, rprotected, payload, ctx.hierarchy.ed25519_private, recipients
        )
    except EventStoreError as exc:
        # Same outcome code the receive commit used for storage conflicts
        # before the unification; callers already map it.
        raise CliError("integrity_conflict", f"storage conflict: {exc}")


def _bump_retry_sighting(
    conn: sqlite3.Connection, relationship_id: str, object_name: str, reason: str
) -> int:
    """Count another retryable sighting of one object; return the total.

    The table is created idempotently so this is safe on any code path
    that did not run _ensure_cli_tables first.
    """
    now = utcnow()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS receive_retry_state ("
        " relationship_id TEXT NOT NULL,"
        " object_name TEXT NOT NULL,"
        " reason TEXT NOT NULL,"
        " sightings INTEGER NOT NULL DEFAULT 0,"
        " first_seen_at TEXT NOT NULL,"
        " last_seen_at TEXT NOT NULL,"
        " PRIMARY KEY (relationship_id, object_name, reason))"
    )
    conn.execute(
        "INSERT INTO receive_retry_state(relationship_id, object_name, reason,"
        " sightings, first_seen_at, last_seen_at)"
        " VALUES (?, ?, ?, 1, ?, ?)"
        " ON CONFLICT(relationship_id, object_name, reason) DO UPDATE SET"
        " sightings = receive_retry_state.sightings + 1,"
        " last_seen_at = excluded.last_seen_at",
        (relationship_id, object_name, reason, now, now),
    )
    row = conn.execute(
        "SELECT sightings FROM receive_retry_state"
        " WHERE relationship_id = ? AND object_name = ? AND reason = ?",
        (relationship_id, object_name, reason),
    ).fetchone()
    return int(row["sightings"])


def _clear_retry_state(
    conn: sqlite3.Connection, relationship_id: str, object_name: str
) -> None:
    """Drop retry accounting for an object that reached a terminal outcome."""
    conn.execute(
        "DELETE FROM receive_retry_state"
        " WHERE relationship_id = ? AND object_name = ?",
        (relationship_id, object_name),
    )


def _clear_retry_state_quiet(
    conn: sqlite3.Connection, relationship_id: str, object_name: str
) -> None:
    """Best-effort _clear_retry_state: cleanup must never raise."""
    try:
        _clear_retry_state(conn, relationship_id, object_name)
    except Exception:
        pass


# sqlite3.OperationalError subclasses that a later poll could plausibly
# heal: lock contention (the 30s busy timeout usually absorbs these, but a
# racing writer can still surface one), I/O hiccups, a full disk. Anything
# else (no such table, a malformed database, a missing column) is
# deterministic and is quarantined with a reason instead of retried.
_TRANSIENT_SQLITE_MARKERS = (
    "database is locked",
    "database table is locked",
    "database schema is locked",
    "database is busy",
    "disk i/o error",
    "database or disk is full",
    "interrupted",
)

# OSError errnos that a later poll could plausibly heal, plus message
# markers for the errno-less synthetic raises the transport layer makes.
_TRANSIENT_OS_ERRNOS = frozenset(
    {errno.EAGAIN, errno.EINTR, errno.EBUSY, errno.ENOSPC, errno.EDQUOT, errno.EIO}
)
_TRANSIENT_OS_MARKERS = (
    "i/o error",
    "no space",
    "quota exceeded",
    "temporarily unavailable",
    "resource busy",
)


def _is_transient_storage_error(exc: BaseException) -> bool:
    """True only for storage failures a later poll could plausibly heal."""
    if isinstance(exc, sqlite3.OperationalError):
        message = str(exc).lower()
        return any(marker in message for marker in _TRANSIENT_SQLITE_MARKERS)
    if isinstance(exc, OSError):
        if exc.errno in _TRANSIENT_OS_ERRNOS:
            return True
        message = str(exc).lower()
        return any(marker in message for marker in _TRANSIENT_OS_MARKERS)
    return False


def _storage_failure_outcome(
    ctx: Ctx, rid: str, object_name: str, exc: BaseException
) -> dict:
    """Classify a storage-layer failure during receive.

    Transient failures stay retry_pending so the object is left on the
    relay, but a consecutive-failure ceiling stops an infinite silent loop:
    after MAX_CONSECUTIVE_RECEIVE_FAILURES the object is quarantined and
    the operator is warned on stderr. Deterministic failures can never
    heal, so they are quarantined immediately with the reason recorded.
    """
    label = f"{type(exc).__name__}: {exc}"
    if not _is_transient_storage_error(exc):
        return _quarantine_outcome(
            ctx, rid, object_name, "storage_error", label[:500]
        )
    sightings = _bump_retry_sighting(
        ctx.conn, rid, object_name, "transient_storage"
    )
    if sightings >= MAX_CONSECUTIVE_RECEIVE_FAILURES:
        print(
            f"warning: receive of {object_name} failed {sightings} times in a"
            f" row ({label}); quarantining as retry_ceiling_exceeded",
            file=sys.stderr,
        )
        return _quarantine_outcome(
            ctx,
            rid,
            object_name,
            "retry_ceiling_exceeded",
            f"{sightings} consecutive storage failures; last: {label}"[:500],
        )
    return {"outcome": "retry_pending", "surfaces": 0, "receipts_queued": 0}


# Process-local count of consecutive receives where even the failure
# bookkeeping could not touch the database (the DB file is gone, the
# disk died mid-write, ...). There is nothing durable to record, so the
# escalation is counting plus loud stderr reporting; the object stays on
# the relay rather than being silently dropped or spun on forever.
_UNWRITABLE_BOOKKEEPING_COUNT: dict[tuple[str, str], int] = {}


def _bookkeeping_failed_outcome(
    ctx: Ctx, rid: str, object_name: str, exc: BaseException
) -> dict:
    """Last resort when failure bookkeeping itself cannot write.

    Best-effort attempts the quarantine write once the process-local
    ceiling is hit (it may succeed when only the retry-state table was
    broken); otherwise the object is left on the relay with a loud
    warning instead of spinning silently.
    """
    key = (rid, object_name)
    count = _UNWRITABLE_BOOKKEEPING_COUNT.get(key, 0) + 1
    _UNWRITABLE_BOOKKEEPING_COUNT[key] = count
    label = f"{type(exc).__name__}: {exc}"
    print(
        f"warning: receive of {object_name} failed and failure bookkeeping"
        f" is unwritable ({label}); consecutive unwritable failures: {count}",
        file=sys.stderr,
    )
    if count >= MAX_CONSECUTIVE_RECEIVE_FAILURES:
        try:
            outcome = _quarantine_outcome(
                ctx,
                rid,
                object_name,
                "storage_error",
                f"unwritable failure bookkeeping after {count} attempts;"
                f" last: {label}"[:500],
            )
            _UNWRITABLE_BOOKKEEPING_COUNT.pop(key, None)
            return outcome
        except Exception as quarantine_exc:
            print(
                f"warning: cannot quarantine {object_name} either"
                f" ({type(quarantine_exc).__name__}: {quarantine_exc});"
                " leaving the object on the relay",
                file=sys.stderr,
            )
    return {"outcome": "retry_pending", "surfaces": 0, "receipts_queued": 0}


def _receive_object(
    ctx: Ctx, rid: str, object_name: str, data: bytes, acc: dict
) -> dict:
    """Full per-object receive pipeline. Never raises.

    Failure classification matters: hostile input (CliError, unexpected
    bugs) becomes a terminal quarantine and the object is consumed, but
    INFRASTRUCTURE failures (lock timeout after the 30s busy timeout,
    disk I/O errors, full disk) mean the event was never stored. Those
    return ``retry_pending`` so the watcher leaves the object on the relay
    for a later poll instead of deleting a peer's event we never saved.
    Deterministic storage failures (missing tables, a malformed database)
    are quarantined with a reason: retrying them forever heals nothing.
    """
    try:
        outcome = _receive_object_inner(ctx, rid, object_name, data, acc)
    except CliError as exc:
        _clear_retry_state_quiet(ctx.conn, rid, object_name)
        return _quarantine_outcome(ctx, rid, object_name, exc.code, exc.message)
    except (sqlite3.DatabaseError, OSError) as exc:
        try:
            return _storage_failure_outcome(ctx, rid, object_name, exc)
        except Exception as bookkeeping_exc:
            # Even the failure bookkeeping failed; escalate with
            # process-local counting and loud reporting rather than a
            # silent infinite retry loop.
            return _bookkeeping_failed_outcome(
                ctx, rid, object_name, bookkeeping_exc
            )
    except Exception as exc:  # never let the watcher see a traceback
        _clear_retry_state_quiet(ctx.conn, rid, object_name)
        return _quarantine_outcome(
            ctx, rid, object_name, "receive_error", f"{type(exc).__name__}: {exc}"
        )
    if outcome.get("outcome") != "retry_pending":
        _clear_retry_state_quiet(ctx.conn, rid, object_name)
        _UNWRITABLE_BOOKKEEPING_COUNT.pop((rid, object_name), None)
    return outcome


def _redrain_projection(ctx: Ctx, rid: str, event_id: str) -> None:
    """Re-run the incremental projection for an already-accepted event.

    Crash gap: the atomic receive commit can succeed while the process
    dies before (or during) the post-commit apply_event. The event is
    durable and its projection_queue row is still present, but the
    projection never ran. Without this, the duplicate resume path would
    report accepted while the message stays unprojected (silent loss).

    apply_event is idempotent (already-projected events are a noop), so
    running it here is safe on every redelivery. G15: a successful
    re-projection acknowledges (deletes) the queue row, matching the
    normal receive and send paths.
    """
    queued = ctx.conn.execute(
        "SELECT 1 FROM projection_queue WHERE event_id = ?", (event_id,)
    ).fetchone()
    if queued is None:
        return
    payload_row = ctx.conn.execute(
        "SELECT payload, reply_to FROM event_payloads WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    if payload_row is None:
        return
    event_row = ctx.conn.execute(
        "SELECT * FROM events WHERE event_id = ?", (event_id,)
    ).fetchone()
    if event_row is None:
        return
    event_row = dict(event_row)
    event_row["payload"] = payload_row["payload"]
    event_row["reply_to"] = payload_row["reply_to"]
    try:
        # Atomic per-event projection (see the send path): a crash between
        # the handler's statements must roll back, so redelivery re-applies
        # the whole event instead of hitting a half-written marker.
        with transaction(ctx.conn):
            apply_event(ctx.conn, event_row)
            ctx.conn.execute(
                "DELETE FROM projection_queue WHERE event_id = ?;", (event_id,)
            )
    except ProjectionError as exc:
        with transaction(ctx.conn):
            quarantine_event(
                ctx.conn,
                rid,
                event_row["sender"],
                int(event_row["sender_seq"]),
                event_id,
                f"projection_{exc.code}",
            )
            ctx.conn.execute(
                "DELETE FROM projection_queue WHERE event_id = ?", (event_id,)
            )


def _verify_identity_rotation_against_pinned(
    announcement: dict, old_identity_id: str
) -> dict:
    """Verify an identity.rotated announcement against the pinned peer identity.

    The peer's full card is not stored locally, so continuity rests on the
    old-key cross-signature: only the holder of the pinned identity's
    private key could have produced it. Checks, fail-closed:

    - announcement is a dict with rotation_version 1
    - new_card verifies (schema, self-signature, expiry) via verify_card
    - the new identity id differs from the old
    - cross_signatures holds exactly the old and new key ids, and both
      Ed25519 signatures verify over the restricted-JCS bytes of new_card

    Returns the new card dict. Raises IdentityRotationError on any problem.
    """
    from cryptography.exceptions import InvalidSignature

    if not isinstance(announcement, dict):
        raise IdentityRotationError("bad_announcement", "announcement must be a dict")
    if announcement.get("rotation_version") != 1:
        raise IdentityRotationError(
            "bad_version", "unsupported rotation_version"
        )
    new_card = announcement.get("new_card")
    if not isinstance(new_card, dict):
        raise IdentityRotationError("bad_card", "announcement has no new_card")
    card_check = verify_card(new_card)
    if not card_check.ok:
        raise IdentityRotationError(
            "bad_card", f"new card failed verification: {card_check.reason_code}"
        )
    new_id = new_card.get("identity_id", "")
    if not old_identity_id or not new_id or old_identity_id == new_id:
        raise IdentityRotationError("bad_identity", "new identity id is not new")
    sigs = announcement.get("cross_signatures")
    if not isinstance(sigs, list) or len(sigs) != 2:
        raise IdentityRotationError(
            "bad_signatures", "need exactly two cross-signatures"
        )
    by_key = {
        s.get("key_id"): s.get("signature")
        for s in sigs
        if isinstance(s, dict)
    }
    if set(by_key) != {old_identity_id, new_id}:
        raise IdentityRotationError(
            "bad_signatures", "cross-signatures must cover the old and new ids"
        )
    canonical_new = restricted_jcs(new_card)
    try:
        for key_id in (old_identity_id, new_id):
            pub = parse_identity_id(key_id)
            signature = b64url_decode(by_key[key_id])
            Ed25519PublicKey.from_public_bytes(pub).verify(signature, canonical_new)
    except (ValueError, InvalidSignature, KeyError, TypeError) as exc:
        raise IdentityRotationError(
            "bad_signatures", f"cross-signature verification failed: {exc}"
        ) from exc
    return new_card


def _apply_identity_rotation(
    ctx: Ctx, rid: str, announcement: dict, old_peer_id: str
) -> bool:
    """Apply a verified identity.rotated announcement to the relationship.

    Verifies the announcement against the pinned peer identity id, then
    updates relationships.peer_identity_id (keeping the old id in
    prior_peer_identity_id so delayed pre-rotation events and redelivered
    rotation announcements stay attributable) and peer_display_name.

    Idempotent: returns False without touching the database when the
    stored peer identity already equals the announced new identity.
    Raises IdentityRotationError when verification fails or the stored
    peer identity no longer matches the announcement's old identity.
    """
    new_card = _verify_identity_rotation_against_pinned(announcement, old_peer_id)
    new_id = new_card["identity_id"]
    rel = get_relationship(ctx.conn, rid)
    if rel["peer_identity_id"] == new_id:
        return False
    if rel["peer_identity_id"] != old_peer_id:
        raise IdentityRotationError(
            "stale_announcement",
            "peer identity changed since this announcement was issued",
        )
    # Retired-key traffic stays acceptable for a bounded grace window so
    # delayed pre-rotation events land; after it, the old key is dead.
    grace_until = add_seconds(utcnow(), PRIOR_IDENTITY_GRACE_SECONDS)
    with transaction(ctx.conn):
        ctx.conn.execute(
            "UPDATE relationships SET peer_identity_id = ?, "
            "prior_peer_identity_id = ?, prior_identity_grace_until = ?, "
            "peer_display_name = ? "
            "WHERE relationship_id = ?",
            (new_id, old_peer_id, grace_until, new_card.get("display_name"), rid),
        )
    return True


def _maybe_apply_pending_identity_rotation(
    ctx: Ctx, rid: str, event_id: str, sender_id: str
) -> None:
    """Re-apply an identity rotation missed by a post-commit crash.

    If the duplicate redelivery is an identity.rotated event whose
    announcement has not been applied yet (the first attempt died after
    the commit but before the identity update), apply it now.
    Idempotent: already-applied announcements are a noop.
    """
    row = ctx.conn.execute(
        "SELECT event_type FROM events WHERE event_id = ?", (event_id,)
    ).fetchone()
    if row is None or row["event_type"] != "identity.rotated":
        return
    payload_row = ctx.conn.execute(
        "SELECT payload FROM event_payloads WHERE event_id = ?", (event_id,)
    ).fetchone()
    if payload_row is None:
        return
    _apply_identity_rotation(ctx, rid, json.loads(payload_row["payload"]), sender_id)


def _converge_rotation_hooks(ctx: Ctx, rid: str, event_id: str) -> None:
    """Re-drive rotation hooks for a redelivered event when unmarked.

    Called on the byte-identical resume path: if the first attempt died
    after the receive commit but before (or during) the rotation hooks,
    the hooks never ran. Already-marked events are skipped; the hooks
    are idempotent, so re-driving converges.
    """
    marked = ctx.conn.execute(
        "SELECT 1 FROM rotation_processed_events WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    if marked is not None:
        return
    row = ctx.conn.execute(
        "SELECT e.event_type, e.key_epoch, p.payload FROM events e "
        "JOIN event_payloads p ON p.event_id = e.event_id "
        "WHERE e.event_id = ?",
        (event_id,),
    ).fetchone()
    if row is None or row["event_type"] not in _ROTATION_EVENT_TYPES:
        return
    try:
        payload = json.loads(row["payload"])
    except ValueError:
        return
    manager = RotationManager(ctx.conn, ctx.keys_dir)
    _run_rotation_hooks(
        ctx, rid, manager, row["event_type"], payload, event_id,
        int(row["key_epoch"]),
    )


def _check_ingress_quota(
    ctx: Ctx, rid: str, now: str
) -> Optional[dict]:
    """Enforce the per-relationship ingress quota (G15).

    Returns a ``retry_pending`` outcome dict when the relationship has
    already accepted ``INGRESS_MAX_EVENTS_PER_DAY`` events in the trailing
    24 hours; the object stays on the relay and is admitted as the window
    slides. Returns None when the object may proceed.

    The count uses the durable receiver acceptance time
    (``event_payloads.received_at``, G13), never sender-controlled
    ``created_at``: a sender must not be able to dodge the quota by
    backdating, nor burn it by postdating.
    """
    cutoff = add_seconds(now, -24 * 3600)
    count = ctx.conn.execute(
        "SELECT COUNT(*) FROM event_payloads p"
        " JOIN events e ON e.event_id = p.event_id"
        " WHERE e.relationship_id = ? AND p.received_at >= ?;",
        (rid, cutoff),
    ).fetchone()[0]
    if int(count) >= INGRESS_MAX_EVENTS_PER_DAY:
        return {
            "outcome": "retry_pending",
            "surfaces": 0,
            "receipts_queued": 0,
            "retry_reason": "ingress_quota_exceeded",
        }
    return None


def _receive_object_inner(
    ctx: Ctx, rid: str, object_name: str, data: bytes, acc: dict
) -> dict:
    if len(data) > OBJECT_MAX_BYTES:
        raise CliError("object_too_large", "object exceeds 262144 bytes")
    rel = get_relationship(ctx.conn, rid)
    if rel is None:
        raise CliError("unknown_relationship", f"unknown relationship {rid}")
    if rel["consent_state"] == "revoked":
        raise CliError("relationship_revoked", "relationship is revoked")
    peer_id = rel["peer_identity_id"]
    if detect_v01(data):
        return _receive_v01(ctx, rid, object_name, data, rel)
    try:
        envelope = strict_parse(data)
    except CanonicalizationError as exc:
        raise CliError("parse_error", f"object is not canonical JSON: {exc}")
    try:
        validate("event-envelope", envelope)
    except SchemaError as exc:
        raise CliError("envelope_schema_invalid", f"{exc}")
    protected = envelope["protected"]
    if protected["relationship_id"] != rid:
        raise CliError("relationship_mismatch", "object is for another relationship")
    # The authenticated sender is protected["sender"], not the relationship's
    # current peer_identity_id: after a rotation, delayed pre-rotation
    # events are signed by the retired identity. Storing them under the new
    # identity would relabel retired-key traffic and collide same-sender_seq
    # events from both keys into false fork quarantines.
    sender_identity = protected["sender"]
    if sender_identity != peer_id and sender_identity != rel.get(
        "prior_peer_identity_id"
    ):
        raise CliError("unknown_sender", f"unexpected sender {sender_identity}")
    now = utcnow()
    if sender_identity != peer_id:
        # Retired-key traffic is only honored inside the post-rotation
        # grace window, so a compromised old key cannot sign forever.
        grace_until = rel.get("prior_identity_grace_until")
        if not grace_until or now > grace_until:
            raise CliError(
                "prior_identity_expired",
                "event signed by the retired peer identity after the grace window",
            )
    event_id = protected["event_id"]
    existing = ctx.conn.execute(
        "SELECT sealed_envelope FROM events WHERE event_id = ?", (event_id,)
    ).fetchone()
    if existing is not None:
        if bytes(existing["sealed_envelope"]) == data:
            # Resume path: this exact object was accepted before. The
            # atomic commit may have succeeded while the process died
            # before (or during) the post-commit apply_event, leaving the
            # projection_queue row behind. Re-drain it so the projection
            # converges exactly once instead of being silently lost.
            _redrain_projection(ctx, rid, event_id)
            # Same crash gap for identity rotation: if the first attempt
            # died after the commit but before the peer identity update,
            # apply the pending rotation now (idempotent). Verify against
            # the sender (the old identity), not the current peer id.
            _maybe_apply_pending_identity_rotation(
                ctx, rid, event_id, protected["sender"]
            )
            # Same crash gap for rotation hooks: the commit may have
            # succeeded while the process died before (or during) the
            # post-commit rotation hooks, or between the hooks and the
            # processed marker. Re-drive them when unmarked; every hook is
            # idempotent, so this converges instead of duplicating.
            _converge_rotation_hooks(ctx, rid, event_id)
            return {"outcome": "accepted", "surfaces": 0, "receipts_queued": 0}
        raise CliError("event_id_conflict", "event id reused with different bytes")
    manager = RotationManager(ctx.conn, ctx.keys_dir)
    try:
        # Authenticate first: unseal verifies the sender's Ed25519
        # signature. The epoch gate below mutates rotation state, so it
        # must never run on an unauthenticated envelope.
        _protected, payload = _try_unseal(ctx, rid, envelope)
    except SealingError as exc:
        raise CliError(f"unseal_{exc.code}", f"{exc}")
    try:
        manager.on_data_event_epoch(rid, int(protected["key_epoch"]))
    except RotationError as exc:
        if exc.code == "unknown_future_epoch":
            sightings = _bump_retry_sighting(
                ctx.conn, rid, object_name, "unknown_future_epoch"
            )
            if sightings > MAX_UNKNOWN_EPOCH_SIGHTINGS:
                raise CliError(
                    "epoch_rejected",
                    f"epoch {protected['key_epoch']} still unknown after"
                    f" {sightings} sightings; giving up",
                ) from exc
            return {"outcome": "retry_pending", "surfaces": 0, "receipts_queued": 0}
        raise CliError("epoch_rejected", f"{exc}")
    # Replay records are bound to (event_id, envelope digest): a nonce hit
    # is only an idempotent accept when the bytes are byte-identical.
    # Nonce reuse with different bytes is quarantined loudly instead of
    # being swallowed with a success report. Rows written before the
    # binding columns existed carry no digest to compare against; they
    # quarantine too, because exact redeliveries never reach this check
    # (the existing-event byte comparison above accepts them) and
    # anything else reusing a legacy nonce is unverifiable.
    nonce_row = ctx.conn.execute(
        "SELECT event_id, envelope_digest FROM replay_guard WHERE replay_nonce = ?",
        (protected["replay_nonce"],),
    ).fetchone()
    if nonce_row is not None:
        digest = hashlib.sha256(data).hexdigest()
        if (
            nonce_row["envelope_digest"] is not None
            and nonce_row["event_id"] == event_id
            and nonce_row["envelope_digest"] == digest
        ):
            # Byte-identical redelivery of the bound envelope.
            return {"outcome": "accepted", "surfaces": 0, "receipts_queued": 0}
        raise CliError(
            "nonce_reuse", "replay nonce reused with different event bytes"
        )
    created = protected["created_at"]
    if created > add_seconds(now, FUTURE_TOLERANCE_SECONDS):
        raise CliError("clock_future", "event created_at is too far in the future")
    if created < add_seconds(now, -ACCEPT_WINDOW_DAYS * 24 * 3600):
        raise CliError("expired_window", "event is older than the 7-day window")
    # G15: per-relationship ingress quota, checked after authentication
    # and window validation but before the receive commit. Over-quota
    # objects stay on the relay (retry_pending), not in quarantine: the
    # rolling window admits them later, and quarantining a flood would
    # both hide the evidence and burn the quarantine table.
    quota_hold = _check_ingress_quota(ctx, rid, now)
    if quota_hold is not None:
        return quota_hold
    event_type = protected["event_type"]
    if event_type == "identity.rotated":
        # Verify the rotation announcement against the sender's pinned
        # identity BEFORE anything is stored: a bogus announcement is
        # quarantined without touching the event log.
        try:
            _verify_identity_rotation_against_pinned(payload, protected["sender"])
        except IdentityRotationError as exc:
            raise CliError(
                "identity_rotation_rejected", f"{exc.code}: {exc}"
            ) from exc
    expires_at = add_seconds(
        now,
        max(
            _ts_delta(created, 7 * 24 * 3600 + 3600),
            7 * 24 * 3600,
        ),
    )
    # The receive commit must be one real transaction: the event row, the
    # replay guard, the staged projection input, the projection queue row,
    # the surface queue row, and the accepted receipt all commit or roll
    # back together. ``with ctx.conn:`` is not enough: every connection is
    # opened with isolation_level=None (autocommit), so the context manager
    # commits nothing and a crash between statements used to leave the
    # event stored but never projected or surfaced (silent loss).
    new_seq = int(protected["sender_seq"])
    # Bound the forward jump BEFORE committing: one signed envelope with
    # sender_seq near the schema max would otherwise make the projection's
    # gap-fill loop insert ~9e15 sequence_gaps rows in this transaction.
    last_row = ctx.conn.execute(
        "SELECT last_seq FROM sender_sequence WHERE relationship_id = ? AND sender = ?",
        (rid, sender_identity),
    ).fetchone()
    last_seq = int(last_row["last_seq"]) if last_row else 0
    if new_seq - last_seq > MAX_SEQ_GAP:
        raise CliError(
            "seq_gap_too_large",
            f"sender_seq {new_seq} jumps {new_seq - last_seq} past last_seq"
            f" {last_seq}; max forward jump is {MAX_SEQ_GAP}",
        )
    try:
        with transaction(ctx.conn):
            ctx.conn.execute(
                "INSERT OR IGNORE INTO conversations (conversation_id) VALUES (?)",
                (protected["conversation_id"],),
            )
            ctx.conn.execute(
                "INSERT OR IGNORE INTO threads (thread_id, conversation_id) "
                "VALUES (?, ?)",
                (
                    protected["thread_id"],
                    protected["conversation_id"],
                ),
            )
            # Fork: same (sender, seq) already holds a different event.
            # Out-of-order (new event, seq <= last_seq) is accepted; the
            # relay does not guarantee upload order. The sender column is
            # the authenticated protected["sender"], never the current
            # peer identity, so old-key and new-key traffic cannot collide.
            clash = ctx.conn.execute(
                "SELECT event_id FROM events WHERE relationship_id = ? "
                "AND sender = ? AND sender_seq = ? AND event_id != ?",
                (rid, sender_identity, new_seq, event_id),
            ).fetchone()
            if clash is not None:
                raise CliError(
                    "sequence_fork",
                    f"sender sequence {new_seq} already used",
                )
            ctx.conn.execute(
                "INSERT INTO sender_sequence (relationship_id, sender, last_seq) "
                "VALUES (?, ?, ?) ON CONFLICT(relationship_id, sender) "
                "DO UPDATE SET last_seq = MAX(last_seq, excluded.last_seq)",
                (rid, sender_identity, new_seq),
            )
            ctx.conn.execute(
                "INSERT INTO events (event_id, relationship_id, conversation_id, "
                "thread_id, sender, sender_seq, created_at, key_epoch, event_type, "
                "replay_nonce, sealed_envelope) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    rid,
                    protected["conversation_id"],
                    protected["thread_id"],
                    sender_identity,
                    new_seq,
                    created,
                    int(protected["key_epoch"]),
                    event_type,
                    protected["replay_nonce"],
                    data,
                ),
            )
            ctx.conn.execute(
                "INSERT INTO replay_guard (replay_nonce, event_id,"
                " envelope_digest, expires_at) VALUES (?, ?, ?, ?)",
                (
                    protected["replay_nonce"],
                    event_id,
                    hashlib.sha256(data).hexdigest(),
                    expires_at,
                ),
            )
            record_projection_input(
                ctx.conn,
                event_id=event_id,
                event_type=event_type,
                payload=payload,
                reply_to=protected.get("reply_to"),
                # G13: the receiver acceptance time is the single `now`
                # computed at the top of this receive, not a second
                # utcnow() call. Poll closure, responded_at, the ingress
                # quota, and rebuilds all key off this one timestamp.
                received_at=now,
            )
            ctx.conn.execute(
                "INSERT INTO projection_queue (event_id, queued_at) VALUES (?, ?)",
                (event_id, now),
            )
            snap = policy_snapshot(ctx.conn, rid)
            action = surface_action(snap["mode"])
            ctx.conn.execute(
                "INSERT OR IGNORE INTO surface_queue "
                "(event_id, policy_snapshot, queued_at) VALUES (?, ?, ?)",
                (event_id, _canon_text(snap), now),
            )
            surfaces = 0 if action == "persist_only" else 1
            receipts_queued = 0
            if accepted_receipt_permitted(ctx.conn, rid) and event_type not in (
                "receipt.accepted",
                "receipt.seen",
            ):
                _queue_accepted_receipt(
                    ctx, rid, peer_id, manager, event_id, now
                )
                receipts_queued = 1
    except CliError:
        raise
    except sqlite3.IntegrityError as exc:
        raise CliError("integrity_conflict", f"storage conflict: {exc}")
    acc["surfaces"] += surfaces
    acc["receipts_queued"] += receipts_queued
    # Incremental projection (outside the atomic commit, per the plan), but
    # itself atomic per event: a crash between the handler's statements
    # rolls back, so redelivery re-applies the whole event and the
    # projection converges exactly once.
    try:
        event_row = dict(
            ctx.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        )
        event_row["payload"] = payload
        event_row["reply_to"] = protected.get("reply_to")
        with transaction(ctx.conn):
            apply_event(ctx.conn, event_row)
            # G15: acknowledge the projection_queue row in the same
            # transaction as the successful projection.
            ctx.conn.execute(
                "DELETE FROM projection_queue WHERE event_id = ?;",
                (event_id,),
            )
    except ProjectionError as exc:
        # Quarantine insert and projection-queue delete must be atomic for
        # the same autocommit reason as the receive commit above.
        with transaction(ctx.conn):
            quarantine_event(
                ctx.conn,
                rid,
                sender_identity,
                new_seq,
                event_id,
                f"projection_{exc.code}",
            )
            ctx.conn.execute(
                "DELETE FROM projection_queue WHERE event_id = ?", (event_id,)
            )
        return _quarantine_outcome(
            ctx, rid, object_name, f"projection_{exc.code}", str(exc)
        )
    if event_type == "identity.rotated":
        # The announcement was verified pre-commit; apply the peer
        # identity update now. A crash between the commit and this update
        # is converged by the duplicate resume path.
        try:
            _apply_identity_rotation(ctx, rid, payload, protected["sender"])
        except IdentityRotationError as exc:
            return _quarantine_outcome(
                ctx, rid, object_name, "identity_rotation_rejected", str(exc)
            )
    # Rotation hooks and relationship.ready activation. Rotation events go
    # through the marking wrapper so a post-commit crash converges via the
    # per-poll reconciler instead of losing the side effects.
    if event_type in _ROTATION_EVENT_TYPES:
        _run_rotation_hooks(
            ctx, rid, manager, event_type, payload, event_id, int(protected["key_epoch"])
        )
    else:
        try:
            _post_receive_hooks(
                ctx, rid, manager, event_type, payload, event_id, int(protected["key_epoch"])
            )
        except Exception as exc:
            print(f"warning: post-receive hook failed: {exc}", file=sys.stderr)
    return {"outcome": "accepted", "surfaces": surfaces, "receipts_queued": receipts_queued}


def _ts_delta(ts: str, delta_seconds: int) -> int:
    """Seconds from now until ts+delta (negative if already past)."""
    target = parse_timestamp(ts).timestamp()
    now = datetime.now(timezone.utc).timestamp()
    return int(target + delta_seconds - now)


def _post_receive_hooks(
    ctx: Ctx,
    rid: str,
    manager: RotationManager,
    event_type: str,
    payload: dict,
    event_id: str,
    key_epoch: int,
) -> None:
    rel = get_relationship(ctx.conn, rid)
    if event_type == "security.key.prepare":
        ack = manager.on_prepare(rid, payload, event_id)
        # Idempotent re-drive (crash between the ack send and the processed
        # marker, or a redelivered prepare) must not emit a duplicate ack:
        # the peer's on_ack is idempotent, but the extra event is noise.
        # The check reads the durable outbox, so a crash before the send
        # persisted still re-sends on re-drive.
        if not _ack_already_sent(ctx, rid, event_id):
            _send_event(ctx, rel, "security.key.ack", ack)
    elif event_type == "security.key.ack":
        manager.on_ack(rid, payload)
    elif event_type == "security.key.confirm":
        manager.on_confirm(rid, payload)
    elif event_type == "security.key.commit":
        manager.on_commit(rid, payload)
    elif event_type == "relationship.ready":
        _maybe_mark_active_after_ready(ctx, rid)
    else:
        try:
            manager.note_decrypted_new_wrap(rid, key_epoch)
        except Exception:
            pass
        try:
            # R10: count toward the relationship's current epoch only;
            # delayed old-epoch traffic must not bump a historical row.
            manager.note_accepted_event(rid)
        except Exception:
            pass


_ROTATION_EVENT_TYPES = (
    "security.key.prepare",
    "security.key.ack",
    "security.key.confirm",
    "security.key.commit",
)


def _mark_rotation_processed(
    conn, event_id: str, rid: str, event_type: str
) -> None:
    """Record that a rotation event's post-receive hooks completed.

    INSERT OR IGNORE: the marker is idempotent, so a crash between the
    hooks and this insert simply re-drives the (idempotent) hooks.
    """
    conn.execute(
        "INSERT OR IGNORE INTO rotation_processed_events "
        "(event_id, relationship_id, event_type, processed_at) "
        "VALUES (?, ?, ?, ?)",
        (event_id, rid, event_type, utcnow()),
    )


def _ack_already_sent(ctx: Ctx, rid: str, prepare_event_id: str) -> bool:
    """True when an ack for this prepare is already durably enqueued.

    The receive hook re-drives after a crash between the ack send and the
    processed marker; without this check every re-drive would emit a
    duplicate ack event. Reads the events table (what _send_event
    persisted), so a crash before the send completed still re-sends.
    """
    row = ctx.conn.execute(
        "SELECT 1 FROM events e JOIN event_payloads p "
        "ON p.event_id = e.event_id "
        "WHERE e.relationship_id = ? AND e.event_type = 'security.key.ack' "
        "AND e.sender = ? "
        "AND json_extract(p.payload, '$.prepare_event_id') = ? LIMIT 1",
        (rid, ctx.identity_id, prepare_event_id),
    ).fetchone()
    return row is not None


def _run_rotation_hooks(
    ctx: Ctx,
    rid: str,
    manager: RotationManager,
    event_type: str,
    payload: dict,
    event_id: str,
    key_epoch: int,
) -> None:
    """Run rotation post-receive hooks and record the outcome.

    Marks ``rotation_processed_events`` when the hooks complete (side
    effects, including the ack send, are done) or when the rotation state
    machine deterministically rejects the event (its answer is final: the
    conflict is quarantined, or the event was never valid). Transient
    failures stay unmarked so the per-poll reconciler retries them.
    """
    try:
        _post_receive_hooks(
            ctx, rid, manager, event_type, payload, event_id, key_epoch
        )
    except (RotationError, ConfirmRejected) as exc:
        # Deterministic rejection: re-driving would give the same answer
        # (and for conflicting prepares, would duplicate the quarantine
        # row), so mark it processed instead of retrying forever.
        print(
            f"warning: rotation hook rejected {event_type} {event_id} "
            f"({getattr(exc, 'code', 'rejected')}): {exc}",
            file=sys.stderr,
        )
    except Exception as exc:
        print(
            f"warning: rotation hook failed for {event_type} {event_id}: "
            f"{exc}; will retry on a later poll",
            file=sys.stderr,
        )
        return
    _mark_rotation_processed(ctx.conn, event_id, rid, event_type)


def _reconcile_rotation_events(ctx: Ctx, limit: int = 50) -> int:
    """Re-drive hooks for accepted rotation events that missed them.

    Crash gap: the receive commit is atomic, but the process can die
    between the commit and the post-receive hooks (or between the hooks
    and the processed marker). Such events are accepted but their
    rotation side effects, including the ack send, never ran. This scans
    for accepted incoming security.key.* events without a processed
    marker and re-runs their hooks; every hook is idempotent, so a
    partially applied event converges instead of duplicating.
    Returns the number of events re-driven. Bounded per poll.
    """
    rows = ctx.conn.execute(
        "SELECT e.event_id, e.relationship_id, e.event_type, e.key_epoch, "
        "p.payload FROM events e "
        "JOIN event_payloads p ON p.event_id = e.event_id "
        "LEFT JOIN rotation_processed_events r ON r.event_id = e.event_id "
        "WHERE e.event_type IN ('security.key.prepare', 'security.key.ack', "
        "'security.key.confirm', 'security.key.commit') "
        "AND e.sender != ? AND r.event_id IS NULL "
        "ORDER BY e.rowid LIMIT ?",
        (ctx.identity_id, limit),
    ).fetchall()
    if not rows:
        return 0
    manager = RotationManager(ctx.conn, ctx.keys_dir)
    redriven = 0
    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except ValueError:
            continue
        _run_rotation_hooks(
            ctx,
            row["relationship_id"],
            manager,
            row["event_type"],
            payload,
            row["event_id"],
            int(row["key_epoch"]),
        )
        redriven += 1
    return redriven


def _rotation_maintenance(ctx: Ctx) -> None:
    """Per-poll rotation housekeeping: sweep plus hook reconciliation.

    Sweep discards lost-ack candidates and retires old keys; the
    reconciler re-drives post-receive hooks for accepted rotation events
    that a post-commit crash left unprocessed. Neither ever fails the
    poll: both report loudly and continue.
    """
    _sweep_rotations(ctx)
    try:
        redriven = _reconcile_rotation_events(ctx)
    except Exception as exc:
        print(f"warning: rotation reconciliation failed: {exc}", file=sys.stderr)
    else:
        if redriven:
            print(
                f"rotation reconciliation: re-drove hooks for "
                f"{redriven} event(s)",
                file=sys.stderr,
            )


def prune_replay_entries(ctx: Ctx) -> int:
    """Delete expired replay-guard entries. Returns rows removed.

    Runs after successful receives (and any other CLI lifecycle point
    that wants it) so the shared replay_guard table stays bounded.
    Never raises: pruning is hygiene, not protocol.
    """
    try:
        return StoreReplayGuard(ctx.conn).prune(utcnow())
    except Exception:
        return 0


def _receive_relationship(
    ctx: Ctx, rid: str, time_budget: float, clock_skew_seconds: Optional[float] = None
) -> tuple[int, dict]:
    transport = _transport_for(ctx, rid, "receive")
    acc = {"surfaces": 0, "receipts_queued": 0}

    def receive_fn(relationship_id: str, object_name: str, data: bytes) -> dict:
        return _receive_object(ctx, relationship_id, object_name, data, acc)

    def policy_callback(relationship_id: str) -> dict:
        snap = policy_snapshot(ctx.conn, relationship_id)
        return {"delivery_mode": snap["mode"], "muted": False}

    code, result = run_once(
        transport,
        rid,
        receive_fn,
        state_dir=ctx.state_dir,
        min_poll_interval=0.0,
        time_budget=time_budget,
        policy_callback=policy_callback,
        # Rotation housekeeping on every watcher poll cycle: sweep
        # discards lost-ack candidates and retires old keys, and the
        # reconciler re-drives post-receive hooks for accepted rotation
        # events that a post-commit crash left unprocessed.
        maintenance_callback=lambda: _rotation_maintenance(ctx),
    )
    receipts_sent = 0
    if code in (EXIT_OK, EXIT_RETRYABLE, EXIT_PARTIAL_TIMEOUT):
        # Release accepted receipts (and any due scheduled sends) that the
        # receive commit queued in the scheduler outbox, then push them.
        try:
            due = scheduler.run_due(
                ctx.conn, utcnow(), _release_fn(ctx),
                clock_skew_seconds=clock_skew_seconds,
            )
            receipts_sent = len(due.get("released", []))
            _warn_expired_by_run_due(due)
        except Exception as exc:
            print(f"warning: release failed: {exc}", file=sys.stderr)
        _flush_send_transports(ctx, [rid])
    # Replay hygiene (Medium 1): prune expired replay-guard entries after
    # a successful receive so the table stays bounded. The v0.1 and v0.2
    # replay entries share this table and expire by acceptance window.
    if code == EXIT_OK:
        result["replay_pruned"] = prune_replay_entries(ctx)
    result["receipts_sent"] = receipts_sent
    return code, result


def _materialize_attachments(ctx: "Ctx", relationship_ids: list[str]) -> dict[str, int]:
    """Write pending attachment bytes to disk.

    Finds attachments rows with stored_path NULL (recorded by the
    message.created projection), decodes the base64 from the stored
    event payload, verifies size and SHA-256, and writes the file to
    <state_dir>/attachments/<relationship_id>/<event_id>_<filename>
    with mode 600. Updates stored_path on success; leaves the row
    pending on any failure so the next receive retries.

    Returns {"materialized": n, "failed": m}. Never raises: a failed
    attachment must not fail the receive run.
    """
    import base64
    import binascii
    import hashlib
    import json
    import os

    result = {"materialized": 0, "failed": 0}
    if not relationship_ids:
        return result
    placeholders = ",".join("?" for _ in relationship_ids)
    try:
        rows = ctx.conn.execute(
            "SELECT a.event_id, a.relationship_id, a.filename, a.size,"
            " a.sha256, p.payload"
            " FROM attachments a JOIN event_payloads p"
            " ON p.event_id = a.event_id"
            f" WHERE a.stored_path IS NULL AND a.relationship_id IN ({placeholders});",
            tuple(relationship_ids),
        ).fetchall()
    except Exception:
        return result
    for row in rows:
        event_id = row["event_id"]
        rid = row["relationship_id"]
        try:
            payload = json.loads(row["payload"])
            data_b64 = payload["attachment"]["data"]
            raw = base64.b64decode(data_b64, validate=True)
        except (ValueError, KeyError, TypeError, binascii.Error):
            result["failed"] += 1
            continue
        if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            result["failed"] += 1
            continue
        safe_name = os.path.basename(row["filename"]) or "attachment"
        if safe_name in (".", ".."):
            safe_name = "attachment"
        target_dir = ctx.state_dir / "attachments" / rid
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            # 0o700 on the per-relationship dir: attachments are private.
            os.chmod(target_dir, 0o700)
            target = target_dir / f"{event_id}_{safe_name}"
            # Write to a temp name then rename: no torn files on crash.
            tmp = target.with_name(target.name + ".tmp")
            with open(tmp, "wb") as fh:
                fh.write(raw)
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
            os.chmod(target, 0o600)
        except OSError:
            result["failed"] += 1
            continue
        try:
            ctx.conn.execute(
                "UPDATE attachments SET stored_path = ? WHERE event_id = ?;",
                (str(target), event_id),
            )
            ctx.conn.commit()
            result["materialized"] += 1
        except Exception:
            result["failed"] += 1
    return result


def cmd_attachments_list(args: argparse.Namespace) -> int:
    """List received attachments and where they were written."""
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        if args.relationship:
            rid = ctx.resolve_relationship(args.relationship)["relationship_id"]
            rows = ctx.conn.execute(
                "SELECT event_id, filename, size, content_type, sha256,"
                " stored_path, received_at FROM attachments"
                " WHERE relationship_id = ? ORDER BY received_at;",
                (rid,),
            ).fetchall()
        else:
            rows = ctx.conn.execute(
                "SELECT event_id, relationship_id, filename, size, content_type,"
                " sha256, stored_path, received_at FROM attachments"
                " ORDER BY received_at;",
            ).fetchall()
        if args.json:
            print(_canon_text({"attachments": [dict(r) for r in rows]}))
        else:
            for r in rows:
                status = r["stored_path"] or "(pending materialization)"
                print(
                    f"{r['filename']} ({r['size']} bytes, {r['content_type'] or 'unknown type'})"
                    f"\n  event: {r['event_id']}\n  file: {status}"
                )
            if not rows:
                print("no attachments received")
        return 0
    finally:
        ctx.close()


def cmd_receive(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        _warn_overdue_scheduled(ctx)
        if args.relationship:
            rids = [ctx.resolve_relationship(args.relationship)["relationship_id"]]
        else:
            rows = ctx.conn.execute(
                "SELECT r.relationship_id FROM relationships r "
                "JOIN relay_config c ON c.relationship_id = r.relationship_id "
                "WHERE r.consent_state != 'revoked'"
            ).fetchall()
            rids = [r["relationship_id"] for r in rows]
        if not rids:
            raise CliError("no_relationships", "no relationships with a relay configured")
        codes: list[int] = []
        per: dict[str, dict] = {}
        totals = {
            "accepted": 0,
            "quarantined": 0,
            "retry_pending": 0,
            "surfaces": 0,
            "receipts_queued": 0,
            "receipts_sent": 0,
        }
        for rid in rids:
            try:
                code, result = _receive_relationship(
                    ctx, rid, float(args.timeout or 120),
                    clock_skew_seconds=args.clock_skew_seconds,
                )
            except CliError as exc:
                code, result = exc.exit_code, {"error": exc.code}
            except TransportError as exc:
                code, result = exc.exit_code, {"error": exc.code}
            except Exception as exc:
                code, result = EXIT_PERMANENT, {"error": type(exc).__name__}
            codes.append(code)
            per[rid] = result
            for key in totals:
                totals[key] += int(result.get(key, 0) or 0)
        exit_code = _receive_exit_precedence(codes)
        # Materialize any attachment bytes that arrived with this receive.
        # Best-effort: failures stay pending for the next run and never
        # fail the receive itself.
        try:
            att = _materialize_attachments(ctx, rids)
            totals["attachments_materialized"] = att["materialized"]
            totals["attachments_failed"] = att["failed"]
        except Exception:
            pass
        # Proactive retention: enforce plaintext-cache periods on every
        # receive run. The purge function existed but no runtime path ever
        # called it, so expired plaintext could linger indefinitely.
        # Best-effort: a purge failure must never fail the receive run.
        try:
            from muse_agent_social.policy import purge_expired_plaintext_cache

            purged = purge_expired_plaintext_cache(ctx.conn, ctx.state_dir)
            totals["plaintext_purged"] = purged
        except Exception:
            pass
        if args.json:
            print(_canon_text({"relationships": per, "totals": totals}))
        else:
            for rid, result in per.items():
                print(
                    f"{rid}: exit={per[rid].get('exit_code')} "
                    f"accepted={result.get('accepted', 0)} "
                    f"quarantined={result.get('quarantined', 0)} "
                    f"retry_pending={result.get('retry_pending', 0)} "
                    f"surfaces={result.get('surfaces', 0)} "
                    f"receipts_queued={result.get('receipts_queued', 0)}"
                )
            print(f"exit={exit_code}")
        return exit_code
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# mas rotate
# ---------------------------------------------------------------------------


# (legacy _atomic_write_bytes removed; see the tombstone note above.
# Rotation persists via muse_agent_social._keyfiles.atomic_write_file.)


def _rotate_identity(ctx: Ctx, args: argparse.Namespace) -> int:
    """Rotate the identity signing key (H11).

    Uses the shipped crypto (rotate_identity_key / verify_identity_rotation),
    notifies each active peer with a signed identity.rotated event (sent as
    the old identity, before the local switch), reissues the local agent card
    under the new identity id, backs up the old seed and card, and persists
    the rotation announcement for out-of-band delivery as a fallback.
    """
    if not args.confirm_identity:
        raise CliError(
            "confirmation_required",
            "rotating the identity key changes your identity_id; existing "
            "peers will not recognize the new identity until they receive "
            "the rotation announcement. Pass --confirm-identity to proceed.",
        )
    from .crypto.identity import derive_identity_hierarchy
    from .crypto.rotation import (
        IdentityRotationError,
        rotate_identity_key,
        verify_identity_rotation,
    )

    old_card = ctx.card
    new_seed = secrets.token_bytes(32)
    new_hierarchy = derive_identity_hierarchy(new_seed)
    try:
        announcement = rotate_identity_key(
            old_card,
            ctx.hierarchy.ed25519_private,
            new_hierarchy.ed25519_private,
        )
    except IdentityRotationError as exc:
        raise CliError("identity_rotation_failed", str(exc))
    # Fail closed: verify with the shipped verifier before touching disk.
    if not verify_identity_rotation(announcement, old_card):
        raise CliError(
            "identity_rotation_failed",
            "self-verification of the rotation announcement failed; "
            "no state was changed",
        )

    # Notify each active peer BEFORE switching the local identity: the
    # identity.rotated event is sealed and signed as the OLD identity,
    # which is what the peer still has pinned. After the switch, the
    # peer could not attribute the announcement.
    active_rels = [
        dict(r)
        for r in ctx.conn.execute(
            "SELECT * FROM relationships WHERE consent_state = 'active'"
        ).fetchall()
    ]
    for rel in active_rels:
        try:
            _send_event(ctx, rel, "identity.rotated", announcement)
        except CliError as exc:
            raise CliError(
                "identity_rotation_notify_failed",
                f"could not notify peer on {rel['relationship_id']}: {exc}; "
                "no state was changed",
            ) from exc

    identity_ref = ctx.config.get("identity_ref") or {}
    seed_rel = identity_ref.get("master_seed_path") or f"keys/{_MASTER_SEED_NAME}"
    card_rel = identity_ref.get("card_path") or _CARD_NAME
    seed_path = ctx.state_dir / seed_rel
    card_path = ctx.state_dir / card_rel
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # Back up the old seed and card first; losing the old seed would brick
    # anything sealed to the old identity. All persistence below goes through
    # the hardened _keyfiles writers (tmp + fsync + atomic publish, 0600 for
    # key material, no 0644 window).
    backup_seed = seed_path.with_name(f"{seed_path.name}.backup-{stamp}")
    backup_card = card_path.with_name(f"{card_path.name}.backup-{stamp}")
    try:
        old_seed_bytes = seed_path.read_bytes()
    except OSError as exc:
        raise CliError(
            "identity_rotation_backup_failed",
            f"cannot read the old master seed for backup: {exc}",
        ) from exc
    try:
        store_private_key(backup_seed, old_seed_bytes)
        if card_path.is_file():
            atomic_write_file(backup_card, card_path.read_bytes(), 0o644)
        # The new seed and card publish as one atomic pair: both temp
        # files are fully durable before either becomes visible, and a
        # journal makes an interrupted publish re-drivable at startup
        # (see recover_pending_pair), so a crash can never leave the
        # seed and card describing different identities.
        atomic_write_pair(
            seed_path,
            new_seed,
            0o600,
            card_path,
            (_canon_text(announcement["new_card"]) + "\n").encode("utf-8"),
            0o644,
            journal_path=ctx.state_dir / _PENDING_IDENTITY_PAIR,
        )
    except (FileExistsError, KeyFileError, OSError) as exc:
        # After the pair-publish journal commit point the new identity is
        # committed (recover_pending_pair completes it at startup), so
        # claiming the old identity is still in place would be a lie.
        pending = (ctx.state_dir / _PENDING_IDENTITY_PAIR).exists()
        hint = (
            "the rotation was committed before the interruption; restart "
            "to complete the pending publish"
            if pending
            else "the old identity is still in place"
        )
        raise CliError(
            "identity_rotation_failed",
            f"could not persist the rotation to disk: {exc}; {hint}",
        ) from exc
    rot_dir = ctx.state_dir / "identity-rotations"
    rot_dir.mkdir(parents=True, exist_ok=True)
    ann_path = rot_dir / f"{new_hierarchy.identity_id}.json"
    try:
        atomic_write_file(
            ann_path,
            (_canon_text(announcement) + "\n").encode("utf-8"),
            0o644,
        )
    except (FileExistsError, KeyFileError, OSError) as exc:
        raise CliError(
            "identity_rotation_failed",
            f"could not save the rotation announcement: {exc}",
        ) from exc

    print(
        "peers notified over the relay: "
        f"{len(active_rels)} active relationship(s) received identity.rotated"
        if active_rels
        else "no active relationships: no peer notification was sent"
    )
    print(
        f"identity rotated: {ctx.identity_id} -> {new_hierarchy.identity_id}"
    )
    print(f"new card: {card_path}")
    print(f"announcement: {ann_path}")
    print(f"backups: {backup_seed}, {backup_card}")
    print(
        "note: the announcement file is also saved for out-of-band "
        "delivery as a fallback (e.g. a peer that was offline).",
        file=sys.stderr,
    )
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        if args.identity:
            return _rotate_identity(ctx, args)
        if not args.relationship:
            raise CliError(
                "missing_relationship",
                "mas rotate needs --relationship (or --identity for "
                "identity-key rotation)",
            )
        rel = ctx.resolve_relationship(args.relationship)
        rid = rel["relationship_id"]
        manager = RotationManager(ctx.conn, ctx.keys_dir)
        action = (
            "prepare"
            if args.prepare
            else "ack"
            if args.ack
            else "confirm"
            if args.confirm
            else "commit"
            if args.commit
            else "status"
        )
        if action == "prepare":
            try:
                bundle = manager.begin_rotation(rid)
            except RotationError as exc:
                raise CliError("rotate_error", f"{exc.code}: {exc}")
            sent = _send_event(ctx, rel, "security.key.prepare", bundle["prepare"])
            print(
                f"rotation prepared: epoch {bundle['epoch']} "
                f"event {sent['event_id']} seq {sent['sender_seq']}"
            )
            return 0
        if action == "ack":
            row = ctx.conn.execute(
                "SELECT e.event_id, p.payload FROM event_payloads p "
                "JOIN events e ON e.event_id = p.event_id "
                "WHERE e.relationship_id = ? AND e.event_type = 'security.key.prepare' "
                "AND e.sender = ? ORDER BY e.created_at DESC LIMIT 1",
                (rid, rel["peer_identity_id"]),
            ).fetchone()
            if row is None:
                raise CliError("rotate_error", "no security.key.prepare received yet")
            try:
                ack = manager.on_prepare(
                    rid, json.loads(row["payload"]), row["event_id"]
                )
            except (RotationError, ConfirmRejected) as exc:
                raise CliError("rotate_error", f"{getattr(exc, 'code', 'rotate_error')}: {exc}")
            if _ack_already_sent(ctx, rid, row["event_id"]):
                print(f"rotation already acknowledged for prepare {row['event_id']}")
                return 0
            sent = _send_event(ctx, rel, "security.key.ack", ack)
            print(f"rotation acknowledged: event {sent['event_id']}")
            return 0
        if action == "confirm":
            # Build first, send, then mark: a failed send leaves the
            # rotation 'acknowledged' (retryable) instead of wedging it in
            # 'confirmed' with no confirm on the wire.
            try:
                confirm = manager.build_confirm_payload(rid)
            except (RotationError, ConfirmRejected) as exc:
                raise CliError("rotate_error", f"{getattr(exc, 'code', 'rotate_error')}: {exc}")
            sent = _send_event(ctx, rel, "security.key.confirm", confirm)
            try:
                manager.mark_confirmed(rid)
            except (RotationError, ConfirmRejected) as exc:
                raise CliError(
                    "rotate_error",
                    f"confirm sent as {sent['event_id']} but marking failed "
                    f"({getattr(exc, 'code', 'rotate_error')}): {exc}",
                )
            print(f"rotation confirmed: event {sent['event_id']}")
            return 0
        if action == "commit":
            # Build first, send, then mark: a failed send leaves the
            # rotation 'confirmed' (retryable) instead of wedging it in
            # 'committed' with no commit on the wire.
            try:
                commit = manager.build_commit_payload(rid)
            except (RotationError, ConfirmRejected) as exc:
                raise CliError("rotate_error", f"{getattr(exc, 'code', 'rotate_error')}: {exc}")
            sent = _send_event(ctx, rel, "security.key.commit", commit)
            try:
                manager.mark_committed(rid)
            except (RotationError, ConfirmRejected) as exc:
                raise CliError(
                    "rotate_error",
                    f"commit sent as {sent['event_id']} but marking failed "
                    f"({getattr(exc, 'code', 'rotate_error')}): {exc}",
                )
            print(f"rotation committed: event {sent['event_id']}")
            return 0
        epochs = ctx.conn.execute(
            "SELECT epoch, state, private_key_ref IS NOT NULL AS has_priv "
            "FROM key_epochs WHERE relationship_id = ? ORDER BY epoch",
            (rid,),
        ).fetchall()
        rotations = ctx.conn.execute(
            "SELECT epoch, role, phase, prior_epoch, deadline, new_wrap_seen, "
            "committed_at FROM key_rotations WHERE relationship_id = ? "
            "ORDER BY epoch",
            (rid,),
        ).fetchall()
        try:
            quarantined = manager.list_quarantine(rid)
        except RotationError:
            quarantined = []
        print(f"relationship {rid} key_epoch={rel['key_epoch']}")
        for e in epochs:
            print(
                f"  epoch {e['epoch']}: state={e['state']} "
                f"local_key={'yes' if e['has_priv'] else 'no (peer)'}"
            )
        for r in rotations:
            print(
                f"  rotation epoch {r['epoch']}: role={r['role']} phase={r['phase']} "
                f"prior={r['prior_epoch']} deadline={r['deadline']} "
                f"new_wrap_seen={r['new_wrap_seen']}"
            )
        for q in quarantined:
            print(f"  quarantined: {q}")
        return 0
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# mas migrate v01
# ---------------------------------------------------------------------------


def cmd_migrate_v01(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir) if args.state_dir else resolve_state_dir()
    ctx = Ctx(state_dir)
    try:
        actions = [
            name
            for name in ("dry_run", "stage", "verify", "cutover", "observe", "rollback")
            if getattr(args, name)
        ]
        if len(actions) != 1:
            raise CliError(
                "bad_args",
                "choose exactly one of --dry-run --stage --verify --cutover "
                "--observe --rollback",
            )
        action = actions[0]
        if not args.pair:
            raise CliError("bad_args", "migrate v01 needs --pair PAIR_ID")
        mctx = MigrationContext(
            state_dir=state_dir,
            legacy_state_dir=Path(args.legacy_state_dir)
            if args.legacy_state_dir
            else state_dir / "legacy",
            vault_dir=Path(args.vault_dir)
            if args.vault_dir
            else state_dir / "migration-vault",
            pair_id=args.pair,
            my_agent_id=args.my_agent_id or ctx.identity_id,
            peer_agent_id=args.peer_agent_id or "",
            role=args.role or "migrating",
        )
        if action == "cutover":
            if not args.confirm_live_pair:
                raise CliError(
                    "bad_args",
                    "cutover needs --confirm-live-pair: confirm the peer is live "
                    "on v0.2 before cutting over",
                )
            if not mctx.peer_agent_id:
                raise CliError("bad_args", "cutover needs --peer-agent-id")
            ready = ctx.conn.execute(
                "SELECT 1 FROM events WHERE event_type = 'migration.ready' "
                "AND sender = ? LIMIT 1",
                (mctx.peer_agent_id,),
            ).fetchone()
            if ready is None:
                raise CliError(
                    "migration_ready_missing",
                    "no peer-signed migration.ready event found; cutover refused",
                )
        try:
            if action == "dry_run":
                result = run_dry_run(mctx)
                out = {
                    "ok": result.ok,
                    "checks": [
                        {"name": c.name, "ok": c.ok, "detail": c.detail}
                        for c in result.checks
                    ],
                }
            elif action == "stage":
                out = stage(mctx)
            elif action == "verify":
                out = verify(mctx)
            elif action == "cutover":
                out = cutover(mctx)
            elif action == "observe":
                out = observe(mctx)
            else:
                out = rollback(mctx, reason=args.reason or "")
        except AwaitingPeer as exc:
            raise CliError("migration_awaiting_peer", f"{exc}")
        except MigrationError as exc:
            raise CliError("migration_error", f"{exc}")
        print(_canon_text(out))
        return 0
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# mas revoke
# ---------------------------------------------------------------------------


class _RevokeHooks:
    """teardown hooks backed by relay.json discovery and the GitHub API."""

    def __init__(
        self,
        state_dir: Path,
        token: Optional[str],
        delete_remote: bool,
    ) -> None:
        self.state_dir = state_dir
        self.token = token
        self.delete_remote = delete_remote
        try:
            self.relay_doc = json.loads(
                (state_dir / "relay.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            self.relay_doc = {}

    def discover_deploy_keys(self):
        return list(self.relay_doc.get("deploy_keys") or [])

    def discover_repos(self):
        return list(self.relay_doc.get("repos") or [])

    def _api(self, method: str, path: str):
        if not self.token:
            raise ProvisioningError(
                "no_token", "GitHub token required (--token or MAS_GITHUB_TOKEN)"
            )
        req = urllib.request.Request(
            f"https://api.github.com{path}",
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "mas-cli/0.2",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return "not_found"
            raise ProvisioningError("api_error", f"GitHub API {exc.code} on {path}")

    def revoke_deploy_key(self, ref: DeployKeyRef):
        try:
            repo = ref.repo
            if not repo:
                repos = self.discover_repos()
                first = repos[0] if repos else None
                repo = (
                    first.get("repo")
                    if isinstance(first, dict)
                    else first
                )
            if not repo:
                return "manual: no relay repo recorded"
            if not ref.key_id:
                return "manual: no deploy key id recorded"
            status = self._api("DELETE", f"/repos/{repo}/keys/{ref.key_id}")
            return "revoked" if status in (204, "not_found") else f"manual: HTTP {status}"
        except ProvisioningError as exc:
            return f"manual: {exc}"

    def delete_relay_repo(self, ref: RelayRef):
        if not self.delete_remote:
            return "manual: pass --delete-remote to delete the relay repository"
        try:
            status = self._api("DELETE", f"/repos/{ref.repo}")
            return "deleted" if status in (204, "not_found") else f"manual: HTTP {status}"
        except ProvisioningError as exc:
            return f"manual: {exc}"


def cmd_revoke(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        # Revoke resolves the EXACT relationship id only: no prefix
        # matching, no peer-label fallback. A typo must fail loudly,
        # never destroy the wrong relationship.
        try:
            rel = get_relationship(ctx.conn, args.relationship)
        except PairingError:
            raise CliError(
                "unknown_relationship",
                f"no relationship with id {args.relationship!r}; "
                "revoke needs the exact relationship id",
            )
        rid = rel["relationship_id"]
        peer_label = rel["peer_identity_id"][:24]
        if not args.yes:
            print(
                f"About to REVOKE relationship {rid} (peer {peer_label}...). "
                "This destroys private keys, relay state, and local history, "
                "and cannot be undone.",
                file=sys.stderr,
            )
            try:
                answer = input(
                    "Type the full relationship id to confirm, "
                    "or anything else to abort: "
                ).strip()
            except EOFError:
                answer = ""
            if answer != rid:
                raise CliError(
                    "revoke_aborted", "revoke aborted: no changes made"
                )
        token = args.token or os.environ.get("MAS_GITHUB_TOKEN")
        hooks = _RevokeHooks(ctx.state_dir, token, bool(args.delete_remote))
        # D10: no pre-cleanup here. teardown_relationship discovers relay
        # refs from relay_config BEFORE its own deletes, so deleting
        # relay_config first would blind relay-repo discovery (repos
        # claimed only by this relationship would look unclaimed and be
        # kept). teardown deletes event_payloads before events inside its
        # own transaction, and relay_config with the other
        # relationship-scoped rows.
        try:
            report = teardown_relationship(
                ctx.conn,
                ctx.state_dir,
                rid,
                hooks=hooks,
                reason_code=args.reason or "operator",
                peer_label=peer_label,
            )
        except TeardownError as exc:
            raise CliError("teardown_error", f"{exc.code}: {exc}")
        ctx.conn.commit()
        summary = {
            "relationship_id_sha256": report.relationship_id_sha256,
            "revoked_at": report.revoked_at,
            "reason_code": report.reason_code,
            "keys_destroyed": report.keys_destroyed,
            "deploy_keys_revoked": report.deploy_keys_revoked,
            "relay_repos_deleted": report.relay_repos_deleted,
            "files_deleted": report.files_deleted,
            "dirs_removed": report.dirs_removed,
            "tombstone_path": report.tombstone_path,
            "postcheck_scanned": report.postcheck_scanned,
            "postcheck_hits": report.postcheck_hits,
            "crypto_erasure_before_bulk": report.crypto_erasure_before_bulk,
            "dry_run": report.dry_run,
        }
        print(_canon_text(summary))
        return 0
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# mas inspect
# ---------------------------------------------------------------------------


def cmd_inspect_relationships(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        rows = ctx.conn.execute(
            "SELECT relationship_id, peer_identity_id, consent_state, key_epoch, "
            "created_at FROM relationships ORDER BY created_at"
        ).fetchall()
        if args.json:
            print(_canon_text([dict(r) for r in rows]))
        else:
            for r in rows:
                print(
                    f"{r['relationship_id']} peer={r['peer_identity_id'][:32]} "
                    f"state={r['consent_state']} epoch={r['key_epoch']}"
                )
        return 0
    finally:
        ctx.close()


def cmd_inspect_conversation(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        rel = ctx.resolve_relationship(args.relationship)
        rid = rel["relationship_id"]
        cid = args.conversation or rid
        limit = int(args.limit or 50)
        rows = ctx.conn.execute(
            "SELECT event_id, sender, sender_seq, created_at, body, format, "
            "reply_to, edited, retracted FROM messages "
            "WHERE relationship_id = ? AND conversation_id = ? "
            "ORDER BY created_at, sender, sender_seq LIMIT ?",
            (rid, cid, limit),
        ).fetchall()
        out = []
        for m in rows:
            md = dict(m)
            reactions = ctx.conn.execute(
                "SELECT emoji, sender FROM reactions WHERE target_event_id = ? "
                "AND active = 1",
                (m["event_id"],),
            ).fetchall()
            receipts = ctx.conn.execute(
                "SELECT kind, sender, at FROM receipts WHERE target_event_id = ?",
                (m["event_id"],),
            ).fetchall()
            md["reactions"] = [dict(r) for r in reactions]
            md["receipts"] = [dict(r) for r in receipts]
            out.append(md)
        if args.json or True:
            print(_canon_text(out))
        return 0
    finally:
        ctx.close()


def ack_surface_notification(conn: sqlite3.Connection, event_id: str) -> bool:
    """Acknowledge (delete) one surface_queue notification (G15).

    Returns True when a pending notification was acknowledged, False when
    no row matched (already acked or unknown id).
    """
    cur = conn.execute(
        "DELETE FROM surface_queue WHERE event_id = ?;", (event_id,)
    )
    conn.commit()
    return cur.rowcount == 1


def cmd_surface_list(args: argparse.Namespace) -> int:
    """List unacknowledged operator notifications (G15)."""
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        rows = ctx.conn.execute(
            "SELECT event_id, policy_snapshot, queued_at FROM surface_queue"
            " ORDER BY queued_at ASC, id ASC;"
        ).fetchall()
        out = [
            {
                "event_id": r["event_id"],
                "queued_at": r["queued_at"],
                "notification": json.loads(r["policy_snapshot"]),
            }
            for r in rows
        ]
        print(_canon_text({"notifications": out}))
        return 0
    finally:
        ctx.close()


def cmd_surface_ack(args: argparse.Namespace) -> int:
    """Acknowledge one operator notification (G15)."""
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        if not ack_surface_notification(ctx.conn, args.event_id):
            raise CliError(
                "unknown_notification",
                f"no pending notification for {args.event_id}",
            )
        print(f"acknowledged {args.event_id}")
        return 0
    finally:
        ctx.close()


def cmd_inspect_queue(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        def count(table: str, where: str = "", params: tuple = ()) -> int:
            q = f"SELECT COUNT(*) FROM {table}" + (f" WHERE {where}" if where else "")
            return int(ctx.conn.execute(q, params).fetchone()[0])

        out = {
            "scheduler_queue": {
                row["state"]: row["n"]
                for row in ctx.conn.execute(
                    "SELECT state, COUNT(*) AS n FROM scheduler_queue GROUP BY state"
                ).fetchall()
            },
            "transport_mutations": {
                row["state"]: row["n"]
                for row in ctx.conn.execute(
                    "SELECT state, COUNT(*) AS n FROM transport_mutations GROUP BY state"
                ).fetchall()
            },
            "surface_queue": count("surface_queue"),
            "projection_queue": count("projection_queue"),
            "rotation_quarantine": count("rotation_quarantine"),
            "receive_quarantine": count("receive_quarantine"),
        }
        print(_canon_text(out))
        return 0
    finally:
        ctx.close()


def cmd_inspect_scheduled(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        state = args.state
        if state is not None and state not in scheduler.SCHEDULER_STATES:
            raise CliError("invalid_state", f"unknown scheduler state {state!r}")
        rows = []
        for r in scheduler.list_scheduled(ctx.conn, state):
            # inner_event is raw sealed bytes (up to 256 KiB); the inspect
            # surface shows its size and digest, not the bytes themselves.
            raw = bytes(r["inner_event"])
            rows.append(
                {
                    "scheduled_id": r["scheduled_id"],
                    "deliver_at": r["deliver_at"],
                    "expires_at": r["expires_at"],
                    "state": r["state"],
                    "release_failures": r["release_failures"],
                    "inner_event_bytes": len(raw),
                    "inner_event_sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        print(_canon_text(rows))
        return 0
    finally:
        ctx.close()


def cmd_inspect_policy(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        rel = ctx.resolve_relationship(args.relationship)
        policy = get_policy(ctx.conn, rel["relationship_id"])
        print(_canon_text(policy_snapshot(ctx.conn, rel["relationship_id"])))
        return 0
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# Delivery policy CLI (H10)
# ---------------------------------------------------------------------------

_POLICY_SET_KEYS = (
    "mode",
    "seen_receipts",
    "accepted_receipts",
    "expiry_handling",
    "expiry_shorten_after_seconds",
)
"""Keys accepted by `mas policy set`, in user-facing spelling."""

_POLICY_GET_KEYS = (
    "mode",
    "version",
    "seen_receipts_enabled",
    "accepted_receipts_enabled",
    "expiry_handling",
    "expiry_shorten_after_seconds",
    "updated_at",
)
"""Snapshot fields readable by `mas policy get`."""


def _parse_policy_bool(raw: str) -> bool:
    """Parse a user-supplied boolean for policy set."""
    text = raw.strip().lower()
    if text in ("true", "1", "yes", "on"):
        return True
    if text in ("false", "0", "no", "off"):
        return False
    raise CliError(
        "invalid_policy_value",
        f"invalid boolean {raw!r}; use one of true/false, 1/0, yes/no, on/off",
    )


def cmd_policy_set(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        rel = ctx.resolve_relationship(args.relationship)
        rid = rel["relationship_id"]
        key = args.key
        value = args.value
        try:
            if key == "mode":
                set_policy(ctx.conn, rid, value)
            elif key == "seen_receipts":
                set_seen_receipts_enabled(
                    ctx.conn, rid, _parse_policy_bool(value))
            elif key == "accepted_receipts":
                set_accepted_receipts_enabled(
                    ctx.conn, rid, _parse_policy_bool(value))
            elif key == "expiry_handling":
                if value == "shorten":
                    current = get_policy(ctx.conn, rid)
                    window = current.expiry_shorten_after_seconds
                    if window is None:
                        raise CliError(
                            "invalid_policy_value",
                            "expiry_handling=shorten needs a window: set "
                            "expiry_shorten_after_seconds <positive seconds> "
                            "first",
                        )
                    set_expiry_policy(ctx.conn, rid, "shorten", window)
                else:
                    set_expiry_policy(ctx.conn, rid, value)
            elif key == "expiry_shorten_after_seconds":
                try:
                    window = int(value)
                except ValueError:
                    raise CliError(
                        "invalid_policy_value",
                        "expiry_shorten_after_seconds must be a positive "
                        f"integer of seconds, got {value!r}",
                    )
                # Setting the window atomically enables shorten with it;
                # there is no chicken-and-egg with expiry_handling.
                set_expiry_policy(ctx.conn, rid, "shorten", window)
            else:
                raise CliError(
                    "unknown_policy_key",
                    f"unknown policy key {key!r}; valid keys: "
                    f"{', '.join(_POLICY_SET_KEYS)}",
                )
        except CliError:
            raise
        except Exception as exc:
            raise CliError("policy_set_failed", str(exc))
        snap = policy_snapshot(ctx.conn, rid)
        print(_canon_text(snap))
        return 0
    finally:
        ctx.close()


def cmd_policy_get(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        rel = ctx.resolve_relationship(args.relationship)
        rid = rel["relationship_id"]
        snap = policy_snapshot(ctx.conn, rid)
        policy = get_policy(ctx.conn, rid)
        snap["expiry_handling"] = policy.expiry_handling
        snap["expiry_shorten_after_seconds"] = policy.expiry_shorten_after_seconds
        if args.key is None:
            print(_canon_text(snap))
            return 0
        if args.key not in _POLICY_GET_KEYS:
            raise CliError(
                "unknown_policy_key",
                f"unknown policy key {args.key!r}; valid keys: "
                f"{', '.join(_POLICY_GET_KEYS)}",
            )
        value = snap[args.key]
        print(_canon_text(value) if not isinstance(value, str) else value)
        return 0
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _add_common(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--json", action="store_true", help="machine-readable output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mas", description="Muse Agent Social v0.2"
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help="installation state directory (default: platform state dir)",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subs = parser.add_subparsers(dest="command", required=True)

    p_init = subs.add_parser("init", help="initialize a new installation")
    p_init.add_argument("--display-name", default=None)
    p_init.add_argument("--principal", default=None)
    p_init.add_argument("--capability", action="append", default=None)
    p_init.set_defaults(func=cmd_init)

    p_pair = subs.add_parser("pair", help="pairing ceremony")
    pair_subs = p_pair.add_subparsers(dest="pair_command", required=True)

    p_invite = pair_subs.add_parser("invite", help="create a pairing invite")
    p_invite.add_argument("--capability", action="append", default=None)
    p_invite.add_argument("--policy-json", default=None)
    p_invite.add_argument("--out", default=None)
    p_invite.set_defaults(func=cmd_pair_invite)

    p_accept = pair_subs.add_parser("accept", help="accept a pairing invite")
    p_accept.add_argument("--invite-text", default=None)
    p_accept.add_argument("--invite-file", default=None)
    p_accept.add_argument(
        "--i-compared-phrase",
        action="store_true",
        help="confirm the 8-word phrase was compared out-of-band",
    )
    p_accept.add_argument("--out", default=None)
    p_accept.set_defaults(func=cmd_pair_accept)

    p_commit = pair_subs.add_parser("commit", help="commit a pairing (inviter)")
    p_commit.add_argument("--acceptance-file", required=True)
    p_commit.add_argument("--relay", required=True)
    p_commit.add_argument("--transport", default=None)
    p_commit.add_argument("--local-relay-dir", default=None)
    p_commit.add_argument("--token", default=None)
    p_commit.add_argument("--capability", action="append", default=None)
    p_commit.add_argument(
        "--i-compared-phrase",
        action="store_true",
        help="confirm the 8-word phrase was compared out-of-band",
    )
    p_commit.add_argument("--out", default=None)
    p_commit.set_defaults(func=cmd_pair_commit)

    p_ingest = pair_subs.add_parser(
        "ingest", help="ingest the inviter's signed commit (acceptor)"
    )
    p_ingest.add_argument("--commit-file", required=True)
    p_ingest.add_argument("--transport", default=None)
    p_ingest.add_argument("--local-relay-dir", default=None)
    p_ingest.add_argument("--token", default=None)
    p_ingest.set_defaults(func=cmd_pair_ingest)

    p_send = subs.add_parser("send", help="send a typed event")
    p_send.add_argument("--relationship", default=None)
    p_send.add_argument("--to", default=None)
    p_send.add_argument("--type", required=True)
    p_send.add_argument("--conversation", default=None)
    p_send.add_argument("--thread", default=None)
    p_send.add_argument("--reply-to", default=None)
    p_send.add_argument("--body", default=None)
    p_send.add_argument(
        "--file", default=None,
        help="attach a local file to a message.created event (at most 128 KiB); "
        "--body/--title become the caption",
    )
    p_send.add_argument("--format", default=None, choices=("plain", "markdown-safe"))
    p_send.add_argument("--title", default=None)
    p_send.add_argument("--url", default=None)
    p_send.add_argument("--target", default=None)
    p_send.add_argument("--emoji", default=None)
    p_send.add_argument("--question", default=None)
    p_send.add_argument("--choices", action="append", default=None)
    p_send.add_argument("--closes-at", default=None)
    p_send.add_argument("--multi-select", action="store_true")
    p_send.add_argument("--poll-id", default=None)
    p_send.add_argument("--choice-ids", action="append", default=None)
    p_send.add_argument("--human-confirmed", action="store_true")
    p_send.add_argument("--owner", default=None)
    p_send.add_argument("--due-at", default=None)
    p_send.add_argument("--status", default=None)
    p_send.add_argument("--note", default=None)
    p_send.add_argument("--prompt", default=None)
    p_send.add_argument("--response-shape", default=None)
    p_send.add_argument("--expires-at", default=None)
    p_send.add_argument("--request-id", default=None)
    p_send.add_argument("--answer", default=None)
    p_send.add_argument("--approved", action="store_true")
    p_send.add_argument("--approval-record", default=None)
    p_send.add_argument("--inner-event-id", default=None)
    p_send.add_argument("--deliver-at", default=None)
    p_send.add_argument("--scheduled-event-id", default=None)
    p_send.add_argument("--canceled-at", default=None)
    p_send.add_argument("--migration-id", default=None)
    p_send.add_argument(
        "--clock-skew-seconds", type=float, default=None,
        help="observed clock skew in seconds; passed to the scheduler so "
        "blocking skew rejects scheduled sends instead of silently "
        "mis-timing them",
    )
    p_send.add_argument("--epoch", type=int, default=None)
    p_send.add_argument("--prepare-event-id", default=None)
    p_send.add_argument("--new-agreement-key", default=None)
    p_send.add_argument("--prior-fingerprint", default=None)
    p_send.add_argument("--deadline", default=None)
    p_send.add_argument("--reason", default=None)
    p_send.add_argument("--dry-run", action="store_true")
    _add_common(p_send)
    p_send.set_defaults(func=cmd_send)

    p_human = subs.add_parser(
        "human",
        help="human-in-the-loop actions (the human's explicit step)",
    )
    human_subs = p_human.add_subparsers(dest="human_cmd", required=True)
    p_hrespond = human_subs.add_parser(
        "respond",
        help="answer a human.requested event; creates the local approval record",
    )
    p_hrespond.add_argument("--relationship", default=None)
    p_hrespond.add_argument("--to", default=None)
    p_hrespond.add_argument("--request-id", required=True)
    p_hrespond.add_argument("--answer", required=True)
    p_hrespond.add_argument("--approved", action="store_true")
    p_hrespond.add_argument("--rejected", action="store_true")
    p_hrespond.add_argument("--note", default=None)
    p_hrespond.add_argument("--conversation", default=None)
    p_hrespond.add_argument("--thread", default=None)
    p_hrespond.add_argument("--reply-to", default=None)
    p_hrespond.add_argument("--dry-run", action="store_true")
    _add_common(p_hrespond)
    p_hrespond.set_defaults(func=cmd_human_respond)
    p_hpoll = human_subs.add_parser(
        "poll-respond",
        help="human-confirmed poll response; creates the local approval record",
    )
    p_hpoll.add_argument("--relationship", default=None)
    p_hpoll.add_argument("--to", default=None)
    p_hpoll.add_argument("--poll-id", required=True)
    p_hpoll.add_argument("--choice-ids", action="append", required=True)
    p_hpoll.add_argument("--note", default=None)
    p_hpoll.add_argument("--conversation", default=None)
    p_hpoll.add_argument("--thread", default=None)
    p_hpoll.add_argument("--reply-to", default=None)
    p_hpoll.add_argument("--dry-run", action="store_true")
    _add_common(p_hpoll)
    p_hpoll.set_defaults(func=cmd_human_poll_respond)

    p_receive = subs.add_parser("receive", help="receive new relay objects")
    p_receive.add_argument("--relationship", default=None)
    p_receive.add_argument("--timeout", type=float, default=120.0)
    p_receive.add_argument(
        "--clock-skew-seconds", type=float, default=None,
        help="observed clock skew in seconds; passed to the scheduler so "
        "blocking skew rejects scheduled releases",
    )
    _add_common(p_receive)
    p_receive.set_defaults(func=cmd_receive)

    # G15: the surface_queue is the operator notification queue; it needs
    # a real acknowledgement path, not just a depth counter.
    p_surface = subs.add_parser(
        "surface", help="operator notifications (surface_queue)")
    surf_subs = p_surface.add_subparsers(dest="surface_cmd", required=True)
    p_slist = surf_subs.add_parser(
        "list", help="list unacknowledged operator notifications")
    _add_common(p_slist)
    p_slist.set_defaults(func=cmd_surface_list)
    p_sack = surf_subs.add_parser(
        "ack", help="acknowledge (dismiss) one operator notification")
    p_sack.add_argument(
        "event_id", help="event_id (or scheduled_id) of the notification")
    _add_common(p_sack)
    p_sack.set_defaults(func=cmd_surface_ack)

    p_att = subs.add_parser(
        "attachments", help="list files received as message attachments")
    att_subs = p_att.add_subparsers(dest="attachments_cmd", required=True)
    p_att_list = att_subs.add_parser("list", help="list received attachments")
    p_att_list.add_argument("--relationship", default=None)
    _add_common(p_att_list)
    p_att_list.set_defaults(func=cmd_attachments_list)

    p_policy = subs.add_parser(
        "policy", help="get or set per-relationship delivery policy")
    pol_subs = p_policy.add_subparsers(dest="policy_command", required=True)
    p_pol_set = pol_subs.add_parser("set", help="set a delivery policy key")
    p_pol_set.add_argument("relationship", help="relationship id")
    p_pol_set.add_argument(
        "key", help=f"one of: {', '.join(_POLICY_SET_KEYS)}")
    p_pol_set.add_argument("value", help="new value for the key")
    p_pol_set.set_defaults(func=cmd_policy_set)
    p_pol_get = pol_subs.add_parser("get", help="read delivery policy")
    p_pol_get.add_argument("relationship", help="relationship id")
    p_pol_get.add_argument(
        "key", nargs="?", default=None,
        help=f"optional field, one of: {', '.join(_POLICY_GET_KEYS)}")
    p_pol_get.set_defaults(func=cmd_policy_get)

    p_rotate = subs.add_parser("rotate", help="agreement key rotation ceremony")
    p_rotate.add_argument("--relationship", default=None)
    p_rotate.add_argument(
        "--identity", action="store_true",
        help="rotate the identity signing key instead of an agreement key",
    )
    p_rotate.add_argument(
        "--confirm-identity", action="store_true",
        help="required for --identity: acknowledge the identity_id changes",
    )
    p_rotate.add_argument("--prepare", action="store_true")
    p_rotate.add_argument("--ack", action="store_true")
    p_rotate.add_argument("--confirm", action="store_true")
    p_rotate.add_argument("--commit", action="store_true")
    p_rotate.add_argument("--status", action="store_true")
    p_rotate.set_defaults(func=cmd_rotate)

    p_migrate = subs.add_parser("migrate", help="v0.1 migration")
    mig_subs = p_migrate.add_subparsers(dest="migrate_command", required=True)
    p_v01 = mig_subs.add_parser("v01", help="migrate a v0.1 pair")
    p_v01.add_argument("--dry-run", action="store_true")
    p_v01.add_argument("--stage", action="store_true")
    p_v01.add_argument("--verify", action="store_true")
    p_v01.add_argument("--cutover", action="store_true")
    p_v01.add_argument("--observe", action="store_true")
    p_v01.add_argument("--rollback", action="store_true")
    p_v01.add_argument("--pair", default=None)
    p_v01.add_argument("--confirm-live-pair", action="store_true")
    p_v01.add_argument("--legacy-state-dir", default=None)
    p_v01.add_argument("--vault-dir", default=None)
    p_v01.add_argument("--my-agent-id", default=None)
    p_v01.add_argument("--peer-agent-id", default=None)
    p_v01.add_argument("--role", default=None)
    p_v01.add_argument("--reason", default=None)
    p_v01.set_defaults(func=cmd_migrate_v01)

    p_revoke = subs.add_parser("revoke", help="revoke a relationship")
    p_revoke.add_argument("--relationship", required=True)
    p_revoke.add_argument("--reason", default=None)
    p_revoke.add_argument("--token", default=None)
    p_revoke.add_argument("--delete-remote", action="store_true")
    p_revoke.add_argument(
        "--yes",
        action="store_true",
        help="skip the interactive confirmation prompt (for automation)",
    )
    p_revoke.set_defaults(func=cmd_revoke)

    p_inspect = subs.add_parser("inspect", help="inspect local state")
    insp_subs = p_inspect.add_subparsers(dest="inspect_command", required=True)
    p_rels = insp_subs.add_parser("relationships", help="list relationships")
    _add_common(p_rels)
    p_rels.set_defaults(func=cmd_inspect_relationships)
    p_conv = insp_subs.add_parser("conversation", help="show a conversation")
    p_conv.add_argument("--relationship", required=True)
    p_conv.add_argument("--conversation", default=None)
    p_conv.add_argument("--limit", type=int, default=50)
    _add_common(p_conv)
    p_conv.set_defaults(func=cmd_inspect_conversation)
    p_queue = insp_subs.add_parser("queue", help="show queue depths")
    _add_common(p_queue)
    p_queue.set_defaults(func=cmd_inspect_queue)
    p_policy = insp_subs.add_parser("policy", help="show delivery policy")
    p_policy.add_argument("--relationship", required=True)
    _add_common(p_policy)
    p_policy.set_defaults(func=cmd_inspect_policy)
    p_sched = insp_subs.add_parser(
        "scheduled", help="list scheduler rows (default: all states)"
    )
    p_sched.add_argument(
        "--state",
        default=None,
        help="filter by scheduler state: "
        + ", ".join(scheduler.SCHEDULER_STATES),
    )
    _add_common(p_sched)
    p_sched.set_defaults(func=cmd_inspect_scheduled)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as exc:
        print(f"error {exc.code}: {exc.message}", file=sys.stderr)
        return exc.exit_code
    except BrokenPipeError:
        return 1
    except Exception:
        import traceback

        traceback.print_exc(file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
