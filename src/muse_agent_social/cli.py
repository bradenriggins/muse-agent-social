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
import json
import os
import secrets
import sqlite3
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import __version__
from ._keyfiles import store_private_key
from .canonical import CanonicalizationError, restricted_jcs, strict_parse
from .compatibility.v01 import (
    LegacyError,
    LegacyPolicy,
    MemoryReplayStore,
    SeqAssigner,
    VaultError,
    adapt_v01,
    detect_v01,
    vault_load,
    verify_v01,
)
from .config import load_config, resolve_state_dir, save_config
from .crypto.identity import (
    derive_identity_hierarchy,
    generate_master_seed,
    parse_agreement_key,
    store_master_seed,
)
from .crypto.rotation import (
    ConfirmRejected,
    RotationError,
    RotationManager,
)
from .crypto.sealing import SealingError, seal_envelope, unseal_envelope
from .migrate import (
    AwaitingPeer,
    MigrationContext,
    MigrationError,
    cutover,
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
    PairingError,
    commit_pairing,
    create_acceptance,
    create_invite,
    generate_deploy_keypair,
    generate_relationship_keypair,
    get_relationship,
    ingest_commit,
    invite_uri,
    mark_active,
    pairing_phrase,
    parse_invite_uri,
    read_invite_file,
    record_verification,
    validate_invite,
)
from .policy.delivery import (
    accepted_receipt_permitted,
    get_policy,
    policy_snapshot,
    surface_action,
)
from .policy.limits import (
    ACCEPT_WINDOW_DAYS,
    FUTURE_TOLERANCE_SECONDS,
    MAX_ENVELOPE_BYTES,
    add_seconds,
)
from .transports.base import OBJECT_MAX_BYTES
from .store.db import open_db, utcnow
from .store.migrations import migrate
from .store.projections import (
    ProjectionError,
    apply_event,
    migrate_projections,
    quarantine_event,
    record_projection_input,
)
from .teardown import TeardownError, teardown_relationship
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
    return restricted_jcs(obj).decode("ascii")


def _new_uuid() -> str:
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# Context: one loaded installation
# ---------------------------------------------------------------------------

_CONFIG_NAME = "config.yaml"
_CARD_NAME = "agent-card.json"
_MASTER_SEED_NAME = "master.seed"

_CLI_DDL = """
CREATE TABLE IF NOT EXISTS relay_config (
    relationship_id TEXT PRIMARY KEY,
    provider        TEXT NOT NULL,
    repo_url        TEXT,
    slots_json      TEXT,
    local_dir       TEXT,
    role            TEXT,
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
"""


def _ensure_cli_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(_CLI_DDL)
    # Older installs predate the role column; add it idempotently.
    try:
        conn.execute("ALTER TABLE relay_config ADD COLUMN role TEXT")
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
        self.conn = open_db(state_dir)
        migrate(self.conn)
        migrate_projections(self.conn)
        from .transports.github import ensure_transport_tables

        ensure_transport_tables(self.conn)
        from .model.invites import _ensure_pairing_tables

        _ensure_pairing_tables(self.conn)
        from .crypto.rotation import _ensure_tables as _ensure_rotation_tables

        _ensure_rotation_tables(self.conn)
        _ensure_cli_tables(self.conn)

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


def _write_file_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


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
    return row


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
) -> None:
    ctx.conn.execute(
        "INSERT OR REPLACE INTO relay_config "
        "(relationship_id, provider, repo_url, slots_json, local_dir, role,"
        " created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            relationship_id,
            provider,
            repo_url,
            json.dumps(slots) if slots else None,
            local_dir,
            role,
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
    _write_file_private(card_path, (_canon_text(card) + "\n").encode("utf-8"))
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


def _load_invite_text(args: argparse.Namespace) -> str:
    if args.invite_file:
        try:
            return Path(args.invite_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise CliError("bad_args", f"cannot read invite file: {exc}")
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
        _write_file_private(
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
            "hand the URI to the peer out-of-band (file: use --out; "
            "QR: encode the URI above with any QR generator)",
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
            elif args.invite_file:
                invite = read_invite_file(args.invite_file)
            else:
                invite = parse_invite_uri(stripped)
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
        rel_priv, rel_pub_mb = generate_relationship_keypair()
        store_private_key(
            pair_dir / "relationship.key",
            rel_priv.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
        )
        deploy_pub = generate_deploy_keypair(pair_dir / "deploy")
        (pair_dir / "deploy.pub").write_text(deploy_pub + "\n", encoding="utf-8")
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
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
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
        try:
            # Consume the invite's one-use status on the inviter's ledger,
            # then record the human-approved phrase comparison.
            validate_invite(ctx.conn, invite)
            record_verification(
                ctx.conn, invite_id, (inviter_fp, acceptor_fp), human_approved=True
            )
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
        try:
            commit = commit_pairing(
                ctx.conn,
                acceptance,
                ctx.hierarchy.ed25519_private,
                commit_relay_url,
                slots,
                negotiated,
                keys_dir=ctx.keys_dir,
            )
        except PairingError as exc:
            raise CliError("pairing_error", f"{exc.code}: {exc}")
        relationship_id = commit["relationship_id"]
        deploy_keys: list = []
        repos: list = []
        if provider == "github":
            repo = _parse_github_repo(relay_url)
            token = _github_token(args)
            try:
                reg = register_peer_deploy_key(
                    repo,
                    acceptance["ssh_deploy_pubkey"],
                    deploy_key_title(relationship_id),
                    lambda: token,
                )
            except ProvisioningError as exc:
                raise CliError("provisioning_error", f"{exc.code}: {exc}")
            key_id = reg.get("id")
            deploy_keys.append(
                {
                    "id": key_id,
                    "title": deploy_key_title(relationship_id),
                    "key": acceptance["ssh_deploy_pubkey"],
                    "role": "peer",
                }
            )
            repos.append({"repo": repo, "transport": "github"})
        _write_relay_json(ctx, deploy_keys, repos)
        _save_relay_config(
            ctx, relationship_id, provider, relay_url, slots, local_dir,
            role="inviter",
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
_LEGACY_SEND_TYPES = ("note", "link", "article", "file-ref")


def _iso_now() -> str:
    return utcnow()


def _build_payload(args: argparse.Namespace) -> dict:
    """Build and schema-validate the typed payload for ``mas send``."""
    t = args.type
    if t == "message.created":
        if not args.body:
            raise CliError("bad_args", "message.created needs --body")
        payload = {
            "body": args.body,
            "format": args.format or "plain",
        }
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
                "human.responded needs --approval-record (local approval id; "
                "the CLI invocation itself is the human's approval)",
            )
        payload = {
            "request_id": args.request_id,
            "answer": args.answer,
            "approved": bool(args.approved),
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
            # Immediate local delivery; the receiver's replay guard makes a
            # retry-after-crash duplicate harmless.
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
) -> dict:
    """Persist, seal, and enqueue one outgoing event.

    Returns a summary dict with event_id, sender_seq, key_epoch and, when
    the event was released to the transport immediately, object_name.
    """
    rid = rel["relationship_id"]
    manager = RotationManager(ctx.conn, ctx.state_dir)
    try:
        manager.may_send(rid)
    except RotationError as exc:
        raise CliError("send_error", f"{exc.code}: {exc}")
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
    try:
        sealed = assign_and_persist_outgoing(
            ctx.conn, protected, payload, ctx.hierarchy.ed25519_private, recipients
        )
    except Exception as exc:
        raise CliError("send_error", f"persist failed: {exc}")
    # Project the sender's own event locally so both sides' projections
    # converge. assign_and_persist_outgoing already queued the projection;
    # the sender needs no surface decision for their own event.
    try:
        with ctx.conn:
            record_projection_input(
                ctx.conn,
                event_id=protected["event_id"],
                event_type=event_type,
                payload=payload,
                reply_to=reply_to,
            )
    except (ProjectionError, SchemaError, sqlite3.IntegrityError) as exc:
        raise CliError("send_error", f"projection staging failed: {exc}")
    try:
        event_row = dict(
            ctx.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (protected["event_id"],)
            ).fetchone()
        )
        event_row["payload"] = payload
        event_row["reply_to"] = reply_to
        apply_event(ctx.conn, event_row)
    except ProjectionError as exc:
        raise CliError("send_error", f"projection failed: {exc.code}: {exc}")
    released: list[str] = []
    try:
        due = scheduler.run_due(ctx.conn, utcnow(), _release_fn(ctx))
    except Exception as exc:
        raise CliError("send_error", f"scheduler release failed: {exc}")
    released.extend(due.get("released", []))
    # Push GitHub send-direction mutations now; anything left queued is
    # flushed by the next receive run.
    _flush_send_transports(ctx, [rid])
    if event_type == "relationship.ready":
        _maybe_mark_active_after_ready(ctx, rid)
    if event_type == "delivery.canceled":
        try:
            scheduler.cancel(ctx.conn, payload["scheduled_event_id"])
        except scheduler.SchedulerError:
            pass
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
            event_type, payload = args.type, _build_payload(args)
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
        )
        if args.json:
            print(_canon_text(result))
        elif result.get("dry_run"):
            print(_canon_text(result))
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
# mas receive
# ---------------------------------------------------------------------------


def _record_quarantine(
    ctx: Ctx, rid: str, object_name: str, reason: str, detail: str = ""
) -> None:
    ctx.conn.execute(
        "INSERT OR REPLACE INTO receive_quarantine "
        "(relationship_id, object_name, reason, detail, quarantined_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (rid, object_name, reason, detail[:500], utcnow()),
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
    phase = mstate_get(ctx.conn, "migration.phase")
    if phase not in ("dual_read", "observing", "committed"):
        return _quarantine_outcome(ctx, rid, object_name, "v01_not_accepted")
    pair_id = mstate_get(ctx.conn, "migration.pair_id")
    vault_dir = ctx.state_dir / "migration-vault"
    if not pair_id or not vault_dir.exists():
        return _quarantine_outcome(ctx, rid, object_name, "v01_no_vault")
    try:
        pair_key = vault_load(vault_dir, pair_id)
    except (LegacyError, VaultError) as exc:
        return _quarantine_outcome(ctx, rid, object_name, "v01_no_vault", str(exc))
    drain_open = phase in ("dual_read", "observing")
    policy = LegacyPolicy(
        expected_sender=mstate_get(ctx.conn, "migration.peer_legacy_id") or "*",
        my_agent_id=mstate_get(ctx.conn, "migration.my_legacy_id") or "*",
        replay_store=MemoryReplayStore(),
        legacy_read_open=drain_open,
        legacy_sends_allowed=False,
    )
    try:
        verified = verify_v01(data, pair_key, policy)
    except LegacyError as exc:
        return _quarantine_outcome(ctx, rid, object_name, "v01_verify_failed", str(exc))
    # Durable sequence assignment: the caller owns SeqAssigner persistence.
    seq_state = mstate_get(ctx.conn, "migration.seq_assigner") or {}
    assigner = SeqAssigner.from_dict({k: int(v) for k, v in seq_state.items()})
    adapted = adapt_v01(verified, assigner)
    mstate_set(ctx.conn, "migration.seq_assigner", assigner.to_dict())
    ctx.conn.commit()
    payload = {
        "body": adapted["payload"].get("legacy_title")
        and f"{adapted['payload']['legacy_title']}\n\n{adapted['payload']['body']}"
        or adapted["payload"]["body"],
        "format": "plain",
    }
    row = adapted["event_row"]
    with ctx.conn:
        ctx.conn.execute(
            "INSERT OR IGNORE INTO conversations (conversation_id) VALUES (?)",
            (row["conversation_id"],),
        )
        ctx.conn.execute(
            "INSERT OR IGNORE INTO threads (thread_id, conversation_id) "
            "VALUES (?, ?)",
            (row["thread_id"], row["conversation_id"]),
        )
        ctx.conn.execute(
            "INSERT INTO events (event_id, relationship_id, conversation_id, "
            "thread_id, sender, sender_seq, created_at, key_epoch, event_type, "
            "replay_nonce, sealed_envelope) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'message.created', ?, ?)",
            (
                row["event_id"],
                rid,
                row["conversation_id"],
                row["thread_id"],
                row["sender"],
                row["sender_seq"],
                row["created_at"],
                1,
                _new_uuid(),
                data,
            ),
        )
        record_projection_input(
            ctx.conn,
            event_id=row["event_id"],
            event_type="message.created",
            payload=payload,
            reply_to=None,
        )
        ctx.conn.execute(
            "INSERT INTO projection_queue (event_id, queued_at) VALUES (?, ?)",
            (row["event_id"], utcnow()),
        )
    return {"outcome": "accepted", "surfaces": 1, "receipts_queued": 0}


def _try_unseal(ctx: Ctx, rid: str, envelope: dict) -> tuple[dict, dict]:
    """Unseal trying the epoch's own key first, then every own key."""
    rows = ctx.conn.execute(
        "SELECT epoch, private_key_ref FROM key_epochs "
        "WHERE relationship_id = ? AND private_key_ref != 'peer' "
        "ORDER BY epoch",
        (rid,),
    ).fetchall()
    if not rows:
        raise SealingError("unknown_recipient", "no local agreement keys")
    want = int(envelope["protected"]["key_epoch"])
    ordered = sorted(rows, key=lambda r: 0 if int(r["epoch"]) == want else 1)
    last: Optional[SealingError] = None
    for row in ordered:
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
    """
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
    row = ctx.conn.execute(
        "SELECT COALESCE(MAX(sender_seq), 0) FROM events "
        "WHERE relationship_id = ? AND sender = ?",
        (rid, ctx.identity_id),
    ).fetchone()
    rprotected["sender_seq"] = int(row[0]) + 1
    try:
        renvelope = seal_envelope(
            rprotected, payload, ctx.hierarchy.ed25519_private, recipients
        )
    except SealingError as exc:
        raise CliError(f"send_error", f"receipt seal failed ({exc.code}): {exc}")
    rsealed = restricted_jcs(renvelope)
    ctx.conn.execute(
        "INSERT OR IGNORE INTO conversations (conversation_id) VALUES (?)",
        (rid,),
    )
    ctx.conn.execute(
        "INSERT OR IGNORE INTO threads (thread_id, conversation_id) "
        "VALUES (?, ?)",
        (rprotected["thread_id"], rid),
    )
    ctx.conn.execute(
        "INSERT INTO events (event_id, relationship_id, conversation_id, "
        "thread_id, sender, sender_seq, created_at, key_epoch, event_type, "
        "replay_nonce, sealed_envelope) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            rprotected["event_id"],
            rid,
            rid,
            rprotected["thread_id"],
            ctx.identity_id,
            rprotected["sender_seq"],
            rprotected["created_at"],
            key_epoch,
            "receipt.accepted",
            rprotected["replay_nonce"],
            rsealed,
        ),
    )
    ctx.conn.execute(
        "INSERT INTO sender_sequence (relationship_id, sender, last_seq) "
        "VALUES (?, ?, ?) ON CONFLICT(relationship_id, sender) "
        "DO UPDATE SET last_seq = MAX(last_seq, excluded.last_seq)",
        (rid, ctx.identity_id, rprotected["sender_seq"]),
    )
    ctx.conn.execute(
        "INSERT OR IGNORE INTO projection_queue (event_id, queued_at) "
        "VALUES (?, ?)",
        (rprotected["event_id"], now),
    )
    ctx.conn.execute(
        "INSERT INTO scheduler_queue(scheduled_id, inner_event, deliver_at, "
        "expires_at, state) VALUES (?, ?, ?, ?, 'scheduled')",
        (rprotected["event_id"], rsealed, now, None),
    )


def _receive_object(
    ctx: Ctx, rid: str, object_name: str, data: bytes, acc: dict
) -> dict:
    """Full per-object receive pipeline. Never raises."""
    try:
        return _receive_object_inner(ctx, rid, object_name, data, acc)
    except CliError as exc:
        return _quarantine_outcome(ctx, rid, object_name, exc.code, exc.message)
    except Exception as exc:  # never let the watcher see a traceback
        return _quarantine_outcome(
            ctx, rid, object_name, "receive_error", f"{type(exc).__name__}: {exc}"
        )


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
    if protected["sender"] != peer_id:
        raise CliError("unknown_sender", f"unexpected sender {protected['sender']}")
    event_id = protected["event_id"]
    existing = ctx.conn.execute(
        "SELECT sealed_envelope FROM events WHERE event_id = ?", (event_id,)
    ).fetchone()
    if existing is not None:
        if bytes(existing["sealed_envelope"]) == data:
            return {"outcome": "accepted", "surfaces": 0, "receipts_queued": 0}
        raise CliError("event_id_conflict", "event id reused with different bytes")
    if ctx.conn.execute(
        "SELECT 1 FROM replay_guard WHERE replay_nonce = ?",
        (protected["replay_nonce"],),
    ).fetchone():
        return {"outcome": "accepted", "surfaces": 0, "receipts_queued": 0}
    now = utcnow()
    created = protected["created_at"]
    if created > add_seconds(now, FUTURE_TOLERANCE_SECONDS):
        raise CliError("clock_future", "event created_at is too far in the future")
    if created < add_seconds(now, -ACCEPT_WINDOW_DAYS * 24 * 3600):
        raise CliError("expired_window", "event is older than the 7-day window")
    manager = RotationManager(ctx.conn, ctx.state_dir)
    try:
        manager.on_data_event_epoch(rid, int(protected["key_epoch"]))
    except RotationError as exc:
        if exc.code == "unknown_future_epoch":
            return {"outcome": "retry_pending", "surfaces": 0, "receipts_queued": 0}
        raise CliError("epoch_rejected", f"{exc}")
    try:
        _protected, payload = _try_unseal(ctx, rid, envelope)
    except SealingError as exc:
        raise CliError(f"unseal_{exc.code}", f"{exc}")
    event_type = protected["event_type"]
    expires_at = add_seconds(
        now,
        max(
            _ts_delta(created, 7 * 24 * 3600 + 3600),
            7 * 24 * 3600,
        ),
    )
    try:
        with ctx.conn:
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
            new_seq = int(protected["sender_seq"])
            # Fork: same (sender, seq) already holds a different event.
            # Out-of-order (new event, seq <= last_seq) is accepted; the
            # relay does not guarantee upload order.
            clash = ctx.conn.execute(
                "SELECT event_id FROM events WHERE relationship_id = ? "
                "AND sender = ? AND sender_seq = ? AND event_id != ?",
                (rid, peer_id, new_seq, event_id),
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
                (rid, peer_id, new_seq),
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
                    peer_id,
                    new_seq,
                    created,
                    int(protected["key_epoch"]),
                    event_type,
                    protected["replay_nonce"],
                    data,
                ),
            )
            ctx.conn.execute(
                "INSERT INTO replay_guard (replay_nonce, expires_at) VALUES (?, ?)",
                (protected["replay_nonce"], expires_at),
            )
            record_projection_input(
                ctx.conn,
                event_id=event_id,
                event_type=event_type,
                payload=payload,
                reply_to=protected.get("reply_to"),
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
    # Incremental projection (outside the atomic commit, per the plan).
    try:
        event_row = dict(
            ctx.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        )
        event_row["payload"] = payload
        event_row["reply_to"] = protected.get("reply_to")
        apply_event(ctx.conn, event_row)
    except ProjectionError as exc:
        with ctx.conn:
            quarantine_event(
                ctx.conn, rid, peer_id, new_seq, event_id, f"projection_{exc.code}"
            )
            ctx.conn.execute(
                "DELETE FROM projection_queue WHERE event_id = ?", (event_id,)
            )
        return _quarantine_outcome(
            ctx, rid, object_name, f"projection_{exc.code}", str(exc)
        )
    # Rotation hooks and relationship.ready activation.
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
            manager.note_accepted_event(rid)
        except Exception:
            pass


def _receive_relationship(
    ctx: Ctx, rid: str, time_budget: float
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
    )
    receipts_sent = 0
    if code in (EXIT_OK, EXIT_RETRYABLE, EXIT_PARTIAL_TIMEOUT):
        # Release accepted receipts (and any due scheduled sends) that the
        # receive commit queued in the scheduler outbox, then push them.
        try:
            due = scheduler.run_due(ctx.conn, utcnow(), _release_fn(ctx))
            receipts_sent = len(due.get("released", []))
        except Exception as exc:
            print(f"warning: release failed: {exc}", file=sys.stderr)
        _flush_send_transports(ctx, [rid])
    result["receipts_sent"] = receipts_sent
    return code, result


def cmd_receive(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
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
                    ctx, rid, float(args.timeout or 120)
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


def cmd_rotate(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        rel = ctx.resolve_relationship(args.relationship)
        rid = rel["relationship_id"]
        manager = RotationManager(ctx.conn, ctx.state_dir)
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
            sent = _send_event(ctx, rel, "security.key.ack", ack)
            print(f"rotation acknowledged: event {sent['event_id']}")
            return 0
        if action == "confirm":
            try:
                confirm = manager.confirm_rotation(rid)
            except (RotationError, ConfirmRejected) as exc:
                raise CliError("rotate_error", f"{getattr(exc, 'code', 'rotate_error')}: {exc}")
            sent = _send_event(ctx, rel, "security.key.confirm", confirm)
            print(f"rotation confirmed: event {sent['event_id']}")
            return 0
        if action == "commit":
            try:
                commit = manager.build_commit_payload(rid)
            except (RotationError, ConfirmRejected) as exc:
                raise CliError("rotate_error", f"{getattr(exc, 'code', 'rotate_error')}: {exc}")
            sent = _send_event(ctx, rel, "security.key.commit", commit)
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

    def revoke_deploy_key(self, key_id):
        try:
            repos = self.discover_repos()
            if not repos:
                return "manual: no relay repo recorded"
            repo = repos[0].get("repo")
            status = self._api("DELETE", f"/repos/{repo}/keys/{key_id}")
            return "revoked" if status in (204, "not_found") else f"manual: HTTP {status}"
        except ProvisioningError as exc:
            return f"manual: {exc}"

    def delete_relay_repo(self, repo):
        if not self.delete_remote:
            return "manual: pass --delete-remote to delete the relay repository"
        try:
            status = self._api("DELETE", f"/repos/{repo}")
            return "deleted" if status in (204, "not_found") else f"manual: HTTP {status}"
        except ProvisioningError as exc:
            return f"manual: {exc}"


def cmd_revoke(args: argparse.Namespace) -> int:
    ctx = Ctx(Path(args.state_dir) if args.state_dir else resolve_state_dir())
    try:
        rel = ctx.resolve_relationship(args.relationship)
        rid = rel["relationship_id"]
        peer_label = rel["peer_identity_id"][:24]
        token = args.token or os.environ.get("MAS_GITHUB_TOKEN")
        hooks = _RevokeHooks(ctx.state_dir, token, bool(args.delete_remote))
        # The release teardown does not know about event_payloads (written by
        # the receive/send projection staging); clear them first so the
        # events DELETE does not hit the foreign key.
        with ctx.conn:
            ctx.conn.execute(
                "DELETE FROM event_payloads WHERE event_id IN "
                "(SELECT event_id FROM events WHERE relationship_id = ?)",
                (rid,),
            )
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
        ctx.conn.execute(
            "DELETE FROM relay_config WHERE relationship_id = ?", (rid,)
        )
        ctx.conn.commit()
        summary = {
            "relationship_id_sha256": report.relationship_id_sha256,
            "revoked_at": report.revoked_at,
            "reason_code": report.reason_code,
            "cleanup": report.cleanup,
            "key_deletion": report.key_deletion,
            "tombstone_path": report.tombstone_path,
            "postcheck": report.postcheck,
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
    p_send.add_argument("--epoch", type=int, default=None)
    p_send.add_argument("--prepare-event-id", default=None)
    p_send.add_argument("--new-agreement-key", default=None)
    p_send.add_argument("--prior-fingerprint", default=None)
    p_send.add_argument("--deadline", default=None)
    p_send.add_argument("--reason", default=None)
    p_send.add_argument("--dry-run", action="store_true")
    _add_common(p_send)
    p_send.set_defaults(func=cmd_send)

    p_receive = subs.add_parser("receive", help="receive new relay objects")
    p_receive.add_argument("--relationship", default=None)
    p_receive.add_argument("--timeout", type=float, default=120.0)
    _add_common(p_receive)
    p_receive.set_defaults(func=cmd_receive)

    p_rotate = subs.add_parser("rotate", help="agreement key rotation ceremony")
    p_rotate.add_argument("--relationship", required=True)
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
