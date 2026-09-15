"""Pairing ceremony: invites, acceptances, verification, commit.

Implements the PAIRING and VERIFICATION sections of the implementation plan
(checkpoint 8). The ceremony is a signed, single-use handshake:

1. Invite: the inviter creates a signed invite (15-minute maximum lifetime)
   carrying its agent card and a one-time X25519 agreement public key. The
   invite ID and one-use status are stored transactionally (state ``issued``).
   Handoff is the URI ``muse-agent-social://pair/v1#BASE64URL(JCS(invite))``
   for text, or the same JSON for files.
2. Accept: the acceptor validates the invite, generates its own relationship
   X25519 keypair and its own SSH deploy keypair locally, and returns a
   signed acceptance. Only public keys leave the acceptor's machine.
3. Verify: both humans compare the eight-word verification phrase
   (``pairing_phrase``) over a second trusted channel. The verification is
   recorded with both card fingerprints, the invite ID, the time, and the
   local human approval. A mismatch aborts and burns the invite.
4. Commit: the inviter validates the acceptance, registers the peer's public
   deploy key, and returns a signed commit with the repository URL, slots,
   negotiated capabilities, initial key epochs, and relationship ID. The
   relationship row is persisted as ``pending`` and becomes ``active`` on the
   ``relationship.ready`` exchange (``mark_active``).

Abort rules (no override flag): expired invite, second use, mismatched
phrase, altered card, unsupported required capability, reused deploy key, or
clock skew above five minutes.

Invite lifecycle in the ``invites`` table:
``issued`` -> ``accepted`` -> ``committed``; ``issued`` -> ``expired``;
``issued``/``accepted`` -> ``canceled`` (burned on abort).

Schema violations raise ``muse_agent_social.validation.ValidationError``.
Ceremony rule violations raise ``PairingError`` with a stable ``code``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from muse_agent_social.canonical import restricted_jcs, strict_parse, CanonicalizationError
from muse_agent_social.validation import validate
from muse_agent_social.store.db import transaction
from .._keyfiles import store_private_key, default_keys_dir
from ..crypto.identity import (
    agreement_key_multibase_from_pubkey,
    b64url_decode,
    b64url_encode,
    identity_id_from_pubkey,
    parse_agreement_key,
    parse_identity_id,
)
from ..crypto.words import load_wordlist, verification_phrase
from .cards import (
    card_fingerprint,
    format_timestamp,
    normalize_capabilities,
    parse_timestamp,
    verify_card,
)

__all__ = [
    "PairingError",
    "INVITE_VERSION",
    "ACCEPTANCE_VERSION",
    "COMMIT_VERSION",
    "INVITE_LIFETIME",
    "MAX_CLOCK_SKEW",
    "INVITE_URI_SCHEME",
    "create_invite",
    "invite_uri",
    "parse_invite_uri",
    "write_invite_file",
    "read_invite_file",
    "validate_invite",
    "generate_relationship_keypair",
    "generate_deploy_keypair",
    "create_acceptance",
    "pairing_phrase",
    "record_verification",
    "burn_invite",
    "commit_pairing",
    "mark_active",
    "ingest_commit",
    "get_relationship",
]

INVITE_VERSION = 1
ACCEPTANCE_VERSION = 1
COMMIT_VERSION = 1
INVITE_LIFETIME = timedelta(minutes=15)
MAX_CLOCK_SKEW = timedelta(minutes=5)
INVITE_URI_SCHEME = "muse-agent-social://pair/v1#"

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
# Mirrors the deploy_public_key pattern in invite-acceptance.schema.json.
_SSH_PUBKEY_RE = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384"
    r"|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com"
    r"|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+( .*)?$"
)
_PRIVATE_MARKERS = ("PRIVATE KEY", "openssh-key-v1")


class PairingError(Exception):
    """A pairing ceremony rule was violated.

    Attributes:
        code: stable machine-readable reason code, e.g. "expired",
            "already_used", "bad_signature", "altered_card",
            "unsupported_capability", "deploy_key_reused", "clock_skew",
            "phrase_mismatch", "private_key_material", "unverified".
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class _BurnAndAbort(PairingError):
    """Internal: abort _commit_txn and burn the invite after rollback."""


# ---------------------------------------------------------------------------
# Auxiliary tables owned by this track (created idempotently; the landed
# v1 migrations are never modified here).
# ---------------------------------------------------------------------------

_PAIRING_TABLES_DDL = """
CREATE TABLE IF NOT EXISTS invite_bodies (
    invite_id   TEXT PRIMARY KEY REFERENCES invites(invite_id),
    invite_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pairing_acceptances (
    -- No REFERENCES invites(invite_id): this row is written on the
    -- acceptor's store, which never holds the inviter's invite row.
    invite_id       TEXT PRIMARY KEY,
    invite_json     TEXT NOT NULL,
    acceptance_json TEXT NOT NULL,
    accepted_at     TEXT NOT NULL CHECK(accepted_at GLOB '????-??-??T??:??:??Z')
);
CREATE TABLE IF NOT EXISTS pairing_verifications (
    invite_id                 TEXT PRIMARY KEY REFERENCES invites(invite_id),
    inviter_card_fingerprint  TEXT NOT NULL,
    acceptor_card_fingerprint TEXT NOT NULL,
    verified_at               TEXT NOT NULL CHECK(verified_at GLOB '????-??-??T??:??:??Z'),
    human_approved            INTEGER NOT NULL CHECK(human_approved IN (0, 1))
);
CREATE TABLE IF NOT EXISTS deploy_key_registry (
    deploy_public_key TEXT PRIMARY KEY,
    relationship_id   TEXT NOT NULL,
    registered_at     TEXT NOT NULL CHECK(registered_at GLOB '????-??-??T??:??:??Z')
);
"""


def _ensure_pairing_tables(conn) -> None:
    conn.executescript(_PAIRING_TABLES_DDL)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _coerce_now(now: Optional[datetime]) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _require_uuid4(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _UUID4_RE.match(value):
        raise PairingError("bad_uuid", f"{field} must be a lowercase canonical UUIDv4")
    return value


def _require_live_card(card: Any, now: datetime, what: str) -> None:
    result = verify_card(card, now)
    if not result.ok:
        raise PairingError(
            "card_invalid",
            f"{what} not acceptable: {result.reason_code}: {result.message}",
        )


def _card_matches_key(card: dict, priv: Ed25519PrivateKey, what: str) -> None:
    expected = identity_id_from_pubkey(priv.public_key().public_bytes_raw())
    if card.get("identity_id") != expected:
        raise PairingError(
            "card_key_mismatch",
            f"{what} identity_id does not match the signing key",
        )


def _sign(priv: Ed25519PrivateKey, unsigned: dict) -> str:
    return b64url_encode(priv.sign(restricted_jcs(unsigned)))


def _verify_signature(identity_id: str, signature_b64u: str, unsigned: dict) -> None:
    try:
        raw_pub = parse_identity_id(identity_id)
    except ValueError as exc:
        raise PairingError("bad_signature", f"unparsable identity_id: {exc}") from exc
    try:
        signature = b64url_decode(signature_b64u)
    except ValueError as exc:
        raise PairingError("bad_signature", f"signature is not base64url: {exc}") from exc
    if len(signature) != 64:
        raise PairingError("bad_signature", "signature must decode to 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(
            signature, restricted_jcs(unsigned)
        )
    except Exception as exc:
        raise PairingError("bad_signature", "signature does not verify") from exc


def _reject_private_material(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise PairingError("private_key_material", f"{field} must be a string")
    for marker in _PRIVATE_MARKERS:
        if marker in value:
            raise PairingError(
                "private_key_material",
                f"{field} appears to contain private key material; "
                "only public keys may cross the pairing boundary",
            )
    if value.strip().startswith("-----BEGIN"):
        raise PairingError(
            "private_key_material",
            f"{field} looks like a PEM block; only public keys are allowed",
        )


def _invite_hash(invite: dict) -> str:
    """Base64url SHA-256 over the restricted-JCS bytes of the full invite."""
    return b64url_encode(hashlib.sha256(restricted_jcs(invite)).digest())


def _check_slots(slots: Any) -> dict:
    if not isinstance(slots, dict):
        raise PairingError("bad_slots", "slots must be an object")
    out = {}
    for key in ("inviter_send_slot", "inviter_receive_slot"):
        value = slots.get(key)
        if not isinstance(value, str) or not value:
            raise PairingError("bad_slots", f"{key} must be a non-empty string")
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise PairingError("bad_slots", f"{key} must be ASCII") from exc
        if len(value.encode("utf-8")) > 128:
            raise PairingError("bad_slots", f"{key} exceeds 128 bytes")
        out[key] = value
    if out["inviter_send_slot"] == out["inviter_receive_slot"]:
        raise PairingError("bad_slots", "send and receive slots must differ")
    # Slot names are randomized by the relay transport layer; the ceremony
    # only requires them to be distinct, opaque, ASCII labels.
    return out


def _check_relay_url(relay_url: Any) -> str:
    if not isinstance(relay_url, str) or not relay_url:
        raise PairingError("bad_relay_url", "repository URL must be a non-empty string")
    if not (relay_url.startswith("https://") or relay_url.startswith("git@")):
        raise PairingError(
            "bad_relay_url", "repository URL must start with https:// or git@"
        )
    return relay_url


# ---------------------------------------------------------------------------
# Invite creation and transport encoding
# ---------------------------------------------------------------------------

def create_invite(
    conn,
    inviter_card: dict,
    inviter_priv: Ed25519PrivateKey,
    ephemeral_priv,
    requested_capabilities,
    requested_policy: dict,
    now: Optional[datetime] = None,
) -> dict:
    """Create and sign a single-use pairing invite (ceremony step 1).

    *inviter_priv* is the inviter's Ed25519 identity key; *ephemeral_priv* is
    a fresh X25519 key whose public half goes into the invite (the private
    half stays with the inviter and is deleted after commit, expiry, or
    cancel). The invite lives at most 15 minutes. The invite ID and one-use
    status are stored transactionally with state ``issued``.

    Returns the invite dict. Raises PairingError on ceremony violations and
    ValidationError on schema violations.
    """
    _ensure_pairing_tables(conn)
    now = _coerce_now(now)
    if not isinstance(inviter_priv, Ed25519PrivateKey):
        raise PairingError("bad_key_type", "inviter_priv must be an Ed25519PrivateKey")
    if not isinstance(ephemeral_priv, X25519PrivateKey):
        raise PairingError("bad_key_type", "ephemeral_priv must be an X25519PrivateKey")
    _require_live_card(inviter_card, now, "inviter_card")
    _card_matches_key(inviter_card, inviter_priv, "inviter_card")
    try:
        capabilities = normalize_capabilities(requested_capabilities)
    except ValueError as exc:
        raise PairingError("bad_capability", str(exc)) from exc
    if not isinstance(requested_policy, dict):
        raise PairingError("bad_policy", "requested_policy must be an object")

    invite_id = str(uuid.uuid4())
    invite = {
        "invite_version": INVITE_VERSION,
        "invite_id": invite_id,
        "inviter_card": inviter_card,
        "ephemeral_agreement_key": agreement_key_multibase_from_pubkey(
            ephemeral_priv.public_key().public_bytes_raw()
        ),
        "requested_capabilities": capabilities,
        "requested_policy": requested_policy,
        "issued_at": format_timestamp(now),
        "expires_at": format_timestamp(now + INVITE_LIFETIME),
    }
    invite["signature"] = _sign(inviter_priv, invite)
    validate("invite", invite)
    with transaction(conn):
        conn.execute(
            "INSERT INTO invites (invite_id, state, issued_at, expires_at)"
            " VALUES (?, 'issued', ?, ?)",
            (invite_id, invite["issued_at"], invite["expires_at"]),
        )
        conn.execute(
            "INSERT INTO invite_bodies (invite_id, invite_json) VALUES (?, ?)",
            (invite_id, json.dumps(invite)),
        )
    return invite


def invite_uri(invite: dict) -> str:
    """Encode an invite as the text-handoff URI.

    ``muse-agent-social://pair/v1#`` + base64url(restricted-JCS(invite)).
    """
    if not isinstance(invite, dict):
        raise PairingError("bad_invite", "invite must be an object")
    return INVITE_URI_SCHEME + b64url_encode(restricted_jcs(invite))


def parse_invite_uri(uri: str) -> dict:
    """Parse and schema-validate an invite URI. Returns the invite dict.

    Structural only; callers must still run ``create_acceptance`` or
    ``validate_invite`` for the cryptographic and liveness checks.
    """
    if not isinstance(uri, str) or not uri.startswith(INVITE_URI_SCHEME):
        raise PairingError(
            "bad_invite_uri",
            "invite URI must start with muse-agent-social://pair/v1#",
        )
    try:
        raw = b64url_decode(uri[len(INVITE_URI_SCHEME):])
    except ValueError as exc:
        raise PairingError("bad_invite_uri", f"fragment is not base64url: {exc}") from exc
    try:
        invite = strict_parse(raw)
    except CanonicalizationError as exc:
        raise PairingError("bad_invite_uri", f"fragment is not valid JSON: {exc}") from exc
    if not isinstance(invite, dict):
        raise PairingError("bad_invite_uri", "invite must be a JSON object")
    validate("invite", invite)
    return invite


def write_invite_file(invite: dict, path) -> None:
    """Write an invite to a file. The file format is the same JSON."""
    if not isinstance(invite, dict):
        raise PairingError("bad_invite", "invite must be an object")
    validate("invite", invite)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(invite, fh, indent=2, sort_keys=True)
        fh.write("\n")


def read_invite_file(path) -> dict:
    """Read and schema-validate an invite file. Returns the invite dict."""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        invite = strict_parse(raw)
    except CanonicalizationError as exc:
        raise PairingError("bad_invite_file", f"not valid JSON: {exc}") from exc
    if not isinstance(invite, dict):
        raise PairingError("bad_invite_file", "invite must be a JSON object")
    validate("invite", invite)
    return invite


def _check_invite_pure(invite: dict, now: datetime) -> None:
    """Cryptographic and liveness checks on an invite (no database)."""
    validate("invite", invite)
    _require_live_card(invite["inviter_card"], now, "inviter_card")
    unsigned = {k: v for k, v in invite.items() if k != "signature"}
    _verify_signature(
        invite["inviter_card"]["identity_id"], invite["signature"], unsigned
    )
    issued = parse_timestamp(invite["issued_at"])
    expires = parse_timestamp(invite["expires_at"])
    if expires - issued > INVITE_LIFETIME:
        raise PairingError(
            "lifetime_exceeded",
            "invite lifetime exceeds the 15-minute maximum",
        )
    if issued > now + MAX_CLOCK_SKEW:
        raise PairingError(
            "clock_skew",
            "invite issued_at is more than 5 minutes in the future",
        )
    if now >= expires:
        raise PairingError("expired", "invite has expired")


def validate_invite(conn, invite: dict, now: Optional[datetime] = None) -> dict:
    """Fully validate an invite and atomically consume its one-use status.

    Checks the schema, the inviter card, the invite signature, the 15-minute
    lifetime cap, expiry, and clock skew, then requires the invite to be in
    state ``issued`` in the local store and moves it to ``accepted`` inside
    one transaction. A second call for the same invite raises
    ``already_used``.

    This runs on the inviter's side when the acceptance arrives (only the
    inviter holds the one-use ledger). Returns the invite dict.
    """
    _ensure_pairing_tables(conn)
    now = _coerce_now(now)
    invite_id = invite.get("invite_id") if isinstance(invite, dict) else None
    try:
        _check_invite_pure(invite, now)
    except PairingError as exc:
        if exc.code == "expired" and invite_id:
            with transaction(conn):
                conn.execute(
                    "UPDATE invites SET state='expired'"
                    " WHERE invite_id=? AND state='issued'",
                    (invite_id,),
                )
        raise
    _require_uuid4(invite_id, "invite_id")
    with transaction(conn):
        row = conn.execute(
            "SELECT state FROM invites WHERE invite_id=?", (invite_id,)
        ).fetchone()
        if row is None:
            raise PairingError("unknown_invite", "invite was not issued here")
        if row["state"] != "issued":
            raise PairingError(
                "already_used",
                f"invite is in state {row['state']!r}, not 'issued'",
            )
        conn.execute(
            "UPDATE invites SET state='accepted' WHERE invite_id=?", (invite_id,)
        )
    return invite


# ---------------------------------------------------------------------------
# Acceptor-side key generation (private material never leaves the machine)
# ---------------------------------------------------------------------------

def generate_relationship_keypair():
    """Generate the acceptor's fresh relationship X25519 keypair.

    Returns ``(private_key, public_multibase)``. The caller persists the
    private key (e.g. with ``muse_agent_social._keyfiles.store_private_key``,
    mode 0o600) and passes only the public half to ``create_acceptance``.
    """
    priv = X25519PrivateKey.generate()
    pub_mb = agreement_key_multibase_from_pubkey(
        priv.public_key().public_bytes_raw()
    )
    return priv, pub_mb


def generate_deploy_keypair(private_path) -> str:
    """Generate the acceptor's SSH deploy keypair, storing the private half.

    Creates an Ed25519 keypair, writes the private key in OpenSSH format to
    *private_path* with mode 0o600 (refuses to overwrite), and returns the
    public key in OpenSSH format (``ssh-ed25519 AAAA...``) for the
    acceptance. The private key never leaves the acceptor's machine.
    """
    priv = Ed25519PrivateKey.generate()
    private_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    store_private_key(private_path, private_bytes)
    public_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return public_bytes.decode("ascii").strip()


def create_acceptance(
    conn,
    invite: dict,
    acceptor_card: dict,
    acceptor_priv: Ed25519PrivateKey,
    relationship_pubkey: str,
    ssh_deploy_pubkey: str,
    now: Optional[datetime] = None,
) -> dict:
    """Create and sign an invite acceptance (ceremony step 2).

    *relationship_pubkey* is the acceptor's fresh relationship X25519 public
    key (multibase) and *ssh_deploy_pubkey* is the acceptor's SSH deploy
    public key (OpenSSH format). Both are checked to contain no private key
    material; a violation raises ``private_key_material``. The acceptance is
    signed by the acceptor's identity key and stored locally for the later
    verification and commit steps.
    """
    _ensure_pairing_tables(conn)
    now = _coerce_now(now)
    _check_invite_pure(invite, now)
    if not isinstance(acceptor_priv, Ed25519PrivateKey):
        raise PairingError("bad_key_type", "acceptor_priv must be an Ed25519PrivateKey")
    _require_live_card(acceptor_card, now, "acceptor_card")
    _card_matches_key(acceptor_card, acceptor_priv, "acceptor_card")
    _reject_private_material(relationship_pubkey, "relationship_agreement_key")
    try:
        parse_agreement_key(relationship_pubkey)
    except ValueError as exc:
        raise PairingError("bad_agreement_key", str(exc)) from exc
    _reject_private_material(ssh_deploy_pubkey, "deploy_public_key")
    if not _SSH_PUBKEY_RE.match(ssh_deploy_pubkey):
        raise PairingError(
            "bad_deploy_key", "deploy_public_key is not an OpenSSH public key"
        )

    acceptance = {
        "acceptance_version": ACCEPTANCE_VERSION,
        "invite_id": invite["invite_id"],
        "invite_hash": _invite_hash(invite),
        "acceptor_card": acceptor_card,
        "relationship_agreement_key": relationship_pubkey,
        "deploy_public_key": ssh_deploy_pubkey,
        "accepted_at": format_timestamp(now),
    }
    acceptance["signature"] = _sign(acceptor_priv, acceptance)
    validate("invite-acceptance", acceptance)
    with transaction(conn):
        conn.execute(
            "INSERT OR REPLACE INTO pairing_acceptances"
            " (invite_id, invite_json, acceptance_json, accepted_at)"
            " VALUES (?, ?, ?, ?)",
            (
                invite["invite_id"],
                json.dumps(invite),
                json.dumps(acceptance),
                acceptance["accepted_at"],
            ),
        )
    return acceptance


# ---------------------------------------------------------------------------
# Verification (eight-word human check)
# ---------------------------------------------------------------------------

def pairing_phrase(inviter_card: dict, acceptor_card: dict, wordlist=None) -> list:
    """Compute the eight-word verification phrase binding both identities.

    Wraps ``muse_agent_social.crypto.words.verification_phrase``; the phrase
    is identical regardless of argument order because the keys are sorted
    before hashing. Humans compare all eight words over a second trusted
    channel.
    """
    words = list(wordlist) if wordlist is not None else load_wordlist()
    return verification_phrase(
        inviter_card["identity_id"], acceptor_card["identity_id"], words
    )


def burn_invite(conn, invite_id: str) -> str:
    """Move an invite to the terminal ``canceled`` state (burn it).

    Returns the previous state. Only ``issued`` and ``accepted`` invites can
    be burned; terminal states are left alone and reported.
    """
    _ensure_pairing_tables(conn)
    _require_uuid4(invite_id, "invite_id")
    with transaction(conn):
        row = conn.execute(
            "SELECT state FROM invites WHERE invite_id=?", (invite_id,)
        ).fetchone()
        if row is None:
            raise PairingError("unknown_invite", "invite was not issued here")
        previous = row["state"]
        if previous in ("issued", "accepted"):
            conn.execute(
                "UPDATE invites SET state='canceled' WHERE invite_id=?", (invite_id,)
            )
    return previous


def record_verification(
    conn, invite_id: str, card_fingerprints, human_approved: bool
) -> dict:
    """Record the human verification step (ceremony step 3).

    *card_fingerprints* is the ``(inviter_fingerprint, acceptor_fingerprint)``
    pair of hex card fingerprints (see ``model.cards.card_fingerprint``) that
    the local human approved. The record stores the fingerprints, the invite
    ID, the time, and the approval; the words are never stored.

    If the inviter card fingerprint does not match the locally stored invite
    (altered card), or *human_approved* is false (phrase mismatch), the invite
    is burned (``canceled``) and ``PairingError`` is raised. There is no
    override.
    """
    _ensure_pairing_tables(conn)
    _require_uuid4(invite_id, "invite_id")
    try:
        inviter_fp, acceptor_fp = card_fingerprints
    except (TypeError, ValueError) as exc:
        raise PairingError(
            "bad_fingerprints", "card_fingerprints must be a (inviter, acceptor) pair"
        ) from exc
    for fp, label in ((inviter_fp, "inviter"), (acceptor_fp, "acceptor")):
        if not isinstance(fp, str) or not re.fullmatch(r"[0-9a-f]{64}", fp):
            raise PairingError(
                "bad_fingerprints", f"{label} fingerprint must be hex sha256"
            )

    burn = None
    with transaction(conn):
        state_row = conn.execute(
            "SELECT state FROM invites WHERE invite_id=?", (invite_id,)
        ).fetchone()
        if state_row is None:
            raise PairingError("unknown_invite", "invite was not issued here")
        state = state_row["state"]
        # Altered-card check against locally stored ceremony material.
        body_row = conn.execute(
            "SELECT invite_json FROM invite_bodies WHERE invite_id=?", (invite_id,)
        ).fetchone()
        if body_row is not None:
            invite = json.loads(body_row["invite_json"])
            if card_fingerprint(invite["inviter_card"]) != inviter_fp:
                burn = (
                    "altered_card",
                    "inviter card fingerprint does not match the invite; "
                    "invite burned",
                )
        acc_row = conn.execute(
            "SELECT acceptance_json FROM pairing_acceptances WHERE invite_id=?",
            (invite_id,),
        ).fetchone()
        if burn is None and acc_row is not None:
            acceptance = json.loads(acc_row["acceptance_json"])
            if card_fingerprint(acceptance["acceptor_card"]) != acceptor_fp:
                burn = (
                    "altered_card",
                    "acceptor card fingerprint does not match the acceptance; "
                    "invite burned",
                )
        if burn is None and not human_approved:
            burn = (
                "phrase_mismatch",
                "human rejected the verification phrase; invite burned",
            )
        if burn is None:
            if state == "committed":
                raise PairingError(
                    "already_committed",
                    "invite is already committed; too late to verify",
                )
            verified_at = format_timestamp(_coerce_now(None))
            conn.execute(
                "INSERT OR REPLACE INTO pairing_verifications"
                " (invite_id, inviter_card_fingerprint, acceptor_card_fingerprint,"
                "  verified_at, human_approved) VALUES (?, ?, ?, ?, 1)",
                (invite_id, inviter_fp, acceptor_fp, verified_at),
            )
    if burn is not None:
        # Burn in its own committed transaction: the read transaction above
        # must not roll the burn back when we raise.
        burn_invite(conn, invite_id)
        raise PairingError(burn[0], burn[1])
    return {
        "invite_id": invite_id,
        "inviter_card_fingerprint": inviter_fp,
        "acceptor_card_fingerprint": acceptor_fp,
        "verified_at": verified_at,
        "human_approved": True,
    }


# ---------------------------------------------------------------------------
# Commit (inviter side) and activation
# ---------------------------------------------------------------------------

def commit_pairing(
    conn,
    acceptance: dict,
    inviter_priv: Ed25519PrivateKey,
    relay_url: str,
    slots: dict,
    negotiated_capabilities,
    now: Optional[datetime] = None,
    keys_dir=None,
    relationship_id: Optional[str] = None,
) -> dict:
    """Validate an acceptance and issue the signed pairing commit (step 4).

    Verifies the acceptance schema, the invite hash, the acceptor card and
    signature, clock skew, deploy-key reuse, and capability negotiation
    (every requested capability must be negotiated, and every negotiated
    capability must appear on both cards). Requires a human-approved
    verification record for the invite. Generates the inviter's epoch-1
    relationship X25519 keypair, stores its private half with mode 0o600,
    registers the peer's deploy public key, persists the relationship row as
    ``pending``, marks the invite ``committed``, and returns the signed
    commit dict.

    Pass ``relationship_id`` to mint the id before calling (so relay
    provisioning can reference it); when omitted a fresh uuid4 is used.
    """
    _ensure_pairing_tables(conn)
    now = _coerce_now(now)
    validate("invite-acceptance", acceptance)
    if not isinstance(inviter_priv, Ed25519PrivateKey):
        raise PairingError("bad_key_type", "inviter_priv must be an Ed25519PrivateKey")
    invite_id = acceptance["invite_id"]
    _require_uuid4(invite_id, "invite_id")
    slots = _check_slots(slots)
    relay_url = _check_relay_url(relay_url)
    try:
        negotiated = normalize_capabilities(negotiated_capabilities)
    except ValueError as exc:
        raise PairingError("bad_capability", str(exc)) from exc

    kdir = keys_dir or default_keys_dir(conn)
    if relationship_id is None:
        relationship_id = str(uuid.uuid4())
    else:
        # Caller-minted id (the CLI provisions the relay before committing
        # so deploy-key titles can reference it). Must still be a uuid4.
        _require_uuid4(relationship_id, "relationship_id")
    rel_priv = X25519PrivateKey.generate()
    rel_pub_mb = agreement_key_multibase_from_pubkey(
        rel_priv.public_key().public_bytes_raw()
    )
    key_path = os.path.join(kdir, relationship_id, "epoch1.key")
    store_private_key(key_path, rel_priv.private_bytes_raw())
    try:
        with transaction(conn):
            return _commit_txn(
                conn, acceptance, inviter_priv, relay_url, slots, negotiated,
                invite_id, relationship_id, rel_pub_mb, key_path, now,
            )
    except _BurnAndAbort:
        # The transaction rolled back; honor the burn in a fresh transaction,
        # clean up the generated key, then re-raise the original abort.
        try:
            burn_invite(conn, invite_id)
        finally:
            try:
                os.unlink(key_path)
            except OSError:
                pass
        raise
    except PairingError as exc:
        if exc.code == "expired":
            with transaction(conn):
                conn.execute(
                    "UPDATE invites SET state='expired' WHERE invite_id=?",
                    (invite_id,),
                )
        try:
            os.unlink(key_path)
        except OSError:
            pass
        raise
    except Exception:
        try:
            os.unlink(key_path)
        except OSError:
            pass
        raise


def _commit_txn(
    conn, acceptance, inviter_priv, relay_url, slots, negotiated,
    invite_id, relationship_id, rel_pub_mb, key_path, now,
):
    def _burn(code, message):
        # Returns the abort; commit_pairing honors the burn AFTER the
        # transaction rolls back (burning inline would be rolled back).
        return _BurnAndAbort(code, message)

    body_row = conn.execute(
        "SELECT invite_json FROM invite_bodies WHERE invite_id=?", (invite_id,)
    ).fetchone()
    state_row = conn.execute(
        "SELECT state FROM invites WHERE invite_id=?", (invite_id,)
    ).fetchone()
    if body_row is None or state_row is None:
        raise PairingError("unknown_invite", "invite was not issued here")
    if state_row["state"] != "accepted":
        raise PairingError(
            "invite_not_accepted",
            f"invite is in state {state_row['state']!r}; validate the acceptance first",
        )
    invite = json.loads(body_row["invite_json"])
    if now >= parse_timestamp(invite["expires_at"]):
        # State update is honored by commit_pairing after rollback.
        raise PairingError("expired", "invite expired before commit")

    if acceptance["invite_hash"] != _invite_hash(invite):
        raise _burn("invite_hash_mismatch",
            "acceptance answers a different invite; invite burned",
        )

    vrow = conn.execute(
        "SELECT human_approved FROM pairing_verifications WHERE invite_id=?",
        (invite_id,),
    ).fetchone()
    if vrow is None or not vrow["human_approved"]:
        raise PairingError(
            "unverified",
            "commit requires a human-approved verification record; "
            "run the eight-word check first",
        )

    acceptor_card = acceptance["acceptor_card"]
    _require_live_card(acceptor_card, now, "acceptor_card")
    _verify_signature(
        acceptor_card["identity_id"],
        acceptance["signature"],
        {k: v for k, v in acceptance.items() if k != "signature"},
    )
    accepted_at = parse_timestamp(acceptance["accepted_at"])
    if accepted_at > now + MAX_CLOCK_SKEW:
        raise _burn("clock_skew",
            "acceptance timestamp is more than 5 minutes in the future; invite burned",
        )
    if accepted_at < parse_timestamp(invite["issued_at"]):
        raise _burn("accepted_before_issued",
            "acceptance predates the invite; invite burned",
        )

    inviter_card = invite["inviter_card"]
    _card_matches_key(inviter_card, inviter_priv, "inviter_card")

    deploy_key = acceptance["deploy_public_key"]
    _reject_private_material(deploy_key, "deploy_public_key")
    if not _SSH_PUBKEY_RE.match(deploy_key):
        raise _burn("bad_deploy_key", "deploy_public_key is not an OpenSSH public key")
    seen = conn.execute(
        "SELECT relationship_id FROM deploy_key_registry WHERE deploy_public_key=?",
        (deploy_key,),
    ).fetchone()
    if seen is not None:
        raise _burn("deploy_key_reused",
            "deploy public key is already registered to another relationship; "
            "invite burned",
        )
    try:
        parse_agreement_key(acceptance["relationship_agreement_key"])
    except ValueError as exc:
        raise _burn("bad_agreement_key", str(exc)) from exc

    requested = invite["requested_capabilities"]
    acceptor_caps = set(acceptor_card["capabilities"])
    inviter_caps = set(inviter_card["capabilities"])
    missing = [c for c in requested if c not in negotiated]
    if missing:
        raise _burn("unsupported_capability",
            f"requested capabilities not negotiated: {missing}; invite burned",
        )
    unsupported = [
        c for c in negotiated if c not in acceptor_caps or c not in inviter_caps
    ]
    if unsupported:
        raise _burn("unsupported_capability",
            f"negotiated capabilities not on both cards: {unsupported}; invite burned",
        )

    committed_at = format_timestamp(now)
    commit = {
        "commit_version": COMMIT_VERSION,
        "relationship_id": relationship_id,
        "invite_id": invite_id,
        "repository_url": relay_url,
        "slots": slots,
        "negotiated_capabilities": negotiated,
        "initial_key_epochs": [
            {"epoch": 1, "agreement_public_key": rel_pub_mb}
        ],
        "committed_at": committed_at,
    }
    commit["signature"] = _sign(inviter_priv, commit)

    conn.execute(
        "INSERT INTO relationships (relationship_id, peer_identity_id,"
        " peer_display_name, peer_agreement_key, consent_state, policy,"
        " key_epoch, created_at) VALUES (?, ?, ?, ?, 'pending', ?, 1, ?)",
        (
            relationship_id,
            acceptor_card["identity_id"],
            acceptor_card["display_name"],
            acceptance["relationship_agreement_key"],
            json.dumps(invite["requested_policy"]),
            committed_at,
        ),
    )
    conn.execute(
        "INSERT INTO key_epochs (relationship_id, epoch, public_key,"
        " private_key_ref, state) VALUES (?, 1, ?, ?, 'active')",
        (relationship_id, rel_pub_mb, key_path),
    )
    conn.execute(
        "INSERT INTO deploy_key_registry (deploy_public_key, relationship_id,"
        " registered_at) VALUES (?, ?, ?)",
        (deploy_key, relationship_id, committed_at),
    )
    conn.execute(
        "UPDATE invites SET state='committed' WHERE invite_id=?", (invite_id,)
    )
    return commit


def get_relationship(conn, relationship_id: str) -> dict:
    """Return the relationship row as a dict. Raises PairingError if unknown."""
    _require_uuid4(relationship_id, "relationship_id")
    row = conn.execute(
        "SELECT * FROM relationships WHERE relationship_id=?", (relationship_id,)
    ).fetchone()
    if row is None:
        raise PairingError("unknown_relationship", "no such relationship")
    return dict(row)


def mark_active(conn, relationship_id: str) -> dict:
    """Move a relationship from ``pending`` to ``active``.

    Called when the ``relationship.ready`` exchange completes over the relay.
    Only ``pending`` -> ``active`` is allowed; anything else raises
    PairingError. Returns the updated relationship row.
    """
    _ensure_pairing_tables(conn)
    _require_uuid4(relationship_id, "relationship_id")
    with transaction(conn):
        cursor = conn.execute(
            "UPDATE relationships SET consent_state='active'"
            " WHERE relationship_id=? AND consent_state='pending'",
            (relationship_id,),
        )
        if cursor.rowcount == 0:
            row = conn.execute(
                "SELECT consent_state FROM relationships WHERE relationship_id=?",
                (relationship_id,),
            ).fetchone()
            if row is None:
                raise PairingError("unknown_relationship", "no such relationship")
            raise PairingError(
                "not_pending",
                f"relationship is {row['consent_state']!r}, not 'pending'",
            )
    return get_relationship(conn, relationship_id)


def ingest_commit(
    conn,
    commit: dict,
    invite: dict,
    own_agreement_pubkey: str,
    own_private_key_ref: str,
    local_card: dict,
    now: Optional[datetime] = None,
) -> str:
    """Acceptor-side: verify the inviter's signed commit and persist state.

    Checks the commit structure, the inviter's signature (using the inviter
    card from the invite), that the commit answers this invite, and that the
    negotiated capabilities are all on the local card. Persists the
    relationship row as ``pending`` with the inviter's epoch-1 agreement key
    as ``peer_agreement_key``, plus the local epoch-1 key row. Returns the
    relationship ID. The caller then completes the ``relationship.ready``
    exchange and calls ``mark_active``.
    """
    _ensure_pairing_tables(conn)
    now = _coerce_now(now)
    if not isinstance(commit, dict):
        raise PairingError("malformed_commit", "commit must be an object")
    for field in (
        "commit_version", "relationship_id", "invite_id", "repository_url",
        "slots", "negotiated_capabilities", "initial_key_epochs",
        "committed_at", "signature",
    ):
        if field not in commit:
            raise PairingError("malformed_commit", f"commit is missing {field!r}")
    if commit["commit_version"] != COMMIT_VERSION:
        raise PairingError("malformed_commit", "unsupported commit_version")
    relationship_id = _require_uuid4(commit["relationship_id"], "relationship_id")
    if not isinstance(invite, dict) or invite.get("invite_id") != commit["invite_id"]:
        raise PairingError("invite_mismatch", "commit does not answer this invite")

    inviter_card = invite["inviter_card"]
    _require_live_card(inviter_card, now, "inviter_card")
    _verify_signature(
        inviter_card["identity_id"],
        commit["signature"],
        {k: v for k, v in commit.items() if k != "signature"},
    )
    try:
        negotiated = normalize_capabilities(commit["negotiated_capabilities"])
    except ValueError as exc:
        raise PairingError("bad_capability", str(exc)) from exc
    local_caps = set(local_card.get("capabilities", []))
    unsupported = [c for c in negotiated if c not in local_caps]
    if unsupported:
        raise PairingError(
            "unsupported_capability",
            f"commit negotiates capabilities not on the local card: {unsupported}",
        )
    try:
        parse_agreement_key(own_agreement_pubkey)
    except ValueError as exc:
        raise PairingError("bad_agreement_key", str(exc)) from exc
    if not isinstance(own_private_key_ref, str) or not own_private_key_ref:
        raise PairingError("bad_key_ref", "own_private_key_ref must be a non-empty path")
    epochs = commit["initial_key_epochs"]
    if not isinstance(epochs, list):
        raise PairingError("malformed_commit", "initial_key_epochs must be a list")
    inviter_keys = [
        e.get("agreement_public_key") for e in epochs
        if isinstance(e, dict) and e.get("epoch") == 1
    ]
    if not inviter_keys:
        raise PairingError("malformed_commit", "initial_key_epochs must include epoch 1")
    try:
        parse_agreement_key(inviter_keys[0])
    except ValueError as exc:
        raise PairingError("bad_agreement_key", str(exc)) from exc
    _check_slots(commit["slots"])
    _check_relay_url(commit["repository_url"])
    try:
        committed_at = parse_timestamp(commit["committed_at"])
    except ValueError as exc:
        raise PairingError("malformed_commit", str(exc)) from exc
    if committed_at > now + MAX_CLOCK_SKEW:
        raise PairingError("clock_skew", "commit timestamp is more than 5 minutes in the future")

    with transaction(conn):
        exists = conn.execute(
            "SELECT 1 FROM relationships WHERE relationship_id=?", (relationship_id,)
        ).fetchone()
        if exists is not None:
            raise PairingError("duplicate_relationship", "relationship already ingested")
        conn.execute(
            "INSERT INTO relationships (relationship_id, peer_identity_id,"
            " peer_display_name, peer_agreement_key, consent_state, policy,"
            " key_epoch, created_at) VALUES (?, ?, ?, ?, 'pending', ?, 1, ?)",
            (
                relationship_id,
                inviter_card["identity_id"],
                inviter_card["display_name"],
                inviter_keys[0],
                json.dumps(invite["requested_policy"]),
                format_timestamp(now),
            ),
        )
        conn.execute(
            "INSERT INTO key_epochs (relationship_id, epoch, public_key,"
            " private_key_ref, state) VALUES (?, 1, ?, ?, 'active')",
            (relationship_id, own_agreement_pubkey, own_private_key_ref),
        )
    return relationship_id
