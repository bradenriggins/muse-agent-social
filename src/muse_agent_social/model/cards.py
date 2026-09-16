"""Agent cards for Muse Agent Social v0.2.

Implements the IDENTITY / "Agent card" section of the implementation plan.

Card schema::

    {
        "card_version": 1,
        "identity_id": "did:key:z...",
        "display_name": "Hermes",
        "principal_label": "Braden",
        "bootstrap_agreement_key": "z...",
        "capabilities": ["events/0.2", "threads/1", "receipts/1"],
        "issued_at": "2026-09-15T20:00:00Z",
        "expires_at": "2027-09-15T20:00:00Z",
        "card_nonce": "base64url(16 random bytes)",
        "signature": "base64url(Ed25519 signature)"
    }

Signature input is restricted-JCS bytes of the card with ``signature``
omitted. Capabilities are sorted ASCII strings, unique, at most 64 entries of
at most 64 bytes each. Names are display labels, never authentication claims;
the identity key is authoritative. Cards expire after 365 days maximum.
Expiry blocks new pairing, not receipt of already-valid signed history.

Signing uses the restricted-JCS canonicalizer. Until the parallel
canonicalization track lands the shared, audited
``muse_agent_social.canonical`` module (one-shot build checkpoint 3), signing
goes through the shared ``muse_agent_social.canonical.restricted_jcs``. See
INTERFACE.md for the swap plan.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from muse_agent_social.canonical import restricted_jcs
from ..crypto.identity import (
    b64url_decode,
    b64url_encode,
    identity_id_from_pubkey,
    parse_agreement_key,
    parse_identity_id,
)

CARD_VERSION = 1
MAX_CAPABILITIES = 64
MAX_CAPABILITY_BYTES = 64
MAX_CARD_LIFETIME = timedelta(days=365)
_CLOCK_SKEW_TOLERANCE = timedelta(minutes=5)
CARD_NONCE_BYTES = 16
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_CARD_FIELDS = (
    "card_version",
    "identity_id",
    "display_name",
    "principal_label",
    "bootstrap_agreement_key",
    "capabilities",
    "issued_at",
    "expires_at",
    "card_nonce",
    "signature",
)


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def format_timestamp(dt: datetime) -> str:
    """Format *dt* as UTC whole-seconds ``YYYY-MM-DDTHH:MM:SSZ``."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.strftime(TIMESTAMP_FORMAT)


def parse_timestamp(text: str) -> datetime:
    """Parse a strict ``YYYY-MM-DDTHH:MM:SSZ`` timestamp. Raises ValueError."""
    if not isinstance(text, str) or not TIMESTAMP_RE.match(text):
        raise ValueError(f"timestamp must match YYYY-MM-DDTHH:MM:SSZ, got {text!r}")
    try:
        return datetime.strptime(text, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"invalid timestamp {text!r}") from exc


def _coerce_timestamp(value: Any, field: str) -> str:
    if isinstance(value, datetime):
        return format_timestamp(value)
    if isinstance(value, str):
        parse_timestamp(value)  # validates
        return value
    raise ValueError(f"{field} must be a datetime or a YYYY-MM-DDTHH:MM:SSZ string")


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------

def normalize_capabilities(capabilities: Any) -> list[str]:
    """Validate and normalize a capability list per the plan's invariants.

    Returns the capabilities sorted by ASCII byte value, unique. Raises
    ValueError on any violation: not a list, non-string entries, non-ASCII
    entries, entries over 64 bytes, more than 64 entries, or duplicates.
    """
    if not isinstance(capabilities, (list, tuple)):
        raise ValueError("capabilities must be a list of strings")
    normalized: list[str] = []
    for entry in capabilities:
        if not isinstance(entry, str):
            raise ValueError(f"capability must be a string, got {entry!r}")
        try:
            encoded = entry.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(f"capability {entry!r} is not ASCII") from exc
        if len(encoded) > MAX_CAPABILITY_BYTES:
            raise ValueError(
                f"capability {entry!r} exceeds {MAX_CAPABILITY_BYTES} bytes"
            )
        normalized.append(entry)
    if len(normalized) > MAX_CAPABILITIES:
        raise ValueError(
            f"at most {MAX_CAPABILITIES} capabilities, got {len(normalized)}"
        )
    if len(set(normalized)) != len(normalized):
        raise ValueError("capabilities must be unique")
    return sorted(normalized, key=lambda s: s.encode("ascii"))


# ---------------------------------------------------------------------------
# Card creation
# ---------------------------------------------------------------------------

def _check_display_label(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def create_card(
    identity_priv: Ed25519PrivateKey,
    display_name: str,
    principal_label: str,
    agreement_pub_multibase: str,
    capabilities: list[str],
    issued_at: Any,
    expires_at: Any,
) -> dict:
    """Create and self-sign an agent card.

    *identity_priv* is the Ed25519 identity private key; the card's
    ``identity_id`` is derived from its public key. ``issued_at``/``expires_at``
    accept datetimes or strict ``YYYY-MM-DDTHH:MM:SSZ`` strings. The card
    lifetime may not exceed 365 days and ``expires_at`` must be after
    ``issued_at``. ``display_name`` and ``principal_label`` are display labels,
    not authentication claims.
    """
    if not isinstance(identity_priv, Ed25519PrivateKey):
        raise ValueError("identity_priv must be an Ed25519PrivateKey")

    display_name = _check_display_label(display_name, "display_name")
    principal_label = _check_display_label(principal_label, "principal_label")
    parse_agreement_key(agreement_pub_multibase)  # validates form
    caps = normalize_capabilities(capabilities)

    issued = _coerce_timestamp(issued_at, "issued_at")
    expires = _coerce_timestamp(expires_at, "expires_at")
    issued_dt = parse_timestamp(issued)
    expires_dt = parse_timestamp(expires)
    if expires_dt <= issued_dt:
        raise ValueError("expires_at must be after issued_at")
    if expires_dt - issued_dt > MAX_CARD_LIFETIME:
        raise ValueError("card lifetime exceeds the 365-day maximum")

    card = {
        "card_version": CARD_VERSION,
        "identity_id": identity_id_from_pubkey(
            identity_priv.public_key().public_bytes_raw()
        ),
        "display_name": display_name,
        "principal_label": principal_label,
        "bootstrap_agreement_key": agreement_pub_multibase,
        "capabilities": caps,
        "issued_at": issued,
        "expires_at": expires,
        "card_nonce": b64url_encode(os.urandom(CARD_NONCE_BYTES)),
    }
    signature = identity_priv.sign(restricted_jcs(card))
    card["signature"] = b64url_encode(signature)
    return card


# ---------------------------------------------------------------------------
# Card verification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CardVerification:
    """Structured result of :func:`verify_card`.

    ``ok`` is True only for a fully valid, live card. ``reason_code`` is one
    of: "VALID", "MALFORMED", "UNKNOWN_FIELD", "BAD_VERSION", "BAD_IDENTITY_ID",
    "BAD_AGREEMENT_KEY", "BAD_CAPABILITY", "BAD_TIMESTAMP", "EXPIRY_TOO_LONG",
    "BAD_NONCE", "BAD_SIGNATURE", "EXPIRED".

    ``expired`` is True only when the signature is valid but the card is past
    ``expires_at``. Per the plan, expiry blocks new pairing but does not
    invalidate already-valid signed history, so callers deciding whether to
    accept historical material should consult ``expired``/``reason_code``
    rather than ``ok`` alone.
    """

    ok: bool
    reason_code: str
    message: str
    expired: bool = False


def _fail(reason_code: str, message: str, expired: bool = False) -> CardVerification:
    return CardVerification(
        ok=False, reason_code=reason_code, message=message, expired=expired
    )


def verify_card(card: Any, now: Optional[datetime] = None) -> CardVerification:
    """Verify an agent card's schema, self-signature, and expiry.

    *now* defaults to the current UTC time. Expiry is checked against
    ``expires_at``; an expired but otherwise valid card returns
    ``reason_code="EXPIRED"`` with ``expired=True``.
    """
    if not isinstance(card, dict):
        return _fail("MALFORMED", "card must be a JSON object")

    unknown = [k for k in card if k not in _CARD_FIELDS]
    if unknown:
        return _fail("UNKNOWN_FIELD", f"unknown card fields: {unknown}")
    missing = [k for k in _CARD_FIELDS if k not in card]
    if missing:
        return _fail("MALFORMED", f"missing card fields: {missing}")

    if card["card_version"] != CARD_VERSION or not isinstance(
        card["card_version"], int
    ):
        return _fail("BAD_VERSION", "card_version must be 1")

    try:
        identity_pub = parse_identity_id(card["identity_id"])
    except ValueError as exc:
        return _fail("BAD_IDENTITY_ID", str(exc))

    try:
        parse_agreement_key(card["bootstrap_agreement_key"])
    except ValueError as exc:
        return _fail("BAD_AGREEMENT_KEY", str(exc))

    if not isinstance(card["display_name"], str) or not card["display_name"]:
        return _fail("MALFORMED", "display_name must be a non-empty string")
    if not isinstance(card["principal_label"], str) or not card["principal_label"]:
        return _fail("MALFORMED", "principal_label must be a non-empty string")

    caps = card["capabilities"]
    if not isinstance(caps, list) or any(not isinstance(c, str) for c in caps):
        return _fail("BAD_CAPABILITY", "capabilities must be a list of strings")
    try:
        expected_caps = normalize_capabilities(caps)
    except ValueError as exc:
        return _fail("BAD_CAPABILITY", str(exc))
    if caps != expected_caps:
        return _fail(
            "BAD_CAPABILITY",
            "capabilities must be sorted ASCII strings, unique",
        )

    try:
        issued_dt = parse_timestamp(card["issued_at"])
        expires_dt = parse_timestamp(card["expires_at"])
    except ValueError as exc:
        return _fail("BAD_TIMESTAMP", str(exc))
    if expires_dt <= issued_dt:
        return _fail("BAD_TIMESTAMP", "expires_at must be after issued_at")
    if expires_dt - issued_dt > MAX_CARD_LIFETIME:
        return _fail(
            "EXPIRY_TOO_LONG", "card lifetime exceeds the 365-day maximum"
        )

    try:
        nonce = b64url_decode(card["card_nonce"])
    except ValueError as exc:
        return _fail("BAD_NONCE", f"card_nonce: {exc}")
    if len(nonce) != CARD_NONCE_BYTES:
        return _fail("BAD_NONCE", "card_nonce must decode to 16 bytes")

    try:
        signature = b64url_decode(card["signature"])
    except ValueError as exc:
        return _fail("BAD_SIGNATURE", f"signature: {exc}")
    if len(signature) != 64:
        return _fail("BAD_SIGNATURE", "signature must decode to 64 bytes")

    unsigned = {k: v for k, v in card.items() if k != "signature"}
    try:
        signing_bytes = restricted_jcs(unsigned)
    except (TypeError, ValueError) as exc:
        return _fail("MALFORMED", f"card not restricted-JCS serializable: {exc}")
    try:
        Ed25519PublicKey.from_public_bytes(identity_pub).verify(
            signature, signing_bytes
        )
    except Exception:
        return _fail("BAD_SIGNATURE", "self-signature does not verify")

    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    if issued_dt > current + _CLOCK_SKEW_TOLERANCE:
        return _fail(
            "ISSUED_IN_FUTURE",
            "issued_at is in the future; the 365-day lifetime cap is "
            "meaningless without anchoring issuance to now",
        )
    if current >= expires_dt:
        return _fail(
            "EXPIRED",
            f"card expired at {card['expires_at']}; blocks new pairing, "
            "not receipt of already-valid signed history",
            expired=True,
        )

    return CardVerification(ok=True, reason_code="VALID", message="card valid")


def card_fingerprint(card: dict) -> str:
    """Hex SHA-256 over restricted-JCS bytes of the full signed card.

    Used by pairing verification records, which store card fingerprints rather
    than card contents.
    """
    return hashlib.sha256(restricted_jcs(card)).hexdigest()
