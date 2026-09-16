"""v0.1 compatibility adapter for Muse Agent Social v0.2.

Implements the implementation plan's COMPATIBILITY section (v0.1 adapter)
exactly as specified in docs/notes/adapter-spec.md.

The adapter is READ-ONLY migration plumbing. It recognizes, verifies, and
adapts sealed v0.1 objects into internal v0.2 ``message.created`` events.
It never signs, never re-encrypts, never re-keys, and never re-signs an
adapted event as v0.2.

Required surface (names, parameters, return types are normative):
    detect_v01(obj) -> bool
    verify_v01(obj, pair_key, *, policy, filename="") -> VerifiedLegacy
    adapt_v01(verified, pair_id, seq_assigner) -> dict

No em dashes are used anywhere in this module, per project convention.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import stat
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, NamedTuple, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "LEGACY_FIELD_SET",
    "LEGACY_TYPES",
    "MAX_V01_BYTES",
    "V01_AGE_WINDOW_DAYS",
    "V01_FUTURE_TOLERANCE",
    "V01_DEFAULT_DAILY_CAP",
    "ALL_CODES",
    "LegacyError",
    "UnsupportedCapabilityError",
    "VaultError",
    "VerifiedLegacy",
    "LegacyPolicy",
    "ReplayStore",
    "MemoryReplayStore",
    "StoreReplayGuard",
    "SeqAssigner",
    "detect_v01",
    "verify_v01",
    "adapt_v01",
    "assert_legacy_sends_allowed",
    "require_capability",
    "record_legacy_replay",
    "vault_store",
    "vault_load",
    "vault_delete",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Exact legacy field set. Recognition and schema require exactly these keys.
LEGACY_FIELD_SET = frozenset(
    {
        "v",
        "id",
        "from",
        "to",
        "pair",
        "type",
        "title",
        "body",
        "url",
        "created_at",
        "nonce",
        "sig",
    }
)

#: Legacy message types, all of which adapt to message.created.
LEGACY_TYPES = frozenset({"note", "link", "article", "file-ref"})

#: Raw sealed bytes size limit, applied before parse or decrypt.
MAX_V01_BYTES = 262144

#: v0.1 acceptance window: not older than 7 days, not more than 1h future.
V01_AGE_WINDOW_DAYS = 7
V01_FUTURE_TOLERANCE = timedelta(hours=1)

#: Default legacy per-peer daily cap (UTC day boundary, v0.1 semantics).
V01_DEFAULT_DAILY_CAP = 5

#: v0.1 created_at wire format, exact.
V01_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#: Key set of the remote-transport encryption wrapper (github/r2 in v0.1).
_WRAPPER_FIELD_SET = frozenset({"n", "c"})

#: AES-GCM nonce length used by the v0.1 envelope wrapper.
_GCM_NONCE_LEN = 12

# ---------------------------------------------------------------------------
# Error codes (normative, from the adapter spec)
# ---------------------------------------------------------------------------

ALL_CODES = (
    "V01_NOT_LEGACY",
    "V01_FIELDSET_MISMATCH",
    "V01_OVERSIZE",
    "V01_DECODE_ERROR",
    "V01_DECRYPT_FAILED",
    "V01_SENDER_MISMATCH",
    "V01_RECIPIENT_MISMATCH",
    "V01_PAIR_MISMATCH",
    "V01_HMAC_INVALID",
    "V01_MISSING_NONCE",
    "V01_BAD_TIMESTAMP",
    "V01_STALE",
    "V01_FUTURE",
    "V01_REPLAY",
    "V01_RATE_LIMITED",
    "V01_DRAIN_CLOSED",
    "V01_SENDS_DISABLED",
)


class LegacyError(Exception):
    """A v0.1 adapter check failed.

    Attributes:
        code: stable machine-readable reason code (one of ALL_CODES).
        detail: human-readable detail with no secret material and no
            message content, per the plan's schema error contract.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class UnsupportedCapabilityError(Exception):
    """A v0.2 capability is absent on the peer side (no-downgrade rule).

    The sender must fail with this explicit error. It must never strip
    expiry, consent, receipts, thread identity, or security semantics to
    fit a v0.1-shaped send. Downgrade-by-omission is a protocol violation,
    not a fallback.
    """

    def __init__(self, capability: str, detail: str = "") -> None:
        self.capability = capability
        self.detail = detail
        super().__init__(
            f"unsupported-capability: {capability}"
            + (f": {detail}" if detail else "")
        )


class VaultError(Exception):
    """The migration vault is missing, unreadable, or has wrong permissions."""


# ---------------------------------------------------------------------------
# Test clock (internal)
# ---------------------------------------------------------------------------

_test_clock: Callable[[], datetime] | None = None


def _now() -> datetime:
    if _test_clock is not None:
        return _test_clock()
    return datetime.now(timezone.utc)


def _set_test_clock(fn: Callable[[], datetime] | None) -> None:
    """Install or clear an injectable clock (tests and migration rehearsal)."""
    global _test_clock
    _test_clock = fn


def _utcnow_text() -> str:
    return _now().replace(microsecond=0).strftime(V01_TIMESTAMP_FORMAT)


# ---------------------------------------------------------------------------
# Policy and replay store
# ---------------------------------------------------------------------------


class ReplayStore(Protocol):
    """Replay consultation surface. The adapter consults it; the caller owns
    retention (expire by acceptance window, never by count, per v0.2 rules)."""

    def has_seen(self, nonce: str) -> bool: ...
    def record(self, nonce: str, expires_at: str) -> None: ...


class MemoryReplayStore:
    """In-memory ReplayStore for tests and single-process rehearsal."""

    def __init__(self) -> None:
        self._seen: dict[str, str] = {}

    def has_seen(self, nonce: str) -> bool:
        return nonce in self._seen

    def record(self, nonce: str, expires_at: str) -> None:
        self._seen[nonce] = expires_at

    def prune(self, now_text: str) -> int:
        stale = [k for k, exp in self._seen.items() if exp < now_text]
        for k in stale:
            del self._seen[k]
        return len(stale)


class StoreReplayGuard:
    """ReplayStore backed by the v0.2 ``replay_guard`` table.

    ``conn`` must be a connection on a migrated v0.2 database (the table is
    created by the v0.2 schema). Entries expire by acceptance window.
    """

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def has_seen(self, nonce: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM replay_guard WHERE replay_nonce = ?",
            (nonce,),
        ).fetchone()
        return row is not None

    def record(self, nonce: str, expires_at: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO replay_guard (replay_nonce, expires_at)"
            " VALUES (?, ?)",
            (nonce, expires_at),
        )

    def prune(self, now_text: str) -> int:
        cur = self._conn.execute(
            "DELETE FROM replay_guard WHERE expires_at < ?", (now_text,)
        )
        return cur.rowcount


@dataclass
class LegacyPolicy:
    """Explicit validation policy for one legacy relationship.

    Passed by the caller (migration, dual-read, drain); the adapter never
    reads peers.yaml, relay.yaml, or any other ambient config.
    """

    pair_id: str
    expected_sender: str  # legacy peer agent id ("from")
    my_agent_id: str  # my agent id ("to")
    daily_cap: int = V01_DEFAULT_DAILY_CAP
    accepted_today: int = 0  # receive-side count for the legacy peer
    replay_store: ReplayStore | None = None
    # Lifecycle gates, driven by the migration state machine:
    legacy_read_open: bool = True  # False after the 24h drain closes
    legacy_sends_allowed: bool = True  # False after cutover commit


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _looks_like_legacy_dict(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and type(obj.get("v")) is int
        and obj.get("v") == 1
        and set(obj.keys()) == LEGACY_FIELD_SET
    )


def detect_v01(obj: bytes) -> bool:
    """Return True only for a recognizable v0.1 sealed object.

    Pure syntactic recognition: parses as JSON, is a dict, ``v`` is int 1,
    and the key set is exactly the legacy field set. No HMAC verification,
    no decryption, no semantic checks.

    The ``{"n","c"}`` remote-transport wrapper is NOT recognized here; it
    is handled inside verify_v01's parse step. v0.2 envelopes and arbitrary
    JSON return False.
    """
    if not isinstance(obj, bytes):
        return False
    try:
        parsed = json.loads(obj.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    return _looks_like_legacy_dict(parsed)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class VerifiedLegacy(NamedTuple):
    """A v0.1 object that passed full verification. Immutable."""

    raw: bytes  # original sealed v0.1 bytes, byte-for-byte
    envelope: dict  # the parsed 12-field legacy envelope (plaintext)
    hmac_ok: bool  # always True when this object exists
    filename: str  # transport filename, for provenance/ordering
    pair_id: str


def verify_v01(
    obj: bytes,
    pair_key: bytes,
    *,
    policy: LegacyPolicy,
    filename: str = "",
) -> VerifiedLegacy:
    """Full legacy validation. Raises LegacyError on any failure.

    Check order is normative: drain gate, size, parse, schema, routing,
    HMAC, decrypt (remote transports), nonce, age, replay, rate.
    """
    if not isinstance(pair_key, bytes) or len(pair_key) != 32:
        raise ValueError("pair_key must be 32 bytes")
    if not isinstance(policy, LegacyPolicy):
        raise ValueError("policy must be a LegacyPolicy")

    # Lifecycle gate (migration state machine owns this flag).
    if not policy.legacy_read_open:
        raise LegacyError(
            "V01_DRAIN_CLOSED",
            "legacy acceptance is disabled (drain window closed)",
        )

    # 1. Size: raw sealed bytes before any parse or decrypt.
    if len(obj) > MAX_V01_BYTES:
        raise LegacyError(
            "V01_OVERSIZE",
            f"sealed bytes exceed {MAX_V01_BYTES}",
        )

    # 2. Parse the outer object.
    try:
        outer = json.loads(obj.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise LegacyError("V01_DECODE_ERROR", "raw bytes are not JSON")
    if not isinstance(outer, dict):
        raise LegacyError("V01_DECODE_ERROR", "top-level JSON is not an object")

    # 6 (deferred). Remote-transport wrapper: decrypt now, inner envelope
    # re-enters validation at step 3. GCM auth failure, bad base64, or a
    # wrong-size nonce is V01_DECRYPT_FAILED, never a decode error.
    if set(outer.keys()) == _WRAPPER_FIELD_SET:
        envelope = _decrypt_wrapper(outer, pair_key)
    else:
        envelope = outer

    # 3. Schema. Missing nonce/sig map to their specific codes here so the
    # documented "nonce absent or empty -> V01_MISSING_NONCE" and "missing
    # sig -> V01_HMAC_INVALID" hold even though the exact key set is also
    # enforced.
    _check_schema(envelope)

    # 4. Sender / recipient / pair, before touching key material.
    _check_routing(envelope, policy)

    # 5. HMAC over canonical bytes (envelope minus sig).
    _check_hmac(envelope, pair_key)

    # 7. Nonce presence (empty string reaches here; absent was caught above).
    nonce = envelope["nonce"]
    if not isinstance(nonce, str) or not nonce:
        raise LegacyError("V01_MISSING_NONCE", "nonce is empty")

    # 8. Age window (v0.1's own window, not v0.2's tolerance).
    _check_age(envelope)

    # 9. Replay.
    _check_replay(envelope, policy)

    # 10. Rate policy.
    if policy.accepted_today >= policy.daily_cap:
        raise LegacyError(
            "V01_RATE_LIMITED",
            f"legacy daily cap reached ({policy.daily_cap}/day)",
        )

    return VerifiedLegacy(
        raw=obj,
        envelope=envelope,
        hmac_ok=True,
        filename=filename,
        pair_id=policy.pair_id,
    )


def _check_schema(envelope: Any) -> None:
    if not isinstance(envelope, dict):
        raise LegacyError("V01_FIELDSET_MISMATCH", "envelope is not an object")
    v = envelope.get("v")
    if type(v) is not int or v != 1:
        raise LegacyError("V01_NOT_LEGACY", "v is absent or not 1")
    if "nonce" not in envelope:
        raise LegacyError("V01_MISSING_NONCE", "nonce is absent")
    if "sig" not in envelope:
        raise LegacyError("V01_HMAC_INVALID", "sig is absent")
    if set(envelope.keys()) != LEGACY_FIELD_SET:
        raise LegacyError("V01_FIELDSET_MISMATCH", "key set is not the legacy set")
    for key in (
        "id",
        "from",
        "to",
        "pair",
        "type",
        "title",
        "body",
        "url",
        "created_at",
        "nonce",
        "sig",
    ):
        if not isinstance(envelope[key], str):
            raise LegacyError(
                "V01_FIELDSET_MISMATCH", f"field has wrong type: {key}"
            )
    if envelope["type"] not in LEGACY_TYPES:
        raise LegacyError("V01_FIELDSET_MISMATCH", "field has wrong type: type")


def _check_routing(envelope: dict, policy: LegacyPolicy) -> None:
    if envelope["from"] != policy.expected_sender:
        raise LegacyError("V01_SENDER_MISMATCH", "from does not match peer")
    if envelope["to"] != policy.my_agent_id:
        raise LegacyError("V01_RECIPIENT_MISMATCH", "to does not match local agent")
    if envelope["pair"] != policy.pair_id:
        raise LegacyError("V01_PAIR_MISMATCH", "pair does not match")


def _canonical_bytes(envelope: dict) -> bytes:
    body = {k: v for k, v in envelope.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _check_hmac(envelope: dict, pair_key: bytes) -> None:
    sig = envelope["sig"]
    if not isinstance(sig, str) or not sig:
        raise LegacyError("V01_HMAC_INVALID", "sig is absent")
    expected = hmac.new(pair_key, _canonical_bytes(envelope), hashlib.sha256)
    if not hmac.compare_digest(expected.hexdigest(), sig):
        raise LegacyError("V01_HMAC_INVALID", "signature mismatch")


def _decrypt_wrapper(outer: dict, pair_key: bytes) -> dict:
    try:
        nonce = base64.b64decode(outer["n"])
        ciphertext = base64.b64decode(outer["c"])
    except (binascii.Error, ValueError, TypeError):
        raise LegacyError("V01_DECRYPT_FAILED", "wrapper base64 decode failed")
    if len(nonce) != _GCM_NONCE_LEN:
        raise LegacyError("V01_DECRYPT_FAILED", "wrapper nonce has wrong length")
    try:
        plaintext = AESGCM(pair_key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise LegacyError("V01_DECRYPT_FAILED", "wrapper authentication failed")
    except Exception:
        raise LegacyError("V01_DECRYPT_FAILED", "wrapper decryption failed")
    try:
        inner = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise LegacyError(
            "V01_FIELDSET_MISMATCH", "decrypted inner object is not JSON"
        )
    return inner


def _check_age(envelope: dict) -> datetime:
    text = envelope["created_at"]
    try:
        created = datetime.strptime(text, V01_TIMESTAMP_FORMAT).replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise LegacyError("V01_BAD_TIMESTAMP", "created_at has wrong format")
    now = _now()
    if created - now > V01_FUTURE_TOLERANCE:
        raise LegacyError("V01_FUTURE", "created_at is too far in the future")
    if now - created > timedelta(days=V01_AGE_WINDOW_DAYS):
        raise LegacyError("V01_STALE", "created_at is older than 7 days")
    return created


def _check_replay(envelope: dict, policy: LegacyPolicy) -> None:
    store = policy.replay_store
    if store is None:
        return
    nonce = envelope["nonce"]
    legacy_id = envelope["id"]
    if store.has_seen(nonce) or store.has_seen("v01id:" + legacy_id):
        raise LegacyError("V01_REPLAY", "nonce or id already seen")


def record_legacy_replay(policy: LegacyPolicy, verified: VerifiedLegacy) -> None:
    """Record a verified legacy object's nonce/id in the replay store.

    Called by the migration/dual-read path after a successful adapt and
    store, not by verify_v01 (which only consults). Expiry follows the
    v0.1 acceptance window.
    """
    store = policy.replay_store
    if store is None:
        return
    expires = _now() + timedelta(days=V01_AGE_WINDOW_DAYS)
    expires_text = expires.replace(microsecond=0).strftime(V01_TIMESTAMP_FORMAT)
    store.record(verified.envelope["nonce"], expires_text)
    store.record("v01id:" + verified.envelope["id"], expires_text)


def assert_legacy_sends_allowed(policy: LegacyPolicy) -> None:
    """Reject a local v0.1 send attempt after the cutover commit."""
    if not policy.legacy_sends_allowed:
        raise LegacyError(
            "V01_SENDS_DISABLED",
            "local v0.1 sends are disabled after cutover commit",
        )


def require_capability(capability: str, peer_capabilities: Any) -> None:
    """Fail explicitly when the peer lacks a v0.2 capability.

    Never strip semantics to fit a v0.1-shaped send; raise instead.
    """
    if capability not in peer_capabilities:
        raise UnsupportedCapabilityError(
            capability,
            "peer does not support this v0.2 capability; refusing downgrade",
        )


# ---------------------------------------------------------------------------
# Sequence assignment
# ---------------------------------------------------------------------------


class SeqAssigner:
    """Assigns synthetic sender sequence numbers by stable filename order.

    The caller feeds filenames in sorted (stable) order across the whole
    legacy backlog. First call for a filename wins; repeats return the
    stored value. The caller owns durability (persist via to_dict/from_dict).
    """

    def __init__(self) -> None:
        self._seq_by_filename: dict[str, int] = {}
        self._next = 1

    def assign(self, filename: str) -> int:
        existing = self._seq_by_filename.get(filename)
        if existing is not None:
            return existing
        seq = self._next
        self._seq_by_filename[filename] = seq
        self._next += 1
        return seq

    def to_dict(self) -> dict[str, int]:
        return dict(self._seq_by_filename)

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> "SeqAssigner":
        inst = cls()
        inst._seq_by_filename = dict(data)
        inst._next = max(data.values(), default=0) + 1
        return inst


# ---------------------------------------------------------------------------
# Adaptation
# ---------------------------------------------------------------------------

#: UUID namespace derivation for synthetic event ids. The namespace is
#: UUIDv5(DNS, "muse-agent-social.v0-1." + pair_id); the event id is
#: UUIDv5(namespace, legacy_id). Deterministic across runs.
_UUID_DNS_PREFIX = "muse-agent-social.v0-1."


def _synthetic_event_id(pair_id: str, legacy_id: str) -> str:
    namespace = uuid.uuid5(uuid.NAMESPACE_DNS, _UUID_DNS_PREFIX + pair_id)
    return str(uuid.uuid5(namespace, legacy_id))


def adapt_v01(
    verified: VerifiedLegacy, pair_id: str, seq_assigner: SeqAssigner
) -> dict:
    """Adapt a VerifiedLegacy into an internal v0.2 message.created event dict.

    Deterministic: same input yields the same synthetic event id, the same
    sequence for the same filename, and byte-identical preserved raw bytes.
    The event is never re-signed as v0.2; provenance stays legacy_source=v0.1.
    """
    if not isinstance(verified, VerifiedLegacy):
        raise ValueError("verified must be a VerifiedLegacy")
    if not verified.hmac_ok:
        raise ValueError("cannot adapt an unverified legacy object")
    envelope = verified.envelope
    legacy_type = envelope["type"]

    payload: dict[str, Any] = {
        "body": envelope["body"],
        "legacy_title": envelope["title"],
    }
    # No new semantics invented: file-ref does not become an attachment,
    # link does not become a preview.
    if legacy_type in ("link", "article", "file-ref"):
        payload["legacy_url"] = envelope.get("url", "")

    return {
        "event_id": _synthetic_event_id(pair_id, envelope["id"]),
        "event_type": "message.created",
        "legacy_source": "v0.1",
        "legacy_id": envelope["id"],
        "legacy_type": legacy_type,
        "pair_id": pair_id,
        "sender": envelope["from"],
        "sender_seq": seq_assigner.assign(verified.filename or envelope["id"]),
        "created_at": envelope["created_at"],
        "received_at": _utcnow_text(),
        "payload": payload,
        "raw_v01": verified.raw,  # original sealed bytes, verbatim
        "hmac_ok": True,
    }


# ---------------------------------------------------------------------------
# Migration vault: legacy pair key custody
# ---------------------------------------------------------------------------

_VAULT_PREFIX = "legacy-key-"

_VAULT_AAD_DOMAIN = b"muse-agent-social/v1/migration-vault:"


def _vault_aad(pair_id: str) -> bytes:
    """Bind vault ciphertext to the pair id (AEAD associated data)."""
    return _VAULT_AAD_DOMAIN + pair_id.encode("utf-8")


def _check_vault_enc_key(enc_key: bytes) -> bytes:
    key = bytes(enc_key)
    if len(key) != 32:
        raise ValueError(
            f"vault encryption key must be 32 bytes, got {len(key)}"
        )
    return key


def _vault_path(vault_dir: str | Path, pair_id: str) -> Path:
    digest = hashlib.sha256(pair_id.encode("utf-8")).hexdigest()[:16]
    return Path(vault_dir) / f"{_VAULT_PREFIX}{digest}.json"


def vault_store(
    vault_dir: str | Path,
    pair_id: str,
    key_hex: str,
    *,
    enc_key: bytes | None = None,
) -> Path:
    """Store the legacy pair key in the migration vault (mode 0600).

    The key arrives only via this path, never from peers.yaml. The vault
    directory is created with mode 0700. Returns the vault file path.

    When *enc_key* (32 bytes) is given, the payload is sealed with
    AES-256-GCM under that key (AAD binds the pair id) and the file holds
    only ciphertext: no base64 key material is visible at rest. Without
    *enc_key* the legacy plaintext JSON format is written (kept for
    operator-handoff compatibility).
    """
    raw = bytes.fromhex(key_hex)
    if len(raw) != 32:
        raise ValueError("legacy pair key must be 32 bytes")
    if enc_key is not None:
        enc_key = _check_vault_enc_key(enc_key)
    vault_dir = Path(vault_dir)
    vault_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(vault_dir, 0o700)
    path = _vault_path(vault_dir, pair_id)
    tmp = path.with_suffix(".tmp")
    payload = {
        "pair_id_sha256": hashlib.sha256(pair_id.encode("utf-8")).hexdigest(),
        "key_b64": base64.b64encode(raw).decode("ascii"),
        "stored_at": _utcnow_text(),
    }
    if enc_key is None:
        body = json.dumps(payload)
    else:
        nonce = os.urandom(12)
        ct = AESGCM(enc_key).encrypt(
            nonce, json.dumps(payload).encode("utf-8"), _vault_aad(pair_id)
        )
        body = json.dumps(
            {
                "v": 2,
                "alg": "AES-256-GCM",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ct": base64.b64encode(ct).decode("ascii"),
            }
        )
    tmp.write_text(body, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return path


def vault_load(
    vault_dir: str | Path,
    pair_id: str,
    *,
    enc_key: bytes | None = None,
) -> bytes:
    """Load the legacy pair key from the migration vault.

    Fails closed if the file is missing or not mode 0600. An entry sealed
    with *enc_key* refuses to load without it (VaultError); a legacy
    plaintext entry loads with or without *enc_key*. The key is returned
    only to the caller (migration/adapter), never logged.
    """
    path = _vault_path(vault_dir, pair_id)
    if not path.is_file():
        raise KeyError(f"no vault entry for pair {pair_id!r}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise VaultError(f"vault file has wrong mode {oct(mode)}: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if "ct" in payload:
        if enc_key is None:
            raise VaultError(
                "vault entry is encrypted at rest; enc_key is required"
            )
        enc_key = _check_vault_enc_key(enc_key)
        try:
            nonce = base64.b64decode(payload["nonce"])
            ct = base64.b64decode(payload["ct"])
        except (binascii.Error, ValueError, KeyError) as exc:
            raise VaultError(f"vault entry is corrupt: {exc}") from exc
        try:
            inner = AESGCM(enc_key).decrypt(nonce, ct, _vault_aad(pair_id))
        except InvalidTag as exc:
            raise VaultError(
                "vault decryption failed: wrong key or tampered entry"
            ) from exc
        payload = json.loads(inner.decode("utf-8"))
    return base64.b64decode(payload["key_b64"])


def vault_delete(vault_dir: str | Path, pair_id: str) -> None:
    """Delete the legacy pair key: single overwrite, then unlink.

    Raises KeyError if there is no vault entry.
    """
    path = _vault_path(vault_dir, pair_id)
    if not path.is_file():
        raise KeyError(f"no vault entry for pair {pair_id!r}")
    try:
        size = path.stat().st_size
        with open(path, "r+b") as fh:
            fh.write(b"\x00" * size)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    path.unlink()
