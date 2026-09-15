"""Relationship key rotation (checkpoint 8).

Implements the plan's rotation lifecycle:

1. Prepare: the rotating side (the "recipient" in plan terms) generates a new
   random relationship X25519 keypair at epoch N+1 and sends
   ``security.key.prepare`` carrying the new public key, the prior
   fingerprint, and a 24-hour deadline.
2. Acknowledge: the peer validates continuity, stores the candidate, and
   sends ``security.key.ack``.
3. Dual-wrap: after acknowledgment the peer wraps each outgoing CEK to both
   epoch N and N+1 keys; the envelope ``key_epoch`` is N+1.
4. Confirm: the rotating side decrypts at least one N+1 wrap and sends
   ``security.key.confirm``.
5. Commit: the peer sends ``security.key.commit`` and stops writing old
   wraps. The rotating side retains the old private key for 24 hours or 100
   accepted events, whichever comes first, then deletes it.

Failure behavior (all fail-closed):
- No acknowledgment within 24 hours: the candidate is discarded and the
  relationship remains on epoch N (``NoAckTimeout`` from ``sweep``).
- Acknowledged but unconfirmed: dual-wrap continues until the deadline, then
  the peer's ``may_send`` raises and outgoing sends pause. Never silently
  fall back.
- Conflicting prepares for the same epoch: the incoming prepare is
  quarantined and a human must resolve it (``resolve_quarantine``).
- Data events using a future unknown epoch are quarantined as retryable for
  24 hours, then rejected.

Payload shapes are exactly the landed ``security.schema.json`` variants.
Epochs are relationship-global: either side may rotate, and each rotation
increments the shared counter. Per-side keys are tracked in ``key_epochs``:
rows with ``private_key_ref = 'peer'`` hold the peer's public keys; epoch 1
peer keys live in ``relationships.peer_agreement_key`` per the landed
schema. This module NEVER generates, accepts, or retains a peer private key.

The sealed event envelope (AES-256-GCM, per-message ephemeral keys) is the
transport's job. This module exposes the CEK wrap/unwrap primitives the
transport uses for dual-wrap (``wrap_cek`` / ``unwrap_cek``).
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .._keyfiles import delete_private_key, store_private_key
from ..model.cards import card_fingerprint, create_card, parse_timestamp, verify_card
from ..canonical import restricted_jcs
from ..validation import validate_payload
from .identity import (
    agreement_key_multibase_from_pubkey,
    b64url_decode,
    b64url_encode,
    parse_agreement_key,
    parse_identity_id,
)

__all__ = [
    "RotationError",
    "NoAckTimeout",
    "ConfirmRejected",
    "IdentityRotationError",
    "ROTATION_WINDOW",
    "OLD_KEY_RETENTION",
    "OLD_KEY_EVENT_LIMIT",
    "ROTATION_QUARANTINE_CAP",
    "ROTATION_QUARANTINE_REJECTED_RETENTION",
    "agreement_fingerprint",
    "build_prepare",
    "build_ack",
    "build_confirm",
    "build_commit",
    "wrap_cek",
    "unwrap_cek",
    "RotationManager",
    "rotate_identity_key",
    "verify_identity_rotation",
]

ROTATION_WINDOW = timedelta(hours=24)
OLD_KEY_RETENTION = timedelta(hours=24)
OLD_KEY_EVENT_LIMIT = 100
# Unknown-epoch envelopes are quarantined before any signature check, so a
# forged stream with distinct bogus key_epoch values could otherwise grow
# rotation_quarantine without bound. Cap rows per relationship; rejected
# rows older than the retention window are expired by sweep().
ROTATION_QUARANTINE_CAP = 50
ROTATION_QUARANTINE_REJECTED_RETENTION = timedelta(days=30)

_PEER_REF = "peer"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class RotationError(Exception):
    """Rotation failed fail-closed.

    Attributes:
        code: stable machine-readable reason, e.g. "no_rotation",
            "unknown_prior_fingerprint", "conflicting_prepare",
            "send_paused_acknowledged", "unknown_future_epoch".
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class NoAckTimeout(RotationError):
    """Raised by ``sweep`` when a prepare got no ack within 24 hours."""

    def __init__(self, relationship_id: str, epoch: int) -> None:
        self.relationship_id = relationship_id
        self.epoch = epoch
        super().__init__(
            "no_ack_timeout",
            f"relationship {relationship_id}: no ack for epoch {epoch} "
            "within 24h; candidate discarded, remaining on prior epoch",
        )


class ConfirmRejected(RotationError):
    """A confirm/ack payload failed validation against local state."""

    def __init__(self, message: str) -> None:
        super().__init__("confirm_rejected", message)


class IdentityRotationError(Exception):
    """Identity signing-key rotation failed fail-closed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def agreement_fingerprint(public_key_multibase: str) -> str:
    """Fingerprint a relationship X25519 public key.

    ``base64url(SHA-256(raw 32-byte public key))``, no padding. This is the
    ``prior_fingerprint`` carried in ``security.key.prepare``.
    """
    raw = parse_agreement_key(public_key_multibase)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw)
    return b64url_encode(digest.finalize())


# ---------------------------------------------------------------------------
# Payload builders (exact landed security.schema.json shapes)
# ---------------------------------------------------------------------------

def build_prepare(
    new_agreement_key: str,
    prior_fingerprint: str,
    deadline: datetime,
) -> dict:
    """Build a ``security.key.prepare`` payload."""
    payload = {
        "deadline": _ts(deadline),
        "new_agreement_key": new_agreement_key,
        "prior_fingerprint": prior_fingerprint,
    }
    validate_payload("security.key.prepare", payload)
    return payload


def build_ack(epoch: int, prepare_event_id: str) -> dict:
    """Build a ``security.key.ack`` payload bound to a prepare event."""
    payload = {"epoch": int(epoch), "prepare_event_id": prepare_event_id}
    validate_payload("security.key.ack", payload)
    return payload


def build_confirm(epoch: int) -> dict:
    """Build a ``security.key.confirm`` payload."""
    payload = {"epoch": int(epoch)}
    validate_payload("security.key.confirm", payload)
    return payload


def build_commit(epoch: int) -> dict:
    """Build a ``security.key.commit`` payload."""
    payload = {"epoch": int(epoch)}
    validate_payload("security.key.commit", payload)
    return payload


# ---------------------------------------------------------------------------
# CEK wrap primitives (used by the transport for dual-wrap)
# ---------------------------------------------------------------------------

def _wrap_key(shared_secret: bytes, epoch: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"mas-cek-wrap-v1",
        info=f"epoch:{epoch}".encode("ascii"),
    )
    return hkdf.derive(shared_secret)


def wrap_cek(cek: bytes, recipient_keys: dict) -> dict:
    """Wrap a content-encryption key to one X25519 public key per epoch.

    *recipient_keys* maps epoch (int) to the recipient's agreement public
    key (multibase). Returns ``{str(epoch): {"ephemeral_public_key": hex,
    "wrapped_cek": b64url}}``. During a rotation transition the transport
    passes both the prior and the new epoch keys, which is the dual-wrap.
    """
    if not isinstance(cek, (bytes, bytearray)) or len(cek) != 32:
        raise RotationError("bad_cek", "cek must be 32 bytes")
    wraps = {}
    for epoch, pub_multibase in recipient_keys.items():
        epoch = int(epoch)
        raw_pub = parse_agreement_key(pub_multibase)
        ephemeral = X25519PrivateKey.generate()
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(raw_pub))
        key = _wrap_key(shared, epoch)
        wrapped = bytes(a ^ b for a, b in zip(cek, key))
        wraps[str(epoch)] = {
            "ephemeral_public_key": ephemeral.public_key().public_bytes_raw().hex(),
            "wrapped_cek": b64url_encode(wrapped),
        }
    if not wraps:
        raise RotationError("no_recipient_keys", "recipient_keys is empty")
    return wraps


def unwrap_cek(wraps: dict, epoch: int, recipient_priv: X25519PrivateKey) -> bytes:
    """Unwrap a CEK using the recipient's private key for *epoch*."""
    if not isinstance(wraps, dict):
        raise RotationError("bad_wraps", "wraps must be a mapping")
    wrap = wraps.get(str(int(epoch)))
    if not isinstance(wrap, dict):
        raise RotationError(
            "no_wrap_for_epoch", f"no wrap present for epoch {int(epoch)}"
        )
    try:
        ephemeral_raw = bytes.fromhex(wrap["ephemeral_public_key"])
        wrapped = b64url_decode(wrap["wrapped_cek"])
    except (KeyError, ValueError, TypeError) as exc:
        raise RotationError("bad_wrap", f"malformed wrap: {exc}") from exc
    if len(wrapped) != 32:
        raise RotationError("bad_wrap", "wrapped CEK must be 32 bytes")
    shared = recipient_priv.exchange(X25519PublicKey.from_public_bytes(ephemeral_raw))
    key = _wrap_key(shared, int(epoch))
    return bytes(a ^ b for a, b in zip(wrapped, key))


# ---------------------------------------------------------------------------
# Auxiliary tables
# ---------------------------------------------------------------------------

_ROTATION_TABLES = """
CREATE TABLE IF NOT EXISTS key_rotations (
    relationship_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('rotating', 'acking')),
    phase TEXT NOT NULL CHECK (
        phase IN ('candidate', 'acknowledged', 'confirmed', 'committed', 'discarded')),
    prior_epoch INTEGER,
    prior_fingerprint TEXT,
    new_public_key TEXT,
    prepare_event_id TEXT,
    prepared_at TEXT NOT NULL,
    acknowledged_at TEXT,
    confirmed_at TEXT,
    committed_at TEXT,
    deadline TEXT NOT NULL,
    new_wrap_seen INTEGER NOT NULL DEFAULT 0,
    accepted_events_since_commit INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (relationship_id, epoch, role)
);
CREATE TABLE IF NOT EXISTS rotation_quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    relationship_id TEXT NOT NULL,
    epoch INTEGER,
    reason TEXT NOT NULL,
    payload TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rotation_quarantine_rel
    ON rotation_quarantine (relationship_id);
"""


def _ensure_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(_ROTATION_TABLES)


# ---------------------------------------------------------------------------
# Rotation manager
# ---------------------------------------------------------------------------

class RotationManager:
    """Per-relationship rotation state machine.

    *conn* is the relationship store connection (same one the pairing
    module uses). *keys_dir* holds this side's private key files.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        keys_dir,
        now=None,
    ) -> None:
        self.conn = conn
        self.keys_dir = str(keys_dir)
        self._now_fn = now or _utcnow
        _ensure_tables(conn)

    # -- time ------------------------------------------------------------
    def _now(self, now=None) -> datetime:
        if now is None:
            now = self._now_fn() if callable(self._now_fn) else self._now_fn
        if isinstance(now, str):
            now = parse_timestamp(now)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return now

    # -- key inventory ----------------------------------------------------
    def _own_epochs(self, rid: str) -> dict:
        """Map epoch -> key_epochs row for keys I hold (private)."""
        rows = self.conn.execute(
            "SELECT * FROM key_epochs WHERE relationship_id=? "
            "AND private_key_ref != ?",
            (rid, _PEER_REF),
        ).fetchall()
        return {int(r["epoch"]): r for r in rows}

    def _peer_key_epochs(self, rid: str) -> dict:
        """Map epoch -> peer agreement public key (multibase).

        Epoch 1 peer keys live in ``relationships.peer_agreement_key`` per
        the landed schema (the key_epochs PRIMARY KEY cannot hold both an
        own and a peer row for the same epoch); later peer epochs live in
        key_epochs rows with ``private_key_ref = 'peer'``. The fallback is
        keyed by the relationship's current key_epoch: after the acking side
        commits a rotation, peer_agreement_key holds the peer's NEW key, so
        a hardcoded epoch-1 seed would mislabel it.
        """
        out: dict[int, str] = {}
        rel = self.conn.execute(
            "SELECT peer_agreement_key, key_epoch FROM relationships "
            "WHERE relationship_id=?",
            (rid,),
        ).fetchone()
        if rel and rel["peer_agreement_key"]:
            out[int(rel["key_epoch"] or 1)] = rel["peer_agreement_key"]
        for r in self.conn.execute(
            "SELECT epoch, public_key FROM key_epochs WHERE relationship_id=? "
            "AND private_key_ref = ?",
            (rid, _PEER_REF),
        ).fetchall():
            out[int(r["epoch"])] = r["public_key"]
        return out

    def _current_epoch(self, rid: str) -> int:
        epochs = set(self._own_epochs(rid)) | set(self._peer_key_epochs(rid))
        return max(epochs) if epochs else 0

    def _get_relationship(self, rid: str):
        rel = self.conn.execute(
            "SELECT * FROM relationships WHERE relationship_id=?", (rid,)
        ).fetchone()
        if rel is None:
            raise RotationError("unknown_relationship", f"unknown {rid}")
        return rel

    def _rotation(self, rid: str, epoch: int, role: str | None = None):
        if role is None:
            return self.conn.execute(
                "SELECT * FROM key_rotations WHERE relationship_id=? AND epoch=? "
                "ORDER BY CASE phase WHEN 'discarded' THEN 1 ELSE 0 END LIMIT 1",
                (rid, int(epoch)),
            ).fetchone()
        return self.conn.execute(
            "SELECT * FROM key_rotations WHERE relationship_id=? AND epoch=? "
            "AND role=?",
            (rid, int(epoch), role),
        ).fetchone()

    def _in_flight(self, rid: str):
        return self.conn.execute(
            "SELECT * FROM key_rotations WHERE relationship_id=? "
            "AND phase NOT IN ('committed', 'discarded')",
            (rid,),
        ).fetchone()

    # -- rotating side ----------------------------------------------------
    def begin_rotation(
        self, rid: str, now=None, prepare_event_id: str | None = None
    ) -> dict:
        """Start a rotation: generate epoch N+1 keypair, return prepare.

        Returns ``{"epoch": new_epoch, "prepare": <security.key.prepare
        payload>}``. *prepare_event_id* is the envelope event ID the
        transport will assign; when provided, acks must reference it.
        """
        now = self._now(now)
        self._get_relationship(rid)
        if self._in_flight(rid):
            raise RotationError(
                "rotation_in_flight",
                "another rotation is already in flight for this relationship",
            )
        own = self._own_epochs(rid)
        if not own:
            raise RotationError("no_own_key", "no local key to rotate from")
        prior_epoch = max(own)
        new_epoch = self._current_epoch(rid) + 1
        if new_epoch <= prior_epoch:
            # A peer rotation is ahead of my key; my prior is stale.
            raise RotationError(
                "stale_prior",
                "my latest key epoch is behind the relationship epoch; "
                "cannot rotate until caught up",
            )
        new_priv = X25519PrivateKey.generate()
        new_pub = agreement_key_multibase_from_pubkey(
            new_priv.public_key().public_bytes_raw()
        )
        prior_pub = own[prior_epoch]["public_key"]
        key_path = os.path.join(self.keys_dir, f"{rid}-e{new_epoch}.key")
        deadline = now + ROTATION_WINDOW
        prepare = build_prepare(
            new_pub, agreement_fingerprint(prior_pub), deadline
        )
        with self.conn:
            store_private_key(key_path, new_priv.private_bytes_raw())
            try:
                self.conn.execute(
                    "INSERT INTO key_epochs (relationship_id, epoch, public_key, "
                    "private_key_ref, state) VALUES (?, ?, ?, ?, 'candidate')",
                    (rid, new_epoch, new_pub, key_path),
                )
                # A discarded earlier attempt for this epoch must not block retry.
                self.conn.execute(
                    "DELETE FROM key_rotations WHERE relationship_id=? "
                    "AND epoch=? AND role='rotating' AND phase='discarded'",
                    (rid, new_epoch),
                )
                self.conn.execute(
                    "INSERT INTO key_rotations (relationship_id, epoch, role, "
                    "phase, prior_epoch, prior_fingerprint, new_public_key, "
                    "prepare_event_id, prepared_at, deadline) "
                    "VALUES (?, ?, 'rotating', 'candidate', ?, ?, ?, ?, ?, ?)",
                    (
                        rid, new_epoch, prior_epoch,
                        agreement_fingerprint(prior_pub), new_pub,
                        prepare_event_id, _ts(now), _ts(deadline),
                    ),
                )
            except Exception:
                delete_private_key(key_path)
                raise
        return {"epoch": new_epoch, "prepare": prepare}

    def on_ack(self, rid: str, ack: dict, now=None) -> None:
        """Process the peer's ``security.key.ack`` for my prepare."""
        now = self._now(now)
        validate_payload("security.key.ack", ack)
        rotation = self._rotation(rid, int(ack["epoch"]), "rotating")
        if (
            rotation is None
            or rotation["role"] != "rotating"
            or rotation["phase"] != "candidate"
        ):
            raise ConfirmRejected(
                f"no candidate rotation for epoch {ack['epoch']}"
            )
        if (
            rotation["prepare_event_id"]
            and rotation["prepare_event_id"] != ack["prepare_event_id"]
        ):
            raise ConfirmRejected("ack references a different prepare event")
        if now > parse_timestamp(rotation["deadline"]):
            raise ConfirmRejected("ack arrived after the prepare deadline")
        with self.conn:
            self.conn.execute(
                "UPDATE key_rotations SET phase='acknowledged', "
                "acknowledged_at=? WHERE relationship_id=? AND epoch=?",
                (_ts(now), rid, int(ack["epoch"])),
            )
            self.conn.execute(
                "UPDATE key_epochs SET state='acknowledged' "
                "WHERE relationship_id=? AND epoch=?",
                (rid, int(ack["epoch"])),
            )

    def note_decrypted_new_wrap(self, rid: str, epoch: int, now=None) -> None:
        """Record that a new-epoch wrap was successfully decrypted."""
        self._now(now)
        rotation = self._rotation(rid, int(epoch), "rotating")
        if (
            rotation is None
            or rotation["role"] != "rotating"
            or rotation["phase"] != "acknowledged"
        ):
            raise RotationError(
                "no_acknowledged_rotation",
                f"no acknowledged rotation at epoch {epoch}",
            )
        with self.conn:
            self.conn.execute(
                "UPDATE key_rotations SET new_wrap_seen=1 "
                "WHERE relationship_id=? AND epoch=?",
                (rid, int(epoch)),
            )

    def confirm_rotation(self, rid: str, now=None) -> dict:
        """Send ``security.key.confirm`` after decrypting a new-epoch wrap."""
        now = self._now(now)
        rotation = self._in_flight(rid)
        if (
            rotation is None
            or rotation["role"] != "rotating"
            or rotation["phase"] != "acknowledged"
        ):
            raise RotationError(
                "nothing_to_confirm", "no acknowledged rotation to confirm"
            )
        if not rotation["new_wrap_seen"]:
            raise RotationError(
                "no_new_wrap_seen",
                "confirm requires decrypting at least one new-epoch wrap first",
            )
        with self.conn:
            self.conn.execute(
                "UPDATE key_rotations SET phase='confirmed', confirmed_at=? "
                "WHERE relationship_id=? AND epoch=?",
                (_ts(now), rid, int(rotation["epoch"])),
            )
        return build_confirm(int(rotation["epoch"]))

    def on_commit(self, rid: str, commit: dict, now=None) -> None:
        """Process the peer's ``security.key.commit``; start old-key retention."""
        now = self._now(now)
        validate_payload("security.key.commit", commit)
        epoch = int(commit["epoch"])
        rotation = self._rotation(rid, epoch, "rotating")
        if (
            rotation is None
            or rotation["role"] != "rotating"
            or rotation["phase"] != "confirmed"
        ):
            raise ConfirmRejected(
                f"no confirmed rotation for epoch {epoch}"
            )
        own = self._own_epochs(rid)
        prior_epoch = int(rotation["prior_epoch"])
        with self.conn:
            self.conn.execute(
                "UPDATE key_rotations SET phase='committed', committed_at=?, "
                "accepted_events_since_commit=0 "
                "WHERE relationship_id=? AND epoch=?",
                (_ts(now), rid, epoch),
            )
            self.conn.execute(
                "UPDATE key_epochs SET state='active' "
                "WHERE relationship_id=? AND epoch=?",
                (rid, epoch),
            )
            if prior_epoch in own:
                self.conn.execute(
                    "UPDATE key_epochs SET state='retired' "
                    "WHERE relationship_id=? AND epoch=?",
                    (rid, prior_epoch),
                )
            self.conn.execute(
                "UPDATE relationships SET key_epoch=? WHERE relationship_id=?",
                (epoch, rid),
            )

    def note_accepted_event(self, rid: str, now=None) -> None:
        """Count an accepted data event toward old-key deletion."""
        self._now(now)
        with self.conn:
            self.conn.execute(
                "UPDATE key_rotations SET accepted_events_since_commit = "
                "accepted_events_since_commit + 1 "
                "WHERE relationship_id=? AND phase='committed' AND role='rotating'",
                (rid,),
            )

    # -- acking side ------------------------------------------------------
    def on_prepare(
        self, rid: str, prepare: dict, prepare_event_id: str, now=None
    ) -> dict:
        """Process a ``security.key.prepare``; return the ack payload.

        *prepare_event_id* is the prepare envelope's event ID, echoed in the
        ack to bind the two.
        """
        now = self._now(now)
        validate_payload("security.key.prepare", prepare)
        self._get_relationship(rid)
        peer_epochs = self._peer_key_epochs(rid)
        prior_epoch = None
        for epoch, pub in peer_epochs.items():
            if agreement_fingerprint(pub) == prepare["prior_fingerprint"]:
                prior_epoch = epoch
                break
        if prior_epoch is None:
            raise RotationError(
                "unknown_prior_fingerprint",
                "prepare references a prior key I do not hold; rejecting",
            )
        new_epoch = prior_epoch + 1
        existing_peer = self.conn.execute(
            "SELECT public_key FROM key_epochs WHERE relationship_id=? "
            "AND epoch=? AND private_key_ref=?",
            (rid, new_epoch, _PEER_REF),
        ).fetchone()
        if existing_peer is not None:
            if existing_peer["public_key"] != prepare["new_agreement_key"]:
                self._quarantine(
                    rid, new_epoch, "conflicting_prepare",
                    {"prepare": prepare, "prepare_event_id": prepare_event_id},
                    now,
                )
                raise RotationError(
                    "conflicting_prepare",
                    f"two different keys proposed for epoch {new_epoch}; "
                    "quarantined for human resolution",
                )
            return build_ack(new_epoch, prepare_event_id)  # redelivery
        if prior_epoch != max(peer_epochs):
            raise RotationError(
                "stale_prior_fingerprint",
                "prepare references an older peer key; possible rollback, "
                "rejecting",
            )
        own = self._own_epochs(rid)
        if new_epoch in own:
            rotation = self._rotation(rid, new_epoch, "rotating")
            if (
                rotation is not None
                and rotation["role"] == "rotating"
                and rotation["phase"] not in ("committed", "discarded")
            ):
                # I am also rotating into this epoch: human must decide.
                self._quarantine(
                    rid, new_epoch, "conflicting_prepare",
                    {"prepare": prepare, "prepare_event_id": prepare_event_id},
                    now,
                )
                raise RotationError(
                    "conflicting_prepare",
                    f"both sides prepared epoch {new_epoch}; quarantined for "
                    "human resolution",
                )
            raise RotationError(
                "stale_epoch",
                f"epoch {new_epoch} is already used on this side; rejecting",
            )
        if new_epoch <= self._current_epoch(rid):
            raise RotationError(
                "stale_epoch",
                f"epoch {new_epoch} is behind the current epoch; rejecting",
            )
        if self._in_flight(rid):
            raise RotationError(
                "rotation_in_flight",
                "another rotation is already in flight for this relationship",
            )
        if now > parse_timestamp(prepare["deadline"]):
            raise RotationError(
                "prepare_expired", "prepare arrived after its own deadline"
            )
        deadline = parse_timestamp(prepare["deadline"])
        with self.conn:
            self.conn.execute(
                "INSERT INTO key_epochs (relationship_id, epoch, public_key, "
                "private_key_ref, state) VALUES (?, ?, ?, ?, 'acknowledged')",
                (rid, new_epoch, prepare["new_agreement_key"], _PEER_REF),
            )
            # A discarded earlier attempt for this epoch must not block retry.
            self.conn.execute(
                "DELETE FROM key_rotations WHERE relationship_id=? "
                "AND epoch=? AND role='acking' AND phase='discarded'",
                (rid, new_epoch),
            )
            self.conn.execute(
                "INSERT INTO key_rotations (relationship_id, epoch, role, "
                "phase, prior_epoch, prior_fingerprint, new_public_key, "
                "prepare_event_id, prepared_at, acknowledged_at, deadline) "
                "VALUES (?, ?, 'acking', 'acknowledged', ?, ?, ?, ?, ?, ?, ?)",
                (
                    rid, new_epoch, prior_epoch, prepare["prior_fingerprint"],
                    prepare["new_agreement_key"], prepare_event_id,
                    _ts(now), _ts(now), _ts(deadline),
                ),
            )
            # A real prepare resolves any queued future-epoch data events.
            self.conn.execute(
                "DELETE FROM rotation_quarantine WHERE relationship_id=? "
                "AND reason='unknown_future_epoch' AND epoch <= ?",
                (rid, new_epoch),
            )
        return build_ack(new_epoch, prepare_event_id)

    def dual_wrap_keys(self, rid: str) -> dict:
        """Peer's keys for dual-wrap: {prior_epoch: key, new_epoch: key}.

        Used by the transport after acknowledgment: every outgoing CEK is
        wrapped to both the peer's prior and new keys, with the envelope
        ``key_epoch`` set to the new epoch.
        """
        rotation = self._in_flight(rid)
        if (
            rotation is None
            or rotation["role"] != "acking"
            or rotation["phase"] not in ("acknowledged", "confirmed")
        ):
            raise RotationError(
                "no_acknowledged_rotation",
                "dual-wrap requires an acknowledged rotation",
            )
        peer_epochs = self._peer_key_epochs(rid)
        epoch = int(rotation["epoch"])
        prior_epoch = int(rotation["prior_epoch"])
        if epoch not in peer_epochs or prior_epoch not in peer_epochs:
            raise RotationError("peer_key_missing", "peer key row vanished")
        return {prior_epoch: peer_epochs[prior_epoch], epoch: peer_epochs[epoch]}

    def may_send(self, rid: str, now=None) -> None:
        """Gate outgoing sends for the acking side.

        Raises ``RotationError("send_paused_acknowledged")`` once the
        deadline passes without a confirm. The peer must alert a human and
        pause; it must not silently fall back to old-epoch-only sends.
        """
        now = self._now(now)
        rotation = self.conn.execute(
            "SELECT * FROM key_rotations WHERE relationship_id=? "
            "AND role='acking' AND phase='acknowledged'",
            (rid,),
        ).fetchone()
        if rotation is None:
            return
        if now > parse_timestamp(rotation["deadline"]):
            raise RotationError(
                "send_paused_acknowledged",
                f"epoch {rotation['epoch']} acknowledged but never confirmed; "
                "deadline passed: pause outgoing sends and alert a human",
            )

    def on_confirm(self, rid: str, confirm: dict, now=None) -> None:
        """Process the rotating side's ``security.key.confirm``."""
        now = self._now(now)
        validate_payload("security.key.confirm", confirm)
        rotation = self._rotation(rid, int(confirm["epoch"]), "acking")
        if (
            rotation is None
            or rotation["role"] != "acking"
            or rotation["phase"] != "acknowledged"
        ):
            raise ConfirmRejected(
                f"no acknowledged rotation for epoch {confirm['epoch']}"
            )
        with self.conn:
            self.conn.execute(
                "UPDATE key_rotations SET phase='confirmed', confirmed_at=? "
                "WHERE relationship_id=? AND epoch=?",
                (_ts(now), rid, int(confirm["epoch"])),
            )

    def build_commit_payload(self, rid: str, now=None) -> dict:
        """Build ``security.key.commit``; the peer stops writing old wraps."""
        now = self._now(now)
        rotation = self._in_flight(rid)
        if (
            rotation is None
            or rotation["role"] != "acking"
            or rotation["phase"] != "confirmed"
        ):
            raise RotationError(
                "nothing_to_commit", "no confirmed rotation to commit"
            )
        epoch = int(rotation["epoch"])
        new_peer_key = rotation["new_public_key"]
        with self.conn:
            self.conn.execute(
                "UPDATE key_rotations SET phase='committed', committed_at=? "
                "WHERE relationship_id=? AND epoch=?",
                (_ts(now), rid, epoch),
            )
            self.conn.execute(
                "UPDATE key_epochs SET state='active' "
                "WHERE relationship_id=? AND epoch=? AND private_key_ref=?",
                (rid, epoch, _PEER_REF),
            )
            # The peer's agreement key changed: future sends must wrap to
            # the new key. Without this, _recipients_for keeps wrapping to
            # the old key while labeling the new key_epoch, so a peer that
            # rotated because its old key was compromised stays readable to
            # the attacker.
            self.conn.execute(
                "UPDATE relationships SET key_epoch=?, peer_agreement_key=? "
                "WHERE relationship_id=?",
                (epoch, new_peer_key, rid),
            )
        return build_commit(epoch)

    # -- data-plane epoch gate --------------------------------------------
    def on_data_event_epoch(self, rid: str, key_epoch: int, now=None) -> str:
        """Gate a data event by its envelope ``key_epoch``.

        Returns ``"ok"`` when the epoch is known. Raises
        ``RotationError("unknown_future_epoch")`` for a future unknown epoch
        (quarantined as retryable); after 24 hours without the epoch becoming
        known, raises ``RotationError("unknown_future_epoch_rejected")``.
        """
        now = self._now(now)
        key_epoch = int(key_epoch)
        known = self._current_epoch(rid)
        if key_epoch <= known:
            return "ok"
        entry = self.conn.execute(
            "SELECT * FROM rotation_quarantine WHERE relationship_id=? "
            "AND epoch=? AND reason IN "
            "('unknown_future_epoch', 'unknown_future_epoch_rejected') "
            "ORDER BY id DESC LIMIT 1",
            (rid, key_epoch),
        ).fetchone()
        if entry is not None:
            if entry["reason"] == "unknown_future_epoch_rejected":
                raise RotationError(
                    "unknown_future_epoch_rejected",
                    f"epoch {key_epoch} was rejected after the 24h window",
                )
            if now > parse_timestamp(entry["received_at"]) + ROTATION_WINDOW:
                with self.conn:
                    self.conn.execute(
                        "UPDATE rotation_quarantine SET reason=?, payload=? "
                        "WHERE id=?",
                        (
                            "unknown_future_epoch_rejected",
                            json.dumps({"epoch": key_epoch}),
                            entry["id"],
                        ),
                    )
                raise RotationError(
                    "unknown_future_epoch_rejected",
                    f"epoch {key_epoch} still unknown after 24h; rejecting",
                )
            raise RotationError(
                "unknown_future_epoch",
                f"epoch {key_epoch} is unknown; quarantined as retryable",
            )
        with self.conn:
            self.conn.execute(
                "INSERT INTO rotation_quarantine "
                "(relationship_id, epoch, reason, payload, received_at) "
                "VALUES (?, ?, 'unknown_future_epoch', ?, ?)",
                (rid, key_epoch, json.dumps({"epoch": key_epoch}), _ts(now)),
            )
            self._cap_quarantine(rid)
        raise RotationError(
            "unknown_future_epoch",
            f"epoch {key_epoch} is unknown; quarantined as retryable",
        )

    # -- quarantine ---------------------------------------------------------
    def _cap_quarantine(self, rid: str) -> None:
        """Keep rotation_quarantine bounded per relationship.

        The unknown-epoch gate inserts before any signature check, so this
        cap is the only thing stopping a forged stream of distinct bogus
        epochs from growing the table without bound. Oldest rows go first;
        the newest ROTATION_QUARANTINE_CAP rows survive.
        """
        self.conn.execute(
            "DELETE FROM rotation_quarantine WHERE relationship_id=? "
            "AND id NOT IN (SELECT id FROM rotation_quarantine "
            "WHERE relationship_id=? ORDER BY id DESC LIMIT ?)",
            (rid, rid, ROTATION_QUARANTINE_CAP),
        )

    def _quarantine(self, rid, epoch, reason, payload, now) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO rotation_quarantine "
                "(relationship_id, epoch, reason, payload, received_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (rid, epoch, reason, json.dumps(payload), _ts(now)),
            )
            self._cap_quarantine(rid)

    def list_quarantine(self, rid: str) -> list:
        """List quarantine entries for a relationship (oldest first)."""
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM rotation_quarantine WHERE relationship_id=? "
                "ORDER BY id",
                (rid,),
            ).fetchall()
        ]

    def resolve_quarantine(
        self, rid: str, index: int, choice: str, now=None
    ):
        """Human resolution of a quarantined conflicting prepare.

        *choice* is ``"mine"`` (keep my candidate, discard theirs) or
        ``"theirs"`` (discard my candidate and process their prepare,
        returning the ack payload). Anything else raises.
        """
        now = self._now(now)
        entries = self.list_quarantine(rid)
        if index < 0 or index >= len(entries):
            raise RotationError(
                "bad_quarantine_index", f"no quarantine entry {index}"
            )
        if choice not in ("mine", "theirs"):
            raise RotationError(
                "bad_choice", 'choice must be "mine" or "theirs"'
            )
        entry = entries[index]
        if entry["reason"] != "conflicting_prepare":
            raise RotationError(
                "not_resolvable",
                f"entry {index} ({entry['reason']}) is not a conflicting prepare",
            )
        payload = json.loads(entry["payload"])
        epoch = int(entry["epoch"])
        with self.conn:
            self.conn.execute(
                "DELETE FROM rotation_quarantine WHERE id=?", (entry["id"],)
            )
            if choice == "theirs":
                self._discard_candidate(rid, epoch)
        if choice == "theirs":
            return self.on_prepare(
                rid, payload["prepare"], payload["prepare_event_id"], now=now
            )
        return None

    def _discard_candidate(self, rid: str, epoch: int) -> None:
        row = self.conn.execute(
            "SELECT private_key_ref FROM key_epochs WHERE relationship_id=? "
            "AND epoch=? AND private_key_ref != ?",
            (rid, epoch, _PEER_REF),
        ).fetchone()
        if row:
            delete_private_key(row["private_key_ref"])
            self.conn.execute(
                "DELETE FROM key_epochs WHERE relationship_id=? AND epoch=?",
                (rid, epoch),
            )
        self.conn.execute(
            "UPDATE key_rotations SET phase='discarded' "
            "WHERE relationship_id=? AND epoch=? AND role='rotating' "
            "AND phase NOT IN ('committed', 'discarded')",
            (rid, epoch),
        )

    # -- sweep ----------------------------------------------------------------
    def sweep(self, now=None) -> None:
        """Run periodic rotation maintenance.

        - Discards unacknowledged candidates after 24h (raises
          ``NoAckTimeout`` for the first one found).
        - Deletes the old private key after commit once 24 hours have passed
          or 100 events were accepted under the new epoch, whichever first.
        - Expires rejected unknown-epoch quarantine rows older than
          ``ROTATION_QUARANTINE_REJECTED_RETENTION``.
        """
        now = self._now(now)
        with self.conn:
            self.conn.execute(
                "DELETE FROM rotation_quarantine "
                "WHERE reason='unknown_future_epoch_rejected' AND received_at <= ?",
                (_ts(now - ROTATION_QUARANTINE_REJECTED_RETENTION),),
            )
        row = self.conn.execute(
            "SELECT relationship_id, epoch FROM key_rotations "
            "WHERE role='rotating' AND phase='candidate' AND deadline <= ? "
            "ORDER BY deadline LIMIT 1",
            (_ts(now),),
        ).fetchone()
        if row is not None:
            rid, epoch = row["relationship_id"], int(row["epoch"])
            with self.conn:
                self._discard_candidate(rid, epoch)
            raise NoAckTimeout(rid, epoch)
        for rotation in self.conn.execute(
            "SELECT relationship_id, epoch, prior_epoch, committed_at, "
            "accepted_events_since_commit FROM key_rotations "
            "WHERE role='rotating' AND phase='committed'"
        ).fetchall():
            rid = rotation["relationship_id"]
            epoch = int(rotation["epoch"])
            prior_epoch = (
                int(rotation["prior_epoch"])
                if rotation["prior_epoch"] is not None
                else None
            )
            committed_at = parse_timestamp(rotation["committed_at"])
            due_time = now >= committed_at + OLD_KEY_RETENTION
            due_events = (
                int(rotation["accepted_events_since_commit"])
                >= OLD_KEY_EVENT_LIMIT
            )
            if (due_time or due_events) and prior_epoch is not None:
                with self.conn:
                    key_row = self.conn.execute(
                        "SELECT private_key_ref FROM key_epochs "
                        "WHERE relationship_id=? AND epoch=? "
                        "AND private_key_ref != ?",
                        (rid, prior_epoch, _PEER_REF),
                    ).fetchone()
                    if key_row:
                        delete_private_key(key_row["private_key_ref"])
                        self.conn.execute(
                            "DELETE FROM key_epochs WHERE relationship_id=? "
                            "AND epoch=?",
                            (rid, prior_epoch),
                        )


# ---------------------------------------------------------------------------
# Identity signing-key rotation
# ---------------------------------------------------------------------------

def rotate_identity_key(
    old_card: dict,
    old_ed25519_priv: Ed25519PrivateKey | None,
    new_ed25519_priv: Ed25519PrivateKey,
    now=None,
) -> dict:
    """Rotate the identity signing key, cross-signed by old and new keys.

    Returns an identity-rotation announcement (NOT a card; the agent-card
    schema is closed)::

        {
          "rotation_version": 1,
          "prior_card_fingerprint": "<hex sha256 of old card>",
          "new_card": { ... new card signed by the new key ... },
          "cross_signatures": [
            {"key_id": "<old identity_id>", "signature": "<b64url>"},
            {"key_id": "<new identity_id>", "signature": "<b64url>"}
          ]
        }

    The new card keeps the display labels, capabilities, agreement key, and
    expiry of the old card, but its ``identity_id`` is derived from the new
    key, so the identity ID changes. Both cross-signatures cover the
    restricted-JCS bytes of the new card (including its signature).

    If the old private key is unavailable, continuity cannot be proven, so
    this raises ``IdentityRotationError("old_key_unavailable")``: the caller
    must pause pairing and run a new eight-word verification ceremony.
    """
    now = _utcnow() if now is None else now
    if old_ed25519_priv is None:
        raise IdentityRotationError(
            "old_key_unavailable",
            "cannot prove continuity without the old signing key; pause "
            "pairing and run a new eight-word verification ceremony",
        )
    if not isinstance(old_ed25519_priv, Ed25519PrivateKey):
        raise IdentityRotationError(
            "bad_old_key", "old_ed25519_priv must be an Ed25519PrivateKey"
        )
    if not isinstance(new_ed25519_priv, Ed25519PrivateKey):
        raise IdentityRotationError(
            "bad_new_key", "new_ed25519_priv must be an Ed25519PrivateKey"
        )
    if not isinstance(old_card, dict):
        raise IdentityRotationError("bad_card", "old_card must be a dict")
    old_id = old_card.get("identity_id", "")
    try:
        old_pub = parse_identity_id(old_id)
    except ValueError as exc:
        raise IdentityRotationError("bad_card", f"bad old identity_id: {exc}") from exc
    if old_ed25519_priv.public_key().public_bytes_raw() != old_pub:
        raise IdentityRotationError(
            "key_mismatch", "old_ed25519_priv does not match old_card"
        )

    new_card = create_card(
        new_ed25519_priv,
        old_card.get("display_name", ""),
        old_card.get("principal_label", ""),
        old_card.get("bootstrap_agreement_key", ""),
        list(old_card.get("capabilities", [])),
        now,
        old_card.get("expires_at", ""),
    )
    new_id = new_card["identity_id"]
    if new_id == old_id:
        raise IdentityRotationError(
            "same_key", "new key must differ from the old key"
        )
    canonical_new = restricted_jcs(new_card)
    cross = []
    for key_id, priv in ((old_id, old_ed25519_priv), (new_id, new_ed25519_priv)):
        cross.append(
            {
                "key_id": key_id,
                "signature": b64url_encode(priv.sign(canonical_new)),
            }
        )
    return {
        "rotation_version": 1,
        "prior_card_fingerprint": card_fingerprint(old_card),
        "new_card": new_card,
        "cross_signatures": cross,
    }


def verify_identity_rotation(announcement: dict, old_card: dict, now=None) -> bool:
    """Verify an identity-rotation announcement. Fail-closed: False on any problem."""
    try:
        if not isinstance(announcement, dict):
            return False
        if announcement.get("rotation_version") != 1:
            return False
        if announcement.get("prior_card_fingerprint") != card_fingerprint(old_card):
            return False
        new_card = announcement.get("new_card")
        if not isinstance(new_card, dict):
            return False
        if not verify_card(new_card, now).ok:
            return False
        old_id = old_card.get("identity_id", "")
        new_id = new_card.get("identity_id", "")
        if not old_id or not new_id or old_id == new_id:
            return False
        sigs = announcement.get("cross_signatures")
        if not isinstance(sigs, list) or len(sigs) != 2:
            return False
        by_key = {s.get("key_id"): s.get("signature") for s in sigs
                  if isinstance(s, dict)}
        if set(by_key) != {old_id, new_id}:
            return False
        canonical_new = restricted_jcs(new_card)
        for key_id in (old_id, new_id):
            pub = parse_identity_id(key_id)
            signature = b64url_decode(by_key[key_id])
            Ed25519PublicKey.from_public_bytes(pub).verify(signature, canonical_new)
        return True
    except (ValueError, InvalidSignature, KeyError, TypeError):
        return False
