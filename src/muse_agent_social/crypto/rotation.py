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
transport's job (``crypto.sealing``); this module supplies the per-epoch
peer public keys the transport dual-wraps to (``dual_wrap_keys``).
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from itertools import count as _count

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

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
    "KEY_ROTATION_COMMITTED_RETENTION",
    "PEER_KEY_EPOCH_RETAIN_NEWEST",
    "SECURITY_KEY_EVENT_RETENTION",
    "agreement_fingerprint",
    "build_prepare",
    "build_ack",
    "build_confirm",
    "build_commit",
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

# G16: committed rotation history retention. Committed key_rotations rows
# are history, not live state: sweep() deletes committed rows older than
# this, always keeping the newest committed row per (relationship, role)
# so build_commit()'s redelivery fallback and mark_committed()'s
# crash re-drive keep working. Safe because the 7-day accept window
# means no commit redelivery can arrive after the retention age.
KEY_ROTATION_COMMITTED_RETENTION = timedelta(days=30)

# G16: peer agreement-key retention. The seal side wraps to at most the
# peer's current and previous epoch (dual-wrap bound), and the 7-day
# accept window means no legitimate send can need an older peer public
# key, so sweep() keeps only the two newest peer key_epochs rows per
# relationship. Own private keys are unaffected: their 24h/100-event
# replay-acceptance retention (OLD_KEY_RETENTION/OLD_KEY_EVENT_LIMIT)
# is handled separately and must not be shortened, or delayed
# pre-rotation events would fail to unseal.
PEER_KEY_EPOCH_RETAIN_NEWEST = 2

# G16: projected security-key ceremony index retention. The ceremony
# events themselves are immutable in the event log; security_key_events
# is a convenience projection, compacted by receiver acceptance time
# (never sender-created_at). A rebuild re-derives the full history from
# the log, so this bounds steady-state growth, not disaster recovery.
SECURITY_KEY_EVENT_RETENTION = timedelta(days=90)

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


_savepoint_ids = _count()


@contextmanager
def _savepoint(conn):
    """Atomic sub-unit when the connection already holds a transaction.

    SQLite rejects a nested BEGIN IMMEDIATE, which happens on legacy
    implicit-transaction connections (some tests open one and never
    commit). A SAVEPOINT scopes the same atomicity without nesting.
    """
    name = f"mas_txn_{next(_savepoint_ids)}"
    conn.execute(f"SAVEPOINT {name};")
    try:
        yield conn
    except BaseException:
        conn.execute(f"ROLLBACK TO SAVEPOINT {name};")
        conn.execute(f"RELEASE SAVEPOINT {name};")
        raise
    else:
        conn.execute(f"RELEASE SAVEPOINT {name};")


def _txn(conn):
    """A real BEGIN IMMEDIATE transaction without a top-level import.

    ``from ..store.db import transaction`` at module top is circular:
    muse_agent_social.store imports this module at package init (for the
    rotation-table DDL), which breaks ``import
    muse_agent_social.crypto.rotation`` as an entry point. Import lazily at
    call time instead; by then every package is fully initialized.

    Re-entrant: when the connection already holds a transaction (legacy
    implicit-transaction connections), a SAVEPOINT provides the atomic
    sub-unit instead of a nested BEGIN IMMEDIATE, which SQLite rejects.
    On production connections (autocommit) this always takes the real
    BEGIN IMMEDIATE path.
    """
    from ..store.db import transaction

    if conn.in_transaction:
        return _savepoint(conn)
    return transaction(conn)


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
-- Durable first-seen record for unknown future epochs. rotation_quarantine
-- is capped by evicting the oldest rows, which must not reset the 24-hour
-- rejection timer: this table keeps one row per (relationship, epoch) that
-- cap eviction can never touch.
CREATE TABLE IF NOT EXISTS unknown_epoch_first_seen (
    relationship_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    first_seen_at TEXT NOT NULL,
    -- Permanent tombstone: once the 24h window elapses the epoch is
    -- rejected forever. Cap eviction must never delete a rejected row,
    -- or the rejection timer would reset and the epoch would become
    -- retryable again.
    rejected INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (relationship_id, epoch)
);
-- Rotation events whose post-receive hook was attempted (success or
-- deterministic rejection). The per-poll reconciler re-drives accepted
-- rotation events lacking a row here, converging the crash gap between
-- the receive commit and _post_receive_hooks.
CREATE TABLE IF NOT EXISTS rotation_processed_events (
    event_id TEXT PRIMARY KEY,
    relationship_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    processed_at TEXT NOT NULL
);
-- Decrypt signals that arrived before their rotation row was acknowledged
-- (a new-epoch data event can beat the ack on a quiet relationship). The
-- ack consumes the parked signal so confirm_rotation never stalls on pure
-- reordering. Swept after ROTATION_WINDOW when never consumed.
CREATE TABLE IF NOT EXISTS rotation_wrap_seen_pending (
    relationship_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    seen_at TEXT NOT NULL,
    PRIMARY KEY (relationship_id, epoch)
);
"""


def _ensure_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(_ROTATION_TABLES)
    _ensure_first_seen_rejected(conn)


def _ensure_first_seen_rejected(conn: sqlite3.Connection) -> None:
    """Backfill the ``rejected`` tombstone column on older databases.

    The CREATE TABLE above is IF NOT EXISTS, so databases created before
    the tombstone existed keep the old shape without this.
    """
    cols = [row[1] for row in conn.execute(
        "PRAGMA table_info(unknown_epoch_first_seen);"
    ).fetchall()]
    if "rejected" not in cols:
        conn.execute(
            "ALTER TABLE unknown_epoch_first_seen"
            " ADD COLUMN rejected INTEGER NOT NULL DEFAULT 0;"
        )


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

    def _in_flight(self, rid: str, role: str | None = None):
        """Return the current in-flight rotation row, if any.

        Pass ``role='rotating'`` or ``role='acking'`` when the caller
        requires a specific side; without it the query is role-agnostic
        and can return the other side's row after conflict resolution.
        """
        if role is None:
            return self.conn.execute(
                "SELECT * FROM key_rotations WHERE relationship_id=? "
                "AND phase NOT IN ('committed', 'discarded')",
                (rid,),
            ).fetchone()
        return self.conn.execute(
            "SELECT * FROM key_rotations WHERE relationship_id=? "
            "AND role=? AND phase NOT IN ('committed', 'discarded')",
            (rid, role),
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
        try:
            store_private_key(key_path, new_priv.private_bytes_raw())
        except FileExistsError:
            # A crashed earlier attempt may have stored the key file without
            # committing its rows. Reconcile: wipe the orphan and retry the
            # store, or re-raise when live state owns the file.
            self._reconcile_orphan_key_file(rid, new_epoch, key_path)
            store_private_key(key_path, new_priv.private_bytes_raw())
        try:
            # All three writes are one atomic transaction (BEGIN IMMEDIATE):
            # a crash between them used to leave a key row with no rotation
            # row (or vice versa), wedging the rotation permanently.
            with _txn(self.conn):
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

    def _reconcile_orphan_key_file(
        self, rid: str, epoch: int, key_path: str
    ) -> None:
        """Reconcile a pre-existing key file before a fresh rotation store.

        Called when ``store_private_key`` raises FileExistsError. When the
        database holds a live key row or a live rotation row for the epoch,
        the file is genuinely owned: re-raise FileExistsError, never
        overwrite. Otherwise the file is an orphan from a crashed attempt
        (stored but never committed, or discarded with the file deletion
        lost): securely delete it so the caller can retry the store.
        """
        key_row = self.conn.execute(
            "SELECT 1 FROM key_epochs WHERE relationship_id=? AND epoch=? "
            "AND private_key_ref != ?",
            (rid, epoch, _PEER_REF),
        ).fetchone()
        rotation = self._rotation(rid, epoch, "rotating")
        live = key_row is not None or (
            rotation is not None and rotation["phase"] != "discarded"
        )
        if live:
            raise FileExistsError(
                f"key file {key_path} already exists and epoch {epoch} has "
                "live rotation state; refusing to overwrite"
            )
        delete_private_key(key_path)

    def on_ack(self, rid: str, ack: dict, now=None) -> None:
        """Process the peer's ``security.key.ack`` for my prepare."""
        now = self._now(now)
        validate_payload("security.key.ack", ack)
        epoch = int(ack["epoch"])
        rotation = self._rotation(rid, epoch, "rotating")
        if rotation is None or rotation["role"] != "rotating":
            raise ConfirmRejected(
                f"no candidate rotation for epoch {ack['epoch']}"
            )
        if (
            rotation["prepare_event_id"]
            and rotation["prepare_event_id"] != ack["prepare_event_id"]
        ):
            raise ConfirmRejected("ack references a different prepare event")
        if rotation["phase"] == "acknowledged":
            # Idempotent re-drive (crash converged the ack but the hook
            # never got marked): already applied. Still consume any decrypt
            # signal parked before the ack arrived.
            with _txn(self.conn):
                self._consume_pending_wrap_seen(rid, epoch)
            return
        if rotation["phase"] != "candidate":
            raise ConfirmRejected(
                f"no candidate rotation for epoch {ack['epoch']}"
            )
        if now > parse_timestamp(rotation["deadline"]):
            raise ConfirmRejected("ack arrived after the prepare deadline")
        with _txn(self.conn):
            cur = self.conn.execute(
                "UPDATE key_rotations SET phase='acknowledged', "
                "acknowledged_at=? WHERE relationship_id=? AND epoch=? "
                "AND role='rotating' AND phase='candidate'",
                (_ts(now), rid, epoch),
            )
            if cur.rowcount == 0:
                # Lost a race (e.g. sweep discarded the candidate
                # concurrently): re-read and report honestly instead of
                # silently succeeding or resurrecting the row.
                raise ConfirmRejected(
                    f"no candidate rotation for epoch {epoch}"
                )
            self.conn.execute(
                "UPDATE key_epochs SET state='acknowledged' "
                "WHERE relationship_id=? AND epoch=? AND private_key_ref != ?",
                (rid, epoch, _PEER_REF),
            )
            self._consume_pending_wrap_seen(rid, epoch)

    def _consume_pending_wrap_seen(self, rid: str, epoch: int) -> None:
        """Backfill new_wrap_seen from a decrypt signal parked pre-ack.

        Must be called inside the caller's transaction.
        """
        cur = self.conn.execute(
            "DELETE FROM rotation_wrap_seen_pending "
            "WHERE relationship_id=? AND epoch=?",
            (rid, epoch),
        )
        if cur.rowcount:
            self.conn.execute(
                "UPDATE key_rotations SET new_wrap_seen=1 "
                "WHERE relationship_id=? AND epoch=? AND role='rotating' "
                "AND phase NOT IN ('discarded', 'committed')",
                (rid, epoch),
            )

    def note_decrypted_new_wrap(self, rid: str, epoch: int, now=None) -> None:
        """Record that a new-epoch wrap was successfully decrypted.

        Idempotent and phase-agnostic: a new-epoch data event can arrive
        before the ack on a quiet relationship, and the old code dropped
        the signal (raising ``no_acknowledged_rotation``), which later
        failed ``confirm_rotation`` with ``no_new_wrap_seen``. The signal
        is recorded on any live rotating row; when no row exists yet it is
        parked and consumed by ``on_ack``.
        """
        now = self._now(now)
        epoch = int(epoch)
        with _txn(self.conn):
            cur = self.conn.execute(
                "UPDATE key_rotations SET new_wrap_seen=1 "
                "WHERE relationship_id=? AND epoch=? AND role='rotating' "
                "AND phase NOT IN ('discarded', 'committed')",
                (rid, epoch),
            )
            if cur.rowcount == 0:
                self.conn.execute(
                    "INSERT OR REPLACE INTO rotation_wrap_seen_pending "
                    "(relationship_id, epoch, seen_at) VALUES (?, ?, ?)",
                    (rid, epoch, _ts(now)),
                )

    def build_confirm_payload(self, rid: str, now=None) -> dict:
        """Build ``security.key.confirm`` without changing phase.

        Idempotent: safe to call any number of times while the rotation is
        acknowledged (or already confirmed, for re-emit after a crash
        between send and mark). The CLI sends this payload first and calls
        ``mark_confirmed`` only after the send is durably enqueued, so a
        failed send never wedges the rotation in 'confirmed' with no
        confirm event on the wire.
        """
        self._now(now)
        rotation = self._in_flight(rid, role='rotating')
        if (
            rotation is None
            or rotation["role"] != "rotating"
            or rotation["phase"] not in ("acknowledged", "confirmed")
        ):
            raise RotationError(
                "nothing_to_confirm", "no acknowledged rotation to confirm"
            )
        if not rotation["new_wrap_seen"]:
            raise RotationError(
                "no_new_wrap_seen",
                "confirm requires decrypting at least one new-epoch wrap first",
            )
        return build_confirm(int(rotation["epoch"]))

    def mark_confirmed(self, rid: str, now=None) -> None:
        """Record that the confirm was sent (acknowledged -> confirmed).

        Idempotent: a re-drive after a crash between the send and this
        mark is a no-op.
        """
        now = self._now(now)
        with _txn(self.conn):
            rotation = self._in_flight(rid, role='rotating')
            if rotation is not None and rotation["phase"] == "confirmed":
                return
            if (
                rotation is None
                or rotation["role"] != "rotating"
                or rotation["phase"] != "acknowledged"
            ):
                raise RotationError(
                    "nothing_to_confirm", "no acknowledged rotation to confirm"
                )
            cur = self.conn.execute(
                "UPDATE key_rotations SET phase='confirmed', confirmed_at=? "
                "WHERE relationship_id=? AND epoch=? AND role='rotating' "
                "AND phase='acknowledged'",
                (_ts(now), rid, int(rotation["epoch"])),
            )
            if cur.rowcount == 0:
                raise RotationError(
                    "nothing_to_confirm", "lost race confirming rotation"
                )

    def confirm_rotation(self, rid: str, now=None) -> dict:
        """Build and mark the confirm atomically (single-process path).

        Prefer ``build_confirm_payload`` + ``mark_confirmed`` around the
        real send: this combined form transitions before the caller can
        send, so a send failure after it returns still needs the
        idempotent re-emit below to recover.
        """
        now = self._now(now)
        with _txn(self.conn):
            rotation = self._in_flight(rid, role='rotating')
            if rotation is not None and rotation["phase"] == "confirmed":
                # Idempotent re-emit: the confirm was already marked (a
                # previous send failed after the transition); hand the
                # payload back so the caller can retry the send.
                return build_confirm(int(rotation["epoch"]))
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
            cur = self.conn.execute(
                "UPDATE key_rotations SET phase='confirmed', confirmed_at=? "
                "WHERE relationship_id=? AND epoch=? AND role='rotating' "
                "AND phase='acknowledged'",
                (_ts(now), rid, int(rotation["epoch"])),
            )
            if cur.rowcount == 0:
                raise RotationError(
                    "nothing_to_confirm", "lost race confirming rotation"
                )
            return build_confirm(int(rotation["epoch"]))

    def on_commit(self, rid: str, commit: dict, now=None) -> None:
        """Process the peer's ``security.key.commit``; start old-key retention."""
        now = self._now(now)
        validate_payload("security.key.commit", commit)
        epoch = int(commit["epoch"])
        rotation = self._rotation(rid, epoch, "rotating")
        if rotation is None:
            # The committed row may have been cleaned up by sweep after
            # old-key deletion (R10): if the epoch is already our active
            # epoch, this is a benign redelivery.
            rel = self.conn.execute(
                "SELECT key_epoch FROM relationships WHERE relationship_id=?",
                (rid,),
            ).fetchone()
            if rel is not None and int(rel["key_epoch"]) == epoch:
                return
            raise ConfirmRejected(
                f"no confirmed rotation for epoch {epoch}"
            )
        if rotation["role"] != "rotating":
            raise ConfirmRejected(
                f"no confirmed rotation for epoch {epoch}"
            )
        if rotation["phase"] == "committed":
            return  # idempotent re-drive: already applied
        if rotation["phase"] != "confirmed":
            raise ConfirmRejected(
                f"no confirmed rotation for epoch {epoch}"
            )
        own = self._own_epochs(rid)
        prior_epoch = (
            int(rotation["prior_epoch"])
            if rotation["prior_epoch"] is not None
            else None
        )
        with _txn(self.conn):
            cur = self.conn.execute(
                "UPDATE key_rotations SET phase='committed', committed_at=?, "
                "accepted_events_since_commit=0 "
                "WHERE relationship_id=? AND epoch=? AND role='rotating' "
                "AND phase='confirmed'",
                (_ts(now), rid, epoch),
            )
            if cur.rowcount == 0:
                row = self._rotation(rid, epoch, "rotating")
                if row is not None and row["phase"] == "committed":
                    return  # re-drive won by a concurrent apply
                raise ConfirmRejected(
                    f"no confirmed rotation for epoch {epoch}"
                )
            self.conn.execute(
                "UPDATE key_epochs SET state='active' "
                "WHERE relationship_id=? AND epoch=? AND private_key_ref != ?",
                (rid, epoch, _PEER_REF),
            )
            if prior_epoch is not None and prior_epoch in own:
                self.conn.execute(
                    "UPDATE key_epochs SET state='retired' "
                    "WHERE relationship_id=? AND epoch=? AND private_key_ref != ?",
                    (rid, prior_epoch, _PEER_REF),
                )
            self.conn.execute(
                "UPDATE relationships SET key_epoch=? WHERE relationship_id=?",
                (epoch, rid),
            )

    def note_accepted_event(self, rid: str, now=None) -> None:
        """Count an accepted data event toward old-key deletion.

        Only the committed rotating row for the relationship's CURRENT
        ``key_epoch`` is incremented. Delayed traffic under an older
        envelope epoch must not bump a historical rotation (R10): the
        100-event retirement bound belongs to the live epoch, and
        historical committed rows are deleted by the sweep once their
        old key is retired, so only one counter can move per event.
        """
        self._now(now)
        rel = self.conn.execute(
            "SELECT key_epoch FROM relationships WHERE relationship_id=?",
            (rid,),
        ).fetchone()
        if rel is None:
            return
        current_epoch = int(rel["key_epoch"])
        with _txn(self.conn):
            self.conn.execute(
                "UPDATE key_rotations SET accepted_events_since_commit = "
                "accepted_events_since_commit + 1 "
                "WHERE relationship_id=? AND epoch=? AND role='rotating' "
                "AND phase='committed'",
                (rid, current_epoch),
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
            # Redelivery: the peer key row is already stored. A crash
            # between that INSERT and the rotation-row INSERT used to ack
            # here without the rotation row, wedging dual_wrap_keys
            # forever; repair the missing row first, then ack idempotently.
            with _txn(self.conn):
                self._record_acking_rotation(
                    rid, new_epoch, prior_epoch, prepare, prepare_event_id,
                    now,
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
            if rotation is None or (
                rotation["role"] == "rotating"
                and rotation["phase"] not in ("committed", "discarded")
            ):
                # I am also rotating into this epoch, or my key row exists
                # with no rotation row (a crashed or interleaved begin):
                # quarantine for human resolution, never misdiagnose as
                # stale_epoch (which would stall on a 24h NoAckTimeout).
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
        # The peer key row and the rotation row commit atomically (BEGIN
        # IMMEDIATE): a crash between them used to leave the peer key row
        # with no rotation row, and the redelivery shortcut then acked
        # without repairing it.
        with _txn(self.conn):
            self.conn.execute(
                "INSERT INTO key_epochs (relationship_id, epoch, public_key, "
                "private_key_ref, state) VALUES (?, ?, ?, ?, 'acknowledged')",
                (rid, new_epoch, prepare["new_agreement_key"], _PEER_REF),
            )
            self._record_acking_rotation(
                rid, new_epoch, prior_epoch, prepare, prepare_event_id, now
            )
        return build_ack(new_epoch, prepare_event_id)

    def _record_acking_rotation(
        self,
        rid: str,
        new_epoch: int,
        prior_epoch: int,
        prepare: dict,
        prepare_event_id: str,
        now: datetime,
    ) -> None:
        """Insert the acking-side rotation row (idempotent repair).

        Must be called inside the caller's transaction. Clears a discarded
        earlier attempt, then inserts the row only when no live acking row
        exists for the epoch: the redelivery path uses this to repair a
        rotation row lost to a crash, never to duplicate a live one.
        """
        self.conn.execute(
            "DELETE FROM key_rotations WHERE relationship_id=? "
            "AND epoch=? AND role='acking' AND phase='discarded'",
            (rid, new_epoch),
        )
        existing = self._rotation(rid, new_epoch, "acking")
        if existing is not None and existing["phase"] != "discarded":
            return
        deadline = parse_timestamp(prepare["deadline"])
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
        # And their first-seen records: the epoch is known now.
        self.conn.execute(
            "DELETE FROM unknown_epoch_first_seen WHERE relationship_id=? "
            "AND epoch <= ?",
            (rid, new_epoch),
        )

    def dual_wrap_keys(self, rid: str) -> dict:
        """Peer's keys for dual-wrap: {prior_epoch: key, new_epoch: key}.

        Used by the transport after acknowledgment: every outgoing CEK is
        wrapped to both the peer's prior and new keys, with the envelope
        ``key_epoch`` set to the new epoch.
        """
        rotation = self._in_flight(rid, role='acking')
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
        epoch = int(confirm["epoch"])
        rotation = self._rotation(rid, epoch, "acking")
        if rotation is None or rotation["role"] != "acking":
            raise ConfirmRejected(
                f"no acknowledged rotation for epoch {epoch}"
            )
        if rotation["phase"] == "confirmed":
            return  # idempotent re-drive: already applied
        if rotation["phase"] != "acknowledged":
            raise ConfirmRejected(
                f"no acknowledged rotation for epoch {epoch}"
            )
        with _txn(self.conn):
            cur = self.conn.execute(
                "UPDATE key_rotations SET phase='confirmed', confirmed_at=? "
                "WHERE relationship_id=? AND epoch=? AND role='acking' "
                "AND phase='acknowledged'",
                (_ts(now), rid, epoch),
            )
            if cur.rowcount == 0:
                row = self._rotation(rid, epoch, "acking")
                if row is not None and row["phase"] == "confirmed":
                    return  # re-drive won by a concurrent apply
                raise ConfirmRejected(
                    f"no acknowledged rotation for epoch {epoch}"
                )

    def build_commit_payload(self, rid: str, now=None) -> dict:
        """Build ``security.key.commit`` without changing phase.

        Idempotent: safe to call any number of times while the rotation is
        confirmed. When the rotation is already committed, the payload for
        the latest committed epoch is re-emitted (recovery after a crash
        between send and mark). The CLI sends this payload first and calls
        ``mark_committed`` only after the send is durably enqueued, so a
        failed send never wedges the rotation in 'committed' with no
        commit event on the wire.
        """
        self._now(now)
        rotation = self._in_flight(rid, role='acking')
        if (
            rotation is not None
            and rotation["role"] == "acking"
            and rotation["phase"] == "confirmed"
        ):
            return build_commit(int(rotation["epoch"]))
        row = self.conn.execute(
            "SELECT epoch FROM key_rotations WHERE relationship_id=? "
            "AND role='acking' AND phase='committed' "
            "ORDER BY epoch DESC LIMIT 1",
            (rid,),
        ).fetchone()
        if row is not None:
            return build_commit(int(row["epoch"]))
        raise RotationError(
            "nothing_to_commit", "no confirmed rotation to commit"
        )

    def mark_committed(self, rid: str, now=None) -> None:
        """Record that the commit was sent (confirmed -> committed).

        The peer stops writing old wraps only after this. Idempotent: a
        re-drive after a crash between the send and this mark is a no-op.
        """
        now = self._now(now)
        with _txn(self.conn):
            rotation = self._in_flight(rid, role='acking')
            if rotation is None:
                # _in_flight excludes committed rows: this may be a re-drive
                # after a crash between the send and this mark.
                row = self.conn.execute(
                    "SELECT 1 FROM key_rotations WHERE relationship_id=? "
                    "AND role='acking' AND phase='committed' LIMIT 1",
                    (rid,),
                ).fetchone()
                if row is not None:
                    return
                raise RotationError(
                    "nothing_to_commit", "no confirmed rotation to commit"
                )
            if (
                rotation["role"] != "acking"
                or rotation["phase"] != "confirmed"
            ):
                raise RotationError(
                    "nothing_to_commit", "no confirmed rotation to commit"
                )
            epoch = int(rotation["epoch"])
            new_peer_key = rotation["new_public_key"]
            cur = self.conn.execute(
                "UPDATE key_rotations SET phase='committed', committed_at=? "
                "WHERE relationship_id=? AND epoch=? AND role='acking' "
                "AND phase='confirmed'",
                (_ts(now), rid, epoch),
            )
            if cur.rowcount == 0:
                raise RotationError(
                    "nothing_to_commit", "lost race committing rotation"
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

    # -- data-plane epoch gate --------------------------------------------
    def on_data_event_epoch(self, rid: str, key_epoch: int, now=None) -> str:
        """Gate a data event by its envelope ``key_epoch``.

        Returns ``"ok"`` when the epoch is known. Raises
        ``RotationError("unknown_future_epoch")`` for a future unknown epoch
        (quarantined as retryable); after 24 hours without the epoch becoming
        known, raises ``RotationError("unknown_future_epoch_rejected")``.

        The 24-hour window is measured from a durable first-seen record
        that the rotation_quarantine cap cannot evict: without it, a storm
        of distinct bogus epochs evicts the oldest quarantine rows and
        resets the rejection timer forever. Callers must authenticate the
        envelope (unseal/signature verify) BEFORE calling this: the gate
        mutates rotation state.
        """
        now = self._now(now)
        key_epoch = int(key_epoch)
        known = self._current_epoch(rid)
        if key_epoch <= known:
            return "ok"
        # The first-seen record and the quarantine insert are one atomic
        # transaction: a crash between them used to lose the quarantine
        # row while keeping the timer (or vice versa).
        with _txn(self.conn):
            self.conn.execute(
                "INSERT OR IGNORE INTO unknown_epoch_first_seen"
                "(relationship_id, epoch, first_seen_at, rejected)"
                " VALUES (?, ?, ?, 0)",
                (rid, key_epoch, _ts(now)),
            )
            self._cap_first_seen(rid)
            first = self.conn.execute(
                "SELECT first_seen_at, rejected FROM unknown_epoch_first_seen"
                " WHERE relationship_id=? AND epoch=?",
                (rid, key_epoch),
            ).fetchone()
            if first is not None and first["rejected"]:
                rejected = True
            else:
                rejected = (
                    first is not None
                    and now
                    > parse_timestamp(first["first_seen_at"]) + ROTATION_WINDOW
                )
                if rejected:
                    # Permanent tombstone: cap eviction can never resurrect
                    # this epoch as retryable.
                    self.conn.execute(
                        "UPDATE unknown_epoch_first_seen SET rejected=1"
                        " WHERE relationship_id=? AND epoch=?",
                        (rid, key_epoch),
                    )
            self._quarantine_in_txn(
                rid,
                key_epoch,
                (
                    "unknown_future_epoch_rejected"
                    if rejected
                    else "unknown_future_epoch"
                ),
                {"epoch": key_epoch},
                now,
            )
        if rejected:
            raise RotationError(
                "unknown_future_epoch_rejected",
                f"epoch {key_epoch} still unknown after 24h; rejecting",
            )
        raise RotationError(
            "unknown_future_epoch",
            f"epoch {key_epoch} is unknown; quarantined as retryable",
        )

    def _cap_first_seen(self, rid: str) -> None:
        """Bound unknown_epoch_first_seen per relationship.

        The rows are tiny, but a hostile peer signs each bogus epoch, so
        distinct epochs are not free: cap at 1000 non-rejected rows and
        evict the oldest first. Rejected rows are tombstones the cap can
        never touch: evicting one would reset its 24h timer and make a
        permanently rejected epoch retryable again. Evicting a
        non-rejected row can reset that epoch's timer, but the
        per-object retry-sighting ceiling on the receive path terminates
        each storming object independently of the timer.
        """
        self.conn.execute(
            "DELETE FROM unknown_epoch_first_seen WHERE relationship_id=?"
            " AND rejected = 0"
            " AND (relationship_id, epoch) NOT IN ("
            "  SELECT relationship_id, epoch FROM unknown_epoch_first_seen"
            "  WHERE relationship_id=? AND rejected = 0"
            "  ORDER BY first_seen_at DESC, epoch DESC"
            "  LIMIT 1000)",
            (rid, rid),
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
        with _txn(self.conn):
            self._quarantine_in_txn(rid, epoch, reason, payload, now)

    def _quarantine_in_txn(self, rid, epoch, reason, payload, now) -> None:
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
        if choice == "theirs":
            # Discard my candidate FIRST: on_prepare rejects a prepare for
            # an epoch I am still rotating into, so processing it before the
            # discard always re-conflicts. The quarantine entry is deleted
            # only after the peer's prepare is accepted, so a failure in
            # on_prepare preserves the payload for retry or a different
            # choice (the candidate stays discarded, which the human already
            # chose).
            with _txn(self.conn):
                claimed, discarded_key_path = self._discard_candidate(rid, epoch)
            # The key file is deleted after the transaction commits: a crash
            # between them leaves an orphan file (reconciled on the next
            # begin_rotation), never a live row pointing at a deleted key.
            if discarded_key_path:
                delete_private_key(discarded_key_path)
            ack = self.on_prepare(
                rid, payload["prepare"], payload["prepare_event_id"], now=now
            )
            with _txn(self.conn):
                self.conn.execute(
                    "DELETE FROM rotation_quarantine WHERE id=?", (entry["id"],)
                )
            return ack
        # choice == "mine": keep my candidate, drop their quarantined prepare.
        with _txn(self.conn):
            self.conn.execute(
                "DELETE FROM rotation_quarantine WHERE id=?", (entry["id"],)
            )
        return None

    def _discard_candidate(
        self, rid: str, epoch: int, expected_phase: str | None = None
    ) -> tuple:
        """Discard a rotating candidate.

        Returns ``(claimed, key_path)``: *claimed* is True when the
        guarded state update matched a row (the discard happened), and
        *key_path* is the discarded key file's path, or None when the
        candidate had no key row left to delete. The two are split
        because a keyless candidate must still be discarded AND
        reported (R1): returning only the path made a successful
        keyless discard look like a lost race. The caller deletes the
        file AFTER the surrounding transaction commits. Must be called
        inside the caller's transaction.

        *expected_phase* adds a strict phase predicate to the UPDATE
        (sweep passes ``"candidate"`` so a concurrent on_ack can neither
        resurrect the row nor silently succeed); the default keeps the
        historical ``NOT IN ('committed', 'discarded')`` predicate.
        """
        if expected_phase is None:
            predicate = "AND phase NOT IN ('committed', 'discarded')"
            params: tuple = (rid, epoch)
        else:
            predicate = "AND phase = ?"
            params = (rid, epoch, expected_phase)
        row = self.conn.execute(
            "SELECT private_key_ref FROM key_epochs WHERE relationship_id=? "
            "AND epoch=? AND private_key_ref != ?",
            (rid, epoch, _PEER_REF),
        ).fetchone()
        cur = self.conn.execute(
            "UPDATE key_rotations SET phase='discarded' "
            "WHERE relationship_id=? AND epoch=? AND role='rotating' "
            + predicate,
            params,
        )
        if cur.rowcount == 0:
            return (False, None)
        self.conn.execute(
            "DELETE FROM key_epochs WHERE relationship_id=? AND epoch=? "
            "AND private_key_ref != ?",
            (rid, epoch, _PEER_REF),
        )
        return (True, row["private_key_ref"] if row else None)

    # -- sweep ----------------------------------------------------------------
    def _compact_committed_rotations(self, now) -> None:
        """Delete superseded committed rotation rows (G16).

        Must be called inside the caller's transaction. Deletes committed
        rows older than ``KEY_ROTATION_COMMITTED_RETENTION``, always
        keeping the newest committed row per (relationship_id, role) so
        the commit redelivery fallbacks keep working. Rows with a NULL
        ``committed_at`` are never deleted (fail-safe for legacy rows).
        """
        self.conn.execute(
            "DELETE FROM key_rotations WHERE phase='committed'"
            " AND committed_at IS NOT NULL"
            " AND committed_at <= ?"
            " AND (relationship_id, role, epoch) NOT IN ("
            "  SELECT relationship_id, role, MAX(epoch) FROM key_rotations"
            "  WHERE phase='committed'"
            "  GROUP BY relationship_id, role);",
            (_ts(now - KEY_ROTATION_COMMITTED_RETENTION),),
        )

    def _compact_peer_key_epochs(self) -> None:
        """Delete peer agreement keys older than the dual-wrap window (G16).

        Must be called inside the caller's transaction. Keeps the two
        newest peer ``key_epochs`` rows per relationship: the seal side
        wraps to at most the peer's current and previous epoch, so older
        peer public keys can never be used again. Epoch-1 peer keys live
        on the ``relationships`` row, not here, and are untouched. Own
        private keys are untouched: their replay-acceptance retention is
        handled by the old-key retirement above, not here.
        """
        for (rid,) in self.conn.execute(
            "SELECT DISTINCT relationship_id FROM key_epochs "
            "WHERE private_key_ref = ?;",
            (_PEER_REF,),
        ).fetchall():
            self.conn.execute(
                "DELETE FROM key_epochs WHERE relationship_id = ?"
                " AND private_key_ref = ? AND epoch NOT IN ("
                "  SELECT epoch FROM key_epochs WHERE relationship_id = ?"
                "  AND private_key_ref = ? ORDER BY epoch DESC LIMIT ?);",
                (rid, _PEER_REF, rid, _PEER_REF, PEER_KEY_EPOCH_RETAIN_NEWEST),
            )

    def _compact_security_key_events(self, now) -> None:
        """Compact the projected security-key ceremony index (G16).

        Must be called inside the caller's transaction. Deletes projected
        rows whose receiver acceptance time is past
        ``SECURITY_KEY_EVENT_RETENTION``. The ceremony events themselves
        stay immutable in the event log, and a rebuild re-derives the
        full history; this bounds steady-state growth only. Never uses
        sender-controlled ``created_at`` for the age check: only rows with
        a non-NULL receiver acceptance time are compacted; rows lacking
        one are retained (fail-safe, same as committed rotations with a
        NULL ``committed_at``).
        """
        tables = {
            r[0]
            for r in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
        }
        if "security_key_events" not in tables or "event_payloads" not in tables:
            return
        # G16: p.received_at is the receiver's staging time (durable, not
        # sender-controlled). No COALESCE fallback to s.created_at: a
        # sender can backdate created_at, which would let an adversary's
        # old ceremony rows either evade compaction or, worse, force
        # deletion of rows that are not actually old.
        self.conn.execute(
            "DELETE FROM security_key_events WHERE event_id IN ("
            "  SELECT s.event_id FROM security_key_events s"
            "  JOIN event_payloads p ON p.event_id = s.event_id"
            "  WHERE p.received_at IS NOT NULL"
            "  AND p.received_at <= ?);",
            (_ts(now - SECURITY_KEY_EVENT_RETENTION),),
        )

    def sweep(self, now=None) -> None:
        """Run periodic rotation maintenance.

        - Discards unacknowledged candidates after 24h (raises
          ``NoAckTimeout`` for the first one found).
        - Deletes the old private key after commit once 24 hours have passed
          or 100 events were accepted under the new epoch, whichever first.
        - Expires rejected unknown-epoch quarantine rows older than
          ``ROTATION_QUARANTINE_REJECTED_RETENTION``.
        - G16: compacts committed rotation history
          (``KEY_ROTATION_COMMITTED_RETENTION``), old peer agreement keys
          (``PEER_KEY_EPOCH_RETAIN_NEWEST``), and the projected
          security-key ceremony index (``SECURITY_KEY_EVENT_RETENTION``).
        """
        now = self._now(now)
        with _txn(self.conn):
            self.conn.execute(
                "DELETE FROM rotation_quarantine "
                "WHERE reason='unknown_future_epoch_rejected' AND received_at <= ?",
                (_ts(now - ROTATION_QUARANTINE_REJECTED_RETENTION),),
            )
            self.conn.execute(
                "DELETE FROM rotation_wrap_seen_pending "
                "WHERE seen_at <= ?",
                (_ts(now - ROTATION_WINDOW),),
            )
            self._compact_committed_rotations(now)
            self._compact_peer_key_epochs()
            self._compact_security_key_events(now)
        # Claim exactly one timed-out candidate inside a single BEGIN
        # IMMEDIATE transaction: the SELECT and the guarded discard are
        # atomic, so a concurrent on_ack can neither slip between them
        # (resurrecting a discarded row, R1) nor silently succeed. The
        # phase predicate is the guard; the key file is deleted only after
        # the transaction commits.
        timed_out = None
        with _txn(self.conn):
            row = self.conn.execute(
                "SELECT relationship_id, epoch FROM key_rotations "
                "WHERE role='rotating' AND phase='candidate' AND deadline <= ? "
                "ORDER BY deadline LIMIT 1",
                (_ts(now),),
            ).fetchone()
            if row is not None:
                rid, epoch = row["relationship_id"], int(row["epoch"])
                claimed, key_path = self._discard_candidate(
                    rid, epoch, expected_phase="candidate"
                )
                # Under the write lock the guarded UPDATE applies unless a
                # concurrent transition already moved the row; a keyless
                # claim still counts as a timeout (R1) so the user is
                # alerted even when the key file is already gone.
                if claimed:
                    timed_out = (rid, epoch, key_path)
        if timed_out is not None:
            rid, epoch, key_path = timed_out
            if key_path is not None:
                delete_private_key(key_path)
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
                old_key_path = None
                with _txn(self.conn):
                    # Never delete the old key unless the new epoch's own
                    # private key row still exists. A resurrected or stale
                    # rotating row (e.g. after conflict resolution chose the
                    # peer's rotation, "theirs") must not silently destroy the
                    # still-current key the peer encrypts to.
                    new_key = self.conn.execute(
                        "SELECT private_key_ref FROM key_epochs "
                        "WHERE relationship_id=? AND epoch=? "
                        "AND private_key_ref != ?",
                        (rid, epoch, _PEER_REF),
                    ).fetchone()
                    if new_key is None:
                        continue
                    key_row = self.conn.execute(
                        "SELECT private_key_ref FROM key_epochs "
                        "WHERE relationship_id=? AND epoch=? "
                        "AND private_key_ref != ?",
                        (rid, prior_epoch, _PEER_REF),
                    ).fetchone()
                    if key_row is not None:
                        old_key_path = key_row["private_key_ref"]
                        self.conn.execute(
                            "DELETE FROM key_epochs WHERE relationship_id=? "
                            "AND epoch=? AND private_key_ref != ?",
                            (rid, prior_epoch, _PEER_REF),
                        )
                    # The rotation is fully retired: delete its row so
                    # historical committed rows do not accumulate (R10).
                    # on_commit treats the missing row as a benign
                    # redelivery when the epoch is already active.
                    self.conn.execute(
                        "DELETE FROM key_rotations WHERE relationship_id=? "
                        "AND epoch=? AND role='rotating' AND phase='committed'",
                        (rid, epoch),
                    )
                # Delete the key file after the transaction commits: a crash
                # between them leaves an orphan file (reconciled on the next
                # begin_rotation), never a live row pointing at a deleted key.
                if old_key_path is not None:
                    delete_private_key(old_key_path)


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
