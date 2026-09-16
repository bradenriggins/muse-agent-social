"""Shared adversarial-test harness for the v0.2 gate matrix.

Provides:

* ``make_agent``: fresh random identity (Ed25519) + bootstrap X25519 +
  relationship X25519 keypair + self-signed agent card. No secrets are
  hardcoded; every key is generated per test run.
* ``fresh_db``: file-backed SQLite with the skeleton migration (v1) and the
  projections migration (v2) applied.
* ``provision_receive_side`` / ``provision_send_side``: relationship +
  key-epoch rows so the plan's foreign keys accept event inserts.
* ``make_sealed``: build a protected header and seal it for a recipient.
* ``ReceiveHarness``: a plan-conformant receive pipeline implementing the
  plan's RECEIVE PIPELINE (fetch -> validate -> commit -> consume ->
  surface) with the plan's atomic commit transaction and injectable kill
  points at every transition named in the test plan.

GAP NOTE (see INTERFACE.md): ``mas-release`` ships no receive-pipeline
module; the watcher documents a ``receive_fn`` contract "implemented by the
receive track", which is absent. This harness is the reference
implementation of that contract, built only on landed store APIs, and the
crash/kill-point tests prove the storage-layer protocol contract (atomic
commit, idempotent resume, exactly-once projection, durable surface
marking). They cannot prove properties of a shipped receive path because
none exists yet.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from muse_agent_social._keyfiles import store_private_key
from muse_agent_social.canonical import (
    CanonicalizationError,
    restricted_jcs,
    strict_parse,
)
from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
    identity_id_from_pubkey,
)
from muse_agent_social.crypto.sealing import (
    PROTOCOL,
    SealingError,
    seal_envelope,
    unseal_envelope,
)
from muse_agent_social.model.cards import create_card
from muse_agent_social.model.events import build_protected
from muse_agent_social.policy.limits import (
    ACCEPT_WINDOW_DAYS,
    FUTURE_TOLERANCE_SECONDS,
    format_canonical_utc,
)
from muse_agent_social.store import db as db_mod
from muse_agent_social.store.db import transaction, utcnow
from muse_agent_social.store.migrations import migrate
from muse_agent_social.store.projections import (
    apply_event,
    migrate_projections,
    record_projection_input,
)
from muse_agent_social.transports.local import LocalTransport
from muse_agent_social.validation import (
    MAX_ENVELOPE_BYTES,
    ValidationError,
    check_envelope_size,
    validate,
)

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Agents and databases
# ---------------------------------------------------------------------------


def make_agent(display: str = "TestAgent", principal: str = "TestPrincipal") -> dict:
    """Create a fresh test agent: identity key, bootstrap key, relationship
    key, and a self-signed card. All keys are generated per call."""
    ed_priv = Ed25519PrivateKey.generate()
    ed_pub_raw = ed_priv.public_key().public_bytes_raw()
    identity_id = identity_id_from_pubkey(ed_pub_raw)
    boot_priv = X25519PrivateKey.generate()
    boot_pub_raw = boot_priv.public_key().public_bytes_raw()
    boot_mb = agreement_key_multibase_from_pubkey(boot_pub_raw)
    rel_priv = X25519PrivateKey.generate()
    rel_pub_raw = rel_priv.public_key().public_bytes_raw()
    rel_mb = agreement_key_multibase_from_pubkey(rel_pub_raw)
    now = datetime.now(UTC)
    card = create_card(
        ed_priv,
        display,
        principal,
        boot_mb,
        ["events/0.2", "threads/1", "receipts/1"],
        now,
        now + timedelta(days=365),
    )
    return {
        "ed_priv": ed_priv,
        "identity_id": identity_id,
        "boot_priv": boot_priv,
        "rel_priv": rel_priv,
        "rel_pub_raw": rel_pub_raw,
        "rel_pub_mb": rel_mb,
        "card": card,
    }


def fresh_db(path) -> sqlite3.Connection:
    """Open a file DB and apply migrations v1 (skeleton) and v2
    (projections)."""
    conn = db_mod.connect(str(path))
    migrate(conn)
    migrate_projections(conn)
    return conn


def provision_receive_side(
    conn: sqlite3.Connection,
    relationship_id: str,
    agent_self: dict,
    agent_peer: dict,
    *,
    keys_dir=None,
    consent_state: str = "active",
) -> dict:
    """Provision the receiver's view of a relationship.

    Creates the relationships row (peer = the sender, whose epoch-1
    agreement key lives in relationships.peer_agreement_key) and the
    receiver's own epoch-1 key_epochs row (private key file written via
    store_private_key). key_epochs holds only own rows at epoch 1: the
    PRIMARY KEY is (relationship_id, epoch), so a peer epoch-1 row would
    collide with and replace the own row. Returns context incl. the
    receiver's X25519 relationship private key.
    """
    if keys_dir is None:
        keys_dir = os.path.join(
            os.path.dirname(os.path.abspath(conn.execute("PRAGMA database_list").fetchone()[2])),
            "keys",
        )
    os.makedirs(keys_dir, mode=0o700, exist_ok=True)
    key_path = os.path.join(keys_dir, f"{relationship_id}-e1.key")
    if not os.path.exists(key_path):
        store_private_key(key_path, agent_self["rel_priv"].private_bytes_raw())
    now = utcnow()
    with transaction(conn):
        conn.execute(
            "INSERT OR REPLACE INTO relationships("
            "relationship_id, peer_identity_id, peer_display_name, "
            "peer_agreement_key, consent_state, policy, key_epoch, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (
                relationship_id,
                agent_peer["identity_id"],
                "peer",
                agent_peer["rel_pub_mb"],
                consent_state,
                json.dumps({"delivery_mode": "alert"}),
                now,
            ),
        )
        conn.execute(
            "INSERT OR REPLACE INTO key_epochs("
            "relationship_id, epoch, public_key, private_key_ref, state)"
            " VALUES (?, 1, ?, ?, 'active')",
            (relationship_id, agent_self["rel_pub_mb"], key_path),
        )
        conn.execute(
            "INSERT OR IGNORE INTO conversations(conversation_id) VALUES (?)",
            (str(uuid.uuid4()),),
        )
    return {
        "relationship_id": relationship_id,
        "own_rel_priv": agent_self["rel_priv"],
        "own_identity_id": agent_self["identity_id"],
        "peer_identity_id": agent_peer["identity_id"],
        "keys_dir": keys_dir,
    }


def provision_send_side(
    conn: sqlite3.Connection,
    relationship_id: str,
    agent_self: dict,
    agent_peer: dict,
    *,
    keys_dir=None,
) -> dict:
    """Provision the sender's view (same rows, mirrored identities)."""
    return provision_receive_side(
        conn, relationship_id, agent_self, agent_peer, keys_dir=keys_dir
    )


def new_conversation(conn: sqlite3.Connection) -> str:
    conv = str(uuid.uuid4())
    conn.execute(
        "INSERT OR IGNORE INTO conversations(conversation_id) VALUES (?)",
        (conv,),
    )
    conn.commit()
    return conv


def make_sealed(
    sender: dict,
    recipient: dict,
    relationship_id: str,
    conversation_id: str,
    event_type: str,
    payload: dict,
    seq: int,
    *,
    thread_id=None,
    reply_to=None,
    key_epoch: int = 1,
    created_at: str | None = None,
    deliver_at: str | None = None,
    expires_at: str | None = None,
    event_id: str | None = None,
    replay_nonce: str | None = None,
) -> tuple[dict, bytes]:
    """Build a protected header (with an explicit sender_seq) and seal it.

    event_id / replay_nonce override the fresh values build_protected
    generates; they must be supplied before sealing because the seal's
    wrap AAD binds the protected-header digest. Post-seal mutation of any
    protected field breaks the seal (tampered_wrap) instead of reaching
    the receive pipeline.

    Returns (envelope_dict, canonical_bytes).
    """
    protected = build_protected(
        relationship_id=relationship_id,
        conversation_id=conversation_id,
        sender_id=sender["identity_id"],
        event_type=event_type,
        thread_id=thread_id,
        reply_to=reply_to,
        key_epoch=key_epoch,
        deliver_at=deliver_at,
        expires_at=expires_at,
        created_at=created_at,
    )
    protected["sender_seq"] = seq
    if event_id is not None:
        protected["event_id"] = event_id
    if replay_nonce is not None:
        protected["replay_nonce"] = replay_nonce
    envelope = seal_envelope(
        protected,
        payload,
        sender["ed_priv"],
        [
            {
                "recipient": recipient["identity_id"],
                "agreement_key": recipient["rel_pub_mb"],
                "relationship_pub": recipient["rel_pub_raw"],
            }
        ],
    )
    return envelope, restricted_jcs(envelope)


def random_object_name() -> str:
    return (
        base64.urlsafe_b64encode(os.urandom(24)).rstrip(b"=").decode("ascii")
        + ".json"
    )


# ---------------------------------------------------------------------------
# Plan-conformant receive pipeline with injectable kill points
# ---------------------------------------------------------------------------


class FaultInjected(Exception):
    """Raised when a kill-point fault fires. The harness clears the armed
    fault first, so a resume run proceeds without the fault."""


class Reject(Exception):
    """Internal: the object was rejected with a stable reason code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class SkipObject(Exception):
    """Internal: the object is not addressed to this receiver."""


class AlreadyCommitted(Exception):
    """Internal: this exact event bytes are already committed. Resume the
    idempotent path (no decrypt, no re-validation of the clock)."""

    def __init__(self, event_id: str):
        self.event_id = event_id
        super().__init__(event_id)


KILL_POINTS = (
    "after_inbox_stage",  # after decrypt+validate staging, before commit
    "after_commit",  # after the atomic commit, before transport consume
    "before_consume",  # immediately before the consume call
    "after_consume_before_surface",  # after consume, before surfacing
    "during_surface_mark",  # inside surface marking (pre-commit hook)
)

REPLAY_WINDOW = timedelta(days=ACCEPT_WINDOW_DAYS)


class ReceiveHarness:
    """Reference implementation of the plan's RECEIVE PIPELINE.

    Fetch -> validate -> commit -> consume -> surface, where commit is the
    plan's atomic transaction::

        BEGIN IMMEDIATE;
        INSERT OR IGNORE INTO events(... sealed_envelope ...);
        INSERT INTO replay_guard(replay_nonce, expires_at) ...;
        UPSERT sender_sequence(...);
        stage projection input + apply projection;
        INSERT INTO receipt_queue(...);
        INSERT INTO surface_queue(...);
        COMMIT;

    Kill points are armed via ``fault_at``; the fault fires once and is
    disarmed, so calling the receive entry point again models process
    restart and resume. ``now_fn`` is an injectable clock returning an
    aware datetime.

    Kill points, in pipeline order:

    * ``after_inbox_stage``: after fetch, before commit.
    * ``during_commit_after_events`` / ``during_commit_after_guard`` /
      ``during_commit_after_project`` / ``during_commit_after_receipt`` /
      ``during_commit_after_surface_enqueue``: inside the commit
      transaction; each rolls the whole transaction back.
    * ``after_commit``: after the commit transaction, before consume.
    * ``before_consume`` / ``after_consume_before_surface``: around relay
      consume.
    * ``during_surface_mark``: inside the surface-mark transaction, before
      commit; the marking rolls back and the queue row is preserved.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        relationship_id: str,
        own_identity_id: str,
        own_rel_priv: X25519PrivateKey,
        transport: LocalTransport,
        delivery_mode: str = "alert",
    ):
        self.conn = conn
        self.relationship_id = relationship_id
        self.own_identity_id = own_identity_id
        self.own_rel_priv = own_rel_priv
        self.transport = transport
        self.delivery_mode = delivery_mode
        self.now_fn = lambda: datetime.now(UTC)
        self.fault_at: str | None = None
        self.pre_mark_commit_hook = None  # fires inside the surface-mark txn
        self.notified: list[str] = []  # agent-visible surface log (event ids)
        self.channel_events: list[str] = []  # raw channel notifications
        self.calls: list[tuple] = []  # stage trace for assertions
        self.unseal_attempts: list[str] = []  # object names where unseal ran
        self._ensure_surface_tables()

    # -- setup ---------------------------------------------------------
    def _ensure_surface_tables(self) -> None:
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS surface_log("
            " event_id TEXT PRIMARY KEY, surfaced_at TEXT NOT NULL);"
        )
        # Durable local suppression of repeated notifications at the
        # channel boundary (the plan's seven-day suppression, modeled
        # durably here; expiry pruning is the caller's job).
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS surface_suppression("
            " event_id TEXT PRIMARY KEY, suppressed_at TEXT NOT NULL);"
        )
        self.conn.commit()

    # -- fault injection -----------------------------------------------
    def _maybe_fault(self, point: str) -> None:
        if self.fault_at == point:
            self.fault_at = None
            raise FaultInjected(point)

    # -- entry point ----------------------------------------------------
    def receive_object(self, object_name: str, data: bytes) -> dict:
        """Process one fetched object. Returns an outcome dict."""
        self.calls.append(("fetch", object_name))
        try:
            protected, payload = self._validate(object_name, data)
            committed = None
        except AlreadyCommitted as dup:
            protected, payload, committed = None, None, dup.event_id
        except SkipObject:
            self.calls.append(("skip_not_for_me", object_name))
            return {"outcome": "skipped", "code": "not_for_me"}
        except Reject as rej:
            self.calls.append(("reject", object_name, rej.code))
            if rej.code == "duplicate_nonce":
                # Idempotent ignore per the plan: same replay nonce is not
                # a conflict, it is a replay. Consume, do not quarantine.
                self.transport.consume(object_name)
                return {"outcome": "duplicate_ignored", "code": rej.code}
            # Terminal processed outcome: quarantine the hostile object.
            self.transport.quarantine(object_name, data)
            return {"outcome": "quarantined", "code": rej.code}

        if committed is None:
            self.calls.append(("inbox_stage", object_name))
            self._maybe_fault("after_inbox_stage")
            outcome = self._commit(object_name, protected, payload, data)
        else:
            # Byte-identical replay of a committed event: no decrypt, no
            # clock re-check; the commit path classifies it as identical.
            outcome = self._commit_duplicate(object_name, committed, data)
        self.calls.append(("commit", object_name, outcome["outcome"]))
        self._maybe_fault("after_commit")
        self._maybe_fault("before_consume")

        self.transport.consume(object_name)
        self.calls.append(("consume", object_name))
        self._maybe_fault("after_consume_before_surface")

        surfaced = self._surface()
        self.calls.append(("surface", object_name, surfaced))
        outcome["surfaced"] = surfaced
        return outcome

    def receive_fn(self, relationship_id: str, object_name: str, data: bytes) -> dict:
        """Adapter to the watcher.receive_fn contract."""
        try:
            outcome = self.receive_object(object_name, data)
        except FaultInjected:
            raise
        code = outcome["outcome"]
        if code in ("accepted", "accepted_duplicate", "duplicate_ignored"):
            return {
                "outcome": "accepted",
                "surfaces": int(bool(outcome.get("surfaced"))),
                "receipts_queued": 1 if code == "accepted" else 0,
            }
        if code == "skipped":
            # Not addressed to us: leave it for the other side. Report as
            # retry_pending so the watcher does not consume it.
            return {"outcome": "retry_pending", "surfaces": 0, "receipts_queued": 0}
        return {
            "outcome": "quarantined",
            "surfaces": 0,
            "receipts_queued": 0,
        }

    # -- validation (plan order: size, parse, schema, policy, decrypt) --
    def _validate(self, object_name: str, data: bytes) -> tuple[dict, dict]:
        try:
            check_envelope_size(data)
        except ValidationError as exc:
            raise Reject(exc.code) from None
        try:
            parsed = strict_parse(data)
        except CanonicalizationError as exc:
            raise Reject(exc.code) from None
        if not isinstance(parsed, dict):
            raise Reject("not_an_object")
        try:
            validate("event-envelope", parsed)
        except ValidationError as exc:
            raise Reject(exc.code) from None
        protected = parsed["protected"]

        # Relationship + consent before any cryptographic work.
        row = self.conn.execute(
            "SELECT peer_identity_id, consent_state FROM relationships"
            " WHERE relationship_id = ?",
            (self.relationship_id,),
        ).fetchone()
        if row is None:
            raise Reject("unknown_relationship")
        if row["consent_state"] != "active":
            raise Reject("relationship_revoked")
        if protected.get("relationship_id") != self.relationship_id:
            raise Reject("wrong_relationship")
        if protected.get("protocol") != PROTOCOL:
            raise Reject("unknown_protocol")
        if protected.get("sender") != row["peer_identity_id"]:
            raise Reject("wrong_sender")

        # Already-accepted events are idempotent regardless of age, and
        # byte-identical replays never reach decrypt. Do the event-id
        # lookup right after schema validation.
        known = self.conn.execute(
            "SELECT sealed_envelope FROM events WHERE event_id = ?",
            (protected["event_id"],),
        ).fetchone()
        if known is not None:
            if bytes(known["sealed_envelope"]) == data:
                raise AlreadyCommitted(protected["event_id"])
            raise Reject("event_id_conflict")

        # Clock contract: 5-minute future tolerance, 7-day past window.
        now = self.now_fn()
        try:
            created = datetime.strptime(
                protected["created_at"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=UTC)
        except (ValueError, TypeError, KeyError):
            raise Reject("bad_timestamp") from None
        if created - now > timedelta(seconds=FUTURE_TOLERANCE_SECONDS):
            raise Reject("future_timestamp")
        if now - created > REPLAY_WINDOW:
            raise Reject("event_expired")

        # Data-plane epoch gate (policy layer, before decrypt): the
        # envelope's key_epoch must be a known key_epochs row. Unknown
        # future epochs are quarantined as retryable per the plan; the
        # events-table FK on (relationship_id, key_epoch) is the backstop.
        key_epoch = protected.get("key_epoch")
        epoch_row = self.conn.execute(
            "SELECT 1 FROM key_epochs WHERE relationship_id = ? AND epoch = ?",
            (self.relationship_id, key_epoch),
        ).fetchone()
        if epoch_row is None:
            raise Reject("unknown_future_epoch")

        # Replay guard: same nonce still valid -> idempotent ignore.
        nonce = protected["replay_nonce"]
        guard = self.conn.execute(
            "SELECT expires_at FROM replay_guard WHERE replay_nonce = ?",
            (nonce,),
        ).fetchone()
        if guard is not None:
            raise Reject("duplicate_nonce")

        # Not addressed to this receiver: leave for the other side.
        recipients = parsed.get("recipients", [])
        if not any(
            isinstance(e, dict) and e.get("recipient") == self.own_identity_id
            for e in recipients
        ):
            raise SkipObject()

        # Decrypt (signature, wrap, body, payload schema all inside).
        self.unseal_attempts.append(object_name)
        try:
            unsealed_protected, payload = unseal_envelope(
                parsed, self.own_rel_priv, self.own_identity_id
            )
        except SealingError as exc:
            raise Reject(exc.code) from None
        return unsealed_protected, payload

    def _commit_duplicate(
        self, object_name: str, event_id: str, raw: bytes
    ) -> dict:
        """Idempotent path for a byte-identical replay of a committed event.

        No re-validation, no decrypt, no re-projection: the commit
        transaction's INSERT OR IGNORE classifies it as identical.
        """
        self.calls.append(("commit_duplicate", object_name))
        return {"outcome": "accepted_duplicate"}

    # -- atomic commit ---------------------------------------------------
    def _classify_conflict(
        self, conn: sqlite3.Connection, protected: dict, raw: bytes
    ) -> str:
        """Classify a uniqueness collision on the events insert."""
        existing = conn.execute(
            "SELECT sealed_envelope FROM events WHERE event_id = ?",
            (protected["event_id"],),
        ).fetchone()
        if existing is not None:
            if bytes(existing["sealed_envelope"]) == raw:
                return "identical"
            return "event_id_conflict"
        by_nonce = conn.execute(
            "SELECT event_id FROM events WHERE replay_nonce = ?",
            (protected["replay_nonce"],),
        ).fetchone()
        if by_nonce is not None:
            return "duplicate_nonce"
        by_seq = conn.execute(
            "SELECT event_id FROM events WHERE relationship_id = ?"
            " AND sender = ? AND sender_seq = ?",
            (
                self.relationship_id,
                protected["sender"],
                protected["sender_seq"],
            ),
        ).fetchone()
        if by_seq is not None:
            return "sequence_fork"
        return "unknown_conflict"

    def _commit(
        self, object_name: str, protected: dict, payload: dict, raw: bytes
    ) -> dict:
        now = self.now_fn()
        now_s = format_canonical_utc(now)
        created = datetime.strptime(
            protected["created_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
        replay_expires = format_canonical_utc(
            max(created + REPLAY_WINDOW + timedelta(hours=1), now + REPLAY_WINDOW)
        )
        event_id = protected["event_id"]
        with transaction(self.conn):
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO events(event_id, relationship_id,"
                " conversation_id, thread_id, sender, sender_seq, created_at,"
                " key_epoch, event_type, replay_nonce, sealed_envelope)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    self.relationship_id,
                    protected["conversation_id"],
                    protected.get("thread_id"),
                    protected["sender"],
                    protected["sender_seq"],
                    protected["created_at"],
                    protected["key_epoch"],
                    protected["event_type"],
                    protected["replay_nonce"],
                    raw,
                ),
            )
            if cur.rowcount == 0:
                code = self._classify_conflict(self.conn, protected, raw)
                if code == "identical":
                    return {"outcome": "accepted_duplicate"}
                if code == "duplicate_nonce":
                    # Same replay nonce, new event id: idempotent ignore.
                    return {"outcome": "duplicate_ignored", "code": code}
                self.conn.execute(
                    "INSERT OR IGNORE INTO quarantine(relationship_id, sender,"
                    " sender_seq, event_id, reason, quarantined_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        self.relationship_id,
                        protected["sender"],
                        protected["sender_seq"],
                        event_id,
                        code,
                        now_s,
                    ),
                )
                return {"outcome": "quarantined", "code": code}
            # Kill points inside the commit transaction. Each rolls the
            # whole transaction back; resume must reprocess the event
            # exactly once with no partial projection.
            self._maybe_fault("during_commit_after_events")
            self.conn.execute(
                "INSERT OR IGNORE INTO replay_guard(replay_nonce, expires_at)"
                " VALUES (?, ?)",
                (protected["replay_nonce"], replay_expires),
            )
            self._maybe_fault("during_commit_after_guard")
            self.conn.execute(
                "INSERT INTO sender_sequence(relationship_id, sender, last_seq)"
                " VALUES (?, ?, ?)"
                " ON CONFLICT(relationship_id, sender) DO UPDATE SET"
                " last_seq = MAX(sender_sequence.last_seq, excluded.last_seq)",
                (
                    self.relationship_id,
                    protected["sender"],
                    protected["sender_seq"],
                ),
            )
            record_projection_input(
                self.conn,
                event_id=event_id,
                event_type=protected["event_type"],
                payload=payload,
                reply_to=protected.get("reply_to"),
            )
            apply_event(
                self.conn,
                {
                    "event_id": event_id,
                    "relationship_id": self.relationship_id,
                    "conversation_id": protected["conversation_id"],
                    "thread_id": protected.get("thread_id"),
                    "sender": protected["sender"],
                    "sender_seq": protected["sender_seq"],
                    "created_at": protected["created_at"],
                    "key_epoch": protected["key_epoch"],
                    "event_type": protected["event_type"],
                    "payload": payload,
                    "reply_to": protected.get("reply_to"),
                },
            )
            self._maybe_fault("during_commit_after_project")
            self.conn.execute(
                "INSERT OR IGNORE INTO receipt_queue(target_event_id, kind,"
                " queued_at) VALUES (?, 'accepted', ?)",
                (event_id, now_s),
            )
            self._maybe_fault("during_commit_after_receipt")
            self.conn.execute(
                "INSERT OR IGNORE INTO surface_queue(event_id,"
                " policy_snapshot, queued_at) VALUES (?, ?, ?)",
                (
                    event_id,
                    json.dumps({"delivery_mode": self.delivery_mode}),
                    now_s,
                ),
            )
            self._maybe_fault("during_commit_after_surface_enqueue")
        return {"outcome": "accepted"}

    # -- surface ----------------------------------------------------------
    def _surface(self) -> int:
        """Drain the surface queue. Returns the number of newly notified
        events. Marking (queue delete + durable log) is one transaction;
        the visible notification is suppressed by event id through the
        durable suppression table, so a repeat after a crash cannot
        double-notify."""
        rows = self.conn.execute(
            "SELECT event_id FROM surface_queue ORDER BY id"
        ).fetchall()
        newly = 0
        for (event_id,) in rows:
            with transaction(self.conn):
                self.conn.execute(
                    "DELETE FROM surface_queue WHERE event_id = ?",
                    (event_id,),
                )
                self.conn.execute(
                    "INSERT OR IGNORE INTO surface_log(event_id, surfaced_at)"
                    " VALUES (?, ?)",
                    (event_id, utcnow()),
                )
                if self.pre_mark_commit_hook is not None:
                    # Extra test hook; also fires inside the marking
                    # transaction, before commit.
                    self.pre_mark_commit_hook()
                # Kill point "during_surface_mark": fires inside the marking
                # transaction, before commit, so the transaction rolls back
                # and the queue row is preserved. Resume must surface the
                # event exactly once and notify exactly once.
                self._maybe_fault("during_surface_mark")
            if self._notify_channel(event_id):
                newly += 1
        return newly

    def _notify_channel(self, event_id: str) -> bool:
        """Raw notification channel. Records the attempt durably and
        suppresses repeats by event id (the plan's seven-day local
        suppression). Returns True only for a genuinely new notification."""
        self.channel_events.append(event_id)
        with transaction(self.conn):
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO surface_suppression(event_id,"
                " suppressed_at) VALUES (?, ?)",
                (event_id, utcnow()),
            )
            inserted = cur.rowcount == 1
        if inserted:
            self.notified.append(event_id)
        return inserted

    # -- small query helpers for assertions --------------------------------
    def count(self, table: str, where: str = "", args=()) -> int:
        q = f"SELECT COUNT(*) FROM {table}" + (f" WHERE {where}" if where else "")
        return int(self.conn.execute(q, args).fetchone()[0])

    def event_ids(self) -> list[str]:
        return [
            r[0]
            for r in self.conn.execute(
                "SELECT event_id FROM events WHERE relationship_id = ?"
                " ORDER BY sender_seq",
                (self.relationship_id,),
            ).fetchall()
        ]


def deliver(
    harness: ReceiveHarness, data: bytes, object_name: str | None = None
) -> dict:
    """Upload bytes to the harness transport and run one receive cycle."""
    name = object_name or random_object_name()
    harness.transport.upload(name, data)
    return harness.receive_object(name, data)
