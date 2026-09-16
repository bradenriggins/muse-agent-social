"""Typed event construction and transactional outgoing persistence (v0.2).

build_protected assembles the 15-field protected header required by the
event-envelope schema. seal_envelope (in crypto.sealing) fills the ephemeral
agreement key, wraps the content key per recipient, and signs.

assign_and_persist_outgoing assigns sender_seq = max+1 for
(relationship_id, sender) and persists the sealed event inside a single
SQLite transaction (BEGIN IMMEDIATE via store.db.transaction), as the plan's
ordering rules require: the events row, the sender_sequence upsert, a
projection_queue entry for local visibility, and the scheduler_queue row
that serves as the transactional outbox for the transport/scheduler worker.
The plan's UNIQUE constraints (event_id, replay_nonce, and
(relationship_id, sender, sender_seq)) are enforced by the schema; any
conflict raises EventStoreError and rolls the whole transaction back.

Preconditions (owned by the pairing/rotation tracks): a relationships row
and a key_epochs row for (relationship_id, key_epoch) must exist, otherwise
the events foreign keys reject the insert with "missing_reference".
Conversation and thread scope rows are created with INSERT OR IGNORE here.

The "outbox queue" mapping: the landed schema has no dedicated transport
outbox table. scheduler_queue is the only landed queue whose rows carry a
payload blob plus a deliver_at/state lifecycle, and the plan states that
the scheduler uses the same transactional outgoing queue as immediate
sends, so outgoing sealed envelopes are enqueued there with
deliver_at = protected deliver_at (or now for immediate sends) and
state "scheduled". The scheduler/transport worker releases due rows,
marks them, and uploads; restarts cannot duplicate release because the
row's idempotency key is the event_id.
"""

from __future__ import annotations

import os
import re
import sqlite3
import uuid
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from muse_agent_social.canonical import restricted_jcs
from muse_agent_social import scheduler as _scheduler
from muse_agent_social.crypto.identity import (
    parse_agreement_key,
    parse_identity_id,
)
from muse_agent_social.crypto.sealing import (
    PROTOCOL,
    REPLAY_NONCE_BYTES,
    b64url_encode,
    seal_envelope,
)
from muse_agent_social.model.approvals import consume_approval
from muse_agent_social.model.cards import parse_timestamp
from muse_agent_social.store.db import transaction, utcnow
from muse_agent_social.store.projections import record_projection_input
from muse_agent_social.validation import PAYLOAD_DISPATCH

__all__ = [
    "EventStoreError",
    "PROTECTED_FIELDS",
    "build_protected",
    "new_thread_id",
    "validate_reply",
    "assign_and_persist_outgoing",
    "persist_outgoing_in_txn",
]

PROTECTED_FIELDS = (
    "protocol",
    "event_id",
    "relationship_id",
    "conversation_id",
    "sender",
    "sender_seq",
    "created_at",
    "deliver_at",
    "expires_at",
    "event_type",
    "thread_id",
    "reply_to",
    "key_epoch",
    "replay_nonce",
    "ephemeral_key",
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)


class EventStoreError(Exception):
    """Outgoing event persistence or thread-rule validation failed.

    Attributes:
        code: stable machine-readable reason code. Conflict codes:
            "duplicate_event" (event_id already stored),
            "duplicate_nonce" (replay_nonce already stored),
            "sequence_conflict" ((relationship_id, sender, sender_seq)
            already stored with different bytes: a sequence fork),
            "missing_reference" (relationship, key epoch, conversation, or
            thread row missing), "bad_protected" (protected header missing
            required fields), "integrity_error" (any other constraint
            failure). Thread-rule codes: "bad_reply_target",
            "unknown_reply_target", "reply_wrong_conversation",
            "reply_wrong_thread", "thread_conversation_mismatch".
    """

    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {message}" if message else code)


def _check_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _UUID_RE.match(value):
        raise ValueError(
            f"{field} must be a lowercase canonical UUID string"
        )
    return value


def _check_opt_uuid(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    return _check_uuid(value, field)


def _check_opt_timestamp(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a YYYY-MM-DDTHH:MM:SSZ string")
    parse_timestamp(value)  # raises ValueError on bad form
    return value


def build_protected(
    relationship_id: str,
    conversation_id: str,
    sender_id: str,
    event_type: str,
    thread_id: Optional[str],
    reply_to: Optional[str],
    key_epoch: int,
    deliver_at: Optional[str] = None,
    expires_at: Optional[str] = None,
    ephemeral_key: Optional[str] = None,
    created_at: Optional[str] = None,
) -> dict:
    """Build the 15-field protected header for a new outgoing event.

    event_id is a fresh lowercase uuid4; sender_seq is the placeholder 0
    that assign_and_persist_outgoing replaces with the assigned sequence
    (seal_envelope requires sender_seq >= 1, so a header sealed directly
    without assignment fails schema validation). replay_nonce is 16 random
    bytes as unpadded base64url. created_at defaults to current UTC whole
    seconds. ephemeral_key is normally None here and is filled by
    seal_envelope; passing one is allowed for deterministic fixtures.

    Raises:
        ValueError: on any malformed input (bad UUID, bad did:key, unknown
            event_type, bad key_epoch, bad timestamp, bad multibase key).
    """
    _check_uuid(relationship_id, "relationship_id")
    _check_uuid(conversation_id, "conversation_id")
    parse_identity_id(sender_id)  # raises ValueError on garbage
    if event_type not in PAYLOAD_DISPATCH:
        raise ValueError(f"unknown event_type {event_type!r}")
    _check_opt_uuid(thread_id, "thread_id")
    _check_opt_uuid(reply_to, "reply_to")
    if isinstance(key_epoch, bool) or not isinstance(key_epoch, int):
        raise ValueError("key_epoch must be an integer")
    if key_epoch < 1:
        raise ValueError("key_epoch must be >= 1")
    _check_opt_timestamp(deliver_at, "deliver_at")
    _check_opt_timestamp(expires_at, "expires_at")
    if ephemeral_key is not None:
        parse_agreement_key(ephemeral_key)  # raises ValueError on garbage
    if created_at is None:
        created_at = utcnow()
    else:
        _check_opt_timestamp(created_at, "created_at")

    return {
        "protocol": PROTOCOL,
        "event_id": str(uuid.uuid4()),
        "relationship_id": relationship_id,
        "conversation_id": conversation_id,
        "sender": sender_id,
        "sender_seq": 0,
        "created_at": created_at,
        "deliver_at": deliver_at,
        "expires_at": expires_at,
        "event_type": event_type,
        "thread_id": thread_id,
        "reply_to": reply_to,
        "key_epoch": key_epoch,
        "replay_nonce": b64url_encode(os.urandom(REPLAY_NONCE_BYTES)),
        "ephemeral_key": ephemeral_key,
    }


def new_thread_id() -> str:
    """Generate a thread id for a new thread.

    Per the plan's thread rules, thread_id equals the first message's
    event_id for a new thread. Usage::

        thread_id = new_thread_id()
        protected = build_protected(..., thread_id=thread_id, ...)
        protected["event_id"] = thread_id  # first message carries the id
    """
    return str(uuid.uuid4())


def validate_reply(
    conn: sqlite3.Connection,
    target_event_id: str,
    thread_id: Optional[str],
    conversation_id: str,
) -> None:
    """Validate that reply_to names an accepted event in the same thread.

    The plan's thread rule: reply_to must name an accepted event in the same
    conversation and thread. A target that is not (yet) in the local event
    log raises "unknown_reply_target"; per the plan, projections treat such
    replies as pending for seven days, then show them as unavailable
    context, so callers may catch that specific code and defer.

    Raises:
        EventStoreError: "bad_reply_target", "unknown_reply_target",
            "reply_wrong_conversation", or "reply_wrong_thread".
    """
    try:
        _check_uuid(target_event_id, "target_event_id")
    except ValueError as exc:
        raise EventStoreError("bad_reply_target", str(exc)) from None
    row = conn.execute(
        "SELECT conversation_id, thread_id FROM events WHERE event_id = ?",
        (target_event_id,),
    ).fetchone()
    if row is None:
        raise EventStoreError(
            "unknown_reply_target",
            f"target {target_event_id} is not an accepted event",
        )
    if row["conversation_id"] != conversation_id:
        raise EventStoreError(
            "reply_wrong_conversation",
            "target event is in a different conversation",
        )
    if row["thread_id"] != thread_id:
        raise EventStoreError(
            "reply_wrong_thread", "target event is in a different thread"
        )


def _classify_integrity(exc: sqlite3.IntegrityError) -> tuple[str, str]:
    text = str(exc)
    if "events.event_id" in text:
        return "duplicate_event", text
    if "events.replay_nonce" in text:
        return "duplicate_nonce", text
    if "events.sender_seq" in text or (
        "events.relationship_id" in text and "UNIQUE" in text
    ):
        return "sequence_conflict", text
    if "FOREIGN KEY" in text:
        return "missing_reference", text
    return "integrity_error", text


def persist_outgoing_in_txn(
    conn: sqlite3.Connection,
    protected: dict,
    payload: dict,
    identity_priv: Ed25519PrivateKey,
    recipients: list,
    approval_id: Optional[str] = None,
) -> dict:
    """Seal and persist an outgoing event inside the caller's transaction.

    The shared core of :func:`assign_and_persist_outgoing`: assigns
    sender_seq = max+1, seals, inserts the events row, upserts
    sender_sequence, stages the validated projection input, enqueues
    projection_queue and the scheduler outbox. All of it commits or rolls
    back together in the caller's transaction.
    Raises EventStoreError on persistence conflicts, SealingError on
    crypto/schema failure, ProjectionError/SchemaError on payload
    validation failure. Callers needing their own atomic scope use
    this directly instead of duplicating the persist sequence.

    When ``approval_id`` is given, the human-approval record is claimed
    inside this same transaction: a failed send rolls the consumption
    back, so a human approval is never burned without authorizing a
    durably persisted event. Exactly one racing send can win the claim.
    """
    if approval_id is not None:
        # G12: bind the atomic claim to the exact response being
        # authorized, not just the approval ID. The bindings are derived
        # from the event being persisted: a concurrent or buggy caller
        # cannot redirect an approval for request A to a send answering
        # request B.
        bindings: dict = {}
        event_type = protected.get("event_type")
        if event_type == "human.responded":
            bindings = {
                "relationship_id": protected.get("relationship_id"),
                "subject_type": "human_request",
                "subject_id": payload.get("request_id"),
                "answer": payload.get("answer"),
                "approved": payload.get("approved"),
            }
        elif event_type == "poll.responded" and payload.get("human_confirmed"):
            choice_ids = payload.get("choice_ids")
            bindings = {
                "relationship_id": protected.get("relationship_id"),
                "subject_type": "poll",
                "subject_id": payload.get("poll_id"),
                "answer": (
                    restricted_jcs(list(choice_ids)).decode("utf-8")
                    if isinstance(choice_ids, (list, tuple))
                    else None
                ),
                "approved": True,
            }
        if any(v is None for v in bindings.values()):
            # Missing binding fields: do not guess. The semantic dry-run
            # rejects malformed approval-gated events before persistence,
            # so this only fires for a caller bypassing that path; failing
            # closed is the safe choice.
            raise EventStoreError(
                "approval_binding_incomplete",
                "approval-gated event is missing the fields needed to bind"
                " the approval claim",
            )
        if not consume_approval(conn, approval_id, utcnow(), **bindings):
            raise EventStoreError(
                "approval_consumed",
                "approval was consumed by a concurrent send, expired, or"
                " does not match this response",
            )
    relationship_id = protected.get("relationship_id")
    sender = protected.get("sender")
    if not relationship_id or not sender:
        raise ValueError("protected needs relationship_id and sender")
    missing = [f for f in PROTECTED_FIELDS if f not in protected]
    if missing:
        raise EventStoreError(
            "bad_protected", f"missing protected fields: {missing}"
        )

    row = conn.execute(
        "SELECT COALESCE(MAX(sender_seq), 0) FROM events "
        "WHERE relationship_id = ? AND sender = ?",
        (relationship_id, sender),
    ).fetchone()
    seq = int(row[0]) + 1
    protected["sender_seq"] = seq

    envelope = seal_envelope(protected, payload, identity_priv, recipients)
    sealed_bytes = restricted_jcs(envelope)

    conn.execute(
        "INSERT OR IGNORE INTO conversations(conversation_id) VALUES (?)",
        (protected["conversation_id"],),
    )
    thread_id = protected.get("thread_id")
    if thread_id is not None:
        existing = conn.execute(
            "SELECT conversation_id FROM threads WHERE thread_id = ?",
            (thread_id,),
        ).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO threads(thread_id, conversation_id) "
                "VALUES (?, ?)",
                (thread_id, protected["conversation_id"]),
            )
        elif existing["conversation_id"] != protected["conversation_id"]:
            raise EventStoreError(
                "thread_conversation_mismatch",
                f"thread {thread_id} already belongs to another "
                "conversation",
            )
    try:
        conn.execute(
            "INSERT INTO events(event_id, relationship_id, "
            "conversation_id, thread_id, sender, sender_seq, created_at, "
            "key_epoch, event_type, replay_nonce, sealed_envelope) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                protected["event_id"],
                relationship_id,
                protected["conversation_id"],
                thread_id,
                sender,
                seq,
                protected["created_at"],
                protected["key_epoch"],
                protected["event_type"],
                protected["replay_nonce"],
                sealed_bytes,
            ),
        )
    except sqlite3.IntegrityError as exc:
        code, message = _classify_integrity(exc)
        raise EventStoreError(code, message) from None

    conn.execute(
        "INSERT INTO sender_sequence(relationship_id, sender, last_seq) "
        "VALUES (?, ?, ?) "
        "ON CONFLICT(relationship_id, sender) DO UPDATE SET "
        "last_seq = MAX(sender_sequence.last_seq, excluded.last_seq)",
        (relationship_id, sender, seq),
    )
    conn.execute(
        "INSERT OR IGNORE INTO projection_queue(event_id, queued_at) "
        "VALUES (?, ?)",
        (protected["event_id"], utcnow()),
    )
    # Stage the validated payload atomically with the event row: without
    # this, rebuild_projections raises payload_missing for locally
    # generated events (notably the accepted receipts the receive path
    # persists via this core), breaking disaster recovery after a single
    # inbound message.
    record_projection_input(
        conn,
        event_id=protected["event_id"],
        event_type=protected["event_type"],
        payload=payload,
        reply_to=protected.get("reply_to"),
    )
    try:
        conn.execute(
            "INSERT INTO scheduler_queue(scheduled_id, inner_event, "
            "deliver_at, expires_at, state) "
            "VALUES (?, ?, ?, ?, 'scheduled')",
            (
                protected["event_id"],
                sealed_bytes,
                protected.get("deliver_at") or utcnow(),
                protected.get("expires_at"),
            ),
        )
    except sqlite3.IntegrityError as exc:
        code, message = _classify_integrity(exc)
        raise EventStoreError(code, message) from None
    if approval_id is not None:
        # S8 bookkeeping: record which human approval this scheduled row
        # consumed, so a dead-lettered or expired gated event can restore
        # it instead of silently burning the human's approval.
        _scheduler._ensure_approval_column(conn)
        conn.execute(
            "UPDATE scheduler_queue SET approval_id = ? "
            "WHERE scheduled_id = ?",
            (approval_id, protected["event_id"]),
        )

    return envelope


def assign_and_persist_outgoing(
    conn: sqlite3.Connection,
    protected: dict,
    payload: dict,
    identity_priv: Ed25519PrivateKey,
    recipients: list,
    approval_id: Optional[str] = None,
) -> dict:
    """Assign sender_seq and persist a sealed outgoing event, atomically.

    Inside one SQLite transaction (BEGIN IMMEDIATE): assigns
    sender_seq = max+1 for (relationship_id, sender), updates the passed
    protected dict in place with the assigned sequence, seals the envelope,
    inserts the events row (sealed_envelope stored as restricted-JCS
    bytes), upserts sender_sequence, enqueues the event_id on
    projection_queue for local visibility, and enqueues the sealed envelope
    on scheduler_queue (the transactional outbox) with deliver_at from
    protected (or now) and state "scheduled".

    The plan's UNIQUE constraints (event_id, replay_nonce,
    (relationship_id, sender, sender_seq)) are enforced by the schema; on
    conflict the transaction rolls back and EventStoreError is raised.

    When ``approval_id`` is given, the human-approval claim is part of
    the same transaction (see :func:`persist_outgoing_in_txn`).

    Returns:
        The sealed envelope dict.

    Raises:
        EventStoreError: on any persistence conflict.
        SealingError: from seal_envelope on any crypto/schema failure.
        ValueError: when protected lacks relationship_id/sender.
    """
    with transaction(conn):
        return persist_outgoing_in_txn(
            conn, protected, payload, identity_priv, recipients, approval_id
        )
