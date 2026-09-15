"""Unit tests for envelope sealing/unsealing and event construction.

Covers: round-trip decrypt (single and multi-recipient, dict and bytes
input), the full tamper matrix (protected, wrap, ciphertext, signature bit
flips; wrong AAD; wrong recipient key; truncated nonces; the 262144-byte
boundary) failing closed with stable SealingError codes, the golden
protected-header canonical-bytes fixture, and the transactional outgoing
event store (sequence assignment, UNIQUE enforcement, queue rows).

No real secrets appear in this file. Test keys are generated at runtime
from os.urandom or are obviously synthetic patterned byte vectors marked
as such.
"""

import copy
import os
import re
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from muse_agent_social.canonical import restricted_jcs
from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
    b64url_decode,
    b64url_encode,
    derive_identity_hierarchy,
    generate_master_seed,
    identity_id_from_pubkey,
)
from muse_agent_social.crypto.sealing import (
    MAX_ENVELOPE_BYTES,
    MAX_PAYLOAD_BYTES,
    SealingError,
    seal_envelope,
    unseal_envelope,
)
from muse_agent_social.model.events import (
    PROTECTED_FIELDS,
    EventStoreError,
    assign_and_persist_outgoing,
    build_protected,
    new_thread_id,
    validate_reply,
)
from muse_agent_social.store.db import connect, utcnow
from muse_agent_social.store.migrations import migrate
from muse_agent_social.validation import MAX_ENVELOPE_BYTES as VALIDATION_MAX
from muse_agent_social.validation import validate

REL_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CONV_ID = "12345678-1234-4234-8234-1234567890ab"
THREAD_ID = "11111111-2222-4333-8444-555555555555"
CREATED_AT = "2026-09-15T20:00:00Z"
PAYLOAD = {"body": "hello", "format": "plain"}

# Synthetic test vectors only: patterned bytes, never real keys.
FIXED_SENDER_PUB = bytes(range(32))
FIXED_EPH_PUB = bytes(range(1, 33))
FIXED_PROTECTED_JCS = (
    b'{"conversation_id":"12345678-1234-4234-8234-1234567890ab",'
    b'"created_at":"2026-09-15T20:00:00Z","deliver_at":null,'
    b'"ephemeral_key":"z6LSbk7MN8NDFRJBo2wkq5sYG4XonrAvuJVkS4NaaDcbD6Th",'
    b'"event_id":"11111111-2222-4333-8444-555555555555",'
    b'"event_type":"message.created","expires_at":null,"key_epoch":1,'
    b'"protocol":"muse-agent-social/0.2",'
    b'"relationship_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",'
    b'"replay_nonce":"AAECAwQFBgcICQoLDA0ODw","reply_to":null,'
    b'"sender":"did:key:z6MkeTGwHmLmuCmgg4ABYhzWVh6ZX7hTwWt8gguAretUfc9c",'
    b'"sender_seq":42,"thread_id":"11111111-2222-4333-8444-555555555555"}'
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class Pair:
    """One test relationship side: identity plus one relationship keypair."""

    def __init__(self):
        self.hierarchy = derive_identity_hierarchy(generate_master_seed())
        self.rel_priv = X25519PrivateKey.generate()
        self.rel_pub = self.rel_priv.public_key().public_bytes_raw()

    @property
    def did(self):
        return self.hierarchy.identity_id

    @property
    def entry(self):
        return {
            "recipient": self.did,
            "agreement_key": agreement_key_multibase_from_pubkey(self.rel_pub),
            "relationship_pub": self.rel_pub,
        }


@pytest.fixture()
def sender():
    return Pair()


@pytest.fixture()
def recipient():
    return Pair()


@pytest.fixture()
def other():
    return Pair()


def make_protected(sender_did, seq=1, **overrides):
    kwargs = dict(
        relationship_id=REL_ID,
        conversation_id=CONV_ID,
        sender_id=sender_did,
        event_type="message.created",
        thread_id=THREAD_ID,
        reply_to=None,
        key_epoch=1,
        created_at=CREATED_AT,
    )
    kwargs.update(overrides)
    protected = build_protected(**kwargs)
    protected["sender_seq"] = seq
    return protected


def seal(sender, recipient_pair, payload=None, seq=1, **overrides):
    protected = make_protected(sender.did, seq=seq, **overrides)
    return seal_envelope(
        protected, payload if payload is not None else PAYLOAD,
        sender.hierarchy.ed25519_private, [recipient_pair.entry],
    )


def resign(envelope, sender):
    """Recompute the envelope signature with the sender's identity key."""
    env = copy.deepcopy(envelope)
    unsigned = {k: v for k, v in env.items() if k != "signature"}
    env["signature"] = b64url_encode(
        sender.hierarchy.ed25519_private.sign(restricted_jcs(unsigned))
    )
    return env


def flip_first_char(text):
    # Flip the first base64url char: position 0 always carries six real
    # data bits, so the decoded bytes are guaranteed to change. (Flipping
    # the last char can hit only padding bits and decode identically.)
    assert len(text) >= 1
    first = text[0]
    return ("A" if first != "A" else "B") + text[1:]


# ---------------------------------------------------------------------------
# Golden vector: byte-stable protected canonicalization
# ---------------------------------------------------------------------------


def test_golden_protected_jcs_bytes():
    protected = build_protected(
        relationship_id=REL_ID,
        conversation_id=CONV_ID,
        sender_id=identity_id_from_pubkey(FIXED_SENDER_PUB),
        event_type="message.created",
        thread_id=THREAD_ID,
        reply_to=None,
        key_epoch=1,
        ephemeral_key=agreement_key_multibase_from_pubkey(FIXED_EPH_PUB),
        created_at=CREATED_AT,
    )
    protected["event_id"] = THREAD_ID
    protected["sender_seq"] = 42
    protected["replay_nonce"] = b64url_encode(bytes(range(16)))
    assert restricted_jcs(protected) == FIXED_PROTECTED_JCS


# ---------------------------------------------------------------------------
# build_protected
# ---------------------------------------------------------------------------


def test_build_protected_has_all_15_fields(sender):
    protected = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1
    )
    assert set(protected) == set(PROTECTED_FIELDS)
    assert len(PROTECTED_FIELDS) == 15
    assert protected["protocol"] == "muse-agent-social/0.2"
    assert protected["sender_seq"] == 0  # placeholder for the caller to fill
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{4}-[0-9a-f]{12}",
        protected["event_id"],
    )
    assert len(b64url_decode(protected["replay_nonce"])) == 16
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", protected["created_at"]
    )
    assert protected["deliver_at"] is None
    assert protected["expires_at"] is None
    assert protected["ephemeral_key"] is None


def test_build_protected_rejects_bad_inputs(sender):
    with pytest.raises(ValueError):
        build_protected(
            "not-a-uuid", CONV_ID, sender.did, "message.created",
            THREAD_ID, None, 1,
        )
    with pytest.raises(ValueError):
        build_protected(
            REL_ID, CONV_ID, "did:key:zgarbage", "message.created",
            THREAD_ID, None, 1,
        )
    with pytest.raises(ValueError):
        build_protected(
            REL_ID, CONV_ID, sender.did, "nope.unknown",
            THREAD_ID, None, 1,
        )
    with pytest.raises(ValueError):
        build_protected(
            REL_ID, CONV_ID, sender.did, "message.created",
            THREAD_ID, None, 0,
        )
    with pytest.raises(ValueError):
        build_protected(
            REL_ID, CONV_ID, sender.did, "message.created",
            THREAD_ID, None, 1, created_at="yesterday",
        )


def test_new_thread_id_format():
    first, second = new_thread_id(), new_thread_id()
    assert first != second
    uuid.UUID(first)  # parses as a UUID


# ---------------------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------------------


def test_round_trip_dict_and_bytes(sender, recipient):
    envelope = seal(sender, recipient)
    validate("event-envelope", envelope)  # sealed output is schema-valid
    protected, payload = unseal_envelope(
        envelope, recipient.rel_priv, recipient.did
    )
    assert payload == PAYLOAD
    assert protected["event_id"] == envelope["protected"]["event_id"]
    assert protected["sender"] == sender.did

    raw = restricted_jcs(envelope)
    protected2, payload2 = unseal_envelope(
        raw, recipient.rel_priv, recipient.did
    )
    assert payload2 == PAYLOAD
    assert protected2 == protected


def test_round_trip_multi_recipient(sender, recipient, other):
    protected = make_protected(sender.did)
    envelope = seal_envelope(
        protected, PAYLOAD, sender.hierarchy.ed25519_private,
        [other.entry, recipient.entry],  # unsorted input on purpose
    )
    entries = envelope["recipients"]
    assert [(e["recipient"], e["agreement_key"]) for e in entries] == sorted(
        (e["recipient"], e["agreement_key"]) for e in entries
    )
    _, payload_a = unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    _, payload_b = unseal_envelope(envelope, other.rel_priv, other.did)
    assert payload_a == PAYLOAD
    assert payload_b == PAYLOAD


def test_recipient_entries_sorted_by_recipient_then_key(sender, recipient):
    envelope = seal(sender, recipient)
    keys = [
        (e["recipient"], e["agreement_key"]) for e in envelope["recipients"]
    ]
    assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# Seal-side failures
# ---------------------------------------------------------------------------


def test_seal_rejects_empty_recipients(sender):
    protected = make_protected(sender.did)
    with pytest.raises(SealingError) as excinfo:
        seal_envelope(
            protected, PAYLOAD, sender.hierarchy.ed25519_private, []
        )
    assert excinfo.value.code == "no_recipients"


def test_seal_rejects_placeholder_sender_seq(sender, recipient):
    protected = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT,
    )  # sender_seq stays 0
    with pytest.raises(SealingError) as excinfo:
        seal_envelope(
            protected, PAYLOAD, sender.hierarchy.ed25519_private,
            [recipient.entry],
        )
    assert excinfo.value.code == "schema_invalid"


def test_seal_rejects_wrong_signing_key(sender, recipient, other):
    protected = make_protected(sender.did)
    with pytest.raises(SealingError) as excinfo:
        seal_envelope(
            protected, PAYLOAD, other.hierarchy.ed25519_private,
            [recipient.entry],
        )
    assert excinfo.value.code == "sender_key_mismatch"


def test_seal_rejects_oversize_payload(sender, recipient):
    protected = make_protected(sender.did)
    big = {"body": "x" * (MAX_PAYLOAD_BYTES + 1), "format": "plain"}
    with pytest.raises(SealingError) as excinfo:
        seal_envelope(
            protected, big, sender.hierarchy.ed25519_private,
            [recipient.entry],
        )
    assert excinfo.value.code == "payload_too_large"


def test_seal_rejects_recipient_key_mismatch(sender, recipient):
    protected = make_protected(sender.did)
    bad = dict(recipient.entry)
    bad["agreement_key"] = agreement_key_multibase_from_pubkey(os.urandom(32))
    with pytest.raises(SealingError) as excinfo:
        seal_envelope(
            protected, PAYLOAD, sender.hierarchy.ed25519_private, [bad]
        )
    assert excinfo.value.code == "key_mismatch"


# ---------------------------------------------------------------------------
# Tamper matrix: every corruption fails closed
# ---------------------------------------------------------------------------


def test_tamper_protected_bit_no_resign(sender, recipient):
    envelope = seal(sender, recipient)
    envelope["protected"]["sender_seq"] = 999  # schema-valid, breaks signature
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "bad_signature"


def test_tamper_signature_bit(sender, recipient):
    envelope = seal(sender, recipient)
    envelope["signature"] = flip_first_char(envelope["signature"])
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "bad_signature"


def test_tamper_ciphertext_bit_resigned(sender, recipient):
    envelope = seal(sender, recipient)
    envelope["ciphertext"] = flip_first_char(envelope["ciphertext"])
    envelope = resign(envelope, sender)
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "tampered_body"


def test_tamper_wrap_bit_resigned(sender, recipient):
    envelope = seal(sender, recipient)
    envelope["recipients"][0]["wrapped_key"] = flip_first_char(
        envelope["recipients"][0]["wrapped_key"]
    )
    envelope = resign(envelope, sender)
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "tampered_wrap"


def test_tamper_protected_bit_resigned_changes_aad(sender, recipient):
    # Tampering with protected changes H, which changes the KEK, so the
    # (re-signed) wrap no longer unwraps under the recipient's key.
    envelope = seal(sender, recipient)
    envelope["protected"]["sender_seq"] = 999
    envelope = resign(envelope, sender)
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "tampered_wrap"


def test_wrong_recipient_key_is_wrong_aad(sender, recipient, other):
    envelope = seal(sender, recipient)
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, other.rel_priv, recipient.did)
    assert excinfo.value.code == "wrong_aad"


def test_unknown_recipient(sender, recipient, other):
    envelope = seal(sender, recipient)
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, other.did)
    assert excinfo.value.code == "unknown_recipient"


def test_truncated_content_nonce(sender, recipient):
    envelope = seal(sender, recipient)
    envelope["content_nonce"] = envelope["content_nonce"][:-1]
    envelope = resign(envelope, sender)
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "tampered_body"


def test_truncated_wrap_nonce(sender, recipient):
    envelope = seal(sender, recipient)
    entry = envelope["recipients"][0]
    entry["wrap_nonce"] = entry["wrap_nonce"][:-1]
    envelope = resign(envelope, sender)
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "tampered_wrap"


def test_low_order_ephemeral_key_rejected(sender, recipient):
    envelope = seal(sender, recipient)
    envelope["protected"]["ephemeral_key"] = (
        agreement_key_multibase_from_pubkey(b"\x00" * 32)
    )
    envelope = resign(envelope, sender)
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "low_order_key"


def test_duplicate_keys_rejected(sender, recipient):
    envelope = seal(sender, recipient)
    raw = restricted_jcs(envelope).decode("ascii")
    # Inject a duplicate top-level key before parse.
    duped = raw[:-1] + ',"signature":"AA"}'
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(duped.encode("ascii"), recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "invalid_envelope"
    assert excinfo.value.detail == "duplicate_key"


def test_unknown_top_level_field_rejected(sender, recipient):
    envelope = seal(sender, recipient)
    envelope["extra"] = "nope"
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "schema_invalid"


def test_tampered_payload_fails_payload_schema(sender, recipient):
    # A payload that decrypts but is not valid for its event type.
    envelope = seal(sender, recipient, payload={"body": "x", "format": "plain"})
    # Re-seal with a payload missing the required "body" field is caught
    # at seal time by schema validation of the envelope only, so instead
    # craft the failure at unseal: wrong event_type for the payload.
    envelope["protected"]["event_type"] = "reaction.added"
    envelope = resign(envelope, sender)
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    # H changed with protected, so this surfaces as a wrap failure first.
    assert excinfo.value.code == "tampered_wrap"


def test_payload_schema_checked_after_decrypt(sender, recipient):
    # Directly exercise the payload-validation tail of unseal: seal a
    # message.created envelope, then flip only the payload bytes via a
    # manual re-encryption is not possible without the CEK, so instead
    # verify that a schema-invalid payload for the declared type fails
    # when the envelope is otherwise intact. Build via seal with a payload
    # that is valid JSON but invalid for the type, resigning is not needed
    # because seal signs whatever payload it is given; the failure must
    # come from validate_payload at unseal.
    protected = make_protected(sender.did, event_type="reaction.added")
    envelope = seal_envelope(
        protected, {"not": "an emoji payload"},
        sender.hierarchy.ed25519_private, [recipient.entry],
    )
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(envelope, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "payload_invalid"


def test_dual_wrap_rotation_picks_matching_key(sender, recipient):
    # Key rotation: the envelope carries one wrap per epoch key for the
    # same recipient; unseal with either private key must succeed by
    # selecting the wrap whose agreement key matches.
    new_priv = X25519PrivateKey.generate()
    new_pub = new_priv.public_key().public_bytes_raw()
    new_entry = {
        "recipient": recipient.did,
        "agreement_key": agreement_key_multibase_from_pubkey(new_pub),
        "relationship_pub": new_pub,
    }
    protected = make_protected(sender.did)
    envelope = seal_envelope(
        protected, PAYLOAD, sender.hierarchy.ed25519_private,
        [recipient.entry, new_entry],
    )
    assert len(envelope["recipients"]) == 2
    _, payload_old = unseal_envelope(
        envelope, recipient.rel_priv, recipient.did
    )
    _, payload_new = unseal_envelope(envelope, new_priv, recipient.did)
    assert payload_old == PAYLOAD
    assert payload_new == PAYLOAD


# ---------------------------------------------------------------------------
# Size boundary: 262144 bytes
# ---------------------------------------------------------------------------


def test_size_boundary_bytes(recipient):
    assert MAX_ENVELOPE_BYTES == 262144
    assert VALIDATION_MAX == 262144
    # Exactly at the boundary: passes the size check, fails at parse.
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(b"x" * 262144, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "invalid_envelope"
    # One byte over: rejected before parse.
    with pytest.raises(SealingError) as excinfo:
        unseal_envelope(b"x" * 262145, recipient.rel_priv, recipient.did)
    assert excinfo.value.code == "envelope_too_large"


def test_sealed_envelope_within_size_limit(sender, recipient):
    envelope = seal(sender, recipient)
    assert len(restricted_jcs(envelope)) <= MAX_ENVELOPE_BYTES


# ---------------------------------------------------------------------------
# Transactional outgoing store
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path):
    conn = connect(tmp_path / "state.db")
    migrate(conn)
    return conn


def _insert_relationship(conn, rel_id, peer_did, agreement_key):
    conn.execute(
        "INSERT INTO relationships(relationship_id, peer_identity_id, "
        "consent_state, policy, key_epoch, created_at) "
        "VALUES (?, ?, 'active', '{}', 1, ?)",
        (rel_id, peer_did, utcnow()),
    )
    conn.execute(
        "INSERT INTO key_epochs(relationship_id, epoch, public_key, "
        "private_key_ref, state) VALUES (?, 1, ?, 'test-ref', 'active')",
        (rel_id, agreement_key),
    )


def test_assign_and_persist_assigns_sequences(db, sender, recipient):
    _insert_relationship(db, REL_ID, recipient.did, recipient.entry["agreement_key"])

    p1 = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT,
    )
    env1 = assign_and_persist_outgoing(
        db, p1, PAYLOAD, sender.hierarchy.ed25519_private, [recipient.entry]
    )
    assert p1["sender_seq"] == 1
    assert env1["protected"]["sender_seq"] == 1

    p2 = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT,
    )
    env2 = assign_and_persist_outgoing(
        db, p2, PAYLOAD, sender.hierarchy.ed25519_private, [recipient.entry]
    )
    assert p2["sender_seq"] == 2

    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2
    assert (
        db.execute("SELECT COUNT(*) FROM scheduler_queue").fetchone()[0] == 2
    )
    assert (
        db.execute("SELECT COUNT(*) FROM projection_queue").fetchone()[0] == 2
    )
    last_seq = db.execute(
        "SELECT last_seq FROM sender_sequence "
        "WHERE relationship_id = ? AND sender = ?",
        (REL_ID, sender.did),
    ).fetchone()[0]
    assert last_seq == 2

    state = db.execute(
        "SELECT state, deliver_at FROM scheduler_queue "
        "WHERE scheduled_id = ?",
        (p1["event_id"],),
    ).fetchone()
    assert state["state"] == "scheduled"
    assert state["deliver_at"] is not None

    # The stored sealed bytes unseal to the original payload.
    row = db.execute(
        "SELECT sealed_envelope FROM events WHERE event_id = ?",
        (p1["event_id"],),
    ).fetchone()
    _, payload = unseal_envelope(
        bytes(row["sealed_envelope"]), recipient.rel_priv, recipient.did
    )
    assert payload == PAYLOAD


def test_assign_and_persist_rejects_duplicate_event_id(db, sender, recipient):
    _insert_relationship(db, REL_ID, recipient.did, recipient.entry["agreement_key"])
    p1 = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT,
    )
    assign_and_persist_outgoing(
        db, p1, PAYLOAD, sender.hierarchy.ed25519_private, [recipient.entry]
    )
    p2 = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT,
    )
    p2["event_id"] = p1["event_id"]  # reuse the event id
    with pytest.raises(EventStoreError) as excinfo:
        assign_and_persist_outgoing(
            db, p2, PAYLOAD, sender.hierarchy.ed25519_private,
            [recipient.entry],
        )
    assert excinfo.value.code == "duplicate_event"
    # The rolled-back transaction left no partial state.
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_assign_and_persist_requires_relationship_row(db, sender, recipient):
    p1 = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT,
    )
    with pytest.raises(EventStoreError) as excinfo:
        assign_and_persist_outgoing(
            db, p1, PAYLOAD, sender.hierarchy.ed25519_private,
            [recipient.entry],
        )
    assert excinfo.value.code == "missing_reference"


def test_assign_and_persist_scheduled_delivery(db, sender, recipient):
    _insert_relationship(db, REL_ID, recipient.did, recipient.entry["agreement_key"])
    deliver_at = "2026-09-16T20:00:00Z"
    p1 = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT, deliver_at=deliver_at,
    )
    assign_and_persist_outgoing(
        db, p1, PAYLOAD, sender.hierarchy.ed25519_private, [recipient.entry]
    )
    row = db.execute(
        "SELECT deliver_at, state FROM scheduler_queue WHERE scheduled_id = ?",
        (p1["event_id"],),
    ).fetchone()
    assert row["deliver_at"] == deliver_at
    assert row["state"] == "scheduled"


def test_sequences_are_per_sender(db, sender, recipient, other):
    _insert_relationship(db, REL_ID, recipient.did, recipient.entry["agreement_key"])
    p1 = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT,
    )
    assign_and_persist_outgoing(
        db, p1, PAYLOAD, sender.hierarchy.ed25519_private, [recipient.entry]
    )
    p2 = build_protected(
        REL_ID, CONV_ID, other.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT,
    )
    assign_and_persist_outgoing(
        db, p2, PAYLOAD, other.hierarchy.ed25519_private, [recipient.entry]
    )
    assert p1["sender_seq"] == 1
    assert p2["sender_seq"] == 1  # independent per-sender sequence


# ---------------------------------------------------------------------------
# Thread rules
# ---------------------------------------------------------------------------


def test_validate_reply_happy_path(db, sender, recipient):
    _insert_relationship(db, REL_ID, recipient.did, recipient.entry["agreement_key"])
    thread_id = new_thread_id()
    first = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", thread_id, None, 1,
        created_at=CREATED_AT,
    )
    first["event_id"] = thread_id  # thread_id equals the first message id
    assign_and_persist_outgoing(
        db, first, PAYLOAD, sender.hierarchy.ed25519_private, [recipient.entry]
    )
    validate_reply(db, thread_id, thread_id, CONV_ID)  # no raise


def test_validate_reply_unknown_target_is_pending(db):
    with pytest.raises(EventStoreError) as excinfo:
        validate_reply(db, new_thread_id(), THREAD_ID, CONV_ID)
    assert excinfo.value.code == "unknown_reply_target"


def test_validate_reply_wrong_conversation(db, sender, recipient):
    _insert_relationship(db, REL_ID, recipient.did, recipient.entry["agreement_key"])
    first = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT,
    )
    assign_and_persist_outgoing(
        db, first, PAYLOAD, sender.hierarchy.ed25519_private, [recipient.entry]
    )
    with pytest.raises(EventStoreError) as excinfo:
        validate_reply(db, first["event_id"], THREAD_ID, new_thread_id())
    assert excinfo.value.code == "reply_wrong_conversation"


def test_validate_reply_wrong_thread(db, sender, recipient):
    _insert_relationship(db, REL_ID, recipient.did, recipient.entry["agreement_key"])
    first = build_protected(
        REL_ID, CONV_ID, sender.did, "message.created", THREAD_ID, None, 1,
        created_at=CREATED_AT,
    )
    assign_and_persist_outgoing(
        db, first, PAYLOAD, sender.hierarchy.ed25519_private, [recipient.entry]
    )
    with pytest.raises(EventStoreError) as excinfo:
        validate_reply(db, first["event_id"], new_thread_id(), CONV_ID)
    assert excinfo.value.code == "reply_wrong_thread"
