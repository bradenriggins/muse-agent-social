"""Unit tests for every v0.2 JSON schema plus the validation helpers.

For each schema: at least one positive case and negative cases covering
missing required fields, wrong types, pattern/enum violations, and unknown
fields (additionalProperties). Also covers the 262144-byte envelope boundary,
payload dispatch, and the no-secret-leak guarantee.
"""

import copy

import pytest

from muse_agent_social.validation import (
    MAX_ENVELOPE_BYTES,
    PAYLOAD_DISPATCH,
    ValidationError,
    check_envelope_size,
    validate,
    validate_payload,
)

DID = "did:key:z6MkpTHR8VNsBxYAAWHut2Gea6Cdxx"
DID2 = "did:key:z5Kf8mN2pQrStUvWxYzAbCdEfGhJk"
ZB58 = "z6MkpTHR8VNsBxYAAWHut2Gea6Cdxx"
B64 = "AAECAwQFBgcICQoLDA0ODxAREhMU"
UUID = "12345678-1234-4234-8234-1234567890ab"
UUID2 = "87654321-4321-4234-8234-abcdefabcdef"
TS = "2026-09-15T20:00:00Z"


def valid_card(**over):
    card = {
        "card_version": 1,
        "identity_id": DID,
        "display_name": "Hermes",
        "principal_label": "Braden",
        "bootstrap_agreement_key": ZB58,
        "capabilities": ["events/0.2", "receipts/1", "threads/1"],
        "issued_at": TS,
        "expires_at": "2027-09-15T20:00:00Z",
        "card_nonce": B64,
        "signature": B64,
    }
    card.update(over)
    return card


def valid_envelope(**over):
    env = {
        "protected": {
            "protocol": "muse-agent-social/0.2",
            "event_id": UUID,
            "relationship_id": UUID2,
            "conversation_id": UUID,
            "sender": DID,
            "sender_seq": 42,
            "created_at": TS,
            "deliver_at": None,
            "expires_at": None,
            "event_type": "message.created",
            "thread_id": UUID,
            "reply_to": None,
            "key_epoch": 1,
            "replay_nonce": B64,
            "ephemeral_key": ZB58,
        },
        "recipients": [
            {
                "recipient": DID2,
                "agreement_key": ZB58,
                "wrap_nonce": B64,
                "wrapped_key": B64,
            }
        ],
        "content_nonce": B64,
        "ciphertext": B64,
        "signature": B64,
    }
    env.update(over)
    return env


def expect_error(schema_name, obj, field_path, code):
    with pytest.raises(ValidationError) as exc:
        validate(schema_name, obj)
    assert exc.value.field_path == field_path, (
        f"{schema_name}: path {exc.value.field_path!r} != {field_path!r}"
    )
    assert exc.value.code == code, (
        f"{schema_name}: code {exc.value.code!r} != {code!r}"
    )


# config


def test_config_valid():
    validate(
        "config",
        {"config_version": 1, "state_dir": "/tmp/mas-state", "identity_id": DID},
    )


def test_config_rejects_missing_and_extra():
    expect_error("config", {"config_version": 1}, "state_dir", "required")
    bad = {
        "config_version": 1,
        "state_dir": "/tmp/x",
        "identity_id": DID,
        "master_seed": "deadbeef",
    }
    expect_error("config", bad, "master_seed", "additional_property")


def test_config_rejects_fast_poll():
    bad = {
        "config_version": 1,
        "state_dir": "/tmp/x",
        "identity_id": DID,
        "watcher_poll_seconds": 5,
    }
    expect_error("config", bad, "watcher_poll_seconds", "minimum")


# agent-card


def test_agent_card_valid():
    validate("agent-card", valid_card())


def test_agent_card_rejects_bad_identity_and_dupes():
    expect_error("agent-card", valid_card(identity_id="did:key:zABCDEF0123456789"),
                 "identity_id", "pattern")
    expect_error(
        "agent-card",
        valid_card(capabilities=["events/0.2", "events/0.2"]),
        "capabilities",
        "unique_items",
    )
    expect_error(
        "agent-card", valid_card(capabilities=["c"] * 65), "capabilities", "max_items"
    )
    card = valid_card()
    card["nickname"] = "x"
    expect_error("agent-card", card, "nickname", "additional_property")


# invite


def valid_invite(**over):
    inv = {
        "invite_version": 1,
        "invite_id": UUID,
        "inviter_card": valid_card(),
        "ephemeral_agreement_key": ZB58,
        "requested_capabilities": ["events/0.2", "threads/1"],
        "requested_policy": {"accepted_receipts": True},
        "issued_at": TS,
        "expires_at": "2026-09-15T20:15:00Z",
        "signature": B64,
    }
    inv.update(over)
    return inv


def test_invite_valid():
    validate("invite", valid_invite())


def test_invite_rejects_missing_signature_and_bad_card():
    inv = valid_invite()
    del inv["signature"]
    expect_error("invite", inv, "signature", "required")
    inv = valid_invite()
    inv["inviter_card"] = valid_card(identity_id="not-a-did")
    expect_error("invite", inv, "inviter_card.identity_id", "pattern")


# invite-acceptance


def valid_acceptance(**over):
    acc = {
        "acceptance_version": 1,
        "invite_id": UUID,
        "invite_hash": B64,
        "acceptor_card": valid_card(identity_id=DID2),
        "relationship_agreement_key": ZB58,
        "deploy_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest",
        "accepted_at": TS,
        "signature": B64,
    }
    acc.update(over)
    return acc


def test_invite_acceptance_valid():
    validate("invite-acceptance", valid_acceptance())


def test_invite_acceptance_rejects_bad_deploy_key():
    expect_error(
        "invite-acceptance",
        valid_acceptance(deploy_public_key="not a key"),
        "deploy_public_key",
        "pattern",
    )


# relationship


def valid_relationship(**over):
    rel = {
        "relationship_version": 1,
        "relationship_id": UUID2,
        "local_card": valid_card(),
        "peer_card": valid_card(identity_id=DID2),
        "negotiated_capabilities": ["events/0.2", "threads/1"],
        "delivery_policy": "alert",
        "consent_state": "active",
        "key_epochs": [
            {"epoch": 1, "agreement_public_key": ZB58, "state": "active"}
        ],
        "created_at": TS,
    }
    rel.update(over)
    return rel


def test_relationship_valid():
    validate("relationship", valid_relationship())


def test_relationship_rejects_bad_state_and_empty_epochs():
    expect_error(
        "relationship",
        valid_relationship(consent_state="paused"),
        "consent_state",
        "enum",
    )
    expect_error(
        "relationship", valid_relationship(key_epochs=[]), "key_epochs", "min_items"
    )
    rel = valid_relationship()
    rel["key_epochs"][0]["state"] = "active-tomorrow"
    expect_error("relationship", rel, "key_epochs[0].state", "enum")


# relay


def test_relay_valid():
    validate(
        "relay",
        {
            "relay_version": 1,
            "provider": "github",
            "repo_url": "git@github.com:example/relay.git",
            "slots": {"send_slot": "a-to-b", "receive_slot": "b-to-a"},
            "local_key_path": "/tmp/mas-state/relay_key",
        },
    )


def test_relay_rejects_unknown_provider_and_peer_key_field():
    bad = {
        "relay_version": 1,
        "provider": "s3",
        "repo_url": "x",
        "slots": {"send_slot": "a", "receive_slot": "b"},
        "local_key_path": "/tmp/k",
    }
    expect_error("relay", bad, "provider", "enum")
    bad["provider"] = "local"
    bad["peer_private_key"] = "deadbeef"
    expect_error("relay", bad, "peer_private_key", "additional_property")


# event-envelope


def test_envelope_valid():
    validate("event-envelope", valid_envelope())


def test_envelope_rejects_missing_protected_field_with_path():
    env = valid_envelope()
    del env["protected"]["event_id"]
    expect_error("event-envelope", env, "protected.event_id", "required")


def test_envelope_rejects_unknown_top_level_and_protected_fields():
    env = valid_envelope()
    env["bogus"] = 1
    expect_error("event-envelope", env, "bogus", "additional_property")
    env = valid_envelope()
    env["protected"]["bogus"] = 1
    expect_error("event-envelope", env, "protected.bogus", "additional_property")


def test_envelope_rejects_bad_event_type_uuid_and_base64():
    env = valid_envelope()
    env["protected"]["event_type"] = "message.deleted"
    expect_error("event-envelope", env, "protected.event_type", "enum")
    env = valid_envelope()
    env["protected"]["event_id"] = "12345678-1234-4234-8234-1234567890AB"
    expect_error("event-envelope", env, "protected.event_id", "pattern")
    env = valid_envelope()
    env["signature"] = "AB=="  # padding is forbidden
    expect_error("event-envelope", env, "signature", "pattern")


def test_envelope_rejects_bad_seq_and_protocol():
    env = valid_envelope()
    env["protected"]["sender_seq"] = 0
    expect_error("event-envelope", env, "protected.sender_seq", "minimum")
    env = valid_envelope()
    env["protected"]["protocol"] = "muse-agent-social/0.3"
    expect_error("event-envelope", env, "protected.protocol", "const")


def test_envelope_nullable_fields():
    env = valid_envelope()
    env["protected"]["deliver_at"] = TS
    env["protected"]["expires_at"] = TS
    env["protected"]["thread_id"] = None
    env["protected"]["reply_to"] = UUID2
    validate("event-envelope", env)
    env["protected"]["deliver_at"] = "not-a-time"
    expect_error("event-envelope", env, "protected.deliver_at", "pattern")


def test_envelope_requires_recipient_entries():
    env = valid_envelope()
    env["recipients"] = []
    expect_error("event-envelope", env, "recipients", "min_items")
    env = valid_envelope()
    del env["recipients"][0]["wrapped_key"]
    expect_error(
        "event-envelope", env, "recipients[0].wrapped_key", "required"
    )


def test_envelope_accepts_all_event_types():
    for event_type in sorted(PAYLOAD_DISPATCH):
        env = valid_envelope()
        env["protected"]["event_type"] = event_type
        validate("event-envelope", env)
    assert len(PAYLOAD_DISPATCH) == 22


# payloads


def expect_payload_error(event_type, payload, field_path, code):
    with pytest.raises(ValidationError) as exc:
        validate_payload(event_type, payload)
    assert exc.value.field_path == field_path
    assert exc.value.code == code


def test_payload_message_variants():
    validate_payload("message.created", {"body": "hi", "format": "plain"})
    validate_payload("message.created", {"body": "hi", "format": "markdown-safe"})
    expect_payload_error("message.created", {"body": "hi"}, "format", "required")
    expect_payload_error(
        "message.created", {"body": "hi", "format": "html"}, "format", "enum"
    )
    validate_payload(
        "message.edited",
        {"target_event_id": UUID, "body": "fixed", "reason": "typo"},
    )
    validate_payload("message.retracted", {"target_event_id": UUID})
    validate_payload(
        "message.retracted", {"target_event_id": UUID, "reason": "oops"}
    )
    bad = {"body": "x", "format": "plain", "extra": 1}
    expect_payload_error("message.created", bad, "extra", "additional_property")


def test_payload_reaction_variants():
    validate_payload("reaction.added", {"target_event_id": UUID, "emoji": "👍"})
    validate_payload("reaction.removed", {"target_event_id": UUID, "emoji": "👍"})
    expect_payload_error(
        "reaction.added",
        {"target_event_id": UUID, "emoji": "a\x01b"},
        "emoji",
        "pattern",
    )
    expect_payload_error(
        "reaction.added",
        {"target_event_id": UUID, "emoji": "😀" * 9},  # 36 UTF-8 bytes
        "emoji",
        "too_long_bytes",
    )


def test_payload_receipt_variants():
    validate_payload(
        "receipt.accepted", {"target_event_id": UUID, "accepted_at": TS}
    )
    validate_payload("receipt.seen", {"target_event_id": UUID, "seen_at": TS})
    expect_payload_error(
        "receipt.accepted", {"target_event_id": UUID}, "accepted_at", "required"
    )


def test_payload_poll_variants():
    validate_payload(
        "poll.created",
        {
            "question": "lunch?",
            "choices": ["tacos", "sushi"],
            "closes_at": TS,
            "multi_select": False,
        },
    )
    expect_payload_error(
        "poll.created",
        {"question": "q", "choices": ["only"], "closes_at": TS,
         "multi_select": True},
        "choices",
        "min_items",
    )
    expect_payload_error(
        "poll.created",
        {
            "question": "q",
            "choices": ["ok", "x" * 121],
            "closes_at": TS,
            "multi_select": False,
        },
        "choices[1]",
        "max_length",
    )
    # 61 two-byte chars: 61 chars (within maxLength 120) but 122 UTF-8 bytes.
    expect_payload_error(
        "poll.created",
        {
            "question": "q",
            "choices": ["ok", "é" * 61],
            "closes_at": TS,
            "multi_select": False,
        },
        "choices[1]",
        "too_long_bytes",
    )
    validate_payload(
        "poll.responded",
        {"poll_id": UUID, "choice_ids": ["tacos"], "human_confirmed": True,
         "approval_record_id": "rec1"},
    )
    expect_payload_error(
        "poll.responded", {"poll_id": UUID, "choice_ids": []}, "choice_ids",
        "min_items",
    )


def test_payload_task_variants():
    validate_payload(
        "task.created",
        {"title": "write demo", "owner_identity": DID, "due_at": TS},
    )
    expect_payload_error(
        "task.created", {"title": "x"}, "owner_identity", "required"
    )
    validate_payload(
        "task.updated", {"task_id": UUID, "status": "in_progress", "note": "started"}
    )
    expect_payload_error(
        "task.updated", {"task_id": UUID, "status": "archived"}, "status", "enum"
    )


def test_payload_human_variants():
    validate_payload(
        "human.requested",
        {"prompt": "approve?", "response_shape": "approval", "expires_at": TS},
    )
    validate_payload(
        "human.responded",
        {"request_id": UUID, "answer": "yes", "approved": True,
         "approval_record_id": "rec1"},
    )
    expect_payload_error(
        "human.responded",
        {"request_id": UUID, "answer": "yes", "approved": "yes",
         "approval_record_id": "rec1"},
        "approved",
        "type",
    )


def test_payload_delivery_variants():
    validate_payload(
        "delivery.scheduled",
        {"inner_event_id": UUID, "deliver_at": TS, "late_by_seconds": 30},
    )
    expect_payload_error(
        "delivery.scheduled",
        {"inner_event_id": UUID, "deliver_at": TS, "late_by_seconds": -1},
        "late_by_seconds",
        "minimum",
    )
    validate_payload(
        "delivery.canceled", {"scheduled_event_id": UUID, "canceled_at": TS}
    )


def test_payload_security_variants():
    validate_payload(
        "security.key.prepare",
        {
            "new_agreement_key": ZB58,
            "prior_fingerprint": B64,
            "deadline": TS,
        },
    )
    expect_payload_error(
        "security.key.prepare",
        {"new_agreement_key": ZB58, "prior_fingerprint": B64},
        "deadline",
        "required",
    )
    validate_payload(
        "security.key.ack", {"prepare_event_id": UUID, "epoch": 2}
    )
    validate_payload("security.key.confirm", {"epoch": 2})
    validate_payload("security.key.commit", {"epoch": 2})


def test_payload_relationship_and_migration_variants():
    validate_payload("relationship.ready", {"relationship_id": UUID2})
    validate_payload(
        "migration.ready", {"migration_id": UUID, "relationship_id": UUID2}
    )
    validate_payload(
        "migration.commit", {"migration_id": UUID, "relationship_id": UUID2}
    )
    expect_payload_error(
        "migration.commit", {"migration_id": UUID}, "relationship_id", "required"
    )


def test_payload_unknown_event_type():
    with pytest.raises(ValidationError) as exc:
        validate_payload("message.deleted", {})
    assert exc.value.field_path == "event_type"
    assert exc.value.code == "unknown_event_type"


def test_payload_top_level_oneof_rejects_garbage():
    with pytest.raises(ValidationError):
        validate("payloads/message", {"nonsense": True})


# state


def valid_state(**over):
    st = {
        "state_version": 1,
        "sender_sequences": [
            {"relationship_id": UUID2, "sender": DID, "last_seq": 42}
        ],
        "replay_nonces": [{"nonce": B64, "expires_at": TS}],
        "watcher_cursors": [
            {"relationship_id": UUID2, "last_successful_head": "abc123"}
        ],
        "retry_queue": [
            {"id": UUID, "kind": "consume", "not_before": TS}
        ],
        "migration": {"status": "dry_run", "started_at": TS},
    }
    st.update(over)
    return st


def test_state_valid():
    validate("state", valid_state())
    st = valid_state()
    del st["migration"]
    validate("state", st)


def test_state_rejects_bad_migration_status():
    st = valid_state()
    st["migration"]["status"] = "halfway"
    expect_error("state", st, "migration.status", "enum")


# envelope size


def test_envelope_size_boundary():
    assert MAX_ENVELOPE_BYTES == 262144
    check_envelope_size(b"x" * 262144)
    check_envelope_size(b"")
    with pytest.raises(ValidationError) as exc:
        check_envelope_size(b"x" * 262145)
    assert exc.value.field_path == ""
    assert exc.value.code == "envelope_too_large"


def test_envelope_size_requires_bytes():
    with pytest.raises(TypeError):
        check_envelope_size("x" * 10)


# error hygiene


def test_all_schema_files_are_valid_draft_2020_12():
    import json as std_json

    import jsonschema
    from pathlib import Path

    schemas_dir = Path(__file__).parent.parent.parent / "schemas"
    files = sorted(schemas_dir.rglob("*.schema.json"))
    assert len(files) == 16, [f.name for f in files]
    for path in files:
        schema = std_json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)


def test_pipeline_size_parse_schema_in_order():
    import json as std_json

    from muse_agent_social.canonical import restricted_jcs, strict_parse

    raw = restricted_jcs(valid_envelope())
    check_envelope_size(raw)
    parsed = strict_parse(raw)
    validate("event-envelope", parsed)
    # Canonical bytes are stable: parse and re-encode is a fixed point.
    assert restricted_jcs(parsed) == raw
    # Tampering with bytes fails closed at parse or schema time.
    tampered = std_json.loads(raw.decode("utf-8"))
    tampered["protected"]["event_type"] = "message.deleted"
    with pytest.raises(ValidationError):
        validate("event-envelope", tampered)


def test_canonicalizer_matches_json_dumps_on_safe_subset():
    import json as std_json

    from muse_agent_social.canonical import restricted_jcs

    safe_inputs = [
        {"b": 2, "a": [3, 1, {"y": True, "x": None}]},
        {"nested": {"deep": {"z": -1, "a": 0}}},
        ["a", "b", 1, -9007199254740991, True, None],
        {"s": "plain ascii ~!@#$%^&*()"},
        {"esc": "tab\there"},
    ]
    for value in safe_inputs:
        expected = std_json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        assert restricted_jcs(value) == expected


def test_unknown_schema_name():
    with pytest.raises(ValidationError) as exc:
        validate("nope", {})
    assert exc.value.code == "unknown_schema"


def test_validation_errors_never_leak_values():
    secret = "super-secret-ciphertext-value"
    env = valid_envelope()
    env["ciphertext"] = secret + "!!!"  # fails base64url pattern
    try:
        validate("event-envelope", env)
    except ValidationError as exc:
        assert secret not in str(exc)
        assert secret not in exc.field_path
        assert secret not in exc.code
    else:
        pytest.fail("expected ValidationError")
    env = valid_envelope()
    env["mystery"] = secret
    try:
        validate("event-envelope", env)
    except ValidationError as exc:
        assert secret not in str(exc)
    else:
        pytest.fail("expected ValidationError")


def test_deep_copy_safety_of_fixtures():
    env = valid_envelope()
    env2 = copy.deepcopy(env)
    env2["protected"]["sender_seq"] = 43
    assert env["protected"]["sender_seq"] == 42
