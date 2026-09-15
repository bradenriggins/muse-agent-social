"""Gate: the receipt.seen policy gate is live on the send path.

``mas send --type receipt.seen`` must consult the receiver's delivery policy
before emitting: seen receipts default off, and the target event must be
committed locally. The gate is ``policy.delivery.should_send_seen_receipt``;
running the send command is the operator's human-visible assertion that the
event was seen, so the CLI passes ``human_visible_view_opened=True`` and the
remaining branches (policy enabled, event committed) must hold.
"""

import argparse
import uuid
from types import SimpleNamespace

import pytest

from muse_agent_social.cli import CliError, _build_payload
from muse_agent_social.policy import delivery
from muse_agent_social.store.db import utcnow


def _args(**kw):
    args = argparse.Namespace(
        type="receipt.seen",
        target=None,
        seen_at=None,
        _relationship_id=None,
    )
    for key, value in kw.items():
        setattr(args, key, value)
    return args


@pytest.fixture()
def ctx(make_relationship, conn):
    rid = make_relationship(policy='{"seen_receipts_enabled": false}')
    conn.execute(
        "INSERT OR IGNORE INTO conversations(conversation_id) VALUES (?)",
        ("conv-seen-gate",),
    )
    conn.commit()
    return SimpleNamespace(conn=conn), rid


def _commit_event(conn, rid, event_id):
    conn.execute(
        "INSERT INTO events(event_id, relationship_id, conversation_id,"
        " sender, sender_seq, created_at, key_epoch, event_type,"
        " replay_nonce, sealed_envelope)"
        " VALUES (?, ?, 'conv-seen-gate', 'did:key:zPeer', 1,"
        " '2026-09-15T20:00:00Z', 1, 'message.created', ?, ?)",
        (event_id, rid, f"nonce-{event_id}", b"{}"),
    )
    conn.commit()


def test_seen_receipt_denied_when_policy_disabled(ctx):
    """Default policy has seen receipts off: the send path must refuse."""
    context, rid = ctx
    event_id = str(uuid.uuid4())
    _commit_event(context.conn, rid, event_id)
    with pytest.raises(CliError) as exc:
        _build_payload(
            context, _args(target=event_id, _relationship_id=rid)
        )
    assert exc.value.code == "seen_receipt_not_permitted"


def test_seen_receipt_denied_when_target_not_committed(ctx):
    """Policy on, but the target event is not in local storage: refuse."""
    context, rid = ctx
    delivery.set_seen_receipts_enabled(context.conn, rid, True)
    with pytest.raises(CliError) as exc:
        _build_payload(
            context,
            _args(target=str(uuid.uuid4()), _relationship_id=rid),
        )
    assert exc.value.code == "seen_receipt_not_permitted"


def test_seen_receipt_allowed_when_policy_enabled_and_committed(ctx):
    """Policy on and the event is committed: the payload is built."""
    context, rid = ctx
    delivery.set_seen_receipts_enabled(context.conn, rid, True)
    event_id = str(uuid.uuid4())
    _commit_event(context.conn, rid, event_id)
    payload = _build_payload(
        context, _args(target=event_id, _relationship_id=rid)
    )
    assert payload["target_event_id"] == event_id
    assert payload["seen_at"].endswith("Z")


def test_seen_receipt_still_needs_target(ctx):
    """The --target requirement is unchanged by the gate."""
    context, rid = ctx
    with pytest.raises(CliError) as exc:
        _build_payload(context, _args(_relationship_id=rid))
    assert exc.value.code == "bad_args"
