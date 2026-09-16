"""Regression: the unified outgoing persistence core.

``persist_outgoing_in_txn`` is the single core behind
``assign_and_persist_outgoing`` (normal sends) and the accepted-receipt
path: sequence assignment, sealing, the event row, the sender_sequence
upsert, the projection queue entry, the scheduler outbox entry, and
conflict classification must behave identically for both.
"""

import uuid

import pytest

from muse_agent_social.model.events import (
    EventStoreError,
    build_protected,
    persist_outgoing_in_txn,
)
from muse_agent_social.store.db import transaction
from support.harness import fresh_db, make_agent, new_conversation

RID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def _protected(sender_id, conv):
    return build_protected(
        relationship_id=RID,
        conversation_id=conv,
        sender_id=sender_id,
        event_type="message.created",
        thread_id=None,
        reply_to=None,
        key_epoch=1,
    )


def _db_with_relationship(tmp_path, alice, bob):
    conn = fresh_db(tmp_path / "state.db")
    conn.execute(
        "INSERT INTO relationships(relationship_id, peer_identity_id, "
        "peer_display_name, peer_agreement_key, consent_state, policy, created_at) "
        "VALUES (?, ?, 'peer', ?, 'active', '{}', '2026-09-16T00:00:00Z')",
        (RID, bob["identity_id"], bob["rel_pub_mb"]),
    )
    conn.execute(
        "INSERT INTO key_epochs(relationship_id, epoch, public_key, "
        "private_key_ref, state) VALUES (?, 1, ?, 'test-ref', 'active')",
        (RID, bob["rel_pub_mb"]),
    )
    conn.commit()
    return conn


def _recipients(peer):
    return [
        {
            "recipient": peer["identity_id"],
            "agreement_key": peer["rel_pub_mb"],
            "relationship_pub": peer["rel_pub_raw"],
        }
    ]


def test_two_sends_assign_sequential_seqs_and_persist_everywhere(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = _db_with_relationship(tmp_path, alice, bob)
    conv = new_conversation(conn)

    with transaction(conn):
        env1 = persist_outgoing_in_txn(
            conn, _protected(alice["identity_id"], conv),
            {"body": "one", "format": "plain"},
            alice["ed_priv"], _recipients(bob),
        )
    with transaction(conn):
        env2 = persist_outgoing_in_txn(
            conn, _protected(alice["identity_id"], conv),
            {"body": "two", "format": "plain"},
            alice["ed_priv"], _recipients(bob),
        )

    seqs = [r[0] for r in conn.execute(
        "SELECT sender_seq FROM events ORDER BY sender_seq")]
    assert seqs == [1, 2]
    assert env1["protected"]["sender_seq"] == 1
    assert env2["protected"]["sender_seq"] == 2
    # Sender sequence tracks the max.
    row = conn.execute(
        "SELECT last_seq FROM sender_sequence WHERE relationship_id=? AND sender=?",
        (RID, alice["identity_id"]),
    ).fetchone()
    assert row["last_seq"] == 2
    # Projection queue and the scheduler outbox both got every event.
    assert conn.execute("SELECT COUNT(*) FROM projection_queue").fetchone()[0] == 2
    assert conn.execute(
        "SELECT COUNT(*) FROM scheduler_queue WHERE state='scheduled'"
    ).fetchone()[0] == 2


def test_duplicate_event_id_conflict_is_stable_and_leaves_no_partial_rows(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = _db_with_relationship(tmp_path, alice, bob)
    conv = new_conversation(conn)

    p1 = _protected(alice["identity_id"], conv)
    p2 = _protected(alice["identity_id"], conv)
    p2["event_id"] = p1["event_id"]  # same event id: storage conflict
    payload = {"body": "x", "format": "plain"}
    with transaction(conn):
        persist_outgoing_in_txn(
            conn, p1, payload, alice["ed_priv"], _recipients(bob))
    with pytest.raises(EventStoreError):
        with transaction(conn):
            persist_outgoing_in_txn(
                conn, p2, payload, alice["ed_priv"], _recipients(bob))
    # The failed second send left exactly one event, one queue entry each.
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM projection_queue").fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM scheduler_queue WHERE state='scheduled'"
    ).fetchone()[0] == 1


def test_sequence_is_per_sender(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    carol = make_agent("Carol", "PrincipalC")
    conn = _db_with_relationship(tmp_path, alice, bob)
    conv = new_conversation(conn)

    with transaction(conn):
        persist_outgoing_in_txn(
            conn, _protected(alice["identity_id"], conv),
            {"body": "a", "format": "plain"}, alice["ed_priv"], _recipients(bob))
    with transaction(conn):
        persist_outgoing_in_txn(
            conn, _protected(carol["identity_id"], conv),
            {"body": "c", "format": "plain"}, carol["ed_priv"], _recipients(bob))

    seqs = conn.execute(
        "SELECT sender, sender_seq FROM events").fetchall()
    by_sender = {r["sender"]: r["sender_seq"] for r in seqs}
    assert by_sender[alice["identity_id"]] == 1
    assert by_sender[carol["identity_id"]] == 1


def test_accepted_receipt_path_uses_shared_core_and_send_gate():
    """_queue_accepted_receipt must persist through persist_outgoing_in_txn
    (not a duplicate persist sequence) and resolve recipients through the
    rotation send gate."""
    import inspect

    import muse_agent_social.cli as cli_mod

    src = inspect.getsource(cli_mod._queue_accepted_receipt)
    assert "persist_outgoing_in_txn" in src
    assert "_recipients_for" in src
    assert "INSERT INTO events" not in src
    assert "INSERT INTO sender_sequence" not in src
    assert "INSERT INTO scheduler_queue" not in src
