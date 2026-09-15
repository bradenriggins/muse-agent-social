"""Lane A C4: human approval attestation (local vs peer).

A peer's fabricated approval_record_id must never be stored as locally
verified. human_requests carries an attestation column: 'peer' when the
human.responded sender is the relationship's peer, 'local' only when the
response was generated locally and its approval_record_id resolves to a
real row in human_approvals.
"""

from __future__ import annotations

import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from muse_agent_social.model.approvals import create_approval
from muse_agent_social.store import migrations
from muse_agent_social.store import projections
from muse_agent_social.store.db import utcnow

ALICE = "did:key:zAliceLocal000000000000000000000001"
BOB = "did:key:zBobPeer00000000000000000000000002"
RID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CONV = "cccccccc-dddd-4eee-8fff-000000000000"

BASE = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)


def _ts(seconds: int) -> str:
    return (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture()
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.db", isolation_level=None)
    c.row_factory = sqlite3.Row
    migrations.migrate(c)
    c.execute(
        "INSERT INTO relationships(relationship_id, peer_identity_id,"
        " consent_state, policy, key_epoch, created_at)"
        " VALUES (?, ?, 'active', '{}', 1, ?);",
        (RID, BOB, utcnow()),
    )
    c.execute("INSERT INTO conversations(conversation_id) VALUES (?);", (CONV,))
    yield c
    c.close()


def _event(event_id, event_type, payload, sender, at):
    return {
        "event_id": event_id,
        "relationship_id": RID,
        "conversation_id": CONV,
        "thread_id": None,
        "sender": sender,
        "sender_seq": 1,
        "created_at": _ts(at),
        "key_epoch": 1,
        "event_type": event_type,
        "replay_nonce": uuid.uuid4().hex,
        "payload": payload,
        "reply_to": None,
    }


def _open_request(c, at=0):
    req_id = str(uuid.uuid4())
    projections.apply_event(
        c,
        _event(
            req_id,
            "human.requested",
            {
                "prompt": "approve the deploy?",
                "response_shape": "approval",
                "expires_at": _ts(3600),
            },
            ALICE,
            at,
        ),
    )
    return req_id


def test_peer_fabricated_approval_id_is_attested_peer(conn):
    """A malicious peer's human.responded with a made-up approval_record_id
    is stored as the peer's claim (attestation='peer'), never 'local'."""
    req_id = _open_request(conn)
    projections.apply_event(
        conn,
        _event(
            str(uuid.uuid4()),
            "human.responded",
            {
                "request_id": req_id,
                "answer": "yes",
                "approved": True,
                "approval_record_id": "fabricated-by-peer-0001",
            },
            BOB,
            10,
        ),
    )
    req = projections.get_human_request(conn, req_id)
    assert req["state"] == "responded"
    assert req["approved"] == 1
    # The peer's claim is preserved verbatim...
    assert req["approval_record_id"] == "fabricated-by-peer-0001"
    # ...but it is never presented as locally verified.
    assert req["attestation"] == "peer"
    assert req["attestation"] != "local"


def test_local_verified_response_is_attested_local(conn):
    """The honest local path (cmd_human_respond creates the approval record
    first) projects with attestation='local'."""
    req_id = _open_request(conn)
    approval_id = create_approval(
        conn,
        relationship_id=RID,
        subject_type="human_request",
        subject_id=req_id,
        answer="yes",
        approved=True,
        created_at=utcnow(),
        note=None,
    )
    projections.apply_event(
        conn,
        _event(
            str(uuid.uuid4()),
            "human.responded",
            {
                "request_id": req_id,
                "answer": "yes",
                "approved": True,
                "approval_record_id": approval_id,
            },
            ALICE,
            10,
        ),
    )
    req = projections.get_human_request(conn, req_id)
    assert req["state"] == "responded"
    assert req["attestation"] == "local"


def test_local_response_without_approval_record_is_not_local(conn):
    """A locally-sent human.responded whose approval_record_id has no local
    record (should not happen via the honest CLI) is not marked 'local'."""
    req_id = _open_request(conn)
    projections.apply_event(
        conn,
        _event(
            str(uuid.uuid4()),
            "human.responded",
            {
                "request_id": req_id,
                "answer": "yes",
                "approved": True,
                "approval_record_id": "no-such-record",
            },
            ALICE,
            10,
        ),
    )
    req = projections.get_human_request(conn, req_id)
    assert req["attestation"] != "local"


def test_migration3_adds_attestation_and_backfills(tmp_path):
    """Existing v2 databases gain the column through migration 3; rows
    whose approval_record_id resolves locally backfill to 'local',
    everything else defaults to 'peer'."""
    c = sqlite3.connect(tmp_path / "v2.db", isolation_level=None)
    c.row_factory = sqlite3.Row
    # Apply only migrations 1 and 2, like a database from before the fix.
    for version, name, ddl in migrations.MIGRATIONS:
        if version > 2:
            continue
        with c:
            c.executescript(ddl)
            c.execute(f"PRAGMA user_version = {version};")
    assert c.execute("PRAGMA user_version;").fetchone()[0] == 2
    c.execute(
        "INSERT INTO relationships(relationship_id, peer_identity_id,"
        " consent_state, policy, key_epoch, created_at)"
        " VALUES (?, ?, 'active', '{}', 1, ?);",
        (RID, BOB, utcnow()),
    )
    c.execute("INSERT INTO conversations(conversation_id) VALUES (?);", (CONV,))
    # One legit local approval...
    good_id = create_approval(
        c,
        relationship_id=RID,
        subject_type="human_request",
        subject_id="req-good",
        answer="yes",
        approved=True,
        created_at=utcnow(),
        note=None,
    )
    c.execute(
        "INSERT INTO human_requests(request_id, relationship_id,"
        " conversation_id, sender, created_at, prompt, response_shape,"
        " expires_at, state, answer, approved, responded_at,"
        " response_event_id, approval_record_id)"
        " VALUES ('req-good', ?, ?, ?, ?, 'p', 'approval', ?, 'responded',"
        " 'yes', 1, ?, 'ev1', ?);",
        (RID, CONV, ALICE, _ts(0), _ts(3600), _ts(10), good_id),
    )
    # ...and one row carrying a fabricated (unresolvable) record id.
    c.execute(
        "INSERT INTO human_requests(request_id, relationship_id,"
        " conversation_id, sender, created_at, prompt, response_shape,"
        " expires_at, state, answer, approved, responded_at,"
        " response_event_id, approval_record_id)"
        " VALUES ('req-bad', ?, ?, ?, ?, 'p', 'approval', ?, 'responded',"
        " 'yes', 1, ?, 'ev2', 'fabricated');",
        (RID, CONV, BOB, _ts(0), _ts(3600), _ts(10)),
    )
    version = migrations.migrate(c)
    assert version == migrations.SCHEMA_VERSION == 3
    cols = [r["name"] for r in c.execute("PRAGMA table_info(human_requests);")]
    assert "attestation" in cols
    assert (
        c.execute(
            "SELECT attestation FROM human_requests WHERE request_id='req-good';"
        ).fetchone()["attestation"]
        == "local"
    )
    assert (
        c.execute(
            "SELECT attestation FROM human_requests WHERE request_id='req-bad';"
        ).fetchone()["attestation"]
        == "peer"
    )
    c.close()


def test_fresh_schema_includes_attestation(tmp_path):
    c = sqlite3.connect(tmp_path / "fresh.db", isolation_level=None)
    c.row_factory = sqlite3.Row
    migrations.migrate(c)
    cols = [r["name"] for r in c.execute("PRAGMA table_info(human_requests);")]
    assert "attestation" in cols
    c.close()
