"""Shared fixtures for track-social unit tests."""

import pytest

from muse_agent_social.store import db
from muse_agent_social.store import migrations


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "state.db"


@pytest.fixture
def conn(db_path):
    connection = db.connect(db_path)
    migrations.migrate(connection)
    yield connection
    connection.close()


@pytest.fixture
def make_relationship(conn):
    counter = {"n": 0}

    def _make(relationship_id=None, consent_state="active", policy="{}"):
        counter["n"] += 1
        rid = relationship_id or f"rel-{counter['n']:04d}"
        conn.execute(
            "INSERT INTO relationships (relationship_id, peer_identity_id,"
            " peer_display_name, peer_agreement_key, consent_state, policy,"
            " key_epoch, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (
                rid,
                "did:key:zTestPeerIdentity",
                "Peer",
                "zTestAgreementKey",
                consent_state,
                policy,
                db.utcnow(),
            ),
        )
        conn.execute(
            "INSERT INTO key_epochs (relationship_id, epoch, public_key,"
            " private_key_ref, state) VALUES (?, 1, ?, ?, 'active')",
            (rid, "zTestRelationshipPublicKey", "ref/test"),
        )
        return rid

    return _make
