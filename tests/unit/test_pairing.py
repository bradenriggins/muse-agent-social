"""Unit tests for the pairing ceremony (checkpoint 8).

Covers: invite replay, stale invites, tampered cards, unsupported
capabilities, clock skew, phrase-mismatch burn, private key material in
acceptances, deploy-key reuse, the full two-sided ceremony, and GitHub relay
provisioning (HTTP layer stubbed; no network).
"""

import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.expanduser("~/workspace/mas-release/src"))
sys.path.insert(0, os.path.expanduser("~/workspace/mas-build/track-pairing/src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from muse_agent_social._keyfiles import store_private_key
from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
    parse_agreement_key,
)
from muse_agent_social.crypto.rotation import agreement_fingerprint
from muse_agent_social.model.cards import (
    card_fingerprint,
    create_card,
    verify_card,
)
from muse_agent_social.model.invites import (
    PairingError,
    burn_invite,
    commit_pairing,
    create_acceptance,
    create_invite,
    generate_deploy_keypair,
    generate_relationship_keypair,
    get_relationship,
    ingest_commit,
    invite_uri,
    mark_active,
    pairing_phrase,
    parse_invite_uri,
    read_invite_file,
    record_verification,
    validate_invite,
    write_invite_file,
)
from muse_agent_social.store.migrations import migrate
from muse_agent_social.transports.provisioning import (
    PrivateKeyMaterialFound,
    ProvisioningError,
    assert_no_peer_private_key,
    deploy_key_title,
    register_peer_deploy_key,
)
from muse_agent_social.validation import ValidationError

from muse_agent_social.crypto.identity import derive_identity_hierarchy, generate_master_seed

CAPS = ["events/0.2", "threads/1"]
T0 = datetime(2026, 9, 15, 20, 0, 0, tzinfo=timezone.utc)


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    migrate(conn)
    return conn


def make_agent(display_name):
    ident = derive_identity_hierarchy(generate_master_seed())
    card = create_card(
        ident.ed25519_private,
        display_name,
        "Test Principal",
        ident.agreement_key_multibase,
        CAPS,
        T0,
        T0 + timedelta(days=30),
    )
    assert verify_card(card, T0).ok
    return ident, card


@pytest.fixture
def inviter():
    return make_agent("Inviter")


@pytest.fixture
def acceptor():
    return make_agent("Acceptor")


def make_invite(conn, inviter, now=T0, caps=CAPS, policy=None):
    ident, card = inviter
    return create_invite(
        conn,
        card,
        ident.ed25519_private,
        X25519PrivateKey.generate(),
        caps,
        policy if policy is not None else {"accepted_receipts": True},
        now=now,
    )


def accept_invite(conn, invite, acceptor, now, keys_dir, deploy_dir):
    ident, card = acceptor
    rel_priv, rel_pub = generate_relationship_keypair()
    rel_key_path = os.path.join(keys_dir, "acceptor-rel.key")
    store_private_key(rel_key_path, rel_priv.private_bytes_raw())
    deploy_pub = generate_deploy_keypair(os.path.join(deploy_dir, "deploy_key"))
    acceptance = create_acceptance(
        conn, invite, card, ident.ed25519_private, rel_pub, deploy_pub, now=now
    )
    return acceptance, rel_pub, rel_key_path, deploy_pub


def full_ceremony(tmp_path):
    """Run the whole happy-path ceremony; return the interesting objects."""
    conn_i, conn_a = make_db(), make_db()
    inviter, acceptor = make_agent("Inviter"), make_agent("Acceptor")
    keys_i = str(tmp_path / "keys_i")
    keys_a = str(tmp_path / "keys_a")
    deploy = str(tmp_path / "deploy")
    os.makedirs(keys_a)
    os.makedirs(deploy)

    invite = make_invite(conn_i, inviter)
    uri = invite_uri(invite)
    parsed = parse_invite_uri(uri)
    assert parsed == invite

    acceptance, rel_pub_a, rel_key_a, deploy_pub = accept_invite(
        conn_a, parsed, acceptor, T0 + timedelta(seconds=30), keys_a, deploy
    )

    phrase_i = pairing_phrase(invite["inviter_card"], acceptance["acceptor_card"])
    phrase_a = pairing_phrase(acceptance["acceptor_card"], invite["inviter_card"])
    assert phrase_i == phrase_a and len(phrase_i) == 8

    validate_invite(conn_i, invite, now=T0 + timedelta(seconds=60))
    record_verification(
        conn_i,
        invite["invite_id"],
        (
            card_fingerprint(invite["inviter_card"]),
            card_fingerprint(acceptance["acceptor_card"]),
        ),
        True,
    )

    commit = commit_pairing(
        conn_i,
        acceptance,
        inviter[0].ed25519_private,
        "https://github.com/example-org/relay-xyz",
        {"inviter_send_slot": "slot-a", "inviter_receive_slot": "slot-b"},
        CAPS,
        now=T0 + timedelta(seconds=90),
        keys_dir=keys_i,
    )
    relationship_id = ingest_commit(
        conn_a,
        commit,
        invite,
        rel_pub_a,
        rel_key_a,
        acceptor[1],
        now=T0 + timedelta(seconds=120),
    )
    assert relationship_id == commit["relationship_id"]
    mark_active(conn_i, relationship_id)
    mark_active(conn_a, relationship_id)
    return {
        "conn_i": conn_i,
        "conn_a": conn_a,
        "inviter": inviter,
        "acceptor": acceptor,
        "invite": invite,
        "acceptance": acceptance,
        "commit": commit,
        "relationship_id": relationship_id,
        "deploy_pub": deploy_pub,
        "keys_i": keys_i,
    }


# ---------------------------------------------------------------------------
# Invite lifecycle
# ---------------------------------------------------------------------------

def test_invite_create_validate_roundtrip(inviter):
    conn = make_db()
    invite = make_invite(conn, inviter)
    assert invite["invite_version"] == 1
    assert invite["expires_at"] > invite["issued_at"]
    uri = invite_uri(invite)
    assert uri.startswith("muse-agent-social://pair/v1#")
    assert parse_invite_uri(uri) == invite
    out = validate_invite(conn, invite, now=T0 + timedelta(minutes=1))
    assert out["invite_id"] == invite["invite_id"]
    row = conn.execute(
        "SELECT state FROM invites WHERE invite_id=?", (invite["invite_id"],)
    ).fetchone()
    assert row["state"] == "accepted"


def test_invite_replay_second_use_rejected(inviter):
    conn = make_db()
    invite = make_invite(conn, inviter)
    validate_invite(conn, invite, now=T0 + timedelta(minutes=1))
    with pytest.raises(PairingError) as excinfo:
        validate_invite(conn, invite, now=T0 + timedelta(minutes=2))
    assert excinfo.value.code == "already_used"


def test_stale_invite_rejected(inviter):
    conn = make_db()
    invite = make_invite(conn, inviter, now=T0)
    with pytest.raises(PairingError) as excinfo:
        validate_invite(conn, invite, now=T0 + timedelta(minutes=16))
    assert excinfo.value.code == "expired"
    row = conn.execute(
        "SELECT state FROM invites WHERE invite_id=?", (invite["invite_id"],)
    ).fetchone()
    assert row["state"] == "expired"


def test_invite_lifetime_capped(inviter):
    conn = make_db()
    invite = make_invite(conn, inviter, now=T0)
    # Simulate an invite from a non-conforming implementation: a longer
    # lifetime but a valid signature, so the lifetime cap is what fires.
    from muse_agent_social.model.invites import _sign  # internal, test-only
    invite["expires_at"] = "2026-09-15T20:30:00Z"  # 30 minutes
    signature = invite.pop("signature")
    invite["signature"] = _sign(inviter[0].ed25519_private, invite)
    assert invite["signature"] != signature
    with pytest.raises(PairingError) as excinfo:
        validate_invite(conn, invite, now=T0 + timedelta(minutes=1))
    assert excinfo.value.code == "lifetime_exceeded"


def test_tampered_inviter_card_rejected(inviter):
    conn = make_db()
    invite = make_invite(conn, inviter)
    invite["inviter_card"]["display_name"] = "Mallory"
    with pytest.raises(PairingError) as excinfo:
        validate_invite(conn, invite, now=T0 + timedelta(minutes=1))
    assert excinfo.value.code == "card_invalid"
    # The card itself no longer verifies either.
    assert not verify_card(invite["inviter_card"], T0).ok


def test_tampered_invite_signature_rejected(inviter):
    conn = make_db()
    invite = make_invite(conn, inviter)
    invite["signature"] = "A" * 86
    with pytest.raises(PairingError) as excinfo:
        validate_invite(conn, invite, now=T0 + timedelta(minutes=1))
    assert excinfo.value.code == "bad_signature"


def test_clock_skew_rejected(inviter):
    conn = make_db()
    # Invite issued 6 minutes in the future relative to the validator's clock.
    invite = make_invite(conn, inviter, now=T0 + timedelta(minutes=6))
    with pytest.raises(PairingError) as excinfo:
        validate_invite(conn, invite, now=T0)
    assert excinfo.value.code == "clock_skew"


def test_unknown_invite_rejected(inviter):
    conn = make_db()
    invite = make_invite(make_db(), inviter)  # issued on a different store
    with pytest.raises(PairingError) as excinfo:
        validate_invite(conn, invite, now=T0 + timedelta(minutes=1))
    assert excinfo.value.code == "unknown_invite"


def test_invite_file_roundtrip(inviter, tmp_path):
    conn = make_db()
    invite = make_invite(conn, inviter)
    path = str(tmp_path / "invite.json")
    write_invite_file(invite, path)
    assert read_invite_file(path) == invite


def test_invite_uri_rejects_garbage():
    with pytest.raises(PairingError) as excinfo:
        parse_invite_uri("https://example.com/not-an-invite")
    assert excinfo.value.code == "bad_invite_uri"
    with pytest.raises(PairingError):
        parse_invite_uri("muse-agent-social://pair/v1#%%%not-base64%%%")


# ---------------------------------------------------------------------------
# Acceptance
# ---------------------------------------------------------------------------

def test_acceptance_rejects_private_key_material(inviter, acceptor, tmp_path):
    conn_i, conn_a = make_db(), make_db()
    invite = make_invite(conn_i, inviter)
    ident, card = acceptor
    rel_priv, rel_pub = generate_relationship_keypair()
    fake_private = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----"
    )
    with pytest.raises(PairingError) as excinfo:
        create_acceptance(
            conn_a, invite, card, ident.ed25519_private, rel_pub, fake_private,
            now=T0 + timedelta(seconds=10),
        )
    assert excinfo.value.code == "private_key_material"
    with pytest.raises(PairingError) as excinfo:
        create_acceptance(
            conn_a, invite, card, ident.ed25519_private,
            "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "A" * 40,
            now=T0 + timedelta(seconds=10),
        )
    assert excinfo.value.code == "private_key_material"


def test_acceptance_rejects_malformed_deploy_key(inviter, acceptor):
    conn_i, conn_a = make_db(), make_db()
    invite = make_invite(conn_i, inviter)
    ident, card = acceptor
    _, rel_pub = generate_relationship_keypair()
    with pytest.raises(PairingError) as excinfo:
        create_acceptance(
            conn_a, invite, card, ident.ed25519_private, rel_pub,
            "not-a-key", now=T0 + timedelta(seconds=10),
        )
    assert excinfo.value.code == "bad_deploy_key"


def test_generate_deploy_keypair_stores_private_0600(tmp_path):
    path = str(tmp_path / "deploy_key")
    pub = generate_deploy_keypair(path)
    assert pub.startswith("ssh-ed25519 ")
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    with open(path, "rb") as fh:
        assert b"PRIVATE KEY" in fh.read()
    with pytest.raises(FileExistsError):
        generate_deploy_keypair(path)  # refuses to overwrite


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def test_phrase_mismatch_aborts_and_burns_invite(inviter, acceptor, tmp_path):
    conn_i, conn_a = make_db(), make_db()
    invite = make_invite(conn_i, inviter)
    keys_a, deploy = str(tmp_path / "ka"), str(tmp_path / "d")
    os.makedirs(keys_a)
    os.makedirs(deploy)
    acceptance, _, _, _ = accept_invite(
        conn_a, invite, acceptor, T0 + timedelta(seconds=30), keys_a, deploy
    )
    validate_invite(conn_i, invite, now=T0 + timedelta(minutes=1))
    fps = (
        card_fingerprint(invite["inviter_card"]),
        card_fingerprint(acceptor[1]),
    )
    with pytest.raises(PairingError) as excinfo:
        record_verification(conn_i, invite["invite_id"], fps, False)
    assert excinfo.value.code == "phrase_mismatch"
    row = conn_i.execute(
        "SELECT state FROM invites WHERE invite_id=?", (invite["invite_id"],)
    ).fetchone()
    assert row["state"] == "canceled"
    # A burned invite can never be committed, even with a valid acceptance.
    with pytest.raises(PairingError) as excinfo:
        commit_pairing(
            conn_i, acceptance, inviter[0].ed25519_private,
            "https://github.com/e/r",
            {"inviter_send_slot": "s1", "inviter_receive_slot": "r1"},
            [], now=T0,
            keys_dir=str(tmp_path / "ki"),
        )
    assert excinfo.value.code == "invite_not_accepted"


def test_altered_card_burns_invite_on_verify(inviter, acceptor):
    conn_i = make_db()
    invite = make_invite(conn_i, inviter)
    validate_invite(conn_i, invite, now=T0 + timedelta(minutes=1))
    wrong_fp = "0" * 64
    with pytest.raises(PairingError) as excinfo:
        record_verification(
            conn_i, invite["invite_id"],
            (wrong_fp, card_fingerprint(acceptor[1])), True,
        )
    assert excinfo.value.code == "altered_card"
    row = conn_i.execute(
        "SELECT state FROM invites WHERE invite_id=?", (invite["invite_id"],)
    ).fetchone()
    assert row["state"] == "canceled"


def test_pairing_phrase_is_order_independent_and_8_words(inviter, acceptor):
    phrase = pairing_phrase(inviter[1], acceptor[1])
    assert pairing_phrase(acceptor[1], inviter[1]) == phrase
    assert len(phrase) == 8
    assert all(isinstance(w, str) and w for w in phrase)


# ---------------------------------------------------------------------------
# Commit
# ---------------------------------------------------------------------------

def test_commit_requires_human_verification(inviter, acceptor, tmp_path):
    conn_i, conn_a = make_db(), make_db()
    invite = make_invite(conn_i, inviter)
    keys_a, deploy = str(tmp_path / "ka"), str(tmp_path / "d")
    os.makedirs(keys_a)
    os.makedirs(deploy)
    acceptance, _, _, _ = accept_invite(
        conn_a, invite, acceptor, T0 + timedelta(seconds=30), keys_a, deploy
    )
    validate_invite(conn_i, invite, now=T0 + timedelta(seconds=60))
    with pytest.raises(PairingError) as excinfo:
        commit_pairing(
            conn_i, acceptance, inviter[0].ed25519_private,
            "https://github.com/example-org/relay-1",
            {"inviter_send_slot": "s1", "inviter_receive_slot": "r1"},
            CAPS, now=T0 + timedelta(seconds=90), keys_dir=str(tmp_path / "ki"),
        )
    assert excinfo.value.code == "unverified"


def test_commit_rejects_unsupported_capability(inviter, acceptor, tmp_path):
    conn_i, conn_a = make_db(), make_db()
    invite = make_invite(conn_i, inviter)
    keys_a, deploy = str(tmp_path / "ka"), str(tmp_path / "d")
    os.makedirs(keys_a)
    os.makedirs(deploy)
    acceptance, _, _, _ = accept_invite(
        conn_a, invite, acceptor, T0 + timedelta(seconds=30), keys_a, deploy
    )
    validate_invite(conn_i, invite, now=T0 + timedelta(seconds=60))
    record_verification(
        conn_i, invite["invite_id"],
        (card_fingerprint(invite["inviter_card"]),
         card_fingerprint(acceptance["acceptor_card"])), True,
    )
    with pytest.raises(PairingError) as excinfo:
        commit_pairing(
            conn_i, acceptance, inviter[0].ed25519_private,
            "https://github.com/example-org/relay-1",
            {"inviter_send_slot": "s1", "inviter_receive_slot": "r1"},
            ["events/0.2", "threads/1", "mind-reading/9"],
            now=T0 + timedelta(seconds=90), keys_dir=str(tmp_path / "ki"),
        )
    assert excinfo.value.code == "unsupported_capability"
    row = conn_i.execute(
        "SELECT state FROM invites WHERE invite_id=?", (invite["invite_id"],)
    ).fetchone()
    assert row["state"] == "canceled"


def test_commit_rejects_unnegotiated_requested_capability(inviter, acceptor, tmp_path):
    conn_i, conn_a = make_db(), make_db()
    invite = make_invite(conn_i, inviter, caps=["events/0.2", "threads/1"])
    keys_a, deploy = str(tmp_path / "ka"), str(tmp_path / "d")
    os.makedirs(keys_a)
    os.makedirs(deploy)
    acceptance, _, _, _ = accept_invite(
        conn_a, invite, acceptor, T0 + timedelta(seconds=30), keys_a, deploy
    )
    validate_invite(conn_i, invite, now=T0 + timedelta(seconds=60))
    record_verification(
        conn_i, invite["invite_id"],
        (card_fingerprint(invite["inviter_card"]),
         card_fingerprint(acceptance["acceptor_card"])), True,
    )
    with pytest.raises(PairingError) as excinfo:
        commit_pairing(
            conn_i, acceptance, inviter[0].ed25519_private,
            "https://github.com/example-org/relay-1",
            {"inviter_send_slot": "s1", "inviter_receive_slot": "r1"},
            ["events/0.2"],  # threads/1 was requested but not negotiated
            now=T0 + timedelta(seconds=90), keys_dir=str(tmp_path / "ki"),
        )
    assert excinfo.value.code == "unsupported_capability"


def test_commit_rejects_invite_hash_mismatch(inviter, acceptor, tmp_path):
    conn_i, conn_a = make_db(), make_db()
    invite = make_invite(conn_i, inviter)
    keys_a, deploy = str(tmp_path / "ka"), str(tmp_path / "d")
    os.makedirs(keys_a)
    os.makedirs(deploy)
    acceptance, _, _, _ = accept_invite(
        conn_a, invite, acceptor, T0 + timedelta(seconds=30), keys_a, deploy
    )
    acceptance["invite_hash"] = "A" * 43
    validate_invite(conn_i, invite, now=T0 + timedelta(seconds=60))
    record_verification(
        conn_i, invite["invite_id"],
        (card_fingerprint(invite["inviter_card"]),
         card_fingerprint(acceptance["acceptor_card"])), True,
    )
    # Re-sign after tampering so the failure is the hash check, not the signature.
    tampered = dict(acceptance)
    from muse_agent_social.model.invites import _sign  # internal, test-only
    del tampered["signature"]
    tampered["signature"] = _sign(acceptor[0].ed25519_private, tampered)
    with pytest.raises(PairingError) as excinfo:
        commit_pairing(
            conn_i, tampered, inviter[0].ed25519_private,
            "https://github.com/example-org/relay-1",
            {"inviter_send_slot": "s1", "inviter_receive_slot": "r1"},
            CAPS, now=T0 + timedelta(seconds=90), keys_dir=str(tmp_path / "ki"),
        )
    assert excinfo.value.code == "invite_hash_mismatch"


def test_reused_deploy_key_rejected(inviter, acceptor, tmp_path):
    first = full_ceremony(tmp_path / "first")
    conn_i = first["conn_i"]
    deploy_pub = first["deploy_pub"]

    # Second pairing attempt reusing the same deploy public key.
    conn_i2, conn_a2 = make_db(), make_db()
    # Share the deploy-key registry view: same inviter store as the first run.
    invite = make_invite(conn_i, inviter)
    keys_a, deploy = str(tmp_path / "ka2"), str(tmp_path / "d2")
    os.makedirs(keys_a)
    os.makedirs(deploy)
    ident_a, card_a = acceptor
    rel_priv, rel_pub = generate_relationship_keypair()
    acceptance = create_acceptance(
        conn_a2, invite, card_a, ident_a.ed25519_private, rel_pub, deploy_pub,
        now=T0 + timedelta(seconds=30),
    )
    validate_invite(conn_i, invite, now=T0 + timedelta(seconds=60))
    record_verification(
        conn_i, invite["invite_id"],
        (card_fingerprint(invite["inviter_card"]),
         card_fingerprint(acceptance["acceptor_card"])), True,
    )
    with pytest.raises(PairingError) as excinfo:
        commit_pairing(
            conn_i, acceptance, inviter[0].ed25519_private,
            "https://github.com/example-org/relay-2",
            {"inviter_send_slot": "s2", "inviter_receive_slot": "r2"},
            CAPS, now=T0 + timedelta(seconds=90),
            keys_dir=str(tmp_path / "ki2"),
        )
    assert excinfo.value.code == "deploy_key_reused"


def test_full_ceremony_happy_path(tmp_path):
    ctx = full_ceremony(tmp_path)
    conn_i, conn_a = ctx["conn_i"], ctx["conn_a"]
    commit, invite = ctx["commit"], ctx["invite"]
    rid = ctx["relationship_id"]

    # Commit is signed by the inviter over restricted JCS.
    assert commit["commit_version"] == 1
    assert commit["invite_id"] == invite["invite_id"]
    assert commit["repository_url"] == "https://github.com/example-org/relay-xyz"
    assert commit["initial_key_epochs"][0]["epoch"] == 1
    parse_agreement_key(commit["initial_key_epochs"][0]["agreement_public_key"])

    for conn, peer_card in ((conn_i, ctx["acceptor"][1]), (conn_a, ctx["inviter"][1])):
        rel = get_relationship(conn, rid)
        assert rel["consent_state"] == "active"
        assert rel["peer_identity_id"] == peer_card["identity_id"]
        assert rel["key_epoch"] == 1
        epoch_row = conn.execute(
            "SELECT * FROM key_epochs WHERE relationship_id=? AND epoch=1", (rid,)
        ).fetchone()
        assert epoch_row["state"] == "active"
        assert os.path.isfile(epoch_row["private_key_ref"])
        assert oct(os.stat(epoch_row["private_key_ref"]).st_mode & 0o777) == "0o600"

    # Inviter side knows the acceptor's epoch-1 key as peer_agreement_key.
    rel_i = get_relationship(conn_i, rid)
    assert rel_i["peer_agreement_key"] == ctx["acceptance"]["relationship_agreement_key"]
    # Acceptor side knows the inviter's epoch-1 key from the commit.
    rel_a = get_relationship(conn_a, rid)
    assert (
        rel_a["peer_agreement_key"]
        == commit["initial_key_epochs"][0]["agreement_public_key"]
    )
    # Deploy key registered exactly once.
    reg = conn_i.execute(
        "SELECT * FROM deploy_key_registry WHERE deploy_public_key=?",
        (ctx["deploy_pub"],),
    ).fetchone()
    assert reg["relationship_id"] == rid

    # mark_active is one-way: pending -> active only.
    with pytest.raises(PairingError) as excinfo:
        mark_active(conn_i, rid)
    assert excinfo.value.code == "not_pending"


def test_mark_active_unknown_relationship():
    conn = make_db()
    with pytest.raises(PairingError) as excinfo:
        mark_active(conn, str(uuid.uuid4()))
    assert excinfo.value.code == "unknown_relationship"


def test_burn_invite_terminal_states(inviter):
    conn = make_db()
    invite = make_invite(conn, inviter)
    assert burn_invite(conn, invite["invite_id"]) == "issued"
    assert burn_invite(conn, invite["invite_id"]) == "canceled"  # idempotent report


# ---------------------------------------------------------------------------
# Provisioning (HTTP stubbed)
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _stub_urlopen(capture, status=201, payload=None):
    def _fake(request, timeout=None):
        capture["url"] = request.full_url
        capture["headers"] = dict(request.header_items())
        capture["body"] = json.loads(request.data.decode("utf-8"))
        return _FakeResponse(status, payload or {"id": 42, "key": "k"})
    return _fake


def _good_deploy_pub():
    return "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA" + "A" * 38


def test_register_peer_deploy_key_success():
    capture = {}
    with patch(
        "urllib.request.urlopen", _stub_urlopen(capture, 201, {"id": 7, "title": "t"})
    ):
        resp = register_peer_deploy_key(
            "example-org/relay-xyz",
            _good_deploy_pub(),
            deploy_key_title(str(uuid.uuid4())),
            lambda: "test-token",
        )
    assert resp["id"] == 7
    assert capture["url"] == "https://api.github.com/repos/example-org/relay-xyz/keys"
    assert capture["headers"]["Authorization"] == "Bearer test-token"
    assert "test-token" not in json.dumps(capture["body"])
    assert capture["body"]["read_only"] is False
    assert capture["body"]["title"].startswith("mas-pair-")


def test_register_peer_deploy_key_rejects_private_key():
    capture = {}
    with patch("urllib.request.urlopen", _stub_urlopen(capture)):
        with pytest.raises(ProvisioningError) as excinfo:
            register_peer_deploy_key(
                "example-org/relay-xyz",
                "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----",
                deploy_key_title(str(uuid.uuid4())),
                lambda: "test-token",
            )
    assert excinfo.value.code == "private_key_material"
    assert "url" not in capture  # no network attempt


def test_register_peer_deploy_key_rejects_personal_title():
    with pytest.raises(ProvisioningError) as excinfo:
        register_peer_deploy_key(
            "example-org/relay-xyz", _good_deploy_pub(), "Braden's relay key",
            lambda: "test-token",
        )
    assert excinfo.value.code == "bad_title"


def test_register_peer_deploy_key_rejects_bad_repo():
    with pytest.raises(ProvisioningError) as excinfo:
        register_peer_deploy_key(
            "not a repo", _good_deploy_pub(), deploy_key_title(str(uuid.uuid4())),
            lambda: "test-token",
        )
    assert excinfo.value.code == "bad_repo"


def test_register_peer_deploy_key_http_errors():
    capture = {}
    with patch("urllib.request.urlopen", _stub_urlopen(capture, 422, {})):
        with pytest.raises(ProvisioningError) as excinfo:
            register_peer_deploy_key(
                "example-org/relay-xyz", _good_deploy_pub(),
                deploy_key_title(str(uuid.uuid4())), lambda: "test-token",
            )
    assert excinfo.value.code == "key_rejected"


def test_register_peer_deploy_key_needs_token():
    with pytest.raises(ProvisioningError) as excinfo:
        register_peer_deploy_key(
            "example-org/relay-xyz", _good_deploy_pub(),
            deploy_key_title(str(uuid.uuid4())), lambda: "",
        )
    assert excinfo.value.code == "no_token"


def test_assert_no_peer_private_key_clean(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "acceptance.json").write_text('{"a": 1}')
    (bundle / "notes.txt").write_text("nothing secret here")
    assert_no_peer_private_key(str(bundle))  # no raise


def test_assert_no_peer_private_key_dirty(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "peer_deploy_key").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    with pytest.raises(PrivateKeyMaterialFound) as excinfo:
        assert_no_peer_private_key(str(bundle))
    assert "peer_deploy_key" in excinfo.value.path

    bundle2 = tmp_path / "bundle2"
    bundle2.mkdir()
    (bundle2 / "id_ed25519").write_text("whatever")
    with pytest.raises(PrivateKeyMaterialFound):
        assert_no_peer_private_key(str(bundle2))


def test_invite_file_size_cap_rejects_oversize(tmp_path):
    from muse_agent_social.model.invites import MAX_INVITE_FILE_BYTES

    path = tmp_path / "big.json"
    path.write_bytes(b"x" * (MAX_INVITE_FILE_BYTES + 1))
    with pytest.raises(PairingError) as excinfo:
        read_invite_file(str(path))
    assert excinfo.value.code == "invite_too_large"


def test_invite_file_at_cap_boundary(tmp_path):
    from muse_agent_social.model.invites import MAX_INVITE_FILE_BYTES

    path = tmp_path / "big.json"
    # Exactly at the cap: passes the size gate (then fails as bad JSON,
    # which proves the size check did not fire first).
    path.write_bytes(b" " * MAX_INVITE_FILE_BYTES)
    with pytest.raises(PairingError) as excinfo:
        read_invite_file(str(path))
    assert excinfo.value.code != "invite_too_large"


def test_commit_binds_exact_human_verified_cards(inviter, tmp_path):
    """The commit must bind to the EXACT cards the human verified: an
    acceptance from a different (validly signed) identity must not pair
    the human's approval to an identity they never verified."""
    acceptor = make_agent("Acceptor")
    intruder = make_agent("Intruder")
    conn_i, conn_a = make_db(), make_db()
    invite = make_invite(conn_i, inviter)
    keys_a, deploy = str(tmp_path / "ka"), str(tmp_path / "d")
    os.makedirs(keys_a)
    os.makedirs(deploy)
    # The intruder answers the same invite with their own valid card.
    intruder_acceptance, _, _, _ = accept_invite(
        conn_a, invite, intruder, T0 + timedelta(seconds=30), keys_a, deploy
    )
    validate_invite(conn_i, invite, now=T0 + timedelta(seconds=60))
    # The human verified the REAL acceptor's card, not the intruder's.
    record_verification(
        conn_i,
        invite["invite_id"],
        (
            card_fingerprint(invite["inviter_card"]),
            card_fingerprint(acceptor[1]),
        ),
        True,
    )
    with pytest.raises(PairingError) as excinfo:
        commit_pairing(
            conn_i,
            intruder_acceptance,
            inviter[0].ed25519_private,
            "https://github.com/example-org/relay-1",
            {"inviter_send_slot": "s1", "inviter_receive_slot": "r1"},
            CAPS,
            now=T0 + timedelta(seconds=90),
            keys_dir=str(tmp_path / "ki"),
        )
    assert excinfo.value.code == "acceptor_card_changed"
    # A swapped card is a hostile act: the invite is burned, not retried.
    row = conn_i.execute(
        "SELECT state FROM invites WHERE invite_id=?", (invite["invite_id"],)
    ).fetchone()
    assert row["state"] == "canceled"


def test_commit_rejects_swapped_inviter_card(inviter, acceptor, tmp_path):
    """The inviter side is bound too: recording a verification whose
    inviter fingerprint does not match the issued invite burns the
    invite at verification time, so no commit can ever bind to it."""
    conn_i, conn_a = make_db(), make_db()
    invite = make_invite(conn_i, inviter)
    keys_a, deploy = str(tmp_path / "ka"), str(tmp_path / "d")
    os.makedirs(keys_a)
    os.makedirs(deploy)
    acceptance, _, _, _ = accept_invite(
        conn_a, invite, acceptor, T0 + timedelta(seconds=30), keys_a, deploy
    )
    validate_invite(conn_i, invite, now=T0 + timedelta(seconds=60))
    # The human-approved inviter fingerprint does not match the invite's
    # stored inviter card: the ceremony is hostile, burn immediately.
    with pytest.raises(PairingError) as excinfo:
        record_verification(
            conn_i,
            invite["invite_id"],
            ("0" * 64, card_fingerprint(acceptance["acceptor_card"])),
            True,
        )
    assert excinfo.value.code == "altered_card"
    row = conn_i.execute(
        "SELECT state FROM invites WHERE invite_id=?", (invite["invite_id"],)
    ).fetchone()
    assert row["state"] == "canceled"


def _invite_in_state(conn, invite_id, state):
    conn.execute(
        "UPDATE invites SET state=? WHERE invite_id=?", (state, invite_id)
    )
    conn.commit()


def test_reset_invite_for_retry_restores_accepted_to_issued(inviter):
    """A commit that failed WITHOUT burning (invite still 'accepted')
    returns the invite to 'issued' so the human can retry cleanly."""
    import muse_agent_social.cli as cli_mod

    conn = make_db()
    invite = make_invite(conn, inviter)
    _invite_in_state(conn, invite["invite_id"], "accepted")
    cli_mod._reset_invite_for_retry(conn, invite["invite_id"])
    row = conn.execute(
        "SELECT state FROM invites WHERE invite_id=?", (invite["invite_id"],)
    ).fetchone()
    assert row["state"] == "issued"


def test_reset_invite_for_retry_leaves_terminal_states(inviter):
    """Burned, expired, and committed invites are never touched: those
    are terminal decisions, not retryable errors."""
    import muse_agent_social.cli as cli_mod

    conn = make_db()
    invite = make_invite(conn, inviter)
    for terminal in ("canceled", "expired", "committed"):
        _invite_in_state(conn, invite["invite_id"], terminal)
        cli_mod._reset_invite_for_retry(conn, invite["invite_id"])
        row = conn.execute(
            "SELECT state FROM invites WHERE invite_id=?", (invite["invite_id"],)
        ).fetchone()
        assert row["state"] == terminal


def test_reset_invite_for_retry_unknown_invite_is_noop(inviter):
    import muse_agent_social.cli as cli_mod

    conn = make_db()
    make_invite(conn, inviter)
    # Must not raise on an invite id that was never issued here.
    cli_mod._reset_invite_for_retry(conn, "12345678-1234-4234-8234-123456789abc")
