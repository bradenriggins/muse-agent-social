"""Randomized invite-lifecycle property tests (seeded stdlib random).

- Randomized create/validate/burn interleavings: ``issued -> accepted``
  on the first validation; the second validation raises ``already_used``;
  ``burn`` moves ``issued``/``accepted`` to terminal ``canceled`` and
  reports the previous state; terminal burns are no-ops reporting
  ``canceled``; burning an unknown id raises ``unknown_invite``.
- Expiry: validation succeeds inside the 15-minute lifetime and raises
  ``expired`` after it, moving the row to ``expired``.
- URI round trip: ``parse_invite_uri(invite_uri(invite))`` reproduces the
  canonical bytes (``restricted_jcs``), and malformed URIs raise
  ``PairingError``.
"""

import random
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from muse_agent_social.model.invites import (
    PairingError,
    burn_invite,
    create_invite,
    invite_uri,
    parse_invite_uri,
    validate_invite,
)
from muse_agent_social.canonical import restricted_jcs
from muse_agent_social.crypto.identity import (
    derive_identity_hierarchy,
    generate_master_seed,
)
from muse_agent_social.model.cards import create_card, verify_card
from muse_agent_social.store import db
from muse_agent_social.store import migrations

T0 = datetime(2026, 9, 15, 20, 0, 0, tzinfo=timezone.utc)
CAPS = ["messages", "threads", "reactions", "receipts"]
POLICY = {"accepted_receipts": True}


@pytest.fixture()
def ctx(tmp_path):
    conn = db.connect(tmp_path / "invites.db")
    migrations.migrate(conn)
    ident = derive_identity_hierarchy(generate_master_seed())
    card = create_card(
        ident.ed25519_private,
        "Inviter",
        "Test Principal",
        ident.agreement_key_multibase,
        CAPS,
        T0,
        T0 + timedelta(days=30),
    )
    assert verify_card(card, T0).ok
    yield conn, ident, card
    conn.close()


def _create(conn, inviter, now):
    ident, card = inviter
    return create_invite(
        conn,
        card,
        ident.ed25519_private,
        X25519PrivateKey.generate(),
        CAPS,
        POLICY,
        now=now,
    )


def _state(conn, invite_id):
    return conn.execute(
        "SELECT state FROM invites WHERE invite_id = ?;", (invite_id,)
    ).fetchone()[0]


@pytest.mark.parametrize("seed", range(8))
def test_randomized_invite_lifecycle(ctx, seed):
    """Random create/validate/burn sequences obey the state machine."""
    conn, ident, card = ctx
    inviter = (ident, card)
    rng = random.Random(5000 + seed)
    now = T0 + timedelta(minutes=1)
    invites = []  # (invite dict, state)

    for step in range(rng.randrange(6, 16)):
        action = rng.randrange(4)
        if action == 0 or not invites:
            invite = _create(conn, inviter, now)
            assert _state(conn, invite["invite_id"]) == "issued"
            invites.append([invite, "issued"])
        else:
            invite, state = rng.choice(invites)
            iid = invite["invite_id"]
            if action == 1:
                # Validate: first succeeds, later ones raise already_used.
                if state == "issued":
                    validate_invite(conn, invite, now)
                    assert _state(conn, iid) == "accepted"
                    for entry in invites:
                        if entry[0]["invite_id"] == iid:
                            entry[1] = "accepted"
                else:
                    with pytest.raises(PairingError) as ei:
                        validate_invite(conn, invite, now)
                    assert ei.value.code in ("already_used", "expired")
            elif action == 2:
                # Burn: issued/accepted -> canceled (previous reported);
                # terminal burn is a no-op reporting the terminal state.
                prev = burn_invite(conn, iid)
                if state in ("issued", "accepted"):
                    assert prev == state
                    assert _state(conn, iid) == "canceled"
                    for entry in invites:
                        if entry[0]["invite_id"] == iid:
                            entry[1] = "canceled"
                else:
                    assert prev == state
            else:
                # URI round trip reproduces the canonical bytes.
                parsed = parse_invite_uri(invite_uri(invite))
                assert restricted_jcs(parsed) == restricted_jcs(invite)

    # Closing sweep: drive every invite to a terminal state, then confirm
    # no further validation is possible.
    for invite, _ in invites:
        iid = invite["invite_id"]
        state = _state(conn, iid)
        if state == "issued":
            assert burn_invite(conn, iid) == "issued"
        assert _state(conn, iid) in ("accepted", "canceled", "expired")
        with pytest.raises(PairingError):
            validate_invite(conn, invite, now)


def test_burn_unknown_invite_raises(ctx):
    conn, _, _ = ctx
    with pytest.raises(PairingError) as ei:
        burn_invite(conn, "12345678-1234-4234-8234-1234567890ab")
    assert ei.value.code == "unknown_invite"


@pytest.mark.parametrize("seed", range(4))
def test_invite_expiry(ctx, seed):
    """Validation inside the 15-minute lifetime succeeds; after it the
    invite raises ``expired`` and the row moves to ``expired``."""
    conn, ident, card = ctx
    inviter = (ident, card)
    rng = random.Random(5100 + seed)

    ok = _create(conn, inviter, T0)
    validate_invite(conn, ok, T0 + timedelta(minutes=14, seconds=59))
    assert _state(conn, ok["invite_id"]) == "accepted"

    late = _create(conn, inviter, T0)
    with pytest.raises(PairingError) as ei:
        validate_invite(conn, late, T0 + timedelta(minutes=15, seconds=1))
    assert ei.value.code == "expired"
    assert _state(conn, late["invite_id"]) == "expired"


def test_malformed_invite_uris_rejected(ctx):
    conn, _, _ = ctx
    with pytest.raises(PairingError):
        parse_invite_uri("https://example.com/not-an-invite")
    with pytest.raises(PairingError):
        parse_invite_uri("muse-agent-social://pair/v1#!!!not-base64!!!")
    with pytest.raises(PairingError):
        parse_invite_uri("muse-agent-social://pair/v1#")
