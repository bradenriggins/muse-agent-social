"""Gate: Pairing adversarial fixtures (plan mandatory fixtures).

Forged card, reused invite, stale invite, and malicious relay URL.
All keys are fresh random; no network; local sqlite only.
"""

import copy
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
)
from muse_agent_social.model.cards import create_card, verify_card
from muse_agent_social.model.invites import (
    PairingError,
    create_invite,
    validate_invite,
)

UTC = timezone.utc


@pytest.fixture()
def inviter(tmp_path):
    from support.harness import fresh_db

    conn = fresh_db(tmp_path / "pairing.db")
    ed_priv = Ed25519PrivateKey.generate()
    x_priv = X25519PrivateKey.generate()
    card = create_card(
        identity_priv=ed_priv,
        display_name="Alice",
        principal_label="PrincipalA",
        agreement_pub_multibase=agreement_key_multibase_from_pubkey(
            x_priv.public_key().public_bytes_raw()
        ),
        capabilities=["chat", "receipts"],
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    return {"conn": conn, "ed_priv": ed_priv, "card": card}


def _invite(inviter, **kw):
    args = {
        "conn": inviter["conn"],
        "inviter_card": inviter["card"],
        "inviter_priv": inviter["ed_priv"],
        "ephemeral_priv": X25519PrivateKey.generate(),
        "requested_capabilities": ["chat"],
        "requested_policy": {},
    }
    args.update(kw)
    return create_invite(**args)


# -- forged card -----------------------------------------------------------------------


def test_forged_card_signature_rejected(inviter):
    forged = copy.deepcopy(inviter["card"])
    forged["display_name"] = "Mallory"
    result = verify_card(forged)
    assert result.ok is False
    assert result.reason_code == "BAD_SIGNATURE"


def test_card_key_mismatch_rejected_at_invite_creation(inviter):
    other_priv = Ed25519PrivateKey.generate()
    with pytest.raises(PairingError) as exc:
        _invite(inviter, inviter_priv=other_priv)
    assert exc.value.code == "card_key_mismatch"


def test_tampered_invite_signature_rejected(inviter):
    invite = _invite(inviter)
    invite["requested_capabilities"] = ["chat", "admin"]
    with pytest.raises(PairingError) as exc:
        validate_invite(inviter["conn"], invite)
    assert exc.value.code == "bad_signature"


# -- reused invite ------------------------------------------------------------------------------


def test_reused_invite_rejected(inviter):
    invite = _invite(inviter)
    validate_invite(inviter["conn"], invite)
    with pytest.raises(PairingError) as exc:
        validate_invite(inviter["conn"], invite)
    assert exc.value.code == "already_used"


# -- stale invite -------------------------------------------------------------------------------------


def test_stale_invite_rejected(inviter):
    stale_now = datetime.now(UTC) - timedelta(minutes=20)
    invite = _invite(inviter, now=stale_now)
    with pytest.raises(PairingError) as exc:
        validate_invite(inviter["conn"], invite)
    assert exc.value.code == "expired"
    # The ledger marks it expired, not issued: no later use.
    row = inviter["conn"].execute(
        "SELECT state FROM invites WHERE invite_id = ?",
        (invite["invite_id"],),
    ).fetchone()
    assert row["state"] == "expired"


def test_invite_lifetime_capped_at_15_minutes(inviter):
    invite = _invite(inviter)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    issued = datetime.strptime(invite["issued_at"], fmt)
    expires = datetime.strptime(invite["expires_at"], fmt)
    assert (expires - issued) <= timedelta(minutes=15)


# -- malicious relay URL -----------------------------------------------------------------------


def test_malicious_relay_url_rejected():
    from muse_agent_social.model.invites import _check_relay_url

    for bad in (
        "javascript:alert(1)",
        "http://evil.example/relay",
        "ftp://files.example/x",
        "",
    ):
        with pytest.raises(PairingError) as exc:
            _check_relay_url(bad)
        assert exc.value.code == "bad_relay_url"


def test_valid_relay_urls_accepted():
    from muse_agent_social.model.invites import _check_relay_url

    assert _check_relay_url("https://github.com/o/r") == "https://github.com/o/r"
    assert _check_relay_url("git@github.com:o/r.git") == "git@github.com:o/r.git"
