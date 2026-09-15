"""Unit tests for v0.2 agent cards: creation, schema, signing, verification."""

from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone

import pytest

from muse_agent_social.crypto.identity import (
    b64url_decode,
    derive_identity_hierarchy,
)
from muse_agent_social.canonical import restricted_jcs
from muse_agent_social.model.cards import (
    CardVerification,
    card_fingerprint,
    create_card,
    format_timestamp,
    normalize_capabilities,
    verify_card,
)

UTC = timezone.utc
ISSUED = datetime(2026, 9, 15, 20, 0, 0, tzinfo=UTC)
NOW = datetime(2026, 9, 16, 12, 0, 0, tzinfo=UTC)

# Fixed TEST ONLY identity; never a real key.
_H = derive_identity_hierarchy(bytes(range(32)))
_AGREE = _H.agreement_key_multibase
_CAPS = ["threads/1", "events/0.2", "receipts/1"]


def _card(**overrides):
    kwargs = dict(
        identity_priv=_H.ed25519_private,
        display_name="Hermes",
        principal_label="Braden",
        agreement_pub_multibase=_AGREE,
        capabilities=list(_CAPS),
        issued_at=ISSUED,
        expires_at=ISSUED + timedelta(days=360),
    )
    kwargs.update(overrides)
    return create_card(**kwargs)


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------

def test_create_card_schema_shape():
    card = _card()
    assert card["card_version"] == 1
    assert card["identity_id"] == _H.identity_id
    assert card["display_name"] == "Hermes"
    assert card["principal_label"] == "Braden"
    assert card["bootstrap_agreement_key"] == _AGREE
    assert card["capabilities"] == ["events/0.2", "receipts/1", "threads/1"]
    assert card["issued_at"] == "2026-09-15T20:00:00Z"
    assert card["expires_at"] == "2027-09-10T20:00:00Z"
    nonce = b64url_decode(card["card_nonce"])
    assert len(nonce) == 16
    assert len(b64url_decode(card["signature"])) == 64


def test_create_card_capabilities_sorted():
    card = _card(capabilities=["threads/1", "events/0.2", "receipts/1"])
    assert card["capabilities"] == ["events/0.2", "receipts/1", "threads/1"]


def test_create_card_rejects_duplicate_capabilities():
    with pytest.raises(ValueError):
        _card(capabilities=["threads/1", "threads/1"])


def test_create_card_timestamps_whole_seconds_utc():
    card = _card(issued_at=datetime(2026, 9, 15, 20, 0, 0, 123456, tzinfo=UTC))
    assert card["issued_at"] == "2026-09-15T20:00:00Z"
    card = _card(issued_at="2026-09-15T20:00:00Z")
    assert card["issued_at"] == "2026-09-15T20:00:00Z"


@pytest.mark.parametrize(
    "caps",
    [
        ["dup", "dup"],
        ["x"] * 65,
        ["a" * 65],
        ["caf\xe9"],
        ["ok", 42],
        "not-a-list",
    ],
)
def test_create_card_rejects_bad_capabilities(caps):
    with pytest.raises(ValueError):
        _card(capabilities=caps)


def test_create_card_rejects_overlong_lifetime():
    with pytest.raises(ValueError):
        _card(expires_at=ISSUED + timedelta(days=366))


def test_create_card_rejects_expiry_before_issue():
    with pytest.raises(ValueError):
        _card(expires_at=ISSUED - timedelta(seconds=1))


def test_create_card_rejects_bad_timestamp():
    with pytest.raises(ValueError):
        _card(issued_at="2026-09-15 20:00:00")
    with pytest.raises(ValueError):
        _card(expires_at="not-a-time")


def test_create_card_rejects_bad_agreement_key():
    with pytest.raises(ValueError):
        _card(agreement_pub_multibase="bogus")


def test_create_card_rejects_empty_names():
    with pytest.raises(ValueError):
        _card(display_name="")
    with pytest.raises(ValueError):
        _card(principal_label="")


def test_card_nonces_differ():
    assert _card()["card_nonce"] != _card()["card_nonce"]


def test_signature_covers_restricted_jcs_bytes():
    card = _card()
    unsigned = {k: v for k, v in card.items() if k != "signature"}
    expected = restricted_jcs(unsigned)
    _H.ed25519_private.public_key().verify(b64url_decode(card["signature"]), expected)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def test_verify_round_trip():
    result = verify_card(_card(), now=NOW)
    assert isinstance(result, CardVerification)
    assert result.ok is True
    assert result.reason_code == "VALID"
    assert result.expired is False


def test_verify_rejects_tampered_display_name():
    card = _card()
    card["display_name"] = "Mallory"
    result = verify_card(card, now=NOW)
    assert result.ok is False
    assert result.reason_code == "BAD_SIGNATURE"


def test_verify_rejects_tampered_capabilities():
    card = _card()
    # Sorted and unique, so it passes schema checks and must fail on signature.
    card["capabilities"] = ["events/0.2", "evil/9", "receipts/1", "threads/1"]
    result = verify_card(card, now=NOW)
    assert result.ok is False
    assert result.reason_code == "BAD_SIGNATURE"


def test_verify_rejects_flipped_signature_byte():
    card = _card()
    sig = bytearray(b64url_decode(card["signature"]))
    sig[0] ^= 0x01
    card["signature"] = (
        base64.urlsafe_b64encode(bytes(sig)).rstrip(b"=").decode("ascii")
    )
    result = verify_card(card, now=NOW)
    assert result.ok is False
    assert result.reason_code == "BAD_SIGNATURE"


def test_verify_rejects_wrong_signer():
    other = derive_identity_hierarchy(bytes([9]) * 32)
    card = _card(identity_priv=other.ed25519_private)
    # Swap in the original identity id: signature no longer matches the key.
    card["identity_id"] = _H.identity_id
    result = verify_card(card, now=NOW)
    assert result.ok is False
    assert result.reason_code == "BAD_SIGNATURE"


def test_verify_expired_card_blocks_pairing_not_history():
    card = _card(
        issued_at=ISSUED - timedelta(days=400),
        expires_at=ISSUED - timedelta(days=40),
    )
    result = verify_card(card, now=NOW)
    assert result.ok is False
    assert result.reason_code == "EXPIRED"
    assert result.expired is True


def test_verify_boundary_expiry():
    card = _card(expires_at=ISSUED + timedelta(days=365))
    assert verify_card(card, now=ISSUED + timedelta(days=364)).ok is True
    result = verify_card(card, now=ISSUED + timedelta(days=365))
    assert result.reason_code == "EXPIRED"


def test_verify_rejects_overlong_lifetime_card():
    card = _card()
    card["expires_at"] = format_timestamp(ISSUED + timedelta(days=366))
    unsigned = {k: v for k, v in card.items() if k != "signature"}
    card["signature"] = (
        base64.urlsafe_b64encode(_H.ed25519_private.sign(restricted_jcs(unsigned)))
        .rstrip(b"=")
        .decode("ascii")
    )
    result = verify_card(card, now=NOW)
    assert result.ok is False
    assert result.reason_code == "EXPIRY_TOO_LONG"


def test_verify_rejects_unknown_field():
    card = _card()
    card["extra"] = "nope"
    result = verify_card(card, now=NOW)
    assert result.reason_code == "UNKNOWN_FIELD"
    assert result.ok is False


def test_verify_rejects_missing_field():
    card = _card()
    del card["principal_label"]
    result = verify_card(card, now=NOW)
    assert result.reason_code == "MALFORMED"


def test_verify_rejects_bad_version():
    card = _card()
    card["card_version"] = 2
    result = verify_card(card, now=NOW)
    assert result.reason_code == "BAD_VERSION"


def test_verify_rejects_bad_identity_id():
    card = _card()
    card["identity_id"] = "did:key:zbogus"
    result = verify_card(card, now=NOW)
    assert result.reason_code == "BAD_IDENTITY_ID"


def test_verify_rejects_bad_agreement_key():
    card = _card()
    card["bootstrap_agreement_key"] = "bogus"
    result = verify_card(card, now=NOW)
    assert result.reason_code == "BAD_AGREEMENT_KEY"


def test_verify_rejects_unsorted_capabilities():
    card = _card()
    card["capabilities"] = ["threads/1", "events/0.2"]
    result = verify_card(card, now=NOW)
    assert result.reason_code == "BAD_CAPABILITY"


def test_verify_rejects_bad_timestamp():
    card = _card()
    card["issued_at"] = "yesterday"
    result = verify_card(card, now=NOW)
    assert result.reason_code == "BAD_TIMESTAMP"


def test_verify_rejects_bad_nonce():
    card = _card()
    card["card_nonce"] = b64url_decode(card["card_nonce"])[:4].hex()
    result = verify_card(card, now=NOW)
    assert result.reason_code in ("BAD_NONCE", "BAD_SIGNATURE")
    # Nonce length alone: re-sign a short nonce to isolate the check.
    card = _card()
    card["card_nonce"] = "aGk"  # decodes to 2 bytes
    unsigned = {k: v for k, v in card.items() if k != "signature"}
    card["signature"] = (
        base64.urlsafe_b64encode(_H.ed25519_private.sign(restricted_jcs(unsigned)))
        .rstrip(b"=")
        .decode("ascii")
    )
    result = verify_card(card, now=NOW)
    assert result.reason_code == "BAD_NONCE"


def test_verify_rejects_non_dict():
    assert verify_card("nope", now=NOW).reason_code == "MALFORMED"


def test_display_labels_are_not_authentication_claims():
    # A card re-issued under a different display name, signed by the same
    # identity key, verifies fine: the key is authoritative, the name is a label.
    card = _card(display_name="Totally Different Name")
    assert verify_card(card, now=NOW).ok is True
    assert card["identity_id"] == _H.identity_id


def test_normalize_capabilities_ascii_byte_sort():
    assert normalize_capabilities(["b", "A", "a"]) == ["A", "a", "b"]


def test_card_fingerprint_stable_and_sensitive():
    card = _card()
    fp = card_fingerprint(card)
    assert len(fp) == 64 and all(c in "0123456789abcdef" for c in fp)
    assert card_fingerprint(copy.deepcopy(card)) == fp
    other = _card()
    assert card_fingerprint(other) != fp  # nonce differs
