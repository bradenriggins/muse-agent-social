"""Identity key hierarchy and did:key identifiers for Muse Agent Social v0.2.

Implements the CRYPTOGRAPHIC FOUNDATION and IDENTITY sections of the
implementation plan:

* One 32-byte installation master seed from the OS CSPRNG, stored mode 0600.
* PRK = HKDF-Extract(salt=UTF8("muse-agent-social/v1"), IKM=master_seed_32, SHA-256).
* ed25519_seed      = HKDF-Expand(PRK, info=UTF8("muse-agent-social/v1/id-signing"), L=32)
* x25519_bootstrap  = HKDF-Expand(PRK, info=UTF8("muse-agent-social/v1/key-agreement"), L=32)
* local_store_key   = HKDF-Expand(PRK, info=UTF8("muse-agent-social/v1/local-store"), L=32)
* identity_id = "did:key:z" + base58btc(0xED 0x01 || 32-byte Ed25519 pubkey)
* agreement key multibase = "z" + base58btc(0xEC 0x01 || 32-byte X25519 pubkey)

Every cryptographic purpose gets a distinct derived key. Raw key material is
never reused across purposes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass, field

import base58
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# Domain separation, UTF-8 encoded, exactly as specified in the plan.
_DOMAIN = b"muse-agent-social/v1"
_INFO_ID_SIGNING = _DOMAIN + b"/id-signing"
_INFO_KEY_AGREEMENT = _DOMAIN + b"/key-agreement"
_INFO_LOCAL_STORE = _DOMAIN + b"/local-store"

_MASTER_SEED_LEN = 32
_DERIVED_KEY_LEN = 32

# Multicodec prefixes (unsigned-varint encoded): 0xed -> ED 01, 0xec -> EC 01.
_MULTICODEC_ED25519 = b"\xed\x01"
_MULTICODEC_X25519 = b"\xec\x01"
_RAW_PUBKEY_LEN = 32

_IDENTITY_ID_PREFIX = "did:key:z"
_AGREEMENT_KEY_PREFIX = "z"


def generate_master_seed() -> bytes:
    """Generate a fresh 32-byte installation master seed from the OS CSPRNG."""
    return os.urandom(_MASTER_SEED_LEN)


def store_master_seed(path: str | os.PathLike, seed: bytes) -> None:
    """Write *seed* to *path* with mode 0600. Refuses to overwrite an existing file.

    Uses O_CREAT | O_EXCL so a concurrent creation cannot silently replace an
    existing seed file. Raises FileExistsError if the file already exists and
    ValueError if the seed is not exactly 32 bytes.
    """
    seed = bytes(seed)
    if len(seed) != _MASTER_SEED_LEN:
        raise ValueError(
            f"master seed must be exactly {_MASTER_SEED_LEN} bytes, got {len(seed)}"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, seed)
    finally:
        os.close(fd)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract per RFC 5869 section 2.2: PRK = HMAC-SHA256(salt, IKM).

    The plan's notation is exactly this step followed by HKDF-Expand; doing the
    two steps explicitly keeps the audit trail one-to-one with the spec.
    """
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int = _DERIVED_KEY_LEN) -> bytes:
    """HKDF-Expand per RFC 5869 section 2.3 via the cryptography package."""
    return (
        HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
        .derive(prk)
    )


def derive_identity_hierarchy(master_seed: bytes) -> "IdentityHierarchy":
    """Derive the full v0.2 key hierarchy from a 32-byte master seed.

    Returns an IdentityHierarchy with the Ed25519 identity signing key, the
    X25519 bootstrap key-agreement key, the local-store key, and both public
    identifiers (identity_id and bootstrap agreement key multibase).
    """
    seed = bytes(master_seed)
    if len(seed) != _MASTER_SEED_LEN:
        raise ValueError(
            f"master seed must be exactly {_MASTER_SEED_LEN} bytes, got {len(seed)}"
        )

    prk = _hkdf_extract(_DOMAIN, seed)
    ed25519_seed = _hkdf_expand(prk, _INFO_ID_SIGNING)
    x25519_bootstrap = _hkdf_expand(prk, _INFO_KEY_AGREEMENT)
    local_store_key = _hkdf_expand(prk, _INFO_LOCAL_STORE)

    ed25519_private = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    x25519_private = X25519PrivateKey.from_private_bytes(x25519_bootstrap)

    ed25519_public_bytes = ed25519_private.public_key().public_bytes_raw()
    x25519_public_bytes = x25519_private.public_key().public_bytes_raw()

    return IdentityHierarchy(
        ed25519_private=ed25519_private,
        x25519_private=x25519_private,
        local_store_key=local_store_key,
        identity_id=identity_id_from_pubkey(ed25519_public_bytes),
        agreement_key_multibase=agreement_key_multibase_from_pubkey(
            x25519_public_bytes
        ),
        # Retained only so tests can assert cross-purpose separation.
        _ed25519_seed=ed25519_seed,
        _x25519_bootstrap=x25519_bootstrap,
    )


@dataclass
class IdentityHierarchy:
    """The derived v0.2 identity hierarchy for one installation.

    ed25519_private signs agent cards and envelopes. x25519_private is the
    long-lived bootstrap agreement key that authenticates pairing ceremonies
    (never routine message wrapping). local_store_key protects local storage.
    """

    ed25519_private: Ed25519PrivateKey
    x25519_private: X25519PrivateKey
    local_store_key: bytes
    identity_id: str
    agreement_key_multibase: str
    # Raw derivation outputs, kept for tests/audit; never persisted or sent.
    _ed25519_seed: bytes = field(repr=False)
    _x25519_bootstrap: bytes = field(repr=False)

    @property
    def ed25519_public_bytes(self) -> bytes:
        return self.ed25519_private.public_key().public_bytes_raw()

    @property
    def x25519_public_bytes(self) -> bytes:
        return self.x25519_private.public_key().public_bytes_raw()

    def sign(self, data: bytes) -> bytes:
        return self.ed25519_private.sign(bytes(data))


def identity_id_from_pubkey(ed25519_public_bytes: bytes) -> str:
    """Build "did:key:z" + base58btc(0xED 0x01 || 32-byte Ed25519 pubkey)."""
    raw = bytes(ed25519_public_bytes)
    if len(raw) != _RAW_PUBKEY_LEN:
        raise ValueError(
            f"Ed25519 public key must be {_RAW_PUBKEY_LEN} bytes, got {len(raw)}"
        )
    return _IDENTITY_ID_PREFIX + base58.b58encode(
        _MULTICODEC_ED25519 + raw
    ).decode("ascii")


def agreement_key_multibase_from_pubkey(x25519_public_bytes: bytes) -> str:
    """Build "z" + base58btc(0xEC 0x01 || 32-byte X25519 pubkey)."""
    raw = bytes(x25519_public_bytes)
    if len(raw) != _RAW_PUBKEY_LEN:
        raise ValueError(
            f"X25519 public key must be {_RAW_PUBKEY_LEN} bytes, got {len(raw)}"
        )
    return _AGREEMENT_KEY_PREFIX + base58.b58encode(
        _MULTICODEC_X25519 + raw
    ).decode("ascii")


def parse_identity_id(identity_id: str) -> bytes:
    """Parse a did:key identity ID and return the raw 32-byte Ed25519 pubkey.

    Validates the "did:key:z" prefix, the base58btc payload, the 0xED 0x01
    multicodec bytes, and the exact length. Raises ValueError on any garbage.
    """
    if not isinstance(identity_id, str):
        raise ValueError("identity_id must be a string")
    if not identity_id.startswith(_IDENTITY_ID_PREFIX):
        raise ValueError(
            f"identity_id must start with {_IDENTITY_ID_PREFIX!r}"
        )
    payload = identity_id[len(_IDENTITY_ID_PREFIX):]
    return _decode_multicodec(payload, _MULTICODEC_ED25519, "identity_id")


def parse_agreement_key(agreement_key: str) -> bytes:
    """Parse a bootstrap agreement key multibase, returning the raw X25519 pubkey.

    Validates the leading "z", the base58btc payload, the 0xEC 0x01 multicodec
    bytes, and the exact length. Raises ValueError on any garbage.
    """
    if not isinstance(agreement_key, str):
        raise ValueError("agreement key must be a string")
    if not agreement_key.startswith(_AGREEMENT_KEY_PREFIX) or len(agreement_key) < 2:
        raise ValueError("agreement key must start with 'z' (multibase base58btc)")
    payload = agreement_key[len(_AGREEMENT_KEY_PREFIX):]
    return _decode_multicodec(payload, _MULTICODEC_X25519, "agreement key")


def _decode_multicodec(
    payload: str, expected_prefix: bytes, what: str
) -> bytes:
    try:
        decoded = base58.b58decode(payload)
    except Exception as exc:
        raise ValueError(f"{what}: invalid base58btc payload") from exc
    if not decoded.startswith(expected_prefix):
        raise ValueError(f"{what}: wrong multicodec prefix")
    raw = decoded[len(expected_prefix):]
    if len(raw) != _RAW_PUBKEY_LEN:
        raise ValueError(
            f"{what}: public key must be {_RAW_PUBKEY_LEN} bytes, got {len(raw)}"
        )
    return raw


def b64url_encode(raw: bytes) -> str:
    """RFC 4648 base64url without padding (the plan's envelope/card encoding)."""
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url, raising ValueError on garbage."""
    if not isinstance(text, str):
        raise ValueError("base64url input must be a string")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise ValueError("invalid base64url") from exc
