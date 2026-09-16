"""Per-recipient envelope sealing and unsealing for Muse Agent Social v0.2.

Implements the ENCRYPTION section of the implementation plan.

Seal (the plan's 9-step construction):

1. Generate the per-message ephemeral X25519 keypair first, then
   H = SHA-256(restricted_jcs(protected)). The ephemeral keypair must exist
   before H is computed because its multibase public key lives in protected
   (a required envelope field) and is therefore covered by H and by the
   envelope signature. The plan lists header canonicalization before key
   generation, but that order is only consistent with the envelope schema
   when the ephemeral key is generated first; this module implements the
   schema-consistent order.
2. Generate a random 32-byte content-encryption key CEK and a random 12-byte
   content nonce.
3. ciphertext = AESGCM(CEK).encrypt(content_nonce, restricted_jcs(payload), H).
4. For each recipient: shared = X25519(ephemeral_priv, recipient
   relationship pubkey).
5. KEK = HKDF-SHA256(shared, salt=H, info=UTF8("muse-agent-social/v1/msg-wrap"),
   L=32).
6. wrap_aad = H || UTF8(recipient) || UTF8(agreement_key); generate a fresh
   12-byte wrap nonce.
7. wrapped_key = AESGCM(KEK).encrypt(wrap_nonce, CEK, wrap_aad).
8. Zero mutable references to CEK, KEK, shared secret, and the ephemeral
   private key as far as Python permits (see below).
9. Sort recipient entries by (recipient, agreement_key), assemble the
   envelope, then Ed25519-sign restricted_jcs(envelope minus signature).
   Base64url without padding is used throughout.

Unseal follows the plan's decrypt order: raw size check, strict_parse with
duplicate-key rejection, schema validation, sender/relationship sanity,
signature verification, recipient wrap selection, KEK derivation, CEK unwrap,
payload decrypt with H as AAD, then validate_payload(event_type, payload).

Replay and time-window enforcement are CALLER responsibilities (the receive
pipeline owns replay_guard and the clock contract); unseal_envelope performs
no replay or clock checks and documents this.

Sensitive-material handling: CEK, KEK, and Diffie-Hellman shared secrets are
held in bytearrays and overwritten with zeros as soon as they are no longer
needed, then deleted; the ephemeral private key object is deleted after use.
This is best-effort only: copies can persist inside cryptography's internal
buffers and the CPython allocator, and AESGCM() unavoidably copies key bytes
when constructed. Errors never carry secret values, only stable reason
codes and field paths. Returned plaintext payloads are the caller's
responsibility: decrypt in memory, never persist plaintext by default.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from muse_agent_social.canonical import (
    CanonicalizationError,
    restricted_jcs,
    strict_parse,
)
from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
    b64url_decode,
    b64url_encode,
    parse_agreement_key,
    parse_identity_id,
)
from muse_agent_social.validation import (
    MAX_ENVELOPE_BYTES,
    ValidationError,
    check_envelope_size,
    validate,
    validate_payload,
)

__all__ = [
    "SealingError",
    "PROTOCOL",
    "CEK_BYTES",
    "NONCE_BYTES",
    "REPLAY_NONCE_BYTES",
    "MAX_PAYLOAD_BYTES",
    "seal_envelope",
    "unseal_envelope",
]

PROTOCOL = "muse-agent-social/0.2"
CEK_BYTES = 32
NONCE_BYTES = 12
REPLAY_NONCE_BYTES = 16
# Default clear-payload budget from the plan: 240 KiB of canonical payload
# bytes. The whole sealed envelope is separately capped at 262144 bytes.
MAX_PAYLOAD_BYTES = 240 * 1024

_MSG_WRAP_INFO = b"muse-agent-social/v1/msg-wrap"
_ZERO32 = b"\x00" * 32


class SealingError(Exception):
    """A seal or unseal operation failed closed.

    Attributes:
        code: stable machine-readable reason code (see the module docstring
            and INTERFACE.md for the full list). Never contains secret values.
        field_path: dotted path to the offending field, "" when the failure
            is not field-specific.
        detail: extra stable sub-code or short ASCII note, never values.
    """

    def __init__(
        self, code: str, field_path: str = "", detail: str = ""
    ) -> None:
        self.code = code
        self.field_path = field_path
        self.detail = detail
        message = code
        if field_path:
            message += f" at {field_path}"
        if detail:
            message += f": {detail}"
        super().__init__(message)


def _zero(buf: bytearray) -> None:
    """Overwrite a bytearray with zeros. Best-effort secret hygiene."""
    for i in range(len(buf)):
        buf[i] = 0


def _canonical_or_raise(obj: Any, what: str) -> bytes:
    try:
        return restricted_jcs(obj)
    except CanonicalizationError as exc:
        raise SealingError(
            "not_canonical", field_path=exc.field_path, detail=exc.code
        ) from None


def _reject_low_order_shared(shared: bytearray) -> None:
    """Reject low-order X25519 peer keys (second layer of defense).

    The first layer is the library itself: OpenSSL's X25519 refuses
    degenerate peer points (identity, u=1, u=p-1, and the other low-order
    points) by raising ValueError from exchange(), which callers map to
    "low_order_key". This check is defense in depth for any peer point
    that the library accepts: our X25519 private keys are always clamped
    (the low 3 bits are cleared), so the scalar is a multiple of 8, and any
    low-order peer point has order dividing 8, therefore scalar *
    low_order_point is always the identity, whose encoding is 32 zero
    bytes. Checking the shared secret for all zeros rejects every such
    peer public key without a point list.
    """
    if bytes(shared) == _ZERO32:
        _zero(shared)
        del shared
        raise SealingError("low_order_key")


def _exchange_or_reject(priv: X25519PrivateKey, peer: X25519PublicKey) -> bytearray:
    """X25519 exchange that fails closed on degenerate peer keys.

    Raises:
        SealingError: "low_order_key" when the library refuses the peer
            point (its low-order rejection) or the shared secret is the
            all-zero identity encoding.
    """
    try:
        shared = bytearray(priv.exchange(peer))
    except ValueError:
        raise SealingError("low_order_key") from None
    _reject_low_order_shared(shared)
    return shared


def _check_recipient_entry(entry: Any, index: int) -> dict:
    path = f"recipients[{index}]"
    if not isinstance(entry, dict):
        raise SealingError("bad_recipient", field_path=path)
    for key in ("recipient", "agreement_key", "relationship_pub"):
        if key not in entry:
            raise SealingError(
                "bad_recipient", field_path=path, detail=f"missing_{key}"
            )
    recipient = entry["recipient"]
    agreement_key = entry["agreement_key"]
    try:
        relationship_pub = bytes(entry["relationship_pub"])
    except (TypeError, ValueError):
        raise SealingError(
            "bad_recipient", field_path=f"{path}.relationship_pub"
        ) from None
    if len(relationship_pub) != 32:
        raise SealingError(
            "bad_recipient", field_path=f"{path}.relationship_pub"
        )
    try:
        parse_identity_id(recipient)
    except (ValueError, TypeError):
        raise SealingError(
            "bad_recipient", field_path=f"{path}.recipient"
        ) from None
    try:
        decoded = parse_agreement_key(agreement_key)
    except (ValueError, TypeError):
        raise SealingError(
            "bad_recipient", field_path=f"{path}.agreement_key"
        ) from None
    if decoded != relationship_pub:
        # The multibase agreement key in the wrap AAD must name the same key
        # used for the Diffie-Hellman exchange; otherwise the recipient can
        # neither derive the KEK nor match the AAD.
        raise SealingError("key_mismatch", field_path=path)
    return {
        "recipient": recipient,
        "agreement_key": agreement_key,
        "relationship_pub": relationship_pub,
    }


def seal_envelope(
    protected: dict,
    payload: dict,
    identity_priv: Ed25519PrivateKey,
    recipients: list,
) -> dict:
    """Seal a typed event payload for one or more recipients.

    Args:
        protected: the 15-field protected header (see model.events
            .build_protected). It is copied, never mutated; the ephemeral
            agreement key multibase is filled into the copy.
        payload: the typed event payload dict for protected["event_type"].
        identity_priv: the sender's Ed25519 identity private key. It must
            correspond to protected["sender"].
        recipients: list of dicts, each with "recipient" (did:key),
            "agreement_key" (multibase, from the recipient's card), and
            "relationship_pub" (raw 32 bytes) keys.

    Returns:
        The sealed envelope dict, schema-valid and at most 262144
        canonical bytes.

    Raises:
        SealingError: with a stable code on any failure. The canonical
            payload is capped at 240 KiB ("payload_too_large") and the
            sealed envelope at 262144 bytes ("envelope_too_large").
    """
    if not isinstance(identity_priv, Ed25519PrivateKey):
        raise SealingError("bad_identity_key")
    if not isinstance(recipients, list) or not recipients:
        raise SealingError("no_recipients")
    # G14 dual-wrap bound: a sender wraps to at most the recipient's
    # current and immediately-previous agreement epochs. More than two
    # wraps is a protocol violation, not just a schema failure.
    if len(recipients) > 2:
        raise SealingError("too_many_recipients")
    if not isinstance(protected, dict):
        raise SealingError("bad_protected")
    if not isinstance(payload, dict):
        raise SealingError("bad_payload")

    try:
        sender_pub = parse_identity_id(protected["sender"])
    except (KeyError, ValueError, TypeError):
        raise SealingError("bad_sender", field_path="protected.sender") from None
    if sender_pub != identity_priv.public_key().public_bytes_raw():
        raise SealingError("sender_key_mismatch", field_path="protected.sender")

    checked = [_check_recipient_entry(r, i) for i, r in enumerate(recipients)]

    header = dict(protected)
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub_raw = ephemeral_priv.public_key().public_bytes_raw()
    header["ephemeral_key"] = agreement_key_multibase_from_pubkey(
        ephemeral_pub_raw
    )

    payload_bytes = _canonical_or_raise(payload, "payload")
    if len(payload_bytes) > MAX_PAYLOAD_BYTES:
        raise SealingError("payload_too_large")

    header_bytes = _canonical_or_raise(header, "protected")
    digest = hashlib.sha256(header_bytes).digest()

    cek = bytearray(os.urandom(CEK_BYTES))
    content_nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(bytes(cek)).encrypt(content_nonce, payload_bytes, digest)
    del payload_bytes

    entries: list[dict] = []
    try:
        for item in checked:
            peer_pub = X25519PublicKey.from_public_bytes(
                item["relationship_pub"]
            )
            shared = _exchange_or_reject(ephemeral_priv, peer_pub)
            kek = bytearray(
                HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=digest,
                    info=_MSG_WRAP_INFO,
                ).derive(bytes(shared))
            )
            _zero(shared)
            del shared
            wrap_aad = (
                digest
                + item["recipient"].encode("utf-8")
                + item["agreement_key"].encode("utf-8")
            )
            wrap_nonce = os.urandom(NONCE_BYTES)
            try:
                wrapped = AESGCM(bytes(kek)).encrypt(
                    wrap_nonce, bytes(cek), wrap_aad
                )
            finally:
                _zero(kek)
                del kek
            entries.append(
                {
                    "recipient": item["recipient"],
                    "agreement_key": item["agreement_key"],
                    "wrap_nonce": b64url_encode(wrap_nonce),
                    "wrapped_key": b64url_encode(wrapped),
                }
            )
    finally:
        _zero(cek)
        del cek
        del ephemeral_priv

    entries.sort(key=lambda e: (e["recipient"], e["agreement_key"]))

    envelope = {
        "protected": header,
        "recipients": entries,
        "content_nonce": b64url_encode(content_nonce),
        "ciphertext": b64url_encode(ciphertext),
        "signature": "",
    }
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    envelope["signature"] = b64url_encode(
        identity_priv.sign(_canonical_or_raise(unsigned, "envelope"))
    )

    try:
        validate("event-envelope", envelope)
    except ValidationError as exc:
        raise SealingError(
            "schema_invalid", field_path=exc.field_path, detail=exc.code
        ) from None
    sealed_bytes = _canonical_or_raise(envelope, "envelope")
    if len(sealed_bytes) > MAX_ENVELOPE_BYTES:
        raise SealingError("envelope_too_large")
    del sealed_bytes
    return envelope


def _parse_envelope_input(envelope: Any) -> dict:
    """Apply the raw size check and duplicate-rejecting parse.

    Accepts raw UTF-8 bytes (the wire form) or an already-parsed dict.
    """
    if isinstance(envelope, (bytes, bytearray)):
        data = bytes(envelope)
        try:
            check_envelope_size(data)
        except ValidationError as exc:
            raise SealingError("envelope_too_large") from None
        except TypeError:
            raise SealingError("bad_envelope_type") from None
        try:
            parsed = strict_parse(data)
        except CanonicalizationError as exc:
            raise SealingError(
                "invalid_envelope", detail=exc.code
            ) from None
        if not isinstance(parsed, dict):
            raise SealingError("invalid_envelope", detail="not_an_object")
        return parsed
    if isinstance(envelope, dict):
        raw = _canonical_or_raise(envelope, "envelope")
        if len(raw) > MAX_ENVELOPE_BYTES:
            raise SealingError("envelope_too_large")
        del raw
        return envelope
    raise SealingError("bad_envelope_type")


def unseal_envelope(
    envelope: Any,
    relationship_priv: X25519PrivateKey,
    expected_recipient_id: str,
) -> tuple[dict, dict]:
    """Unseal an envelope for one recipient.

    Implements the plan's decrypt order: raw size check, strict_parse with
    duplicate rejection, schema validation, sender/relationship sanity,
    signature verification, recipient wrap selection, KEK derivation, CEK
    unwrap, payload decrypt with H as AAD, then
    validate_payload(event_type, payload).

    Replay and time-window checks are NOT performed here; they are the
    caller's responsibility (the receive pipeline owns replay_guard and the
    clock contract).

    Args:
        envelope: raw sealed-envelope bytes, or an already-parsed envelope
            dict.
        relationship_priv: this recipient's X25519 relationship private key
            for the envelope's key epoch.
        expected_recipient_id: the did:key identity id selecting which
            recipient wrap to use.

    Returns:
        (protected, payload): the protected header dict and the decrypted,
            schema-validated typed payload dict.

    Raises:
        SealingError: with a stable code. Tampering with the protected
            header or the signature is reported as "bad_signature" because
            the Ed25519 signature covers the protected header. A wrap that
            targets a different agreement key than relationship_priv is
            reported as "wrong_aad" (the wrap AAD embeds the agreement key,
            so a wrong key is a wrong AAD). Corrupted wrap bytes under the
            correct key are "tampered_wrap"; corrupted body bytes are
            "tampered_body".
    """
    env = _parse_envelope_input(envelope)

    try:
        validate("event-envelope", env)
    except ValidationError as exc:
        raise SealingError(
            "schema_invalid", field_path=exc.field_path, detail=exc.code
        ) from None

    protected = env["protected"]
    try:
        sender_pub = parse_identity_id(protected["sender"])
    except (ValueError, TypeError):
        raise SealingError(
            "bad_sender", field_path="protected.sender"
        ) from None
    try:
        ephemeral_pub_raw = parse_agreement_key(protected["ephemeral_key"])
    except (ValueError, TypeError):
        raise SealingError(
            "bad_ephemeral_key", field_path="protected.ephemeral_key"
        ) from None
    try:
        signature = b64url_decode(env["signature"])
    except ValueError:
        raise SealingError("bad_signature", field_path="signature") from None
    if len(signature) != 64:
        raise SealingError("bad_signature", field_path="signature")

    unsigned = {k: v for k, v in env.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(sender_pub).verify(
            signature, restricted_jcs(unsigned)
        )
    except InvalidSignature:
        raise SealingError("bad_signature") from None
    except CanonicalizationError as exc:
        raise SealingError(
            "not_canonical", field_path=exc.field_path, detail=exc.code
        ) from None

    digest = hashlib.sha256(restricted_jcs(protected)).digest()

    if not isinstance(relationship_priv, X25519PrivateKey):
        raise SealingError("bad_relationship_key")
    own_pub_raw = relationship_priv.public_key().public_bytes_raw()

    candidates = [
        e for e in env["recipients"] if e["recipient"] == expected_recipient_id
    ]
    if not candidates:
        raise SealingError("unknown_recipient")

    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_raw)
    shared = _exchange_or_reject(relationship_priv, ephemeral_pub)
    kek = bytearray(
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=digest,
            info=_MSG_WRAP_INFO,
        ).derive(bytes(shared))
    )
    _zero(shared)
    del shared

    cek: bytearray | None = None
    failure = "tampered_wrap"
    try:
        for entry in candidates:
            try:
                entry_key_raw = parse_agreement_key(entry["agreement_key"])
            except (ValueError, TypeError):
                failure = "bad_agreement_key"
                continue
            wrap_aad = (
                digest
                + entry["recipient"].encode("utf-8")
                + entry["agreement_key"].encode("utf-8")
            )
            try:
                wrap_nonce = b64url_decode(entry["wrap_nonce"])
                wrapped = b64url_decode(entry["wrapped_key"])
            except ValueError:
                failure = "tampered_wrap"
                continue
            if len(wrap_nonce) != NONCE_BYTES:
                failure = "tampered_wrap"
                continue
            try:
                cek = bytearray(
                    AESGCM(bytes(kek)).decrypt(wrap_nonce, wrapped, wrap_aad)
                )
            except InvalidTag:
                # Either the wrap bytes are corrupted or this wrap targets
                # a different agreement key (wrong KEK and wrong AAD). The
                # agreement key check disambiguates the two cases.
                if entry_key_raw != own_pub_raw:
                    failure = "wrong_aad"
                else:
                    failure = "tampered_wrap"
                continue
            break
    finally:
        _zero(kek)
        del kek
    if cek is None:
        raise SealingError(failure)

    try:
        try:
            content_nonce = b64url_decode(env["content_nonce"])
            ciphertext = b64url_decode(env["ciphertext"])
        except ValueError:
            raise SealingError(
                "tampered_body", field_path="ciphertext"
            ) from None
        if len(content_nonce) != NONCE_BYTES:
            raise SealingError(
                "tampered_body", field_path="content_nonce"
            ) from None
        try:
            payload_bytes = AESGCM(bytes(cek)).decrypt(
                content_nonce, ciphertext, digest
            )
        except InvalidTag:
            raise SealingError("tampered_body") from None
    finally:
        _zero(cek)
        del cek

    try:
        payload = strict_parse(payload_bytes)
    except CanonicalizationError as exc:
        raise SealingError("invalid_payload", detail=exc.code) from None
    finally:
        del payload_bytes
    if not isinstance(payload, dict):
        raise SealingError("invalid_payload", detail="not_an_object")
    try:
        validate_payload(protected["event_type"], payload)
    except ValidationError as exc:
        raise SealingError(
            "payload_invalid", field_path=exc.field_path, detail=exc.code
        ) from None
    return protected, payload
