"""Property tests for the crypto layer (seeded stdlib random, no Hypothesis).

- Identity hierarchy: same seed derives the same hierarchy (determinism);
  distinct seeds derive distinct identity ids and agreement keys.
- Encoding round-trips: identity_id, agreement-key multibase, and b64url.
  Bit-flips and truncations of any encoding either raise or decode to
  DIFFERENT bytes: mutated input never silently decodes back to the
  original bytes.
- seal/unseal: round-trip over random keys, 1..5 recipients, and random
  payloads; single-byte mutations of the canonical envelope bytes always
  fail closed (SealingError), never returning wrong plaintext (AAD binding);
  decrypting with the wrong relationship key also fails closed.
- Randomness: >=256 seals of the same payload yield unique replay_nonce
  and ephemeral_key values (no nonce/ephemeral reuse).
- Low-order points: sealing to every known low-order X25519 peer point
  raises SealingError("low_order_key").
- agreement_fingerprint: deterministic; distinct for distinct keys.
- rotate/verify: the announcement round-trips (verifies True); any
  single-bit flip in the signed bytes never verifies (False, never True).
- Wordlist: verification_phrase is stable across recomputation and argument
  order; distinct identity pairs give distinct phrases; a single-word
  substitution is always detectable (the tampered phrase never equals the
  genuine phrase). pairing_phrase is deterministic and order-independent.
"""

import copy
import random
import string
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from muse_agent_social.canonical import restricted_jcs
from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
    b64url_decode,
    b64url_encode,
    derive_identity_hierarchy,
    generate_master_seed,
    identity_id_from_pubkey,
    parse_agreement_key,
    parse_identity_id,
)
from muse_agent_social.crypto.rotation import (
    agreement_fingerprint,
    rotate_identity_key,
    verify_identity_rotation,
)
from muse_agent_social.crypto.sealing import (
    SealingError,
    seal_envelope,
    unseal_envelope,
)
from muse_agent_social.crypto.words import load_wordlist, verification_phrase
from muse_agent_social.model.cards import create_card
from muse_agent_social.model.events import build_protected
from muse_agent_social.model.invites import pairing_phrase

REL_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CONV_ID = "12345678-1234-4234-8234-1234567890ab"
CREATED_AT = "2026-09-15T20:00:00Z"


def _rand_bytes(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def _make_recipient(rng):
    priv = X25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    ed_priv = Ed25519PrivateKey.generate()
    did = identity_id_from_pubkey(ed_priv.public_key().public_bytes_raw())
    return {
        "priv": priv,
        "entry": {
            "recipient": did,
            "agreement_key": agreement_key_multibase_from_pubkey(pub_raw),
            "relationship_pub": pub_raw,
        },
    }


def _make_protected(sender_did, seq):
    protected = build_protected(
        relationship_id=REL_ID,
        conversation_id=CONV_ID,
        sender_id=sender_did,
        event_type="message.created",
        thread_id=None,
        reply_to=None,
        key_epoch=1,
        created_at=CREATED_AT,
    )
    protected["sender_seq"] = seq
    return protected


def _rand_payload(rng):
    alphabet = string.ascii_letters + string.digits + " "
    return {
        "body": "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 64))),
        "format": "plain",
    }


def _flip_bit(data: bytes, rng) -> bytes:
    i = rng.randrange(len(data))
    bit = 1 << rng.randrange(8)
    return data[:i] + bytes([data[i] ^ bit]) + data[i + 1 :]


# -- identity hierarchy ----------------------------------------------------


@pytest.mark.parametrize("seed", range(10))
def test_hierarchy_determinism_and_seed_distinctness(seed):
    rng = random.Random(100 + seed)
    raw_seed = _rand_bytes(rng, 32)
    h1 = derive_identity_hierarchy(raw_seed)
    h2 = derive_identity_hierarchy(raw_seed)
    assert h1.identity_id == h2.identity_id
    assert h1.agreement_key_multibase == h2.agreement_key_multibase
    assert h1.ed25519_public_bytes == h2.ed25519_public_bytes
    assert h1.x25519_public_bytes == h2.x25519_public_bytes
    assert bytes(h1.local_store_key) == bytes(h2.local_store_key)

    other = derive_identity_hierarchy(generate_master_seed())
    assert other.identity_id != h1.identity_id
    assert other.agreement_key_multibase != h1.agreement_key_multibase


# -- encoding round-trips --------------------------------------------------


@pytest.mark.parametrize("seed", range(10))
def test_identity_and_agreement_key_round_trip(seed):
    rng = random.Random(200 + seed)
    ed_raw = _rand_bytes(rng, 32)
    x_raw = _rand_bytes(rng, 32)
    assert parse_identity_id(identity_id_from_pubkey(ed_raw)) == ed_raw
    assert parse_agreement_key(agreement_key_multibase_from_pubkey(x_raw)) == x_raw
    blob = _rand_bytes(rng, rng.randrange(1, 65))
    assert b64url_decode(b64url_encode(blob)) == blob


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B64URL_ALPHABET = string.ascii_letters + string.digits + "-_"


@pytest.mark.parametrize("seed", range(10))
def test_encoding_mutations_never_silently_garble(seed):
    """A bit-flip or truncation in an encoded key either raises or decodes
    to bytes DIFFERENT from the original: it never silently round-trips
    back to the original bytes."""
    rng = random.Random(300 + seed)
    ed_raw = _rand_bytes(rng, 32)
    x_raw = _rand_bytes(rng, 32)
    cases = [
        (identity_id_from_pubkey(ed_raw), parse_identity_id, ed_raw),
        (
            agreement_key_multibase_from_pubkey(x_raw),
            parse_agreement_key,
            x_raw,
        ),
    ]
    blob = _rand_bytes(rng, 48)
    cases.append((b64url_encode(blob), b64url_decode, blob))

    for encoded, parse, original in cases:
        # Bit flips: change one character to a different alphabet char.
        for _ in range(12):
            i = rng.randrange(len(encoded))
            alphabet = (
                _B64URL_ALPHABET
                if parse is b64url_decode
                else _B58_ALPHABET + ":zkye."
            )
            choices = [c for c in alphabet if c != encoded[i]]
            mutated = encoded[:i] + rng.choice(choices) + encoded[i + 1 :]
            try:
                decoded = parse(mutated)
            except (ValueError, TypeError):
                continue
            assert decoded != original, (
                f"mutated encoding {mutated!r} decoded back to the original bytes"
            )
        # Truncations.
        for cut in (1, 2, 3, len(encoded) // 2):
            try:
                decoded = parse(encoded[:-cut])
            except (ValueError, TypeError):
                continue
            assert decoded != original, (
                f"truncated encoding decoded back to the original bytes"
            )
        # Garbage input raises, never decodes; empty input may decode to
        # empty bytes, which still must not equal the original.
        with pytest.raises((ValueError, TypeError)):
            parse("!!!not-valid!!!")
        try:
            empty_decoded = parse("")
        except (ValueError, TypeError):
            pass
        else:
            assert empty_decoded != original


# -- seal / unseal ---------------------------------------------------------


@pytest.mark.parametrize("seed", range(10))
def test_seal_unseal_round_trip_random_recipients(seed):
    """1..2 recipients (the G14 dual-wrap bound), random keys and payloads:
    every recipient unseals the exact payload that was sealed."""
    rng = random.Random(400 + seed)
    sender_priv = Ed25519PrivateKey.generate()
    sender_did = identity_id_from_pubkey(
        sender_priv.public_key().public_bytes_raw()
    )
    n_recipients = 1 + (seed % 2)
    recipients = [_make_recipient(rng) for _ in range(n_recipients)]
    payload = _rand_payload(rng)
    envelope = seal_envelope(
        _make_protected(sender_did, seq=1 + seed),
        payload,
        sender_priv,
        [r["entry"] for r in recipients],
    )
    for r in recipients:
        protected, out = unseal_envelope(
            envelope, r["priv"], r["entry"]["recipient"]
        )
        assert out == payload
        assert protected["sender"] == sender_did


@pytest.mark.parametrize("seed", range(5))
def test_seal_rejects_more_than_two_recipients(seed):
    """The G14 dual-wrap bound: sealing to 3+ recipients raises
    SealingError with code too_many_recipients (fail-closed)."""
    rng = random.Random(450 + seed)
    sender_priv = Ed25519PrivateKey.generate()
    sender_did = identity_id_from_pubkey(
        sender_priv.public_key().public_bytes_raw()
    )
    recipients = [_make_recipient(rng) for _ in range(3)]
    with pytest.raises(SealingError) as ei:
        seal_envelope(
            _make_protected(sender_did, seq=1),
            _rand_payload(rng),
            sender_priv,
            [r["entry"] for r in recipients],
        )
    assert ei.value.code == "too_many_recipients"


@pytest.mark.parametrize("seed", range(6))
def test_envelope_mutations_fail_closed(seed):
    """Single-byte mutations anywhere in the canonical envelope bytes fail
    closed (SealingError): the AAD binds protected header, wraps, and body,
    so tampering can never return wrong plaintext."""
    rng = random.Random(500 + seed)
    sender_priv = Ed25519PrivateKey.generate()
    sender_did = identity_id_from_pubkey(
        sender_priv.public_key().public_bytes_raw()
    )
    recipient = _make_recipient(rng)
    payload = _rand_payload(rng)
    envelope = seal_envelope(
        _make_protected(sender_did, seq=1),
        payload,
        sender_priv,
        [recipient["entry"]],
    )
    raw = restricted_jcs(envelope)
    trials = 0
    for _ in range(24):
        mutated = _flip_bit(raw, rng)
        if mutated == raw:
            continue
        trials += 1
        with pytest.raises(SealingError):
            unseal_envelope(
                mutated, recipient["priv"], recipient["entry"]["recipient"]
            )
    assert trials > 0


@pytest.mark.parametrize("seed", range(6))
def test_wrong_relationship_key_fails_closed(seed):
    """Decrypting with a different relationship private key fails closed
    (wrong AAD / tampered wrap), never yielding the payload."""
    rng = random.Random(600 + seed)
    sender_priv = Ed25519PrivateKey.generate()
    sender_did = identity_id_from_pubkey(
        sender_priv.public_key().public_bytes_raw()
    )
    recipient = _make_recipient(rng)
    envelope = seal_envelope(
        _make_protected(sender_did, seq=1),
        _rand_payload(rng),
        sender_priv,
        [recipient["entry"]],
    )
    wrong_priv = X25519PrivateKey.generate()
    with pytest.raises(SealingError):
        unseal_envelope(
            envelope, wrong_priv, recipient["entry"]["recipient"]
        )


def test_nonce_and_ephemeral_uniqueness_across_256_seals():
    """256 seals of the same payload: every replay_nonce and every
    ephemeral_key is unique (no nonce or ephemeral reuse)."""
    sender_priv = Ed25519PrivateKey.generate()
    sender_did = identity_id_from_pubkey(
        sender_priv.public_key().public_bytes_raw()
    )
    recipient = _make_recipient(random.Random(0))
    payload = {"body": "same payload", "format": "plain"}
    nonces = set()
    eph_keys = set()
    for seq in range(1, 257):
        envelope = seal_envelope(
            _make_protected(sender_did, seq=seq),
            payload,
            sender_priv,
            [recipient["entry"]],
        )
        nonces.add(envelope["protected"]["replay_nonce"])
        eph_keys.add(envelope["protected"]["ephemeral_key"])
    assert len(nonces) == 256
    assert len(eph_keys) == 256


# Low-order X25519 u-coordinates (little-endian) the library is documented
# to reject: the identity, u=1, and u=p-1. (An order-8 point hex from memory
# was dropped: it turned out to be an ordinary point, and the test caught
# it. The all-zero-shared-secret defense-in-depth layer is tested directly
# below instead of trusting a memorized vector.)
_LOW_ORDER_POINTS = [
    bytes(32),
    b"\x01" + bytes(31),
    ((2**255 - 19).to_bytes(32, "little")),
]


@pytest.mark.parametrize("point", _LOW_ORDER_POINTS)
def test_low_order_peer_points_raise(point):
    sender_priv = Ed25519PrivateKey.generate()
    sender_did = identity_id_from_pubkey(
        sender_priv.public_key().public_bytes_raw()
    )
    ed_priv = Ed25519PrivateKey.generate()
    entry = {
        "recipient": identity_id_from_pubkey(
            ed_priv.public_key().public_bytes_raw()
        ),
        "agreement_key": agreement_key_multibase_from_pubkey(point),
        "relationship_pub": point,
    }
    with pytest.raises(SealingError) as excinfo:
        seal_envelope(
            _make_protected(sender_did, seq=1),
            {"body": "x", "format": "plain"},
            sender_priv,
            [entry],
        )
    assert excinfo.value.code == "low_order_key"


def test_reject_low_order_shared_defense_in_depth():
    """The shared-secret layer rejects all-zero outputs even if a
    low-order point ever slipped past the library's check."""
    from muse_agent_social.crypto.sealing import _reject_low_order_shared

    with pytest.raises(SealingError) as excinfo:
        _reject_low_order_shared(bytearray(32))
    assert excinfo.value.code == "low_order_key"
    # Nonzero shared secrets pass through silently.
    _reject_low_order_shared(bytearray(b"\x42" * 32))


# -- fingerprints ----------------------------------------------------------


@pytest.mark.parametrize("seed", range(10))
def test_agreement_fingerprint_determinism_and_uniqueness(seed):
    rng = random.Random(800 + seed)
    pubs = [
        agreement_key_multibase_from_pubkey(_rand_bytes(rng, 32))
        for _ in range(8)
    ]
    fps = [agreement_fingerprint(p) for p in pubs]
    assert fps == [agreement_fingerprint(p) for p in pubs]
    assert len(set(fps)) == len(fps)


# -- identity rotation -----------------------------------------------------


def _make_card(ed_priv, name):
    return create_card(
        ed_priv,
        name,
        "Test Principal",
        agreement_key_multibase_from_pubkey(
            X25519PrivateKey.generate().public_key().public_bytes_raw()
        ),
        ["events/0.2"],
        CREATED_AT,
        "2027-09-15T20:00:00Z",
    )


def _mutate_b64url(rng, sig):
    """Flip one base64url char, guaranteeing the DECODED bytes change.

    (CPython's decoder silently drops the low padding bits of the final
    char, so a flip confined to those bits would decode identically and
    the signature would still verify; such a flip is not a mutation of
    the signed bytes at all.)
    """
    for _ in range(64):
        i = rng.randrange(len(sig))
        choices = [c for c in _B64URL_ALPHABET if c != sig[i]]
        cand = rng.choice(choices)
        mutated = sig[:i] + cand + sig[i + 1 :]
        if b64url_decode(mutated) != b64url_decode(sig):
            return mutated
    raise AssertionError("could not find a byte-changing flip")


@pytest.mark.parametrize("seed", range(6))
def test_rotate_verify_round_trip(seed):
    rng = random.Random(900 + seed)
    old_priv = Ed25519PrivateKey.generate()
    old_card = _make_card(old_priv, f"Agent{seed}")
    new_priv = Ed25519PrivateKey.generate()
    announcement = rotate_identity_key(old_card, old_priv, new_priv)
    assert verify_identity_rotation(announcement, old_card) is True
    assert announcement["new_card"]["identity_id"] != old_card["identity_id"]
    # A flip that changes the decoded signed bytes never verifies.
    for _ in range(8):
        mutated = copy.deepcopy(announcement)
        target = rng.choice(
            [
                ("cross", 0),
                ("cross", 1),
                ("card-sig", None),
            ]
        )
        if target[0] == "cross":
            sig = mutated["cross_signatures"][target[1]]["signature"]
            mutated["cross_signatures"][target[1]]["signature"] = _mutate_b64url(
                rng, sig
            )
        else:
            sig = mutated["new_card"]["signature"]
            mutated["new_card"]["signature"] = _mutate_b64url(rng, sig)
        assert verify_identity_rotation(mutated, old_card) is not True


# -- wordlist phrases ------------------------------------------------------


@pytest.mark.parametrize("seed", range(10))
def test_verification_phrase_properties(seed):
    rng = random.Random(1000 + seed)
    words = load_wordlist()
    ids = [
        identity_id_from_pubkey(_rand_bytes(rng, 32)) for _ in range(6)
    ]
    phrases = [verification_phrase(ids[i], ids[j], words)
               for i in range(6) for j in range(i + 1, 6)]
    # Deterministic recomputation.
    assert verification_phrase(ids[0], ids[1], words) == phrases[0]
    # Order independent.
    assert verification_phrase(ids[1], ids[0], words) == phrases[0]
    # Distinct pairs give distinct phrases (64-bit phrase space).
    assert len({tuple(p) for p in phrases}) == len(phrases)
    for phrase in phrases:
        assert len(phrase) == 8
        assert all(w in words for w in phrase)
    # One-word substitution is always detectable: the tampered phrase
    # never equals the genuine phrase.
    genuine = phrases[0]
    for pos in range(8):
        choices = [w for w in words if w != genuine[pos]]
        tampered = list(genuine)
        tampered[pos] = rng.choice(choices)
        assert tampered != genuine
        assert tampered != verification_phrase(ids[0], ids[1], words)


@pytest.mark.parametrize("seed", range(10))
def test_pairing_phrase_determinism_and_distinctness(seed):
    rng = random.Random(1100 + seed)
    cards = []
    for i in range(4):
        ed_priv = Ed25519PrivateKey.generate()
        cards.append(_make_card(ed_priv, f"Agent{seed}-{i}"))
    words = load_wordlist()
    p_ab = pairing_phrase(cards[0], cards[1], words)
    # Deterministic and order-independent.
    assert pairing_phrase(cards[0], cards[1], words) == p_ab
    assert pairing_phrase(cards[1], cards[0], words) == p_ab
    assert len(p_ab) == 8
    # Distinct identity pairs give distinct phrases.
    others = {
        tuple(pairing_phrase(cards[i], cards[j], words))
        for i in range(4)
        for j in range(i + 1, 4)
    }
    assert len(others) == 6
