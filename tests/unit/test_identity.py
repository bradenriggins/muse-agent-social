"""Unit tests for the v0.2 identity key hierarchy and did:key identifiers.

Golden vectors use a FIXED, PUBLIC, TEST ONLY master seed (bytes 0..31).
They assert exact derivation outputs and must never be treated as real keys.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from muse_agent_social.crypto.identity import (
    agreement_key_multibase_from_pubkey,
    derive_identity_hierarchy,
    generate_master_seed,
    identity_id_from_pubkey,
    parse_agreement_key,
    parse_identity_id,
    store_master_seed,
)

ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Golden vectors (TEST ONLY seed = bytes(range(32)))
# ---------------------------------------------------------------------------

TEST_SEED = bytes(range(32))

GOLDEN_ED25519_SEED = "693d30a5d9e7fcb825a3808f5cbdd5dd76c616a384b9c043cda968c33d6f80a4"
GOLDEN_X25519_BOOTSTRAP = "197767dbb1871a41e0c9caa301ab40b9a7b7605997c84e1b86f909bb32128e33"
GOLDEN_LOCAL_STORE_KEY = "d69edf013391bfc2f619d67a834ae644a6d617bb760ef9d256d573244ab9aad9"
GOLDEN_ED25519_PUB = "a263cb062c240cd9244fb2c0860fe24f55218cf288e8253797ab9639bd6f9848"
GOLDEN_X25519_PUB = "e4721e8bcdd13e95093f32cb3d757e2eb77238ff6ea033c352382c71fc6ee056"
GOLDEN_IDENTITY_ID = "did:key:z6MkqPAMFgL7xwS7w26cXTA43N36s98k5BYEJTMz4KM62L8F"
GOLDEN_AGREEMENT_MULTIBASE = "z6LSs3w3j2mohaaTU1D4QU5cHYrv6VcKskNrg7pXM2zgker1"


def _hierarchy():
    return derive_identity_hierarchy(TEST_SEED)


def test_golden_derived_keys():
    h = _hierarchy()
    assert h._ed25519_seed.hex() == GOLDEN_ED25519_SEED
    assert h._x25519_bootstrap.hex() == GOLDEN_X25519_BOOTSTRAP
    assert h.local_store_key.hex() == GOLDEN_LOCAL_STORE_KEY


def test_golden_public_keys():
    h = _hierarchy()
    assert h.ed25519_public_bytes.hex() == GOLDEN_ED25519_PUB
    assert h.x25519_public_bytes.hex() == GOLDEN_X25519_PUB


def test_golden_identity_id():
    h = _hierarchy()
    assert h.identity_id == GOLDEN_IDENTITY_ID
    assert h.agreement_key_multibase == GOLDEN_AGREEMENT_MULTIBASE


def test_golden_identity_id_form_matches_plan_example():
    # did:key Ed25519 identifiers start with "did:key:z6Mk" (multibase base58btc
    # of the 0xED01 multicodec prefix), per the did:key spec's example form.
    assert GOLDEN_IDENTITY_ID.startswith("did:key:z6Mk")
    assert GOLDEN_AGREEMENT_MULTIBASE.startswith("z6LS")


def test_golden_vectors_match_across_two_processes():
    """Checkpoint 4 gate: golden vectors are deterministic across processes."""
    code = (
        "from muse_agent_social.crypto.identity import derive_identity_hierarchy;"
        "h = derive_identity_hierarchy(bytes(range(32)));"
        "print(h.identity_id);"
        "print(h.agreement_key_multibase);"
        "print(h.ed25519_public_bytes.hex());"
        "print(h.x25519_public_bytes.hex());"
        "print(h._ed25519_seed.hex());"
        "print(h._x25519_bootstrap.hex());"
        "print(h.local_store_key.hex())"
    )
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
        check=True,
    )
    lines = proc.stdout.split()
    assert lines[0] == GOLDEN_IDENTITY_ID
    assert lines[1] == GOLDEN_AGREEMENT_MULTIBASE
    assert lines[2] == GOLDEN_ED25519_PUB
    assert lines[3] == GOLDEN_X25519_PUB
    assert lines[4] == GOLDEN_ED25519_SEED
    assert lines[5] == GOLDEN_X25519_BOOTSTRAP
    assert lines[6] == GOLDEN_LOCAL_STORE_KEY


# ---------------------------------------------------------------------------
# Master seed handling
# ---------------------------------------------------------------------------

def test_generate_master_seed_is_32_random_bytes():
    a = generate_master_seed()
    b = generate_master_seed()
    assert len(a) == 32 and len(b) == 32
    assert a != b


def test_store_master_seed_mode_0600_and_roundtrip(tmp_path):
    path = tmp_path / "master.seed"
    store_master_seed(path, TEST_SEED)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes() == TEST_SEED


def test_store_master_seed_refuses_to_overwrite(tmp_path):
    path = tmp_path / "master.seed"
    store_master_seed(path, TEST_SEED)
    with pytest.raises(FileExistsError):
        store_master_seed(path, os.urandom(32))
    # Original seed untouched.
    assert path.read_bytes() == TEST_SEED


def test_store_master_seed_rejects_wrong_length(tmp_path):
    with pytest.raises(ValueError):
        store_master_seed(tmp_path / "x.seed", b"short")


def test_derive_rejects_wrong_seed_length():
    with pytest.raises(ValueError):
        derive_identity_hierarchy(b"short")


# ---------------------------------------------------------------------------
# Purpose separation
# ---------------------------------------------------------------------------

def test_each_purpose_gets_a_distinct_key():
    h = _hierarchy()
    keys = {h._ed25519_seed, h._x25519_bootstrap, h.local_store_key}
    assert len(keys) == 3


def test_derivation_is_deterministic_but_seed_sensitive():
    h1 = derive_identity_hierarchy(TEST_SEED)
    h2 = derive_identity_hierarchy(TEST_SEED)
    assert h1.identity_id == h2.identity_id
    other = derive_identity_hierarchy(bytes([1]) + bytes(range(1, 32)))
    assert other.identity_id != h1.identity_id
    assert other.local_store_key != h1.local_store_key


# ---------------------------------------------------------------------------
# did:key construction and parsing
# ---------------------------------------------------------------------------

def test_identity_id_roundtrip():
    h = _hierarchy()
    assert parse_identity_id(h.identity_id) == h.ed25519_public_bytes


def test_agreement_key_roundtrip():
    h = _hierarchy()
    assert parse_agreement_key(h.agreement_key_multibase) == h.x25519_public_bytes


def test_builders_validate_pubkey_length():
    with pytest.raises(ValueError):
        identity_id_from_pubkey(b"short")
    with pytest.raises(ValueError):
        agreement_key_multibase_from_pubkey(b"\x00" * 33)


@pytest.mark.parametrize(
    "bad",
    [
        "did:key:z6MkqPAMFgL7xwS7w26cXTA43N36s98k5BYEJTMz4KM62L",  # truncated
        "did:key:Z6MkqPAMFgL7xwS7w26cXTA43N36s98k5BYEJTMz4KM62L8F",  # bad multibase code
        "did:key:z6MkqPAMFgL7xwS7w26cXTA43N36s98k5BYEJTMz4KM62L8!",  # bad base58 char
        "did:key:z6LSs3w3j2mohaaTU1D4QU5cHYrv6VcKskNrg7pXM2zgker1",  # X25519 multicodec
        "did:key:QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",  # wrong method
        "did:key:z",  # empty payload
        "",  # empty
        "not-a-did",  # wrong prefix
        None,  # not a string
    ],
)
def test_parse_identity_id_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_identity_id(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "6LSs3w3j2mohaaTU1D4QU5cHYrv6VcKskNrg7pXM2zgker1",  # missing z
        "x6LSs3w3j2mohaaTU1D4QU5cHYrv6VcKskNrg7pXM2zgker1",  # wrong multibase code
        "z6LSs3w3j2mohaaTU1D4QU5cHYrv6VcKskNrg7pXM2zgker!",  # bad base58 char
        "z6MkqPAMFgL7xwS7w26cXTA43N36s98k5BYEJTMz4KM62L8F",  # Ed25519 multicodec
        "z",  # empty payload
        "",
        None,
    ],
)
def test_parse_agreement_key_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_agreement_key(bad)


def test_sign_verify_smoke():
    h = _hierarchy()
    sig = h.sign(b"hello")
    assert len(sig) == 64
    h.ed25519_private.public_key().verify(sig, b"hello")
