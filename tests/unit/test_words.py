"""Unit tests for the eight-word verification phrase and its wordlist."""

from __future__ import annotations

import hashlib

import pytest

from muse_agent_social.crypto.identity import derive_identity_hierarchy
from muse_agent_social.crypto.words import (
    load_wordlist,
    verification_phrase,
    wordlist_path,
    wordlist_sha256,
)

# Pinned digest of verify-words-v1.txt (file bytes). Changing the list
# requires a deliberate, reviewed update of this pin and the filename version.
PINNED_WORDLIST_SHA256 = "586805a8b76cc82c66ecdb542fb9d8c3fd1ca319b3b6352371d3bc8f0e715f83"

# Fixed TEST ONLY identities.
_H_A = derive_identity_hierarchy(bytes(range(32)))
_H_B = derive_identity_hierarchy(bytes([7]) * 32)
_H_C = derive_identity_hierarchy(bytes([9]) * 32)


def _words():
    return load_wordlist()


def test_wordlist_has_exactly_256_unique_words():
    words = _words()
    assert len(words) == 256
    assert len(set(words)) == 256


def test_wordlist_words_are_simple_lowercase_ascii():
    for word in _words():
        assert word, "no blank lines"
        assert word == word.lower()
        assert word.isascii() and word.isalpha()


def test_wordlist_sha256_pinned():
    assert wordlist_sha256() == PINNED_WORDLIST_SHA256
    path = wordlist_path()
    with open(path, "rb") as fh:
        assert hashlib.sha256(fh.read()).hexdigest() == PINNED_WORDLIST_SHA256


def test_wordlist_rejects_bad_files(tmp_path):
    bad = tmp_path / "words.txt"
    bad.write_text("only\nthree\nwords\n")
    with pytest.raises(ValueError):
        load_wordlist(str(bad))
    bad.write_text("amber\namber\n" + "\n".join(f"w{i}" for i in range(254)) + "\n")
    with pytest.raises(ValueError):
        load_wordlist(str(bad))


def test_phrase_is_eight_words_from_list():
    words = _words()
    phrase = verification_phrase(_H_A.identity_id, _H_B.identity_id, words)
    assert len(phrase) == 8
    assert all(w in words for w in phrase)


def test_phrase_order_independent():
    words = _words()
    ab = verification_phrase(_H_A.identity_id, _H_B.identity_id, words)
    ba = verification_phrase(_H_B.identity_id, _H_A.identity_id, words)
    assert ab == ba


def test_phrase_changes_when_either_key_changes():
    words = _words()
    ab = verification_phrase(_H_A.identity_id, _H_B.identity_id, words)
    ac = verification_phrase(_H_A.identity_id, _H_C.identity_id, words)
    cb = verification_phrase(_H_C.identity_id, _H_B.identity_id, words)
    assert ab != ac
    assert ab != cb


def test_phrase_deterministic():
    words = _words()
    first = verification_phrase(_H_A.identity_id, _H_B.identity_id, words)
    assert verification_phrase(_H_A.identity_id, _H_B.identity_id, words) == first


def test_phrase_self_pairing_works():
    words = _words()
    phrase = verification_phrase(_H_A.identity_id, _H_A.identity_id, words)
    assert len(phrase) == 8


def test_phrase_rejects_bad_identity_ids():
    words = _words()
    with pytest.raises(ValueError):
        verification_phrase("did:key:zbogus", _H_B.identity_id, words)
    with pytest.raises(ValueError):
        verification_phrase(_H_A.identity_id, _H_B.identity_id, words[:100])


def test_phrase_matches_plan_construction():
    """Independent re-implementation of the plan's formula."""
    words = _words()
    from muse_agent_social.crypto.identity import parse_identity_id

    a = parse_identity_id(_H_A.identity_id)
    b = parse_identity_id(_H_B.identity_id)
    lo, hi = (a, b) if a <= b else (b, a)
    digest = hashlib.sha256(b"muse-agent-social/verify-v1" + lo + hi).digest()
    expected = [words[i] for i in digest[:8]]
    assert verification_phrase(_H_B.identity_id, _H_A.identity_id, words) == expected
