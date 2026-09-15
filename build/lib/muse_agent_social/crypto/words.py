"""Eight-word verification phrases for Muse Agent Social v0.2.

Implements the VERIFICATION section of the implementation plan: eight words
bind both identities without a directory.

    A = raw Ed25519 public key from inviter identity_id
    B = raw Ed25519 public key from acceptor identity_id
    ordered = min(A, B) || max(A, B)      # unsigned byte order
    input = UTF8("muse-agent-social/verify-v1") || ordered
    digest = SHA-256(input)
    indices = digest[0:8]                 # eight 8-bit values
    phrase = WORDLIST[indices[0]] ... WORDLIST[indices[7]]

Both agents compute the same phrase because the keys are sorted before
hashing. Humans compare all eight words over a second trusted channel; a
mismatch aborts and burns the invite. The phrase is 64 bits. The words are
never stored as an authenticator.
"""

from __future__ import annotations

import hashlib
import importlib.resources
from typing import Sequence

from .identity import parse_identity_id

_VERIFY_DOMAIN = b"muse-agent-social/verify-v1"
_WORDLIST_RESOURCE = "verify-words-v1.txt"
_WORDLIST_SIZE = 256
_PHRASE_LEN = 8


def wordlist_path() -> str:
    """Filesystem path of the shipped ``verify-words-v1.txt``."""
    ref = importlib.resources.files("muse_agent_social.data").joinpath(
        _WORDLIST_RESOURCE
    )
    return str(ref)


def load_wordlist(path: str | None = None) -> list[str]:
    """Load and validate the 256-word verification wordlist.

    Enforces exactly 256 lines, one word per line, no blank lines, all
    distinct lowercase ASCII words. Raises ValueError on any violation.
    """
    path = path or wordlist_path()
    with open(path, "r", encoding="ascii") as fh:
        text = fh.read()
    if not text.endswith("\n"):
        raise ValueError("wordlist must end with a newline")
    words = text.split("\n")[:-1]
    if any(not w for w in words):
        raise ValueError("wordlist must not contain blank lines")
    if len(words) != _WORDLIST_SIZE:
        raise ValueError(
            f"wordlist must have exactly {_WORDLIST_SIZE} words, got {len(words)}"
        )
    if len(set(words)) != _WORDLIST_SIZE:
        raise ValueError("wordlist words must be distinct")
    for word in words:
        if word != word.lower() or not word.isascii() or not word.isalpha():
            raise ValueError(f"wordlist word {word!r} is not simple lowercase ASCII")
    return words


def wordlist_sha256(path: str | None = None) -> str:
    """Hex SHA-256 of the wordlist file bytes, for pinning in tests."""
    path = path or wordlist_path()
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def verification_phrase(
    identity_id_a: str,
    identity_id_b: str,
    wordlist: Sequence[str],
) -> list[str]:
    """Compute the eight-word verification phrase binding two identities.

    *identity_id_a* and *identity_id_b* are did:key identity IDs. The raw
    Ed25519 public keys are parsed, sorted in unsigned byte order, and hashed
    with the verification domain separator; the first eight digest bytes index
    the 256-word list. Both input orders produce the same phrase.

    Raises ValueError if either identity ID is malformed or the wordlist does
    not have exactly 256 entries.
    """
    words = list(wordlist)
    if len(words) != _WORDLIST_SIZE:
        raise ValueError(
            f"wordlist must have exactly {_WORDLIST_SIZE} entries, got {len(words)}"
        )
    key_a = parse_identity_id(identity_id_a)
    key_b = parse_identity_id(identity_id_b)
    lo, hi = (key_a, key_b) if key_a <= key_b else (key_b, key_a)
    digest = hashlib.sha256(_VERIFY_DOMAIN + lo + hi).digest()
    return [words[b] for b in digest[:_PHRASE_LEN]]
