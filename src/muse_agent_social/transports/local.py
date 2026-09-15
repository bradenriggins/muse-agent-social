"""Directory-based transport adapter for tests and local demos.

Layout under <dir>/:
    incoming/<name>.json   objects waiting to be fetched
    consumed/<name>.json   objects moved here by consume()
    quarantine/<name>.json objects the receiver quarantined (written by the
                           receive path, not by this adapter)

All writes are atomic (tmp file + fsync + rename). consume() is idempotent.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
from pathlib import Path

from .base import OBJECT_MAX_BYTES, Transport, TransportError

# base64url(24 random bytes) -> 32 chars, plus ".json". No timestamps, no
# event IDs, no sender info in the name.
OBJECT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{32}\.json$")


def check_object_name(name: str) -> str:
    """Validate a relay object name; raise TransportError if malformed."""
    if not OBJECT_NAME_RE.match(name):
        raise TransportError(
            "config_error",
            f"invalid relay object name: {name!r}",
            retryable=False,
        )
    return name


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".tmp-{os.getpid()}-{threading.get_ident()}"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def check_object_size(object_name: str, size_bytes: int) -> int:
    """Pre-read size gate: reject over-cap objects before buffering.

    Takes the size from metadata (stat() / git cat-file -s) so callers can
    enforce OBJECT_MAX_BYTES without ever reading the object content: a
    hostile multi-GB blob must never be buffered into memory. Raises
    TransportError('object_too_large') (non-retryable) when *size_bytes*
    exceeds OBJECT_MAX_BYTES; returns *size_bytes* otherwise.
    """
    if size_bytes > OBJECT_MAX_BYTES:
        raise TransportError(
            "object_too_large",
            f"object {object_name} is {size_bytes} bytes; "
            f"limit is {OBJECT_MAX_BYTES}",
            retryable=False,
        )
    return size_bytes


class LocalTransport(Transport):
    """Filesystem transport. Two agents (or tests) share a directory."""

    def __init__(self, directory: str | Path) -> None:
        self.root = Path(directory).resolve()
        self.incoming = self.root / "incoming"
        self.consumed = self.root / "consumed"
        self.quarantine_dir = self.root / "quarantine"
        for sub in (self.incoming, self.consumed, self.quarantine_dir):
            sub.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # -- Transport interface -------------------------------------------
    def head(self) -> str:
        """Marker over the current incoming set: sha256 of sorted entries."""
        digest = hashlib.sha256()
        for path in sorted(self.incoming.glob("*.json")):
            stat = path.stat()
            digest.update(path.name.encode("ascii"))
            digest.update(b"\x00")
            digest.update(str(stat.st_size).encode("ascii"))
            digest.update(b"\x00")
        return digest.hexdigest()

    def changed(self, since_head: str) -> bool:
        return self.head() != since_head

    def fetch_new(self, since: str) -> list[tuple[str, bytes]]:
        if since and since == self.head():
            return []
        items: list[tuple[str, bytes]] = []
        for path in sorted(self.incoming.glob("*.json")):
            # Size pre-check from stat() metadata BEFORE read_bytes(): an
            # over-cap object is rejected without ever being buffered.
            check_object_size(path.name, path.stat().st_size)
            items.append((path.name, path.read_bytes()))
        return items

    def upload(self, object_name: str, data: bytes) -> None:
        check_object_name(object_name)
        if len(data) > OBJECT_MAX_BYTES:
            raise TransportError(
                "object_too_large",
                f"object {object_name} is {len(data)} bytes; "
                f"limit is {OBJECT_MAX_BYTES}",
                retryable=False,
            )
        _atomic_write(self.incoming / object_name, data)

    def consume(self, object_name: str) -> None:
        check_object_name(object_name)
        src = self.incoming / object_name
        with self._lock:
            if not src.exists():
                return  # idempotent: already consumed
            _atomic_write(self.consumed / object_name, src.read_bytes())
            src.unlink()

    # -- test/demo helpers (not part of the Transport interface) --------
    def quarantine(self, object_name: str, data: bytes) -> None:
        """Copy a hostile/malformed object aside locally, then consume it."""
        check_object_name(object_name)
        _atomic_write(self.quarantine_dir / object_name, data)
        self.consume(object_name)

    def reset(self) -> None:
        """Remove all objects (test helper)."""
        for sub in (self.incoming, self.consumed, self.quarantine_dir):
            for path in sub.glob("*.json"):
                path.unlink()
