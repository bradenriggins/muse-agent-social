"""Abstract transport interface for Muse Agent Social v0.2.

The transport layer moves opaque sealed objects between the local agent and
a relay. It never sees plaintext semantics: every object is an opaque byte
string produced by the sealing layer. The transport never decides identity,
consent, ordering, retention, delivery policy, or surfacing; it stores
opaque sealed objects and reports transport outcomes.

Plan constants (GIT TRANSPORT, WATCHER CONTRACT) are defined here as
module-level values. They mirror the values that will live in
policy/limits.py (a parallel track); when that module lands, these must be
replaced by imports from it. See INTERFACE.md.
"""

from __future__ import annotations

import fcntl
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

# ---------------------------------------------------------------------------
# Plan constants (GIT TRANSPORT section). Canonical values live in
# policy/limits.py; the names below are kept as aliases so transport code
# and tests keep working against a single source of truth.
# ---------------------------------------------------------------------------
from muse_agent_social.policy.limits import (
    MAX_ENVELOPE_BYTES as OBJECT_MAX_BYTES,
)
from muse_agent_social.policy.limits import (
    MAX_PUSHES_PER_MINUTE as PUSH_HARD_CEILING_PER_MINUTE,
)
from muse_agent_social.policy.limits import (
    MIN_POLL_SECONDS as POLL_INTERVAL_SECONDS,
)
from muse_agent_social.policy.limits import (
    REPO_SIZE_BLOCK_BYTES as REPO_BLOCK_BYTES,
)
from muse_agent_social.policy.limits import (
    REPO_SIZE_ROTATE_BYTES as REPO_ROTATE_BYTES,
)
from muse_agent_social.policy.limits import (
    REPO_SIZE_WARN_BYTES as REPO_WARN_BYTES,
)
from muse_agent_social.policy.limits import (
    SOFT_PUSH_TARGET_PER_MINUTE,
)
from muse_agent_social.policy.limits import (
    FETCH_MAX_OBJECTS,
    FETCH_MAX_AGGREGATE_BYTES,
)

PUSH_SOFT_INTERVAL_SECONDS = 60 // SOFT_PUSH_TARGET_PER_MINUTE  # 1 push/min soft
LOCK_TIMEOUT_SECONDS = 30  # mirror lock acquisition timeout
PUSH_MAX_ATTEMPTS = 3  # push retry attempts before preserving queue


def new_stream_stats() -> dict[str, Any]:
    """Fresh stats dict for fetch_new_stream implementations."""
    return {
        "objects_streamed": 0,
        "bytes_streamed": 0,
        "truncated": False,
        "truncation_reason": None,
    }


class TransportError(Exception):
    """Transport failure with a stable machine-readable code.

    Attributes:
        code: stable snake_case code, e.g. 'lock_timeout', 'push_failed'.
        retryable: True when the caller should back off and retry.
        detail: optional extra context (never secret material).
    """

    # Stable codes mapped to watcher exit codes. Codes not listed here map
    # to 20 when retryable, 21 when permanent.
    _EXIT_BY_CODE = {
        "lock_timeout": 22,
        "rotation_required": 21,
        "object_too_large": 21,
        "config_error": 21,
        "schema_error": 21,
    }

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = True,
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.detail = detail

    @property
    def exit_code(self) -> int:
        """Watcher exit code for this failure (0/20/21/22/23 contract)."""
        if self.code in self._EXIT_BY_CODE:
            return self._EXIT_BY_CODE[self.code]
        return 20 if self.retryable else 21

    def __str__(self) -> str:  # pragma: no cover - trivial
        base = f"[{self.code}] {super().__str__()}"
        return f"{base} ({self.detail})" if self.detail else base


class RotationRequired(TransportError):
    """Repository hit the 500 MiB rotation threshold.

    Raised instead of committing or pushing further. The caller must run the
    explicit relay-rotation migration; the queued mutations are preserved.
    """

    def __init__(self, size_bytes: int, detail: str | None = None) -> None:
        super().__init__(
            "rotation_required",
            f"relay repository size {size_bytes} bytes exceeds the "
            f"{REPO_ROTATE_BYTES} byte rotation threshold; refusing to "
            "commit or push until the relay is rotated",
            retryable=False,
            detail=detail,
        )
        self.size_bytes = size_bytes


# ---------------------------------------------------------------------------
# Mirror lock: one flock owns the mirror. Every fetch, reset, read, move,
# commit, rebase, and push runs under it. Reentrant within this process so a
# Reentrant per thread within this process: a thread that already holds the
# lock may re-acquire it (watcher holds it while transport methods lock).
# Keyed by (thread ident, path) so cross-thread contention still blocks.
_lock_registry: dict[tuple[int, str], list] = {}


@contextmanager
def mirror_lock(
    state_dir: str | Path,
    relationship_id: str,
    timeout: float = LOCK_TIMEOUT_SECONDS,
) -> Iterator[None]:
    """Hold an exclusive flock on <state>/locks/<relationship_id>.lock.

    Raises TransportError('lock_timeout') (watcher exit 22) when the lock
    cannot be acquired within `timeout` seconds. timeout=0 tries once.
    """
    lock_path = Path(state_dir).resolve() / "locks" / f"{relationship_id}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    key = (threading.get_ident(), str(lock_path))

    entry = _lock_registry.get(key)
    if entry is not None:
        entry[1] += 1
        try:
            yield
        finally:
            entry[1] -= 1
            if entry[1] <= 0:
                try:
                    fcntl.flock(entry[0], fcntl.LOCK_UN)
                    entry[0].close()
                finally:
                    _lock_registry.pop(key, None)
        return

    fd = open(lock_path, "w")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    fd.close()
                    raise TransportError(
                        "lock_timeout",
                        f"mirror lock busy for relationship {relationship_id} "
                        f"after {timeout}s",
                        retryable=True,
                        detail=key,
                    ) from None
                time.sleep(0.05)
        _lock_registry[key] = [fd, 1]
        try:
            yield
        finally:
            entry = _lock_registry.pop(key, None)
            if entry is not None:
                fcntl.flock(entry[0], fcntl.LOCK_UN)
                entry[0].close()
    except BaseException:
        # If we registered and something above failed before registration,
        # make sure the fd is not leaked. Registration happens before yield,
        # so a failure here means we never locked; close the fd.
        if key not in _lock_registry:
            try:
                fd.close()
            except OSError:
                pass
        raise


class Transport:
    """Abstract relay transport. All payloads are opaque bytes.

    Implementations must be safe to call with arbitrary bytes; they must
    never parse, decrypt, or otherwise interpret object content.
    """

    def head(self) -> str:
        """Return the current remote HEAD marker (opaque string)."""
        raise NotImplementedError

    def changed(self, since_head: str) -> bool:
        """True when the remote HEAD differs from `since_head`."""
        raise NotImplementedError

    def fetch_new(self, since: str) -> list[tuple[str, bytes]]:
        """Return [(object_name, bytes)] for objects newer than `since`.

        `since` is a marker previously returned by head(). An empty marker
        means "everything currently present". Order is unspecified; the
        protocol (per-sender sequence) defines conversation order, not the
        transport.
        """
        raise NotImplementedError

    def fetch_new_stream(
        self,
        since: str,
        visit: Callable[[str, bytes], bool],
    ) -> dict[str, Any]:
        """Stream objects newer than `since`, visiting each as it is fetched.

        ``visit(name, data)`` runs AS each object is fetched, so the whole
        batch is never materialized: this is the memory-safe way to consume
        a relay. ``visit`` returns True to continue, False to stop early
        (e.g. the caller's time budget is spent); the transport stops
        fetching as soon as it is told to.

        Returns a stats dict: ``{"objects_streamed": int,
        "bytes_streamed": int, "truncated": bool, "truncation_reason":
        str | None}``. ``truncated`` is True when the stream stopped before
        exhausting the relay: the caller asked to stop (``"caller_stopped"``)
        or a documented bound was hit (``"object_cap"``,
        ``"aggregate_bytes_cap"``).

        Hard bounds per call, independent of the visitor: at most
        FETCH_MAX_OBJECTS objects and at most FETCH_MAX_AGGREGATE_BYTES
        total bytes are ever delivered; hitting either stops the stream
        with ``truncated=True``. A relay that exceeds them is hostile or
        pathological, and the truncation is reported loudly rather than
        buffered into the watcher process.

        The default implementation delegates to fetch_new (buffered, but
        still capped); transports that can page SHOULD override so objects
        are processed per-fetch.
        """
        stats = new_stream_stats()
        for name, data in self.fetch_new(since):
            if stats["objects_streamed"] >= FETCH_MAX_OBJECTS:
                stats["truncated"] = True
                stats["truncation_reason"] = "object_cap"
                break
            # An exact-cap total is allowed; only exceeding it truncates.
            if stats["bytes_streamed"] + len(data) > FETCH_MAX_AGGREGATE_BYTES:
                stats["truncated"] = True
                stats["truncation_reason"] = "aggregate_bytes_cap"
                break
            stats["objects_streamed"] += 1
            stats["bytes_streamed"] += len(data)
            if visit(name, data) is False:
                stats["truncated"] = True
                stats["truncation_reason"] = "caller_stopped"
                break
        return stats

    def upload(self, object_name: str, data: bytes) -> None:
        """Store a new object on the relay."""
        raise NotImplementedError

    def consume(self, object_name: str) -> None:
        """Move an object to consumed (idempotent).

        After a crash between the receive commit and consume, retrying must
        see the committed event and perform only the consume operation, so
        consuming an already-consumed or missing object is success.
        """
        raise NotImplementedError

    def pending_outgoing(self) -> int:
        """Number of locally queued outgoing mutations not yet pushed."""
        return 0

    def flush(self) -> dict:
        """Push queued outgoing mutations. Returns a result dict.

        Default is a no-op for transports with no queue. Result dicts carry
        counts, ids, durations, and reason codes only, never content.
        """
        return {"status": "noop", "pushed": 0}
