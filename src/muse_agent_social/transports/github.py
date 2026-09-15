"""Git-based relay transport (git-CLI subprocess adapter).

Mirror layout under <state>/:
    mirrors/<relationship_id>/   git working clone of the relay repository
    locks/<relationship_id>.lock flock: one lock owns every fetch, reset,
                                 read, move, commit, rebase, and push

Relay repository layout (single branch, default "main"):
    incoming/<name>.json         sealed objects awaiting fetch

Consumed objects are deleted from the repository (git rm via replay) and
pushed; this keeps the relay small. The transport never parses object
bytes.

Queued-mutation interface (called by the send and receive paths):
    queue_mutation(conn, relationship_id, op, object_name, data)
    replay_queued(conn, relationship_id, workdir) -> [mutation ids]
    mark_mutations_done(conn, ids)

Push algorithm (exactly per plan):
    1. fetch origin, reset --hard to origin/<branch>
    2. replay queued mutations from SQLite onto the clean tree
    3. commit once, batching all current mutations
    4. push; on non-fast-forward: fetch, abort any rebase, reset hard,
       replay, retry with full-jitter backoff, max 3 attempts
    5. on final failure: preserve the queue, raise retryable (exit 20)

Rate limits (plan values; swap for policy/limits.py when it lands):
    soft: at most 1 push/minute/side (extra pushes defer, queue preserved)
    hard: 6 pushes/minute ceiling (raise retryable)
    poll: no faster than 30s (watcher enforces via change detection with
          git ls-remote)
Size alarms: warn 100 MiB, block new objects at 250 MiB, raise
    RotationRequired at 500 MiB.
"""

from __future__ import annotations

import base64
import os
import random
import secrets
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Callable

from ..store.db import open_db, utcnow
from .base import (
    LOCK_TIMEOUT_SECONDS,
    OBJECT_MAX_BYTES,
    PUSH_HARD_CEILING_PER_MINUTE,
    PUSH_MAX_ATTEMPTS,
    PUSH_SOFT_INTERVAL_SECONDS,
    REPO_BLOCK_BYTES,
    REPO_ROTATE_BYTES,
    REPO_WARN_BYTES,
    RotationRequired,
    Transport,
    TransportError,
    mirror_lock,
)
from .local import OBJECT_NAME_RE, check_object_size

GIT_TIMEOUT_SECONDS = 120
LS_REMOTE_TIMEOUT_SECONDS = 30
COMMIT_USER_NAME = "muse-agent-social"
COMMIT_USER_EMAIL = "muse-agent-social@localhost"

# Retry backoff caps (plan: full-jitter backoff, watcher retry max 300s).
PUSH_RETRY_BASE_SECONDS = 1.0
PUSH_RETRY_CAP_SECONDS = 60.0
WATCHER_RETRY_CAP_SECONDS = 300.0


def _default_sleep(seconds: float) -> None:
    time.sleep(seconds)


def full_jitter_delay(attempt: int, base: float, cap: float) -> float:
    """Full-jitter backoff: uniform(0, min(cap, base * 2**attempt))."""
    return random.uniform(0.0, min(cap, base * (2**attempt)))


def new_object_name() -> str:
    """Random relay object filename: base64url(24 random bytes) + '.json'.

    No timestamps, no event IDs, no sender information in the name.
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(24)).decode("ascii") + ".json"


# ---------------------------------------------------------------------------
# Queued-mutation store. The DDL lives in transports/tables.py (a leaf
# module with no package imports, so store/migrations.py can apply it as a
# versioned migration without creating an import cycle). Table and column
# names are the contract (see INTERFACE.md).
# ---------------------------------------------------------------------------
from .tables import TRANSPORT_DDL as _TRANSPORT_DDL


def ensure_transport_tables(conn: sqlite3.Connection) -> None:
    """Create transport state tables if absent (idempotent).

    Uses plain ``execute`` calls, never ``executescript``: executescript
    implicitly commits any pending transaction, which would break callers
    that queue mutations inside an explicit transaction (e.g. the
    scheduler's transactional release).
    """
    for statement in _TRANSPORT_DDL.split(";"):
        statement = statement.strip()
        if statement:
            conn.execute(statement)


def queue_mutation(
    conn: sqlite3.Connection,
    relationship_id: str,
    op: str,
    object_name: str,
    data: bytes | None = None,
) -> str:
    """Queue a relay mutation; returns the stable idempotency key.

    op is 'upload' (data required, the sealed object bytes) or 'consume'
    (data must be None). The mutation is replayed onto the mirror by
    replay_queued() during the next push and marked done only after the
    push succeeds, so a crash between queueing and push is recoverable.
    """
    ensure_transport_tables(conn)
    if op not in ("upload", "consume"):
        raise ValueError(f"unknown mutation op: {op!r}")
    if not OBJECT_NAME_RE.match(object_name):
        raise TransportError(
            "config_error", f"invalid relay object name: {object_name!r}",
            retryable=False,
        )
    if op == "upload":
        if data is None:
            raise ValueError("upload mutation requires data")
        if len(data) > OBJECT_MAX_BYTES:
            raise TransportError(
                "object_too_large",
                f"object {object_name} is {len(data)} bytes; "
                f"limit is {OBJECT_MAX_BYTES}",
                retryable=False,
            )
    elif data is not None:
        raise ValueError("consume mutation must not carry data")
    mutation_id = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii")
    conn.execute(
        "INSERT INTO transport_mutations "
        "(mutation_id, relationship_id, op, object_name, data, state, created_at) "
        "VALUES (?, ?, ?, ?, ?, 'queued', ?)",
        (mutation_id, relationship_id, op, object_name, data, utcnow()),
    )
    return mutation_id


def replay_queued(
    conn: sqlite3.Connection, relationship_id: str, workdir: str | Path
) -> list[int]:
    """Apply queued mutations onto a clean mirror tree.

    Returns the row ids applied, in order. Does NOT mark them done; the
    caller marks them done only after the push succeeds.
    """
    ensure_transport_tables(conn)
    rows = conn.execute(
        "SELECT id, op, object_name, data FROM transport_mutations "
        "WHERE relationship_id = ? AND state = 'queued' ORDER BY id",
        (relationship_id,),
    ).fetchall()
    incoming = Path(workdir) / "incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    applied: list[int] = []
    for row in rows:
        name = row["object_name"]
        if not OBJECT_NAME_RE.match(name):
            raise TransportError(
                "config_error", f"invalid relay object name in queue: {name!r}",
                retryable=False,
            )
        target = incoming / name
        if row["op"] == "upload":
            with open(target, "wb") as fh:
                fh.write(row["data"])
                fh.flush()
                os.fsync(fh.fileno())
        else:
            try:
                target.unlink()
            except FileNotFoundError:
                pass  # consume is idempotent
        applied.append(row["id"])
    return applied


def mark_mutations_done(conn: sqlite3.Connection, ids: list[int]) -> None:
    """Mark replayed mutations done after a successful push."""
    if not ids:
        return
    ensure_transport_tables(conn)
    placeholders = ",".join("?" for _ in ids)
    conn.execute(
        f"UPDATE transport_mutations SET state = 'done' WHERE id IN ({placeholders})",
        ids,
    )


def count_queued(conn: sqlite3.Connection, relationship_id: str) -> int:
    """Number of queued (not yet pushed) mutations for a relationship."""
    ensure_transport_tables(conn)
    row = conn.execute(
        "SELECT COUNT(*) FROM transport_mutations "
        "WHERE relationship_id = ? AND state = 'queued'",
        (relationship_id,),
    ).fetchone()
    return int(row[0])


def _dir_size_bytes(path: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for filename in filenames:
            try:
                total += (Path(dirpath) / filename).stat().st_size
            except OSError:
                pass
    return total


def check_repo_size(size_bytes: int, has_uploads: bool) -> str | None:
    """Enforce relay repository size alarms. Returns 'warn' or None.

    Raises RotationRequired at 500 MiB, and TransportError('repo_size_blocked')
    when new objects are queued at or above 250 MiB.
    """
    if size_bytes >= REPO_ROTATE_BYTES:
        raise RotationRequired(size_bytes)
    if has_uploads and size_bytes >= REPO_BLOCK_BYTES:
        raise TransportError(
            "repo_size_blocked",
            f"relay repository size {size_bytes} bytes blocks new objects "
            f"(threshold {REPO_BLOCK_BYTES}); rotate the relay",
            retryable=False,
            detail=f"size_bytes={size_bytes}",
        )
    if size_bytes >= REPO_WARN_BYTES:
        return "warn"
    return None


# ---------------------------------------------------------------------------
# Git runner (injectable for tests).
# ---------------------------------------------------------------------------
class GitRunner:
    """Runs git as a subprocess. Override run() to stub git in tests."""

    def __init__(self, ssh_key_path: str | Path | None = None) -> None:
        self.ssh_key_path = Path(ssh_key_path) if ssh_key_path else None

    def _ssh_env(self) -> dict[str, str]:
        if not self.ssh_key_path:
            return {}
        return {
            "GIT_SSH_COMMAND": (
                f"ssh -i {self.ssh_key_path} -o IdentitiesOnly=yes "
                "-o StrictHostKeyChecking=accept-new"
            )
        }

    def run(
        self, args: list[str], cwd: str | Path, timeout: int
    ) -> "subprocess.CompletedProcess[bytes]":
        import os

        try:
            env = {**os.environ, **self._ssh_env()}
            return subprocess.run(
                ["git", *args],
                cwd=str(cwd),
                capture_output=True,
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransportError(
                "git_timeout",
                f"git {' '.join(args)} timed out after {timeout}s",
                retryable=True,
            ) from exc


class GitHubTransport(Transport):
    """Git relay transport. Mutations queue in SQLite; flush() pushes.

    upload()/consume() only queue mutations (fast, no network). Call
    flush() to run the push algorithm, or let the watcher do it.
    """

    def __init__(
        self,
        state_dir: str | Path,
        relationship_id: str,
        repo_url: str,
        *,
        branch: str = "main",
        runner: GitRunner | None = None,
        sleeper: Callable[[float], None] | None = None,
        ssh_key_path: str | Path | None = None,
    ) -> None:
        self.state_dir = Path(state_dir).resolve()
        self.relationship_id = relationship_id
        self.repo_url = repo_url
        self.branch = branch
        self.ssh_key_path = Path(ssh_key_path) if ssh_key_path else None
        # Deploy keys authenticate over SSH; convert HTTPS relay URLs to the
        # SSH form when we have a key to use.
        if self.ssh_key_path and self.repo_url.startswith(
            "https://github.com/"
        ):
            rest = self.repo_url[len("https://github.com/") :].removesuffix(
                ".git"
            )
            self.repo_url = f"git@github.com:{rest}.git"
        self._runner = runner or GitRunner(ssh_key_path=self.ssh_key_path)
        self._sleeper = sleeper or _default_sleep
        self._conn: sqlite3.Connection | None = None
        # Test hook: called immediately before `git push` in _push_once.
        # Lets tests inject a racing peer commit to force non-fast-forward.
        self._pre_push_hook: Callable[[], None] | None = None

    # -- paths ---------------------------------------------------------
    @property
    def mirror_path(self) -> Path:
        return self.state_dir / "mirrors" / self.relationship_id

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = open_db(self.state_dir)
        ensure_transport_tables(self._conn)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -- low-level git (call only with the mirror lock held) ------------
    def _git(self, *args: str, cwd: Path | None = None, timeout: int = GIT_TIMEOUT_SECONDS) -> "subprocess.CompletedProcess[bytes]":
        return self._runner.run(list(args), cwd or self.mirror_path, timeout)

    def _ref_exists(self, ref: str) -> bool:
        cp = self._git("rev-parse", "--verify", "--quiet", ref, timeout=LS_REMOTE_TIMEOUT_SECONDS)
        return cp.returncode == 0

    def _ensure_mirror_locked(self) -> None:
        """Clone the mirror on first use; verify it tracks our repo."""
        mirror = self.mirror_path
        if not (mirror / ".git").exists():
            if mirror.exists():
                raise TransportError(
                    "config_error",
                    f"mirror path {mirror} exists but is not a git repository",
                    retryable=False,
                )
            cp = self._runner.run(
                ["clone", self.repo_url, str(mirror)],
                self.state_dir,
                GIT_TIMEOUT_SECONDS,
            )
            if cp.returncode != 0:
                raise TransportError(
                    "clone_failed",
                    f"git clone failed for relationship {self.relationship_id}",
                    retryable=True,
                    detail=cp.stderr.decode("utf-8", "replace")[-500:],
                )
        cp = self._git("config", "--get", "remote.origin.url", timeout=LS_REMOTE_TIMEOUT_SECONDS)
        origin_url = cp.stdout.decode("utf-8", "replace").strip()
        if origin_url != self.repo_url:
            raise TransportError(
                "config_error",
                "mirror origin URL does not match configured relay repo URL",
                retryable=False,
                detail=f"mirror={mirror}",
            )
        (mirror / "incoming").mkdir(parents=True, exist_ok=True)

    # -- Transport interface -------------------------------------------
    def head(self) -> str:
        """Remote HEAD marker via git ls-remote (change detection)."""
        with mirror_lock(self.state_dir, self.relationship_id, LOCK_TIMEOUT_SECONDS):
            cp = self._runner.run(
                ["ls-remote", self.repo_url, self.branch],
                self.state_dir,
                LS_REMOTE_TIMEOUT_SECONDS,
            )
            if cp.returncode != 0:
                raise TransportError(
                    "ls_remote_failed",
                    "git ls-remote failed",
                    retryable=True,
                    detail=cp.stderr.decode("utf-8", "replace")[-500:],
                )
            out = cp.stdout.decode("ascii", "replace").strip()
            if not out:
                return ""  # branch does not exist yet (empty relay)
            return out.split()[0]

    def changed(self, since_head: str) -> bool:
        return self.head() != since_head

    def fetch_new(self, since: str) -> list[tuple[str, bytes]]:
        """Fetch origin and list incoming/*.json objects newer than `since`.

        `since` is a remote HEAD sha previously returned by head(). Objects
        whose names do not match the relay object pattern are skipped (the
        receive path quarantines by content; the transport never parses).
        """
        with mirror_lock(self.state_dir, self.relationship_id, LOCK_TIMEOUT_SECONDS):
            self._ensure_mirror_locked()
            cp = self._git("fetch", "origin")
            if cp.returncode != 0:
                raise TransportError(
                    "fetch_failed",
                    "git fetch origin failed",
                    retryable=True,
                    detail=cp.stderr.decode("utf-8", "replace")[-500:],
                )
            ref = f"origin/{self.branch}"
            names: list[str] = []
            did_diff = False
            if since and self._ref_exists(since) and self._ref_exists(ref):
                cp = self._git(
                    "diff", "--name-only", "--diff-filter=AM",
                    since, ref, "--", "incoming",
                )
                if cp.returncode == 0:
                    names = cp.stdout.decode("utf-8", "replace").splitlines()
                    did_diff = True
            if not did_diff and self._ref_exists(ref):
                cp = self._git("ls-tree", "-r", "--name-only", ref, "--", "incoming")
                if cp.returncode != 0:
                    raise TransportError(
                        "fetch_failed", "git ls-tree failed",
                        retryable=True,
                        detail=cp.stderr.decode("utf-8", "replace")[-500:],
                    )
                names = cp.stdout.decode("utf-8", "replace").splitlines()
            items: list[tuple[str, bytes]] = []
            for entry in names:
                entry = entry.strip()
                if not entry.startswith("incoming/"):
                    continue
                name = entry[len("incoming/"):]
                if not OBJECT_NAME_RE.match(name):
                    continue
                # Size pre-check BEFORE buffering: git cat-file -s reports
                # the blob size from metadata, so a hostile oversized blob
                # is never read into memory. The receive loop
                # (watcher.run_once) enforces the cap itself via len(data)
                # and quarantines oversized input without failing the run,
                # so an over-cap blob is returned with a bounded placeholder
                # that still trips that check instead of its full content.
                blob_ref = f"{ref}:incoming/{name}"
                cp = self._git("cat-file", "-s", blob_ref)
                if cp.returncode != 0:
                    continue  # raced deletion; next poll converges
                try:
                    blob_size = int(cp.stdout.decode("ascii", "replace").strip())
                except ValueError:
                    continue  # unexpected output; next poll converges
                try:
                    check_object_size(name, blob_size)
                except TransportError as exc:
                    if exc.code != "object_too_large":
                        raise
                    items.append((name, b"\x00" * (OBJECT_MAX_BYTES + 1)))
                    continue
                cp = self._git("cat-file", "-p", blob_ref)
                if cp.returncode != 0:
                    continue  # raced deletion; next poll converges
                items.append((name, cp.stdout))
            return items

    def read_object(self, object_name: str) -> bytes:
        """Read a single relay object, checking size from metadata first.

        Uses git cat-file -s for the size pre-check, then cat-file -p for
        the content. Raises non-retryable TransportError('object_too_large')
        without buffering when the blob exceeds OBJECT_MAX_BYTES.
        """
        if not OBJECT_NAME_RE.match(object_name):
            raise TransportError(
                "bad_object_name", f"invalid relay object name: {object_name}"
            )
        with mirror_lock(self.state_dir, self.relationship_id, LOCK_TIMEOUT_SECONDS):
            self._ensure_mirror_locked()
            ref = f"origin/{self.branch}"
            blob_ref = f"{ref}:incoming/{object_name}"
            cp = self._git("cat-file", "-s", blob_ref)
            if cp.returncode != 0:
                raise TransportError(
                    "object_not_found",
                    f"relay object {object_name} not found",
                    retryable=False,
                )
            try:
                blob_size = int(cp.stdout.decode("ascii", "replace").strip())
            except ValueError:
                raise TransportError(
                    "object_not_found",
                    f"relay object {object_name} has unreadable size",
                    retryable=False,
                )
            check_object_size(object_name, blob_size)
            cp = self._git("cat-file", "-p", blob_ref)
            if cp.returncode != 0:
                raise TransportError(
                    "object_not_found",
                    f"relay object {object_name} not found",
                    retryable=False,
                )
            return cp.stdout

    def upload(self, object_name: str, data: bytes) -> None:
        """Queue an upload mutation (flush() pushes it)."""
        queue_mutation(self._db(), self.relationship_id, "upload", object_name, data)

    def consume(self, object_name: str) -> None:
        """Queue a consume mutation (flush() pushes it). Idempotent."""
        queue_mutation(self._db(), self.relationship_id, "consume", object_name)

    def pending_outgoing(self) -> int:
        return count_queued(self._db(), self.relationship_id)

    def flush(self) -> dict:
        """Run the push algorithm for queued mutations. See module docstring."""
        conn = self._db()
        with mirror_lock(self.state_dir, self.relationship_id, LOCK_TIMEOUT_SECONDS):
            self._ensure_mirror_locked()
            queued = conn.execute(
                "SELECT id FROM transport_mutations "
                "WHERE relationship_id = ? AND state = 'queued' ORDER BY id",
                (self.relationship_id,),
            ).fetchall()
            if not queued:
                return {"status": "nothing_queued", "pushed": 0,
                        "head": self._remote_head_locked()}
            rate = self._check_push_rate(conn)
            if rate == "deferred":
                return {"status": "deferred", "reason": "push_soft_interval",
                        "pushed": 0, "queued": len(queued)}
            for attempt in range(PUSH_MAX_ATTEMPTS):
                try:
                    return self._push_once(conn, [r["id"] for r in queued])
                except TransportError as exc:
                    if (exc.code == "push_non_fast_forward"
                            and attempt < PUSH_MAX_ATTEMPTS - 1):
                        self._sleeper(full_jitter_delay(
                            attempt, PUSH_RETRY_BASE_SECONDS, PUSH_RETRY_CAP_SECONDS))
                        continue
                    # Anything else, or the final non-fast-forward: the queue
                    # stays 'queued' in SQLite, so a later flush retries it.
                    # Both map to watcher exit 20 (retryable).
                    raise

    # -- push internals (lock held) -------------------------------------
    def _remote_head_locked(self) -> str:
        cp = self._runner.run(
            ["ls-remote", self.repo_url, self.branch],
            self.state_dir, LS_REMOTE_TIMEOUT_SECONDS,
        )
        if cp.returncode != 0:
            return ""
        out = cp.stdout.decode("ascii", "replace").strip()
        return out.split()[0] if out else ""

    def _check_push_rate(self, conn: sqlite3.Connection) -> str:
        """'ok' or 'deferred'; raises on the hard ceiling."""
        now = time.time()
        conn.execute(
            "DELETE FROM transport_push_log "
            "WHERE relationship_id = ? AND pushed_at < ?",
            (self.relationship_id, now - 60.0),
        )
        recent = conn.execute(
            "SELECT COUNT(*), MAX(pushed_at) FROM transport_push_log "
            "WHERE relationship_id = ?",
            (self.relationship_id,),
        ).fetchone()
        count, last = int(recent[0]), recent[1]
        if count >= PUSH_HARD_CEILING_PER_MINUTE:
            raise TransportError(
                "push_rate_limited",
                f"{count} pushes in the last 60s hit the hard ceiling of "
                f"{PUSH_HARD_CEILING_PER_MINUTE}/min",
                retryable=True,
            )
        if last is not None and (now - float(last)) < PUSH_SOFT_INTERVAL_SECONDS:
            return "deferred"
        return "ok"

    def _push_once(self, conn: sqlite3.Connection, queued_ids: list[int]) -> dict:
        t0 = time.monotonic()
        mirror = self.mirror_path
        # 1. Fetch origin, abort any stale rebase, then move the local branch
        #    onto the remote tip (or an empty tree on an empty relay). This
        #    also discards local commits left by failed push attempts, so a
        #    retry replays purely from the SQLite queue. -f tolerates dirty
        #    trees from crashed runs; the mirror is disposable.
        cp = self._git("fetch", "origin")
        if cp.returncode != 0:
            raise TransportError(
                "fetch_failed", "git fetch origin failed before push",
                retryable=True,
                detail=cp.stderr.decode("utf-8", "replace")[-500:],
            )
        self._git("rebase", "--abort")  # ignore result; may be nothing to abort
        ref = f"origin/{self.branch}"
        if self._ref_exists(ref):
            cp = self._git("checkout", "-f", "-B", self.branch, ref)
        else:
            # Empty relay: start from an unborn branch with a clear index,
            # discarding any local branch left by a failed push attempt.
            self._git("update-ref", "-d", f"refs/heads/{self.branch}")
            cp = self._git("checkout", "-f", "--orphan", self.branch)
            if cp.returncode == 0:
                self._git("rm", "-q", "-rf", ".")  # best effort
        if cp.returncode != 0:
            raise TransportError(
                "reset_failed",
                "could not reset the mirror to the relay tip",
                retryable=True,
                detail=cp.stderr.decode("utf-8", "replace")[-500:],
            )
        # Exact replay: drop every untracked file, then rebuild incoming/.
        self._git("clean", "-fdx", "-q")
        queued_rows = conn.execute(
            "SELECT op, data FROM transport_mutations WHERE id IN "
            f"({','.join('?' for _ in queued_ids)})",
            queued_ids,
        ).fetchall()
        has_uploads = any(r["op"] == "upload" for r in queued_rows)
        upload_bytes = sum(len(r["data"]) for r in queued_rows
                           if r["op"] == "upload" and r["data"])
        # 2. size alarms before commit (projected size).
        size_alarm = check_repo_size(
            _dir_size_bytes(mirror) + upload_bytes, has_uploads)
        # 3. replay queued mutations onto the clean tree.
        applied = replay_queued(conn, self.relationship_id, mirror)
        self._git("add", "-A")
        cp = self._git("status", "--porcelain")
        if not cp.stdout.strip():
            # Mutations were no-ops (e.g. consuming an already-absent file).
            mark_mutations_done(conn, applied)
            return {"status": "noop", "pushed": 0, "mutations": len(applied),
                    "head": self._remote_head_locked(),
                    "size_bytes": _dir_size_bytes(mirror),
                    "size_alarm": size_alarm,
                    "duration_ms": int((time.monotonic() - t0) * 1000)}
        cp = self._git(
            "-c", f"user.name={COMMIT_USER_NAME}",
            "-c", f"user.email={COMMIT_USER_EMAIL}",
            "commit", "-q", "-m",
            f"mas relay batch: {len(applied)} mutation(s)",
        )
        if cp.returncode != 0:
            raise TransportError(
                "commit_failed", "git commit failed",
                retryable=True,
                detail=cp.stderr.decode("utf-8", "replace")[-500:],
            )
        # 4. push.
        if self._pre_push_hook is not None:
            self._pre_push_hook()
        cp = self._git("push", "origin", self.branch)
        if cp.returncode != 0:
            err = cp.stderr.decode("utf-8", "replace")
            if "non-fast-forward" in err or "[rejected]" in err:
                raise TransportError(
                    "push_non_fast_forward",
                    "push rejected: remote advanced (non-fast-forward); "
                    "will refetch and retry",
                    retryable=True,
                    detail=err[-500:],
                )
            raise TransportError(
                "push_failed", "git push failed",
                retryable=True,
                detail=err[-500:],
            )
        cp = self._git("rev-parse", "HEAD")
        head_sha = cp.stdout.decode("ascii", "replace").strip()
        mark_mutations_done(conn, applied)
        conn.execute(
            "INSERT INTO transport_push_log (relationship_id, pushed_at) "
            "VALUES (?, ?)",
            (self.relationship_id, time.time()),
        )
        return {"status": "pushed", "pushed": 1, "mutations": len(applied),
                "commit": head_sha, "head": head_sha,
                "size_bytes": _dir_size_bytes(mirror),
                "size_alarm": size_alarm,
                "duration_ms": int((time.monotonic() - t0) * 1000)}
