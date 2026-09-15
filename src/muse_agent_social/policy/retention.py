"""Retention policy: encrypted envelope by default, explicit plaintext opt-in.

Default: keep the sealed envelope and non-content metadata only. Decrypt
in memory for surfacing. No plaintext inbox or outbox files are ever
written under the default policy.

Explicit opt-in: per-relationship plaintext cache with a named period:
"1d", "7d", "30d", or "indefinite". The cache lives under
<state_dir>/plaintext_cache/<relationship_id>/ as <event_id>.json files
plus an optin.json manifest. delete_plaintext_cache() removes the whole
directory immediately. purge_expired_plaintext_cache() enforces the
period for timed opt-ins.

retention_scan(state_dir) lists unexpected plaintext files. It backs the
teardown post-check and the release gate ("no plaintext under default
policy"): inbox/outbox files are always unexpected, and cache files are
unexpected unless a valid, unexpired opt-in manifest covers them.

The authoritative opt-in record lives in the relationships.policy JSON
document under the "retention" key. The on-disk optin.json manifest is a
redundant marker so the filesystem scan can judge a cache directory
without opening the database.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any

from muse_agent_social.policy.delivery import UnknownRelationshipError
from muse_agent_social.policy.limits import (
    MAX_ENVELOPE_BYTES,
    add_seconds,
    parse_canonical_utc,
)
from muse_agent_social.store.db import transaction, utcnow

__all__ = [
    "PLAINTEXT_CACHE_PERIODS",
    "PLAINTEXT_PERIOD_ALIASES",
    "RetentionError",
    "set_plaintext_cache",
    "plaintext_cache_status",
    "write_plaintext_cache",
    "read_plaintext_cache",
    "delete_plaintext_cache",
    "purge_expired_plaintext_cache",
    "retention_scan",
]

# Named plaintext-cache periods to seconds. None means no expiry.
PLAINTEXT_CACHE_PERIODS: dict[str, int | None] = {
    "1d": 24 * 3600,
    "7d": 7 * 24 * 3600,
    "30d": 30 * 24 * 3600,
    "indefinite": None,
}

PLAINTEXT_PERIOD_ALIASES = {
    "1d": "1d",
    "1day": "1d",
    "1-day": "1d",
    "day": "1d",
    "7d": "7d",
    "7day": "7d",
    "7days": "7d",
    "7-day": "7d",
    "week": "7d",
    "30d": "30d",
    "30day": "30d",
    "30days": "30d",
    "30-day": "30d",
    "month": "30d",
    "indefinite": "indefinite",
    "forever": "indefinite",
}

_CACHE_DIRNAME = "plaintext_cache"
_MANIFEST_FILENAME = "optin.json"
_RETENTION_KEY = "retention"


class RetentionError(Exception):
    """Base error for retention-policy failures. Carries a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def _normalize_period(period: str) -> str:
    try:
        canonical = PLAINTEXT_PERIOD_ALIASES[str(period).strip().lower()]
    except (KeyError, AttributeError) as exc:
        raise RetentionError("invalid_period", str(period)) from exc
    return canonical


def _state_dir_for_conn(conn: sqlite3.Connection) -> Path:
    rows = conn.execute("PRAGMA database_list;").fetchall()
    main = next((r for r in rows if r["name"] == "main"), None)
    db_file = main["file"] if main is not None else ""
    if not db_file or db_file == ":memory:":
        raise RetentionError(
            "state_dir_unresolvable",
            "connection is not backed by a state.db file",
        )
    return Path(db_file).resolve().parent


def _cache_dir(state_dir: str | Path, relationship_id: str) -> Path:
    return Path(state_dir) / _CACHE_DIRNAME / relationship_id


def _load_policy_document(
    conn: sqlite3.Connection, relationship_id: str
) -> dict[str, Any]:
    row = conn.execute(
        "SELECT policy FROM relationships WHERE relationship_id = ?",
        (relationship_id,),
    ).fetchone()
    if row is None:
        raise UnknownRelationshipError(relationship_id)
    try:
        document = json.loads(row["policy"])
    except (ValueError, TypeError) as exc:
        raise RetentionError("policy_not_json", relationship_id) from exc
    if not isinstance(document, dict):
        raise RetentionError("policy_not_json", relationship_id)
    return document


def _write_manifest(
    cache_dir: Path, relationship_id: str, record: dict[str, Any]
) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(cache_dir, 0o700)
    manifest = cache_dir / _MANIFEST_FILENAME
    manifest.write_text(
        json.dumps(record, sort_keys=True), encoding="utf-8"
    )
    os.chmod(manifest, 0o600)


def set_plaintext_cache(
    conn: sqlite3.Connection, relationship_id: str, period: str
) -> dict[str, Any]:
    """Opt a relationship into a plaintext cache for a named period.

    period is one of "1d", "7d", "30d", "indefinite" (aliases like "week"
    or "month" are accepted). The opt-in is recorded in the relationship
    policy document and an optin.json manifest is written into the cache
    directory. Timed opt-ins expire period seconds after they are set.

    Returns the opt-in record.

    Raises:
        UnknownRelationshipError: when the relationship does not exist.
        RetentionError: on an unknown period name.
    """
    canonical = _normalize_period(period)
    now = utcnow()
    seconds = PLAINTEXT_CACHE_PERIODS[canonical]
    expires_at: str | None = None
    if seconds is not None:
        expires_at = add_seconds(now, seconds)
    record = {
        "relationship_id": relationship_id,
        "period": canonical,
        "set_at": now,
        "expires_at": expires_at,
    }
    with transaction(conn):
        document = _load_policy_document(conn, relationship_id)
        retention = document.get(_RETENTION_KEY)
        if not isinstance(retention, dict):
            retention = {}
        retention["plaintext_cache"] = record
        document[_RETENTION_KEY] = retention
        conn.execute(
            "UPDATE relationships SET policy = ? WHERE relationship_id = ?",
            (json.dumps(document, sort_keys=True), relationship_id),
        )
    state_dir = _state_dir_for_conn(conn)
    _write_manifest(_cache_dir(state_dir, relationship_id), relationship_id, record)
    return record


def _optin_record(document: dict[str, Any]) -> dict[str, Any] | None:
    retention = document.get(_RETENTION_KEY)
    if not isinstance(retention, dict):
        return None
    record = retention.get("plaintext_cache")
    return record if isinstance(record, dict) else None


def plaintext_cache_status(
    conn: sqlite3.Connection,
    relationship_id: str,
    now: str | None = None,
) -> dict[str, Any]:
    """Report whether the plaintext cache opt-in is currently in force.

    Returns {"enabled": bool, "period": str|None, "set_at": str|None,
    "expires_at": str|None}. A timed opt-in whose window has passed reports
    enabled False; the caller should purge the cache.
    """
    moment = now or utcnow()
    document = _load_policy_document(conn, relationship_id)
    record = _optin_record(document)
    status = {
        "enabled": False,
        "period": None,
        "set_at": None,
        "expires_at": None,
    }
    if record is None:
        return status
    status["period"] = record.get("period")
    status["set_at"] = record.get("set_at")
    status["expires_at"] = record.get("expires_at")
    expires_at = record.get("expires_at")
    if expires_at is None:
        status["enabled"] = True
    else:
        try:
            status["enabled"] = parse_canonical_utc(
                moment
            ) < parse_canonical_utc(expires_at)
        except (ValueError, TypeError):
            status["enabled"] = False
    return status


def _require_enabled(
    conn: sqlite3.Connection, relationship_id: str, now: str | None
) -> dict[str, Any]:
    status = plaintext_cache_status(conn, relationship_id, now)
    if not status["enabled"]:
        raise RetentionError(
            "plaintext_cache_not_enabled",
            relationship_id,
        )
    return status


def write_plaintext_cache(
    conn: sqlite3.Connection,
    relationship_id: str,
    event_id: str,
    payload_bytes: bytes,
    now: str | None = None,
) -> Path:
    """Cache one decrypted payload file. Requires an active opt-in.

    Raises:
        RetentionError: when no opt-in is in force, or the payload is
            absurdly large.
    """
    if not isinstance(payload_bytes, (bytes, bytearray)) or not payload_bytes:
        raise RetentionError("invalid_payload", event_id)
    if len(payload_bytes) > MAX_ENVELOPE_BYTES:
        raise RetentionError("payload_too_large", event_id)
    _require_enabled(conn, relationship_id, now)
    state_dir = _state_dir_for_conn(conn)
    cache_dir = _cache_dir(state_dir, relationship_id)
    cache_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(cache_dir, 0o700)
    target = cache_dir / f"{event_id}.json"
    target.write_bytes(bytes(payload_bytes))
    os.chmod(target, 0o600)
    return target


def read_plaintext_cache(
    conn: sqlite3.Connection,
    relationship_id: str,
    event_id: str,
    now: str | None = None,
) -> bytes | None:
    """Read a cached payload, honoring the opt-in and the period window.

    Returns None when the opt-in is not in force, the file is missing, or
    the file is older than a timed period allows.
    """
    status = plaintext_cache_status(conn, relationship_id, now)
    if not status["enabled"]:
        return None
    state_dir = _state_dir_for_conn(conn)
    target = _cache_dir(state_dir, relationship_id) / f"{event_id}.json"
    if not target.is_file():
        return None
    period = status["period"]
    seconds = PLAINTEXT_CACHE_PERIODS.get(period) if period else None
    if seconds is not None:
        moment = now or utcnow()
        cutoff = parse_canonical_utc(moment).timestamp() - seconds
        if target.stat().st_mtime < cutoff:
            return None
    return target.read_bytes()


def _count_files(root: Path) -> int:
    return sum(1 for _ in root.rglob("*") if _.is_file()) if root.exists() else 0


def delete_plaintext_cache(
    conn: sqlite3.Connection, relationship_id: str
) -> int:
    """Immediately delete a relationship's plaintext cache.

    Removes the cache directory and clears the opt-in record. Returns the
    number of files removed.
    """
    state_dir = _state_dir_for_conn(conn)
    cache_dir = _cache_dir(state_dir, relationship_id)
    removed = _count_files(cache_dir)
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    with transaction(conn):
        document = _load_policy_document(conn, relationship_id)
        retention = document.get(_RETENTION_KEY)
        if isinstance(retention, dict):
            retention.pop("plaintext_cache", None)
            document[_RETENTION_KEY] = retention
            conn.execute(
                "UPDATE relationships SET policy = ? WHERE relationship_id = ?",
                (json.dumps(document, sort_keys=True), relationship_id),
            )
    return removed


def _relationship_ids(conn: sqlite3.Connection) -> set[str]:
    return {
        row["relationship_id"]
        for row in conn.execute("SELECT relationship_id FROM relationships;")
    }


def purge_expired_plaintext_cache(
    conn: sqlite3.Connection,
    state_dir: str | Path,
    now: str | None = None,
) -> int:
    """Enforce plaintext-cache periods across the state directory.

    Deletes whole cache directories whose opt-in is missing or expired,
    and deletes individual files older than a timed period allows.
    Returns the number of files removed.
    """
    moment = now or utcnow()
    now_epoch = parse_canonical_utc(moment).timestamp()
    root = Path(state_dir) / _CACHE_DIRNAME
    if not root.is_dir():
        return 0
    known = _relationship_ids(conn)
    removed = 0
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            if entry.is_file():
                entry.unlink()
                removed += 1
            continue
        rel_id = entry.name
        enabled = False
        period_seconds: int | None = None
        if rel_id in known:
            status = plaintext_cache_status(conn, rel_id, moment)
            enabled = bool(status["enabled"])
            period = status["period"]
            period_seconds = (
                PLAINTEXT_CACHE_PERIODS.get(period) if period else None
            )
        if not enabled:
            removed += _count_files(entry)
            shutil.rmtree(entry)
            continue
        if period_seconds is None:
            continue
        cutoff = now_epoch - period_seconds
        for path in sorted(entry.rglob("*")):
            if path.is_file() and path.name != _MANIFEST_FILENAME:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
    return removed


def _read_manifest(cache_dir: Path) -> dict[str, Any] | None:
    manifest = cache_dir / _MANIFEST_FILENAME
    if not manifest.is_file():
        return None
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _manifest_covers(
    record: dict[str, Any] | None, path: Path, now_epoch: float
) -> tuple[bool, str]:
    """Check one cache file against the directory manifest."""
    if record is None:
        return False, "stale_or_unauthorized_plaintext_cache"
    expires_at = record.get("expires_at")
    if expires_at is not None:
        try:
            expired = now_epoch >= parse_canonical_utc(expires_at).timestamp()
        except (ValueError, TypeError):
            return False, "stale_or_unauthorized_plaintext_cache"
        if expired:
            return False, "expired_optin_plaintext_cache"
    period = record.get("period")
    seconds = PLAINTEXT_CACHE_PERIODS.get(period) if period else None
    if seconds is not None and path.stat().st_mtime < now_epoch - seconds:
        return False, "cache_file_older_than_period"
    return True, ""


def retention_scan(
    state_dir: str | Path, now: str | None = None
) -> list[dict[str, str]]:
    """List unexpected plaintext files under a state directory.

    Findings are {"path": absolute path, "reason": stable code} dicts,
    sorted by path:

    * anything under inbox/ or outbox/ is always unexpected (v0.2 never
      writes plaintext inbox/outbox files);
    * plaintext_cache/<relationship>/ files are unexpected unless a valid,
      unexpired optin.json manifest covers them and timed files are within
      the period window;
    * legacy v0.1-style names (inbox*/outbox* prefixes, .plaintext or
      .decrypted suffixes) anywhere else are unexpected.

    Used by the teardown post-check and the release gate. After teardown
    the scan must return an empty list.
    """
    base = Path(state_dir).resolve()
    moment = now or utcnow()
    now_epoch = parse_canonical_utc(moment).timestamp()
    findings: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(path: Path, reason: str) -> None:
        key = str(path)
        if key not in seen:
            seen.add(key)
            findings.append({"path": key, "reason": reason})

    if not base.is_dir():
        return []

    for box in ("inbox", "outbox"):
        box_dir = base / box
        if box_dir.is_dir():
            for path in sorted(box_dir.rglob("*")):
                if path.is_file():
                    add(path, f"plaintext_{box}_forbidden")

    cache_root = base / _CACHE_DIRNAME
    if cache_root.is_dir():
        for rel_dir in sorted(cache_root.iterdir()):
            if not rel_dir.is_dir():
                if rel_dir.is_file():
                    add(rel_dir, "stray_file_in_plaintext_cache")
                continue
            record = _read_manifest(rel_dir)
            for path in sorted(rel_dir.rglob("*")):
                if not path.is_file() or path.name == _MANIFEST_FILENAME:
                    continue
                ok, reason = _manifest_covers(record, path, now_epoch)
                if not ok:
                    add(path, reason)

    skip_dirs = {cache_root}
    for name in ("mirror", "locks"):
        candidate = base / name
        if candidate.is_dir():
            skip_dirs.add(candidate)

    def under_skipped(path: Path) -> bool:
        return any(
            path == skipped or skipped in path.parents for skipped in skip_dirs
        )

    for path in sorted(base.rglob("*")):
        if not path.is_file() or under_skipped(path):
            continue
        name = path.name
        if (
            name.startswith("inbox")
            or name.startswith("outbox")
            or name.endswith((".plaintext", ".decrypted"))
        ):
            add(path, "legacy_plaintext_pattern")

    findings.sort(key=lambda item: item["path"])
    return findings
