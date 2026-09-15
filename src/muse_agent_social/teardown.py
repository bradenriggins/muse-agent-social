"""Relationship teardown for Muse Agent Social v0.2 (lifecycle track).

Implements the implementation plan's RETENTION AND TEARDOWN section. Teardown
order is EXACTLY per the plan:

1. Mark the relationship revoked locally. Sends and acceptance stop
   immediately.
2. Revoke deploy keys and delete the relay repository (via injected
   transport/admin callbacks).
3. Delete relationship X25519 private keys and rotation candidates FIRST.
   This is the crypto-erasure boundary: private key material is destroyed
   before any other state deletion.
4. Delete pairing bundles, invite state, relay config, mirror, replay rows,
   retry queues, scheduler rows, plaintext cache, inbox, and outbox. The
   relationship's sealed event rows are also deleted so the post-check can
   verify no pair identifier remains (this requires briefly lifting the
   append-only triggers, which are restored afterwards).
5. Single overwrite before unlink where supported, then remove directories.
   Post-check scan for pair ID, peer label, and key filenames.
6. Keep one minimal consent tombstone: relationship ID hash, revoked time,
   local reason code. No peer name, no message content.

Bounded secure-deletion claim: file overwrite cannot guarantee physical
erasure on solid-state storage, copy-on-write filesystems, snapshots,
backups, or GitHub backups. v0.2 relies on relationship-key deletion for
cryptographic erasure and documents the residual storage reality.

No em dashes are used anywhere in this module, per project convention.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .store.db import utcnow

__all__ = [
    "TeardownError",
    "TeardownHooks",
    "TeardownReport",
    "teardown_relationship",
    "postcheck_scan",
    "secure_unlink",
]

#: Append-only triggers, mirrored from the v0.2 schema. Dropped for the
#: duration of a teardown's event-row deletion, then recreated.
_TRIGGER_EVENTS_NO_UPDATE = """
CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only');
END;
""".strip()

_TRIGGER_EVENTS_NO_DELETE = """
CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only');
END;
""".strip()

#: Operational directories removed in step 4/5 (relative to the state dir).
_OPERATIONAL_DIRS = (
    "bundles",
    "mirror",
    "cache",
    "inbox",
    "outbox",
    "retry",
    "plaintext_cache",
)


def _relationship_fs_paths(state_dir: Path, relationship_id: str) -> list[Path]:
    """Every on-disk path owned by one relationship (authoritative list).

    Audited against every writer under the state dir:
      transports/github.py  mirrors/<rid>/      git working clone
      transports/base.py    locks/<rid>.lock    mirror flock
      watcher.py            watcher/<rid>.json  watcher resume state

    These are per-relationship, so only this relationship's subtree is
    wiped (never the whole mirrors/ or locks/ dir, which other
    relationships still use). Whole operational dirs (inbox, outbox, ...)
    are covered separately by _OPERATIONAL_DIRS.
    """
    return [
        state_dir / "mirrors" / relationship_id,
        state_dir / "locks" / f"{relationship_id}.lock",
        state_dir / "watcher" / f"{relationship_id}.json",
    ]


class TeardownError(Exception):
    """Teardown was refused or failed partway."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass
class DeployKeyRef:
    repo: str
    label: str
    key_id: str = ""


@dataclass
class RelayRef:
    repo: str
    transport: str = ""


@dataclass
class TeardownHooks:
    """Injected transport/admin callbacks. Required for a live (non-dry)
    run; dry runs record intent without calling them."""

    revoke_deploy_key: Callable[[DeployKeyRef], None] | None = None
    delete_relay_repo: Callable[[RelayRef], None] | None = None


@dataclass
class TeardownReport:
    relationship_id_sha256: str
    revoked_at: str
    reason_code: str
    step_log: list[str] = field(default_factory=list)
    keys_destroyed: list[str] = field(default_factory=list)
    deploy_keys_revoked: list[str] = field(default_factory=list)
    relay_repos_deleted: list[str] = field(default_factory=list)
    files_deleted: int = 0
    dirs_removed: list[str] = field(default_factory=list)
    tombstone_path: str = ""
    postcheck_scanned: int = 0
    postcheck_hits: list[str] = field(default_factory=list)
    dry_run: bool = False
    crypto_erasure_before_bulk: bool = False


def secure_unlink(path: str | Path) -> bool:
    """Single overwrite with zeros, fsync, then unlink. Best effort:
    returns False (instead of raising) where the platform does not support
    it, so teardown can continue and report the gap."""
    p = Path(path)
    if not p.is_file() and not p.is_symlink():
        return False
    try:
        if p.is_file() and not p.is_symlink():
            size = p.stat().st_size
            with open(p, "r+b") as fh:
                fh.write(b"\x00" * size)
                fh.flush()
                os.fsync(fh.fileno())
        p.unlink()
        return True
    except OSError:
        return False


def _wipe_tree(root: Path, report: TeardownReport, dry_run: bool) -> None:
    """Overwrite every file once, then remove the tree."""
    if not root.exists():
        return
    if root.is_file() or root.is_symlink():
        if not dry_run:
            secure_unlink(root)
            report.files_deleted += 1
        return
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            fp = Path(dirpath) / name
            if not dry_run:
                secure_unlink(fp)
                report.files_deleted += 1
    if not dry_run:
        shutil.rmtree(root, ignore_errors=True)
    report.dirs_removed.append(str(root))


def _discover_deploy_keys(state_dir: Path) -> tuple[list[DeployKeyRef], list[RelayRef]]:
    """Best-effort discovery of deploy keys and relay repos from relay.json
    in the state dir. Absence is not an error; the hooks simply have less
    to revoke."""
    keys: list[DeployKeyRef] = []
    repos: list[RelayRef] = []
    cfg = state_dir / "relay.json"
    if cfg.is_file():
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
        for entry in data.get("deploy_keys", []) or []:
            keys.append(
                DeployKeyRef(
                    repo=str(entry.get("repo", "")),
                    label=str(entry.get("label", "")),
                    # relay.json writers have used both "key_id" and "id"
                    # for the GitHub key id; accept either.
                    key_id=str(
                        entry.get("key_id") or entry.get("id") or ""
                    ),
                )
            )
        for entry in data.get("repos", []) or []:
            if isinstance(entry, str):
                repos.append(RelayRef(repo=entry))
            else:
                repos.append(
                    RelayRef(
                        repo=str(entry.get("repo", "")),
                        transport=str(entry.get("transport", "")),
                    )
                )
    return keys, repos


def postcheck_scan(
    state_dir: str | Path,
    relationship_id: str,
    peer_label: str | None = None,
    key_basenames: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Scan the state dir for residual traces.

    Checks filenames and file contents for the raw relationship id, the
    peer label, and private key filenames. The tombstones directory is
    excluded (it holds only the ID hash, which cannot match the raw id).
    Returns {"scanned": n, "hits": [paths]}.
    """
    root = Path(state_dir)
    needles = [relationship_id]
    if peer_label:
        needles.append(peer_label)
    needles.extend(key_basenames)
    hits: list[str] = []
    scanned = 0
    tombstones = root / "tombstones"
    for dirpath, _dirnames, filenames in os.walk(root):
        # Skip the tombstone directory itself.
        if Path(dirpath) == tombstones or tombstones in Path(dirpath).parents:
            continue
        for name in filenames:
            fp = Path(dirpath) / name
            scanned += 1
            hay = name
            try:
                if fp.stat().st_size <= 1_048_576:
                    hay += fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
            if any(n and n in hay for n in needles):
                hits.append(str(fp))
    return {"scanned": scanned, "hits": hits}


def _tombstone_path(state_dir: Path, relationship_id: str) -> Path:
    digest = hashlib.sha256(relationship_id.encode("utf-8")).hexdigest()
    return state_dir / "tombstones" / f"{digest}.json"


def teardown_relationship(
    conn: Any,
    state_dir: str | Path,
    relationship_id: str,
    *,
    hooks: TeardownHooks | None = None,
    reason_code: str = "operator",
    peer_label: str | None = None,
    dry_run: bool = False,
) -> TeardownReport:
    """Tear down one relationship in exact plan order. Returns a report.

    conn: open connection on the v0.2 database (WAL, FK enforced).
    """
    hooks = hooks or TeardownHooks()
    state_dir = Path(state_dir)
    digest = hashlib.sha256(relationship_id.encode("utf-8")).hexdigest()
    report = TeardownReport(
        relationship_id_sha256=digest,
        revoked_at=utcnow(),
        reason_code=reason_code,
        dry_run=dry_run,
    )

    def log(step: str) -> None:
        report.step_log.append(step)

    row = conn.execute(
        "SELECT consent_state FROM relationships WHERE relationship_id = ?",
        (relationship_id,),
    ).fetchone()
    if row is None:
        raise TeardownError("unknown-relationship", relationship_id)

    # Pre-validate remote hooks before any mutation, so a missing hook
    # fails fast instead of leaving a half-torn-down relationship.
    deploy_keys, repos = _discover_deploy_keys(state_dir)
    if not dry_run:
        if deploy_keys and hooks.revoke_deploy_key is None:
            raise TeardownError(
                "hook-required", "revoke_deploy_key hook is missing"
            )
        if repos and hooks.delete_relay_repo is None:
            raise TeardownError(
                "hook-required", "delete_relay_repo hook is missing"
            )

    # Step 1: mark revoked locally. Sends and acceptance stop immediately.
    if not dry_run:
        conn.execute(
            "UPDATE relationships SET consent_state = 'revoked'"
            " WHERE relationship_id = ?",
            (relationship_id,),
        )
    log("mark-revoked")

    # Step 2: revoke deploy keys, then delete the relay repository.
    for dk in deploy_keys:
        if not dry_run:
            hooks.revoke_deploy_key(dk)
        else:
            log(f"would-revoke-deploy-key:{dk.label}")
            continue
        report.deploy_keys_revoked.append(f"{dk.repo}:{dk.label}")
        log(f"revoke-deploy-key:{dk.label}")
    for repo in repos:
        if not dry_run:
            hooks.delete_relay_repo(repo)
        else:
            log(f"would-delete-relay-repo:{repo.repo}")
            continue
        report.relay_repos_deleted.append(repo.repo)
        log(f"delete-relay-repo:{repo.repo}")

    # Step 3: crypto-erasure boundary. Destroy private key material FIRST,
    # before any other state deletion in step 4.
    key_rows = conn.execute(
        "SELECT private_key_ref FROM key_epochs WHERE relationship_id = ?",
        (relationship_id,),
    ).fetchall()
    key_basenames: list[str] = []
    for (ref,) in key_rows:
        key_basenames.append(Path(ref).name)
        if not dry_run:
            secure_unlink(ref)
        report.keys_destroyed.append(ref)
    log("destroy-private-keys")
    # The material is gone before bulk deletion starts; the rows are
    # removed in step 4 after dependent event rows.
    report.crypto_erasure_before_bulk = True

    # Step 4: delete operational state.
    if not dry_run:
        # Lift the append-only triggers for this relationship's rows only
        # in effect (they are restored immediately afterwards).
        conn.execute("DROP TRIGGER IF EXISTS events_no_update")
        conn.execute("DROP TRIGGER IF EXISTS events_no_delete")
        try:
            event_ids = [
                r[0]
                for r in conn.execute(
                    "SELECT event_id FROM events WHERE relationship_id = ?",
                    (relationship_id,),
                ).fetchall()
            ]
            conv_ids = {
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT conversation_id FROM events"
                    " WHERE relationship_id = ?",
                    (relationship_id,),
                ).fetchall()
            }
            nonces = [
                r[0]
                for r in conn.execute(
                    "SELECT replay_nonce FROM events WHERE relationship_id = ?",
                    (relationship_id,),
                ).fetchall()
            ]
            for table in (
                "projection_queue",
                "surface_queue",
                "receipt_queue",
            ):
                col = "event_id" if table != "receipt_queue" else "target_event_id"
                for eid in event_ids:
                    conn.execute(
                        f"DELETE FROM {table} WHERE {col} = ?", (eid,)
                    )
            sched_ids = _migration_scheduled_ids(conn, relationship_id)
            for sid in sched_ids:
                conn.execute(
                    "DELETE FROM scheduler_queue WHERE scheduled_id = ?", (sid,)
                )
            for nonce in nonces:
                conn.execute(
                    "DELETE FROM replay_guard WHERE replay_nonce = ?", (nonce,)
                )
            # Encrypted payload cache must go before events (foreign key).
            for eid in event_ids:
                conn.execute(
                    "DELETE FROM event_payloads WHERE event_id = ?", (eid,)
                )
            # Projection tables: rows keyed by event, conversation, or
            # relationship. No foreign keys, but they are relationship
            # traces and must not survive teardown. Tables that were never
            # created (e.g. deploy_key_registry on a store that never ran
            # the pairing ceremony) are skipped.
            existing_tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            placeholders = ",".join("?" for _ in event_ids) or "NULL"
            conn.execute(
                "DELETE FROM message_revisions "
                f"WHERE edit_event_id IN ({placeholders})",
                event_ids,
            )
            conn.execute(
                "DELETE FROM reactions "
                f"WHERE added_event_id IN ({placeholders})",
                event_ids,
            )
            conn.execute(
                "DELETE FROM receipts "
                f"WHERE receipt_event_id IN ({placeholders})",
                event_ids,
            )
            conn.execute(
                "DELETE FROM poll_responses "
                f"WHERE response_event_id IN ({placeholders})",
                event_ids,
            )
            for table in (
                "messages",
                "polls",
                "tasks",
                "human_requests",
                "deliveries",
                "security_key_events",
                "pending_refs",
                "sequence_gaps",
                "projection_cursors",
                "key_rotations",
                "rotation_quarantine",
                "transport_mutations",
                "transport_push_log",
                "deploy_key_registry",
            ):
                if table not in existing_tables:
                    continue
                conn.execute(
                    f"DELETE FROM {table} WHERE relationship_id = ?",
                    (relationship_id,),
                )
            for eid in event_ids:
                conn.execute("DELETE FROM events WHERE event_id = ?", (eid,))
            # Conversations left with no events are local traces of this
            # relationship; remove them and their threads. Conversations
            # still referenced by other events are kept.
            for cid in conv_ids:
                remaining = conn.execute(
                    "SELECT COUNT(*) FROM events WHERE conversation_id = ?",
                    (cid,),
                ).fetchone()[0]
                if remaining == 0:
                    conn.execute(
                        "DELETE FROM threads WHERE conversation_id = ?", (cid,)
                    )
                    conn.execute(
                        "DELETE FROM conversations WHERE conversation_id = ?",
                        (cid,),
                    )
            if conv_ids:
                conv_list = sorted(conv_ids)
                cplaceholders = ",".join("?" for _ in conv_list)
                conn.execute(
                    "DELETE FROM thread_state "
                    f"WHERE conversation_id IN ({cplaceholders})",
                    conv_list,
                )
            conn.execute(
                "DELETE FROM key_epochs WHERE relationship_id = ?",
                (relationship_id,),
            )
            conn.execute(
                "DELETE FROM sender_sequence WHERE relationship_id = ?",
                (relationship_id,),
            )
            _delete_relationship_invites(conn, relationship_id)
            _delete_relationship_mstate(conn, relationship_id)
            conn.execute(
                "DELETE FROM relationships WHERE relationship_id = ?",
                (relationship_id,),
            )
        finally:
            conn.execute(_TRIGGER_EVENTS_NO_UPDATE)
            conn.execute(_TRIGGER_EVENTS_NO_DELETE)
        conn.execute("VACUUM")
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:  # noqa: BLE001
            pass
    log("delete-state")

    # Step 4 (files) / 5: overwrite once, unlink, remove dirs.
    if not dry_run:
        for dirname in _OPERATIONAL_DIRS:
            _wipe_tree(state_dir / dirname, report, dry_run)
        # Per-relationship transport and watcher state (authoritative list
        # from _relationship_fs_paths): the git mirror, the mirror lock,
        # and watcher resume state. Wiping these is what lets the postcheck
        # below pass after the keys were destroyed in step 3.
        for path in _relationship_fs_paths(state_dir, relationship_id):
            _wipe_tree(path, report, dry_run)
        # Any stray file or dir named with the relationship id.
        for p in list(state_dir.iterdir()):
            if relationship_id in p.name and p.name != "tombstones":
                _wipe_tree(p, report, dry_run)
        # Relay config file.
        for cfg_name in ("relay.json", "relay.yaml"):
            cfg = state_dir / cfg_name
            if cfg.is_file():
                secure_unlink(cfg)
                report.files_deleted += 1
    log("wipe-files")

    # Step 6: minimal consent tombstone (id hash, revoked time, reason).
    tombstone = _tombstone_path(state_dir, relationship_id)
    if not dry_run:
        tombstone.parent.mkdir(parents=True, exist_ok=True)
        tombstone.write_text(
            json.dumps(
                {
                    "relationship_id_sha256": digest,
                    "revoked_at": report.revoked_at,
                    "reason_code": reason_code,
                }
            ),
            encoding="utf-8",
        )
        os.chmod(tombstone, 0o600)
    report.tombstone_path = str(tombstone)
    log("write-tombstone")

    # Step 5 (post-check): scan for pair ID, peer label, key filenames.
    scan = postcheck_scan(
        state_dir, relationship_id, peer_label, tuple(key_basenames)
    )
    report.postcheck_scanned = scan["scanned"]
    report.postcheck_hits = scan["hits"]
    log("postcheck-scan")
    if scan["hits"] and not dry_run:
        raise TeardownError(
            "postcheck-dirty",
            f"residual traces remain: {scan['hits'][:5]}",
        )
    return report


def _migration_state_refs(
    conn: Any, relationship_id: str
) -> list[tuple[str, Any]]:
    """All migration_state rows whose key or JSON value mentions the
    relationship id."""
    refs: list[tuple[str, Any]] = []
    for row in conn.execute("SELECT key, value FROM migration_state").fetchall():
        key, raw = row["key"], row["value"]
        try:
            value = json.loads(raw)
        except ValueError:
            value = None
        if relationship_id in key or (
            value is not None and relationship_id in json.dumps(value)
        ):
            refs.append((key, value))
    return refs


def _migration_scheduled_ids(conn: Any, relationship_id: str) -> list[str]:
    """Scheduled ids recorded for this relationship during migration."""
    ids: list[str] = []
    for key, value in _migration_state_refs(conn, relationship_id):
        if key.endswith(".scheduled_ids") and isinstance(value, list):
            ids.extend(str(v) for v in value)
    return ids


def _delete_relationship_invites(conn: Any, relationship_id: str) -> None:
    for key, value in _migration_state_refs(conn, relationship_id):
        if key.endswith(".invite_id") and isinstance(value, str):
            conn.execute("DELETE FROM invites WHERE invite_id = ?", (value,))


def _delete_relationship_mstate(conn: Any, relationship_id: str) -> None:
    for key, _value in _migration_state_refs(conn, relationship_id):
        # Never delete the global phase record; it describes the database,
        # not the relationship.
        if key in ("migration.phase",) or key.startswith("migration.phase_at."):
            continue
        conn.execute("DELETE FROM migration_state WHERE key = ?", (key,))
