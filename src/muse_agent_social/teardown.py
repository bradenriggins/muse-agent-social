"""Relationship teardown for Muse Agent Social v0.2 (lifecycle track).

Implements the implementation plan's RETENTION AND TEARDOWN section. Teardown
order is EXACTLY per the plan:

1. Mark the relationship revoked locally. Sends and acceptance stop
   immediately.
2. Revoke deploy keys and delete the relay repository (via injected
   transport/admin callbacks). Only relay metadata attributable to THIS
   relationship_id is acted on: deploy-key entries titled
   ``mas-pair-<relationship_id>`` (or whose public key is registered to this
   relationship in deploy_key_registry), and repos claimed by this
   relationship's relay_config row and by no other relationship. Other
   relationships' entries are kept: relay.json is rewritten without this
   relationship's entries and the file is removed only when nothing
   remains for anyone.
3. Delete relationship X25519 private keys and rotation candidates FIRST.
   This is the crypto-erasure boundary: private key material is destroyed
   (random overwrite, fsync, unlink via the keyfiles helper) before any
   other state deletion.
4. Delete pairing bundles, invite state, relay config, mirror, replay rows,
   retry queues, scheduler rows, plaintext cache, inbox, and outbox. The
   relationship's sealed event rows are also deleted so the post-check can
   verify no pair identifier remains (this requires briefly lifting the
   append-only triggers, which are restored afterwards). Scheduler rows are
   deleted both via the migration-scheduled-ids linkage and via the
   relationship's own event ids (scheduler_queue is the transactional
   outbox: scheduled_id IS the event_id for sends). Invite, pairing,
   approval, and quarantine rows scoped to the relationship are deleted;
   other relationships' rows are untouched.
5. Filesystem deletions are scoped to the relationship's own subtrees:
   shared operational dirs are pruned of only this relationship's files
   (own subdirectory, or files naming/mentioning the relationship id) and
   removed only when left empty; the per-relationship key subtree
   <keys_dir>/<relationship_id> is secure-wiped and removed; pairing
   ephemeral key material for this relationship's invites is wiped. Shared
   parent dirs (state dir, keys dir) are never removed.
6. Keep one minimal consent tombstone: relationship ID hash, revoked time,
   local reason code. No peer name, no message content.

Idempotency: re-running teardown for an already-torn-down relationship
(tombstone present, relationship row gone) is a no-op that returns a
report instead of raising.

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

from ._keyfiles import (
    PEER_KEY_REF,
    KeyFileError,
    default_keys_dir,
    delete_private_key,
)
from .store.db import utcnow
from .transports.provisioning import DEPLOY_KEY_TITLE_PREFIX

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

#: Shared operational directories pruned in step 4/5. These are NEVER
#: removed wholesale: only the relationship's own subdirectory and files
#: naming or mentioning the relationship id are deleted, and the shared
#: dir itself is removed only when left empty.
_OPERATIONAL_DIRS = (
    "bundles",
    "mirror",
    "cache",
    "inbox",
    "outbox",
    "retry",
    "plaintext_cache",
)

#: Content-scan cap for the operational-dir prune (mirrors postcheck_scan).
_CONTENT_SCAN_LIMIT = 1_048_576


def _relationship_fs_paths(state_dir: Path, relationship_id: str) -> list[Path]:
    """Every on-disk path owned by one relationship (authoritative list).

    Audited against every writer under the state dir:
      transports/github.py  mirrors/<rid>/      git working clone
      transports/base.py    locks/<rid>.lock    mirror flock
      watcher.py            watcher/<rid>.json  watcher resume state

    These are per-relationship, so only this relationship's subtree is
    wiped (never the whole mirrors/ or locks/ dir, which other
    relationships still use). Shared operational dirs (inbox, outbox, ...)
    are covered separately by _wipe_operational_dir.
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
    already_torn_down: bool = False


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
    """Overwrite every file once, then remove the tree.

    Only ever called with a relationship-owned path (see
    _relationship_fs_paths and the stray-name sweep in
    teardown_relationship); shared parent dirs never reach this function.
    """
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


def _file_mentions_rid(path: Path, relationship_id: str) -> bool:
    """True when a file's name (or, for small regular files, content)
    mentions the relationship id. Symlinks are judged by name only so a
    link pointing outside the state dir is never read through."""
    if relationship_id in path.name:
        return True
    if path.is_symlink():
        return False
    try:
        if path.stat().st_size > _CONTENT_SCAN_LIMIT:
            return False
        return relationship_id in path.read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return False


def _wipe_operational_dir(
    root: Path,
    relationship_id: str,
    report: TeardownReport,
    dry_run: bool,
) -> None:
    """Relationship-scoped prune of one shared operational directory.

    Deletes only this relationship's material: its own ``<dir>/<rid>``
    subdirectory, any other file or subdirectory whose name mentions the
    relationship id, and small files whose content mentions it. Other
    relationships' files are never touched. The shared directory itself is
    removed only when the prune leaves it empty; otherwise it stays for
    the relationships still using it.
    """
    if not root.exists() and not root.is_symlink():
        return
    if root.is_file() or root.is_symlink():
        # Not a directory at all: remove only if it names the relationship.
        if not dry_run and relationship_id in root.name:
            secure_unlink(root)
            report.files_deleted += 1
        return
    if dry_run:
        return
    # The relationship's own subtree first (per-relationship layout).
    own = root / relationship_id
    if own.is_dir() and not own.is_symlink():
        _wipe_tree(own, report, dry_run)
    elif own.is_file() or own.is_symlink():
        secure_unlink(own)
        report.files_deleted += 1
    # Then any stray file/subtree whose name mentions the relationship, or
    # whose (small) content does. Scoping: name/content match on
    # relationship_id; nothing else is unlinked.
    for dirpath, dirnames, filenames in os.walk(root):
        for d in list(dirnames):
            if relationship_id in d:
                _wipe_tree(Path(dirpath) / d, report, dry_run)
                dirnames.remove(d)
        for name in filenames:
            fp = Path(dirpath) / name
            if _file_mentions_rid(fp, relationship_id):
                secure_unlink(fp)
                report.files_deleted += 1
    # Prune directories left empty, bottom-up; never above root.
    for dirpath, _dirnames, _filenames in os.walk(root, topdown=False):
        p = Path(dirpath)
        if p == root:
            continue
        try:
            p.rmdir()
        except OSError:
            pass
    try:
        root.rmdir()
    except OSError:
        return
    report.dirs_removed.append(str(root))


def _secure_wipe_subtree(
    target: Path, report: TeardownReport, dry_run: bool
) -> None:
    """Secure-wipe a relationship-owned subtree (key material).

    Every regular file is random-overwritten, fsynced, and unlinked via
    the keyfiles helper (symlinks are unlinked, never wiped through);
    emptied directories are then removed bottom-up. The target's parent
    (e.g. the shared keys dir) is never removed.
    """
    if not target.exists() and not target.is_symlink():
        return
    if dry_run:
        return
    if target.is_symlink() or target.is_file():
        delete_private_key(str(target))
        report.files_deleted += 1
        return
    if not target.is_dir():
        return
    for dirpath, _dirnames, filenames in os.walk(target):
        for name in filenames:
            # Scoping: only files under this relationship's subtree.
            delete_private_key(str(Path(dirpath) / name))
            report.files_deleted += 1
    for dirpath, _dirnames, _filenames in os.walk(target, topdown=False):
        try:
            Path(dirpath).rmdir()
        except OSError:
            pass
    report.dirs_removed.append(str(target))


def _keys_dir_candidates(conn: Any, state_dir: Path) -> list[Path]:
    """Candidate key directories holding per-relationship key subtrees.

    The state-dir convention (``<state_dir>/keys``) first, then the
    DB-derived default from _keyfiles. Deduped; callers only ever remove
    the ``<relationship_id>`` subtree inside each candidate.
    """
    cands = [Path(state_dir) / "keys"]
    try:
        derived = Path(default_keys_dir(conn))
    except KeyFileError:
        derived = None
    if derived is not None and os.path.abspath(
        derived
    ) != os.path.abspath(cands[0]):
        cands.append(derived)
    return cands


def _owner_slash_name(repo_url: str | None) -> str:
    """Extract ``owner/name`` from a GitHub relay URL (https or ssh form)."""
    if not repo_url:
        return ""
    if repo_url.startswith("https://github.com/"):
        rest = repo_url[len("https://github.com/") :]
    elif repo_url.startswith("git@github.com:"):
        rest = repo_url[len("git@github.com:") :]
    else:
        return ""
    if rest.endswith(".git"):
        rest = rest[: -len(".git")]
    owner, _, name = rest.partition("/")
    if not owner or not name or "/" in name:
        return ""
    return f"{owner}/{name}"


@dataclass
class _RelayRefs:
    """Relationship-filtered view of the global relay.json metadata."""

    keys_to_revoke: list[DeployKeyRef] = field(default_factory=list)
    repos_to_delete: list[RelayRef] = field(default_factory=list)
    keep_deploy_keys: list[Any] = field(default_factory=list)
    keep_repos: list[Any] = field(default_factory=list)
    relay_json_present: bool = False
    relay_json_parseable: bool = False


def _deploy_key_claim(
    entry: dict, key_claims: dict[str, str]
) -> str | None:
    """Which relationship a relay.json deploy-key entry belongs to.

    Returns the claimed relationship id, or None when the entry carries
    no attribution (legacy format). Attribution signals, in order:
    the ``mas-pair-<relationship_id>`` title prefix written by the pairing
    flow, then the deploy_key_registry public-key mapping.
    """
    title = str(entry.get("title") or entry.get("label") or "")
    if title.startswith(DEPLOY_KEY_TITLE_PREFIX):
        return title[len(DEPLOY_KEY_TITLE_PREFIX) :]
    pub = entry.get("key") or ""
    if pub and pub in key_claims:
        return key_claims[pub]
    return None


def _discover_relay_refs(
    conn: Any, state_dir: Path, relationship_id: str
) -> _RelayRefs:
    """Filter the global relay.json metadata to this relationship_id.

    Deploy keys: revoked only when claimed by this relationship (title
    prefix or registry mapping), or when the entry carries no attribution
    at all AND this is the only relationship in the database (legacy
    format; with a single relationship the unattributed entry can only
    be its). Entries claimed by a different relationship, and unattributed
    entries while other relationships exist, are kept, never revoked.

    Repos: deleted only when claimed by this relationship's relay_config
    row and by no other relationship, or when claimed by nobody AND this
    is the only relationship in the database (legacy entry). A repo
    another relationship's relay_config still references, and an
    unclaimed repo while other relationships exist, is never deleted.
    """
    refs = _RelayRefs()
    cfg = state_dir / "relay.json"
    if not cfg.is_file():
        return refs
    refs.relay_json_present = True
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        # Unparseable: fail closed. Nothing is revoked and the file is
        # left untouched; the postcheck will flag any residual traces.
        return refs
    raw_keys = data.get("deploy_keys", []) or []
    raw_repos = data.get("repos", []) or []
    if not isinstance(raw_keys, list) or not isinstance(raw_repos, list):
        return refs
    refs.relay_json_parseable = True

    existing_tables = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    # Unattributed legacy entries are only actionable when ownership is
    # unambiguous: exactly one relationship in the database, which must
    # be this one (its row still exists at discovery time).
    single_relationship = (
        conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0] == 1
    )
    # repo name -> relationships whose relay_config row references it.
    repo_claims: dict[str, set[str]] = {}
    own_repo = ""
    if "relay_config" in existing_tables:
        for rel_row in conn.execute(
            "SELECT relationship_id, repo_url FROM relay_config"
        ).fetchall():
            name = _owner_slash_name(rel_row[1])
            if name:
                repo_claims.setdefault(name, set()).add(rel_row[0])
        row = conn.execute(
            "SELECT repo_url FROM relay_config WHERE relationship_id = ?",
            (relationship_id,),
        ).fetchone()
        if row:
            own_repo = _owner_slash_name(row[0])
    # deploy public key -> relationship it is registered to.
    key_claims: dict[str, str] = {}
    if "deploy_key_registry" in existing_tables:
        for reg_row in conn.execute(
            "SELECT deploy_public_key, relationship_id FROM deploy_key_registry"
        ).fetchall():
            key_claims[reg_row[0]] = reg_row[1]

    for entry in raw_keys:
        if not isinstance(entry, dict):
            # Not a shape we can revoke; keep it rather than destroy it.
            refs.keep_deploy_keys.append(entry)
            continue
        claim = _deploy_key_claim(entry, key_claims)
        if claim is not None and claim != relationship_id:
            # Scoping: another relationship's deploy key; never revoke.
            refs.keep_deploy_keys.append(entry)
            continue
        if claim is None and not single_relationship:
            # Scoping: unattributed legacy entry while other relationships
            # exist; ownership is ambiguous, so preserve it and never pass
            # it to the revoke hook.
            refs.keep_deploy_keys.append(entry)
            continue
        refs.keys_to_revoke.append(
            DeployKeyRef(
                # Scoping: this relationship's key (claimed by it, or the
                # sole relationship's unattributed legacy entry).
                repo=str(entry.get("repo") or "") or own_repo,
                label=str(entry.get("title") or entry.get("label") or ""),
                # relay.json writers have used both "key_id" and "id"
                # for the GitHub key id; accept either.
                key_id=str(entry.get("key_id") or entry.get("id") or ""),
            )
        )
    for entry in raw_repos:
        if isinstance(entry, str):
            name, transport = entry, ""
        elif isinstance(entry, dict):
            name, transport = str(entry.get("repo") or ""), str(
                entry.get("transport") or ""
            )
        else:
            refs.keep_repos.append(entry)
            continue
        if not name:
            refs.keep_repos.append(entry)
            continue
        claimants = repo_claims.get(name, set())
        if claimants and claimants != {relationship_id}:
            # Scoping: another relationship still references this repo
            # (or shares it); never delete it.
            refs.keep_repos.append(entry)
            continue
        if not claimants and not single_relationship:
            # Scoping: unclaimed legacy repo while other relationships
            # exist; ownership is ambiguous, so preserve it and never pass
            # it to the delete hook.
            refs.keep_repos.append(entry)
            continue
        # Scoping: claimed only by this relationship, or the sole
        # relationship's unclaimed legacy entry; never a repo another
        # relationship uses.
        refs.repos_to_delete.append(RelayRef(repo=name, transport=transport))
    return refs


def _prune_relay_json(
    state_dir: Path,
    refs: _RelayRefs,
    report: TeardownReport,
    dry_run: bool,
    log: Callable[[str], None],
) -> None:
    """Remove only this relationship's entries from the global relay.json.

    Scoping: entries kept for other relationships are rewritten back to
    the file; the file itself is deleted only when no entries remain for
    anyone. An unparseable file is left untouched (fail closed).
    """
    if not refs.relay_json_present:
        return
    if not refs.relay_json_parseable:
        log("relay-json-unparseable: left untouched")
        return
    cfg = state_dir / "relay.json"
    if refs.keep_deploy_keys or refs.keep_repos:
        if not dry_run:
            cfg.write_text(
                json.dumps(
                    {
                        "deploy_keys": refs.keep_deploy_keys,
                        "repos": refs.keep_repos,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        log("prune-relay-json: kept other relationships' entries")
    else:
        if not dry_run:
            secure_unlink(cfg)
            report.files_deleted += 1
        log("delete-relay-json: no entries remain")


def postcheck_scan(
    state_dir: str | Path,
    relationship_id: str,
    peer_label: str | None = None,
    key_refs: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Scan the state dir for residual traces.

    Checks filenames, file paths, and file contents for the raw
    relationship id, the peer label, and private key refs. Full key ref
    paths (not bare basenames) are used as needles so a surviving
    relationship's key files, which may share a basename (per-relationship
    layout ``<keys_dir>/<rid>/epoch1.key``), are not flagged. The
    tombstones directory is excluded (it holds only the ID hash, which
    cannot match the raw id). Returns {"scanned": n, "hits": [paths]}.
    """
    root = Path(state_dir)
    needles = [relationship_id]
    if peer_label:
        needles.append(peer_label)
    needles.extend(key_refs)
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
            # The path itself is part of the haystack so full key ref
            # paths match leftover files at their recorded location.
            hay = str(fp) + "\x00" + name
            try:
                if fp.stat().st_size <= 1_048_576:
                    hay += "\x00" + fp.read_text(encoding="utf-8", errors="replace")
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

    Every destructive step is scoped to relationship_id: relay metadata
    reads are filtered to this relationship's entries, filesystem
    deletions touch only this relationship's subtrees and entries, and
    database deletions are keyed by this relationship's ids. Re-running
    for an already-torn-down relationship is a no-op returning a report.
    """
    hooks = hooks or TeardownHooks()
    state_dir = Path(state_dir)
    if (
        not relationship_id
        or "/" in relationship_id
        or "\\" in relationship_id
        or relationship_id in (".", "..")
    ):
        # Scoping: a path-unsafe id must never reach the filesystem sweeps
        # below, where it would act as a substring match on file names.
        raise TeardownError("bad-relationship-id", str(relationship_id))
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
    tombstone = _tombstone_path(state_dir, relationship_id)
    if row is None:
        if tombstone.is_file():
            # Idempotency: a previous run completed and left its tombstone.
            # Re-verify the postcheck is still clean, then no-op.
            report.already_torn_down = True
            report.tombstone_path = str(tombstone)
            log("already-torn-down")
            scan = postcheck_scan(state_dir, relationship_id, peer_label)
            report.postcheck_scanned = scan["scanned"]
            report.postcheck_hits = scan["hits"]
            if scan["hits"] and not dry_run:
                raise TeardownError(
                    "postcheck-dirty",
                    f"residual traces remain: {scan['hits'][:5]}",
                )
            return report
        raise TeardownError("unknown-relationship", relationship_id)

    # Relationship-filtered relay metadata: only entries belonging to this
    # relationship_id may be revoked or deleted in step 2.
    refs = _discover_relay_refs(conn, state_dir, relationship_id)
    # Invite ids linked to this relationship (for pairing-table and
    # ephemeral key-material cleanup); resolved before step 4 deletes the
    # migration_state refs that carry the linkage.
    invite_ids = _relationship_invite_ids(conn, relationship_id)

    # Pre-validate remote hooks before any mutation, so a missing hook
    # fails fast instead of leaving a half-torn-down relationship.
    # Scoping: hooks are required only for this relationship's entries;
    # other relationships' entries never force a hook requirement here.
    if not dry_run:
        if refs.keys_to_revoke and hooks.revoke_deploy_key is None:
            raise TeardownError(
                "hook-required", "revoke_deploy_key hook is missing"
            )
        if refs.repos_to_delete and hooks.delete_relay_repo is None:
            raise TeardownError(
                "hook-required", "delete_relay_repo hook is missing"
            )

    # Step 1: mark revoked locally. Sends and acceptance stop immediately.
    # Scoping: WHERE relationship_id = ?; no other relationship is touched.
    if not dry_run:
        conn.execute(
            "UPDATE relationships SET consent_state = 'revoked'"
            " WHERE relationship_id = ?",
            (relationship_id,),
        )
    log("mark-revoked")

    # Step 2: revoke deploy keys, then delete the relay repository.
    # Scoping: refs.keys_to_revoke / refs.repos_to_delete were filtered to
    # this relationship_id at discovery; other relationships' keys and
    # repos are never passed to the hooks.
    for dk in refs.keys_to_revoke:
        if not dry_run:
            hooks.revoke_deploy_key(dk)
        else:
            log(f"would-revoke-deploy-key:{dk.label}")
            continue
        report.deploy_keys_revoked.append(f"{dk.repo}:{dk.label}")
        log(f"revoke-deploy-key:{dk.label}")
    for repo in refs.repos_to_delete:
        if not dry_run:
            hooks.delete_relay_repo(repo)
        else:
            log(f"would-delete-relay-repo:{repo.repo}")
            continue
        report.relay_repos_deleted.append(repo.repo)
        log(f"delete-relay-repo:{repo.repo}")

    # Step 3: crypto-erasure boundary. Destroy private key material FIRST,
    # before any other state deletion in step 4.
    # Scoping: only key_epochs rows for this relationship_id.
    key_rows = conn.execute(
        "SELECT private_key_ref FROM key_epochs WHERE relationship_id = ?",
        (relationship_id,),
    ).fetchall()
    # Full key ref paths (not bare basenames) are the postcheck needles:
    # a surviving relationship's key files may share a basename
    # (per-relationship layout <keys_dir>/<rid>/epoch1.key), and those
    # are not this relationship's traces.
    key_refs: list[str] = []
    for (ref,) in key_rows:
        if ref == PEER_KEY_REF:
            # Sentinel marking a peer-public-key row: no local private key
            # exists, so there is nothing to unlink (and the bare name must
            # never be resolved against the process working directory).
            continue
        key_refs.append(ref)
        if not dry_run:
            # Random overwrite, fsync, unlink; O_NOFOLLOW so a symlinked
            # ref is never wiped through.
            delete_private_key(ref)
            report.keys_destroyed.append(ref)
    log("destroy-private-keys")
    # The material is gone before bulk deletion starts; the rows are
    # removed in step 4 after dependent event rows.
    report.crypto_erasure_before_bulk = not dry_run

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
            # Tables that were never created (e.g. deploy_key_registry on a
            # store that never ran the pairing ceremony) are skipped.
            existing_tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            for table in (
                "projection_queue",
                "surface_queue",
                "receipt_queue",
            ):
                # Scoping: only queue rows for this relationship's events.
                col = "event_id" if table != "receipt_queue" else "target_event_id"
                for eid in event_ids:
                    conn.execute(
                        f"DELETE FROM {table} WHERE {col} = ?", (eid,)
                    )
            # Scoping: only scheduler rows recorded for this relationship
            # during migration...
            sched_ids = _migration_scheduled_ids(conn, relationship_id)
            for sid in sched_ids:
                conn.execute(
                    "DELETE FROM scheduler_queue WHERE scheduled_id = ?", (sid,)
                )
            # ...plus rows for this relationship's own events. The
            # scheduler queue is the transactional outbox and scheduled_id
            # IS the event_id for sends: any surviving row would later
            # transmit for a dead relationship.
            # Scoping: scheduled_id IN this relationship's event_ids only.
            if event_ids:
                eplaceholders = ",".join("?" for _ in event_ids)
                conn.execute(
                    "DELETE FROM scheduler_queue"
                    f" WHERE scheduled_id IN ({eplaceholders})",
                    event_ids,
                )
                # sent_objects maps scheduled_id (= event_id) to uploaded
                # relay object names: per-relationship outbox bookkeeping.
                # Scoping: this relationship's event_ids only.
                if "sent_objects" in existing_tables:
                    conn.execute(
                        "DELETE FROM sent_objects"
                        f" WHERE scheduled_id IN ({eplaceholders})",
                        event_ids,
                    )
            for nonce in nonces:
                # Scoping: only this relationship's replay nonces.
                conn.execute(
                    "DELETE FROM replay_guard WHERE replay_nonce = ?", (nonce,)
                )
            # Encrypted payload cache must go before events (foreign key).
            # Scoping: only this relationship's events.
            for eid in event_ids:
                conn.execute(
                    "DELETE FROM event_payloads WHERE event_id = ?", (eid,)
                )
            # Projection tables: rows keyed by event, conversation, or
            # relationship. No foreign keys, but they are relationship
            # traces and must not survive teardown.
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
                # Scoping on every table: WHERE relationship_id = ?, so only
                # this relationship's keys, approvals, quarantine rows, and
                # relay config are deleted.
                "deploy_key_registry",
                "human_approvals",
                "quarantine",
                "receive_quarantine",
                "relay_config",
            ):
                if table not in existing_tables:
                    continue
                conn.execute(
                    f"DELETE FROM {table} WHERE relationship_id = ?",
                    (relationship_id,),
                )
            for eid in event_ids:
                # Scoping: only this relationship's sealed event rows.
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
            _delete_relationship_invites(conn, relationship_id, existing_tables)
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

    # Step 4 (files) / 5: overwrite once, unlink, remove dirs. Every
    # deletion below is scoped to this relationship_id: shared parent dirs
    # (state dir, keys dir, relay.json) are pruned, never removed wholesale.
    if not dry_run:
        for dirname in _OPERATIONAL_DIRS:
            _wipe_operational_dir(
                state_dir / dirname, relationship_id, report, dry_run
            )
        # Per-relationship transport and watcher state (authoritative list
        # from _relationship_fs_paths): the git mirror, the mirror lock,
        # and watcher resume state. Wiping these is what lets the postcheck
        # below pass after the keys were destroyed in step 3.
        # Scoping: only this relationship's paths; sibling relationships'
        # mirrors/locks/watcher files are untouched.
        for path in _relationship_fs_paths(state_dir, relationship_id):
            _wipe_tree(path, report, dry_run)
        # Any stray file or dir named with the relationship id.
        # Scoping: name match on relationship_id (validated path-safe
        # above); the tombstones dir is excluded.
        for p in list(state_dir.iterdir()):
            if relationship_id in p.name and p.name != "tombstones":
                _wipe_tree(p, report, dry_run)
        # The per-relationship key subtree, secure-wiped first (random
        # overwrite, fsync, unlink per file). Scoping: only
        # <keys_dir>/<relationship_id>; the shared keys dir itself stays.
        # Pairing-ephemeral key material for this relationship's invites
        # (<keys_dir>/invites/<iid>, <keys_dir>/pairing/<iid>) goes too.
        for keys_dir in _keys_dir_candidates(conn, state_dir):
            _secure_wipe_subtree(
                keys_dir / relationship_id, report, dry_run
            )
            for iid in invite_ids:
                if (
                    not iid
                    or "/" in iid
                    or "\\" in iid
                    or iid in (".", "..")
                ):
                    continue
                _secure_wipe_subtree(
                    keys_dir / "invites" / iid, report, dry_run
                )
                _secure_wipe_subtree(
                    keys_dir / "pairing" / iid, report, dry_run
                )
        # Relay config file: only this relationship's entries are pruned;
        # the file survives while other relationships have entries.
        _prune_relay_json(state_dir, refs, report, dry_run, log)
        # relay.yaml is legacy ambient config (nothing in v0.2 writes it).
        cfg = state_dir / "relay.yaml"
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

    # Step 5 (post-check): scan for pair ID, peer label, key refs.
    scan = postcheck_scan(
        state_dir, relationship_id, peer_label, tuple(key_refs)
    )
    report.postcheck_scanned = scan["scanned"]
    hits = scan["hits"]
    report.postcheck_hits = hits
    log("postcheck-scan")
    if hits and not dry_run:
        raise TeardownError(
            "postcheck-dirty",
            f"residual traces remain: {hits[:5]}",
        )
    return report


def _relationship_invite_ids(conn: Any, relationship_id: str) -> list[str]:
    """Invite ids linked to this relationship via migration_state refs.

    Scoping: only refs whose key segment or JSON value names this
    relationship_id; other relationships' invites are never returned.
    """
    ids: list[str] = []
    for key, value in _migration_state_refs(conn, relationship_id):
        if (
            key.endswith(".invite_id")
            and isinstance(value, str)
            and value not in ids
        ):
            ids.append(value)
    return ids


def _migration_state_refs(
    conn: Any, relationship_id: str
) -> list[tuple[str, Any]]:
    """All migration_state rows scoped to the relationship id.

    A row matches when its key is exactly ``migration.<id>`` or starts
    with the ``migration.<id>.`` segment, or when its JSON value mentions
    the id. Segment matching (not substring) keeps one relationship from
    matching another's keys.
    """
    refs: list[tuple[str, Any]] = []
    segment = f"migration.{relationship_id}."
    exact = f"migration.{relationship_id}"
    for row in conn.execute("SELECT key, value FROM migration_state").fetchall():
        key, raw = row["key"], row["value"]
        try:
            value = json.loads(raw)
        except ValueError:
            value = None
        if (
            key == exact
            or key.startswith(segment)
            or (value is not None and relationship_id in json.dumps(value))
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


def _delete_relationship_invites(
    conn: Any, relationship_id: str, existing_tables: set[str]
) -> None:
    """Delete pairing-ceremony rows for this relationship's invites.

    Scoping: only invites linked to this relationship_id (via
    migration_state refs); other relationships' invites keep their rows.
    Child rows (pairing_verifications, invite_bodies) are deleted before
    the invites parent rows for the foreign key.
    """
    invite_ids = _relationship_invite_ids(conn, relationship_id)
    if not invite_ids:
        return
    placeholders = ",".join("?" for _ in invite_ids)
    for table in (
        "pairing_verifications",
        "invite_bodies",
        "pairing_acceptances",
    ):
        if table not in existing_tables:
            continue
        conn.execute(
            f"DELETE FROM {table} WHERE invite_id IN ({placeholders})",
            invite_ids,
        )
    if "invites" in existing_tables:
        conn.execute(
            f"DELETE FROM invites WHERE invite_id IN ({placeholders})",
            invite_ids,
        )


def _delete_relationship_mstate(conn: Any, relationship_id: str) -> None:
    """Delete migration_state rows scoped to this relationship_id.

    Scoping: only rows whose key segment or JSON value names this
    relationship; the global phase record is never deleted.
    """
    for key, _value in _migration_state_refs(conn, relationship_id):
        # Never delete the global phase record; it describes the database,
        # not the relationship.
        if key in ("migration.phase",) or key.startswith("migration.phase_at."):
            continue
        conn.execute("DELETE FROM migration_state WHERE key = ?", (key,))
