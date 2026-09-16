"""Private-key file storage conventions for Muse Agent Social v0.2.

Internal helper shared by the pairing ceremony (``model.invites``) and key
rotation (``crypto.rotation``). Not part of the public protocol surface.

Conventions:
- Private key files live under ``<keys_dir>/`` (default: ``<db_dir>/keys``,
  where ``<db_dir>`` is the directory holding the SQLite state database).
- Files are created with mode 0o600 and never overwritten (O_CREAT | O_EXCL
  semantics, enforced atomically).
- Parent directories are created with mode 0o700; a chmod that does not take
  effect is a hard error, never silently ignored.
- Writes are atomic: bytes go to a temp file in the same directory, are
  fsynced, then hard-linked to the final path (link(2) fails atomically if
  the destination exists), so a crash can never leave a partial key file.
- Deletion overwrites the file with random bytes (fsynced) before unlinking,
  so a retired key is not recoverable from the raw disk after deletion.
- ``private_key_ref`` values stored in the ``key_epochs`` table are
  filesystem paths, except the reserved sentinel ``"peer"`` which marks a
  row that describes the PEER's public key for that epoch (no local private
  key exists). The sentinel is never a valid path and must never be treated
  as one.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile

__all__ = [
    "KeyFileError",
    "PEER_KEY_REF",
    "default_keys_dir",
    "store_private_key",
    "delete_private_key",
    "atomic_write_no_overwrite",
    "atomic_write_file",
    "atomic_write_pair",
    "recover_pending_pair",
]


class KeyFileError(Exception):
    """Private key file storage failed."""


PEER_KEY_REF = "peer"
"""Reserved ``private_key_ref`` marking a peer public-key row (no local key)."""

_DIR_MODE = 0o700
_FILE_MODE = 0o600
_WIPE_CHUNK = 65536


def default_keys_dir(conn) -> str:
    """Resolve the default keys directory from a SQLite connection.

    Uses the directory containing the database file, plus ``/keys``. Raises
    KeyFileError for pathless databases (e.g. ``:memory:``); callers must
    pass an explicit ``keys_dir`` in that case.
    """
    row = conn.execute("PRAGMA database_list").fetchone()
    db_file = row[2] if row else ""
    if not db_file:
        raise KeyFileError(
            "keys_dir is required when the database has no file path "
            "(e.g. :memory:); pass keys_dir explicitly"
        )
    return os.path.join(os.path.dirname(os.path.abspath(db_file)), "keys")


def _secure_parent_dir(parent: str, *, strict: bool = True) -> str:
    """Create *parent* (mode 0o700) and verify the mode actually took effect.

    With strict=True (the default, used for all key material) a directory
    whose mode cannot be locked down is a hard KeyFileError, never silently
    ignored. With strict=False the failure degrades to a loud stderr
    warning and the directory is used as-is; this is only for non-secret
    files (config) on filesystems without POSIX permission semantics, where
    refusing to run at all would be worse than running with degraded
    permissions. The default is never silently weakened.
    """
    os.makedirs(parent, mode=_DIR_MODE, exist_ok=True)
    try:
        os.chmod(parent, _DIR_MODE)
    except OSError as exc:
        if not strict:
            print(
                f"WARNING: cannot set mode 0700 on {parent} ({exc}); "
                "continuing with degraded directory permissions",
                file=sys.stderr,
            )
            return parent
        raise KeyFileError(
            f"cannot set mode 0700 on key directory {parent}: {exc}"
        ) from exc
    try:
        actual = stat.S_IMODE(os.stat(parent).st_mode)
    except OSError as exc:
        if not strict:
            print(
                f"WARNING: cannot stat {parent} ({exc}); continuing with "
                "degraded directory permissions",
                file=sys.stderr,
            )
            return parent
        raise KeyFileError(
            f"cannot stat key directory {parent}: {exc}"
        ) from exc
    if actual != _DIR_MODE:
        msg = (
            f"key directory {parent} has mode {oct(actual)}, expected 0o700; "
            "this filesystem cannot express POSIX permissions"
        )
        if not strict:
            print(f"WARNING: {msg}; continuing with degraded permissions",
                  file=sys.stderr)
            return parent
        raise KeyFileError(msg + "; refusing to store key material there")
    return parent


def atomic_write_no_overwrite(
    path, data: bytes, mode: int = _FILE_MODE, *, strict: bool = True
) -> str:
    """Atomically write *data* to *path* without overwriting an existing file.

    The bytes are written to a temp file in the same directory, fsynced, then
    hard-linked to the final path; link(2) fails atomically with
    FileExistsError when the destination already exists, so the
    never-overwrite guarantee holds even under concurrency and a crash can
    never leave a partial file at the destination. The parent directory is
    fsynced after the link for durability. Returns the path as a string.

    strict=False degrades an unenforceable parent-dir mode to a loud
    warning (see _secure_parent_dir); the default strict=True keeps the
    hard error for key material.
    """
    path = os.path.abspath(os.fspath(path))
    data = bytes(data)
    parent = _secure_parent_dir(os.path.dirname(path), strict=strict)
    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".tmp-key-")
    try:
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb", closefd=True) as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        # Atomic, no-overwrite publish.
        os.link(tmp_path, path)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return path


def atomic_write_file(
    path, data: bytes, mode: int = _FILE_MODE, *, strict: bool = True
) -> str:
    """Atomically write *data* to *path*, replacing any existing file.

    Same durability guarantees as :func:`atomic_write_no_overwrite`, but the
    final publish uses os.replace(2), so an existing destination is replaced
    atomically. For non-key files (config, state) that are routinely updated.

    strict=False degrades an unenforceable parent-dir mode to a loud
    warning (see _secure_parent_dir); the default strict=True keeps the
    hard error.
    """
    path = os.path.abspath(os.fspath(path))
    data = bytes(data)
    parent = _secure_parent_dir(os.path.dirname(path), strict=strict)
    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".tmp-write-")
    try:
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb", closefd=True) as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        os.replace(tmp_path, path)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return path


def _fsync_dir(path: str) -> None:
    """fsync a directory so file creations/renames inside it are durable."""
    dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _unlink_quiet(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _stage_temp(parent: str, data: bytes, mode: int) -> str:
    """Write *data* to a temp file in *parent*: chmod, write, fsync.

    Returns the temp path. The file is NOT published; the caller renames it
    into place. On failure the temp file is removed and the error re-raised.
    """
    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".tmp-pair-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        _unlink_quiet(tmp_path)
        raise
    return tmp_path


def atomic_write_pair(
    path_a,
    data_a: bytes,
    mode_a: int,
    path_b,
    data_b: bytes,
    mode_b: int,
    *,
    journal_path,
    strict: bool = True,
) -> tuple[str, str]:
    """Atomically publish two files as a pair (crash-safe).

    Both temp files are fully written, chmodded and fsynced, and both
    parent directories fsynced, before either file becomes visible. A
    journal file at *journal_path* records the pending publish and is
    itself fsynced as the commit point; both renames then run back to
    back, the parent directories are fsynced again, and the journal is
    removed. A crash at any point leaves either the old pair or the new
    pair: :func:`recover_pending_pair` re-drives an interrupted publish
    at startup, so the pair converges instead of staying torn.

    This is for files that must change together (identity seed + agent
    card). Do not use it for single files; use :func:`atomic_write_file`.
    """
    path_a = os.path.abspath(os.fspath(path_a))
    path_b = os.path.abspath(os.fspath(path_b))
    journal_path = os.path.abspath(os.fspath(journal_path))
    data_a = bytes(data_a)
    data_b = bytes(data_b)
    parent_a = _secure_parent_dir(os.path.dirname(path_a), strict=strict)
    parent_b = _secure_parent_dir(os.path.dirname(path_b), strict=strict)
    journal_parent = _secure_parent_dir(
        os.path.dirname(journal_path), strict=strict
    )
    tmp_a = _stage_temp(parent_a, data_a, mode_a)
    try:
        tmp_b = _stage_temp(parent_b, data_b, mode_b)
    except BaseException:
        _unlink_quiet(tmp_a)
        raise
    journal_written = False
    try:
        _fsync_dir(parent_a)
        if parent_b != parent_a:
            _fsync_dir(parent_b)
        # The journal is the commit point: once it is durable, the new
        # pair is committed and any interruption is repaired by
        # recover_pending_pair (which re-drives the renames).
        journal_tmp = _stage_temp(
            journal_parent,
            json.dumps(
                {
                    "v": 1,
                    "files": [
                        {"tmp": tmp_a, "target": path_a},
                        {"tmp": tmp_b, "target": path_b},
                    ],
                },
                sort_keys=True,
            ).encode("utf-8"),
            0o600,
        )
        try:
            os.replace(journal_tmp, journal_path)
            _fsync_dir(journal_parent)
        except BaseException:
            _unlink_quiet(journal_tmp)
            raise
        journal_written = True
        os.replace(tmp_a, path_a)
        os.replace(tmp_b, path_b)
        _fsync_dir(parent_a)
        if parent_b != parent_a:
            _fsync_dir(parent_b)
        os.unlink(journal_path)
        _fsync_dir(journal_parent)
    except BaseException:
        # Before the journal commit point the old pair is untouched, so
        # staged temps are just garbage: remove them. After the commit
        # point the temps MUST survive for recover_pending_pair.
        if not journal_written:
            _unlink_quiet(tmp_a)
            _unlink_quiet(tmp_b)
        raise
    return path_a, path_b


def recover_pending_pair(journal_path) -> bool:
    """Complete an interrupted :func:`atomic_write_pair`.

    Re-drives any renames that did not happen before the crash, fsyncs the
    parent directories, and removes the journal. Returns True when a
    pending journal was found and handled, False when there was nothing to
    do. Idempotent: safe to call on every startup. A journal that cannot
    be parsed raises KeyFileError (loud, never silently ignored).
    """
    jp = os.path.abspath(os.fspath(journal_path))
    try:
        with open(jp, "rb") as fh:
            journal = json.load(fh)
    except FileNotFoundError:
        return False
    except (OSError, ValueError) as exc:
        raise KeyFileError(
            f"cannot parse pending pair journal {jp}: {exc}"
        ) from exc
    try:
        files = journal["files"]
    except (TypeError, KeyError) as exc:
        raise KeyFileError(
            f"pending pair journal {jp} has no file list"
        ) from exc
    parents = set()
    for item in files:
        tmp, target = item["tmp"], item["target"]
        parents.add(os.path.dirname(os.path.abspath(target)))
        if os.path.exists(tmp):
            os.replace(tmp, target)
    for parent in parents:
        _fsync_dir(parent)
    os.unlink(jp)
    _fsync_dir(os.path.dirname(jp))
    return True


def store_private_key(path, data: bytes) -> str:
    """Write private key *data* to *path* with mode 0o600.

    Creates parent directories with mode 0o700. Refuses to overwrite an
    existing file (raises FileExistsError). The write is atomic: a crash
    mid-write leaves no partial file behind. Returns the path as a string.
    """
    return atomic_write_no_overwrite(path, data, _FILE_MODE)


def delete_private_key(path) -> bool:
    """Securely delete a private key file: overwrite with random bytes, fsync, unlink.

    The overwrite runs through O_NOFOLLOW so a symlinked path is never wiped
    through. Returns True only when the file is gone (or was already
    absent) AND the random overwrite completed: a wipe that failed partway
    (e.g. ENOSPC) still unlinks the file but returns False, so callers can
    never attest crypto erasure they did not achieve. Returns False when the
    file still exists afterwards.
    """
    try:
        st = os.lstat(os.fspath(path))
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        # Not a regular file (symlink, dir, ...): unlink only, never wipe through it.
        try:
            os.unlink(path)
            return True
        except OSError:
            return False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    except (FileNotFoundError, OSError):
        return not os.path.lexists(path)
    wipe_ok = True
    try:
        remaining = st.st_size
        while remaining > 0:
            chunk = os.urandom(min(remaining, _WIPE_CHUNK))
            written = os.write(fd, chunk)
            remaining -= written
        os.fsync(fd)
    except OSError:
        # The overwrite did not complete (disk full, I/O error, ...): the
        # wipe guarantee is void. Still unlink below so no key file is left
        # behind, but report failure so the caller never claims erasure.
        wipe_ok = False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(path)
    except FileNotFoundError:
        return wipe_ok
    except OSError:
        return False
    return wipe_ok
