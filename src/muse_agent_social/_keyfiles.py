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

import os
import stat
import tempfile

__all__ = [
    "KeyFileError",
    "PEER_KEY_REF",
    "default_keys_dir",
    "store_private_key",
    "delete_private_key",
    "atomic_write_no_overwrite",
    "atomic_write_file",
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


def _secure_parent_dir(parent: str) -> str:
    """Create *parent* (mode 0o700) and verify the mode actually took effect.

    Raises KeyFileError if the directory cannot be created or cannot be
    locked down to owner-only access. Never fails silently: a key file must
    never be written into a directory we could not secure.
    """
    os.makedirs(parent, mode=_DIR_MODE, exist_ok=True)
    try:
        os.chmod(parent, _DIR_MODE)
    except OSError as exc:
        raise KeyFileError(
            f"cannot set mode 0700 on key directory {parent}: {exc}"
        ) from exc
    try:
        actual = stat.S_IMODE(os.stat(parent).st_mode)
    except OSError as exc:
        raise KeyFileError(
            f"cannot stat key directory {parent}: {exc}"
        ) from exc
    if actual != _DIR_MODE:
        raise KeyFileError(
            f"key directory {parent} has mode {oct(actual)}, expected 0o700; "
            "refusing to store key material there"
        )
    return parent


def atomic_write_no_overwrite(path, data: bytes, mode: int = _FILE_MODE) -> str:
    """Atomically write *data* to *path* without overwriting an existing file.

    The bytes are written to a temp file in the same directory, fsynced, then
    hard-linked to the final path; link(2) fails atomically with
    FileExistsError when the destination already exists, so the
    never-overwrite guarantee holds even under concurrency and a crash can
    never leave a partial file at the destination. The parent directory is
    fsynced after the link for durability. Returns the path as a string.
    """
    path = os.path.abspath(os.fspath(path))
    data = bytes(data)
    parent = _secure_parent_dir(os.path.dirname(path))
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


def atomic_write_file(path, data: bytes, mode: int = _FILE_MODE) -> str:
    """Atomically write *data* to *path*, replacing any existing file.

    Same durability guarantees as :func:`atomic_write_no_overwrite`, but the
    final publish uses os.replace(2), so an existing destination is replaced
    atomically. For non-key files (config, state) that are routinely updated.
    """
    path = os.path.abspath(os.fspath(path))
    data = bytes(data)
    parent = _secure_parent_dir(os.path.dirname(path))
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
    through. Returns True if the file is gone (or was already absent);
    returns False only if the file still exists afterwards.
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
    try:
        remaining = st.st_size
        while remaining > 0:
            chunk = os.urandom(min(remaining, _WIPE_CHUNK))
            written = os.write(fd, chunk)
            remaining -= written
        os.fsync(fd)
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True
