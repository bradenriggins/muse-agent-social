"""Private-key file storage conventions for Muse Agent Social v0.2.

Internal helper shared by the pairing ceremony (``model.invites``) and key
rotation (``crypto.rotation``). Not part of the public protocol surface.

Conventions:
- Private key files live under ``<keys_dir>/`` (default: ``<db_dir>/keys``,
  where ``<db_dir>`` is the directory holding the SQLite state database).
- Files are created with mode 0o600 and never overwritten (O_CREAT | O_EXCL).
- Parent directories are created with mode 0o700.
- ``private_key_ref`` values stored in the ``key_epochs`` table are
  filesystem paths, except the reserved sentinel ``"peer"`` which marks a
  row that describes the PEER's public key for that epoch (no local private
  key exists). The sentinel is never a valid path and must never be treated
  as one.
"""

from __future__ import annotations

import os


class KeyFileError(Exception):
    """Private key file storage failed."""


PEER_KEY_REF = "peer"
"""Reserved ``private_key_ref`` marking a peer public-key row (no local key)."""


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


def store_private_key(path, data: bytes) -> str:
    """Write private key *data* to *path* with mode 0o600.

    Creates parent directories with mode 0o700. Refuses to overwrite an
    existing file (raises FileExistsError). Returns the path as a string.
    """
    path = os.fspath(path)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, bytes(data))
    finally:
        os.close(fd)
    return path


def delete_private_key(path) -> bool:
    """Best-effort unlink of a private key file. Returns True if removed."""
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False
