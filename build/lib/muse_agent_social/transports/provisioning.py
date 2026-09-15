"""GitHub relay provisioning: peer deploy keys (checkpoint 8).

The inviter provisions the relay by registering the peer's SSH deploy
PUBLIC key on the relay repository via the GitHub REST API. The peer
generates its own deploy keypair locally (see
``model.invites.generate_deploy_keypair``) and sends only the public key in
the signed acceptance.

Hard rules, all fail-closed:
- This module NEVER generates a peer private key and NEVER accepts one:
  ``register_peer_deploy_key`` rejects anything that is not an OpenSSH
  public key, and ``assert_no_peer_private_key`` scans a delivery bundle
  directory to prove no peer private key copy remains (provisioning fix).
- Deploy key titles must not contain personal names. Titles must use the
  relationship-ID prefix produced by ``deploy_key_title``
  (``mas-pair-<relationship_id>``); anything else is rejected.

Boundary note: randomized relay object names (``base64url(24 random
bytes).json`` per the GIT TRANSPORT relay object policy) and randomized
slot names are a transport concern, owned by the relay transport layer, not
by provisioning. Provisioning only registers the peer's public deploy key.

The GitHub credential arrives via *token_provider*, a callable taking no
arguments and returning the token string. In production it reads the dynamic
credential on every call (never cached, never logged, never persisted); in
tests pass a stub. Only ``urllib`` from the standard library is used.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
import uuid
from pathlib import Path

__all__ = [
    "ProvisioningError",
    "PrivateKeyMaterialFound",
    "GITHUB_API_BASE",
    "DEPLOY_KEY_TITLE_PREFIX",
    "deploy_key_title",
    "register_peer_deploy_key",
    "assert_no_peer_private_key",
]

GITHUB_API_BASE = "https://api.github.com"
DEPLOY_KEY_TITLE_PREFIX = "mas-pair-"

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
# Same shape as the deploy_public_key pattern in invite-acceptance.schema.json.
_SSH_PUBKEY_RE = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384"
    r"|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com"
    r"|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+( .*)?$"
)
_PRIVATE_MARKERS = (b"PRIVATE KEY", b"openssh-key-v1")
_PRIVATE_KEY_FILENAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
_PRIVATE_KEY_SUFFIXES = (".pem", ".key")
_SCAN_BYTES = 4096


class ProvisioningError(Exception):
    """Relay provisioning failed.

    Attributes:
        code: stable machine-readable reason code, e.g. "bad_repo",
            "bad_title", "private_key_material", "bad_deploy_key",
            "no_token", "http_error", "key_rejected".
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class PrivateKeyMaterialFound(ProvisioningError):
    """A bundle scan found suspected peer private key material."""

    def __init__(self, path) -> None:
        self.path = str(path)
        super().__init__(
            "private_key_found",
            f"peer private key material suspected at {self.path}; "
            "the peer private key must never be generated, accepted, or retained",
        )


def deploy_key_title(relationship_id: str) -> str:
    """Build the deploy-key title for a relationship: ``mas-pair-<id>``.

    Titles carry the relationship ID prefix and never personal names.
    """
    if not isinstance(relationship_id, str) or not relationship_id:
        raise ProvisioningError("bad_relationship_id", "relationship_id is required")
    try:
        uuid.UUID(relationship_id, version=4)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ProvisioningError(
            "bad_relationship_id", "relationship_id must be a UUID"
        ) from exc
    return f"{DEPLOY_KEY_TITLE_PREFIX}{relationship_id}"


def _check_public_key_only(peer_ssh_public_key, field="peer_ssh_public_key") -> None:
    if not isinstance(peer_ssh_public_key, str):
        raise ProvisioningError(
            "private_key_material", f"{field} must be a string"
        )
    for marker in ("PRIVATE KEY", "openssh-key-v1"):
        if marker in peer_ssh_public_key:
            raise ProvisioningError(
                "private_key_material",
                f"{field} appears to contain private key material; "
                "only the peer's PUBLIC deploy key may be registered",
            )
    if peer_ssh_public_key.strip().startswith("-----BEGIN"):
        raise ProvisioningError(
            "private_key_material",
            f"{field} looks like a PEM block; only public keys are allowed",
        )
    if not _SSH_PUBKEY_RE.match(peer_ssh_public_key):
        raise ProvisioningError(
            "bad_deploy_key",
            f"{field} is not an OpenSSH public key",
        )


def _post_json(url: str, payload: dict, token: str, timeout: int):
    """POST JSON with a bearer token. Returns (status, parsed_body).

    The token is used only in the Authorization header and never appears in
    errors or logs.
    """
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "muse-agent-social/0.2",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", "replace")[:500]
        except Exception:
            body = ""
        return exc.code, {"_error_body": body}


def _check_title(title: Any) -> None:
    """Titles must be ``mas-pair-<relationship-uuid>``; personal names fail."""
    if not isinstance(title, str) or not title.startswith(
        DEPLOY_KEY_TITLE_PREFIX
    ):
        raise ProvisioningError(
            "bad_title",
            "deploy key titles must use the relationship_id prefix "
            f"({DEPLOY_KEY_TITLE_PREFIX}<relationship-uuid>); personal names "
            "are forbidden",
        )
    suffix = title[len(DEPLOY_KEY_TITLE_PREFIX):]
    try:
        uuid.UUID(suffix, version=4)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ProvisioningError(
            "bad_title",
            "deploy key title suffix must be the relationship UUID",
        ) from exc


def register_peer_deploy_key(
    repo: str,
    peer_ssh_public_key: str,
    title: str,
    token_provider,
    timeout: int = 30,
) -> dict:
    """Register the peer's SSH deploy public key on the relay repository.

    *repo* is ``"owner/name"``. *title* must carry the relationship-ID
    prefix (use ``deploy_key_title``); personal names are forbidden. The key
    is registered with write access (``read_only: False``) because both
    sides push relay objects.

    *token_provider* is a callable taking no arguments and returning the
    GitHub token string; it is called fresh on every invocation. In
    production it reads the dynamic credential; in tests pass a stub such
    as ``lambda: "test-token"``.

    Returns the parsed GitHub API response (201). Raises ProvisioningError;
    the token never appears in errors.
    """
    if not isinstance(repo, str) or not _REPO_RE.match(repo):
        raise ProvisioningError(
            "bad_repo", 'repo must look like "owner/name"'
        )
    _check_title(title)
    _check_public_key_only(peer_ssh_public_key)
    if not callable(token_provider):
        raise ProvisioningError("no_token", "token_provider must be callable")
    token = token_provider()
    if not isinstance(token, str) or not token:
        raise ProvisioningError(
            "no_token", "token_provider returned no usable token"
        )
    url = f"{GITHUB_API_BASE}/repos/{repo}/keys"
    status, body = _post_json(
        url,
        {"title": title, "key": peer_ssh_public_key, "read_only": False},
        token,
        timeout,
    )
    if status == 201:
        return body
    if status == 404:
        raise ProvisioningError(
            "repo_not_found",
            f"repository {repo} not found or token lacks access (status 404)",
        )
    if status == 401:
        raise ProvisioningError(
            "unauthorized", "GitHub rejected the token (status 401)"
        )
    if status == 422:
        raise ProvisioningError(
            "key_rejected",
            f"GitHub rejected the deploy key (status 422): "
            f"{body.get('_error_body', '')}",
        )
    raise ProvisioningError(
        "http_error", f"GitHub API returned unexpected status {status}"
    )


def assert_no_peer_private_key(bundle_dir) -> None:
    """Scan *bundle_dir* and prove no peer private key copy remains.

    Inspects file names (``id_rsa``/``id_dsa``/``id_ecdsa``/``id_ed25519``,
    ``*.pem``, ``*.key``) and the first 4096 bytes of every file for private
    key markers (``PRIVATE KEY``, ``openssh-key-v1``). Raises
    ``PrivateKeyMaterialFound`` naming the offending path (never key
    material). Use after delivery per the RETENTION provisioning fix.
    """
    base = Path(bundle_dir)
    if not base.is_dir():
        raise ProvisioningError(
            "bad_bundle_dir", f"{base} is not a directory"
        )
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        name = path.name
        if name in _PRIVATE_KEY_FILENAMES or name.endswith(_PRIVATE_KEY_SUFFIXES):
            raise PrivateKeyMaterialFound(path)
        try:
            with open(path, "rb") as fh:
                head = fh.read(_SCAN_BYTES)
        except OSError:
            continue
        if any(marker in head for marker in _PRIVATE_MARKERS):
            raise PrivateKeyMaterialFound(path)
