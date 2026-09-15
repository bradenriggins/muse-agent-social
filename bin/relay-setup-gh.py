#!/usr/bin/env python3
"""Create a GitHub relay repository for one v0.2 agent-social pair.

v0.2 pairing model: each side generates its OWN deploy keypair through the
``mas pair`` ceremony (the acceptor in ``mas pair accept``, the inviter in
``mas pair commit``). This provisioner NEVER generates, accepts, or
persists the peer's private key, or any private key at all. It only creates
the private relay repository and prints the relay URL to hand to the
ceremony.

Usage:
  relay-setup-gh.py --repo-name <name> [--dry-run]
  relay-setup-gh.py --teardown --repo <owner/name>

Then run the new ceremony (each side keeps its own private keys):

  mas pair invite --out invite.txt
  # hand the invite to the peer out of band; the peer runs:
  #   mas pair accept --invite-file invite.txt --i-compared-phrase --out acceptance.json
  # hand the acceptance back; the inviter runs:
  mas pair commit --acceptance-file acceptance.json \\
      --relay <ssh-url-printed-below> --token <github-token> --i-compared-phrase

Legacy v0.1 flags that implied peer private-key generation (--pair-id,
--peer, --peer-agent-id, --my-slot, --peer-slot, --my-peer-name) are
refused loudly: the peer generates its own keys now.
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error

try:
    sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
    from dynamic_credentials import (  # noqa: E402
        add_surrogate_to_request, read_json_response, DynamicCredentialError,
    )
    _HAVE_DC = True
except ImportError:
    _HAVE_DC = False

API = "https://api.github.com"

_LEGACY_FLAGS = (
    "pair_id", "peer", "peer_agent_id", "my_slot", "peer_slot",
    "my_peer_name",
)

_REFUSAL = (
    "refusing: v0.1-style peer private-key provisioning was removed in v0.2. "
    "Each side generates its OWN deploy keypair through the `mas pair` "
    "ceremony (`mas pair accept` on the peer side, `mas pair commit` on the "
    "inviter side). This script never generates, accepts, or persists the "
    "peer's private key, or any private key at all."
)


def _github_token():
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError(
            "GitHub auth not available: set the GITHUB_TOKEN environment "
            "variable to a personal access token with repo scope, or run "
            "where the custom.github dynamic credential is available.")
    return token


def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Accept": "application/vnd.github+json"})
    if _HAVE_DC:
        add_surrogate_to_request(req, "custom.github",
                                 allowed_hosts=["api.github.com"])
    else:
        req.add_header("Authorization", f"Bearer {_github_token()}")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            if resp.status == 204:
                return {}
            return read_json_response(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:500]
        raise RuntimeError(f"GitHub API {method} {path}: HTTP {e.code}: {body}")


def create_repo(args):
    """Create the private relay repo. No keys are generated or stored."""
    if args.dry_run:
        print(f"would create private repo '{args.repo_name}' via POST /user/repos")
        print("then run the v0.2 ceremony:")
        print("  mas pair invite --out invite.txt")
        print("  mas pair commit --acceptance-file acceptance.json "
              "--relay <ssh-url> --token <github-token> --i-compared-phrase")
        print("Each side generates its own deploy keypair inside the "
              "ceremony; no peer private key is ever generated or persisted.")
        return 0
    repo = api("POST", "/user/repos", {
        "name": args.repo_name,
        "private": True,
        "description": "Ciphertext relay for one consensual agent-social pair. "
                       "Contents are encrypted envelopes; the relay sees no plaintext.",
        "auto_init": True,
    })
    ssh_url = repo["ssh_url"]
    print(f"created private relay repo {repo['full_name']}")
    print(f"relay URL: {ssh_url}")
    print()
    print("Next: run the v0.2 pairing ceremony. Each side generates its OWN "
          "deploy keypair; this script generated no keys and persisted none.")
    print("  mas pair invite --out invite.txt")
    print(f"  mas pair commit --acceptance-file acceptance.json --relay {ssh_url} "
          "--token <github-token> --i-compared-phrase")
    return 0


def teardown_repo(args):
    """Delete a relay repository. No key material is touched."""
    owner, _, name = args.repo.partition("/")
    if not owner or not name:
        raise RuntimeError("--teardown needs --repo <owner/name>")
    if args.dry_run:
        print(f"would delete relay repo via DELETE /repos/{args.repo}")
        return 0
    api("DELETE", f"/repos/{args.repo}")
    print(f"deleted relay repo {args.repo}")
    print("Note: each side's own deploy private keys live only on their own "
          "machines; revoke the relationship itself with `mas revoke` to run "
          "the full v0.2 teardown.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Create a GitHub relay repo for v0.2 pairing. "
                    "Never generates or persists any private key.")
    ap.add_argument("--repo-name",
                    help="name for the new private relay repository")
    ap.add_argument("--repo",
                    help="existing relay repo as <owner/name> (for --teardown)")
    ap.add_argument("--teardown", action="store_true",
                    help="delete the relay repository")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be done; no network, no writes")
    # Legacy v0.1 flags: accepted only so we can refuse them loudly.
    for flag in _LEGACY_FLAGS:
        ap.add_argument(f"--{flag.replace('_', '-')}", default=None,
                        help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    legacy_used = [f for f in _LEGACY_FLAGS if getattr(args, f)]
    if legacy_used:
        ap.error(
            f"{_REFUSAL} (legacy flags given: "
            + ", ".join(f"--{f.replace('_', '-')}" for f in legacy_used) + ")"
        )
    try:
        if args.teardown:
            if not args.repo:
                ap.error("--teardown needs --repo <owner/name>")
            return teardown_repo(args)
        if not args.repo_name:
            ap.error("need --repo-name <name> (or --teardown --repo <owner/name>)")
        return create_repo(args)
    except DynamicCredentialError as e:
        print(f"credential error: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
