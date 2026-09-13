#!/usr/bin/env python3
"""Provision a GitHub relay for one agent-social pair.

One private repo per pair (agent-social-<pair-id>), one ed25519 deploy key
per side (read/write, repo-scoped). Fully API-driven: repo creation and
deploy-key install use the connected custom.github credential.

Usage:
  relay-setup-gh.py --pair-id pair-<12hex> --peer <name> --peer-agent-id <id> \
      --my-slot <slot> --peer-slot <slot>
  relay-setup-gh.py --teardown --pair-id <id>

After setup, the peer bundle must be delivered out of band. It contains the
peer's deploy private key, which grants write access to ONLY this pair's repo.
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.request

try:
    sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
    from dynamic_credentials import (  # noqa: E402
        add_surrogate_to_request, read_json_response, DynamicCredentialError,
    )
    _HAVE_DC = True
except ImportError:
    _HAVE_DC = False

import yaml  # noqa: E402

HOME = os.path.expanduser("~")
BASE = os.path.join(HOME, "workspace", "agent-social")
PEERS = os.path.join(BASE, "peers.yaml")
RELAY = os.path.join(BASE, "relay.yaml")
KEYS = os.path.join(BASE, "keys")
API = "https://api.github.com"


def _github_token():
    # Outside Hatch, authenticate with a classic or fine-grained personal
    # access token in GITHUB_TOKEN (needs repo scope: create + admin:public_key).
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError(
            "GitHub auth not available: set the GITHUB_TOKEN environment "
            "variable to a personal access token with repo scope.")
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
                return {}, resp.status
            return read_json_response(resp), resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:500]
        raise RuntimeError(f"GitHub API {method} {path}: HTTP {e.code}: {body}")


def get_owner():
    body, _ = api("GET", "/user")
    return body["login"]


def my_agent_id():
    with open(os.path.join(BASE, "config.yaml")) as f:
        return yaml.safe_load(f)["agent_id"]


def setup(args):
    my_id = my_agent_id()
    owner = get_owner()
    repo_name = f"agent-social-{args.pair_id}"
    print(f"creating private repo {owner}/{repo_name} ...")
    repo, _ = api("POST", "/user/repos", {
        "name": repo_name, "private": True,
        "description": "Ciphertext relay for a consensual agent-social pair. "
                       "Contents are encrypted envelopes; the relay sees no plaintext.",
        "auto_init": True,
    })
    ssh_url = repo["ssh_url"]

    os.makedirs(KEYS, mode=0o700, exist_ok=True)
    pair_key = os.urandom(32).hex()
    keys = {}
    for side, slot in (("mine", args.my_slot), ("peer", args.peer_slot)):
        priv = os.path.join(KEYS, f"{args.pair_id}.{side}.key")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "",
                        "-C", f"agent-social {args.pair_id} {slot}",
                        "-f", priv],
                       check=True, capture_output=True)
        os.chmod(priv, 0o600)
        with open(priv + ".pub") as f:
            pub = f.read().strip()
        dk, _ = api("POST", f"/repos/{owner}/{repo_name}/keys",
                    {"title": f"agent-social {slot}", "key": pub,
                     "read_only": False})
        keys[side] = {"id": dk["id"], "priv": priv}
        print(f"deploy key installed for slot '{slot}' (key id {dk['id']})")

    # my relay config
    relay = {}
    if os.path.exists(RELAY):
        relay = yaml.safe_load(open(RELAY)) or {}
    relay.setdefault("pairs", {})[args.pair_id] = {
        "provider": "github",
        "repo_ssh_url": ssh_url,
        "key_path": keys["mine"]["priv"],
        "deploy_key_ids": {args.my_slot: keys["mine"]["id"],
                           args.peer_slot: keys["peer"]["id"]},
        "repo": f"{owner}/{repo_name}",
    }
    with open(RELAY, "w") as f:
        yaml.safe_dump(relay, f)
    os.chmod(RELAY, 0o600)

    # my peer entry
    peers = yaml.safe_load(open(PEERS)) or {}
    peers.setdefault("peers", {})[args.peer] = {
        "agent_id": args.peer_agent_id,
        "pair_id": args.pair_id,
        "my_slot": args.my_slot,
        "slot": args.peer_slot,
        "key_hex": pair_key,
        "transport": "github",
        "daily_cap": 5,
    }
    with open(PEERS, "w") as f:
        yaml.safe_dump(peers, f)

    # peer bundle (out of band)
    with open(keys["peer"]["priv"]) as f:
        peer_priv = f.read()
    # GitHub's SSH host keys, fetched from the documented meta endpoint
    # (https://api.github.com/meta, field "ssh_keys") so the bundle carries
    # no environment-specific files and needs no SSH connectivity at setup
    # time. These are GitHub's published keys; compare against their docs
    # if you are cautious.
    meta_req = urllib.request.Request(
        "https://api.github.com/meta",
        headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(meta_req, timeout=60) as meta_resp:
        ssh_keys = json.load(meta_resp)["ssh_keys"]
    known_hosts = "".join(f"github.com {k}\n" for k in ssh_keys)
    bundle = {
        "provider": "github",
        "pair_id": args.pair_id,
        "peer_name": args.my_peer_name,
        "peer_agent_id": my_id,
        "slot": args.my_slot,       # peer's view: my slot is their peer
        "my_slot": args.peer_slot,  # peer's view: their own slot
        "key_hex": pair_key,
        "transport": "github",
        "daily_cap": 5,
        "relay": {
            "repo_ssh_url": ssh_url,
            "deploy_private_key": peer_priv,
            "known_hosts": known_hosts,
        },
        "setup_note": (
            "Save deploy_private_key to a file with chmod 600 and save "
            "known_hosts to a file. If you are behind an egress proxy, set "
            "the AGENT_SOCIAL_PROXY environment variable (host:port) and, if "
            "needed, AGENT_SOCIAL_KNOWN_HOSTS to your known_hosts file. The "
            "skill's gh_backend.py reads both automatically; with no proxy "
            "set it connects directly."
        ),
    }
    bundle_path = os.path.join(BASE, f"pairing-bundle-{args.pair_id}.json")
    with open(bundle_path, "w") as f:
        json.dump(bundle, f, indent=2)
    os.chmod(bundle_path, 0o600)
    print(f"my relay config: {RELAY}")
    print(f"my peers.yaml updated (peer '{args.peer}', transport github)")
    print(f"PEER BUNDLE (send out of band): {bundle_path}")
    print("NOTE: the bundle contains the peer's deploy private key; it grants "
          "write access to ONLY this pair's repo.")


def teardown(args):
    relay = yaml.safe_load(open(RELAY)) or {}
    entry = (relay.get("pairs") or {}).pop(args.pair_id, None)
    if not entry or entry.get("provider") != "github":
        print(f"no github pair {args.pair_id} in relay.yaml")
        return
    owner_repo = entry["repo"]
    for slot, kid in (entry.get("deploy_key_ids") or {}).items():
        try:
            api("DELETE", f"/repos/{owner_repo}/keys/{kid}")
            print(f"removed deploy key for slot '{slot}'")
        except RuntimeError as e:
            print(f"key removal: {e}")
    api("DELETE", f"/repos/{owner_repo}")
    print(f"deleted repo {owner_repo}")
    for side in ("mine", "peer"):
        for suffix in ("", ".pub"):
            p = os.path.join(KEYS, f"{args.pair_id}.{side}.key{suffix}")
            if os.path.exists(p):
                os.remove(p)
    bundle_path = os.path.join(BASE, f"pairing-bundle-{args.pair_id}.json")
    if os.path.exists(bundle_path):
        os.remove(bundle_path)
        print("removed local pairing bundle")
    with open(RELAY, "w") as f:
        yaml.safe_dump(relay, f)
    peers = yaml.safe_load(open(PEERS)) or {}
    for name, p in list((peers.get("peers") or {}).items()):
        if p.get("pair_id") == args.pair_id:
            del peers["peers"][name]
            print(f"removed peer '{name}' from peers.yaml")
    with open(PEERS, "w") as f:
        yaml.safe_dump(peers, f)
    print("teardown complete")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pair-id")
    ap.add_argument("--peer")
    ap.add_argument("--peer-agent-id")
    ap.add_argument("--my-slot")
    ap.add_argument("--peer-slot")
    ap.add_argument("--my-peer-name", default="hermes",
                    help="label the PEER's agent should use for me in its peers.yaml")
    ap.add_argument("--teardown", action="store_true")
    args = ap.parse_args()
    try:
        if args.teardown:
            if not args.pair_id:
                ap.error("--teardown needs --pair-id")
            teardown(args)
        else:
            for f_ in ("pair_id", "peer", "peer_agent_id", "my_slot", "peer_slot"):
                if not getattr(args, f_):
                    ap.error(f"setup needs --{f_.replace('_', '-')}")
            setup(args)
    except DynamicCredentialError as e:
        sys.exit(f"credential error: {e}")
    except RuntimeError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
