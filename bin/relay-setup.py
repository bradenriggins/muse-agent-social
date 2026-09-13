#!/usr/bin/env python3
"""Provision the v1 neutral relay for one agent pair on Cloudflare R2.

Creates one bucket per pair plus two R2 API tokens (one per side), each scoped
to that bucket with Object Read & Write. Derives S3 credentials, writes this
side's relay config, appends the peers.yaml entry, and writes the peer's
pairing bundle (hand it to the peer out of band).

Requires R2 enabled on the Cloudflare account (dashboard: R2 -> Enable).

Usage:
    relay-setup.py --pair-id pair-9f3a2c1d4e5b --peer rachael \\
        --peer-agent-id "agent:<name>:rachael" --my-slot braden --peer-slot rachael
    relay-setup.py --teardown --pair-id pair-9f3a2c1d4e5b
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error

import yaml

try:
    sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
    from dynamic_credentials import (  # noqa: E402
        add_surrogate_to_request, read_json_response)
    _HAVE_DC = True
except ImportError:
    _HAVE_DC = False

BASE = os.path.expanduser("~/workspace/agent-social")
API = "https://api.cloudflare.com/client/v4"
WRITE_GROUP_NAME = "Workers R2 Storage Bucket Item Write"


class CFError(RuntimeError):
    pass


def _cf_token():
    # Outside Hatch, authenticate with a Cloudflare API token in
    # CLOUDFLARE_API_TOKEN (needs R2 write scope for the bucket).
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if not token:
        raise RuntimeError(
            "Cloudflare auth not available: set the CLOUDFLARE_API_TOKEN "
            "environment variable.")
    return token


def api(method, path, account_id=None, body=None):
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    if _HAVE_DC:
        add_surrogate_to_request(req, "custom.cloudflare",
                                 allowed_hosts=["api.cloudflare.com"])
    else:
        req.add_header("Authorization", f"Bearer {_cf_token()}")
    try:
        resp = urllib.request.urlopen(req)
        data = read_json_response(resp)
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode())
        except Exception:
            raise CFError(f"{method} {path}: HTTP {e.code}")
        errs = "; ".join(x.get("message", "") for x in data.get("errors", []))
        raise CFError(f"{method} {path}: HTTP {e.code}: {errs}")
    if not data.get("success"):
        raise CFError(f"{method} {path} failed: {data.get('errors')}")
    return data["result"]


def discover_account_id():
    accounts = api("GET", "/accounts")
    if not accounts:
        raise CFError("no Cloudflare accounts found")
    return accounts[0]["id"]


def bucket_name(pair_id):
    return f"agent-social-{pair_id}"


def write_group_id(account_id):
    groups = api("GET", f"/accounts/{account_id}/tokens/permission_groups")
    for g in groups:
        if g.get("name") == WRITE_GROUP_NAME:
            return g["id"]
    raise CFError(f"permission group '{WRITE_GROUP_NAME}' not found")


def chmod600(path):
    os.chmod(path, 0o600)


def load_yaml(path, default):
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or default
    return default


def save_yaml(path, data):
    with open(path, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
    chmod600(path)


def setup(args):
    account_id = args.account_id or discover_account_id()
    pair_id, bucket = args.pair_id, bucket_name(args.pair_id)
    endpoint = f"https://{account_id}.r2.cloudflarestorage.com"

    if args.dry_run:
        print(f"would create bucket: PUT /accounts/{account_id}/r2/buckets/{bucket}")
        print(f"would create 2 API tokens scoped to {bucket} "
              f"({WRITE_GROUP_NAME})")
        print(f"would write: {BASE}/relay.yaml, {BASE}/peers.yaml, "
              f"pairing bundle for '{args.peer}'")
        return 0

    api("PUT", f"/accounts/{account_id}/r2/buckets/{bucket}", body={})
    print(f"bucket created: {bucket}")

    group_id = write_group_id(account_id)
    resource = f"com.cloudflare.edge.r2.bucket.{account_id}_default_{bucket}"
    creds, token_ids = {}, {}
    for slot in (args.my_slot, args.peer_slot):
        token = api("POST", f"/accounts/{account_id}/tokens", body={
            "name": f"agent-social-{pair_id}-{slot}",
            "policies": [{
                "effect": "allow",
                "resources": {resource: "*"},
                "permission_groups": [{"id": group_id}],
            }],
        })
        ak = token["id"]
        sk = hashlib.sha256(token["value"].encode()).hexdigest()
        creds[slot] = {"access_key_id": ak, "secret_access_key": sk}
        token_ids[slot] = token["id"]
        print(f"token created for slot '{slot}' (id {ak[:8]}...)")

    pair_key = os.urandom(32).hex()

    relay_path = os.path.join(BASE, "relay.yaml")
    relay = load_yaml(relay_path, {})
    relay.setdefault("pairs", {})[pair_id] = {
        "endpoint": endpoint,
        "bucket": bucket,
        "access_key_id": creds[args.my_slot]["access_key_id"],
        "secret_access_key": creds[args.my_slot]["secret_access_key"],
        "token_ids": token_ids,
        "account_id": account_id,
    }
    save_yaml(relay_path, relay)

    peers_path = os.path.join(BASE, "peers.yaml")
    peers = load_yaml(peers_path, {})
    peers.setdefault("peers", {})[args.peer] = {
        "agent_id": args.peer_agent_id,
        "pair_id": pair_id,
        "my_slot": args.my_slot,
        "slot": args.peer_slot,
        "key_hex": pair_key,
        "transport": "r2",
        "daily_cap": 5,
    }
    save_yaml(peers_path, peers)

    with open(os.path.join(BASE, "config.yaml")) as f:
        my_agent_id = yaml.safe_load(f)["agent_id"]
    bundle = {
        "pair_id": pair_id,
        "peer_agent_id": my_agent_id,
        "my_slot": args.peer_slot,
        "slot": args.my_slot,
        "key_hex": pair_key,
        "transport": "r2",
        "relay": {
            "endpoint": endpoint,
            "bucket": bucket,
            "access_key_id": creds[args.peer_slot]["access_key_id"],
            "secret_access_key": creds[args.peer_slot]["secret_access_key"],
        },
        "note": ("Hand this file to the peer out of band. Their agent writes "
                 "relay.yaml + peers.yaml from it, then both sides exchange a "
                 "pairing-test note."),
    }
    bundle_path = os.path.join(BASE, f"pairing-bundle-{pair_id}.json")
    with open(bundle_path, "w") as f:
        json.dump(bundle, f, indent=2)
    chmod600(bundle_path)

    print(f"my relay config: {relay_path}")
    print(f"my peers.yaml updated (peer '{args.peer}', transport r2)")
    print(f"PEER BUNDLE (send out of band): {bundle_path}")
    return 0


def teardown(args):
    account_id = args.account_id or discover_account_id()
    relay_path = os.path.join(BASE, "relay.yaml")
    relay = load_yaml(relay_path, {})
    pair = (relay.get("pairs") or {}).get(args.pair_id)
    if not pair:
        print(f"error: no relay entry for {args.pair_id}", file=sys.stderr)
        return 1
    for slot, tid in (pair.get("token_ids") or {}).items():
        try:
            api("DELETE", f"/accounts/{account_id}/tokens/{tid}")
            print(f"revoked token for slot '{slot}'")
        except CFError as e:
            print(f"token revoke warning: {e}")
    try:
        api("DELETE", f"/accounts/{account_id}/r2/buckets/{pair['bucket']}")
        print(f"deleted bucket {pair['bucket']}")
    except CFError as e:
        print(f"bucket delete warning: {e}")
    del relay["pairs"][args.pair_id]
    save_yaml(relay_path, relay)
    print("relay.yaml entry removed")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pair-id")
    ap.add_argument("--peer", help="peer key for my peers.yaml")
    ap.add_argument("--peer-agent-id")
    ap.add_argument("--my-slot", default="braden")
    ap.add_argument("--peer-slot")
    ap.add_argument("--account-id", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--teardown", action="store_true")
    args = ap.parse_args()
    if args.teardown:
        if not args.pair_id:
            print("error: --pair-id required", file=sys.stderr)
            return 1
        return teardown(args)
    for req in ("pair_id", "peer", "peer_agent_id", "peer_slot"):
        if not getattr(args, req):
            print(f"error: --{req.replace('_', '-')} required", file=sys.stderr)
            return 1
    try:
        return setup(args)
    except CFError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
