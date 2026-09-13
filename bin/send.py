#!/usr/bin/env python3
"""Package a signed envelope and drop it in a peer's relay slot.

Usage:
    send.py --to <peer> --type note --title "..." --body "..."
    send.py --to <peer> --type link --title "..." --url https://... --body "..."
    send.py --to <peer> --type file-ref --title "..." --url <share-link> --body "..."
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import uuid
from datetime import datetime, timezone

import yaml

BASE = os.path.expanduser("~/workspace/agent-social")
TYPES = ("note", "link", "article", "file-ref")
TITLE_MAX = 200
BODY_MAX = 262144  # 256 KB


def canonical(envelope: dict) -> bytes:
    body = {k: v for k, v in envelope.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(envelope: dict, key_hex: str) -> str:
    key = bytes.fromhex(key_hex)
    return hmac.new(key, canonical(envelope), hashlib.sha256).hexdigest()


def today_count(outbox_dir: str, peer: str) -> int:
    d = os.path.join(outbox_dir, peer)
    if not os.path.isdir(d):
        return 0
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return sum(1 for f in os.listdir(d) if f.startswith(today))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", required=True, help="peer key in peers.yaml")
    ap.add_argument("--type", required=True, choices=TYPES)
    ap.add_argument("--title", required=True)
    ap.add_argument("--body", default="")
    ap.add_argument("--url", default="")
    ap.add_argument("--file", default="", help="read body from a local file")
    ap.add_argument("--config", default=os.path.join(BASE, "config.yaml"))
    ap.add_argument("--peers", default=os.path.join(BASE, "peers.yaml"))
    ap.add_argument("--relay", default=os.path.join(BASE, "relay"))
    ap.add_argument("--relay-cfg", default=os.path.join(BASE, "relay.yaml"))
    ap.add_argument("--outbox-log", default=os.path.join(BASE, "outbox-log"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)
    with open(args.peers) as f:
        peers = yaml.safe_load(f) or {}

    peer = (peers.get("peers") or {}).get(args.to)
    if not peer:
        print(f"error: no peer '{args.to}' in {args.peers} (pairing required)",
              file=sys.stderr)
        return 1

    body = args.body
    if args.file:
        with open(os.path.expanduser(args.file)) as f:
            body = f.read()
    if args.type in ("link", "article", "file-ref") and not args.url:
        print(f"error: --url is required for type '{args.type}'", file=sys.stderr)
        return 1
    if len(args.title) > TITLE_MAX:
        print(f"error: title exceeds {TITLE_MAX} chars", file=sys.stderr)
        return 1
    if len(body) > BODY_MAX:
        print(f"error: body exceeds {BODY_MAX} chars", file=sys.stderr)
        return 1

    daily_cap = peer.get("daily_cap", 5)
    sent_today = today_count(args.outbox_log, args.to)
    if sent_today >= daily_cap:
        print(f"error: daily cap reached for '{args.to}' ({daily_cap}/day)",
              file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc)
    envelope = {
        "v": 1,
        "id": str(uuid.uuid4()),
        "from": config["agent_id"],
        "to": peer["agent_id"],
        "pair": peer["pair_id"],
        "type": args.type,
        "title": args.title,
        "body": body,
        "url": args.url,
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": str(uuid.uuid4()),
    }
    envelope["sig"] = sign(envelope, peer["key_hex"])

    slot_dir = os.path.join(args.relay, "pairs", peer["pair_id"],
                            f"to-{peer['slot']}", "incoming")
    os.makedirs(slot_dir, exist_ok=True)
    fname = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{envelope['id']}.json"
    payload = json.dumps(envelope, indent=2) + "\n"

    if args.dry_run:
        print(payload)
        return 0

    transport = peer.get("transport", "local")
    if transport == "r2":
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from r2_backend import R2Backend, encrypt_envelope
        with open(args.relay_cfg) as f:
            cfg = ((yaml.safe_load(f) or {}).get("pairs") or {})[peer["pair_id"]]
        r2 = R2Backend(cfg["endpoint"], cfg["bucket"],
                       cfg["access_key_id"], cfg["secret_access_key"])
        r2.put_incoming(peer["slot"], fname,
                        encrypt_envelope(envelope, peer["key_hex"]))
    elif transport == "github":
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from gh_backend import GitHubRelay, encrypt_envelope
        with open(args.relay_cfg) as f:
            cfg = ((yaml.safe_load(f) or {}).get("pairs") or {})[peer["pair_id"]]
        gh = GitHubRelay(cfg["repo_ssh_url"], cfg["key_path"], peer["pair_id"])
        gh.put_incoming(peer["slot"], fname,
                        encrypt_envelope(envelope, peer["key_hex"]))
    else:
        with open(os.path.join(slot_dir, fname), "w") as f:
            f.write(payload)
    log_dir = os.path.join(args.outbox_log, args.to)
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, f"{now.strftime('%Y-%m-%d')}-{envelope['id']}.json"),
              "w") as f:
        f.write(payload)

    print(f"sent {envelope['type']} '{envelope['title']}' to {args.to} "
          f"(id {envelope['id'][:8]}, {sent_today + 1}/{daily_cap} today)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
