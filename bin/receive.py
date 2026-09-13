#!/usr/bin/env python3
"""Verify incoming envelopes and file the valid ones.

Supports two transports (per peer, from peers.yaml):
  local - the v0 directory relay under ~/workspace/agent-social/relay/
  r2    - the v1 Cloudflare R2 bucket from relay.yaml (AES-GCM encrypted)

Scans my incoming slot in every pair, verifies signatures, enforces replay and
rate limits, files valid envelopes to the inbox, quarantines the rest with
reasons. Prints a digest of what arrived.
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone, timedelta

import yaml

BASE = os.path.expanduser("~/workspace/agent-social")
MAX_AGE = timedelta(days=7)
FUTURE_SKEW = timedelta(hours=1)


def canonical(envelope: dict) -> bytes:
    body = {k: v for k, v in envelope.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify(envelope: dict, key_hex: str) -> bool:
    sig = envelope.get("sig", "")
    key = bytes.fromhex(key_hex)
    expected = hmac.new(key, canonical(envelope), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def check_envelope(env, peer, peer_key, my_id, pair_id, state, accepted_today,
                   cap, now):
    """Return (ok, reason). reason is None when ok."""
    if env.get("pair") != pair_id or env.get("from") != peer["agent_id"]:
        return False, "pair/from mismatch with peers.yaml"
    if env.get("to") != my_id:
        return False, "envelope addressed to someone else"
    if not verify(env, peer_key):
        return False, "signature verification failed"
    try:
        created = datetime.strptime(env["created_at"], "%Y-%m-%dT%H:%M:%SZ") \
            .replace(tzinfo=timezone.utc)
    except Exception:
        return False, "bad created_at format"
    if now - created > MAX_AGE or created - now > FUTURE_SKEW:
        return False, "created_at outside acceptance window"
    if env.get("nonce") in state["seen_nonces"]:
        return False, "duplicate nonce (replay)"
    if accepted_today >= cap:
        return False, f"daily cap reached ({cap}/day)"
    return True, None


class LocalBackend:
    def __init__(self, pair_dir, my_slot):
        self.slot_dir = os.path.join(pair_dir, f"to-{my_slot}")
        self.incoming = os.path.join(self.slot_dir, "incoming")
        os.makedirs(os.path.join(self.slot_dir, "consumed"), exist_ok=True)
        os.makedirs(os.path.join(self.slot_dir, "quarantine"), exist_ok=True)

    def list_incoming(self):
        if not os.path.isdir(self.incoming):
            return []
        return sorted(os.listdir(self.incoming))

    def read(self, fname):
        with open(os.path.join(self.incoming, fname)) as f:
            return json.load(f)

    def consume(self, fname):
        os.rename(os.path.join(self.incoming, fname),
                  os.path.join(self.slot_dir, "consumed", fname))

    def quarantine(self, fname, reason):
        dst = os.path.join(self.slot_dir, "quarantine", fname)
        os.rename(os.path.join(self.incoming, fname), dst)
        with open(dst + ".reason.txt", "w") as f:
            f.write(reason + "\n")


class R2BackendAdapter:
    def __init__(self, relay_cfg, my_slot, key_hex):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
        from r2_backend import R2Backend, decrypt_envelope
        self.r2 = R2Backend(relay_cfg["endpoint"], relay_cfg["bucket"],
                           relay_cfg["access_key_id"], relay_cfg["secret_access_key"])
        self.decrypt_envelope = decrypt_envelope
        self.slot = my_slot
        self.key_hex = key_hex

    def list_incoming(self):
        return self.r2.list_incoming(self.slot)

    def read(self, fname):
        body = self.r2.read(self.slot, "incoming", fname)
        return self.decrypt_envelope(body, self.key_hex)

    def consume(self, fname):
        self.r2.move(self.slot, fname, "incoming", "consumed")

    def quarantine(self, fname, reason):
        self.r2.move(self.slot, fname, "incoming", "quarantine")
        self.r2.write_reason(self.slot, fname, reason)


class GitHubBackendAdapter:
    def __init__(self, relay_cfg, my_slot, key_hex, pair_id):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
        from gh_backend import GitHubRelay, decrypt_envelope
        self.gh = GitHubRelay(relay_cfg["repo_ssh_url"], relay_cfg["key_path"],
                              pair_id)
        self.decrypt_envelope = decrypt_envelope
        self.slot = my_slot
        self.key_hex = key_hex

    def list_incoming(self):
        return self.gh.list_incoming(self.slot)

    def read(self, fname):
        body = self.gh.read(self.slot, "incoming", fname)
        return self.decrypt_envelope(body, self.key_hex)

    def consume(self, fname):
        self.gh.move(self.slot, fname, "incoming", "consumed")

    def quarantine(self, fname, reason):
        self.gh.move(self.slot, fname, "incoming", "quarantine")
        self.gh.write_reason(self.slot, fname, reason)


def load_state(pair_id, transport, pair_dir):
    if transport in ("r2", "github"):
        path = os.path.join(BASE, "relay-state", f"{pair_id}.json")
    else:
        path = os.path.join(pair_dir, ".state.json")
    state = {"seen_nonces": [], "daily": {}}
    if os.path.exists(path):
        with open(path) as f:
            state = json.load(f)
    return state, path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(BASE, "config.yaml"))
    ap.add_argument("--peers", default=os.path.join(BASE, "peers.yaml"))
    ap.add_argument("--relay", default=os.path.join(BASE, "relay"))
    ap.add_argument("--relay-cfg", default=os.path.join(BASE, "relay.yaml"))
    ap.add_argument("--inbox", default=os.path.join(BASE, "inbox"))
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output for schedulers/notifiers")
    args = ap.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)
    with open(args.peers) as f:
        peers = yaml.safe_load(f) or {}
    peer_map = peers.get("peers") or {}
    relay_cfg = {}
    if os.path.exists(args.relay_cfg):
        with open(args.relay_cfg) as f:
            relay_cfg = (yaml.safe_load(f) or {}).get("pairs", {})

    my_id = config["agent_id"]
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    new_items, quarantined = [], []

    for peer_key in sorted(peer_map):
        peer = peer_map[peer_key]
        pair_id = peer["pair_id"]
        transport = peer.get("transport", "local")
        pair_dir = os.path.join(args.relay, "pairs", pair_id)

        if transport == "r2":
            cfg = relay_cfg.get(pair_id)
            if not cfg:
                print(f"  [{peer_key}] no relay.yaml entry for {pair_id}, skipping",
                      file=sys.stderr)
                continue
            backend = R2BackendAdapter(cfg, peer["my_slot"], peer["key_hex"])
        elif transport == "github":
            cfg = relay_cfg.get(pair_id)
            if not cfg:
                print(f"  [{peer_key}] no relay.yaml entry for {pair_id}, skipping",
                      file=sys.stderr)
                continue
            backend = GitHubBackendAdapter(cfg, peer["my_slot"], peer["key_hex"],
                                           pair_id)
        else:
            if not os.path.isdir(pair_dir):
                continue
            backend = LocalBackend(pair_dir, peer["my_slot"])

        state, state_path = load_state(pair_id, transport, pair_dir)
        accepted_today = state.get("daily", {}).get(today, 0)
        cap = peer.get("daily_cap", 5)

        for fname in backend.list_incoming():
            if fname.endswith(".reason.txt"):
                continue
            try:
                env = backend.read(fname)
            except Exception as e:
                backend.quarantine(fname, f"unreadable payload: {e}")
                quarantined.append((peer_key, fname, "unreadable payload"))
                continue
            ok, reason = check_envelope(env, peer, peer["key_hex"], my_id,
                                        pair_id, state, accepted_today, cap, now)
            if not ok:
                backend.quarantine(fname, reason)
                quarantined.append((peer_key, fname, reason))
                continue
            inbox_dir = os.path.join(args.inbox, peer_key)
            os.makedirs(inbox_dir, exist_ok=True)
            with open(os.path.join(inbox_dir, fname), "w") as f:
                json.dump(env, f, indent=2)
                f.write("\n")
            state["seen_nonces"].append(env["nonce"])
            state["seen_nonces"] = state["seen_nonces"][-1000:]
            state.setdefault("daily", {})[today] = accepted_today + 1
            accepted_today += 1
            backend.consume(fname)
            new_items.append((peer_key, env))

        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        with open(state_path, "w") as f:
            json.dump(state, f, indent=2)

    if args.json:
        print(json.dumps({
            "new": [
                {"peer": peer_key, "id": env["id"], "type": env["type"],
                 "title": env["title"], "body": env.get("body"),
                 "url": env.get("url"), "created_at": env["created_at"]}
                for peer_key, env in new_items
            ],
            "quarantined": [
                {"peer": peer_key, "file": fname, "reason": reason}
                for peer_key, fname, reason in quarantined
            ],
        }))
    elif new_items:
        print(f"{len(new_items)} new item(s):")
        for peer_key, env in new_items:
            print(f"  [{peer_key}] {env['type']}: {env['title']}")
            if env.get("url"):
                print(f"    {env['url']}")
    else:
        print("no new items")
    if not args.json:
        for peer_key, fname, reason in quarantined:
            print(f"  quarantined [{peer_key}] {fname}: {reason}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
