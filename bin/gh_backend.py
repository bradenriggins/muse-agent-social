#!/usr/bin/env python3
"""GitHub relay transport for agent-social.

One private repo per pair (agent-social-<pair-id>), per-side ed25519 deploy
keys (read/write), git over SSH (direct, or through an egress proxy set via
AGENT_SOCIAL_PROXY). Repo layout mirrors
the pair protocol: to-<slot>/{incoming,accepted,rejected}/*.json.

Objects stored are AES-256-GCM ciphertext (see envelope_crypto.py); the repo
(and GitHub) never sees plaintext.
"""
import os
import subprocess
import sys

BIN_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BIN_DIR)
from envelope_crypto import encrypt_envelope, decrypt_envelope  # noqa: E402

HOME = os.path.expanduser("~")
BASE = os.path.join(HOME, "workspace", "agent-social")
MIRRORS = os.path.join(BASE, "git")
# Where to find GitHub's host keys. Defaults to the user's own known_hosts;
# make sure github.com is in it (ssh-keyscan github.com >> ~/.ssh/known_hosts).
KNOWN_HOSTS = os.environ.get(
    "AGENT_SOCIAL_KNOWN_HOSTS", os.path.join(HOME, ".ssh", "known_hosts"))
# Egress proxy for git+ssh, e.g. "proxy.example.com:3128".
# Empty (the default) means connect directly, no ProxyCommand.
PROXY = os.environ.get("AGENT_SOCIAL_PROXY", "")


def _git_env(key_path: str) -> dict:
    env = dict(os.environ)
    ssh_cmd = (f"ssh -i {key_path} -o BatchMode=yes "
               f"-o UserKnownHostsFile={KNOWN_HOSTS} ")
    if PROXY:
        ssh_cmd += f"-o ProxyCommand='nc -X connect -x {PROXY} %h %p'"
    env["GIT_SSH_COMMAND"] = ssh_cmd
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


class GitHubRelay:
    def __init__(self, repo_ssh_url: str, key_path: str, pair_id: str):
        self.repo = repo_ssh_url
        self.key = key_path
        self.pair_id = pair_id
        self.mirror = os.path.join(MIRRORS, pair_id)
        self.env = _git_env(key_path)
        self._ensure_mirror()

    def _run(self, *args, cwd=None, check=True):
        r = subprocess.run(["git", *args], cwd=cwd or self.mirror,
                           env=self.env, capture_output=True, text=True,
                           timeout=120)
        if check and r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
        return r

    def _ensure_mirror(self):
        if os.path.isdir(os.path.join(self.mirror, ".git")):
            self._run("fetch", "origin")
            self._run("reset", "--hard", "origin/main")
        else:
            os.makedirs(MIRRORS, exist_ok=True)
            self._run("clone", self.repo, self.mirror, cwd=MIRRORS)
        self._run("config", "user.name", "agent-social")
        self._run("config", "user.email", "agent-social@localhost")

    def _sync_down(self):
        self._run("fetch", "origin")
        r = self._run("rev-parse", "--verify", "origin/main", check=False)
        if r.returncode == 0:
            self._run("reset", "--hard", "origin/main")

    def _push(self, msg: str):
        self._run("add", "-A")
        r = self._run("commit", "-m", msg, check=False)
        if r.returncode != 0 and "nothing to commit" not in (r.stdout + r.stderr):
            raise RuntimeError(f"git commit failed: {r.stderr.strip()}")
        # retry once against races from the other side
        for _ in range(2):
            self._run("fetch", "origin")
            pr = self._run("pull", "--rebase", "origin", "main", check=False)
            if pr.returncode == 0:
                break
        self._run("push", "origin", "main")

    def _path(self, slot, subdir, fname):
        return os.path.join(self.mirror, f"to-{slot}", subdir, fname)

    def put_incoming(self, slot, fname, payload: bytes):
        p = self._path(slot, "incoming", fname)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(payload)
        self._push(f"incoming {fname} for {slot}")

    def list_incoming(self, slot):
        self._sync_down()
        d = os.path.join(self.mirror, f"to-{slot}", "incoming")
        if not os.path.isdir(d):
            return []
        return sorted(f for f in os.listdir(d) if f.endswith(".json"))

    def read(self, slot, subdir, fname):
        self._sync_down()
        with open(self._path(slot, subdir, fname), "rb") as f:
            return f.read()

    def move(self, slot, fname, from_subdir, to_subdir):
        src = self._path(slot, from_subdir, fname)
        dst = self._path(slot, to_subdir, fname)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        os.rename(src, dst)
        self._push(f"move {fname} {from_subdir}->{to_subdir} for {slot}")

    def write_reason(self, slot, fname, reason: str):
        p = os.path.join(self.mirror, f"to-{slot}", "rejected",
                         fname + ".reason.txt")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(reason)
        self._push(f"reason for {fname} for {slot}")


__all__ = ["GitHubRelay", "encrypt_envelope", "decrypt_envelope"]
