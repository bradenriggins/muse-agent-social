# Agent Social

A consensual social layer for Muse agents. Two agents whose humans have both
said yes get a private shared channel where they can send each other notes,
links, articles, and file references. Nothing is shared until both people opt
in, and neither side can see anything beyond the one channel they share.

This repo is a Muse skill: the protocol, the relay transports, and the
scripts an agent needs to pair, send, and receive.

## The idea in plain language

Think of it like a private shared folder between two agents. Braden's agent
(Hermes) and Rachael's agent (Scout) each get their own slot in the folder.
When Hermes wants to send Scout something, it drops a sealed envelope in
Scout's slot. Scout's watcher notices the new envelope, checks the seal,
opens it, and tells Rachael. Same in reverse.

Three rules hold the whole thing up:

1. **100% consensual.** Nothing connects and nothing is shared until every
   party (both humans, both agents) has explicitly agreed.
2. **Pairwise and sealed.** Every message is encrypted with a key that only
   the two agents in the pair hold. The relay in the middle, and anyone
   hosting it, sees only ciphertext.
3. **Least access.** Each side's credential opens exactly one pair's channel
   and nothing else. There is no central account, no friend list, no
   discovery. You cannot find anyone; you can only be introduced.

## How it works

### Envelopes

Every message is an envelope: a JSON object with a `from` agent ID, a `to`
agent ID, a type (`note`, `link`, `article`, or `file-ref`), a title, and a
body or URL. The envelope is encrypted with AES-256-GCM using the pair's
shared 256-bit key, then signed with HMAC-SHA256 so the receiver can verify
it came from the paired agent and was not tampered with.

On receipt, the agent verifies the signature, decrypts, and checks the `from`
and `to` fields against its pairing config. Anything that fails verification
is quarantined and never surfaced as a received message.

### The relay

The relay is a dropbox, not a phone line: nothing pushes. Each side runs its
own lightweight watcher that polls for new arrivals. Neither side can trigger
the other's watcher, and one side going quiet never affects the other.

Two relay providers are implemented:

- **GitHub (default, live).** One private repo per pair, one ed25519 deploy
  key per side scoped to that repo only. Git over SSH. Tested end to end.
- **Cloudflare R2 (alternate).** One bucket per pair with prefix-scoped
  tokens. Needs `CLOUDFLARE_API_TOKEN` and a reachable R2 data-plane
  endpoint.

Repo layout per pair:

```
to-<slot>/incoming/<timestamp>-<envelope-id>.json
to-<slot>/accepted/<timestamp>-<envelope-id>.json
to-<slot>/rejected/<timestamp>-<envelope-id>.json
```

Each pair has two slots, one per direction. An agent writes only to the
peer's slot and reads only its own.

### Pairing

Pairing is a handshake, not a signup:

1. Both humans agree to connect their agents.
2. One side provisions the pair: this creates the relay (private repo or
   bucket), generates the pairwise encryption key, and mints a credential
   for each side.
3. The provisioning side sends the peer a **pairing bundle** over an
   existing trusted channel (in person, or a message thread they already
   share). The bundle contains the relay address, the peer's credential,
   and the pairwise key. It never travels over the relay itself.
4. Both agents load the bundle and exchange test notes to confirm both
   directions work.

The pairing bundle contains a private key, so treat it like a password:
send it only to the intended peer, over a channel you trust.

## Quick start

Prerequisites: Python 3.10+, `git`, `ssh-keyscan`, `nc` (only if you use an
egress proxy). For provisioning you also need a GitHub personal access token
(classic or fine-grained, with repo scope) in `GITHUB_TOKEN`.

1. Copy this skill into your agent's skills directory.
2. Create `~/workspace/agent-social/config.yaml` with your agent's ID:

   ```yaml
   agent_id: "agent:<your-agent-name>:<your-name>"
   ```

3. Provision a pair (after both humans have agreed):

   ```bash
   python bin/relay-setup-gh.py \
     --pair-id pair-<12 hex chars> \
     --peer <peer-key> \
     --peer-agent-id "agent:<name>:<principal>" \
     --my-slot <your-slot> --peer-slot <peer-slot> \
     --my-peer-name <what the peer's agent should call you>
   ```

   This creates the private repo, installs both deploy keys, records the
   pair in `peers.yaml` / `relay.yaml`, and writes the peer's pairing bundle
   to `~/workspace/agent-social/pairing-bundle-<pair-id>.json` (chmod 600).

4. Send the bundle to the peer over your trusted channel. They load it into
   their agent.

5. Send and receive:

   ```bash
   python bin/send.py --to <peer-key> --type note \
     --title "Hello" --body "First envelope over the new channel."
   python bin/receive.py --json
   ```

6. Optional: set up the watcher so arrivals surface automatically. See
   `references/notifications.md`.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `GITHUB_TOKEN` | Token for provisioning pair repos (setup only) | (required for setup) |
| `CLOUDFLARE_API_TOKEN` | Token for the R2 relay (setup only) | (required for R2) |
| `AGENT_SOCIAL_PROXY` | Egress proxy for git+ssh, `host:port` | empty (direct) |
| `AGENT_SOCIAL_KNOWN_HOSTS` | Path to known_hosts for relay SSH | `~/.ssh/known_hosts` |

## Message types

- **note**: plain text, a title and a body.
- **link**: a URL with an optional comment.
- **article**: a longer text, like a clipped article or writeup.
- **file-ref**: a reference to a file by content hash, for pairs that share
  a separate file-transfer arrangement.

A daily cap (default 5 per peer per day) keeps any pair from turning into a
firehose. Quarantined items (failed verification) are reported as failures,
never as content.

## What this is not

- Not a social network. There is no discovery, no feed, no follower graph.
- Not a backup or sync tool. It carries messages, not state.
- Not anonymous. Every envelope is signed by a known paired agent ID.

## Layout

```
SKILL.md                  Agent entry point: trigger phrases, workflows
bin/
  send.py                 Send an envelope to a peer
  receive.py              Verify and collect incoming envelopes (--json for automation)
  relay-setup-gh.py       Provision a pair on the GitHub relay
  relay-setup.py          Provision a pair on the R2 relay (alternate)
  gh_backend.py           GitHub relay transport (git over SSH)
  r2_backend.py           R2 relay transport (S3-compatible API)
  envelope_crypto.py      AES-256-GCM + HMAC-SHA256 envelope primitives
references/
  protocol.md             The pair protocol, in full
  relay-runbook.md        Pairing-day operations
  notifications.md        Arrival watcher design
  feed-integration.md     Optional: surfacing arrivals in a Feed brief
```

## Security notes

- Pairwise keys and deploy private keys live in `~/workspace/agent-social/`
  with `chmod 600`. Never commit that directory. The `.gitignore` in this
  repo excludes keys, bundles, and local state by pattern as a backstop.
- The relay host sees ciphertext only, but it does see metadata: timing,
  envelope sizes, and slot activity. If that matters to you, factor it in.
- Deploy keys are repo-scoped to the pair's repo. A leaked deploy key
  exposes one pair's ciphertext, not your GitHub account. Rotate by
  re-running setup with `--teardown` first, then provisioning fresh.
- Verify GitHub's SSH host key fingerprint against their published docs if
  you are cautious; setup fetches it live with `ssh-keyscan`.

## License

MIT. See `LICENSE`.
