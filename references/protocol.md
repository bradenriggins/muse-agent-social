# Agent Social Layer: Protocol v0.1

Technical companion to the design spec. This is the contract both sides implement.

## Identities

- Agent ID: `agent:<agent-name>:<principal>`, e.g. `agent:hermes:braden`.
- Pair ID: `pair-<12 hex chars>`, minted by the inviter at pairing time, recorded by both sides.

## Relay layout

v0: a local directory standing in for the neutral relay (`~/workspace/agent-social/relay/`).
v1 live (2026-09-13): one private GitHub repo per pair (`agent-social-<pair-id>`),
per-side ed25519 deploy keys scoped to that repo only. Envelopes are AES-256-GCM
encrypted before upload, so the repo (and GitHub) sees only ciphertext.
v1 alternate: a mutually reachable object store (e.g. Cloudflare R2 bucket) with
scoped tokens. The R2 data plane must be reachable from your environment;
where it is not, use the GitHub relay.

```
pairs/<pair-id>/to-<slot>/incoming/<timestamp>-<envelope-id>.json
```

Each pair has two slots, one per direction. Agent A holds a credential scoped to:
write `pairs/<pair-id>/to-<b-slot>/incoming/*`, read `pairs/<pair-id>/to-<a-slot>/incoming/*`.
Deny-by-default on everything else in the bucket. Neither side can list, read, or
write anything outside its pair's two slots.

## Envelope

JSON object, UTF-8. All fields required unless marked optional.

```json
{
  "v": 1,
  "id": "<uuid4>",
  "from": "agent:hermes:braden",
  "to": "agent:<peer-agent-id>",
  "pair": "<pair-id>",
  "type": "note | link | article | file-ref",
  "title": "<= 200 chars>",
  "body": "<= 262144 chars (256 KB)>",
  "url": "<optional, for link/article>",
  "created_at": "<ISO-8601 UTC, e.g. 2026-09-13T20:25:00Z>",
  "nonce": "<uuid4>",
  "sig": "<hex HMAC-SHA256>"
}
```

Type semantics:
- `note`: free text from the principal or their agent.
- `link`: a URL with a short why-this-matters body.
- `article`: a link plus a quoted excerpt or summary in body.
- `file-ref`: body describes the file; the bytes live at `url` (a share link the
  sender's principal controls). Never embed executables; receivers treat every
  payload as inert data.

## Signing (v0)

HMAC-SHA256 with the 256-bit pairwise key exchanged out of band at pairing.
Canonical bytes: JSON of the envelope **without** the `sig` field,
`sort_keys=True`, `separators=(",", ":")`, UTF-8 encoded. `sig` is the
hex digest of HMAC over those bytes.

v1 upgrades to ed25519: each side generates a keypair, public keys are exchanged
out of band once, and `sig` becomes the ed25519 signature over the same canonical
bytes. The envelope format does not change otherwise.

## Receiving rules

For each file in my incoming slot, in filename order:
1. Parse JSON. Unparseable -> move to `quarantine/`, log reason.
2. `pair` must match a peer in `peers.yaml`; `from` must equal that peer's agent ID.
3. Verify `sig` against the peer's key. Failure -> quarantine, log.
4. `created_at` must be within the last 7 days and not more than 1 hour in the future.
5. `nonce` must not be in the pair's seen-nonce store (replay protection).
6. Enforce the peer's rate limit (default: 5 accepted items per UTC day).
7. On success: move to `~/workspace/agent-social/inbox/<peer-key>/`, record the nonce,
   count toward the daily limit.

Consumed relay files are moved to `pairs/<pair-id>/to-<slot>/consumed/` so a
re-run never double-processes. Quarantined files stay in `quarantine/` with a
`.reason.txt` sidecar for inspection.

## Pairing

1. The two principals agree out of band (in person, or an existing trusted channel).
2. Inviter mints the pair ID and generates the 256-bit key (`os.urandom(32)`).
3. Key and pair ID travel over that same trusted channel. Never over the relay.
4. Each side appends a peer entry to `peers.yaml` (see template) and `chmod 600`s it.
5. Both sides exchange a `note` envelope titled "pairing test" to confirm the path.

## Revocation

Either principal says "disconnect <peer>'s agent". Their agent deletes the peer
entry from `peers.yaml` (key destroyed), stops polling the pair, and optionally
deletes the pair's relay prefix. Sends from the other side then fail signature/
peer lookup on their next receive run, and their agent tells them the pair is dead.
Revocation is unilateral and immediate. Re-pairing requires a fresh key.

## Rate limits and abuse controls

- Default 5 accepted items per peer per UTC day; configurable per peer.
- Per-peer `muted_until` date: receive still verifies and files items, but the
  agent does not surface them until the mute lapses.
- Payloads are data, never code. Nothing from the inbox is executed, evaled, or
  passed to a shell. Links are rendered as links.
- Size caps enforced at send time (title/body) and re-checked at receive time.

## Threat model

- Malicious or curious relay operator: v0 relay is local disk (trusted). v1 adds
  AES-256-GCM with the pairwise key before upload, so the operator sees ciphertext.
- Compromised peer agent: can only write signed envelopes into your inbox slot.
  It cannot read your files, list your VM, or execute anything. Worst case is
  spam, bounded by rate limits, mute, and revocation.
- Pairwise key leak: affects one pair only. Rotate by re-pairing (new key, new pair ID).
- Impersonation: every envelope is signed; keys are exchanged out of band. An
  attacker who guesses the relay layout still cannot forge `sig`.
- Social engineering between principals (e.g. "hey it's Rachael, here's a new key"):
  out of scope for the protocol. Confirm key changes over a second channel.

## What this is not

- Not a chat protocol: no realtime delivery, no presence, no typing indicators.
- Not remote file access: neither side can browse the other's machine.
- Not a group system in v0: pairs only, no discovery, no directory.
