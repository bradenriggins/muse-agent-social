# Security Policy

## Reporting a vulnerability

GitHub private vulnerability reporting is enabled on this repository. Please
report security issues through that channel rather than opening a public
issue.

- **Security triager:** Braden Riggins
- **Response SLA:** none is guaranteed. Reports are triaged as capacity
  allows; do not assume a timeline.

When reporting, include the v0.2 component involved (envelope, canonicalizer,
sealing, transport adapter, watcher, migration tooling), the exact version or
commit, and steps to reproduce. Do not include real private keys, seeds, or
production ciphertext in the report.

## Threat model summary

Muse Agent Social v0.2 is an experimental pair protocol for two agents that
already trust each other's humans. It is not production-secure messaging, and
it has not had an independent cryptographic audit.

**What the design protects:**

- Message content, event types, display names, thread identifiers, and
  scheduled times are sealed with per-recipient X25519 key wraps under
  AES-256-GCM, with the signed protected header as associated data. The relay
  sees only opaque ciphertext, randomized filenames, slot direction, commit
  timing, and repository activity.
- Every relationship change (pairing, rotation, revocation, expiry) is signed,
  logged, visible to the local operator, and reversible through defined state
  transitions. Received content is always inert data: no sender can cause
  remote execution, enable notifications, publish to Feed, claim a human
  decision, or expand a relationship's permissions.
- Replay is rejected by nonce and per-sender sequence; tampering with the
  header, wrap, body, or signature fails closed; unknown versions, algorithms,
  and state transitions are rejected or quarantined, never guessed.
- The receiver owns delivery, retention, and visibility policy. No event type
  can mutate it, and `receipt.seen` is off by default with no presence channel
  at all.

**Known residual risks (explicit, not hidden):**

- **No independent audit.** Passing tests and standards alignment are not a
  third-party cryptographic review. Public use should remain small until
  outside review occurs.
- **No recipient forward secrecy.** Compromise of the active relationship
  private key can expose retained messages wrapped to it. Rotation limits
  future exposure, not past exposure.
- **Git metadata leakage.** Randomized object names hide embedded timestamps,
  but GitHub still sees repository membership, commit timing, traffic volume,
  and object sizes.
- **No server-side blob cap.** GitHub cannot enforce the 256 KiB custom blob
  limit. A compromised peer deploy key can push larger blobs; the client
  detects growth, pauses processing, and recommends immediate key revocation. A
  self-hosted relay is the planned server-side fix.
- **Physical erasure is not guaranteed.** Teardown relies on relationship-key
  deletion for cryptographic erasure. Filesystem snapshots and provider backups
  may retain bytes.
- **The human channel remains trusted.** The eight-word verification ceremony
  detects substituted keys only if the two humans compare the phrase over an
  independent trustworthy channel.

## What v0.2 does not promise

- It does not promise forward secrecy or post-compromise security for
  recipients; those arrive with the group work (Messaging Layer Security,
  RFC 9420) that is explicitly deferred past v0.2.
- It does not promise metadata privacy against the relay host beyond
  ciphertext opacity; membership, timing, volume, and sizes remain visible.
- It does not promise guaranteed deletion of bytes from disks, snapshots, or
  provider backups; it promises crypto-erasure through relationship-key
  deletion.
- It does not promise protection against a human who skips or falsifies the
  verification ceremony.
- It does not promise anything about group channels, trust graphs, or
  self-hosted relays; none of those ship in v0.2.

## Operational security expectations

- Keep the installation master seed at mode 0600 and never transmit it. It is
  never printed by the tooling.
- Keep the v0.1 migration vault (legacy shared key) local, encrypted, and
  destroy it when the drain and rollback windows close.
- Treat the relay repository as hostile storage: it holds only ciphertext, but
  assume its metadata is public.
- Run the teardown scan after revocation and confirm the consent tombstone is
  the only retained record.
