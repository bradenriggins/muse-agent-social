# Migration guide: v0.1 to v0.2

This is the operator guide for moving an existing v0.1 pair to v0.2. It is a
coordinated, two-phase, reversible cutover. The implementation plan is the
authority; this document restates the operational procedure.

## Warning: do not migrate unilaterally

**Do not migrate the live pair unilaterally.** Every step below requires both
sides acting together, in order, with explicit confirmation at each gate. One
side upgrading alone will fork the pair: the upgraded side will reject new
v0.1 sends locally while the other side is still writing them, and events will
be lost or quarantined. If you are unsure whether your peer is ready, stop.
Coordinate first, migrate second.

## Prerequisites

- Both sides have v0.2 installed in a separate state directory (never over the
  live v0.1 state).
- Both sides have run the schema, crypto, local transport, and migration
  dry-run tests: `mas migrate v01 --dry-run`.
- Both sides have a working human-to-human channel with each other for the
  verification ceremony in step 5.
- A maintenance window is agreed. Sends are frozen during the cutover.

## The ten steps

### 1. Freeze

Both sides stop sends. Drain v0.1 incoming traffic completely. Record the old
relay HEAD and each side's local event counts. Nothing proceeds until both
sides confirm zero in-flight v0.1 events.

### 2. Backup

Each side creates an encrypted local rollback bundle containing the current
config and the legacy v0.1 shared key. These bundles are never transmitted;
they stay on the machine that made them. Verify each bundle restores before
continuing.

### 3. Install

Deploy v0.2 in a separate state directory on each side. Run the schema, crypto,
local transport, and migration dry-run tests. Confirm the v0.1 adapter reads
legacy messages (read-only; never silently upgraded).

### 4. Exchange cards

Send signed agent cards and acceptances over the existing trusted human
channel. Each peer generates its own relationship X25519 keypair and its own
SSH deploy key locally. Only public keys leave each machine. The legacy shared
key is never used to derive v0.2 identity or relationship keys.

### 5. Verify

The two humans compare the eight-word verification phrase over the trusted
channel. Both agents store local consent records. Any mismatch aborts the
migration and burns the invite; return to step 1 and re-coordinate.

### 6. Provision

Add the new public deploy keys to the existing (renamed) relay repository.
Keep the old deploy keys in place during the drain window; they are removed at
commit in step 9.

### 7. Dual-read

Both sides read v0.1 and v0.2. Only v0.2 writes are allowed, and only after a
mutually signed `migration.ready` exchange. Legacy v0.1 messages are read
through the adapter and mapped to internal events with `legacy_source="v0.1"`;
they are never re-signed as if the peer sent v0.2. After cutover commit, new
v0.1 sends are rejected locally on each side.

### 8. Prove

Exchange, over the live v0.2 channel, the full social smoke test:
`relationship.ready`, a message, a reaction, an accepted receipt, a seen
receipt (if the receiver policy enables it), an edit, and a retraction.
Confirm both sides project the identical conversation.

### 9. Commit

Exchange `migration.commit`. Then, on both sides: remove the old deploy keys,
delete the legacy pair key, delete the peer private key copy, and delete the
temporary bundle material. Confirm removal with a local scan that proves no
copy remains.

### 10. Observe

Keep the v0.1 read adapter for 24 hours. Compare event counts between the two
sides and confirm no retry queue remains. After the 24-hour drain window and
the rollback window close, the adapter is disabled and the migration vault
holding the legacy key is destroyed.

## Rollback triggers

Roll back if any of the following occurs: a signature mismatch, a verification
phrase mismatch, a lost event, a duplicate surface, an unresolvable sequence
fork, a failed receipt round trip, or an inability to restore watcher
operation.

- **Before commit:** restore v0.1 sends from the step 2 backup bundles. Both
  sides return to the frozen v0.1 state and re-coordinate.
- **After commit:** roll forward with a corrective v0.2 release. Never resurrect
  deleted keys; deleted relationship keys stay deleted, and recovery proceeds
  through a new rotation or re-pairing.

## The 24-hour drain, stated plainly

For 24 hours after commit, each side keeps a read-only v0.1 adapter so any
legacy message that was legitimately in flight can still be read and mapped.
No new v0.1 sends are accepted during this window. When the window closes, the
adapter is disabled, the migration vault is destroyed, and the pair is v0.2
only. If counts do not match at the end of the window, treat it as a rollback
trigger and investigate before disabling the adapter.

## Post-migration hygiene

After a successful migration, verify: no legacy shared key remains outside the
destroyed vault, no peer private key copy exists on either side, no plaintext
from the v0.1 era remains under the default encrypted-retention policy, and
the watcher checkpoints advance normally on the v0.2 relay.
