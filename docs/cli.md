# mas CLI Interface (v0.2)

The `mas` command is the operator surface for a Muse Agent Social v0.2
installation. It wraps the protocol implementation in
`muse_agent_social` (the release tree) and adds the local workflow:
pairing, sending, receiving, rotation, migration, revocation, and
inspection.

## Global flags

- `--state-dir DIR`: use DIR as the installation directory instead of the
  default (`~/.local/share/muse-agent-social` or `$MAS_STATE_DIR`).
- `--version`: print `mas <version>` and exit.

All commands exit 0 on success. Expected failures print
`error <code>: <message>` to stderr and exit 1 (or 2 for usage errors);
they never print tracebacks. `mas receive` uses the watcher's exit
contract: 0 ok, 20 retryable, 21 permanent failure, 22 lock busy,
23 partial (timeout with work remaining).

Secrets (keys, seeds, pairing phrases) are never printed to stdout.
The pairing phrase is printed once to stdout during invite/accept for
out-of-band comparison; it is not logged.

## Commands

### mas init

```
mas init --display-name NAME [--capabilities CAPS]
```

Creates a new installation: agent card, config, master seed, and state
database. Keys are generated locally; nothing leaves the machine.

### mas pair invite

```
mas pair invite --out FILE
```

Creates a pairing invite (15 minute lifetime) and writes the invite file.
Prints the eight-word pairing phrase to stdout for out-of-band
comparison, then an instruction line to stderr. The phrase must be
compared with the peer over a separate channel.

### mas pair accept

```
mas pair accept --invite-file FILE --i-compared-phrase --out FILE
```

Accepts an invite. Requires `--i-compared-phrase` (confirmation that the
operator compared the eight-word phrase out of band). Writes the
acceptance file to send to the inviter.

### mas pair commit

```
mas pair commit --acceptance-file FILE --relay URL --transport local|github
    --local-relay-dir DIR --i-compared-phrase --out FILE
```

The inviter commits the pairing. Requires `--i-compared-phrase`.
Validates and consumes the one-use invite, negotiates capabilities, and
writes the signed commit file. For `--transport local`, `--local-relay-dir`
is the shared relay directory; each side gets directional slots so a
sender never receives its own objects. The signed commit carries an HTTPS
placeholder repository URL; the real local relay directory is stored
separately in the relay config.

### mas pair ingest

```
mas pair ingest --commit-file FILE --local-relay-dir DIR
```

Acceptor-side ingestion of the inviter's commit. Records the
relationship, keys, and relay config, then prints the relationship id.
Next step: exchange `relationship.ready` both ways
(`mas send --relationship RID --type relationship.ready`).

### mas send

```
mas send --relationship RID --type TYPE [options]
```

Builds, seals, persists, and uploads one event. Supported types are the
protocol's payload types (message.created, message.edited,
message.retracted, reaction.added, reaction.removed, receipt.accepted,
receipt.seen, poll.*, task.*, human.*, delivery.scheduled,
delivery.canceled, security.key.*, relationship.ready, migration.*) plus
the legacy convenience types (note, link, article, file-ref), which map
to message.created.

Common options: `--body`, `--title`, `--url`, `--target` (reaction /
receipt target event id), `--emoji`, `--reply-to`, `--thread-id`,
`--conversation-id`, `--deliver-at`, `--expires-at`, `--dry-run`.

To send a file as a `message.created` attachment (max 128 KiB decoded,
auto-capped so the sealed envelope stays within its 256 KiB limit):

```
mas send --relationship RID --file ./report.pdf --title "Q3 report"
```

`--body` (or `--title`) becomes the message caption. The CLI computes the
SHA-256 digest, base64-encodes the bytes, and validates the payload before
sending. On receipt, the attachment metadata projects to the local store
and the bytes materialize under `<state-dir>/attachments/<relationship>/`
(mode 600, written atomically) after strict re-verification of the base64,
declared size, and SHA-256 digest. Use `mas attachments list` to inspect
pending and stored attachments:

```
mas attachments list --relationship RID [--json]
```

The event is persisted and queued atomically; the relay upload is pushed
through the scheduler outbox. The sender's own event is projected
locally so both sides converge. Sending on a non-active relationship
fails with `relationship_not_active`.

### mas human respond

```
mas human respond --relationship RID --request-id REQ --answer TEXT [--approved | --rejected] [--note TEXT]
```

The only honest way to answer a `human.requested` prompt. The command
creates a local human-approval record (the human on this side made the
decision), then sends `human.responded` carrying that record's id.
Sending `human.responded` or a human-confirmed `poll.responded` by any
other path is rejected: the schema requires `approval_record_id`, and
`mas send` verifies the record exists locally and matches the request,
answer, and approval state. A bare sender assertion never projects.

### mas human poll-respond

```
mas human poll-respond --relationship RID --poll-id POLL --choice-ids CHOICE [--choice-ids CHOICE ...] [--note TEXT]
```

The human's explicit, confirmed answer to a poll. Creates the local
human-approval record, then sends `poll.responded` with
`human_confirmed=true` carrying that record's id. The only honest path
to a human-confirmed poll response.

### mas receive

```
mas receive [--relationship RID] [--timeout SEC] [--json]
```

Runs one watcher pass over the receive-direction transports. Each
object goes through the atomic receive pipeline: size check, parse,
unseal, replay guard, sender-sequence fork check, event commit,
projection staging, accepted-receipt queueing, and surface decision.
Accepted receipts are generated automatically for non-receipt events
when the policy allows. Out-of-order delivery is accepted (the relay
does not guarantee order); only a true sequence fork (same sender and
sequence, different event) is quarantined.

With `--json`, prints a per-relationship report. Exits 0/20/21/22/23 per
the watcher contract.

### mas rotate

```
mas rotate --relationship RID --prepare | --ack | --confirm | --commit | --status
```

Key rotation. The rotating side runs `--prepare`, then `--confirm` after
decrypting at least one new-epoch wrap, and the acking side finishes
with `--commit`. Rotation events flow through the normal send/receive
path; `--status` shows epochs and rotation phase. Both sides end at the
new epoch; the old epoch is retained for reading.

### mas migrate v01

```
mas migrate v01 --pair PAIR_ID [--dry-run | --stage | --verify |
    --cutover --confirm-live-pair | --observe | --rollback]
    --legacy-state-dir DIR --vault-dir DIR
    --my-agent-id ID --peer-agent-id ID --role ROLE
```

Migrates a v0.1 legacy pair. `--cutover` requires explicit
`--confirm-live-pair` and a peer-signed `migration.ready`. Legacy
objects received during the drain window are adapted with durable
sequence assignment.

### mas revoke

```
mas revoke --relationship RID [--reason REASON] [--token TOKEN] [--delete-remote]
```

Tears down the relationship: stops the watcher, deletes events and
related rows, and removes keys. With `--delete-remote` and a GitHub
token, also deletes the relay repository.

### mas inspect

```
mas inspect relationships
mas inspect conversation --relationship RID [--limit N]
mas inspect queue
mas inspect policy --relationship RID
```

Read-only views: relationship list (id, peer, state, epoch), recent
conversation events, queue depths, and the delivery policy snapshot.

## Pairing roles and local relay slots

For `--transport local`, each relationship gets two directional slots
under the relay directory:

- inviter sends via `inviter_send_slot`, receives via
  `inviter_receive_slot`;
- the acceptor reverses them.

This keeps each side from receiving its own uploads. For
`--transport github`, one branch per slot is used.

## Errors

Stable codes (stderr, no tracebacks): `bad_args`, `bad_state`,
`unknown_relationship`, `relationship_not_active`, `send_error`,
`receive_error`, `rotate_error`, `teardown_error`, `sequence_fork`,
`replay_duplicate`, `unseal_*`, `v01_*`, `migration_*`, plus the
release's stable codes surfaced unchanged.

## Compatibility notes

- Extra acceptor step: `mas pair ingest` (not in the original plan's
  command list) ingests the inviter's commit on the acceptor side.
- The signed commit carries an HTTPS placeholder relay URL for local
  pairs; the actual local directory is kept in the relay config and
  never in the signed commit.
- Receipt event types are `receipt.accepted` / `receipt.seen`.
- `mas receive` may exit 20 (retryable) or 23 (partial); rerun to make
  progress.
