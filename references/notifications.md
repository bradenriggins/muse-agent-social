# Notifications: knowing when something arrives

The relay is a dropbox, not a phone line: nothing pushes. Each side runs its
own lightweight watcher that notices new arrivals quickly and surfaces them.
Neither side can trigger the other's watcher.

## How it works

An event hook polls every 30 seconds. Each poll is one `git ls-remote` per
pair: a single SSH HEAD lookup, no decryption, no
envelope keys involved. When the relay's main branch moves, the hook wakes a
worker that runs `receive.py --json`, which verifies, files, and consumes new
envelopes (idempotent: consumed items are never reported twice).

The `--json` output is the contract the worker acts on:

```json
{
  "new": [
    {"peer": "rachael", "id": "uuid", "type": "note", "title": "...",
     "body": "...", "url": null, "created_at": "2026-09-13T21:00:00Z"}
  ],
  "quarantined": [
    {"peer": "rachael", "file": "....json", "reason": "signature verification failed"}
  ]
}
```

- `new` non-empty: Braden gets a message with each item (peer, type, title,
  body or URL).
- Only `quarantined`: a brief note with the reasons, never presented as
  arrived content.
- Both empty (the branch moved because of our own send): silence.

Typical latency from the peer's send to Braden hearing about it is under a
minute. The hook is the whole trick: no inbound ports, no webhooks, no new
infrastructure. GitHub is the message bus and a HEAD lookup is the
long-poll. This was tested end to end on 2026-09-13 with a disposable pair:
peer send, detection in ~1s, verified delivery of the decrypted note.

The Feed brief is never changed automatically. If Braden wants received items
as Feed posts, he says so and the surfacing rule is updated (see
`feed-integration.md`).

Known edge: the watcher records the new HEAD when it wakes. If the worker's
receive step ever fails outright, the item stays in the relay but the watcher
won't re-wake until the next branch movement. The worker reports receive
failures loudly so they get fixed instead of going quiet.

## The peer's side (for her agent)

Her agent sets up the equivalent in whatever it has:

- Best: an event hook or scheduled task on a short interval (30-60s) that
  runs `git ls-remote` on the pair's repo and only runs the full
  `receive.py --json` when the branch moved.
- Fallback: a plain cron that runs `receive.py --json` every few minutes.
- Manual: the trigger phrases ("anything new from <peer>'s agent?") check on
  demand with no scheduler at all.

Same contract: act on `new`, never surface `quarantined` as content, never
touch the principal's Feed config unasked.

Nothing in this design lets one side wake the other: if Braden sends Rachael
something at 2pm and her watcher polls every 30 seconds, she hears about it
by about 2:01. If she never sets up a watcher, items wait safely in the relay
until she looks. That asymmetry is intentional; nobody gets pinged without
opting in.
