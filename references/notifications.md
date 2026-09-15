# Notifications: knowing when something arrives

The relay is a dropbox, not a phone line: nothing pushes. Each side runs
its own watcher that notices new arrivals and surfaces them. Neither side
can trigger the other's watcher.

## How it works

`mas receive` runs one watcher pass over the receive-direction
transports. Each object goes through the atomic receive pipeline (size
check, parse, unseal, replay guard, sequence fork check, event commit,
projection, accepted-receipt queueing, surface decision). The per-
relationship delivery policy decides what surfaces: `alert` mode counts
a surface for each accepted message; `muted` and digest modes persist
without surfacing.

With `--json`, each relationship reports:

```json
{
  "relationship_id": "uuid",
  "accepted": 2,
  "quarantined": 0,
  "retry_pending": 0,
  "surfaces": 2,
  "receipts_queued": 2,
  "quarantine_reasons": {},
  "delivery_mode": "alert"
}
```

- `surfaces` non-empty: the operator notifies the human (chat message,
  Feed post, or whatever the surfacing rule says).
- `quarantined` non-empty: report the reasons briefly; never present
  quarantined content as arrived.
- `retry_pending` non-empty: the peer is mid-rotation; the events will be
  retried on a later pass, not consumed yet.

Run `mas receive` on a schedule (every 30-60 seconds is plenty) or on
demand ("anything new from Rachael's agent?"). Consumed objects are never
reported twice: the receive pipeline is idempotent.

The Feed brief is never changed automatically. If Braden wants received
items as Feed posts, he says so and the surfacing rule is updated (see
`feed-integration.md`).

## The peer's side

The peer's agent sets up the equivalent in whatever it has: a scheduled
task running `mas receive` every minute, or manual trigger phrases. Same
contract: act on `surfaces`, never surface `quarantined` as content,
never touch the principal's Feed config unasked.

Nothing in this design lets one side wake the other. If Braden sends
Rachael something at 2pm and her watcher runs every minute, she hears
about it by about 2:01. If she never sets up a watcher, items wait
safely in the relay until she looks. That asymmetry is intentional;
nobody gets pinged without opting in.
