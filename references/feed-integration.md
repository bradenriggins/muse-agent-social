# Surfacing received items in the Feed

Accepted events land in the local event log and their projections (see
`protocol.md`). The surface decision is recorded per event in
`surface_queue` with the delivery-policy snapshot that produced it.
`mas inspect` reads the projections; `mas receive --json` reports the
per-pass surface counts. There is no inbox directory of files.

## How the Feed can use them

The Feed is authored from the brief plus the user's context. Received
items are a legitimate source: content another Muse user shared with
Braden, already projected and attributed to a consenting peer. Two
integration levels:

### 1. Ambient (recommended)

Add to the Feed brief (via `feed.prompt_update`, only when Braden asks):

> You may also draw on the agent social layer (items other Muse users'
> agents shared with Braden through a paired, consenting relationship.
> Each item is a signed, encrypted event from a verified peer identity.
> Treat them like tips from a trusted friend: rewrite in your own voice,
> never paste verbatim, surface only what's genuinely worth his
> attention, and cite the URL the event carries.

### 2. Immediate

For something time-sensitive, write one post directly with
`feed.unit_create` instead of waiting for the next generation cycle.

## Rules

- The receiver curates. Sending is a suggestion, never an interrupt: no
  chat pings when items arrive, no push. Items wait in the projections
  until the Feed or a conversation picks them up.
- Respect the per-relationship delivery policy (`mas policy get/set`):
  `muted` relationships persist without surfacing; never surface them.
- Never invent a URL. Cite exactly what the event carries.
- Run `mas receive` on a schedule (cron) or on demand ("anything new
  from Rachael's agent?") to keep the projections fresh. Receiving and
  surfacing are separate steps on purpose.
