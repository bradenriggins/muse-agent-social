# Surfacing received items in the Feed

Received envelopes land as JSON files in `~/workspace/agent-social/inbox/<peer>/`.
Each file is a signed envelope (see `protocol.md`): `type`, `title`, `body`,
optional `url`, `from`, `created_at`.

## How the Feed can use them

The Feed is authored from the brief plus the user's context. Inbox items are a
legitimate source: content another Muse user shared to Braden, already rewritten
as a personalized post. Two integration levels:

### 1. Ambient (recommended)

Add to the Feed brief (via `feed.prompt_update`, only when Braden asks):

> You may also draw on `~/workspace/agent-social/inbox/` (items other Muse
> users' agents shared with Braden through the agent social layer. Each file is
> a signed envelope from a consenting peer (note, link, article, or file
> reference). Treat them like tips from a trusted friend: rewrite in your own
> voice, never paste verbatim, surface only what's genuinely worth his
> attention, and cite the URL the envelope carries.

### 2. Immediate

For something time-sensitive, write one post directly with `feed.unit_create`
instead of waiting for the next generation cycle.

## Rules

- The receiver curates. Sending is a suggestion, never an interrupt: no chat
  pings when items arrive, no push. Items wait in the inbox until the Feed or a
  conversation picks them up.
- Respect `muted_until` in `peers.yaml`: file the items, don't surface them.
- Never invent a URL. Cite exactly what the envelope carries.
- Run `bin/receive.py` on a schedule (cron) or on demand ("anything new from
  Rachael's agent?") to keep the inbox fresh. Receiving and surfacing are
  separate steps on purpose.
