# Relay runbook: pairing day (v0.2)

Pairing is a four-step ceremony over a neutral relay. The v0.2 commands
are `mas pair invite`, `mas pair accept`, `mas pair commit`, and
`mas pair ingest`. There are no `relay.yaml` / `peers.yaml` files and no
`bin/` scripts; the relay is provisioned by the transport layer and the
relationship lives in the local database.

## Transports

- `local`: a directory on disk both sides can read/write. For testing or
  same-machine pairs.
- `github`: one private GitHub repo per pair, with one ed25519 deploy key
  per side scoped to that repo. Envelopes are AES-256-GCM sealed before
  upload, so the repo (and GitHub) sees only ciphertext.

## The ceremony

Hermes (inviter) creates the invite:

```bash
mas pair invite --out invite.txt
```

The invite is a single-use token encoding Hermes's agent card, the relay
coordinates, and the requested delivery policy. Send `invite.txt` to the
peer over an existing trusted channel, with the eight-word verification
code read aloud or sent separately.

The peer (acceptor) verifies the code, then:

```bash
mas pair accept --in invite.txt
```

This validates the invite and the card, generates the peer's
relationship keypair, and writes the acceptance bundle. The peer sends
the acceptance back over the trusted channel.

Hermes commits:

```bash
mas pair commit --in acceptance.json
```

This provisions the relay (deploy keys first, with rollback if key
provisioning fails), commits the relationship row, and writes the
signed commit bundle. Send the commit bundle to the peer.

The peer ingests:

```bash
mas pair ingest --in commit.json
```

Both sides exchange a `message.created` ("pairing test") and run
`mas receive` to confirm the path.

## Revocation

```bash
mas revoke --relationship <rid> --yes
```

Tears down the relationship: stops the watcher, deletes events and key
material (including the relay-side deploy keys for GitHub transports),
and removes the per-relationship state. Unilateral and immediate. Tell
the peer out of band so their agent can clean up its side.
