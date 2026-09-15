# Stale-State Scrub List (checkpoint 1 gate)

Track: inventory. Rule (plan, RETENTION AND TEARDOWN, "State hygiene
before release"): remove the disposable demo outbox and torn-down
relay-state record; scan release artifacts for private keys, bundles,
live pair IDs, principal names, absolute home paths, and ciphertext
copied from production. Checkpoint 1 gate: "Live pair quiet; rollback
inputs verified" AND stale state scrubbed.

Constraints honored: I did not list or read `~/workspace/agent-social/`
(live v0.1 pair state). Entries below are marked OBSERVED (seen in the
read-only prototype tree or code), INFERRED (the code provably creates
them; presence on disk not checked), or UNVERIFIED (expected by the plan
but not checkable from my position). No secrets are quoted; paths and
filenames are safe to name.

## Release artifact tree: what ships vs what must not

The v0.2 public repository is the new `muse-agent-social/` package from
the plan's REPOSITORY DESIGN. The legacy skill tree
(`~/workspace/skills/agent-social/`) is NOT a release artifact and must
not be copied into it. If any file is carried over (e.g. protocol
documentation), scrub it per the rules below.

## Concrete scrub items

### 1. Private key material (highest priority)

- [ ] OBSERVED (code path, presence UNVERIFIED): `keys/<pair-id>.mine.key`
  and `keys/<pair-id>.peer.key` (+ `.pub` files) under
  `~/workspace/agent-social/keys/`, written by `relay-setup-gh.py
  setup()`. Both sides' deploy private keys live on the provisioner's
  disk until `--teardown`; the peer's key is the custody violation.
- [ ] INFERRED: `pairing-bundle-<pair-id>.json` under
  `~/workspace/agent-social/`, written by both `relay-setup.py` and
  `relay-setup-gh.py`. Contains the pair key (`key_hex`), and for the
  GitHub variant the peer's deploy PRIVATE key. There is no code path
  that deletes this file after delivery; `relay-setup-gh.py --teardown`
  deletes key files but NOT the bundle. Treat every bundle as live
  credential material until proven destroyed.
- [ ] INFERRED: `peers.yaml` `key_hex` values (the 256-bit pair key per
  peer, chmod 600 but still on disk) and `relay.yaml` R2
  `secret_access_key` values. These are config, not release artifacts;
  they must never appear in docs, demo transcripts, fixtures, or tests.
- [ ] OBSERVED: `~/workspace/skills/agent-social/bin/__pycache__/` holds
  compiled `.pyc` files for all seven scripts. Exclude from any release
  tree; they embed absolute source paths and are stale build artifacts.
- [ ] OBSERVED: `~/workspace/skills/agent-social/ssh/known_hosts` and
  `known_hosts_github` (empty file) are public host keys, safe to keep
  if needed, but they are v0.1 skill files, not v0.2 release files.

### 2. Live pair identifiers and principal names

- [ ] UNVERIFIED (not listed, per constraint): any live pair id
  (`pair-<12hex>`, e.g. the plan's live pair
  `pair-hermes-rachael-20260913`), agent ids (`agent:<name>:<principal>`),
  principal names, and peer labels appearing in `peers.yaml`,
  `relay.yaml`, `config.yaml`, relay object filenames, or inbox/outbox
  filenames. The plan's teardown post-check explicitly names pair ID,
  peer label, and key filenames as the scan targets. None of these may
  appear in release artifacts, docs, demo transcripts, fixtures, or
  example configs. The v0.2 demo must use fictional identities (plan
  release gate: "Demo transcript uses fictional identities").
- [ ] OBSERVED (in code defaults, harmless but must not ship):
  `send.py`/`receive.py` default `--my-peer-name`-style constants such
  as `"braden"` (relay-setup.py `--my-slot` default) and `"hermes"`
  (relay-setup-gh.py `--my-peer-name` default). These are CLI defaults
  in non-release scripts; ensure no v0.2 example or doc copies them as
  sample identities.

### 3. Plaintext message stores (demo/disposable)

- [ ] INFERRED: `~/workspace/agent-social/outbox-log/` plaintext envelope
  copies (the "disposable demo outbox" named in checkpoint 1). Delete
  before release. Note: `send.py today_count()` derives the daily cap
  from this directory, so it must be empty or absent, never shipped.
- [ ] INFERRED: `~/workspace/agent-social/inbox/<peer>/` plaintext filed
  envelopes. Delete before release.
- [ ] INFERRED: local relay plaintext copies under
  `~/workspace/agent-social/relay/pairs/<pair-id>/to-<slot>/{incoming,consumed,quarantine}/`
  plus `.state.json` replay files. Delete before release.
- [ ] INFERRED: `~/workspace/agent-social/relay-state/<pair-id>.json`
  (the "torn-down relay-state record" named in checkpoint 1) for
  r2/github pairs. Delete before release.
- [ ] INFERRED: `~/workspace/agent-social/git/<pair-id>/` git mirrors.
  They contain ciphertext only, but also commit messages with
  timestamps, filenames, and slot names. Delete before release; do not
  copy any mirror into release artifacts.

### 4. Ciphertext copied from production

- [ ] UNVERIFIED: any `.json` fixture or doc attachment containing
  `{"n","c"}` AES-GCM wrapper objects copied from the live pair's relay.
  The plan explicitly bans "ciphertext copied from production" in
  release artifacts. Test vectors must be generated fresh with random
  keys, never lifted from live traffic.

### 5. Absolute home paths

- [ ] OBSERVED: every script in `bin/` hardcodes
  `~/workspace/agent-social` (via `os.path.expanduser`) and
  `relay-setup.py` / `relay-setup-gh.py` hardcode
  `/opt/hatch/skills/skill-creator/bin` for `dynamic_credentials`.
  `gh_backend.py` hardcodes the skill's `ssh/known_hosts` path.
  Checkpoint 2's gate is "no hardcoded home path"; none of these paths
  may appear in v0.2 code, config samples, docs, or error strings.
  Scan release artifacts for `/home/hatch`, `~/workspace/agent-social`,
  and `/opt/hatch`.

### 6. Bundles and pairing leftovers

- [ ] Covered in section 1, repeated here because the plan's teardown
  order names them explicitly: "Delete pairing bundles, invite state,
  relay config, mirror, replay rows, retry queues, scheduler rows,
  plaintext cache, inbox, and outbox." For v0.1 state this maps to:
  `pairing-bundle-*.json`, `peers.yaml` peer entries for torn-down
  pairs, `relay.yaml` pair entries, `git/` mirrors,
  `relay-state/*.json`, `.state.json` files, `inbox/`, `outbox-log/`.
- [ ] UNVERIFIED: any `*.reason.txt` quarantine sidecars retained for
  inspection. They contain failure metadata and filenames; do not ship.

## Verification procedure (for the implementing track)

1. After the v0.2 package tree is assembled and before tagging v0.2.0,
   run a content scan over the release tree for: `BEGIN .*PRIVATE KEY`,
   `key_hex`, `secret_access_key`, `deploy_private_key`,
   `pairing-bundle`, `pair-` followed by hex, `agent:`, `/home/hatch`,
   `~/workspace`, `/opt/hatch`, and base64 blobs longer than 200 chars
   (possible ciphertext). Zero hits required.
2. Confirm the release tree contains no `__pycache__/`, no `.pyc`, no
   `keys/`, no `inbox/`, no `outbox-log/`, no `relay-state/`, no `git/`.
3. Confirm demo transcripts and fixtures use fictional identities and
   freshly generated keys (plan release gate).
4. Confirm the v0.1 teardown of the live pair (plan LIVE MIGRATION step
   9) completed on BOTH sides: old deploy keys removed, relay repo
   handled per the rename plan, legacy pair key and peer private key
   copy deleted, bundle destroyed, local scan for pair id / peer label /
   key filenames returns clean, and only the minimal consent tombstone
   (relationship id hash, revoked time, local reason code) remains.
5. Rollback inputs for checkpoint 1 ("rollback inputs verified") are the
   encrypted local rollback bundles from LIVE MIGRATION step 2; verify
   they exist and are restorable BEFORE scrubbing anything the rollback
   might need. Scrub order: verify rollback inputs first, then delete
   disposable state.

## Known gaps in the prototype's own teardown (do not rely on it)

Neither `--teardown` path is sufficient for this scrub list (see
`docs/v01-inventory.md` section "Incomplete teardown"): the R2 teardown
leaves the `peers.yaml` entry, and neither teardown deletes the pairing
bundle, inbox, outbox-log, replay state, or git mirror. The scrub must
be performed by explicit deletion and verified by the scan above, not by
running the prototype's teardown scripts.
