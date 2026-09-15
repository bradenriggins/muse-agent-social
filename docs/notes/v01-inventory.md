# v0.1 Prototype Inventory

Track: inventory. Source of truth: `muse-agent-social-implementation-plan.pdf`
(release candidate, owner Braden Riggins, 2026-09-15), read in full 2026-09-15.
Read-only sources inspected: `~/workspace/skills/agent-social/bin/send.py`,
`receive.py`, `envelope_crypto.py`, `r2_backend.py`, `gh_backend.py`,
`relay-setup.py`, `relay-setup-gh.py`, and
`~/workspace/skills/agent-social/references/protocol.md`.

Constraints honored: no code changed, no network calls, no secrets copied
(key material is described, never quoted), no inspection of
`~/workspace/agent-social/` (live pair state, not touched).

Conventions in this document:
- "Claimed" = what `references/protocol.md` or code docstrings promise.
- "Observed" = what the code actually does.
- UNVERIFIED = inferred from code or the plan but not directly observed
  (e.g. live state I was forbidden from listing).

## Exact legacy envelope field set

`send.py main()` emits exactly these 12 fields, in this insertion order,
every time. There is no optional-field omission in the sender.

1. `"v"` : integer 1
2. `"id"` : uuid4 string
3. `"from"` : sender agent id string, from `config.yaml` `agent_id`
4. `"to"` : recipient agent id string, from `peers.yaml` peer entry `agent_id`
5. `"pair"` : pair id string, from `peers.yaml` peer entry `pair_id`
6. `"type"` : one of `"note"`, `"link"`, `"article"`, `"file-ref"`
   (`TYPES` tuple in `send.py`)
7. `"title"` : string, required CLI arg, max 200 chars (`TITLE_MAX = 200`)
8. `"body"` : string, defaults to `""` if no `--body`/`--file`; max 262144
   chars (`BODY_MAX = 262144`)
9. `"url"` : string, defaults to `""`; **always present** (see section
   "Where the plan and code disagree" below). Required CLI arg only when
   `--type` is `link`, `article`, or `file-ref`.
10. `"created_at"` : UTC string exactly `%Y-%m-%dT%H:%M:%SZ`
    (e.g. `2026-09-15T20:00:00Z`)
11. `"nonce"` : uuid4 string (fresh per envelope)
12. `"sig"` : hex HMAC-SHA256 over canonical bytes (see Crypto)

Wire form differs by transport:
- local transport: the 12-field envelope as plain JSON (`indent=2` plus
  trailing newline) written to
  `relay/pairs/<pair-id>/to-<slot>/incoming/<fname>`.
- github transport: the 12-field envelope JSON is AES-256-GCM encrypted by
  `envelope_crypto.encrypt_envelope` (imported via `gh_backend.py`); stored
  bytes are a second JSON object `{"n": "<base64 12-byte nonce>",
  "c": "<base64 ciphertext>"}`.
- r2 transport: same encryption, via `r2_backend.encrypt_envelope`
  (a separate copy of the identical function; see duplication note below).

So a v0.1 "sealed" object on the relay is either the 12-field plaintext
JSON (local) or the `{"n","c"}` wrapper JSON (github/r2).

## send.py

- CLI: `--to` (peer key in peers.yaml), `--type` (choices `note`, `link`,
  `article`, `file-ref`), `--title` (required), `--body`, `--url`,
  `--file` (read body from file), `--config`, `--peers`, `--relay`,
  `--relay-cfg`, `--outbox-log`, `--dry-run`. Defaults point at
  `~/workspace/agent-social/`.
- Send-time size checks (only place they exist): title > 200 chars is
  rejected; body > 262144 chars is rejected. Both enforced in `main()`
  before envelope construction.
- Daily cap: `daily_cap = peer.get("daily_cap", 5)`; `today_count()`
  counts files in `outbox-log/<peer-key>/` whose names start with today's
  UTC `%Y-%m-%d` string. Send is refused when `sent_today >= daily_cap`.
  Boundary-sensitive: counts reset at the UTC date boundary, not on a
  rolling 24-hour window.
- Envelope filename: `f"{now.strftime('%Y%m%dT%H%M%SZ')}-{envelope['id']}.json"`.
  The timestamp is UTC send time to the second, exposing exact send times
  in object names (plan's "timestamped filenames" finding).
- Outbox log: after transport write, the full plaintext envelope is written
  to `outbox-log/<peer-key>/<YYYY-MM-DD>-<id>.json`. This is the
  "disposable demo outbox" the plan's checkpoint 1 says to remove, and it
  is also the daily-cap accounting source. Plaintext retained indefinitely.
- Transport dispatch on `peer.get("transport", "local")`: `"r2"` imports
  `r2_backend.R2Backend` and encrypts; `"github"` imports
  `gh_backend.GitHubRelay` and encrypts; anything else writes plaintext
  into the local relay slot dir (which is created unconditionally with
  `os.makedirs` even for remote transports).

### Crypto (send.py `canonical`, `sign`; receive.py `verify`)

- `canonical(envelope)`: `json.dumps({k: v for k, v in envelope.items() if k != "sig"}, sort_keys=True, separators=(",", ":")).encode("utf-8")`.
  The `sig` field is excluded; everything else (including empty-string
  `body`/`url`) is included. No Unicode normalization; Python default
  float/bool handling (v0.1 never emits floats or booleans in the envelope).
- `sign(envelope, key_hex)`: `hmac.new(bytes.fromhex(key_hex), canonical(envelope), hashlib.sha256).hexdigest()`. Key is the single 256-bit
  pairwise key stored as hex in `peers.yaml` `key_hex`, minted with
  `os.urandom(32).hex()` in both provisioning scripts.
- `verify(envelope, key_hex)` (receive.py): recomputes the same HMAC and
  compares with `hmac.compare_digest`. Missing `sig` fails (empty string
  never matches the digest).
- That same pair key is also the AES-256-GCM key for relay encryption
  (`envelope_crypto.encrypt_envelope` / `decrypt_envelope`, and the
  duplicate copies in `r2_backend.py`). One key does both authentication
  (HMAC) and confidentiality (GCM). The plan's "v0.1 pair key currently
  signs and encrypts" is confirmed.

### Nonce and replay (receive.py `check_envelope`, `main`)

- `nonce` is a uuid4 assigned in `send.py main()`.
- Receive keeps `state["seen_nonces"]`, a list, persisted as JSON at
  `relay/pairs/<pair-id>/.state.json` (local transport) or
  `~/workspace/agent-social/relay-state/<pair-id>.json` (r2/github).
- `check_envelope()` rejects with `"duplicate nonce (replay)"` if
  `env.get("nonce") in state["seen_nonces"]`.
- After acceptance, `main()` appends the nonce and truncates with
  `state["seen_nonces"] = state["seen_nonces"][-1000:]`. This is the
  plan's "count-based nonce truncation": history drops after 1000 entries
  even while entries are still age-valid (MAX_AGE = 7 days).
- Missing nonce passes: `env.get("nonce")` returns `None`, and `None` is
  never in `seen_nonces`, so the check is skipped. Then
  `state["seen_nonces"].append(env["nonce"])` appends `None`, which does
  not block a second envelope that also lacks `nonce`. The plan's
  "Missing nonce fields pass validation" is confirmed. (A missing nonce
  also crashes nowhere; acceptance proceeds normally.)

### Receive validation order (receive.py `check_envelope`)

1. `env.get("pair") != pair_id or env.get("from") != peer["agent_id"]`
   -> "pair/from mismatch with peers.yaml". Note the `v` field is never
   checked; the receiver does not gate on `v == 1`.
2. `env.get("to") != my_id` -> "envelope addressed to someone else".
3. `verify()` -> "signature verification failed".
4. `created_at` parsed with `datetime.strptime(env["created_at"], "%Y-%m-%dT%H:%M:%SZ")`;
   any parse failure -> "bad created_at format".
5. Age window: `now - created > MAX_AGE` (7 days) or
   `created - now > FUTURE_SKEW` (1 hour) -> "created_at outside
   acceptance window".
6. Duplicate nonce -> "duplicate nonce (replay)".
7. `accepted_today >= cap` -> "daily cap reached".

Notably absent from `check_envelope()`: any size/length check (plan's
"Receive-side size checks are promised, not implemented"), any check of
`v`, `type` membership, title length, `id` uniqueness, or `nonce`
presence. `protocol.md` claims "Size caps enforced at send time (title/body)
and re-checked at receive time"; the second half is not implemented.

### Receive behaviors

- Filing: accepted envelopes are written as plaintext JSON (`indent=2`)
  into `~/workspace/agent-social/inbox/<peer-key>/<fname>` (the same
  timestamped filename as the relay object). Plaintext inbox, retained
  indefinitely. The plan's "plaintext retention" blocker is confirmed for
  both inbox and outbox-log.
- Ordering: `backend.list_incoming()` returns `sorted(os.listdir(...))`,
  i.e. filename order, which is chronological only because of the
  timestamped name scheme. No sequence numbers exist in v0.1.
- Consume: after inbox write and state append, `backend.consume(fname)`
  moves the object from `incoming` to `consumed` (local: `os.rename`;
  github: `move` = rename + `git push`; r2: copy + delete). The inbox
  write, state write, and consume are three separate steps with no
  atomicity: a crash between them yields either duplicates on re-run
  (inbox written, consume not done) or accepted-but-unfiled items (state
  written, inbox write lost), or nonce recorded with no filed copy.
  The plan's "Crash duplication" blocker is confirmed.
- Quarantine: unparseable objects and failed validations are moved to
  `quarantine/` with a `<fname>.reason.txt` sidecar (local). r2 puts the
  reason file in `quarantine/` too; github writes it to `rejected/`
  (an inconsistency: github quarantine moves the object to `quarantine/`
  but writes the reason to `rejected/`). Reason files starting with
  `.reason.txt` are skipped during `list_incoming` scanning.
- `muted_until`: documented in `protocol.md` ("Per-peer muted_until date:
  receive still verifies and files items, but the agent does not surface
  them until the mute lapses") and in `references/feed-integration.md`
  ("Respect muted_until in peers.yaml: file the items, don't surface
  them"). `receive.py` never reads `muted_until`; it performs no
  surfacing at all (it prints a digest / `--json` for an external
  notifier). The plan's "muted_until is documented but unused" is
  confirmed.
- Rate accounting: `state["daily"][today]` increments per accepted item
  (UTC day key). `state["daily"]` accumulates one key per UTC day forever
  (no pruning), minor state bloat.
- Exit codes: `main()` returns 0 on every successful run, including runs
  that quarantined items or failed to read objects (failures print to
  stderr). There is no 0/20/21/22/23 exit-code contract. A watcher cannot
  distinguish "all objects reached terminal state" from "read failures
  happened". The plan's "watcher silence" finding is consistent with this.
- Unbounded receive: no size limit is applied to any incoming object
  before `json.load`/`decrypt` (the plan's "Unbounded receive" blocker).
  For r2, `list_objects_v2` pages 1000 keys at a time; names are sorted.

## envelope_crypto.py

- `encrypt_envelope(envelope, key_hex) -> bytes`: fresh 12-byte nonce
  from `os.urandom(12)`; `AESGCM(bytes.fromhex(key_hex)).encrypt(nonce,
  json.dumps(envelope).encode("utf-8"), None)`; returns JSON bytes of
  `{"n": base64(12-byte nonce), "c": base64(ciphertext)}`. AAD is `None`.
- `decrypt_envelope(body, key_hex) -> dict`: parses the outer JSON,
  base64-decodes `n` and `c`, AES-GCM decrypts, JSON-parses the plaintext.
  Raises on any malformed input (base64 errors, GCM auth failure, JSON
  errors), which `receive.py` catches and quarantines as "unreadable
  payload".
- Base64 here is standard `base64.b64encode` (padded), unlike v0.2's
  unpadded base64url. The key role is identical to the HMAC key (single
  pair key, see above). The nonce is a random GCM nonce per message,
  not a replay nonce.

## r2_backend.py

- Duplicate `encrypt_envelope`/`decrypt_envelope` functions identical in
  behavior to `envelope_crypto.py` (code duplication: three copies of the
  same construction exist across `envelope_crypto.py`, `r2_backend.py`;
  `gh_backend.py` imports from `envelope_crypto`). Module docstring
  references `~/workspace/agent-social/.venv` for boto3/cryptography.
- `R2Backend` maps slots to S3 keys `to-<slot>/<subdir>/<fname>` under one
  bucket per pair (`agent-social-<pair-id>`).
- `put_incoming`: `put_object`. `read`: `get_object` body. `move`:
  copy_object + delete_object. `write_reason`: `put_object` of reason
  text under `to-<slot>/quarantine/<fname>.reason.txt`.
- `list_incoming` paginates with `MaxKeys=1000`, sorts names.
- `protocol.md` itself notes R2 is unreachable from this VM ("this VM's
  egress proxy kills TLS to *.r2.cloudflarestorage.com (verified
  2026-09-13)"), so the R2 data plane is not proven here. The plan's
  "R2 exists as code but is not proven in this environment" is consistent.

## gh_backend.py

- Module docstring says repo layout is
  `to-<slot>/{incoming,accepted,rejected}/*.json`. The code actually uses
  `incoming`, `consumed`, and `quarantine` subdirectories (with reason
  sidecars written to `rejected/`). Docstring/code mismatch.
- `GitHubRelay.__init__(repo_ssh_url, key_path, pair_id)`: `_ensure_mirror`
  clones (or fetch + `reset --hard origin/main`) into
  `~/workspace/agent-social/git/<pair_id>`; sets git identity
  `agent-social` / `agent-social@localhost`.
- `_git_env`: `GIT_SSH_COMMAND` uses the deploy key (`-i key_path`),
  `UserKnownHostsFile` from the skill's `ssh/known_hosts`,
  `ProxyCommand='nc -X connect -x hatch-egress-proxy:3128 %h %p'`,
  `GIT_TERMINAL_PROMPT=0`. Git subprocess timeout 120s.
- `_sync_down()`: `git fetch origin`, then `reset --hard origin/main`
  if `origin/main` exists. Called by `list_incoming` and `read`.
- `_push(msg)`: `git add -A`, `git commit` (tolerates "nothing to commit"),
  then up to 2 attempts of `fetch` + `pull --rebase origin main`, then
  `git push origin main`. No lock of any kind around fetch/reset/commit/
  rebase/push; `_ensure_mirror` also does `reset --hard` outside a lock.
  This is the plan's "Git race": send and receive both mutate the same
  mirror with no mutual exclusion.
- Rebase wedge risk: if `pull --rebase` exits nonzero (conflict), the
  code just retries once more, then proceeds to `push` anyway. There is
  no `git rebase --abort` on failure, so a conflicted rebase state can
  persist and wedge the mirror. The plan's "Rebase conflicts can leave
  the mirror permanently wedged" is confirmed.
- Object naming: the caller (`send.py`) supplies the timestamped
  filename; `put_incoming` writes it and pushes commit
  `f"incoming {fname} for {slot}"`. Every send and every receive-side
  move/quarantine is a separate git push (no batching), so bidirectional
  traffic generates interleaved pushes, the race surface the plan's
  "Batch to at most one push per minute per side" rule is meant to fix.
- `move(slot, fname, from_subdir, to_subdir)`: `os.rename` + push commit
  `f"move {fname} {from_subdir}->{to_subdir} for {slot}"`.
- `write_reason`: writes reason text to
  `to-<slot>/rejected/<fname>.reason.txt` + push (see subdirectory
  inconsistency noted above).

## relay-setup.py (R2 provisioning)

- Creates one bucket per pair named `agent-social-<pair-id>`.
- Creates two API tokens (`agent-social-<pair-id>-<slot>`), each scoped
  to the pair's bucket with "Workers R2 Storage Bucket Item Write".
- Derives the S3 secret access key as
  `hashlib.sha256(token["value"].encode()).hexdigest()`; access key id
  is the token id.
- Mints the pair key with `os.urandom(32).hex()`.
- Writes `relay.yaml` entry: `endpoint`, `bucket`, `access_key_id`,
  `secret_access_key`, `token_ids`, `account_id` (chmod 600).
- Appends `peers.yaml` entry: `agent_id`, `pair_id`, `my_slot`, `slot`,
  `key_hex` (the pair key), `transport: "r2"`, `daily_cap: 5`.
- Writes peer bundle to `~/workspace/agent-social/pairing-bundle-<pair-id>.json`
  (chmod 600) containing: `pair_id`, `peer_agent_id` (inviter's id),
  `my_slot`/`slot` (from the peer's point of view), `key_hex` (the pair
  key), `transport`, `relay` with the peer's `endpoint`, `bucket`,
  `access_key_id`, `secret_access_key`. The bundle carries live
  credentials plus the pair key; nothing in the script deletes it after
  delivery.
- `--teardown`: revokes both API tokens, deletes the bucket, removes the
  `relay.yaml` entry. It does NOT remove the `peers.yaml` entry, does
  NOT delete the pairing bundle, does NOT delete inbox/outbox-log/replay
  state. Incomplete teardown (see state hygiene section).
- `--dry-run` prints what would be created; everything else hits the
  Cloudflare API over the network.

## relay-setup-gh.py (GitHub provisioning)

- Creates private repo `agent-social-<pair-id>` (auto_init) via
  `custom.github` dynamic credentials.
- Generates BOTH sides' ed25519 deploy keys locally with `ssh-keygen`
  into `~/workspace/agent-social/keys/<pair-id>.{mine,peer}.key`
  (chmod 600) and registers both public keys on the repo as read/write
  deploy keys. This is the plan's "Peer key custody" blocker: the
  provisioner generates and keeps the peer's deploy private key, and the
  peer bundle hands it over afterward instead of the peer generating it.
- `relay.yaml` entry: `provider: "github"`, `repo_ssh_url`, `key_path`
  (my private key path), `deploy_key_ids` (both slots), `repo`
  (`owner/agent-social-<pair-id>`).
- `peers.yaml` entry: same fields as R2 (`agent_id`, `pair_id`,
  `my_slot`, `slot`, `key_hex` pair key, `transport: "github"`,
  `daily_cap: 5`).
- Peer bundle at `~/workspace/agent-social/pairing-bundle-<pair-id>.json`
  (chmod 600) contains the PEER'S DEPLOY PRIVATE KEY under
  `relay.deploy_private_key`, plus the pair key, repo URL, and
  known_hosts. Note the bundle's slot mapping: `"slot": args.my_slot`
  (peer's view: my slot is their peer) and `"my_slot": args.peer_slot`
  (peer's view: their own slot); `"peer_name"`/`"peer_agent_id"` identify
  the inviter.
- Old repo prefix: `repo_name = f"agent-social-{args.pair_id}"`. The
  plan's "New pair provisioning still emits the old repo prefix" is
  confirmed (the live-migration step 6 references a renamed repository).
- `--teardown`: removes both deploy keys, deletes the repo, deletes both
  private and public key files, removes the `relay.yaml` entry and the
  `peers.yaml` peer entry. It does NOT delete the pairing bundle
  (which retains the peer's deploy private key and the pair key), does
  NOT delete inbox, outbox-log, replay state (`relay-state/<pair-id>.json`),
  or the git mirror. Incomplete teardown.

## Adversarial table: plan claims vs observed behavior

Every item named in the task brief, with file and function evidence:

1. **Peer key custody** (relay-setup-gh.py `setup()`): confirmed. Both
   ed25519 keypairs are generated locally via `ssh-keygen`; the peer's
   private key persists at `keys/<pair-id>.peer.key` and inside the peer
   bundle at `BASE/pairing-bundle-<pair-id>.json` until `--teardown`.
   Additionally, nothing ever deletes the bundle after delivery; the
   teardown path deletes key files but leaves the bundle (which still
   contains the peer private key and the pair key).
2. **Git race** (gh_backend.py `_push`, `_ensure_mirror`, `_sync_down`;
   receive.py `GitHubBackendAdapter`; send.py `main`): confirmed. No
   flock or any lock anywhere; `reset --hard`, `add -A`, commit, rebase,
   and push are interleaved by concurrent send/receive processes.
3. **Crash duplication** (receive.py `main`): confirmed. Inbox write
   (`json.dump` to inbox), nonce append + `state` file write, and
   `backend.consume()` are sequential, non-atomic steps. Reruns after a
   crash between any two steps double-process or lose items.
4. **Replay gap** (receive.py `main`): confirmed.
   `state["seen_nonces"][-1000:]` truncates by count while the acceptance
   window is 7 days; a peer sending >1000 messages in 7 days (or a long
   history on disk) makes replays of the oldest accepted envelopes pass
   again.
5. **Unbounded receive** (receive.py `check_envelope`, backends):
   confirmed. No size check before or after parse/decrypt on any
   transport. `json.load` reads the whole file into memory.
6. **Plaintext retention** (receive.py inbox write; send.py outbox-log
   write): confirmed. Both are plaintext JSON, kept indefinitely, with no
   retention policy or delete path.
7. **Watcher silence** (receive.py `main`): confirmed as far as the code
   goes. No watcher exists in `bin/`; `receive.py` always exits 0,
   including on unreadable/quarantined objects, so any external scheduler
   cannot tell success from failure from the exit status. Nothing writes
   a "last successful HEAD" checkpoint or retries failures independently
   of new branch movement.
8. **muted_until unused** (receive.py): confirmed. Never read. Documented
   in `protocol.md` and `references/feed-integration.md`.
9. **Missing nonce accepted** (receive.py `check_envelope`): confirmed.
   `env.get("nonce")` is `None`, never in `seen_nonces`, so the replay
   check is skipped silently.
10. **Rebase wedge risk** (gh_backend.py `_push`): confirmed. Failed
    `pull --rebase` is retried once with no abort; the push proceeds
    afterward. A conflicted rebase persists in the mirror.
11. **Timestamped filenames** (send.py `main`): confirmed.
    `%Y%m%dT%H%M%SZ-<uuid>.json` embeds exact UTC send time to the second.
12. **Non-installable layout** (all scripts): confirmed. Hardcoded
    `~/workspace/agent-social` paths, `sys.path.insert` hacks,
    `#!/usr/bin/env python3` shebangs, undeclared dependency on
    `/opt/hatch/skills/skill-creator/bin/dynamic_credentials` for the
    setup scripts, `boto3` for R2, `yaml` for all. No `pyproject.toml`.
13. **Incomplete teardown** (relay-setup.py `teardown`, relay-setup-gh.py
    `teardown`): confirmed, and worse than the summary. R2 teardown does
    not even remove the `peers.yaml` entry. Neither teardown deletes:
    the pairing bundle (holds pair key + peer credentials), inbox,
    outbox-log, replay state (`relay-state/<pair-id>.json` or
    `.state.json`), or the git mirror.
14. **Count-based nonce truncation** (receive.py `main`): confirmed.
    `state["seen_nonces"][-1000:]`.
15. **Old repo prefix in provisioning** (relay-setup-gh.py `setup()`):
    confirmed. `repo_name = f"agent-social-{args.pair_id}"`.
16. **Boundary-sensitive daily limits** (send.py `today_count`;
    receive.py `main`): confirmed. `today_count()` counts outbox-log
    filenames with today's UTC date prefix; receive counts
    `state["daily"][today]` per UTC day. No rolling window. (Bonus:
    `today_count` also breaks if outbox-log files are pruned, since the
    cap is derived from the same disposable directory the plan says to
    delete.)
17. **No `v` gating** (receive.py `check_envelope`): not in the plan's
    table but relevant to the adapter spec: the receiver never inspects
    `env.get("v")`, so a non-v1 object with a valid HMAC would be
    accepted by v0.1 code.

## Where the plan and code disagree (plan misdescriptions of v0.1)

1. **`url` optionality.** `protocol.md` says fields are required "unless
   marked optional" and marks `url` as optional ("for link/article").
   `send.py` always emits `url` (default `""`), and requires `--url` for
   `link`, `article`, AND `file-ref` (not just link/article). An exact
   legacy field-set check in the adapter must therefore accept `url`
   present with an empty string, not only present-with-value or absent.
2. **Size checks "re-checked at receive time".** `protocol.md` promises
   this; it is not implemented. The plan's adversarial table correctly
   reclassifies it as "promised, not implemented", but the protocol doc
   still overstates the baseline.
3. **Repo layout docstring.** `gh_backend.py`'s module docstring says
   `to-<slot>/{incoming,accepted,rejected}/*.json`; the code uses
   `incoming`, `consumed`, `quarantine` (plus reason files in `rejected/`).
   Any migration tooling that trusts the docstring will look in the wrong
   directories.
4. **Teardown completeness.** The plan says "Teardown leaves plaintext,
   replay state, and bundles." The reality is sharper: the R2 teardown
   does not remove the `peers.yaml` entry either, and neither teardown
   has any code path that deletes the pairing bundle after delivery
   (the bundle is written once and never referenced again). The plan's
   "Delete transient bundle material after confirmed delivery" has no
   corresponding mechanism in the prototype at all.
5. **R2 status.** Consistent, not a misdescription: `protocol.md` itself
   records the R2 data plane as blocked from this VM (egress proxy kills
   TLS to `*.r2.cloudflarestorage.com`, verified 2026-09-13), matching
   the plan's "not proven in this environment".
6. **`sig` vs "signature".** `protocol.md` and the plan describe v0.1 as
   having a `sig` field that is an HMAC hex digest. Code confirms. The
   plan's adapter language "signature result" should be read as the
   HMAC hex digest string, not a public-key signature.
7. **Rate-limit denominator.** The plan says "Current daily limits are
   boundary-sensitive rather than rolling" without noting that the send
   side (`today_count`) and receive side (`state["daily"]`) use different
   storage (outbox-log filenames vs state file) and that the send-side
   cap evaporates if the outbox-log is pruned. The adapter's rate policy
   should be defined on receive-side accounting only.
