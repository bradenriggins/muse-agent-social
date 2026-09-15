# v0.1 Compatibility Adapter Specification

Track: inventory. Target module: `compatibility/v01.py` in the v0.2 package
(`muse_agent_social.compatibility.v01`). This spec implements EXACTLY the
behavior the implementation plan's COMPATIBILITY section prescribes, plus
the validation order and error-code contract the plan's test and failure
tables require. No behavior is added or removed.

## Scope and non-goals

- The adapter is READ-ONLY migration plumbing. It recognizes, verifies,
  and adapts sealed v0.1 objects into internal v0.2 `message.created`
  events. It never signs, never re-encrypts, never re-keys.
- It does not perform the cutover itself (`mas migrate v01` owns the
  migration state machine); it is the primitive that migration, dual-read,
  and the 24-hour drain use to interpret legacy objects.
- Unknown protocol versions fail closed. A v0.1 object is recognized
  ONLY when `v == 1` AND the exact legacy field set validates. Anything
  else is `V01_NOT_LEGACY` or `V01_FIELDSET_MISMATCH`, never silently
  adapted and never "upgraded" in place.

## Inputs

- `obj`: one candidate sealed object, as raw bytes (exactly what the
  transport stored), plus metadata: transport filename (for stable
  sequence ordering and provenance), transport id (local / github),
  relay slot direction.
- `pair_key`: the 32-byte legacy pair key, supplied ONLY from the
  migration vault (see Key custody). The adapter receives it as bytes;
  it must not read `peers.yaml`, `relay.yaml`, or any other config.
- `pair_id`: the legacy pair id, used for synthetic event id derivation
  and policy lookup.
- `seq_assigner`: a callable/state handle that maps a stable ordering key
  to a synthetic sender sequence, assigning once and returning the stored
  value on repeat (see Sequence assignment).

## Required function signatures

The implementer MUST provide exactly these (names, parameters, return
types). Internal helpers may be added but must not change this surface.

```python
def detect_v01(obj: bytes) -> bool:
    """Return True only if obj is a recognizable v0.1 sealed object:
    parses as JSON, is a dict, obj.get("v") == 1, and the key set is
    EXACTLY the legacy field set (see Legacy field set). No HMAC
    verification, no decryption, no semantic checks. Pure syntactic
    recognition."""

class VerifiedLegacy(NamedTuple):
    """A v0.1 object that passed full verification. Immutable."""
    raw: bytes            # original sealed v0.1 bytes, byte-for-byte
    envelope: dict        # the parsed 12-field legacy envelope (plaintext)
    hmac_ok: bool         # always True when this object exists
    filename: str         # transport filename, for provenance/ordering
    pair_id: str

def verify_v01(obj: bytes, pair_key: bytes, *, policy, filename: str = "") -> VerifiedLegacy:
    """Full legacy validation. Raises LegacyError on any failure.
    Order of checks is normative (see Validation order). policy carries:
    pair_id, expected sender agent id, my agent id, daily cap, accepted-today
    count for the legacy peer, and replay store access."""

def adapt_v01(verified: VerifiedLegacy, pair_id: str, seq_assigner) -> dict:
    """Adapt a VerifiedLegacy into an internal v0.2 event dict of type
    message.created. Deterministic: same input yields same output."""
```

`policy` is an explicit parameter object, not ambient config, so the
adapter is testable without the v0.2 store. `seq_assigner` must implement:

```python
def assign(filename: str) -> int: ...
```

returning a positive integer, idempotent per filename, assigned in one
transaction by the caller (the adapter calls it exactly once per adapted
event; the caller owns durability).

## Legacy field set (normative)

Exact key set for recognition: `{"v", "id", "from", "to", "pair", "type",
"title", "body", "url", "created_at", "nonce", "sig"}`. No more, no fewer.
Type expectations: `v` is int 1; `type` is one of `note`, `link`,
`article`, `file-ref`; `title`, `body`, `url`, `id`, `from`, `to`,
`pair`, `created_at`, `nonce`, `sig` are strings. `url` may be the empty
string (the v0.1 sender always emits it). Extra fields, missing fields,
or wrong types are `V01_FIELDSET_MISMATCH`. `detect_v01` checks the key
set only (no type coercion); `verify_v01` enforces types.

## Validation order (normative)

Mirrors the plan's "Size, Parse, Schema, Signature, Policy, Decrypt"
ordering, specialized to v0.1. First failure wins; raise the matching
error code.

1. **Size**: `len(obj) > 262144` bytes -> `V01_OVERSIZE`. Applies to raw
   sealed bytes before any parse or decrypt, on every transport
   (plaintext JSON for local; the `{"n","c"}` wrapper for github).
2. **Parse**: JSON decode of the raw bytes; must be a dict ->
   `V01_DECODE_ERROR`. For github-transport objects, the outer
   `{"n","c"}` wrapper is parsed here; AES-256-GCM decryption with the
   legacy pair key (12-byte nonce, no AAD) happens at step 6, and a
   decryption/auth failure is `V01_DECRYPT_FAILED`, not a decode error.
   Base64 here is standard padded base64, matching v0.1.
3. **Schema**: `v == 1` and exact legacy key set with correct types ->
   `V01_NOT_LEGACY` if `v` is absent or not 1; `V01_FIELDSET_MISMATCH`
   for any other shape problem.
4. **Sender / recipient / pair**: `from` equals the expected legacy peer
   agent id, `to` equals my agent id, `pair` equals the legacy pair id.
   Violations: `V01_SENDER_MISMATCH`, `V01_RECIPIENT_MISMATCH`,
   `V01_PAIR_MISMATCH`. Checked before HMAC so misrouted objects are
   rejected without touching key material.
5. **HMAC**: recompute HMAC-SHA256 over canonical bytes (JSON of envelope
   minus `sig`, `sort_keys=True`, `separators=(",",":")`, UTF-8) with the
   legacy pair key; compare with `hmac.compare_digest` against the hex
   `sig`. Mismatch or missing `sig` -> `V01_HMAC_INVALID`. This is the
   plan's "Verify the legacy HMAC before decryption or adaptation":
   decryption of the `{"n","c"}` wrapper and any adaptation happen only
   after this passes.
6. **Decrypt (remote transports only)**: AES-GCM decrypt the inner
   envelope with the legacy pair key -> `V01_DECRYPT_FAILED` on auth
   failure. The resulting plaintext envelope re-enters validation at
   step 3 (schema) to guard against a validly-encrypted but malformed
   inner object.
7. **Nonce presence**: `nonce` missing or not a non-empty string ->
   `V01_MISSING_NONCE`. This is the plan's "missing nonce rejection";
   v0.1 accepted missing nonces, the adapter must not.
8. **Age window**: `created_at` must parse exactly as
   `%Y-%m-%dT%H:%M:%SZ` -> `V01_BAD_TIMESTAMP` on parse failure. Must be
   within the last 7 days and not more than 1 hour in the future, the
   v0.1 acceptance window -> `V01_STALE` / `V01_FUTURE`. The adapter
   preserves v0.1's window; it does not apply v0.2's 5-minute future
   tolerance to legacy objects.
9. **Replay**: `nonce` (or `id`) already seen for this pair ->
   `V01_REPLAY`. The migration replay store is keyed by the v0.2 rule
   (expire by acceptance window, never by count); the adapter consults
   it but does not own its retention.
10. **Rate policy**: legacy per-peer daily cap (default 5 per UTC day,
    boundary-based, matching v0.1 semantics) exceeded ->
    `V01_RATE_LIMITED`. Accounting uses receive-side counts in the v0.2
    store, never the v0.1 outbox-log or `.state.json`.

## Adaptation (adapt_v01)

Input: a `VerifiedLegacy`. Output: an internal event dict with
`event_type == "message.created"` and `legacy_source == "v0.1"`.

- **Type mapping**: `note`, `link`, `article`, `file-ref` all map to
  `message.created`. The payload `body` is the legacy `body`; the
  payload carries `legacy_title` (legacy `title`) and, for
  `link`/`article`/`file-ref`, `legacy_url` (legacy `url`, empty string
  when absent). No new semantics are invented: a `file-ref` does not
  become an attachment, a `link` does not become a preview.
- **Synthetic event id**: `UUIDv5(pair_id, legacy_event_id)` where
  `legacy_event_id` is the legacy `id` string and `pair_id` is the
  legacy pair id. Deterministic across runs; the same legacy object
  always yields the same synthetic id, so duplicate adaptation is
  idempotent in the v0.2 store.
- **Sender sequence**: assigned by stable filename order via
  `seq_assigner.assign(filename)`. The caller must feed filenames in
  sorted (stable) order across the whole legacy backlog so sequence
  numbers are deterministic; the assignment is stored once (first call
  wins) and returned unchanged on repeat calls for the same filename.
  Sequence space is per (relationship, legacy sender) and does not
  collide with v0.2 `sender_seq` (the migration records the legacy
  mapping separately).
- **Preservation**: the internal event stores the original sealed v0.1
  bytes verbatim and the HMAC verification result. It is NEVER re-signed
  as if the peer sent v0.2; the event is explicitly marked
  `legacy_source="v0.1"` and its `created_at` is the legacy timestamp,
  not a v0.2 claim.
- **Timestamps**: `created_at` is the legacy `created_at` value.
  `received_at` is the adaptation time. No backdated v0.2 claims.

## Error codes (normative)

`LegacyError` carries a stable `code` and a human-readable `detail`
with no secret material. Codes:

- `V01_NOT_LEGACY`: no `v` field, or `v != 1`. Fail closed; do not attempt
  adaptation.
- `V01_FIELDSET_MISMATCH`: wrong key set, extra keys, missing keys, or
  wrong value types.
- `V01_OVERSIZE`: raw sealed bytes exceed 262144 bytes.
- `V01_DECODE_ERROR`: raw bytes are not parseable JSON (or not a dict).
- `V01_DECRYPT_FAILED`: the `{"n","c"}` wrapper failed AES-GCM auth or
  base64 decode (remote transports).
- `V01_SENDER_MISMATCH`, `V01_RECIPIENT_MISMATCH`, `V01_PAIR_MISMATCH`:
  routing fields do not match the expected legacy relationship.
- `V01_HMAC_INVALID`: HMAC verification failed (includes missing `sig`).
- `V01_MISSING_NONCE`: `nonce` absent or empty. v0.1 accepted this; the
  adapter rejects it.
- `V01_BAD_TIMESTAMP`: `created_at` does not match the exact v0.1 format.
- `V01_STALE`: older than 7 days. `V01_FUTURE`: more than 1 hour ahead.
- `V01_REPLAY`: nonce or id already seen.
- `V01_RATE_LIMITED`: legacy daily cap reached.
- `V01_DRAIN_CLOSED`: legacy acceptance is disabled (after the 24-hour
  drain window). See Lifecycle.
- `V01_SENDS_DISABLED`: a local v0.1 send was attempted after the
  cutover commit. See Lifecycle.

Validation errors must expose only the field path and code, never key
material or message content, per the plan's schema error contract.

## Lifecycle: cutover, drain, disable

The adapter itself is stateless about lifecycle; the migration state
machine gates it. The normative transitions the implementer must honor:

1. **Pre-cutover (dual-read)**: both v0.1 and v0.2 objects are accepted.
   v0.1 sends are still allowed locally. New v0.1 arrivals verify and
   adapt through this module.
2. **Cutover commit** (`migration.commit` exchanged): local v0.1 sends
   are rejected immediately with `V01_SENDS_DISABLED`. Legacy read
   acceptance continues for a **24-hour read-only drain window** so
   in-flight v0.1 objects can still arrive and adapt.
3. **Drain expiry**: after 24 hours, legacy acceptance is disabled.
   `verify_v01` raises `V01_DRAIN_CLOSED` for any v0.1 object. The
   adapter code remains for forensic re-verification but accepts nothing.
4. **No downgrade**: if a v0.2 capability is absent on the peer side,
   the sender fails with an explicit `unsupported-capability` result. It
   must not strip expiry, consent, receipts, thread identity, or
   security semantics to fit a v0.1-shaped send. Downgrade-by-omission
   is a protocol violation, not a fallback.

## Key custody

- The legacy pair key lives ONLY in a migration vault (encrypted local
  store, mode 0600, never printed, never logged) from freeze through
  drain-window close plus the rollback window.
- It is NEVER used to derive v0.2 identity or relationship keys. The
  v0.2 key hierarchy (HKDF from a fresh master seed) is independent;
  sharing the legacy key into it would couple the two security domains
  the plan deliberately separates.
- On successful completion (drain closed, no rollback): delete the key,
  the old bundle, and any retained copy of the peer's deploy private key.
  On rollback before commit: the v0.1 key remains authoritative and v0.1
  sends resume; after commit, roll forward only, never resurrect deleted
  keys.

## What the adapter must NOT do

- Never re-sign an adapted event with the v0.2 identity key as if the
  peer authored v0.2 content. Provenance stays `legacy_source="v0.1"`.
- Never accept an object with `v != 1` through the legacy path.
- Never skip HMAC verification before decrypt or adapt, even for
  locally-stored objects.
- Never apply v0.2's 5-minute future tolerance or v0.2 canonicalization
  to legacy objects; v0.1's exact format and window are authoritative.
- Never consult or trust the v0.1 `.state.json` / `relay-state` files
  for security decisions (replay store is rebuilt under v0.2 rules).
- Never read `peers.yaml` `key_hex` directly; the key arrives only via
  the migration vault.

## Acceptance criteria for the implementer

- `detect_v01` returns True for every object `send.py` can emit and False
  for every v0.2 envelope, for the `{"n","c"}` wrapper form, and for
  arbitrary JSON.
- `verify_v01` rejects: oversized raw bytes (>262144) before parse;
  missing `nonce`; `v` absent or not 1; any extra/missing field; wrong
  `type` value; bad HMAC (including flipped bit in `sig` and in `body`);
  wrong `from`/`to`/`pair`; `created_at` 8 days old; `created_at` 2 hours
  in the future; replayed `nonce`; tampered `{"n","c"}` ciphertext.
- `adapt_v01` is deterministic: same legacy object adapted twice yields
  the same synthetic event id (`UUIDv5(pair_id, legacy id)`), the same
  sequence for the same filename, and byte-identical preserved raw bytes.
- Type mapping covers all four legacy types to `message.created` with
  `legacy_source="v0.1"` present.
- Post-cutover: local v0.1 send attempt raises `V01_SENDS_DISABLED`;
  post-drain: any legacy verify raises `V01_DRAIN_CLOSED`.
- The migration rehearsal (plan checkpoint 11) uses a disposable pair to
  prove: cutover, 24-hour drain behavior (simulated clock), rollback
  before commit restores v0.1 sends, and key deletion on success.
