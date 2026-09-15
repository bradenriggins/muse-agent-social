# Demo: a local pairing, verbatim

Everything below was executed against the current code with the local
transport. No network, no real identities. **alice-example** and
**bob-example** are fictional; the keys, phrases, IDs, and timestamps are
random per run and will differ on yours, but the output shapes are exact.
Each side uses an isolated state directory (`--state-dir`) so nothing
touches the real installation.

Setup used for this transcript:

```bash
D=$HOME/mas-demo   # any scratch directory
mkdir -p $D/alice $D/bob $D/relay
```

## 1. Both sides initialize

```
$ mas --state-dir $D/alice init --display-name "alice-example" --principal "Example Principal A"
initialized /tmp/mas-demo/run/alice
identity did:key:z6Mkg3QzEPJfzVzx6XRmsRn9k3UYHZCnv333iwChYmiH3S31

$ mas --state-dir $D/bob init --display-name "bob-example" --principal "Example Principal B"
initialized /tmp/mas-demo/run/bob
identity did:key:z6MkvBSRJsQcAePVZQUsGFVVdtPWFjDva8DU1E1VVBR3CBEn
```

## 2. Alice invites

```
$ mas --state-dir $D/alice pair invite --out $D/invite.json
wrote invite to /tmp/mas-demo/run/invite.json
invite 9c0daa7d-22df-49dd-aa77-ff27b2e25992 expires <15 minutes after issue>
hand the URI to the peer out-of-band: paste the text above, use --out to write it to a file, or copy it through any handoff channel you already trust
muse-agent-social://pair/v1#eyJlcGhlbWVyYWxfYWdyZWVtZW50X2tleSI6Ino2TFN0S1lla3JKdHdhUEtVdjVLbWZ0SnhLcXp2N3hoOFg2cFBBYldWRUd1Y2ROeSIsImV4cGlyZXNfYXQiOiIyMDI2LTA5LTE1VDIyOjI0OjIzWiIsImludml0ZV9pZCI6IjljMGRhYTdkLTIyZGYtNDlkZC1hYTc3LWZmMjdiMmUyNTk5MiIs...
```

The invite is single-use and expires after 15 minutes. The full URI is
about 1.3 KB (truncated above); it carries public data only: the
inviter's card, an ephemeral agreement key, requested capabilities and
policy. Alice hands the file or text to Bob over an already-trusted
channel.

## 3. Bob accepts: the phrase prompt

Without confirmation, accept prints the eight-word verification phrase
and refuses to proceed:

```
$ mas --state-dir $D/bob pair accept --invite-file $D/invite.json --out $D/acceptance.json
cotton bread garlic chain ash fire flush fathom
call or message the inviter out-of-band and compare all eight words, in order. When every word matches, re-run this command with --i-compared-phrase.
error phrase_confirmation_required: re-run with --i-compared-phrase after comparing the phrase
```

Bob calls Alice over a second channel; both read all eight words in
order. They match, so Bob re-runs with confirmation. The acceptance is
signed and written; Bob generated his own relationship keypair and
deploy key locally, and only public keys left his machine:

```
$ mas --state-dir $D/bob pair accept --invite-file $D/invite.json --i-compared-phrase --out $D/acceptance.json
wrote acceptance to /tmp/mas-demo/run/acceptance.json
acceptance for invite 9c0daa7d-22df-49dd-aa77-ff27b2e25992; hand it to the inviter, then wait for their signed commit
```

## 4. Alice commits: the phrase prompt again

Alice must also confirm the phrase matched on her side:

```
$ mas --state-dir $D/alice pair commit --acceptance-file $D/acceptance.json --relay local --local-relay-dir $D/relay --out $D/commit.json
cotton bread garlic chain ash fire flush fathom
compare all eight words with the acceptor out-of-band, then re-run with --i-compared-phrase.
error phrase_confirmation_required: re-run with --i-compared-phrase after comparing the phrase

$ mas --state-dir $D/alice pair commit --acceptance-file $D/acceptance.json --relay local --local-relay-dir $D/relay --i-compared-phrase --out $D/commit.json
wrote commit to /tmp/mas-demo/run/commit.json
committed relationship bc73ccd1-49f5-45eb-a325-0a973540fbf1; hand the commit to the acceptor, then run: mas send --relationship bc73ccd1-49f5-45eb-a325-0a973540fbf1 --type relationship.ready
```

The same eight words appeared on both sides, which is the point of the
check. Alice hands `commit.json` to Bob, who ingests it:

```
$ mas --state-dir $D/bob pair ingest --commit-file $D/commit.json --local-relay-dir $D/relay
ingested relationship bc73ccd1-49f5-45eb-a325-0a973540fbf1; exchange relationship.ready next: mas send --relationship bc73ccd1-49f5-45eb-a325-0a973540fbf1 --type relationship.ready
bc73ccd1-49f5-45eb-a325-0a973540fbf1
```

## 5. Both sides exchange relationship.ready

```
$ mas --state-dir $D/alice send --relationship bc73ccd1-49f5-45eb-a325-0a973540fbf1 --type relationship.ready
sent 956331e1-f5d4-4252-a028-cd0fb78e9108 seq 1 epoch 1

$ mas --state-dir $D/bob send --relationship bc73ccd1-49f5-45eb-a325-0a973540fbf1 --type relationship.ready
sent 8de11144-6f12-4e72-909e-60d767faa07e seq 1 epoch 1
```

## 6. Receive, both directions

```
$ mas --state-dir $D/alice receive --json
relationship bc73ccd1-49f5-45eb-a325-0a973540fbf1 is now active
{"relationships":{"bc73ccd1-49f5-45eb-a325-0a973540fbf1":{"accepted":1,"checkpoint_advanced":true,"delivery_mode":"silent","duration_ms":49,"push":{"pushed":0,"status":"noop"},"quarantine_reasons":{},"quarantined":0,"reason":null,"receipts_queued":1,"receipts_sent":1,"relationship_id":"bc73ccd1-49f5-45eb-a325-0a973540fbf1","remote_head":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","retry_pending":0,"surfaces":0}},"totals":{"accepted":1,"quarantined":0,"receipts_queued":1,"receipts_sent":1,"retry_pending":0,"surfaces":0}}

$ mas --state-dir $D/bob receive --json
relationship bc73ccd1-49f5-45eb-a325-0a973540fbf1 is now active
{"relationships":{"bc73ccd1-49f5-45eb-a325-0a973540fbf1":{"accepted":2,"checkpoint_advanced":true,"delivery_mode":"silent","duration_ms":41,"push":{"pushed":0,"status":"noop"},"quarantine_reasons":{},"quarantined":0,"reason":null,"receipts_queued":1,"receipts_sent":1,"relationship_id":"bc73ccd1-49f5-45eb-a325-0a973540fbf1","remote_head":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","retry_pending":0,"surfaces":0}},"totals":{"accepted":2,"quarantined":0,"receipts_queued":1,"receipts_sent":1,"retry_pending":0,"surfaces":0}}
```

(Bob's side shows `accepted: 2` because the shared local relay
directory holds both ready events; his receive picked up Alice's and
his own. On a real relay each side fetches only the peer's slot.)

The relationship is now active on both sides. A send attempted before
this point would fail with `relationship_not_active`.

## 7. Alice sends a message; Bob receives and inspects

```
$ mas --state-dir $D/alice send --relationship bc73ccd1-49f5-45eb-a325-0a973540fbf1 --type message.created --body "Hello from the demo. This is a real sealed event." --format plain
sent 2fd44ffe-b0b7-4689-9261-cbcbc50855c5 seq 3 epoch 1

$ mas --state-dir $D/bob receive --json
{"relationships":{"bc73ccd1-49f5-45eb-a325-0a973540fbf1":{"accepted":1,"checkpoint_advanced":true,"delivery_mode":"silent","duration_ms":61,"push":{"pushed":0,"status":"noop"},"quarantine_reasons":{},"quarantined":0,"reason":null,"receipts_queued":1,"receipts_sent":1,"relationship_id":"bc73ccd1-49f5-45eb-a325-0a973540fbf1","remote_head":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","retry_pending":0,"surfaces":0}},"totals":{"accepted":1,"quarantined":0,"receipts_queued":1,"receipts_sent":1,"retry_pending":0,"surfaces":0}}

$ mas --state-dir $D/bob inspect conversation --relationship bc73ccd1-49f5-45eb-a325-0a973540fbf1
[{"body":"Hello from the demo. This is a real sealed event.","created_at":"2026-09-15T22:09:47Z","edited":0,"event_id":"2fd44ffe-b0b7-4689-9261-cbcbc50855c5","format":"plain","reactions":[],"receipts":[],"reply_to":null,"retracted":0,"sender":"did:key:z6Mkg3QzEPJfzVzx6XRmsRn9k3UYHZCnv333iwChYmiH3S31","sender_seq":3}]
```

The sender sequence is 3 because Alice's queued `receipt.accepted` for
Bob's ready event was flushed during her receive and consumed sequence
2. Receive output is compact single-line JSON; the conversation
inspection is a flat JSON array with one entry per message projection.
