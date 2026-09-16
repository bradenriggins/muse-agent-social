"""V5 regression: replay_nonce records must bind to the envelope they
were first seen with.

Before the fix, replay_guard stored only (nonce, expires_at). A replayed
nonce with different bytes passed the guard: the old row's event_id and
digest were read but never compared, so a sender could reuse a nonce for a
different signed event and have it accepted.
"""

from types import SimpleNamespace

import muse_agent_social.cli as cli_mod
from muse_agent_social.canonical import restricted_jcs
from muse_agent_social.model.events import build_protected, seal_envelope
from muse_agent_social.policy.delivery import set_accepted_receipts_enabled
from muse_agent_social.policy.limits import add_seconds
from muse_agent_social.store.db import utcnow
from support.harness import (
    fresh_db,
    make_agent,
    new_conversation,
    provision_receive_side,
)

RID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def _oname(tag: str) -> str:
    return (tag + "0" * 32)[:32] + ".json"


def _ctx(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    conn = fresh_db(tmp_path / "state.db")
    provision_receive_side(conn, RID, bob, alice)
    set_accepted_receipts_enabled(conn, RID, False)
    cli_mod._ensure_cli_tables(conn)
    ctx = SimpleNamespace(
        conn=conn,
        state_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        identity_id=bob["identity_id"],
    )
    return ctx, conn, alice, bob


def _sealed(alice, bob, rid, conv, seq, nonce, body):
    protected = build_protected(
        relationship_id=rid,
        conversation_id=conv,
        sender_id=alice["identity_id"],
        event_type="message.created",
        thread_id=None,
        reply_to=None,
        key_epoch=1,
    )
    protected["replay_nonce"] = nonce
    protected["sender_seq"] = seq
    envelope = seal_envelope(
        protected,
        {"body": body, "format": "plain"},
        alice["ed_priv"],
        [
            {
                "recipient": bob["identity_id"],
                "agreement_key": bob["rel_pub_mb"],
                "relationship_pub": bob["rel_pub_raw"],
            }
        ],
    )
    return restricted_jcs(envelope), protected


def test_nonce_reuse_with_different_bytes_is_quarantined(tmp_path):
    """Same replay_nonce, different envelope bytes: quarantined, and the
    forged event is not persisted."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    raw_a, prot_a = _sealed(alice, bob, RID, conv, 1, "Tm9uY2UtMDAwMDAwMDAwMQ", "one")
    acc = {"surfaces": 0, "receipts_queued": 0}
    assert cli_mod._receive_object(
        ctx, RID, _oname("rpa"), raw_a, acc)["outcome"] == "accepted"
    # Same nonce, brand-new event_id and bytes: a replay forgery.
    raw_b, _ = _sealed(alice, bob, RID, conv, 2, "Tm9uY2UtMDAwMDAwMDAwMQ", "two")
    outcome = cli_mod._receive_object(ctx, RID, _oname("rpb"), raw_b, acc)
    assert outcome["outcome"] == "quarantined"
    reason = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()["reason"]
    assert reason == "nonce_reuse"
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_byte_identical_redelivery_is_still_idempotent(tmp_path):
    """Redelivering the exact same bytes stays accepted, not a replay."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    raw_a, _ = _sealed(alice, bob, RID, conv, 1, "Tm9uY2UtMDAwMDAwMDAwMg", "one")
    acc = {"surfaces": 0, "receipts_queued": 0}
    assert cli_mod._receive_object(
        ctx, RID, _oname("rpc"), raw_a, acc)["outcome"] == "accepted"
    again = cli_mod._receive_object(ctx, RID, _oname("rpc"), raw_a, acc)
    assert again["outcome"] == "accepted"
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_legacy_unbound_nonce_row_quarantines_loudly(tmp_path):
    """A pre-existing replay_guard row without a bound digest (from the
    old schema) is quarantined, not accepted: exact redeliveries never
    reach the nonce check (the existing-event byte comparison accepts
    them), so anything reusing a legacy nonce is unverifiable."""
    ctx, conn, alice, bob = _ctx(tmp_path)
    conv = new_conversation(conn)
    nonce = "Tm9uY2UtMDAwMDAwMDAwMw"
    conn.execute(
        "INSERT INTO replay_guard(replay_nonce, event_id, envelope_digest,"
        " expires_at) VALUES (?, NULL, NULL, ?)",
        (nonce, add_seconds(utcnow(), 3600)),
    )
    conn.commit()
    raw_a, _ = _sealed(alice, bob, RID, conv, 1, nonce, "legacy claim")
    acc = {"surfaces": 0, "receipts_queued": 0}
    outcome = cli_mod._receive_object(ctx, RID, _oname("rpd"), raw_a, acc)
    assert outcome["outcome"] == "quarantined"
    reason = conn.execute(
        "SELECT reason FROM receive_quarantine"
    ).fetchone()["reason"]
    assert reason == "nonce_reuse"
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
