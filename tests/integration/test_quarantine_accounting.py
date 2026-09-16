"""Gate: quarantine-row accounting under a forged-epoch flood.

Fifty forged envelopes with distinct unknown ``key_epoch`` values go
through the real CLI receive path (``cli._receive_object``), which gates
on ``RotationManager.on_data_event_epoch`` before any cryptographic
work. Each envelope must come back ``retry_pending`` (never accepted),
and the ``rotation_quarantine`` table must stay bounded by the
production cap (50 rows per relationship), not grow without limit.
"""

import os
import types
import uuid
from datetime import datetime, timezone

import pytest

from muse_agent_social.canonical import restricted_jcs
from muse_agent_social.crypto.identity import b64url_encode
from muse_agent_social.crypto.rotation import _ensure_tables as _ensure_rotation_tables
from muse_agent_social.store import db as db_mod
from muse_agent_social.store.migrations import migrate
from muse_agent_social.store.projections import migrate_projections

from support.harness import (
    fresh_db,
    make_agent,
    make_sealed,
    new_conversation,
    provision_receive_side,
)

N_FORGED_EPOCHS = 50
# The production bound (crypto/rotation.py ROTATION_QUARANTINE_CAP): at most
# 50 unknown-epoch rows per relationship, not one per forged epoch without
# limit. Rejected rows older than 30 days are expired by sweep().
QUARANTINE_ROW_CAP = 50


def _resign(envelope: dict, signer) -> bytes:
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    envelope["signature"] = b64url_encode(signer.sign(restricted_jcs(unsigned)))
    return restricted_jcs(envelope)


@pytest.fixture()
def ctx(tmp_path):
    from muse_agent_social.cli import _receive_object  # noqa: F401

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    conn = db_mod.connect(str(state_dir / "state.db"))
    migrate(conn)
    migrate_projections(conn)
    _ensure_rotation_tables(conn)
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    rid = "eeeeeeee-ffff-4000-8000-222222222222"
    provision_receive_side(conn, rid, bob, alice,
                           keys_dir=str(state_dir / "keys"))
    conv = new_conversation(conn)
    from muse_agent_social import cli as cli_mod
    cli_mod._ensure_cli_tables(conn)
    return types.SimpleNamespace(
        conn=conn, state_dir=state_dir, keys_dir=state_dir / "keys",
        alice=alice, bob=bob, rid=rid, conv=conv,
        identity_id=bob["identity_id"],
    )


def _forged_epoch_envelope(ctx, key_epoch: int, seq: int) -> bytes:
    """A schema-valid, correctly signed AND correctly sealed envelope whose
    only lie is the unknown key_epoch (plus fresh ids so each forgery is
    distinct).

    The epoch lie must be sealed in at build time: the seal binds the
    protected headers, so mutating key_epoch after sealing breaks the
    seal's integrity (tampered_wrap) instead of exercising the epoch
    gate. A real hostile peer seals self-consistently and lies in the
    epoch claim, which is what reaches the gate.
    """
    envelope, raw = make_sealed(
        ctx.alice, ctx.bob, ctx.rid, ctx.conv,
        "message.created", {"body": "forged epoch", "format": "plain"},
        seq=seq, key_epoch=key_epoch,
        event_id=str(uuid.uuid4()),
        replay_nonce=b64url_encode(os.urandom(16)),
    )
    return raw


def test_forged_epoch_flood_keeps_quarantine_bounded(ctx):
    from muse_agent_social.cli import _receive_object

    for i, epoch in enumerate(range(2, 2 + N_FORGED_EPOCHS)):
        raw = _forged_epoch_envelope(ctx, epoch, seq=1000 + i)
        name = ("forge%06d" % i + "0" * 32)[:32] + ".json"
        outcome = _receive_object(ctx, ctx.rid, name, raw, {})
        assert outcome["outcome"] == "retry_pending", (epoch, outcome)
    count = ctx.conn.execute(
        "SELECT COUNT(*) FROM rotation_quarantine WHERE relationship_id = ?",
        (ctx.rid,),
    ).fetchone()[0]
    assert count <= QUARANTINE_ROW_CAP, (
        "rotation_quarantine grew to %d rows for %d forged epochs; "
        "it must stay bounded" % (count, N_FORGED_EPOCHS)
    )
    # Nothing was accepted or stored as an event.
    assert ctx.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
