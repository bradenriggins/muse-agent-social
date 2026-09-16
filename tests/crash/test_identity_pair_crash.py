"""D2 regression: the identity seed/card pair publish is crash-safe.

atomic_write_pair stages both files fully, commits via a durable journal,
then renames back to back. A crash at any window must leave either the old
pair or the new pair, never a torn one; recover_pending_pair converges the
pending publish at the next startup.
"""

from __future__ import annotations

import json
import os

import pytest

from muse_agent_social._keyfiles import atomic_write_pair, recover_pending_pair


class Crash(Exception):
    """Simulated kill at a chosen window of the pair publish."""


OLD_SEED = b"old-seed" + b"\x00" * 24
NEW_SEED = b"new-seed" + b"\x01" * 24
OLD_CARD = b'{"identity_id": "old-id"}\n'
NEW_CARD = b'{"identity_id": "new-id"}\n'


def _paths(tmp_path):
    seed = tmp_path / "keys" / "master.seed"
    card = tmp_path / "agent-card.json"
    journal = tmp_path / ".pending-identity-pair.json"
    seed.parent.mkdir(parents=True, exist_ok=True)
    seed.write_bytes(OLD_SEED)
    card.write_bytes(OLD_CARD)
    return seed, card, journal


def _kill_at(monkeypatch, predicate):
    real_replace = os.replace

    def _replace(src, dst):
        if predicate(src, dst):
            raise Crash(f"kill at {dst}")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _replace)


def _publish(seed, card, journal):
    return atomic_write_pair(
        seed,
        NEW_SEED,
        0o600,
        card,
        NEW_CARD,
        0o644,
        journal_path=journal,
    )


def test_crash_before_journal_commit_leaves_old_pair(tmp_path, monkeypatch):
    """Kill at the journal publish: the old pair is untouched, no journal
    exists, and recovery is a no-op."""
    seed, card, journal = _paths(tmp_path)
    _kill_at(
        monkeypatch,
        lambda src, dst: os.path.abspath(dst)
        == os.path.abspath(str(journal)),
    )
    with pytest.raises(Crash):
        _publish(seed, card, journal)
    monkeypatch.undo()
    assert not journal.exists()
    assert recover_pending_pair(journal) is False
    assert seed.read_bytes() == OLD_SEED
    assert card.read_bytes() == OLD_CARD


def test_crash_between_journal_and_renames_recovers_new_pair(
    tmp_path, monkeypatch
):
    """Kill after the journal commit but before any rename: the old files
    are still in place, the journal survives, and recovery publishes the
    new pair."""
    seed, card, journal = _paths(tmp_path)
    _kill_at(
        monkeypatch,
        lambda src, dst: os.path.abspath(dst)
        == os.path.abspath(str(seed)),
    )
    with pytest.raises(Crash):
        _publish(seed, card, journal)
    monkeypatch.undo()
    assert journal.exists()
    assert seed.read_bytes() == OLD_SEED
    assert card.read_bytes() == OLD_CARD
    assert recover_pending_pair(journal) is True
    assert seed.read_bytes() == NEW_SEED
    assert card.read_bytes() == NEW_CARD
    assert not journal.exists()


def test_crash_between_renames_recovers_new_pair(tmp_path, monkeypatch):
    """Kill between the two renames: the seed is new, the card is old (the
    torn state the design exists to repair). Recovery converges to the new
    pair."""
    seed, card, journal = _paths(tmp_path)
    _kill_at(
        monkeypatch,
        lambda src, dst: os.path.abspath(dst)
        == os.path.abspath(str(card)),
    )
    with pytest.raises(Crash):
        _publish(seed, card, journal)
    monkeypatch.undo()
    # The torn window the journal exists to repair.
    assert seed.read_bytes() == NEW_SEED
    assert card.read_bytes() == OLD_CARD
    assert journal.exists()
    assert recover_pending_pair(journal) is True
    assert seed.read_bytes() == NEW_SEED
    assert card.read_bytes() == NEW_CARD
    assert not journal.exists()


def test_crash_after_renames_recovery_is_idempotent(tmp_path, monkeypatch):
    """Kill after both renames but before the journal unlink: both files
    are already new, and recovery only removes the leftover journal."""
    seed, card, journal = _paths(tmp_path)
    real_unlink = os.unlink

    def _unlink(path):
        if os.path.abspath(path) == os.path.abspath(str(journal)):
            raise Crash("kill at journal unlink")
        return real_unlink(path)

    monkeypatch.setattr(os, "unlink", _unlink)
    with pytest.raises(Crash):
        _publish(seed, card, journal)
    monkeypatch.undo()
    assert seed.read_bytes() == NEW_SEED
    assert card.read_bytes() == NEW_CARD
    assert journal.exists()
    assert recover_pending_pair(journal) is True
    assert seed.read_bytes() == NEW_SEED
    assert card.read_bytes() == NEW_CARD
    assert not journal.exists()


def test_recovery_refuses_unparseable_journal(tmp_path):
    """A journal that cannot be parsed fails loudly instead of being
    silently ignored."""
    from muse_agent_social._keyfiles import KeyFileError

    journal = tmp_path / ".pending-identity-pair.json"
    journal.write_bytes(b"not json{{{")
    with pytest.raises(KeyFileError):
        recover_pending_pair(journal)


# ---------------------------------------------------------------------------
# D2: startup refuses a torn identity (seed/card mismatch).
# ---------------------------------------------------------------------------


def test_ctx_rejects_seed_card_identity_mismatch(tmp_path):
    """D2: a valid self-signed card for a DIFFERENT identity than the
    master seed derives fails closed with identity_mismatch instead of
    running as the wrong identity."""
    from types import SimpleNamespace

    import muse_agent_social.cli as cli_mod
    from muse_agent_social.crypto.identity import (
        derive_identity_hierarchy,
        generate_master_seed,
    )
    from muse_agent_social.model.cards import create_card
    from muse_agent_social.policy.limits import add_seconds
    from muse_agent_social.store.db import utcnow

    sd = tmp_path / "state"
    cli_mod.cmd_init(
        SimpleNamespace(
            state_dir=str(sd),
            display_name=None,
            principal=None,
            capability=None,
        )
    )
    # A second, fully valid identity and its self-signed card.
    hier2 = derive_identity_hierarchy(generate_master_seed())
    now = utcnow()
    card2 = create_card(
        hier2.ed25519_private,
        display_name="Other Agent",
        principal_label="operator",
        agreement_pub_multibase=hier2.agreement_key_multibase,
        capabilities=["chat"],
        issued_at=now,
        expires_at=add_seconds(now, 365 * 24 * 3600),
    )
    (sd / "agent-card.json").write_text(
        cli_mod._canon_text(card2) + "\n", encoding="utf-8"
    )
    with pytest.raises(cli_mod.CliError) as excinfo:
        cli_mod.Ctx(sd)
    assert excinfo.value.code == "identity_mismatch"


def test_ctx_accepts_matching_seed_and_card(tmp_path):
    """D2 control: the untouched init installation loads cleanly."""
    from types import SimpleNamespace

    import muse_agent_social.cli as cli_mod

    sd = tmp_path / "state"
    cli_mod.cmd_init(
        SimpleNamespace(
            state_dir=str(sd),
            display_name=None,
            principal=None,
            capability=None,
        )
    )
    ctx = cli_mod.Ctx(sd)
    assert ctx.identity_id == ctx.hierarchy.identity_id
    ctx.close()
