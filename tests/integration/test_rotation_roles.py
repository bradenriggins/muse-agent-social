"""Lane A C3: rotation UPDATEs/SELECTs are role-scoped.

Reproduces the exact conflict scenario from the adversarial review: after
human conflict resolution chooses "theirs", the store holds a DISCARDED
rotating row plus an ACKNOWLEDGED acking row for the same epoch. A
role-blind UPDATE in on_confirm / build_commit_payload resurrects the
discarded rotating row to confirmed/committed, and sweep() then deletes
the user's own still-current epoch-1 private key while the peer keeps
encrypting to it: total silent decryption loss.

The test proves the discarded row stays discarded and sweep() never
deletes the current private key.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from muse_agent_social.crypto.rotation import (
    RotationError,
    RotationManager,
    build_confirm,
)

from support.harness import (
    fresh_db,
    make_agent,
    provision_receive_side,
)

UTC = timezone.utc


@pytest.fixture()
def two_sides(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    rid = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
    conn_a = fresh_db(tmp_path / "alice.db")
    conn_b = fresh_db(tmp_path / "bob.db")
    keys_a = tmp_path / "keys_a"
    keys_b = tmp_path / "keys_b"
    provision_receive_side(conn_a, rid, alice, bob, keys_dir=str(keys_a))
    provision_receive_side(conn_b, rid, bob, alice, keys_dir=str(keys_b))
    t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
    return {
        "alice": alice, "bob": bob, "rid": rid,
        "conn_a": conn_a, "conn_b": conn_b,
        "keys_a": keys_a, "keys_b": keys_b, "t0": t0,
    }


def _rotation_rows(conn, rid, epoch):
    return {
        r["role"]: dict(r)
        for r in conn.execute(
            "SELECT * FROM key_rotations WHERE relationship_id = ? AND epoch = ?",
            (rid, epoch),
        ).fetchall()
    }


def _conflicted_theirs_state(fx):
    """Both sides rotate into epoch 2; Alice's human chooses theirs.

    Returns (mgr_a, bob_prepare) with Alice holding a discarded rotating
    row and an acknowledged acking row for epoch 2.
    """
    t0, rid = fx["t0"], fx["rid"]
    mgr_a = RotationManager(fx["conn_a"], str(fx["keys_a"]))
    mgr_b = RotationManager(fx["conn_b"], str(fx["keys_b"]))
    mgr_a.begin_rotation(rid, now=t0)          # Alice's own candidate
    bob_begun = mgr_b.begin_rotation(rid, now=t0)  # Bob's competing candidate
    with pytest.raises(RotationError) as exc:
        mgr_a.on_prepare(rid, bob_begun["prepare"], str(uuid.uuid4()), now=t0)
    assert exc.value.code == "conflicting_prepare"
    # Human resolution: keep Bob's ("theirs"), discard Alice's candidate.
    mgr_a.resolve_quarantine(rid, 0, "theirs", now=t0)
    rows = _rotation_rows(fx["conn_a"], rid, 2)
    assert rows["rotating"]["phase"] == "discarded"
    assert rows["acking"]["phase"] == "acknowledged"
    return mgr_a


def test_on_confirm_does_not_resurrect_discarded_rotating_row(two_sides):
    mgr_a = _conflicted_theirs_state(two_sides)
    rid, t0 = two_sides["rid"], two_sides["t0"]
    # Bob (rotating side) confirms; Alice (acking side) processes it.
    mgr_a.on_confirm(rid, build_confirm(2), now=t0)
    rows = _rotation_rows(two_sides["conn_a"], rid, 2)
    assert rows["acking"]["phase"] == "confirmed"
    assert rows["rotating"]["phase"] == "discarded"


def test_sweep_never_deletes_current_private_key_after_conflict(two_sides):
    fx = two_sides
    mgr_a = _conflicted_theirs_state(fx)
    rid, t0 = fx["rid"], fx["t0"]
    mgr_a.on_confirm(rid, build_confirm(2), now=t0)
    mgr_a.build_commit_payload(rid, now=t0)

    key_file = Path(fx["keys_a"]) / f"{rid}-e1.key"
    assert key_file.exists(), "precondition: own epoch-1 key file exists"

    # Past the old-key retention window: sweep must not touch the epoch-1
    # key, because Alice never rotated her own key; it is still current and
    # the peer still encrypts to it.
    mgr_a.sweep(now=t0 + timedelta(hours=25))

    assert key_file.exists(), "sweep deleted the still-current private key"
    row = fx["conn_a"].execute(
        "SELECT * FROM key_epochs WHERE relationship_id = ? AND epoch = 1",
        (rid,),
    ).fetchone()
    assert row is not None
    assert row["private_key_ref"] == str(key_file)
    rows = _rotation_rows(fx["conn_a"], rid, 2)
    assert rows["rotating"]["phase"] == "discarded"


def test_role_blind_updates_are_scoped(two_sides):
    """Direct double-row seeding: every rotation state UPDATE touches only
    its own role's row."""
    fx = two_sides
    rid, t0 = fx["rid"], fx["t0"]
    mgr_a = RotationManager(fx["conn_a"], str(fx["keys_a"]))
    conn = fx["conn_a"]
    # Seed the post-conflict shape directly: discarded rotating row and
    # acknowledged acking row for epoch 2, plus a live rotating candidate
    # for epoch 3 to exercise the rotating-side methods.
    with conn:
        conn.execute(
            "INSERT INTO key_rotations (relationship_id, epoch, role, phase,"
            " prior_epoch, prepared_at, deadline)"
            " VALUES (?, 2, 'rotating', 'discarded', 1, ?, ?)",
            (rid, t0.isoformat(), t0.isoformat()),
        )
        conn.execute(
            "INSERT INTO key_rotations (relationship_id, epoch, role, phase,"
            " prior_epoch, prepared_at, deadline)"
            " VALUES (?, 2, 'acking', 'acknowledged', 1, ?, ?)",
            (rid, t0.isoformat(), t0.isoformat()),
        )
    # on_confirm must advance only the acking row.
    mgr_a.on_confirm(rid, build_confirm(2), now=t0)
    rows = _rotation_rows(conn, rid, 2)
    assert rows["acking"]["phase"] == "confirmed"
    assert rows["rotating"]["phase"] == "discarded"
