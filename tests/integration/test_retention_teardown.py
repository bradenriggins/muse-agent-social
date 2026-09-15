"""Gate: Retention and teardown.

Plaintext-cache opt-in with named periods (aliases canonicalize),
writes require an active opt-in, expiry purges timed files, immediate
deletion removes the cache and clears the opt-in, retention_scan flags
unexpected plaintext, and teardown_relationship leaves no residual
traces (postcheck_scan empty).
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from muse_agent_social.policy.limits import format_canonical_utc
from muse_agent_social.policy.retention import (
    RetentionError,
    delete_plaintext_cache,
    plaintext_cache_status,
    purge_expired_plaintext_cache,
    read_plaintext_cache,
    retention_scan,
    set_plaintext_cache,
    write_plaintext_cache,
)
from muse_agent_social.teardown import (
    TeardownError,
    postcheck_scan,
    teardown_relationship,
)

from support.harness import fresh_db, make_agent, provision_receive_side

UTC = timezone.utc


@pytest.fixture()
def ctx(tmp_path):
    alice = make_agent("Alice", "PrincipalA")
    bob = make_agent("Bob", "PrincipalB")
    # The DB file must live directly inside the state dir: retention
    # resolves the state dir from the DB path.
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    conn = fresh_db(state_dir / "state.db")
    rid = "eeeeeeee-5555-4666-8777-888888888888"
    provision_receive_side(conn, rid, bob, alice)
    return {"conn": conn, "rid": rid, "state_dir": state_dir}


# -- named periods ----------------------------------------------------------------------


def test_named_periods_and_aliases(ctx):
    conn, rid = ctx["conn"], ctx["rid"]
    rec = set_plaintext_cache(conn, rid, "week")
    assert rec["period"] == "7d"
    assert rec["expires_at"] is not None
    rec = set_plaintext_cache(conn, rid, "forever")
    assert rec["period"] == "indefinite"
    assert rec["expires_at"] is None


def test_invalid_period_rejected(ctx):
    with pytest.raises(RetentionError) as exc:
        set_plaintext_cache(ctx["conn"], ctx["rid"], "fortnight")
    assert exc.value.code == "invalid_period"


def test_status_reflects_expiry(ctx):
    conn, rid = ctx["conn"], ctx["rid"]
    set_plaintext_cache(conn, rid, "1d")
    assert plaintext_cache_status(conn, rid)["enabled"] is True
    future = format_canonical_utc(
        datetime.now(UTC) + timedelta(days=2)
    )
    status = plaintext_cache_status(conn, rid, now=future)
    assert status["enabled"] is False


# -- writes require opt-in ------------------------------------------------------------------


def test_write_requires_active_opt_in(ctx):
    conn, rid = ctx["conn"], ctx["rid"]
    with pytest.raises(RetentionError) as exc:
        write_plaintext_cache(conn, rid, str(uuid.uuid4()), b"secret")
    assert exc.value.code == "plaintext_cache_not_enabled"


def test_write_and_read_round_trip(ctx):
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    set_plaintext_cache(conn, rid, "7d")
    event_id = str(uuid.uuid4())
    path = write_plaintext_cache(conn, rid, event_id, b'{"body": "x"}')
    assert path.parent == state_dir / "plaintext_cache" / rid
    assert read_plaintext_cache(conn, rid, event_id) == b'{"body": "x"}'
    # Permissions: dir 0700, file 0600.
    assert (path.stat().st_mode & 0o777) == 0o600
    assert (path.parent.stat().st_mode & 0o777) == 0o700


def test_write_after_expiry_rejected(ctx):
    conn, rid = ctx["conn"], ctx["rid"]
    set_plaintext_cache(conn, rid, "1d")
    future = format_canonical_utc(datetime.now(UTC) + timedelta(days=2))
    with pytest.raises(RetentionError) as exc:
        write_plaintext_cache(conn, rid, str(uuid.uuid4()), b"x", now=future)
    assert exc.value.code == "plaintext_cache_not_enabled"


# -- purge and delete ------------------------------------------------------------------------------


def test_purge_expired_removes_timed_cache(ctx):
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    set_plaintext_cache(conn, rid, "1d")
    event_id = str(uuid.uuid4())
    write_plaintext_cache(conn, rid, event_id, b"data")
    assert (state_dir / "plaintext_cache" / rid / f"{event_id}.json").exists()
    future = format_canonical_utc(datetime.now(UTC) + timedelta(days=2))
    removed = purge_expired_plaintext_cache(conn, state_dir, now=future)
    assert removed >= 1
    assert not (state_dir / "plaintext_cache" / rid).exists()


def test_purge_keeps_unexpired_cache(ctx):
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    set_plaintext_cache(conn, rid, "30d")
    event_id = str(uuid.uuid4())
    write_plaintext_cache(conn, rid, event_id, b"data")
    removed = purge_expired_plaintext_cache(conn, state_dir)
    assert removed == 0
    assert (state_dir / "plaintext_cache" / rid / f"{event_id}.json").exists()


def test_delete_plaintext_cache_immediate(ctx):
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    set_plaintext_cache(conn, rid, "indefinite")
    write_plaintext_cache(conn, rid, str(uuid.uuid4()), b"a")
    write_plaintext_cache(conn, rid, str(uuid.uuid4()), b"b")
    # Two payload files plus the optin.json manifest.
    removed = delete_plaintext_cache(conn, rid)
    assert removed == 3
    assert not (state_dir / "plaintext_cache" / rid).exists()
    assert plaintext_cache_status(conn, rid)["enabled"] is False


# -- retention scan -------------------------------------------------------------------------------------


def test_retention_scan_flags_stray_plaintext(ctx):
    state_dir = ctx["state_dir"]
    inbox = state_dir / "inbox"
    inbox.mkdir()
    stray = inbox / "note.txt"
    stray.write_text("should not be here")
    findings = retention_scan(state_dir)
    assert any(f["path"] == str(stray.resolve()) for f in findings)


def test_retention_scan_clean_after_delete(ctx):
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    set_plaintext_cache(conn, rid, "7d")
    write_plaintext_cache(conn, rid, str(uuid.uuid4()), b"data")
    delete_plaintext_cache(conn, rid)
    assert retention_scan(state_dir) == []


# -- teardown ----------------------------------------------------------------------------------------------

# Historical note: teardown_relationship once left plaintext_cache behind
# (defect D5 in the adversarial report). Fixed by adding 'plaintext_cache'
# to _OPERATIONAL_DIRS; the test below proves the postcheck is clean.


def test_teardown_unknown_relationship_rejected(ctx):
    with pytest.raises(TeardownError):
        teardown_relationship(
            ctx["conn"], ctx["state_dir"],
            "00000000-0000-4000-8000-000000000000",
        )


def test_teardown_dry_run_changes_nothing(ctx):
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    set_plaintext_cache(conn, rid, "indefinite")
    write_plaintext_cache(conn, rid, str(uuid.uuid4()), b"data")
    report = teardown_relationship(
        conn, state_dir, rid, dry_run=True, peer_label="Bob",
    )
    assert report.dry_run is True
    # Relationship row still present; cache files still present.
    assert conn.execute(
        "SELECT COUNT(*) FROM relationships WHERE relationship_id = ?",
        (rid,),
    ).fetchone()[0] == 1
    assert (state_dir / "plaintext_cache" / rid).exists()


def test_teardown_removes_traces_and_postcheck_clean(ctx):
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    set_plaintext_cache(conn, rid, "indefinite")
    write_plaintext_cache(conn, rid, str(uuid.uuid4()), b"data")
    report = teardown_relationship(
        conn, state_dir, rid, peer_label="Bob",
    )
    assert report.dry_run is False
    assert conn.execute(
        "SELECT COUNT(*) FROM relationships WHERE relationship_id = ?",
        (rid,),
    ).fetchone()[0] == 0
    assert not (state_dir / "plaintext_cache" / rid).exists()
    scan = postcheck_scan(state_dir, rid, peer_label="Bob")
    assert scan["hits"] == []


def test_teardown_without_cache_leaves_no_traces(ctx):
    """Teardown of a relationship with no plaintext cache completes and
    the postcheck is clean: the defect above is cache-specific."""
    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    report = teardown_relationship(conn, state_dir, rid, peer_label="Bob")
    assert report.dry_run is False
    assert report.postcheck_hits == []
    scan = postcheck_scan(state_dir, rid, peer_label="Bob")
    assert scan["hits"] == []


def test_teardown_requires_hooks_when_deploy_keys_present(ctx):
    import json

    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    (state_dir / "relay.json").write_text(json.dumps({
        "deploy_keys": [
            {"repo": "bradenriggins/muse-agent-social-pair-x",
             "label": "relay", "key_id": "123"},
        ],
        "repos": ["bradenriggins/muse-agent-social-pair-x"],
    }))
    with pytest.raises(TeardownError) as exc:
        teardown_relationship(conn, state_dir, rid)
    assert exc.value.code == "hook-required"
    # Nothing was torn down: fail-fast before mutation.
    assert conn.execute(
        "SELECT COUNT(*) FROM relationships WHERE relationship_id = ?",
        (rid,),
    ).fetchone()[0] == 1


def test_teardown_revokes_remote_resources_via_hooks(ctx):
    import json

    from muse_agent_social.teardown import TeardownHooks

    conn, rid, state_dir = ctx["conn"], ctx["rid"], ctx["state_dir"]
    (state_dir / "relay.json").write_text(json.dumps({
        "deploy_keys": [
            {"repo": "bradenriggins/muse-agent-social-pair-x",
             "label": "relay", "key_id": "123"},
        ],
        "repos": ["bradenriggins/muse-agent-social-pair-x"],
    }))
    revoked, deleted = [], []
    hooks = TeardownHooks(
        revoke_deploy_key=lambda ref: revoked.append(ref.key_id),
        delete_relay_repo=lambda ref: deleted.append(ref.repo),
    )
    report = teardown_relationship(
        conn, state_dir, rid, hooks=hooks, reason_code="operator",
    )
    assert revoked == ["123"]
    assert deleted == ["bradenriggins/muse-agent-social-pair-x"]
    assert report.reason_code == "operator"
    assert report.relationship_id_sha256 != rid  # tombstone hashes the id
    assert not (state_dir / "relay.json").exists()
