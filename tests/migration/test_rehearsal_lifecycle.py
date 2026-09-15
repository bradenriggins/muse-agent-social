"""Gate: Migration rehearsal and v0.1 compatibility.

migrate.rehearse(work_root) migrates a disposable local pair twice:
scenario A (stage, verify, rollback before commit: v0.1 sends restored,
legacy key retained, backlog counts intact) and scenario B (stage,
verify, cutover: v0.1 sends disabled, vault key deleted, drain window
closes legacy reads). The function self-asserts; this file also pins
the v0.1 compatibility surface it exercises: legacy send gating and
legacy verification after drain closes.
"""

from muse_agent_social.compatibility.v01 import (
    LegacyError,
    LegacyPolicy,
    assert_legacy_sends_allowed,
    verify_v01,
)
from muse_agent_social.migrate import rehearse


def test_rehearse_full_lifecycle(tmp_path):
    report = rehearse(tmp_path / "work")
    assert report["ok"] is True
    scenario_a = report["scenarios"]["a_rollback"]
    assert scenario_a["ok"] is True
    assert scenario_a["backlog"] == 6
    assert scenario_a["adapted"] == 6
    assert scenario_a["v01_sends_restored"] is True
    scenario_b = report["scenarios"]["b_commit_drain"]
    assert scenario_b["ok"] is True
    assert scenario_b["vault_key_deleted"] is True
    assert scenario_b["legacy_read_closed"] is True
    assert scenario_b["drain_until"]


def test_rehearse_leaves_no_trace_of_live_state(tmp_path):
    """The rehearsal uses only fictional identities and fresh random keys;
    nothing is written outside work_root."""
    work = tmp_path / "work"
    report = rehearse(work)
    assert report["ok"] is True
    names = [p.name for p in work.rglob("*") if p.is_file()]
    assert names, "rehearsal should produce files under work_root"
    for path in work.rglob("*"):
        data = path.read_bytes() if path.is_file() else b""
        assert b"braden" not in data.lower()
        assert b"hermes" not in data.lower()


def test_legacy_sends_gated_by_policy():
    policy = LegacyPolicy(
        pair_id="pair-rehearsal-x",
        expected_sender="agent:rehearsal-bob:x",
        my_agent_id="agent:rehearsal-alice:x",
        legacy_sends_allowed=False,
    )
    try:
        assert_legacy_sends_allowed(policy)
        raise AssertionError("expected LegacyError")
    except LegacyError as exc:
        assert exc.code == "V01_SENDS_DISABLED"


def test_legacy_verify_rejects_garbage():
    policy = LegacyPolicy(
        pair_id="pair-rehearsal-x",
        expected_sender="agent:rehearsal-bob:x",
        my_agent_id="agent:rehearsal-alice:x",
    )
    try:
        verify_v01(b"not a legacy envelope", b"\x00" * 32, policy=policy)
        raise AssertionError("expected LegacyError")
    except LegacyError:
        pass


def test_legacy_verify_closed_after_drain():
    policy = LegacyPolicy(
        pair_id="pair-rehearsal-x",
        expected_sender="agent:rehearsal-bob:x",
        my_agent_id="agent:rehearsal-alice:x",
        legacy_read_open=False,
    )
    try:
        verify_v01(b"{}", b"\x00" * 32, policy=policy)
        raise AssertionError("expected LegacyError")
    except LegacyError as exc:
        assert exc.code == "V01_DRAIN_CLOSED"


def test_unknown_capability_refuses_downgrade():
    from muse_agent_social.compatibility.v01 import (
        UnsupportedCapabilityError,
        require_capability,
    )

    require_capability("chat", ["chat", "receipts"])
    try:
        require_capability("threads", ["chat"])
        raise AssertionError("expected UnsupportedCapabilityError")
    except UnsupportedCapabilityError as exc:
        assert exc.capability == "threads"
