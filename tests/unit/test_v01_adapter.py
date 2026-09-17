"""Unit tests for the v0.1 compatibility adapter.

No network. All keys and envelopes are generated fresh per test with
fictional identities; no secrets appear in fixtures.
"""

import base64
import hashlib
import hmac
import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from muse_agent_social.compatibility.v01 import (
    ALL_CODES,
    LEGACY_FIELD_SET,
    MAX_V01_BYTES,
    LegacyError,
    LegacyPolicy,
    MemoryReplayStore,
    SeqAssigner,
    UnsupportedCapabilityError,
    VaultError,
    adapt_v01,
    assert_legacy_sends_allowed,
    detect_v01,
    record_legacy_replay,
    require_capability,
    vault_delete,
    vault_load,
    vault_store,
    verify_v01,
)

ALICE = "agent:test-alice:fixture"
BOB = "agent:test-bob:fixture"
PAIR = "pair-test-fixture-0001"


def _fresh_key() -> bytes:
    return os.urandom(32)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ts(dt: datetime) -> str:
    return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_envelope(key: bytes, **overrides) -> dict:
    env = {
        "v": 1,
        "id": "legacy-" + os.urandom(4).hex(),
        "from": BOB,
        "to": ALICE,
        "pair": PAIR,
        "type": "note",
        "title": "hello",
        "body": "world",
        "url": "",
        "created_at": _ts(_utcnow()),
        "nonce": os.urandom(8).hex(),
    }
    env.update(overrides)
    if "sig" not in overrides:
        canonical = json.dumps(
            {k: v for k, v in env.items() if k != "sig"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        env["sig"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return env


def seal(env: dict) -> bytes:
    return json.dumps(env).encode("utf-8")


def wrap(raw: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, raw, None)
    return json.dumps(
        {
            "n": base64.b64encode(nonce).decode("ascii"),
            "c": base64.b64encode(ct).decode("ascii"),
        }
    ).encode("utf-8")


def make_policy(**overrides) -> LegacyPolicy:
    base = {
        "pair_id": PAIR,
        "expected_sender": BOB,
        "my_agent_id": ALICE,
        "replay_store": MemoryReplayStore(),
    }
    base.update(overrides)
    return LegacyPolicy(**base)


def expect_code(fn, code: str):
    with pytest.raises(LegacyError) as exc_info:
        fn()
    assert exc_info.value.code == code, (
        f"expected {code}, got {exc_info.value.code}: {exc_info.value.detail}"
    )
    return exc_info.value


# ---------------------------------------------------------------------------
# detect_v01
# ---------------------------------------------------------------------------


def test_detect_true_for_all_four_types():
    key = _fresh_key()
    for t in ("note", "link", "article", "file-ref"):
        raw = seal(make_envelope(key, type=t))
        assert detect_v01(raw) is True, t


def test_detect_false_cases():
    key = _fresh_key()
    raw = seal(make_envelope(key))
    assert detect_v01(wrap(raw, key)) is False  # {"n","c"} wrapper
    assert detect_v01(b'{"v": 2, "id": "x"}') is False  # v0.2-shaped
    assert detect_v01(b'{"hello": "world"}') is False  # arbitrary JSON
    assert detect_v01(b"not json at all") is False
    assert detect_v01(b"[1, 2, 3]") is False
    assert detect_v01(seal(make_envelope(key, v=2))) is False
    env = make_envelope(key)
    env["extra"] = 1
    assert detect_v01(seal(env)) is False  # extra field
    env2 = make_envelope(key)
    del env2["nonce"]
    assert detect_v01(seal(env2)) is False  # missing field


# ---------------------------------------------------------------------------
# verify_v01: happy paths
# ---------------------------------------------------------------------------


def test_verify_plaintext_ok():
    key = _fresh_key()
    raw = seal(make_envelope(key))
    verified = verify_v01(raw, key, policy=make_policy(), filename="a.json")
    assert verified.hmac_ok is True
    assert verified.raw == raw
    assert verified.filename == "a.json"
    assert verified.pair_id == PAIR
    assert set(verified.envelope.keys()) == LEGACY_FIELD_SET


def test_verify_wrapper_ok():
    key = _fresh_key()
    raw = seal(make_envelope(key))
    wrapped = wrap(raw, key)
    verified = verify_v01(wrapped, key, policy=make_policy(), filename="b.json")
    assert verified.raw == wrapped  # original sealed bytes preserved
    assert verified.envelope["body"] == "world"


def test_verify_wrong_key_rejected():
    key = _fresh_key()
    raw = seal(make_envelope(key))
    expect_code(
        lambda: verify_v01(raw, os.urandom(32), policy=make_policy()),
        "V01_HMAC_INVALID",
    )


# ---------------------------------------------------------------------------
# verify_v01: signature and shape failures
# ---------------------------------------------------------------------------


def test_forged_hmac_rejected():
    key = _fresh_key()
    env = make_envelope(key)
    sig = env["sig"]
    env["sig"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    expect_code(
        lambda: verify_v01(seal(env), key, policy=make_policy()),
        "V01_HMAC_INVALID",
    )


def test_tampered_body_rejected():
    key = _fresh_key()
    env = make_envelope(key)
    env["body"] = "tampered"
    expect_code(
        lambda: verify_v01(seal(env), key, policy=make_policy()),
        "V01_HMAC_INVALID",
    )


def test_missing_sig_rejected():
    key = _fresh_key()
    env = make_envelope(key)
    del env["sig"]
    raw = json.dumps(env).encode("utf-8")  # seal without re-signing
    expect_code(
        lambda: verify_v01(raw, key, policy=make_policy()),
        "V01_HMAC_INVALID",
    )


def test_missing_nonce_rejected():
    key = _fresh_key()
    env = make_envelope(key)
    del env["nonce"]
    # Re-sign so the failure is attributed to the nonce, not the HMAC.
    canonical = json.dumps(
        {k: v for k, v in env.items() if k != "sig"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    env["sig"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    raw = json.dumps(env).encode("utf-8")
    expect_code(
        lambda: verify_v01(raw, key, policy=make_policy()),
        "V01_MISSING_NONCE",
    )


def test_empty_nonce_rejected():
    key = _fresh_key()
    raw = seal(make_envelope(key, nonce=""))
    expect_code(
        lambda: verify_v01(raw, key, policy=make_policy()),
        "V01_MISSING_NONCE",
    )


def test_v_absent_or_not_1_rejected():
    key = _fresh_key()
    env = make_envelope(key)
    del env["v"]
    expect_code(
        lambda: verify_v01(seal(env), key, policy=make_policy()),
        "V01_NOT_LEGACY",
    )
    raw2 = seal(make_envelope(key, v=2))
    expect_code(
        lambda: verify_v01(raw2, key, policy=make_policy()),
        "V01_NOT_LEGACY",
    )


def test_fieldset_mismatch_cases():
    key = _fresh_key()
    env = make_envelope(key)
    env["extra"] = "x"
    expect_code(
        lambda: verify_v01(seal(env), key, policy=make_policy()),
        "V01_FIELDSET_MISMATCH",
    )
    expect_code(
        lambda: verify_v01(
            seal(make_envelope(key, type="poll")), key, policy=make_policy()
        ),
        "V01_FIELDSET_MISMATCH",
    )
    expect_code(
        lambda: verify_v01(
            seal(make_envelope(key, title=123)), key, policy=make_policy()
        ),
        "V01_FIELDSET_MISMATCH",
    )


def test_oversize_rejected_before_parse():
    key = _fresh_key()
    big = b"x" * (MAX_V01_BYTES + 1)
    expect_code(
        lambda: verify_v01(big, key, policy=make_policy()),
        "V01_OVERSIZE",
    )


def test_decode_error():
    key = _fresh_key()
    expect_code(
        lambda: verify_v01(b"\xff\xfe not json", key, policy=make_policy()),
        "V01_DECODE_ERROR",
    )
    expect_code(
        lambda: verify_v01(b"[1,2]", key, policy=make_policy()),
        "V01_DECODE_ERROR",
    )


def test_tampered_wrapper_rejected():
    key = _fresh_key()
    raw = seal(make_envelope(key))
    wrapped = json.loads(wrap(raw, key).decode("utf-8"))
    c = bytearray(base64.b64decode(wrapped["c"]))
    c[0] ^= 0xFF
    wrapped["c"] = base64.b64encode(bytes(c)).decode("ascii")
    bad = json.dumps(wrapped).encode("utf-8")
    expect_code(
        lambda: verify_v01(bad, key, policy=make_policy()),
        "V01_DECRYPT_FAILED",
    )


def test_wrapper_bad_base64_rejected():
    key = _fresh_key()
    bad = json.dumps({"n": "!!!", "c": "!!!"}).encode("utf-8")
    expect_code(
        lambda: verify_v01(bad, key, policy=make_policy()),
        "V01_DECRYPT_FAILED",
    )


# ---------------------------------------------------------------------------
# verify_v01: routing, age, replay, rate, lifecycle
# ---------------------------------------------------------------------------


def test_routing_mismatches():
    key = _fresh_key()
    expect_code(
        lambda: verify_v01(
            seal(make_envelope(key, **{"from": "agent:impostor:x"})),
            key,
            policy=make_policy(),
        ),
        "V01_SENDER_MISMATCH",
    )
    expect_code(
        lambda: verify_v01(
            seal(make_envelope(key, to="agent:someone-else:x")),
            key,
            policy=make_policy(),
        ),
        "V01_RECIPIENT_MISMATCH",
    )
    expect_code(
        lambda: verify_v01(
            seal(make_envelope(key, pair="pair-other")),
            key,
            policy=make_policy(),
        ),
        "V01_PAIR_MISMATCH",
    )


def test_bad_timestamp():
    key = _fresh_key()
    raw = seal(make_envelope(key, created_at="2026/09/15 12:00"))
    expect_code(
        lambda: verify_v01(raw, key, policy=make_policy()),
        "V01_BAD_TIMESTAMP",
    )


def test_stale_and_future():
    key = _fresh_key()
    old = _ts(_utcnow() - timedelta(days=8))
    expect_code(
        lambda: verify_v01(
            seal(make_envelope(key, created_at=old)),
            key,
            policy=make_policy(),
        ),
        "V01_STALE",
    )
    future = _ts(_utcnow() + timedelta(hours=2))
    expect_code(
        lambda: verify_v01(
            seal(make_envelope(key, created_at=future)),
            key,
            policy=make_policy(),
        ),
        "V01_FUTURE",
    )
    # Near the boundaries still passes: just inside 7 days and 1h.
    ok_old = _ts(_utcnow() - timedelta(days=6, hours=23))
    verify_v01(
        seal(make_envelope(key, created_at=ok_old)),
        key,
        policy=make_policy(),
        filename="edge1.json",
    )
    ok_future = _ts(_utcnow() + timedelta(minutes=59))
    verify_v01(
        seal(make_envelope(key, created_at=ok_future)),
        key,
        policy=make_policy(),
        filename="edge2.json",
    )


def test_replay_rejected():
    key = _fresh_key()
    policy = make_policy()
    raw = seal(make_envelope(key))
    verified = verify_v01(raw, key, policy=policy, filename="r.json")
    record_legacy_replay(policy, verified)
    expect_code(
        lambda: verify_v01(raw, key, policy=policy, filename="r.json"),
        "V01_REPLAY",
    )


def test_rate_limited():
    key = _fresh_key()
    raw = seal(make_envelope(key))
    expect_code(
        lambda: verify_v01(
            raw, key, policy=make_policy(accepted_today=5, daily_cap=5)
        ),
        "V01_RATE_LIMITED",
    )
    # Under the cap passes.
    verify_v01(raw, key, policy=make_policy(accepted_today=4, daily_cap=5))


def test_drain_closed():
    key = _fresh_key()
    raw = seal(make_envelope(key))
    expect_code(
        lambda: verify_v01(
            raw, key, policy=make_policy(legacy_read_open=False)
        ),
        "V01_DRAIN_CLOSED",
    )


def test_sends_disabled():
    expect_code(
        lambda: assert_legacy_sends_allowed(
            make_policy(legacy_sends_allowed=False)
        ),
        "V01_SENDS_DISABLED",
    )
    assert_legacy_sends_allowed(make_policy(legacy_sends_allowed=True))


# ---------------------------------------------------------------------------
# adapt_v01
# ---------------------------------------------------------------------------


def _adapt_all_types():
    key = _fresh_key()
    policy = make_policy()
    assigner = SeqAssigner()
    out = {}
    for i, t in enumerate(("note", "link", "article", "file-ref")):
        raw = seal(make_envelope(key, type=t, url="https://example.test/x"))
        verified = verify_v01(raw, key, policy=policy, filename=f"f{i}.json")
        out[t] = (adapt_v01(verified, PAIR, assigner), raw)
    return out


def test_adapt_type_mapping():
    out = _adapt_all_types()
    for t, (event, _raw) in out.items():
        assert event["event_type"] == "message.created", t
        assert event["legacy_source"] == "v0.1", t
        assert event["legacy_type"] == t, t
        assert event["payload"]["body"] == "world", t
        assert event["payload"]["legacy_title"] == "hello", t
    assert "legacy_url" not in out["note"][0]["payload"]
    for t in ("link", "article", "file-ref"):
        assert out[t][0]["payload"]["legacy_url"] == "https://example.test/x", t


def test_adapt_determinism():
    key = _fresh_key()
    policy = make_policy()
    raw = seal(make_envelope(key))
    verified = verify_v01(raw, key, policy=policy, filename="same.json")
    assigner = SeqAssigner()
    first = adapt_v01(verified, PAIR, assigner)
    second = adapt_v01(verified, PAIR, assigner)
    assert first["event_id"] == second["event_id"]
    assert first["sender_seq"] == second["sender_seq"]
    assert first["raw_v01"] == raw == second["raw_v01"]
    # Sequence is stable per filename, distinct across filenames.
    other = adapt_v01(verified, PAIR, assigner)
    assert other["sender_seq"] == first["sender_seq"]
    third_verified = verify_v01(
        seal(make_envelope(key)), key, policy=policy, filename="other.json"
    )
    third = adapt_v01(third_verified, PAIR, assigner)
    assert third["sender_seq"] != first["sender_seq"]


def test_adapt_preserves_provenance_and_never_resigns():
    key = _fresh_key()
    raw = seal(make_envelope(key))
    verified = verify_v01(raw, key, policy=make_policy(), filename="p.json")
    event = adapt_v01(verified, PAIR, SeqAssigner())
    assert event["created_at"] == verified.envelope["created_at"]
    assert event["hmac_ok"] is True
    assert event["sender"] == BOB
    assert "v02_signature" not in event
    assert "sealed_envelope" not in event


def test_adapt_rejects_unverified():
    with pytest.raises(ValueError):
        adapt_v01("not-a-verified-legacy", PAIR, SeqAssigner())


# ---------------------------------------------------------------------------
# No-downgrade, vault, error surface
# ---------------------------------------------------------------------------


def test_no_downgrade_explicit_error():
    with pytest.raises(UnsupportedCapabilityError) as exc_info:
        require_capability("receipts", {"message"})
    assert exc_info.value.capability == "receipts"
    require_capability("message", {"message", "receipts"})  # no raise


def test_vault_roundtrip_and_delete(tmp_path):
    vault = tmp_path / "vault"
    key = _fresh_key()
    path = vault_store(vault, PAIR, key.hex())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert vault_load(vault, PAIR) == key
    vault_delete(vault, PAIR)
    with pytest.raises(KeyError):
        vault_load(vault, PAIR)


def test_vault_wrong_mode_refused(tmp_path):
    vault = tmp_path / "vault"
    key = _fresh_key()
    path = vault_store(vault, PAIR, key.hex())
    os.chmod(path, 0o644)
    with pytest.raises(VaultError):
        vault_load(vault, PAIR)


def test_all_codes_defined():
    assert len(ALL_CODES) == 17
    assert len(set(ALL_CODES)) == 17


def test_legacy_error_carries_code_not_content():
    key = _fresh_key()
    raw = seal(make_envelope(key, body="super secret body"))
    err = expect_code(
        lambda: verify_v01(raw, os.urandom(32), policy=make_policy()),
        "V01_HMAC_INVALID",
    )
    assert "super secret body" not in str(err)
    assert "super secret body" not in err.detail


# ---------------------------------------------------------------------------
# adapt_v01: file attachments
# ---------------------------------------------------------------------------


def _file_envelope(key: bytes, data: bytes, **overrides) -> dict:
    att = {
        "filename": "report.pdf",
        "size": len(data),
        "content_type": "application/pdf",
        "data": base64.b64encode(data).decode("ascii"),
    }
    env = make_envelope(key, type="file", attachment=att)
    env.update(overrides)
    # Re-sign after overrides (make_envelope signs before we add attachment).
    env.pop("sig", None)
    canonical = json.dumps(
        {k: v for k, v in env.items() if k != "sig"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    env["sig"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return env


def _adapt_file(key: bytes, data: bytes, **overrides):
    raw = seal(_file_envelope(key, data, **overrides))
    verified = verify_v01(raw, key, policy=make_policy(), filename="f.json")
    return adapt_v01(verified, PAIR, SeqAssigner())


def test_adapt_file_carries_attachment():
    data = b"%PDF-1.4 tiny"
    event = _adapt_file(_fresh_key(), data)
    assert event["legacy_type"] == "file"
    att = event["payload"]["attachment"]
    assert att["filename"] == "report.pdf"
    assert att["size"] == len(data)
    assert att["data"] == base64.b64encode(data).decode("ascii")
    assert att["sha256"] == hashlib.sha256(data).hexdigest()
    # The adapted payload still validates as message.created.
    from muse_agent_social.validation import validate_payload

    validate_payload("message.created", {
        "body": event["payload"]["body"],
        "format": "plain",
        "attachment": att,
    })


def test_adapt_file_oversize_downgrades_to_body_only():
    from muse_agent_social.validation import MAX_ATTACHMENT_BYTES

    data = b"x" * (MAX_ATTACHMENT_BYTES + 1)
    event = _adapt_file(_fresh_key(), data)
    assert event["legacy_type"] == "file"
    assert "attachment" not in event["payload"]
    # Original bytes preserved verbatim for manual recovery.
    assert event["raw_v01"] is not None


def test_adapt_file_malformed_attachment_downgrades():
    key = _fresh_key()
    env = make_envelope(key, type="file",
                        attachment={"filename": "x", "size": 3,
                                    "data": "!!!bad!!!"})
    env.pop("sig", None)
    canonical = json.dumps(
        {k: v for k, v in env.items() if k != "sig"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    env["sig"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    raw = seal(env)
    verified = verify_v01(raw, key, policy=make_policy(), filename="f.json")
    event = adapt_v01(verified, PAIR, SeqAssigner())
    assert "attachment" not in event["payload"]
