"""Unit tests for the v0.2 message.created attachment contract.

Covers: schema acceptance/rejection, the validation-layer invariants
(strict base64, size match, 128 KiB cap, SHA-256 verification), the
_cli _attachment_from_file helper, the attachments table migration, and
the receive-path materialization (atomic mode-600 writes, idempotent
retry, sha/size re-verification at write time).
"""

from __future__ import annotations

import base64
import hashlib
import os
import sqlite3

import pytest

from muse_agent_social.cli import _attachment_from_file
from muse_agent_social.store import db
from muse_agent_social.store import migrations
from muse_agent_social.validation import (
    MAX_ATTACHMENT_BYTES,
    ValidationError,
    validate_payload,
)


def _make_attachment(data: bytes, filename: str = "note.txt",
                     content_type: str = "text/plain") -> dict:
    return {
        "filename": filename,
        "size": len(data),
        "content_type": content_type,
        "data": base64.b64encode(data).decode("ascii"),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _payload(att: dict) -> dict:
    return {"body": "see attached", "format": "plain", "attachment": att}


def test_valid_attachment_passes():
    validate_payload("message.created", _payload(_make_attachment(b"hello")))


def test_no_attachment_still_passes():
    validate_payload("message.created", {"body": "hi", "format": "plain"})


def test_rejects_bad_base64():
    att = _make_attachment(b"hello")
    att["data"] = "!!! not base64 !!!"
    with pytest.raises(ValidationError) as exc:
        validate_payload("message.created", _payload(att))
    assert exc.value.code == "not_base64"


def test_rejects_size_mismatch():
    att = _make_attachment(b"hello")
    att["size"] = 999
    with pytest.raises(ValidationError) as exc:
        validate_payload("message.created", _payload(att))
    assert exc.value.code == "size_mismatch"


def test_rejects_oversize():
    att = _make_attachment(b"x" * (MAX_ATTACHMENT_BYTES + 1))
    # The JSON Schema maximum fires before the custom check; either way
    # the oversize attachment is rejected.
    with pytest.raises(ValidationError) as exc:
        validate_payload("message.created", _payload(att))
    assert exc.value.code in ("maximum", "too_large")


def test_rejects_digest_mismatch():
    att = _make_attachment(b"hello")
    att["sha256"] = "0" * 64
    with pytest.raises(ValidationError) as exc:
        validate_payload("message.created", _payload(att))
    assert exc.value.code == "digest_mismatch"


def test_rejects_missing_sha256():
    att = _make_attachment(b"hello")
    del att["sha256"]
    with pytest.raises(ValidationError):
        validate_payload("message.created", _payload(att))


def test_rejects_slash_in_filename():
    att = _make_attachment(b"hello", filename="../evil")
    with pytest.raises(ValidationError):
        validate_payload("message.created", _payload(att))


def test_rejects_unknown_attachment_field():
    att = _make_attachment(b"hello")
    att["extra"] = "nope"
    with pytest.raises(ValidationError):
        validate_payload("message.created", _payload(att))


def test_attachment_from_file_round_trip(tmp_path):
    p = tmp_path / "hello.bin"
    p.write_bytes(b"\x00\x01\x02binary")
    att = _attachment_from_file(str(p))
    assert att["filename"] == "hello.bin"
    assert att["size"] == 9
    assert base64.b64decode(att["data"], validate=True) == b"\x00\x01\x02binary"
    assert att["sha256"] == hashlib.sha256(b"\x00\x01\x02binary").hexdigest()
    validate_payload("message.created", _payload(att))


def test_attachment_from_file_rejects_missing():
    with pytest.raises(Exception):
        _attachment_from_file("/does/not/exist.bin")


def test_attachment_from_file_rejects_oversize(tmp_path):
    p = tmp_path / "big.bin"
    p.write_bytes(b"x" * (MAX_ATTACHMENT_BYTES + 1))
    with pytest.raises(Exception):
        _attachment_from_file(str(p))


def test_migration_creates_attachments_table(tmp_path):
    c = db.connect(tmp_path / "m.db")
    try:
        assert migrations.migrate(c) == 5
        cols = [r[1] for r in c.execute("PRAGMA table_info(attachments);")]
        for col in ("event_id", "relationship_id", "filename", "size",
                    "content_type", "sha256", "stored_path", "received_at"):
            assert col in cols, col
    finally:
        c.close()


def test_materialize_writes_mode_600(tmp_path):
    from muse_agent_social.cli import _materialize_attachments

    class FakeCtx:
        def __init__(self, conn, state_dir):
            self.conn = conn
            self.state_dir = state_dir

    c = db.connect(tmp_path / "m.db")
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = OFF;")
    try:
        migrations.migrate(c)
        data = b"file bytes here"
        att = _make_attachment(data, "doc.txt")
        c.execute(
            "INSERT INTO attachments(event_id, relationship_id, filename,"
            " size, content_type, sha256, stored_path, received_at)"
            " VALUES ('evt-1', 'rel-1', 'doc.txt', ?, 'text/plain', ?, NULL, '2026-09-16T00:00:00Z');",
            (len(data), att["sha256"]),
        )
        import json
        c.execute(
            "INSERT INTO event_payloads(event_id, event_type, payload)"
            " VALUES ('evt-1', 'message.created', ?);",
            (json.dumps({"body": "b", "format": "plain", "attachment": att}),),
        )
        c.commit()
        ctx = FakeCtx(c, tmp_path)
        result = _materialize_attachments(ctx, ["rel-1"])
        assert result == {"materialized": 1, "failed": 0}
        target = tmp_path / "attachments" / "rel-1" / "evt-1_doc.txt"
        assert target.exists()
        assert target.read_bytes() == data
        assert oct(os.stat(target).st_mode & 0o777) == "0o600"
        row = c.execute(
            "SELECT stored_path FROM attachments WHERE event_id = 'evt-1';"
        ).fetchone()
        assert row["stored_path"] == str(target)
        # Idempotent: second run finds nothing pending.
        result2 = _materialize_attachments(ctx, ["rel-1"])
        assert result2 == {"materialized": 0, "failed": 0}
    finally:
        c.close()


def test_materialize_rejects_tampered_bytes(tmp_path):
    from muse_agent_social.cli import _materialize_attachments

    class FakeCtx:
        def __init__(self, conn, state_dir):
            self.conn = conn
            self.state_dir = state_dir

    c = db.connect(tmp_path / "m.db")
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = OFF;")
    try:
        migrations.migrate(c)
        att = _make_attachment(b"original", "doc.txt")
        att["data"] = base64.b64encode(b"tampered!!").decode()
        import json
        c.execute(
            "INSERT INTO attachments(event_id, relationship_id, filename,"
            " size, content_type, sha256, stored_path, received_at)"
            " VALUES ('evt-2', 'rel-1', 'doc.txt', 8, 'text/plain', ?, NULL, '2026-09-16T00:00:00Z');",
            (att["sha256"],),
        )
        c.execute(
            "INSERT INTO event_payloads(event_id, event_type, payload)"
            " VALUES ('evt-2', 'message.created', ?);",
            (json.dumps({"body": "b", "format": "plain", "attachment": att}),),
        )
        c.commit()
        ctx = FakeCtx(c, tmp_path)
        result = _materialize_attachments(ctx, ["rel-1"])
        assert result["materialized"] == 0
        assert result["failed"] == 1
        # Stays pending for retry; nothing written.
        assert not (tmp_path / "attachments" / "rel-1" / "evt-2_doc.txt").exists()
        row = c.execute(
            "SELECT stored_path FROM attachments WHERE event_id = 'evt-2';"
        ).fetchone()
        assert row["stored_path"] is None
    finally:
        c.close()
