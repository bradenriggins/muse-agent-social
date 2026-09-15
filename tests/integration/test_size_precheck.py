"""Gate: H2 - relay object size is pre-checked before any content buffering.

The 256 KiB cap used to be enforced only after the transports had fully
buffered the object (git cat-file -p / path.read_bytes()), so a hostile
multi-GB blob in the relay repo OOMed the receiver on the next poll. Both
transports must now check the size from metadata first (git cat-file -s /
stat().st_size) and reject over-cap objects without ever reading them.
"""

import subprocess

import pytest

from muse_agent_social.transports.base import OBJECT_MAX_BYTES, TransportError
from muse_agent_social.transports.github import GitHubTransport, GitRunner
from muse_agent_social.transports.local import LocalTransport, check_object_size


def _valid_name(seed: int) -> str:
    # Deterministic 32-char base64url-ish name + .json (matches OBJECT_NAME_RE).
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return "".join(alphabet[(seed + i) % 64] for i in range(32)) + ".json"


# -- check_object_size unit gate -------------------------------------------------


def test_check_object_size_accepts_at_cap():
    assert check_object_size("a.json", OBJECT_MAX_BYTES) == OBJECT_MAX_BYTES


def test_check_object_size_rejects_one_byte_over():
    with pytest.raises(TransportError) as exc:
        check_object_size("a.json", OBJECT_MAX_BYTES + 1)
    assert exc.value.code == "object_too_large"
    assert exc.value.retryable is False


def test_check_object_size_simulates_multigb_without_allocating():
    # No multi-GB buffer is ever allocated: the gate takes the size alone.
    with pytest.raises(TransportError) as exc:
        check_object_size("evil.json", 5 * 1024**3)
    assert exc.value.code == "object_too_large"


# -- local transport: stat() before read_bytes() --------------------------------


def test_local_fetch_new_never_buffers_oversize_object(tmp_path, monkeypatch):
    relay = tmp_path / "relay"
    transport = LocalTransport(relay)
    name = _valid_name(7)
    big = relay / "incoming" / name
    big.write_bytes(b"x" * (300 * 1024))

    reads = []
    real_read_bytes = __import__("pathlib").Path.read_bytes

    def spy_read_bytes(self):
        reads.append(str(self))
        return real_read_bytes(self)

    monkeypatch.setattr("pathlib.Path.read_bytes", spy_read_bytes)
    # fetch_new does not raise: the receive loop quarantines oversized
    # input itself. The object comes back with a bounded placeholder that
    # still trips the receive-side len() cap check.
    items = transport.fetch_new("")
    assert len(items) == 1
    assert items[0][0] == name
    assert len(items[0][1]) == OBJECT_MAX_BYTES + 1
    # The content was never buffered: read_bytes ran zero times.
    assert reads == []


def test_local_fetch_new_simulated_huge_stat_without_buffering(tmp_path, monkeypatch):
    relay = tmp_path / "relay"
    transport = LocalTransport(relay)
    name = _valid_name(9)
    # Sparse file: st_size reports 8 GiB but allocates no blocks.
    with open(relay / "incoming" / name, "wb") as fh:
        fh.truncate(8 * 1024**3)
    monkeypatch.setattr(
        "pathlib.Path.read_bytes",
        lambda self: (_ for _ in ()).throw(AssertionError("buffered!")),
    )
    items = transport.fetch_new("")
    assert len(items) == 1 and items[0][0] == name
    assert len(items[0][1]) == OBJECT_MAX_BYTES + 1


def test_local_read_object_rejects_oversize_without_buffering(tmp_path, monkeypatch):
    relay = tmp_path / "relay"
    transport = LocalTransport(relay)
    name = _valid_name(13)
    with open(relay / "incoming" / name, "wb") as fh:
        fh.truncate(8 * 1024**3)
    monkeypatch.setattr(
        "pathlib.Path.read_bytes",
        lambda self: (_ for _ in ()).throw(AssertionError("buffered!")),
    )
    with pytest.raises(TransportError) as exc:
        transport.read_object(name)
    assert exc.value.code == "object_too_large"
    assert exc.value.retryable is False


def test_local_read_object_returns_small_object(tmp_path):
    relay = tmp_path / "relay"
    transport = LocalTransport(relay)
    name = _valid_name(15)
    (relay / "incoming" / name).write_bytes(b'{"ok": true}')
    assert transport.read_object(name) == b'{"ok": true}'


def test_local_fetch_new_still_returns_small_objects(tmp_path):
    relay = tmp_path / "relay"
    transport = LocalTransport(relay)
    name = _valid_name(11)
    (relay / "incoming" / name).write_bytes(b'{"ok": true}')
    items = transport.fetch_new("")
    assert items == [(name, b'{"ok": true}')]


# -- github transport: cat-file -s before cat-file -p ----------------------------


class _FakeRunner(GitRunner):
    """Stub git. Records every invocation; cat-file -p must never run for
    an over-cap object."""

    def __init__(self, repo_url, object_name, reported_size):
        super().__init__()
        self.repo_url = repo_url
        self.object_name = object_name
        self.reported_size = reported_size
        self.calls = []

    def run(self, args, cwd, timeout):
        self.calls.append(list(args))
        if args[:2] == ["config", "--get"]:
            return subprocess.CompletedProcess(
                args, 0, stdout=(self.repo_url + "\n").encode(), stderr=b""
            )
        if args[0] == "fetch":
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        if args[0] == "rev-parse":
            # origin/main exists; any other ref (e.g. a `since` sha) does not,
            # so fetch_new falls back to the full ls-tree listing.
            ok = args[-1] == "origin/main"
            return subprocess.CompletedProcess(
                args, 0 if ok else 1, stdout=b"", stderr=b""
            )
        if args[0] == "ls-tree":
            body = f"incoming/{self.object_name}\n".encode()
            return subprocess.CompletedProcess(args, 0, stdout=body, stderr=b"")
        if args[:2] == ["cat-file", "-s"]:
            return subprocess.CompletedProcess(
                args, 0, stdout=f"{self.reported_size}\n".encode(), stderr=b""
            )
        if args[:2] == ["cat-file", "-p"]:
            raise AssertionError(
                "cat-file -p must not run for an over-cap object"
            )
        return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")


def _github_transport(tmp_path, runner):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    rid = "bbbbbbbb-2222-4222-8222-222222222222"
    mirror = state_dir / "mirrors" / rid
    (mirror / ".git").mkdir(parents=True)  # skip the clone
    repo_url = "git@github.com:example/relay.git"
    return GitHubTransport(
        state_dir, rid, repo_url, runner=runner,
    ), "origin/main", repo_url


def test_github_fetch_new_never_buffers_oversize_blob(tmp_path):
    name = _valid_name(13)
    runner = _FakeRunner(
        "git@github.com:example/relay.git", name, 300 * 1024
    )
    transport, ref, _ = _github_transport(tmp_path, runner)
    # fetch_new does not raise: the receive loop quarantines oversized
    # input itself. The blob comes back with a bounded placeholder that
    # still trips the receive-side len() cap check.
    items = transport.fetch_new("")
    assert len(items) == 1 and items[0][0] == name
    assert len(items[0][1]) == OBJECT_MAX_BYTES + 1
    # The size pre-check ran, and cat-file -p never did (the fake raises
    # AssertionError if it runs, so reaching here proves it).
    assert any(
        c[:2] == ["cat-file", "-s"] for c in runner.calls
    )
    assert not any(c[:2] == ["cat-file", "-p"] for c in runner.calls)


def test_github_fetch_new_simulated_multigb_size(tmp_path):
    name = _valid_name(15)
    runner = _FakeRunner(
        "git@github.com:example/relay.git", name, 5 * 1024**3
    )
    transport, _, _ = _github_transport(tmp_path, runner)
    items = transport.fetch_new("")
    assert len(items) == 1 and items[0][0] == name
    assert len(items[0][1]) == OBJECT_MAX_BYTES + 1
    assert not any(c[:2] == ["cat-file", "-p"] for c in runner.calls)


def test_github_read_object_rejects_oversize_without_cat_file_p(tmp_path):
    name = _valid_name(19)
    runner = _FakeRunner(
        "git@github.com:example/relay.git", name, 5 * 1024**3
    )
    transport, _, _ = _github_transport(tmp_path, runner)
    with pytest.raises(TransportError) as exc:
        transport.read_object(name)
    assert exc.value.code == "object_too_large"
    assert exc.value.retryable is False
    assert not any(c[:2] == ["cat-file", "-p"] for c in runner.calls)


def test_github_read_object_returns_small_blob(tmp_path):
    name = _valid_name(21)

    class _SmallRunner(_FakeRunner):
        def run(self, args, cwd, timeout):
            if args[:2] == ["cat-file", "-p"]:
                self.calls.append(list(args))
                return subprocess.CompletedProcess(
                    args, 0, stdout=b'{"ok": true}', stderr=b""
                )
            return super().run(args, cwd, timeout)

    runner = _SmallRunner("git@github.com:example/relay.git", name, 64)
    transport, _, _ = _github_transport(tmp_path, runner)
    assert transport.read_object(name) == b'{"ok": true}'


def test_github_fetch_new_still_fetches_small_objects(tmp_path):
    name = _valid_name(17)

    class _SmallRunner(_FakeRunner):
        def run(self, args, cwd, timeout):
            if args[:2] == ["cat-file", "-p"]:
                self.calls.append(list(args))
                return subprocess.CompletedProcess(
                    args, 0, stdout=b'{"ok": true}', stderr=b""
                )
            return super().run(args, cwd, timeout)

    runner = _SmallRunner("git@github.com:example/relay.git", name, 64)
    transport, _, _ = _github_transport(tmp_path, runner)
    items = transport.fetch_new("")
    assert items == [(name, b'{"ok": true}')]
