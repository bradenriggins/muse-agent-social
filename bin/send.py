#!/usr/bin/env python3
"""Deprecated v0.1 send wrapper.

Preserves the old ``send.py`` argument surface for one release and maps it
onto ``mas send``. Emits a DeprecationWarning on every invocation.

The v0.1-only path flags (--config, --peers, --relay, --relay-cfg,
--outbox-log) are accepted for compatibility but ignored: v0.2 resolves
state from its own state directory.

Note: the ``mas send`` subcommand lands in a later track. This wrapper
builds the new argv and delegates to the v0.2 package CLI, passing through
its exit behavior unchanged.
"""

from __future__ import annotations

import argparse
import sys
import warnings

from muse_agent_social.cli import main as mas_main

_WARNING = (
    "send.py is deprecated and will be removed after one release; "
    "use `mas send` instead"
)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="send.py",
        description="Deprecated v0.1 send wrapper; maps onto `mas send`.",
    )
    ap.add_argument("--to", required=True, help="peer key")
    ap.add_argument(
        "--type",
        required=True,
        choices=("note", "link", "article", "file-ref"),
    )
    ap.add_argument("--title", required=True)
    ap.add_argument("--body", default="")
    ap.add_argument("--url", default="")
    ap.add_argument("--file", default="", help="read body from a local file")
    ap.add_argument("--dry-run", action="store_true")
    # v0.1 path flags: accepted, ignored (v0.2 owns its state dir).
    ap.add_argument("--config", default="")
    ap.add_argument("--peers", default="")
    ap.add_argument("--relay", default="")
    ap.add_argument("--relay-cfg", default="")
    ap.add_argument("--outbox-log", default="")
    return ap


def map_argv(args: argparse.Namespace) -> list[str]:
    """Map the old argument surface onto `mas send` argv."""
    argv = [
        "send",
        "--to",
        args.to,
        "--type",
        args.type,
        "--title",
        args.title,
    ]
    body = args.body
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            body = fh.read()
    if body:
        argv += ["--body", body]
    if args.url:
        argv += ["--url", args.url]
    if args.dry_run:
        argv += ["--dry-run"]
    return argv


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    warnings.warn(_WARNING, DeprecationWarning, stacklevel=2)
    return mas_main(map_argv(args))


if __name__ == "__main__":
    sys.exit(main())
