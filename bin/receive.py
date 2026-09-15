#!/usr/bin/env python3
"""Deprecated v0.1 receive wrapper.

Preserves the old ``receive.py`` argument surface for one release and maps
it onto ``mas receive``. Emits a DeprecationWarning on every invocation.

The v0.1-only path flags (--config, --peers, --relay, --relay-cfg, --inbox)
are accepted for compatibility but ignored: v0.2 resolves state from its
own state directory.

Note: the ``mas receive`` subcommand lands in a later track. This wrapper
builds the new argv and delegates to the v0.2 package CLI, passing through
its exit behavior unchanged.
"""

from __future__ import annotations

import argparse
import sys
import warnings

from muse_agent_social.cli import main as mas_main

_WARNING = (
    "receive.py is deprecated and will be removed after one release; "
    "use `mas receive` instead"
)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="receive.py",
        description="Deprecated v0.1 receive wrapper; maps onto `mas receive`.",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON output",
    )
    # v0.1 path flags: accepted, ignored (v0.2 owns its state dir).
    ap.add_argument("--config", default="")
    ap.add_argument("--peers", default="")
    ap.add_argument("--relay", default="")
    ap.add_argument("--relay-cfg", default="")
    ap.add_argument("--inbox", default="")
    return ap


def map_argv(args: argparse.Namespace) -> list[str]:
    """Map the old argument surface onto `mas receive` argv."""
    argv = ["receive"]
    if args.json:
        argv += ["--json"]
    return argv


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    warnings.warn(_WARNING, DeprecationWarning, stacklevel=2)
    return mas_main(map_argv(args))


if __name__ == "__main__":
    sys.exit(main())
