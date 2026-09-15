#!/usr/bin/env python3
"""REMOVED in v0.2: R2 relay provisioning.

v0.2 ships no R2 transport (only ``github`` and ``local``), so there is no
supported R2 provisioning path. The old script additionally generated the
PEER's API credentials and wrote them into a pairing bundle, which the v0.2
pairing model forbids: each side provisions its own credentials through the
``mas pair`` ceremony and a peer private key is never generated, accepted,
or persisted.

This script now refuses to run, for any arguments, doing zero network
calls and writing zero files. To provision a relay:

  1. bin/relay-setup-gh.py --repo-name <name>   # creates the relay repo
  2. mas pair invite / accept / commit           # new ceremony; each side
                                                # generates its own keys
"""
import sys


def main(argv=None):
    sys.stderr.write(
        "refusing: R2 relay provisioning was removed in v0.2. v0.2 ships no "
        "R2 transport (only `github` and `local`), and the old script's habit "
        "of generating the PEER's credentials and persisting them in a "
        "pairing bundle is forbidden by the v0.2 pairing model: each side "
        "generates its own keys through the `mas pair` ceremony. Use "
        "bin/relay-setup-gh.py to create the relay repo, then run "
        "`mas pair invite` / `mas pair accept` / `mas pair commit`.\n"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
