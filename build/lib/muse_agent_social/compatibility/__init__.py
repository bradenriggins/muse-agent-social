"""v0.1 compatibility adapter package (lifecycle track)."""

from .v01 import (
    LEGACY_FIELD_SET,
    MAX_V01_BYTES,
    LegacyError,
    LegacyPolicy,
    SeqAssigner,
    UnsupportedCapabilityError,
    adapt_v01,
    assert_legacy_sends_allowed,
    detect_v01,
    require_capability,
    vault_delete,
    vault_load,
    vault_store,
    verify_v01,
)

__all__ = [
    "LEGACY_FIELD_SET",
    "MAX_V01_BYTES",
    "LegacyError",
    "LegacyPolicy",
    "SeqAssigner",
    "UnsupportedCapabilityError",
    "adapt_v01",
    "assert_legacy_sends_allowed",
    "detect_v01",
    "require_capability",
    "vault_delete",
    "vault_load",
    "vault_store",
    "verify_v01",
]
