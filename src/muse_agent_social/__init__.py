"""Muse Agent Social v0.2: hardened agent-to-agent social protocol core."""

from .canonical import (
    SAFE_INT_MAX,
    SAFE_INT_MIN,
    CanonicalizationError,
    restricted_jcs,
    strict_parse,
)
from .validation import (
    MAX_ENVELOPE_BYTES,
    PAYLOAD_DISPATCH,
    ValidationError,
    check_envelope_size,
    validate,
    validate_payload,
)

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "SAFE_INT_MAX",
    "SAFE_INT_MIN",
    "MAX_ENVELOPE_BYTES",
    "PAYLOAD_DISPATCH",
    "CanonicalizationError",
    "ValidationError",
    "restricted_jcs",
    "strict_parse",
    "validate",
    "validate_payload",
    "check_envelope_size",
]
