"""Restricted JSON Canonicalization Scheme (JCS) profile for Muse Agent Social v0.2.

Implements the locked profile from the implementation plan ("Restricted JCS
profile"):

- Object keys are ASCII only, recursively sorted by byte value.
- Numbers are integers only, in [-9007199254740991, 9007199254740991].
  Floats, decimals, NaN, and Infinity are rejected before canonicalization.
- Duplicate object keys, unpaired Unicode surrogates, and invalid UTF-8 are
  rejected.
- No Unicode normalization; string data is preserved exactly.
- No whitespace.
- Strings use RFC 8785 escaping: short escapes for backspace, tab, line feed,
  form feed, carriage return; other controls use lowercase \\u00xx.
- Array order is preserved; objects nested inside arrays are recursively sorted.

This module vendors a small dedicated canonicalizer. It does not use
``json.dumps(sort_keys=True)`` as the protocol contract.

Errors expose only the field path and a stable error code, never values.
"""

from __future__ import annotations

import json
import math
from typing import Any

SAFE_INT_MIN = -9007199254740991
SAFE_INT_MAX = 9007199254740991

__all__ = [
    "SAFE_INT_MIN",
    "SAFE_INT_MAX",
    "CanonicalizationError",
    "restricted_jcs",
    "strict_parse",
]


class CanonicalizationError(Exception):
    """Raised when input cannot be canonically serialized.

    Attributes:
        field_path: dotted path to the offending value ("" for the root),
            e.g. "protected.recipients[0]". Never contains secret values.
        code: stable machine-readable reason code.
    """

    def __init__(self, field_path: str, code: str) -> None:
        self.field_path = field_path
        self.code = code
        super().__init__(f"{field_path or '<root>'}: {code}")


# Short escapes mandated by the plan: backspace, tab, LF, FF, CR.
_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _encode_string(value: str, path: str) -> bytes:
    for ch in value:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise CanonicalizationError(path, "unpaired_surrogate")
    parts: list[str] = ['"']
    for ch in value:
        esc = _SHORT_ESCAPES.get(ch)
        if esc is not None:
            parts.append(esc)
            continue
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7F:
            # Lowercase \u00xx per RFC 8785.
            parts.append("\\u%04x" % cp)
        else:
            # Non-ASCII passes through literally (no normalization).
            parts.append(ch)
    parts.append('"')
    return "".join(parts).encode("utf-8")


def _encode(value: Any, path: str, out: bytearray) -> None:
    if value is None:
        out += b"null"
    elif value is True:
        out += b"true"
    elif value is False:
        out += b"false"
    elif isinstance(value, int):
        if not (SAFE_INT_MIN <= value <= SAFE_INT_MAX):
            raise CanonicalizationError(path, "integer_out_of_range")
        out += str(value).encode("ascii")
    elif isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(path, "nan_or_infinity")
        raise CanonicalizationError(path, "float_number")
    elif isinstance(value, str):
        out += _encode_string(value, path)
    elif isinstance(value, dict):
        keys = list(value.keys())
        for key in keys:
            if not isinstance(key, str):
                raise CanonicalizationError(path, "invalid_key_type")
            if not key.isascii():
                raise CanonicalizationError(path, "non_ascii_key")
        if len(set(keys)) != len(keys):
            raise CanonicalizationError(path, "duplicate_key")
        out += b"{"
        first = True
        # Keys are ASCII, so sorting by UTF-8 bytes equals byte-value order.
        for key in sorted(keys, key=lambda k: k.encode("ascii")):
            if not first:
                out += b","
            first = False
            child = f"{path}.{key}" if path else key
            out += _encode_string(key, child)
            out += b":"
            _encode(value[key], child, out)
        out += b"}"
    elif isinstance(value, (list, tuple)):
        out += b"["
        for i, item in enumerate(value):
            if i:
                out += b","
            _encode(item, f"{path}[{i}]", out)
        out += b"]"
    else:
        raise CanonicalizationError(path, "unsupported_type")


def restricted_jcs(obj: Any) -> bytes:
    """Serialize *obj* to canonical bytes under the restricted JCS profile.

    Raises:
        CanonicalizationError: with a stable code and field path when the
            input violates the profile. Never leaks values.
    """
    out = bytearray()
    _encode(obj, "", out)
    return bytes(out)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, val in pairs:
        if key in result:
            raise CanonicalizationError("", "duplicate_key")
        result[key] = val
    return result


def _reject_constant(text: str) -> Any:
    raise CanonicalizationError("", "nan_or_infinity")


def strict_parse(data: bytes) -> Any:
    """Parse JSON bytes, rejecting duplicate keys and non-finite constants.

    Used before schema validation so malformed sealed objects fail early.
    Floats are preserved as Python floats here; ``restricted_jcs`` rejects
    them (including exponent-form numbers, which parse as floats).

    Raises:
        CanonicalizationError: "invalid_utf8", "duplicate_key",
            "nan_or_infinity", "too_deeply_nested", or "invalid_json".
        TypeError: if *data* is not bytes.
    """
    if not isinstance(data, bytes):
        raise TypeError("strict_parse requires bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise CanonicalizationError("", "invalid_utf8") from None
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except CanonicalizationError:
        raise
    except RecursionError as exc:
        # json raises RecursionError (not JSONDecodeError) on deeply nested
        # input. Convert it so hostile nesting can never escape as an
        # unhandled exception past callers' error handling.
        raise CanonicalizationError("", "too_deeply_nested") from exc
    except json.JSONDecodeError as exc:
        raise CanonicalizationError("", "invalid_json") from exc
