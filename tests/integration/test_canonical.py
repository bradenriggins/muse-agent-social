"""Gate: Canonicalization.

Restricted JCS profile: RFC 8785 vectors (recursive key sorting, nested
arrays preserving order, control-character escaping, literal non-ASCII,
empty containers) produce exact expected bytes; profile violations
(floats, exponent form, out-of-range integers, non-ASCII keys, duplicate
keys, lone surrogates) are rejected with stable codes.
"""

import pytest

from muse_agent_social.canonical import (
    SAFE_INT_MAX,
    SAFE_INT_MIN,
    CanonicalizationError,
    restricted_jcs,
    strict_parse,
)


def canon(obj) -> bytes:
    return restricted_jcs(obj)


# -- RFC 8785 vectors: exact bytes ---------------------------------------------


def test_rfc8785_primitive_example():
    # RFC 8785 section 3.2.3: keys sorted, no whitespace.
    assert canon({"1": 2, "3": 4}) == b'{"1":2,"3":4}'


def test_rfc8785_recursive_object_sorting():
    assert (
        canon({"z": 1, "a": {"y": 2, "b": 3}, "m": 4})
        == b'{"a":{"b":3,"y":2},"m":4,"z":1}'
    )


def test_rfc8785_nested_arrays_preserve_order():
    # Array order is preserved; objects inside arrays are sorted.
    assert (
        canon({"a": [3, 2, 1, {"z": 1, "a": 2}]})
        == b'{"a":[3,2,1,{"a":2,"z":1}]}'
    )


def test_rfc8785_deeply_nested_arrays():
    assert (
        canon({"a": [1, {"b": [2, {"c": [3, {"d": 4}]}]}]})
        == b'{"a":[1,{"b":[2,{"c":[3,{"d":4}]}]}]}'
    )


def test_rfc8785_control_character_escaping():
    # Short escapes for backspace, tab, LF, FF, CR; lowercase \u00xx
    # otherwise. This matches RFC 8785 section 3.2.2.2.
    assert (
        canon({"a": "\u0001\u0002\b\t\n\x0c\r\"\\"})
        == b'{"a":"\\u0001\\u0002\\b\\t\\n\\f\\r\\"\\\\"}'
    )


def test_rfc8785_del_escaped():
    assert canon({"a": "\u007f"}) == b'{"a":"\\u007f"}'


def test_rfc8785_literal_non_ascii_output():
    # No normalization; non-ASCII passes through literally as UTF-8.
    expected = b'{"a":"' + "caf\u00e9\u4e2d".encode("utf-8") + b'"}'
    assert canon({"a": "caf\u00e9\u4e2d"}) == expected


def test_rfc8785_empty_objects_and_arrays():
    assert canon({}) == b"{}"
    assert canon([]) == b"[]"
    assert canon({"a": {}, "b": []}) == b'{"a":{},"b":[]}'


def test_rfc8785_literals():
    assert canon({"a": None, "b": True, "c": False, "d": 0}) == (
        b'{"a":null,"b":true,"c":false,"d":0}'
    )


def test_integer_boundaries_exact():
    assert canon({"n": SAFE_INT_MIN}) == b'{"n":-9007199254740991}'
    assert canon({"n": SAFE_INT_MAX}) == b'{"n":9007199254740991}'
    assert SAFE_INT_MIN == -9007199254740991
    assert SAFE_INT_MAX == 9007199254740991


def test_canonical_bytes_are_stable_across_key_insertion_order():
    a = {"z": 1, "a": 2, "m": {"y": 1, "b": 2}}
    b = {"m": {"b": 2, "y": 1}, "a": 2, "z": 1}
    assert canon(a) == canon(b)


def test_strict_parse_round_trip_is_idempotent():
    obj = {"b": [1, {"d": 4, "c": 3}], "a": "x"}
    once = canon(obj)
    assert canon(strict_parse(once)) == once


# -- profile violations ---------------------------------------------------------


def test_reject_float():
    with pytest.raises(CanonicalizationError) as exc:
        canon({"n": 1.5})
    assert exc.value.code == "float_number"


def test_reject_exponent_form():
    # 1e2 parses as a float, so it is rejected even though it is integral.
    with pytest.raises(CanonicalizationError) as exc:
        canon(strict_parse(b'{"n": 1e2}'))
    assert exc.value.code == "float_number"


def test_reject_integer_outside_safe_range():
    for n in (SAFE_INT_MAX + 1, SAFE_INT_MIN - 1, 2**64):
        with pytest.raises(CanonicalizationError) as exc:
            canon({"n": n})
        assert exc.value.code == "integer_out_of_range"


def test_reject_non_ascii_property_key():
    with pytest.raises(CanonicalizationError) as exc:
        canon({"caf\u00e9": 1})
    assert exc.value.code == "non_ascii_key"


def test_reject_lone_surrogate():
    with pytest.raises(CanonicalizationError) as exc:
        canon({"a": "\ud800"})
    assert exc.value.code == "unpaired_surrogate"


def test_reject_duplicate_keys_in_canonicalizer():
    # Python dicts cannot hold duplicates; the parser is the dupe gate.
    with pytest.raises(CanonicalizationError) as exc:
        strict_parse(b'{"a":1,"a":2}')
    assert exc.value.code == "duplicate_key"


def test_reject_nan_and_infinity_constants():
    for raw in (b'{"n": NaN}', b'{"n": Infinity}', b'{"n": -Infinity}'):
        with pytest.raises(CanonicalizationError) as exc:
            strict_parse(raw)
        assert exc.value.code == "nan_or_infinity"


def test_reject_invalid_utf8():
    with pytest.raises(CanonicalizationError) as exc:
        strict_parse(b'{"a": "\xff"}')
    assert exc.value.code == "invalid_utf8"


def test_reject_unsupported_type():
    with pytest.raises(CanonicalizationError) as exc:
        canon({"a": {1, 2}})
    assert exc.value.code == "unsupported_type"


def test_error_carries_path_not_value():
    with pytest.raises(CanonicalizationError) as exc:
        canon({"outer": {"inner": 1.5}})
    assert exc.value.field_path == "outer.inner"
    assert exc.value.code == "float_number"
    assert "1.5" not in str(exc.value)
