"""Unit tests for the restricted JCS profile.

Covers every required canonicalization test from the plan:
RFC 8785 primitive example, recursive sorting, object inside array,
control-character escaping, literal non-ASCII output, empty objects/arrays,
plus every rejection case: duplicate keys, float/exponent form, out-of-range
integers, non-ASCII keys, lone surrogates, invalid UTF-8, NaN/Infinity.
"""

import json
import math
from pathlib import Path

import pytest

from muse_agent_social.canonical import (
    SAFE_INT_MAX,
    SAFE_INT_MIN,
    CanonicalizationError,
    restricted_jcs,
    strict_parse,
)

FIXTURES = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "canonical_vectors.json")
    .read_text(encoding="utf-8")
)


def test_golden_vectors_match_expected_bytes():
    assert FIXTURES, "no golden vectors committed"
    for vector in FIXTURES:
        got = restricted_jcs(vector["input"])
        assert got.hex() == vector["expected_hex"], vector["name"]
        assert isinstance(got, bytes)


def test_golden_vector_names_cover_plan_cases():
    names = {v["name"] for v in FIXTURES}
    required = {
        "rfc8785_primitive_example",
        "recursive_sorting",
        "object_in_array",
        "control_escaping",
        "non_ascii_passthrough",
        "empty_object",
        "empty_array",
        "int_boundaries",
    }
    assert required <= names


def test_rfc8785_primitive_example_exact():
    assert restricted_jcs({"b": True, "a": 1, "d": "text", "c": None}) == (
        b'{"a":1,"b":true,"c":null,"d":"text"}'
    )


def test_recursive_sorting_exact():
    assert restricted_jcs({"z": {"b": 2, "a": 1}, "a": 0}) == (
        b'{"a":0,"z":{"a":1,"b":2}}'
    )


def test_object_inside_array_sorted_array_order_preserved():
    assert restricted_jcs({"k": [{"b": 1, "a": 2}, "z", 1]}) == (
        b'{"k":[{"a":2,"b":1},"z",1]}'
    )


def test_control_escaping_short_and_long_forms():
    # short escapes: \b \t \n \f \r ; other controls: lowercase \u00xx
    assert restricted_jcs("\b\t\n\f\r\x00\x1f\x7f") == (
        b'"\\b\\t\\n\\f\\r\\u0000\\u001f\\u007f"'
    )


def test_quote_and_backslash_escaped():
    assert restricted_jcs('a"b\\c') == b'"a\\"b\\\\c"'


def test_non_ascii_passthrough_literal():
    out = restricted_jcs("héllo→世界")
    assert out == '"héllo→世界"'.encode("utf-8")
    assert b"\\u" not in out


def test_no_unicode_normalization():
    composed = "é"  # U+00E9
    decomposed = "é"  # U+0065 U+0301
    assert restricted_jcs(composed) != restricted_jcs(decomposed)


def test_empty_objects_and_arrays():
    assert restricted_jcs({}) == b"{}"
    assert restricted_jcs([]) == b"[]"
    assert restricted_jcs({"a": {}}) == b'{"a":{}}'
    assert restricted_jcs({"a": []}) == b'{"a":[]}'


def test_int_boundaries_accepted():
    assert restricted_jcs(SAFE_INT_MAX) == b"9007199254740991"
    assert restricted_jcs(SAFE_INT_MIN) == b"-9007199254740991"
    assert restricted_jcs(0) == b"0"


def test_byte_value_key_sorting():
    assert restricted_jcs({"~": 1, "!": 2, "A": 3, "a": 4}) == (
        b'{"!":2,"A":3,"a":4,"~":1}'
    )


def test_no_whitespace_anywhere():
    out = restricted_jcs({"a": [1, {"b": 2}]})
    assert out == b'{"a":[1,{"b":2}]}'
    assert b" " not in out and b"\n" not in out


def test_deterministic_across_key_insertion_orders():
    obj1 = {"z": 1, "a": 2, "m": 3}
    obj2 = {"a": 2, "m": 3, "z": 1}
    assert restricted_jcs(obj1) == restricted_jcs(obj2)


def test_tuple_serializes_as_array():
    assert restricted_jcs((1, 2)) == b"[1,2]"


# Rejection cases


def test_reject_duplicate_keys_at_parse():
    with pytest.raises(CanonicalizationError) as exc:
        strict_parse(b'{"a":1,"a":2}')
    assert exc.value.code == "duplicate_key"


def test_reject_duplicate_keys_nested():
    with pytest.raises(CanonicalizationError) as exc:
        strict_parse(b'{"x":{"a":1,"a":2}}')
    assert exc.value.code == "duplicate_key"


def test_reject_float():
    with pytest.raises(CanonicalizationError) as exc:
        restricted_jcs(1.5)
    assert exc.value.code == "float_number"
    assert exc.value.field_path == ""


def test_reject_float_inside_object_reports_path():
    with pytest.raises(CanonicalizationError) as exc:
        restricted_jcs({"protected": {"sender_seq": 1.0}})
    assert exc.value.code == "float_number"
    assert exc.value.field_path == "protected.sender_seq"


def test_reject_exponent_form_number():
    parsed = strict_parse(b'{"n":1e3}')
    assert isinstance(parsed["n"], float)
    with pytest.raises(CanonicalizationError) as exc:
        restricted_jcs(parsed)
    assert exc.value.code == "float_number"


def test_reject_integer_out_of_range():
    for bad in (SAFE_INT_MAX + 1, SAFE_INT_MIN - 1, 2**64):
        with pytest.raises(CanonicalizationError) as exc:
            restricted_jcs({"n": bad})
        assert exc.value.code == "integer_out_of_range"
        assert exc.value.field_path == "n"


def test_reject_non_ascii_key():
    with pytest.raises(CanonicalizationError) as exc:
        restricted_jcs({"clé": 1})
    assert exc.value.code == "non_ascii_key"


def test_reject_lone_surrogate_in_string():
    with pytest.raises(CanonicalizationError) as exc:
        restricted_jcs("a\ud800b")
    assert exc.value.code == "unpaired_surrogate"


def test_reject_lone_surrogate_from_json_escape():
    parsed = strict_parse('{"s":"\\ud800"}'.encode("ascii"))
    with pytest.raises(CanonicalizationError) as exc:
        restricted_jcs(parsed)
    assert exc.value.code == "unpaired_surrogate"
    assert exc.value.field_path == "s"


def test_reject_invalid_utf8():
    with pytest.raises(CanonicalizationError) as exc:
        strict_parse(b"\xff\xfe not json")
    assert exc.value.code == "invalid_utf8"


def test_reject_nan_and_infinity_at_parse():
    for raw in (b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}'):
        with pytest.raises(CanonicalizationError) as exc:
            strict_parse(raw)
        assert exc.value.code == "nan_or_infinity"


def test_reject_nan_infinity_objects():
    for bad in (math.nan, math.inf, -math.inf):
        with pytest.raises(CanonicalizationError) as exc:
            restricted_jcs(bad)
        assert exc.value.code == "nan_or_infinity"


def test_reject_unsupported_types():
    for bad in (b"bytes", object(), {"a"}, 1j):
        with pytest.raises(CanonicalizationError) as exc:
            restricted_jcs(bad)
        assert exc.value.code == "unsupported_type"


def test_reject_invalid_json():
    with pytest.raises(CanonicalizationError) as exc:
        strict_parse(b'{"a": }')
    assert exc.value.code == "invalid_json"


def test_strict_parse_requires_bytes():
    with pytest.raises(TypeError):
        strict_parse('{"a":1}')


def test_strict_parse_round_trip_valid():
    obj = strict_parse(b'{"b":[1,2],"a":null}')
    assert obj == {"a": None, "b": [1, 2]}
    assert restricted_jcs(obj) == b'{"a":null,"b":[1,2]}'


def test_errors_never_leak_values():
    secret = "super-secret-value-xyz"
    try:
        restricted_jcs({"k": secret + "\ud800"})
    except CanonicalizationError as exc:
        assert secret not in str(exc)
        assert secret not in exc.code
        assert secret not in exc.field_path
    else:
        pytest.fail("expected CanonicalizationError")
