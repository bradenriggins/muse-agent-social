"""Runtime validation for Muse Agent Social v0.2 schemas.

Validates plain Python objects (already parsed with
``canonical.strict_parse``, so duplicate keys are rejected before this runs)
against the JSON Schema draft 2020-12 schemas in ``schemas/``.

Validation errors expose only the field path and a stable error code, never
secret values or payload content.
"""

from __future__ import annotations

import json
import os
from collections import deque
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema.exceptions import best_match
from referencing import Registry, Resource

__all__ = [
    "MAX_ENVELOPE_BYTES",
    "ValidationError",
    "validate",
    "validate_payload",
    "check_envelope_size",
    "PAYLOAD_DISPATCH",
]

# Whole sealed envelope, UTF-8 encoded, is at most 262,144 bytes.
MAX_ENVELOPE_BYTES = 262144


class ValidationError(Exception):
    """A schema or size check failed.

    Attributes:
        field_path: dotted path to the offending field, e.g.
            "protected.event_id" or "recipients[0].wrap_nonce". Empty for
            whole-object failures. Never contains values.
        code: stable machine-readable reason code.
    """

    def __init__(self, field_path: str, code: str) -> None:
        self.field_path = field_path
        self.code = code
        super().__init__(f"{field_path or '<root>'}: {code}")


def _schemas_dir() -> Path:
    override = os.environ.get("MAS_SCHEMAS_DIR")
    if override:
        return Path(override)
    # Track/final layout: schemas/ sits at the repository root, two levels
    # above this file's package directory.
    return Path(__file__).resolve().parent.parent.parent / "schemas"


def _build_registry(schemas_dir: Path) -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in sorted(schemas_dir.rglob("*.schema.json")):
        rel = path.relative_to(schemas_dir).as_posix()
        schema = json.loads(path.read_text(encoding="utf-8"))
        uri = f"https://muse-agent-social/schemas/{rel}"
        resources.append((uri, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _validator_for(schema_name: str) -> jsonschema.Draft202012Validator:
    schemas_dir = _schemas_dir()
    candidate = schemas_dir / f"{schema_name}.schema.json"
    if not candidate.is_file():
        raise ValidationError("", "unknown_schema")
    schema = json.loads(candidate.read_text(encoding="utf-8"))
    registry = _build_registry(schemas_dir)
    return jsonschema.Draft202012Validator(schema, registry=registry)


def _field_path(error: jsonschema.ValidationError) -> str:
    parts: list[str] = []
    for bit in error.absolute_path:
        if isinstance(bit, int):
            parts.append(f"[{bit}]")
        else:
            if parts:
                parts.append(".")
            parts.append(str(bit))
    path = "".join(parts)
    if error.validator == "required":
        missing = error.message.split("'")[1] if "'" in error.message else ""
        path = f"{path}.{missing}" if path else missing
    elif error.validator == "additionalProperties":
        extra = error.message.split("'")[1] if "'" in error.message else ""
        path = f"{path}.{extra}" if path else extra
    return path


_CODE_BY_VALIDATOR = {
    "type": "type",
    "required": "required",
    "additionalProperties": "additional_property",
    "pattern": "pattern",
    "format": "format",
    "enum": "enum",
    "const": "const",
    "minimum": "minimum",
    "maximum": "maximum",
    "exclusiveMinimum": "exclusive_minimum",
    "exclusiveMaximum": "exclusive_maximum",
    "minLength": "min_length",
    "maxLength": "max_length",
    "minItems": "min_items",
    "maxItems": "max_items",
    "uniqueItems": "unique_items",
    "minProperties": "min_properties",
    "maxProperties": "max_properties",
    "multipleOf": "multiple_of",
    "anyOf": "no_variant_matched",
    "oneOf": "no_variant_matched",
    "allOf": "all_of_failed",
    "not": "not_allowed",
    "contains": "contains",
    "minContains": "min_contains",
    "maxContains": "max_contains",
    "dependentRequired": "required",
    "propertyNames": "property_name",
    "if": "condition_failed",
}


def _validate_with(
    validator: jsonschema.Draft202012Validator, obj: Any
) -> None:
    errors = list(validator.iter_errors(obj))
    if not errors:
        return
    error = best_match(errors)
    path = _field_path(error)
    code = _CODE_BY_VALIDATOR.get(error.validator, error.validator)
    raise ValidationError(path, code)


def validate(schema_name: str, obj: Any) -> None:
    """Validate *obj* against the named schema.

    *schema_name* is the schema file path relative to ``schemas/`` without
    the ``.schema.json`` suffix, e.g. ``"event-envelope"``,
    ``"agent-card"``, ``"payloads/message"``.

    Raises:
        ValidationError: with field_path and stable code on failure.
    """
    _validate_with(_validator_for(schema_name), obj)


# event_type -> (payload schema name, $defs variant) for decrypted payloads.
PAYLOAD_DISPATCH: dict[str, tuple[str, str]] = {
    "message.created": ("payloads/message", "created"),
    "message.edited": ("payloads/message", "edited"),
    "message.retracted": ("payloads/message", "retracted"),
    "reaction.added": ("payloads/reaction", "added"),
    "reaction.removed": ("payloads/reaction", "removed"),
    "receipt.accepted": ("payloads/receipt", "accepted"),
    "receipt.seen": ("payloads/receipt", "seen"),
    "poll.created": ("payloads/poll", "created"),
    "poll.responded": ("payloads/poll", "responded"),
    "task.created": ("payloads/task", "created"),
    "task.updated": ("payloads/task", "updated"),
    "human.requested": ("payloads/human", "requested"),
    "human.responded": ("payloads/human", "responded"),
    "delivery.scheduled": ("payloads/delivery", "scheduled"),
    "delivery.canceled": ("payloads/delivery", "canceled"),
    "security.key.prepare": ("payloads/security", "prepare"),
    "security.key.ack": ("payloads/security", "ack"),
    "security.key.confirm": ("payloads/security", "confirm"),
    "security.key.commit": ("payloads/security", "commit"),
    # Payloads defined in event-envelope $defs (no standalone file).
    "relationship.ready": ("event-envelope", "payloads/relationship_ready"),
    "migration.ready": ("event-envelope", "payloads/migration_ready"),
    "migration.commit": ("event-envelope", "payloads/migration_commit"),
}


def _validate_defs_variant(
    schema_name: str, defs_path: str, obj: Any
) -> None:
    schemas_dir = _schemas_dir()
    schema = json.loads(
        (schemas_dir / f"{schema_name}.schema.json").read_text(encoding="utf-8")
    )
    node: Any = schema
    for bit in defs_path.split("/"):
        node = node[bit]
    registry = _build_registry(schemas_dir)
    validator = jsonschema.Draft202012Validator(node, registry=registry)
    _validate_with(validator, obj)


def _check_emoji(obj: Any) -> None:
    emoji = obj.get("emoji")
    if not isinstance(emoji, str):
        return
    if len(emoji.encode("utf-8")) > 32:
        raise ValidationError("emoji", "too_long_bytes")


def _check_poll_choices(obj: Any) -> None:
    choices = obj.get("choices")
    if not isinstance(choices, list):
        return
    for i, choice in enumerate(choices):
        if isinstance(choice, str) and len(choice.encode("utf-8")) > 120:
            raise ValidationError(f"choices[{i}]", "too_long_bytes")


def validate_payload(event_type: str, payload: Any) -> None:
    """Validate a decrypted typed payload for *event_type*.

    Dispatches on the protected event_type to the matching payload variant
    schema, then enforces byte-length constraints the JSON Schema cannot
    express (emoji at most 32 UTF-8 bytes, poll choices at most 120 UTF-8
    bytes each).

    Raises:
        ValidationError: with field_path and stable code on failure.
    """
    dispatch = PAYLOAD_DISPATCH.get(event_type)
    if dispatch is None:
        raise ValidationError("event_type", "unknown_event_type")
    schema_name, defs_variant = dispatch
    _validate_defs_variant(schema_name, f"$defs/{defs_variant}", payload)
    if event_type in ("reaction.added", "reaction.removed"):
        _check_emoji(payload)
    elif event_type == "poll.created":
        _check_poll_choices(payload)


def check_envelope_size(data: bytes) -> None:
    """Reject sealed envelopes larger than 262,144 bytes.

    Call on the raw UTF-8 bytes before parse or decrypt.

    Raises:
        ValidationError: ("", "envelope_too_large") when over the limit.
        TypeError: if *data* is not bytes.
    """
    if not isinstance(data, bytes):
        raise TypeError("check_envelope_size requires bytes")
    if len(data) > MAX_ENVELOPE_BYTES:
        raise ValidationError("", "envelope_too_large")
