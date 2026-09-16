"""State directory resolution and config.yaml handling.

Config files carry paths, defaults, and identity references only. Secret
values (seeds, private keys, tokens, passwords) are never written inline;
only key references or filesystem paths may appear.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

APP_DIR_NAME = "muse-agent-social"
CONFIG_FILENAME = "config.yaml"

DEFAULT_POLL_INTERVAL_SECONDS = 30
DEFAULT_PUSH_CEILING_PER_MINUTE = 6
CONFIG_VERSION = 1

# Keys that may never hold a secret value inline in config.yaml. Reference
# style keys ending in _ref or _path are allowed (they point at material,
# they are not the material).
_SECRET_KEY_DENYLIST = frozenset(
    {
        "master_seed",
        "private_key",
        "secret",
        "password",
        "token",
        "api_key",
        "seed",
        "deploy_private_key",
    }
)
_SECRET_KEY_SUFFIXES = ("_secret", "_password", "_token", "_seed", "_private_key")


def resolve_state_dir() -> Path:
    """Return the state directory for this installation.

    Precedence: MAS_HOME env var, else XDG_DATA_HOME/muse-agent-social,
    else ~/.local/share/muse-agent-social. No path is hardcoded; the home
    fallback derives from the OS user database via Path.home().
    """
    mas_home = os.environ.get("MAS_HOME")
    if mas_home:
        return Path(mas_home).expanduser()
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home).expanduser() / APP_DIR_NAME
    return Path.home() / ".local" / "share" / APP_DIR_NAME


def default_config() -> dict[str, Any]:
    """Return the default config document (no secrets, references only)."""
    return {
        "config_version": CONFIG_VERSION,
        "identity_ref": "",
        "relay": {
            "poll_interval_seconds": DEFAULT_POLL_INTERVAL_SECONDS,
            "push_ceiling_per_minute": DEFAULT_PUSH_CEILING_PER_MINUTE,
        },
        "retention": {
            "mode": "encrypted",
        },
    }


def load_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load and lightly validate config.yaml.

    Raises FileNotFoundError when the file does not exist and ValueError
    when it cannot be parsed or fails validation.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"config file not found: {path}")
    try:
        obj = _parse_yaml(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"cannot parse config file {path}: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError(f"config file {path} must contain a mapping at top level")
    _assert_no_secrets(obj)
    _validate_config(obj)
    return obj


def save_config(path: str | os.PathLike[str], obj: dict[str, Any]) -> None:
    """Write obj to config.yaml, refusing any inline secret values.

    Raises ValueError when obj contains a forbidden secret-bearing key or
    a value type the restricted YAML writer cannot represent.
    """
    if not isinstance(obj, dict):
        raise ValueError("config must be a mapping")
    _assert_no_secrets(obj)
    text = _dump_yaml(obj)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write atomically with owner-only permissions: config lives next to
    # key material and must never be left world-readable or half-written.
    from ._keyfiles import atomic_write_file

    atomic_write_file(path, text.encode("utf-8"), 0o600)


def _validate_config(obj: dict[str, Any]) -> None:
    relay = obj.get("relay", {})
    if not isinstance(relay, dict):
        raise ValueError("config 'relay' section must be a mapping")
    poll = relay.get("poll_interval_seconds", DEFAULT_POLL_INTERVAL_SECONDS)
    ceiling = relay.get("push_ceiling_per_minute", DEFAULT_PUSH_CEILING_PER_MINUTE)
    if not isinstance(poll, int) or poll <= 0:
        raise ValueError("relay.poll_interval_seconds must be a positive integer")
    if not isinstance(ceiling, int) or ceiling <= 0:
        raise ValueError("relay.push_ceiling_per_minute must be a positive integer")


def _assert_no_secrets(obj: Any, trail: str = "") -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            name = str(key).lower()
            location = f"{trail}.{key}" if trail else str(key)
            if name.endswith(("_ref", "_path")):
                continue
            if name in _SECRET_KEY_DENYLIST or name.endswith(_SECRET_KEY_SUFFIXES):
                raise ValueError(
                    f"config must not contain secret values inline "
                    f"(offending key: {location}); store a reference or path instead"
                )
            _assert_no_secrets(value, location)
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            _assert_no_secrets(value, f"{trail}[{index}]")


# --- Restricted YAML subset -------------------------------------------------
# The venv intentionally has no PyYAML dependency, so config.py ships a small
# writer and reader for the subset config.yaml uses: nested mappings,
# sequences, and scalar values (str, int, bool, None). Anything outside that
# subset raises ValueError instead of being guessed.

_INT_RE = re.compile(r"-?\d+")
_NEEDS_QUOTE_RE = re.compile(r"^(?:-?\d+|true|false|null|~)$", re.IGNORECASE)
_SPECIAL_CHARS = set(":#{}[],&*!|>'\"%@`")


def _quote_scalar(text: str) -> str:
    if text == "":
        return '""'
    needs = (
        _NEEDS_QUOTE_RE.match(text) is not None
        or text != text.strip()
        or text[0] in "-?:,[]{}#&*!|>'\"%@`"
        or any(c in _SPECIAL_CHARS or c in "\n\r\t" for c in text)
        or ": " in text
        or " #" in text
    )
    if not needs:
        return text
    escaped = (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _dump_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _quote_scalar(value)
    raise ValueError(f"unsupported config value type: {type(value).__name__}")


def _dump_yaml(obj: dict[str, Any]) -> str:
    lines: list[str] = []
    _emit_mapping(obj, 0, lines)
    return "\n".join(lines) + "\n"


def _emit_mapping(mapping: dict[str, Any], indent: int, lines: list[str]) -> None:
    pad = "  " * indent
    if not mapping:
        lines.append(pad + "{}")
        return
    for key, value in mapping.items():
        if not isinstance(key, str):
            raise ValueError("config keys must be strings")
        rendered_key = _quote_scalar(key)
        if isinstance(value, dict):
            lines.append(f"{pad}{rendered_key}:")
            _emit_mapping(value, indent + 1, lines)
        elif isinstance(value, list):
            lines.append(f"{pad}{rendered_key}:")
            _emit_sequence(value, indent + 1, lines)
        else:
            lines.append(f"{pad}{rendered_key}: {_dump_scalar(value)}")


def _emit_sequence(seq: list[Any], indent: int, lines: list[str]) -> None:
    pad = "  " * indent
    if not seq:
        lines.append(pad + "[]")
        return
    for value in seq:
        if isinstance(value, dict):
            lines.append(f"{pad}-")
            _emit_mapping(value, indent + 1, lines)
        elif isinstance(value, list):
            lines.append(f"{pad}-")
            _emit_sequence(value, indent + 1, lines)
        else:
            lines.append(f"{pad}- {_dump_scalar(value)}")


def _strip_comment(line: str) -> str:
    out: list[str] = []
    in_single = in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            if not (in_double and i > 0 and line[i - 1] == "\\"):
                in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in " \t":
                break
        out.append(ch)
        i += 1
    return "".join(out)


def _unescape(text: str, quote: str) -> str:
    if quote == "'":
        return text.replace("''", "'")
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append(
                {
                    "n": "\n",
                    "r": "\r",
                    "t": "\t",
                    "\\": "\\",
                    '"': '"',
                    "0": "\0",
                }.get(nxt, nxt)
            )
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _parse_scalar(token: str) -> Any:
    text = token.strip()
    if text in ("", "~", "null", "Null", "NULL"):
        return None
    if text in ("true", "True", "TRUE"):
        return True
    if text in ("false", "False", "FALSE"):
        return False
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return _unescape(text[1:-1], text[0])
    if _INT_RE.fullmatch(text):
        return int(text)
    return text


def _parse_yaml(text: str) -> Any:
    raw_lines = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw).rstrip()
        if stripped.strip():
            raw_lines.append(stripped)
    if not raw_lines:
        return {}
    value, pos = _parse_block(raw_lines, 0, -1)
    if pos != len(raw_lines):
        raise ValueError(f"unexpected content at line {pos + 1}")
    return value


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_block(lines: list[str], pos: int, parent_indent: int) -> tuple[Any, int]:
    if pos >= len(lines) or _indent_of(lines[pos]) <= parent_indent:
        raise ValueError(f"expected block at line {pos + 1}")
    indent = _indent_of(lines[pos])
    first = lines[pos].strip()
    if first.startswith("- ") or first == "-":
        return _parse_sequence(lines, pos, indent)
    return _parse_mapping(lines, pos, indent)


def _parse_mapping(lines: list[str], pos: int, indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while pos < len(lines):
        line = lines[pos]
        if _indent_of(line) != indent:
            break
        content = line.strip()
        if content.startswith("- ") or content == "-":
            break
        if ":" not in content:
            raise ValueError(f"invalid mapping line {pos + 1}: {content!r}")
        key_token, _, value_token = content.partition(":")
        key = _parse_scalar(key_token)
        if not isinstance(key, str):
            raise ValueError(f"config keys must be strings (line {pos + 1})")
        value_token = value_token.strip()
        pos += 1
        if value_token == "":
            if pos < len(lines) and _indent_of(lines[pos]) > indent:
                value, pos = _parse_block(lines, pos, indent)
            else:
                value = None
        elif value_token in ("{}",):
            value = {}
        elif value_token in ("[]",):
            value = []
        else:
            value = _parse_scalar(value_token)
        mapping[key] = value
    return mapping, pos


def _parse_sequence(lines: list[str], pos: int, indent: int) -> tuple[list[Any], int]:
    seq: list[Any] = []
    while pos < len(lines):
        line = lines[pos]
        if _indent_of(line) != indent:
            break
        content = line.strip()
        if not (content.startswith("- ") or content == "-"):
            break
        item_token = content[1:].strip()
        pos += 1
        if item_token == "":
            if pos < len(lines) and _indent_of(lines[pos]) > indent:
                value, pos = _parse_block(lines, pos, indent)
            else:
                value = None
            seq.append(value)
        elif item_token in ("{}",):
            seq.append({})
        elif item_token in ("[]",):
            seq.append([])
        else:
            seq.append(_parse_scalar(item_token))
    return seq, pos
