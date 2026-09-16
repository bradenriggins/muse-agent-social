"""Receiver-owned per-relationship delivery policy.

Modes (locked by the v0.2 plan, RECEIVER CONTROL):

    silent         Persist accepted events; no proactive surface. The sender
                   learns only an accepted receipt, and only if accepted
                   receipts are enabled.
    digest         Queue accepted events for the local digest cadence. The
                   sender learns nothing about the cadence.
    alert          Surface promptly through the local agent. The sender learns
                   nothing about the alert channel.
    feed_eligible  Allow local curation to consider the event. No Feed
                   placement is guaranteed.

Ownership rules:

* Only the receiver may change these settings, through the local setters
  in this module. There is deliberately no remote path: no event type can
  mutate delivery policy, and there is no seam that accepts a remote
  mutation (the former apply_remote_policy_request() was dead code and
  was removed in v0.2 hardening).
* Every setter bumps the policy version. Every decision helper returns the
  policy version it used, so callers can store it with the decision (for
  example in surface_queue.policy_snapshot, per the plan's requirement
  that every policy decision stores the relationship policy version used).
* receipt.seen defaults to OFF and is sent only when the receiver enables
  it AND a human-visible view actually opened.

The policy record lives inside the relationships.policy JSON document under
the "delivery" key, so no schema change is needed. A relationship that has
never set a policy reports the implicit default (silent, version 0).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Mapping, NoReturn

from muse_agent_social.policy.limits import (
    add_seconds,
    parse_canonical_utc,
)
from muse_agent_social.store.db import transaction, utcnow

__all__ = [
    "DELIVERY_MODES",
    "DEFAULT_DELIVERY_MODE",
    "EXPIRY_HANDLINGS",
    "DeliveryPolicy",
    "ExpiryDecision",
    "PolicyError",
    "UnknownRelationshipError",
    "get_policy",
    "set_policy",
    "set_seen_receipts_enabled",
    "set_accepted_receipts_enabled",
    "set_expiry_policy",
    "should_send_seen_receipt",
    "accepted_receipt_permitted",
    "surface_action",
    "policy_snapshot",
    "snapshot_to_action",
    "apply_expiry",
]

DELIVERY_MODES = ("silent", "digest", "alert", "feed_eligible")
DEFAULT_DELIVERY_MODE = "silent"

# Receiver-side handling of a sender expires_at request.
EXPIRY_HANDLINGS = ("honor", "ignore", "shorten")

_SURFACE_ACTION_BY_MODE = {
    "silent": "persist_only",
    "digest": "queue_digest",
    "alert": "surface_promptly",
    "feed_eligible": "consider_feed",
}

_DELIVERY_KEY = "delivery"


class PolicyError(Exception):
    """Base error for delivery-policy failures. Carries a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class UnknownRelationshipError(PolicyError):
    """No such relationship in the local store."""

    def __init__(self, relationship_id: str) -> None:
        super().__init__("unknown_relationship", relationship_id)


@dataclass(frozen=True)
class DeliveryPolicy:
    """The receiver-owned delivery policy for one relationship."""

    mode: str
    version: int
    updated_at: str | None
    seen_receipts_enabled: bool
    accepted_receipts_enabled: bool
    expiry_handling: str
    expiry_shorten_after_seconds: int | None


@dataclass(frozen=True)
class ExpiryDecision:
    """Outcome of applying receiver expiry policy to one event."""

    suppress: bool
    effective_expires_at: str | None
    reason: str
    policy_version: int
    # Suppression hides content from the active projection. The signed
    # envelope is always retained under the encrypted-retention policy
    # until teardown; expiry is never remote deletion.
    retain_envelope: bool = True


def _default_delivery_dict() -> dict[str, Any]:
    return {
        "mode": DEFAULT_DELIVERY_MODE,
        "version": 0,
        "updated_at": None,
        "seen_receipts_enabled": False,
        "accepted_receipts_enabled": True,
        "expiry_handling": "honor",
        "expiry_shorten_after_seconds": None,
    }


def _coerce_delivery_dict(raw: Any) -> dict[str, Any]:
    merged = _default_delivery_dict()
    if isinstance(raw, dict):
        for key, value in raw.items():
            if key in merged:
                merged[key] = value
    return merged


def _to_policy(data: dict[str, Any]) -> DeliveryPolicy:
    return DeliveryPolicy(
        mode=data["mode"],
        version=int(data["version"]),
        updated_at=data["updated_at"],
        seen_receipts_enabled=bool(data["seen_receipts_enabled"]),
        accepted_receipts_enabled=bool(data["accepted_receipts_enabled"]),
        expiry_handling=data["expiry_handling"],
        expiry_shorten_after_seconds=data["expiry_shorten_after_seconds"],
    )


def _load_policy_document(
    conn: sqlite3.Connection, relationship_id: str
) -> dict[str, Any]:
    row = conn.execute(
        "SELECT policy FROM relationships WHERE relationship_id = ?",
        (relationship_id,),
    ).fetchone()
    if row is None:
        raise UnknownRelationshipError(relationship_id)
    try:
        document = json.loads(row["policy"])
    except (ValueError, TypeError) as exc:
        raise PolicyError("policy_not_json", relationship_id) from exc
    if not isinstance(document, dict):
        raise PolicyError("policy_not_json", relationship_id)
    return document


def _store_delivery_dict(
    conn: sqlite3.Connection, relationship_id: str, data: dict[str, Any]
) -> DeliveryPolicy:
    with transaction(conn):
        document = _load_policy_document(conn, relationship_id)
        document[_DELIVERY_KEY] = data
        conn.execute(
            "UPDATE relationships SET policy = ? WHERE relationship_id = ?",
            (json.dumps(document, sort_keys=True), relationship_id),
        )
    return _to_policy(data)


def _bump(data: dict[str, Any]) -> dict[str, Any]:
    data = dict(data)
    data["version"] = int(data.get("version", 0)) + 1
    data["updated_at"] = utcnow()
    return data


def get_policy(conn: sqlite3.Connection, relationship_id: str) -> DeliveryPolicy:
    """Return the receiver-owned delivery policy for a relationship.

    A relationship that never set a policy reports the implicit default:
    silent mode, version 0, seen receipts off.

    Raises:
        UnknownRelationshipError: when the relationship does not exist.
    """
    document = _load_policy_document(conn, relationship_id)
    return _to_policy(_coerce_delivery_dict(document.get(_DELIVERY_KEY)))


def set_policy(
    conn: sqlite3.Connection, relationship_id: str, mode: str
) -> DeliveryPolicy:
    """Set the delivery mode. Receiver-local only; bumps the policy version.

    Raises:
        UnknownRelationshipError: when the relationship does not exist.
        PolicyError: when *mode* is not a known delivery mode.
    """
    if mode not in DELIVERY_MODES:
        raise PolicyError("invalid_delivery_mode", str(mode))
    document = _load_policy_document(conn, relationship_id)
    data = _bump(_coerce_delivery_dict(document.get(_DELIVERY_KEY)))
    data["mode"] = mode
    return _store_delivery_dict(conn, relationship_id, data)


def set_seen_receipts_enabled(
    conn: sqlite3.Connection, relationship_id: str, enabled: bool
) -> DeliveryPolicy:
    """Opt receipt.seen in or out. Default is off. Bumps the policy version."""
    document = _load_policy_document(conn, relationship_id)
    data = _bump(_coerce_delivery_dict(document.get(_DELIVERY_KEY)))
    data["seen_receipts_enabled"] = bool(enabled)
    return _store_delivery_dict(conn, relationship_id, data)


def set_accepted_receipts_enabled(
    conn: sqlite3.Connection, relationship_id: str, enabled: bool
) -> DeliveryPolicy:
    """Opt receipt.accepted in or out. Default is on. Bumps the version."""
    document = _load_policy_document(conn, relationship_id)
    data = _bump(_coerce_delivery_dict(document.get(_DELIVERY_KEY)))
    data["accepted_receipts_enabled"] = bool(enabled)
    return _store_delivery_dict(conn, relationship_id, data)


def set_expiry_policy(
    conn: sqlite3.Connection,
    relationship_id: str,
    handling: str,
    shorten_after_seconds: int | None = None,
) -> DeliveryPolicy:
    """Set how this receiver treats a sender expires_at request.

    handling is one of "honor", "ignore", or "shorten". With "shorten",
    shorten_after_seconds (a positive int) caps how long after created_at
    the event stays visible; the receiver never extends a sender window,
    only shortens it. Bumps the policy version.
    """
    if handling not in EXPIRY_HANDLINGS:
        raise PolicyError("invalid_expiry_handling", str(handling))
    if handling == "shorten":
        if (
            not isinstance(shorten_after_seconds, int)
            or isinstance(shorten_after_seconds, bool)
            or shorten_after_seconds <= 0
        ):
            raise PolicyError(
                "invalid_shorten_window", str(shorten_after_seconds)
            )
    elif shorten_after_seconds is not None:
        raise PolicyError(
            "shorten_window_without_shorten", str(shorten_after_seconds)
        )
    document = _load_policy_document(conn, relationship_id)
    data = _bump(_coerce_delivery_dict(document.get(_DELIVERY_KEY)))
    data["expiry_handling"] = handling
    data["expiry_shorten_after_seconds"] = shorten_after_seconds
    return _store_delivery_dict(conn, relationship_id, data)


def should_send_seen_receipt(
    conn: sqlite3.Connection,
    relationship_id: str,
    event_id: str,
    *,
    human_visible_view_opened: bool,
) -> bool:
    """Decide whether a receipt.seen may be queued for an event.

    receipt.seen defaults to off. It is sent only when the receiver enabled
    it in policy AND a human-visible view actually opened AND the event is
    committed locally for this relationship. Fail closed on every branch.
    """
    policy = get_policy(conn, relationship_id)
    if not policy.seen_receipts_enabled:
        return False
    if not human_visible_view_opened:
        return False
    row = conn.execute(
        "SELECT 1 FROM events WHERE event_id = ? AND relationship_id = ?",
        (event_id, relationship_id),
    ).fetchone()
    return row is not None


def accepted_receipt_permitted(
    conn: sqlite3.Connection, relationship_id: str
) -> bool:
    """Whether receipt.accepted may be queued (silent mode still allows it)."""
    return get_policy(conn, relationship_id).accepted_receipts_enabled


def surface_action(mode: str) -> str:
    """Map a delivery mode to the local surface behavior.

    silent -> "persist_only" (no proactive surface), digest ->
    "queue_digest", alert -> "surface_promptly", feed_eligible ->
    "consider_feed" (local curation may consider it; no Feed guarantee).

    Raises:
        PolicyError: on an unknown mode.
    """
    try:
        return _SURFACE_ACTION_BY_MODE[mode]
    except KeyError as exc:
        raise PolicyError("invalid_delivery_mode", str(mode)) from exc


def policy_snapshot(conn: sqlite3.Connection, relationship_id: str) -> dict:
    """Build the policy snapshot stored with a surface decision.

    The receive pipeline stores this (as JSON) in
    surface_queue.policy_snapshot so every surface decision carries the
    relationship policy version used.
    """
    policy = get_policy(conn, relationship_id)
    return {
        "mode": policy.mode,
        "version": policy.version,
        "seen_receipts_enabled": policy.seen_receipts_enabled,
        "accepted_receipts_enabled": policy.accepted_receipts_enabled,
        "updated_at": policy.updated_at,
    }


def snapshot_to_action(snapshot: Mapping[str, Any]) -> str:
    """Interpret a stored policy snapshot as a surface action.

    Fails closed: a snapshot with a missing or unknown mode maps to
    "persist_only" so a corrupt snapshot can never trigger surfacing.
    """
    mode = snapshot.get("mode")
    return _SURFACE_ACTION_BY_MODE.get(mode, "persist_only")


def _event_field(event: Mapping[str, Any], name: str) -> Any:
    try:
        return event[name]
    except (KeyError, IndexError, TypeError):
        return None


def apply_expiry(
    conn: sqlite3.Connection,
    relationship_id: str,
    event: Mapping[str, Any],
    now: str,
) -> ExpiryDecision:
    """Apply the receiver's expiry policy to one event at time *now*.

    *event* carries "created_at" (canonical UTC, required) and
    "expires_at" (canonical UTC or None, the sender's suppression request).
    A sender expires_at requests suppression after a time; it is not remote
    deletion, and the signed envelope is retained regardless.

    Receiver handling: "honor" suppresses at the sender's expires_at;
    "ignore" never suppresses; "shorten" suppresses at the earlier of the
    sender's expires_at and created_at plus the configured window.

    Returns:
        ExpiryDecision with suppress, the effective expiry, a stable reason,
        and the policy version used.

    Raises:
        PolicyError: on a bad timestamp or unknown relationship.
    """
    policy = get_policy(conn, relationship_id)
    created_at = _event_field(event, "created_at")
    sender_expires_at = _event_field(event, "expires_at")
    try:
        created_dt = parse_canonical_utc(created_at)
        now_dt = parse_canonical_utc(now)
    except (ValueError, TypeError) as exc:
        raise PolicyError("invalid_timestamp", str(exc)) from exc

    if policy.expiry_handling == "ignore":
        return ExpiryDecision(
            suppress=False,
            effective_expires_at=None,
            reason="expiry_ignored_by_receiver_policy",
            policy_version=policy.version,
        )

    candidates: list[str] = []
    if sender_expires_at:
        try:
            parse_canonical_utc(sender_expires_at)
        except (ValueError, TypeError) as exc:
            raise PolicyError("invalid_timestamp", str(exc)) from exc
        candidates.append(sender_expires_at)
    if policy.expiry_handling == "shorten":
        window_end = add_seconds(
            created_at, int(policy.expiry_shorten_after_seconds or 0)
        )
        candidates.append(window_end)

    if not candidates:
        return ExpiryDecision(
            suppress=False,
            effective_expires_at=None,
            reason="no_effective_expiry",
            policy_version=policy.version,
        )

    effective = min(candidates)
    effective_dt = parse_canonical_utc(effective)
    if now_dt < effective_dt:
        return ExpiryDecision(
            suppress=False,
            effective_expires_at=effective,
            reason="not_yet_expired",
            policy_version=policy.version,
        )
    reason = (
        "expired_sender_request_honored"
        if policy.expiry_handling == "honor"
        else "expired_shortened_window"
    )
    return ExpiryDecision(
        suppress=True,
        effective_expires_at=effective,
        reason=reason,
        policy_version=policy.version,
    )
