"""
gate.memory.quality
===================
Construction of GATE C18 Data Quality Gate events and evaluation
functions.

The evaluation functions (evaluate_freshness, evaluate_confidence,
evaluate_provenance) are pure functions with no I/O. They can be
called independently to test individual quality dimensions before
calling apply_action_matrix to determine the final outcome.

Per the v1.3 framework constraint, this module is independent of
gate.envelopes and gate.validation. It produces dicts conformant to
quality_decision.schema.json from gate-contracts v1.1.0.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


_VALID_OUTCOMES: frozenset[str] = frozenset(
    {"pass", "flag", "downgrade", "deny"}
)
_SEVERITY = {"pass": 0, "flag": 1, "downgrade": 2, "deny": 3}
_LEVEL_TO_ACTION = {v: k for k, v in _SEVERITY.items()}


def build_quality_decision_event(
    *,
    request_hash: str,
    item_id: str,
    content_class: str,
    freshness_age_seconds: float,
    confidence_score: float,
    provenance_uri: str,
    provenance_hash_verified: bool,
    quality_bundle_hash: str,
    outcome: str,
    flags_set: list[str],
    trace_id: str,
    ledger_event_id: str,
    tenant_id: str,
    environment: str,
) -> dict[str, Any]:
    """
    Build a conformant gate.memory.quality_decision event.

    Called by the Memory Gateway after evaluating a retrieval against
    the quality bundle.
    """
    if outcome not in _VALID_OUTCOMES:
        raise ValueError(f"outcome must be one of {set(_VALID_OUTCOMES)}")
    return {
        "schema_version": "v1",
        "event_type": "gate.memory.quality_decision",
        "time": _now_iso(),
        "request_hash": request_hash,
        "item_id": item_id,
        "content_class": content_class,
        "freshness_age_seconds": freshness_age_seconds,
        "confidence_score": confidence_score,
        "provenance_uri": provenance_uri,
        "provenance_hash_verified": provenance_hash_verified,
        "quality_bundle_hash": quality_bundle_hash,
        "outcome": outcome,
        "flags_set": flags_set,
        "trace_id": trace_id,
        "ledger_event_id": ledger_event_id,
        "tenant_id": tenant_id,
        "environment": environment,
    }


def evaluate_freshness(
    content_class: str,
    item_age_seconds: float,
    ttl_by_class: dict[str, float],
) -> tuple[bool, str]:
    """
    Check whether an item is within its freshness TTL.

    Returns (passes, reason). Pure function.

    If content_class has no TTL configured, defaults to pass.
    """
    ttl = ttl_by_class.get(content_class)
    if ttl is None:
        return True, "no_ttl_configured"
    if item_age_seconds <= ttl:
        return True, "within_ttl"
    return False, f"age_{int(item_age_seconds)}s_exceeds_ttl_{int(ttl)}s"


def evaluate_confidence(
    content_class: str,
    confidence_score: float,
    min_confidence_by_class: dict[str, float],
) -> tuple[bool, str]:
    """
    Check whether an item meets the minimum confidence threshold.

    Returns (passes, reason). Pure function.

    If content_class has no minimum configured, defaults to pass.
    """
    minimum = min_confidence_by_class.get(content_class)
    if minimum is None:
        return True, "no_minimum_configured"
    if confidence_score >= minimum:
        return True, "confidence_meets_minimum"
    return (
        False,
        f"confidence_{confidence_score:.3f}_below_minimum_{minimum:.3f}",
    )


def evaluate_provenance(
    provenance_uri: str | None,
    provenance_hash: str | None,
    stored_hash: str | None,
    required_by_class: bool,
) -> tuple[bool, str]:
    """
    Check whether an item has verifiable provenance.

    Returns (passes, reason). Pure function.

    If required_by_class is False and provenance_uri is absent, passes.
    """
    if not required_by_class and not provenance_uri:
        return True, "provenance_not_required"
    if not provenance_uri:
        return False, "provenance_uri_missing"
    if stored_hash and provenance_hash and provenance_hash != stored_hash:
        return False, "provenance_hash_mismatch"
    return True, "provenance_verified"


def apply_action_matrix(
    freshness_pass: bool,
    confidence_pass: bool,
    provenance_pass: bool,
    content_class: str,
    autonomy_tier: str,
    action_matrix: dict[str, dict[str, dict[str, str]]],
) -> str:
    """
    Determine the quality gate outcome from the action matrix.

    action_matrix shape:

        {tier: {content_class: {dimension: action}}}

    where action is one of: pass, flag, downgrade, deny.

    Returns the most severe action across all failing dimensions.
    Severity order: deny > downgrade > flag > pass.

    If the matrix does not specify the given (tier, content_class)
    pair, falls back to (tier, "default") if present, else returns
    "flag" for each failing dimension (the least-severe non-trivial
    action).
    """
    tier_matrix = action_matrix.get(autonomy_tier, {})
    class_matrix = tier_matrix.get(
        content_class, tier_matrix.get("default", {})
    )

    max_severity = 0
    for dimension, passes in (
        ("freshness", freshness_pass),
        ("confidence", confidence_pass),
        ("provenance", provenance_pass),
    ):
        if not passes:
            action = class_matrix.get(dimension, "flag")
            max_severity = max(max_severity, _SEVERITY.get(action, 1))
    return _LEVEL_TO_ACTION[max_severity]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "build_quality_decision_event",
    "evaluate_freshness",
    "evaluate_confidence",
    "evaluate_provenance",
    "apply_action_matrix",
]
