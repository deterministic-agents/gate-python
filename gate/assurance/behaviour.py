"""
gate.assurance.behaviour
========================
Construction of GATE C19 model behaviour monitoring events and
evaluation functions.

Event constructors and verify_baseline_currency do not require scipy.

compute_drift_score is the only function in this module that depends
on scipy. It is provided as an optional convenience for KS and
chi-square computation. Install the optional dependency with::

    pip install gate-python[assurance]
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


_VALID_DECISIONS = frozenset(
    {"no_drift", "drift_detected", "insufficient_data", "new_dimension_observed"}
)
_VALID_TESTS = frozenset({"ks", "chi2"})
_VALID_ACTIONS = frozenset(
    {"log_only", "flag", "review_ticket", "tier_reduction", "emergency_stop"}
)


def build_drift_decision_event(
    *,
    baseline_hash: str,
    abom_hash: str,
    evaluation_window_start: str,
    evaluation_window_end: str,
    dimension: str,
    statistical_test: str,
    test_statistic: float,
    p_value: float,
    threshold: float,
    decision: str,
    contributing_run_count: int,
    trace_id_sample: list[str],
    ledger_event_id: str,
    tenant_id: str,
    environment: str,
) -> dict[str, Any]:
    """
    Build a conformant gate.assurance.drift_decision event.

    decision must be one of: no_drift, drift_detected,
                             insufficient_data, new_dimension_observed.
    statistical_test must be one of: ks, chi2.
    """
    if decision not in _VALID_DECISIONS:
        raise ValueError(
            f"decision must be one of {set(_VALID_DECISIONS)}"
        )
    if statistical_test not in _VALID_TESTS:
        raise ValueError(
            f"statistical_test must be one of {set(_VALID_TESTS)}"
        )
    return {
        "schema_version": "v1",
        "event_type": "gate.assurance.drift_decision",
        "time": _now_iso(),
        "baseline_hash": baseline_hash,
        "abom_hash": abom_hash,
        "evaluation_window": {
            "start": evaluation_window_start,
            "end": evaluation_window_end,
        },
        "dimension": dimension,
        "statistical_test": statistical_test,
        "test_statistic": test_statistic,
        "p_value": p_value,
        "threshold": threshold,
        "decision": decision,
        "contributing_run_count": contributing_run_count,
        "trace_id_sample": trace_id_sample,
        "ledger_event_id": ledger_event_id,
        "tenant_id": tenant_id,
        "environment": environment,
    }


def build_response_action_event(
    *,
    drift_decision_id: str,
    action: str,
    action_metadata: dict[str, Any],
    trace_id: str,
    ledger_event_id: str,
    tenant_id: str,
    environment: str,
) -> dict[str, Any]:
    """
    Build a conformant gate.assurance.response_action event.

    action must be one of: log_only, flag, review_ticket,
                           tier_reduction, emergency_stop.
    """
    if action not in _VALID_ACTIONS:
        raise ValueError(f"action must be one of {set(_VALID_ACTIONS)}")
    return {
        "schema_version": "v1",
        "event_type": "gate.assurance.response_action",
        "time": _now_iso(),
        "drift_decision_id": drift_decision_id,
        "action": action,
        "action_metadata": action_metadata,
        "trace_id": trace_id,
        "ledger_event_id": ledger_event_id,
        "tenant_id": tenant_id,
        "environment": environment,
    }


def verify_baseline_currency(
    baseline_created_at: str,
    max_age_days: int,
) -> tuple[bool, int]:
    """
    Check whether a baseline is within its maximum age.

    Returns (is_current, age_days). Pure function.

    baseline_created_at must be an ISO 8601 date-time string.
    """
    if max_age_days < 0:
        raise ValueError("max_age_days must be non-negative")
    created = datetime.fromisoformat(
        baseline_created_at.replace("Z", "+00:00")
    )
    now = datetime.now(timezone.utc)
    age_days = (now - created).days
    return age_days <= max_age_days, age_days


def compute_drift_score(
    baseline_distribution: Any,
    current_distribution: Any,
    test_type: str,
) -> tuple[float, float]:
    """
    Compute a drift score between baseline and current distributions.

    test_type:
        "ks"   Kolmogorov-Smirnov (continuous distributions)
        "chi2" chi-square (categorical distributions)

    For "ks", baseline_distribution and current_distribution must be
    sequences of sampled values (e.g. lists of floats).

    For "chi2", they may be:
      - sequences of observed counts (matched index order), or
      - dicts mapping category -> observed count (any keys present in
        either dict are unioned).

    Returns (test_statistic, p_value).

    Requires scipy. Install with: pip install gate-python[assurance]
    """
    try:
        from scipy import stats
    except ImportError as e:
        raise ImportError(
            "compute_drift_score requires scipy. "
            "Install it with: pip install gate-python[assurance]"
        ) from e

    if test_type == "ks":
        result = stats.ks_2samp(
            baseline_distribution, current_distribution
        )
        return float(result.statistic), float(result.pvalue)

    if test_type == "chi2":
        if isinstance(baseline_distribution, dict) or isinstance(
            current_distribution, dict
        ):
            categories = sorted(
                set(baseline_distribution) | set(current_distribution)
            )
            obs_baseline = [
                baseline_distribution.get(c, 0) for c in categories
            ]
            obs_current = [
                current_distribution.get(c, 0) for c in categories
            ]
        else:
            obs_baseline = list(baseline_distribution)
            obs_current = list(current_distribution)
        result = stats.chisquare(obs_current, f_exp=obs_baseline)
        return float(result.statistic), float(result.pvalue)

    raise ValueError(
        f"test_type must be 'ks' or 'chi2'; got {test_type!r}"
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "build_drift_decision_event",
    "build_response_action_event",
    "verify_baseline_currency",
    "compute_drift_score",
]
