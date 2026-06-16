"""
Tests for the v1.1.0 modules:
  gate.discovery
  gate.memory.quality
  gate.assurance.behaviour

Run: pytest tests/test_gate_v13.py -v

The compute_drift_score function depends on scipy. It is tested in a
separate file (test_assurance_scipy.py) that is skipped if scipy is not
installed. The tests in this file run without scipy.
"""
from __future__ import annotations

import pytest

from gate.discovery import (
    build_agent_discovered_event,
    build_remediation_outcome_event,
    verify_classifier_coverage,
)
from gate.memory.quality import (
    apply_action_matrix,
    build_quality_decision_event,
    evaluate_confidence,
    evaluate_freshness,
    evaluate_provenance,
)
from gate.assurance.behaviour import (
    build_drift_decision_event,
    build_response_action_event,
    verify_baseline_currency,
)


# ============================================================
# gate.discovery
# ============================================================

def test_build_agent_discovered_event_returns_correct_event_type():
    e = build_agent_discovered_event(
        workload_identity="spiffe://example.com/unknown",
        detection_boundary="network",
        classification_confidence=0.85,
        evidence_payload={"detector_id": "net_v1", "detector_version": "1.0"},
        classifier_bundle_hash="sha256:" + "a" * 64,
        tenant_id="t-1",
        environment="prod",
    )
    assert e["event_type"] == "gate.discovery.agent_discovered"
    assert e["schema_version"] == "v1"
    assert e["candidate"]["classification_confidence"] == 0.85


def test_build_agent_discovered_event_candidate_hash_is_deterministic():
    args = dict(
        workload_identity="spiffe://example.com/x",
        detection_boundary="network",
        classification_confidence=0.5,
        evidence_payload={"x": 1, "y": 2},
        classifier_bundle_hash="sha256:" + "b" * 64,
        tenant_id="t-1",
        environment="prod",
    )
    a = build_agent_discovered_event(**args)
    b = build_agent_discovered_event(**args)
    assert a["candidate"]["candidate_hash"] == b["candidate"]["candidate_hash"]


def test_build_agent_discovered_event_rejects_invalid_detection_boundary():
    with pytest.raises(ValueError):
        build_agent_discovered_event(
            workload_identity="x",
            detection_boundary="not_a_boundary",
            classification_confidence=0.5,
            evidence_payload={},
            classifier_bundle_hash="sha256:" + "c" * 64,
            tenant_id="t",
            environment="prod",
        )


def test_build_remediation_outcome_enrolled():
    e = build_remediation_outcome_event(
        candidate_hash="sha256:" + "0" * 64,
        outcome="enrolled",
        owner_identity="platform-eng",
        time_to_remediation_seconds=3600,
        tenant_id="t",
        environment="prod",
        c04_commission_id="11111111-1111-1111-1111-111111111111",
    )
    assert e["outcome"] == "enrolled"
    assert e["c04_commission_id"] == "11111111-1111-1111-1111-111111111111"


def test_build_remediation_outcome_terminated_with_revocation_proof():
    e = build_remediation_outcome_event(
        candidate_hash="sha256:" + "0" * 64,
        outcome="terminated",
        owner_identity=None,
        time_to_remediation_seconds=259200,
        tenant_id="t",
        environment="prod",
        revocation_proof={
            "idp_revocation_id": "rev-1",
            "gateway_deny_rule_version": "v3",
            "network_policy_version": "v9",
        },
    )
    assert e["outcome"] == "terminated"
    assert e["revocation_proof"]["idp_revocation_id"] == "rev-1"


def test_build_remediation_outcome_exception_without_id_raises():
    with pytest.raises(ValueError):
        build_remediation_outcome_event(
            candidate_hash="sha256:" + "0" * 64,
            outcome="exception",
            owner_identity="x",
            time_to_remediation_seconds=0,
            tenant_id="t",
            environment="prod",
        )


def test_verify_classifier_coverage_zero_total():
    assert verify_classifier_coverage(0, 0) == 100.0


def test_verify_classifier_coverage_partial():
    assert verify_classifier_coverage(100, 50) == 50.0


def test_verify_classifier_coverage_rejects_negative():
    with pytest.raises(ValueError):
        verify_classifier_coverage(-1, 0)


def test_verify_classifier_coverage_rejects_scanned_gt_total():
    with pytest.raises(ValueError):
        verify_classifier_coverage(10, 20)


# ============================================================
# gate.memory.quality
# ============================================================

def test_evaluate_freshness_within_ttl_passes():
    passes, _ = evaluate_freshness(
        "legal_text", 1000, {"legal_text": 86400}
    )
    assert passes


def test_evaluate_freshness_beyond_ttl_fails():
    passes, _ = evaluate_freshness(
        "legal_text", 1_000_000, {"legal_text": 86400}
    )
    assert not passes


def test_evaluate_freshness_no_ttl_passes():
    passes, reason = evaluate_freshness(
        "unknown_class", 100, {"legal_text": 86400}
    )
    assert passes
    assert reason == "no_ttl_configured"


def test_evaluate_confidence_above_minimum_passes():
    passes, _ = evaluate_confidence(
        "x", 0.9, {"x": 0.7}
    )
    assert passes


def test_evaluate_confidence_below_minimum_fails():
    passes, _ = evaluate_confidence(
        "x", 0.5, {"x": 0.7}
    )
    assert not passes


def test_evaluate_provenance_not_required_passes_without_uri():
    passes, _ = evaluate_provenance(None, None, None, required_by_class=False)
    assert passes


def test_evaluate_provenance_required_no_uri_fails():
    passes, _ = evaluate_provenance(None, None, None, required_by_class=True)
    assert not passes


def test_evaluate_provenance_hash_mismatch_fails():
    passes, _ = evaluate_provenance(
        "https://example.com/x",
        "sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
        required_by_class=True,
    )
    assert not passes


def test_apply_action_matrix_all_pass_returns_pass():
    out = apply_action_matrix(
        freshness_pass=True,
        confidence_pass=True,
        provenance_pass=True,
        content_class="legal_text",
        autonomy_tier="bounded",
        action_matrix={
            "bounded": {
                "legal_text": {"freshness": "deny", "confidence": "deny", "provenance": "flag"}
            }
        },
    )
    assert out == "pass"


def test_apply_action_matrix_deny_wins_over_flag():
    out = apply_action_matrix(
        freshness_pass=False,
        confidence_pass=False,
        provenance_pass=True,
        content_class="product_pricing",
        autonomy_tier="bounded",
        action_matrix={
            "bounded": {
                "product_pricing": {"freshness": "deny", "confidence": "flag", "provenance": "flag"}
            }
        },
    )
    assert out == "deny"


def test_apply_action_matrix_missing_class_uses_default():
    out = apply_action_matrix(
        freshness_pass=False,
        confidence_pass=True,
        provenance_pass=True,
        content_class="new_class_not_in_matrix",
        autonomy_tier="bounded",
        action_matrix={
            "bounded": {
                "default": {"freshness": "downgrade", "confidence": "deny", "provenance": "flag"}
            }
        },
    )
    assert out == "downgrade"


def test_build_quality_decision_event_returns_correct_type():
    e = build_quality_decision_event(
        request_hash="sha256:" + "1" * 64,
        item_id="item-1",
        content_class="legal_text",
        freshness_age_seconds=100,
        confidence_score=0.9,
        provenance_uri="https://example.com/source",
        provenance_hash_verified=True,
        quality_bundle_hash="sha256:" + "2" * 64,
        outcome="pass",
        flags_set=[],
        trace_id="otel-trace",
        ledger_event_id="11111111-1111-1111-1111-111111111111",
        tenant_id="t",
        environment="prod",
    )
    assert e["event_type"] == "gate.memory.quality_decision"


def test_build_quality_decision_event_rejects_invalid_outcome():
    with pytest.raises(ValueError):
        build_quality_decision_event(
            request_hash="sha256:" + "1" * 64,
            item_id="item-1",
            content_class="legal_text",
            freshness_age_seconds=100,
            confidence_score=0.9,
            provenance_uri="https://example.com/source",
            provenance_hash_verified=True,
            quality_bundle_hash="sha256:" + "2" * 64,
            outcome="reject",  # not in enum
            flags_set=[],
            trace_id="otel-trace",
            ledger_event_id="11111111-1111-1111-1111-111111111111",
            tenant_id="t",
            environment="prod",
        )


# ============================================================
# gate.assurance.behaviour
# ============================================================

def test_build_drift_decision_event_returns_correct_type():
    e = build_drift_decision_event(
        baseline_hash="sha256:" + "a" * 64,
        abom_hash="sha256:" + "b" * 64,
        evaluation_window_start="2026-06-15T00:00:00Z",
        evaluation_window_end="2026-06-16T00:00:00Z",
        dimension="tool_choice",
        statistical_test="chi2",
        test_statistic=12.3,
        p_value=0.001,
        threshold=0.01,
        decision="drift_detected",
        contributing_run_count=1234,
        trace_id_sample=["t-1", "t-2"],
        ledger_event_id="11111111-1111-1111-1111-111111111111",
        tenant_id="t",
        environment="prod",
    )
    assert e["event_type"] == "gate.assurance.drift_decision"
    assert e["decision"] == "drift_detected"


def test_build_drift_decision_event_rejects_invalid_decision():
    with pytest.raises(ValueError):
        build_drift_decision_event(
            baseline_hash="sha256:" + "a" * 64,
            abom_hash="sha256:" + "b" * 64,
            evaluation_window_start="2026-06-15T00:00:00Z",
            evaluation_window_end="2026-06-16T00:00:00Z",
            dimension="tool_choice",
            statistical_test="chi2",
            test_statistic=12.3,
            p_value=0.001,
            threshold=0.01,
            decision="probably_drift",  # invalid
            contributing_run_count=10,
            trace_id_sample=[],
            ledger_event_id="11111111-1111-1111-1111-111111111111",
            tenant_id="t",
            environment="prod",
        )


@pytest.mark.parametrize(
    "action",
    ["log_only", "flag", "review_ticket", "tier_reduction", "emergency_stop"],
)
def test_build_response_action_event_accepts_valid_actions(action):
    e = build_response_action_event(
        drift_decision_id="11111111-1111-1111-1111-111111111111",
        action=action,
        action_metadata={"note": "test"},
        trace_id="otel-trace",
        ledger_event_id="22222222-2222-2222-2222-222222222222",
        tenant_id="t",
        environment="prod",
    )
    assert e["action"] == action


def test_build_response_action_event_rejects_invalid_action():
    with pytest.raises(ValueError):
        build_response_action_event(
            drift_decision_id="11111111-1111-1111-1111-111111111111",
            action="halt_everything",
            action_metadata={},
            trace_id="otel-trace",
            ledger_event_id="22222222-2222-2222-2222-222222222222",
            tenant_id="t",
            environment="prod",
        )


def test_verify_baseline_currency_current():
    # 30 days old, max 90 days -> current
    from datetime import datetime, timedelta, timezone
    created = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    is_current, age_days = verify_baseline_currency(created, 90)
    assert is_current
    assert 29 <= age_days <= 31


def test_verify_baseline_currency_stale():
    from datetime import datetime, timedelta, timezone
    created = (datetime.now(timezone.utc) - timedelta(days=100)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    is_current, age_days = verify_baseline_currency(created, 90)
    assert not is_current
    assert age_days >= 100
