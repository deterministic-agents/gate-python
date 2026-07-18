"""
Tests for gate.output (C20 v1.4).

Run: pytest tests/test_output.py -v
"""
from __future__ import annotations

import uuid

import pytest

from gate.hashing import gate_hash
from gate.output import (
    OutputClassificationBundle,
    apply_output_action_matrix,
    build_output_classification_event,
    evaluate_output_sensitivity,
    select_retention_class,
)
from gate.validation import validate_output_classification_event


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_hash():
    return "sha256:" + "a" * 64


@pytest.fixture
def basic_classification():
    return {
        "sensitivity_tier": "high",
        "regulated_categories": ["medical"],
        "confidence_score": 0.92,
        "requires_human_review": True,
    }


@pytest.fixture
def basic_action_matrix():
    # Shared baseline used by tests that do not depend on pass-through
    # semantics. The wildcard-driven low/bounded pass-through entry was
    # removed when W5 was aligned to the W3 rego's no-wildcard contract
    # (rego lines 46-51). Tests that need a pass-through entry construct
    # it inline; see test_pass_through_entry_suppresses_guardrail.
    return [
        {
            "sensitivity_tier": "high",
            "regulated_categories": ["medical"],
            "autonomy_tier": "high_privilege",
            "confidence_band": {"min": 0.0, "max": 1.0},
            "obligations": ["hitl_review", "redact_fields"],
            "retention_class": "regulated_cold_7y_plus",
        },
    ]


@pytest.fixture
def basic_bundle(basic_action_matrix):
    return {
        "bundle_id": str(uuid.uuid4()),
        "bundle_version": "1.0.0",
        "sensitivity_tiers": ["low", "medium", "high"],
        "regulated_categories": ["medical", "legal", "financial"],
        "default_sensitivity_tier": "low",
        "default_confidence": 0.5,
        "action_matrix": basic_action_matrix,
    }


# ---------------------------------------------------------------------------
# build_output_classification_event
# ---------------------------------------------------------------------------

class TestBuildOutputClassificationEvent:
    def test_event_type(self, basic_classification, fake_hash):
        event = build_output_classification_event(
            run_id=str(uuid.uuid4()),
            trace_id="trace-1",
            output={"answer": "consult your physician"},
            classification=basic_classification,
            obligations=["hitl_review"],
            ledger_event_id=str(uuid.uuid4()),
            tenant_id="acme",
            environment="prod",
            bundle_hash=fake_hash,
        )
        assert event["event_type"] == "gate.output.classification"
        assert event["schema_version"] == "v1"

    def test_output_hash_computed_via_gate_hash(
        self, basic_classification, fake_hash
    ):
        output = {"answer": "consult your physician", "id": 42}
        event = build_output_classification_event(
            run_id=str(uuid.uuid4()),
            trace_id="trace-1",
            output=output,
            classification=basic_classification,
            obligations=["hitl_review"],
            ledger_event_id=str(uuid.uuid4()),
            tenant_id="acme",
            environment="prod",
            bundle_hash=fake_hash,
        )
        assert event["output_hash"] == gate_hash(output)

    def test_event_validates_against_schema(
        self, basic_classification, fake_hash
    ):
        event = build_output_classification_event(
            run_id=str(uuid.uuid4()),
            trace_id="trace-1",
            output={"answer": "ok"},
            classification=basic_classification,
            obligations=["hitl_review"],
            ledger_event_id=str(uuid.uuid4()),
            tenant_id="acme",
            environment="prod",
            bundle_hash=fake_hash,
        )
        result = validate_output_classification_event(event)
        assert result.valid, result.summary()

    def test_rejects_invalid_environment(
        self, basic_classification, fake_hash
    ):
        with pytest.raises(ValueError, match="environment"):
            build_output_classification_event(
                run_id=str(uuid.uuid4()),
                trace_id="trace-1",
                output={},
                classification=basic_classification,
                obligations=[],
                ledger_event_id=str(uuid.uuid4()),
                tenant_id="acme",
                environment="staging",
                bundle_hash=fake_hash,
            )

    def test_rejects_unknown_obligation(
        self, basic_classification, fake_hash
    ):
        with pytest.raises(ValueError, match="obligation"):
            build_output_classification_event(
                run_id=str(uuid.uuid4()),
                trace_id="trace-1",
                output={},
                classification=basic_classification,
                obligations=["block"],
                ledger_event_id=str(uuid.uuid4()),
                tenant_id="acme",
                environment="prod",
                bundle_hash=fake_hash,
            )


# ---------------------------------------------------------------------------
# evaluate_output_sensitivity
# ---------------------------------------------------------------------------

class TestEvaluateOutputSensitivity:
    def test_high_sensitivity_returns_requires_human_review(
        self, basic_bundle
    ):
        def classifier(_text):
            return {
                "sensitivity_tier": "high",
                "regulated_categories": ["medical"],
            }

        def confidence(_text):
            return 0.92

        bundle = dict(basic_bundle)
        bundle["classifier_fn"] = classifier
        bundle["confidence_fn"] = confidence

        result = evaluate_output_sensitivity(
            "Take this medication twice daily.",
            bundle,
            autonomy_tier="high_privilege",
        )
        assert result["sensitivity_tier"] == "high"
        assert result["regulated_categories"] == ["medical"]
        assert result["confidence_score"] == 0.92
        assert result["requires_human_review"] is True

    def test_low_sensitivity_at_bounded_passes_without_review(
        self, basic_bundle
    ):
        def classifier(_text):
            return {
                "sensitivity_tier": "low",
                "regulated_categories": [],
            }

        bundle = dict(basic_bundle)
        bundle["classifier_fn"] = classifier
        bundle["confidence_fn"] = lambda _t: 0.95

        result = evaluate_output_sensitivity(
            "The weather in London is rainy.",
            bundle,
            autonomy_tier="bounded",
        )
        assert result["requires_human_review"] is False

    def test_rejects_invalid_autonomy_tier(self, basic_bundle):
        with pytest.raises(ValueError, match="autonomy_tier"):
            evaluate_output_sensitivity(
                "x", basic_bundle, autonomy_tier="full_autonomy"
            )


# ---------------------------------------------------------------------------
# apply_output_action_matrix
# ---------------------------------------------------------------------------

class TestApplyOutputActionMatrix:
    def test_regulated_category_triggers_redact(self, basic_action_matrix):
        classification = {
            "sensitivity_tier": "high",
            "regulated_categories": ["medical"],
            "confidence_score": 0.9,
            "requires_human_review": False,
        }
        obligations = apply_output_action_matrix(
            classification=classification,
            autonomy_tier="high_privilege",
            action_matrix=basic_action_matrix,
        )
        assert "redact_fields" in obligations
        assert "hitl_review" in obligations

    def test_high_privilege_default_produces_non_empty_obligations(self):
        # Empty action matrix means no entry matches at high_privilege; the
        # fail-closed guardrail MUST force hold_for_review.
        obligations = apply_output_action_matrix(
            classification={
                "sensitivity_tier": "low",
                "regulated_categories": [],
                "confidence_score": 0.99,
                "requires_human_review": False,
            },
            autonomy_tier="high_privilege",
            action_matrix=[],
        )
        assert obligations == ["hold_for_review"]

    def test_pass_through_entry_suppresses_guardrail(self):
        # An empty regulated_categories list on the entry is vacuously
        # true and matches any classification's regulated_categories,
        # per the W3 rego at lines 103-109. No wildcard token needed.
        matrix = [
            {
                "sensitivity_tier": "low",
                "regulated_categories": [],
                "autonomy_tier": "high_privilege",
                "confidence_band": {"min": 0.9, "max": 1.0},
                "obligations": [],
                "is_pass_through": True,
            }
        ]
        obligations = apply_output_action_matrix(
            classification={
                "sensitivity_tier": "low",
                "regulated_categories": [],
                "confidence_score": 0.95,
                "requires_human_review": False,
            },
            autonomy_tier="high_privilege",
            action_matrix=matrix,
        )
        assert obligations == []

    def test_obligation_list_sorted_and_unique(self, basic_action_matrix):
        obligations = apply_output_action_matrix(
            classification={
                "sensitivity_tier": "high",
                "regulated_categories": ["medical"],
                "confidence_score": 0.9,
                "requires_human_review": False,
            },
            autonomy_tier="high_privilege",
            action_matrix=basic_action_matrix,
        )
        assert obligations == sorted(set(obligations))

    def test_bounded_tier_no_guardrail(self):
        # No high-privilege guardrail at bounded; empty matrix means empty
        # obligations (deliver as-is).
        obligations = apply_output_action_matrix(
            classification={
                "sensitivity_tier": "low",
                "regulated_categories": [],
                "confidence_score": 0.5,
                "requires_human_review": False,
            },
            autonomy_tier="bounded",
            action_matrix=[],
        )
        assert obligations == []


# ---------------------------------------------------------------------------
# select_retention_class (Erratum 2 / 3)
# ---------------------------------------------------------------------------

class TestSelectRetentionClass:
    def test_matched_entry_value_used(self, basic_action_matrix):
        # Regulated medical entry carries regulated_cold_7y_plus.
        rc = select_retention_class(
            classification={
                "sensitivity_tier": "high",
                "regulated_categories": ["medical"],
                "confidence_score": 0.9,
                "requires_human_review": False,
            },
            autonomy_tier="high_privilege",
            action_matrix=basic_action_matrix,
        )
        assert rc == "regulated_cold_7y_plus"

    def test_fallback_to_per_tier_default_sandbox(self):
        rc = select_retention_class(
            classification={
                "sensitivity_tier": "low",
                "regulated_categories": [],
                "confidence_score": 0.5,
                "requires_human_review": False,
            },
            autonomy_tier="sandbox",
            action_matrix=[],
        )
        assert rc == "sandbox_hot_30d"

    def test_fallback_to_per_tier_default_bounded(self):
        rc = select_retention_class(
            classification={
                "sensitivity_tier": "low",
                "regulated_categories": [],
                "confidence_score": 0.5,
                "requires_human_review": False,
            },
            autonomy_tier="bounded",
            action_matrix=[],
        )
        assert rc == "prod_cold_6y_worm"

    def test_fallback_to_per_tier_default_high_privilege(self):
        rc = select_retention_class(
            classification={
                "sensitivity_tier": "low",
                "regulated_categories": [],
                "confidence_score": 0.5,
                "requires_human_review": False,
            },
            autonomy_tier="high_privilege",
            action_matrix=[],
        )
        assert rc == "prod_cold_6y_worm"

    def test_strongest_retention_wins_across_matched_entries(self):
        # Construct two entries that both match the same classification
        # input through overlapping but explicit dimensions. No wildcard
        # tokens, in line with the W3 rego no-wildcard contract at
        # policies/output/c20_output_classification.rego lines 46-51.
        #
        # Classification has sensitivity_tier=medium and
        # regulated_categories=[pii, phi]. Both entries are at medium
        # tier; the regulated_categories matching is the rego's set-
        # inclusion rule (every category in the entry list must be
        # present in the classification list).
        #
        # Entry A: regulated_categories=[pii]. Vacuously satisfied:
        #   {pii} subset {pii, phi}. retention_class=prod_hot_365d.
        # Entry B: regulated_categories=[pii, phi]. Satisfied:
        #   {pii, phi} subset {pii, phi}. retention_class=
        #   regulated_cold_7y_plus.
        #
        # Both entries match. Strongest-wins selects the stronger
        # retention, regulated_cold_7y_plus.
        matrix = [
            {
                "sensitivity_tier": "medium",
                "regulated_categories": ["pii"],
                "autonomy_tier": "high_privilege",
                "obligations": ["hold_for_review"],
                "retention_class": "prod_hot_365d",
            },
            {
                "sensitivity_tier": "medium",
                "regulated_categories": ["pii", "phi"],
                "autonomy_tier": "high_privilege",
                "obligations": ["hitl_review"],
                "retention_class": "regulated_cold_7y_plus",
            },
        ]
        rc = select_retention_class(
            classification={
                "sensitivity_tier": "medium",
                "regulated_categories": ["pii", "phi"],
                "confidence_score": 0.5,
                "requires_human_review": False,
            },
            autonomy_tier="high_privilege",
            action_matrix=matrix,
        )
        assert rc == "regulated_cold_7y_plus"


# ---------------------------------------------------------------------------
# OutputClassificationBundle
# ---------------------------------------------------------------------------

class TestOutputClassificationBundle:
    def test_load_and_basic_properties(self, basic_bundle):
        bundle = OutputClassificationBundle.load(basic_bundle)
        assert bundle.bundle_id == basic_bundle["bundle_id"]
        assert bundle.bundle_version == "1.0.0"
        assert bundle.action_matrix == basic_bundle["action_matrix"]

    def test_load_rejects_missing_required_keys(self):
        with pytest.raises(ValueError, match="missing required keys"):
            OutputClassificationBundle.load(
                {"bundle_version": "1.0.0", "action_matrix": []}
            )

    def test_bundle_hash_excludes_signature(self, basic_bundle):
        signed = dict(basic_bundle)
        signed["signature"] = "test-sig"
        bundle_signed = OutputClassificationBundle.load(signed)
        bundle_unsigned = OutputClassificationBundle.load(basic_bundle)
        assert bundle_signed.bundle_hash() == bundle_unsigned.bundle_hash()

    def test_apply_returns_obligations(self, basic_bundle):
        bundle = OutputClassificationBundle.load(basic_bundle)
        obligations = bundle.apply(
            classification={
                "sensitivity_tier": "high",
                "regulated_categories": ["medical"],
                "confidence_score": 0.9,
                "requires_human_review": False,
            },
            autonomy_tier="high_privilege",
        )
        assert "hitl_review" in obligations

    def test_select_retention_class_via_bundle(self, basic_bundle):
        bundle = OutputClassificationBundle.load(basic_bundle)
        rc = bundle.select_retention_class(
            classification={
                "sensitivity_tier": "high",
                "regulated_categories": ["medical"],
                "confidence_score": 0.9,
                "requires_human_review": False,
            },
            autonomy_tier="high_privilege",
        )
        assert rc == "regulated_cold_7y_plus"
