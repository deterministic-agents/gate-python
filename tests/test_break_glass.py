"""
Tests for gate.invariants.break_glass (C09 v1.4).

Run: pytest tests/test_break_glass.py -v
"""
from __future__ import annotations

import uuid

import pytest

from gate.invariants.break_glass import (
    build_break_glass_record,
    verify_break_glass_record,
)
from gate.validation import validate_break_glass_record


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_JUSTIFICATION = (
    "Emergency override for incident #4421; halt at 02:13 UTC blocks "
    "recovery of customer-impacting deploy rollback per runbook RB-09."
)


@pytest.fixture
def two_approvers():
    return ["role:sec-lead/u-alice", "role:eng-vp/u-bob"]


@pytest.fixture
def signing_pair():
    return (
        ["kid-sec-lead-2026", "kid-eng-vp-2026"],
        ["base64sig-alice", "base64sig-bob"],
    )


@pytest.fixture
def specific_run_record(two_approvers, signing_pair):
    signing_key_ids, signatures = signing_pair
    return build_break_glass_record(
        invariant_halt_event_id=str(uuid.uuid4()),
        invariant_rule_id="INV-DELETE-001",
        tenant_id="acme",
        environment="prod",
        approver_ids=two_approvers,
        justification=_JUSTIFICATION,
        exception_scope="specific_run",
        exception_expires_at="2099-12-31T23:59:59Z",
        gate_version="1.4",
        signing_key_ids=signing_key_ids,
        signatures=signatures,
    )


@pytest.fixture
def time_window_record(two_approvers, signing_pair):
    signing_key_ids, signatures = signing_pair
    return build_break_glass_record(
        invariant_halt_event_id=str(uuid.uuid4()),
        invariant_rule_id="INV-DELETE-001",
        tenant_id="acme",
        environment="prod",
        approver_ids=two_approvers,
        justification=_JUSTIFICATION,
        exception_scope="time_window",
        exception_expires_at="2099-12-31T23:59:59Z",
        time_window_start="2099-01-01T00:00:00Z",
        gate_version="1.4",
        signing_key_ids=signing_key_ids,
        signatures=signatures,
    )


# ---------------------------------------------------------------------------
# build_break_glass_record
# ---------------------------------------------------------------------------

class TestBuildBreakGlassRecord:
    def test_raises_on_single_approver(self, signing_pair):
        signing_key_ids, signatures = signing_pair
        with pytest.raises(ValueError, match="distinct"):
            build_break_glass_record(
                invariant_halt_event_id=str(uuid.uuid4()),
                invariant_rule_id="INV-X",
                tenant_id="acme",
                environment="prod",
                approver_ids=["role:sec-lead/u-alice"],
                justification=_JUSTIFICATION,
                exception_scope="specific_run",
                exception_expires_at="2099-12-31T23:59:59Z",
                gate_version="1.4",
                signing_key_ids=signing_key_ids,
                signatures=signatures,
            )

    def test_raises_on_duplicate_approvers(self, signing_pair):
        signing_key_ids, signatures = signing_pair
        with pytest.raises(ValueError, match="distinct"):
            build_break_glass_record(
                invariant_halt_event_id=str(uuid.uuid4()),
                invariant_rule_id="INV-X",
                tenant_id="acme",
                environment="prod",
                approver_ids=["role:sec/u-a", "role:sec/u-a"],
                justification=_JUSTIFICATION,
                exception_scope="specific_run",
                exception_expires_at="2099-12-31T23:59:59Z",
                gate_version="1.4",
                signing_key_ids=signing_key_ids,
                signatures=signatures,
            )

    def test_builds_valid_specific_run_record(self, specific_run_record):
        assert specific_run_record["exception_scope"] == "specific_run"
        assert "time_window_start" not in specific_run_record
        assert specific_run_record["schema_version"] == "v1"

    def test_specific_run_record_validates_against_schema(
        self, specific_run_record
    ):
        result = validate_break_glass_record(specific_run_record)
        assert result.valid, result.summary()

    def test_builds_valid_time_window_record(self, time_window_record):
        assert time_window_record["exception_scope"] == "time_window"
        assert time_window_record["time_window_start"] == "2099-01-01T00:00:00Z"

    def test_time_window_record_validates_against_schema(
        self, time_window_record
    ):
        result = validate_break_glass_record(time_window_record)
        assert result.valid, result.summary()

    def test_raises_time_window_without_start(
        self, two_approvers, signing_pair
    ):
        signing_key_ids, signatures = signing_pair
        with pytest.raises(ValueError, match="time_window_start"):
            build_break_glass_record(
                invariant_halt_event_id=str(uuid.uuid4()),
                invariant_rule_id="INV-X",
                tenant_id="acme",
                environment="prod",
                approver_ids=two_approvers,
                justification=_JUSTIFICATION,
                exception_scope="time_window",
                exception_expires_at="2099-12-31T23:59:59Z",
                gate_version="1.4",
                signing_key_ids=signing_key_ids,
                signatures=signatures,
            )

    def test_raises_specific_run_with_time_window_start(
        self, two_approvers, signing_pair
    ):
        signing_key_ids, signatures = signing_pair
        with pytest.raises(ValueError, match="forbids time_window_start"):
            build_break_glass_record(
                invariant_halt_event_id=str(uuid.uuid4()),
                invariant_rule_id="INV-X",
                tenant_id="acme",
                environment="prod",
                approver_ids=two_approvers,
                justification=_JUSTIFICATION,
                exception_scope="specific_run",
                exception_expires_at="2099-12-31T23:59:59Z",
                time_window_start="2099-01-01T00:00:00Z",
                gate_version="1.4",
                signing_key_ids=signing_key_ids,
                signatures=signatures,
            )

    def test_raises_on_short_justification(self, two_approvers, signing_pair):
        signing_key_ids, signatures = signing_pair
        with pytest.raises(ValueError, match="50 characters"):
            build_break_glass_record(
                invariant_halt_event_id=str(uuid.uuid4()),
                invariant_rule_id="INV-X",
                tenant_id="acme",
                environment="prod",
                approver_ids=two_approvers,
                justification="too short",
                exception_scope="specific_run",
                exception_expires_at="2099-12-31T23:59:59Z",
                gate_version="1.4",
                signing_key_ids=signing_key_ids,
                signatures=signatures,
            )


# ---------------------------------------------------------------------------
# verify_break_glass_record
# ---------------------------------------------------------------------------

class TestVerifyBreakGlassRecord:
    def test_valid_record_passes(self, specific_run_record):
        valid, reason = verify_break_glass_record(
            specific_run_record,
            current_time="2026-06-23T02:15:00Z",
        )
        assert valid is True
        assert reason == "ok"

    def test_expired_record_fails(
        self, two_approvers, signing_pair
    ):
        signing_key_ids, signatures = signing_pair
        record = build_break_glass_record(
            invariant_halt_event_id=str(uuid.uuid4()),
            invariant_rule_id="INV-DELETE-001",
            tenant_id="acme",
            environment="prod",
            approver_ids=two_approvers,
            justification=_JUSTIFICATION,
            exception_scope="specific_run",
            exception_expires_at="2026-01-01T00:00:00Z",
            gate_version="1.4",
            signing_key_ids=signing_key_ids,
            signatures=signatures,
        )
        valid, reason = verify_break_glass_record(
            record,
            current_time="2026-06-23T02:15:00Z",
        )
        assert valid is False
        assert reason == "exception_expired"

    def test_missing_signatures_fails(
        self, two_approvers, signing_pair
    ):
        signing_key_ids, _ = signing_pair
        record = build_break_glass_record(
            invariant_halt_event_id=str(uuid.uuid4()),
            invariant_rule_id="INV-X",
            tenant_id="acme",
            environment="prod",
            approver_ids=two_approvers,
            justification=_JUSTIFICATION,
            exception_scope="specific_run",
            exception_expires_at="2099-12-31T23:59:59Z",
            gate_version="1.4",
            signing_key_ids=signing_key_ids,
            signatures=[],
        )
        valid, reason = verify_break_glass_record(
            record,
            current_time="2026-06-23T02:15:00Z",
        )
        assert valid is False
        assert reason == "signatures_missing"

    def test_single_approver_after_construction_fails(
        self, specific_run_record
    ):
        # The build helper prevents single-approver construction; verify
        # the verify helper independently catches a tampered record.
        tampered = dict(specific_run_record)
        tampered["approver_ids"] = ["role:sec-lead/u-alice"]
        valid, reason = verify_break_glass_record(
            tampered,
            current_time="2026-06-23T02:15:00Z",
        )
        assert valid is False
        assert reason == "dual_approval_violated"

    def test_signing_key_and_signature_length_mismatch(
        self, specific_run_record
    ):
        tampered = dict(specific_run_record)
        tampered["signing_key_ids"] = list(tampered["signing_key_ids"]) + [
            "extra-kid"
        ]
        valid, reason = verify_break_glass_record(
            tampered,
            current_time="2026-06-23T02:15:00Z",
        )
        assert valid is False
        assert reason == "key_signature_length_mismatch"

    def test_time_window_window_start_after_expiry_fails(
        self, two_approvers, signing_pair
    ):
        signing_key_ids, signatures = signing_pair
        # Have to bypass the builder since the builder does not enforce
        # window_start < expiry (the policy / verify do).
        record = build_break_glass_record(
            invariant_halt_event_id=str(uuid.uuid4()),
            invariant_rule_id="INV-X",
            tenant_id="acme",
            environment="prod",
            approver_ids=two_approvers,
            justification=_JUSTIFICATION,
            exception_scope="time_window",
            exception_expires_at="2099-12-31T23:59:59Z",
            time_window_start="2099-01-01T00:00:00Z",
            gate_version="1.4",
            signing_key_ids=signing_key_ids,
            signatures=signatures,
        )
        # Tamper: window_start equals expiry.
        record["time_window_start"] = record["exception_expires_at"]
        valid, reason = verify_break_glass_record(
            record,
            current_time="2026-06-23T02:15:00Z",
        )
        assert valid is False
        assert reason == "window_start_after_expiry"

    def test_record_malformed_when_invariant_rule_id_missing(self):
        valid, reason = verify_break_glass_record(
            {"approver_ids": ["a", "b"]},
            current_time="2026-06-23T00:00:00Z",
        )
        assert valid is False
        assert reason == "record_malformed"


# ---------------------------------------------------------------------------
# Cross-workstream drift guard (W5 verify helper vs W3 rego policy)
#
# verify_break_glass_record duplicates a narrow subset of the rego's reason
# codes as a defence-in-depth fail-fast surface at the SDK boundary. The
# rego policy at gate-policies is the authoritative override decision.
# This test catches name drift in the monorepo CI: if a future change
# renames a reason code on one side without the other, this fails.
#
# When the gate-policies tree is not adjacent to gate-python (e.g. the
# library is being tested in isolation), the test skips with a clear
# message rather than failing. The point is to catch drift, not to require
# the rego tree at every install site.
# ---------------------------------------------------------------------------

# Relative path from this test file to the rego policy under
# gate-policies, computed lazily from __file__ at test time so the cross-
# workstream path is explicit and easy to grep.
REGO_POLICY_RELATIVE_PATH = (
    "../../../workstream-3/gate-policies/policies/invariants/"
    "c09_break_glass_verification.rego"
)

# Reason codes the Python verify helper emits that mirror rego rules. The
# defence-in-depth subset: schema-level and time-bound checks. Cross-
# document checks (tenant_mismatch, environment_mismatch, rule_id_mismatch,
# halt_event_id_mismatch, halt_outside_time_window) are rego-only because
# they require the halt event the SDK does not hold.
PYTHON_MIRRORED_REASON_CODES = (
    "dual_approval_violated",
    "exception_expired",
    "signatures_missing",
    "key_signature_length_mismatch",
    "window_start_after_expiry",
)


def test_reason_codes_present_in_rego_policy():
    import os

    rego_path = os.path.normpath(
        os.path.join(os.path.dirname(__file__), REGO_POLICY_RELATIVE_PATH)
    )
    if not os.path.isfile(rego_path):
        pytest.skip(
            f"gate-policies tree not adjacent (looked for {rego_path}); "
            f"drift check requires the monorepo layout"
        )
    rego_source = open(rego_path, encoding="utf-8").read()
    missing = [
        code
        for code in PYTHON_MIRRORED_REASON_CODES
        if f'"{code}"' not in rego_source
    ]
    assert not missing, (
        f"Reason code drift detected: Python emits "
        f"{missing} but the rego policy at {rego_path} does not contain "
        f"matching string literal(s). Either rename in Python to match "
        f"rego, or update the rego policy."
    )
