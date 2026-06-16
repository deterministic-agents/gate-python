"""
gate.discovery
==============
Construction of GATE C17 discovery plane events.

Provides builder functions for agent.discovered and
agent.remediation_outcome events emitted by the C17 discovery
and classification service.

Per the v1.3 framework constraint, this module is independent of
the existing gate.* modules. It does not modify gate.envelopes,
gate.ledger, gate.replay, gate.signing, or gate.validation. Those
remain at v1.0.0 semantics.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from ..hashing import gate_hash


def build_agent_discovered_event(
    *,
    workload_identity: str,
    detection_boundary: str,
    classification_confidence: float,
    evidence_payload: dict[str, Any],
    classifier_bundle_hash: str,
    tenant_id: str,
    environment: str,
    trace_id: str | None = None,
) -> dict[str, Any]:
    """
    Build a conformant gate.discovery.agent_discovered event.

    Called by the C17 discovery service when a candidate workload
    is detected that is not present in the C04 inventory.

    The candidate_hash is computed deterministically over
    workload_identity, detection_boundary, and the canonicalised
    evidence_payload. This lets the C04 lifecycle service
    deduplicate repeat detections and correlate the agent_discovered
    event to the eventual agent_remediation_outcome event.
    """
    valid_boundaries = {
        "network",
        "asset_inventory",
        "identity_classifier",
        "tool_gateway_ingress",
    }
    if detection_boundary not in valid_boundaries:
        raise ValueError(
            f"detection_boundary must be one of {valid_boundaries}"
        )
    if not 0.0 <= classification_confidence <= 1.0:
        raise ValueError(
            "classification_confidence must be in [0, 1]"
        )

    candidate_hash = gate_hash({
        "workload_identity": workload_identity,
        "detection_boundary": detection_boundary,
        "evidence_payload": evidence_payload,
    })

    event: dict[str, Any] = {
        "schema_version": "v1",
        "event_type": "gate.discovery.agent_discovered",
        "time": _now_iso(),
        "tenant_id": tenant_id,
        "environment": environment,
        "candidate": {
            "workload_identity": workload_identity,
            "detection_boundary": detection_boundary,
            "classification_confidence": classification_confidence,
            "evidence_payload": evidence_payload,
            "candidate_hash": candidate_hash,
            "classifier_bundle_hash": classifier_bundle_hash,
        },
    }
    if trace_id:
        event["trace_id"] = trace_id
    return event


def build_remediation_outcome_event(
    *,
    candidate_hash: str,
    outcome: str,
    owner_identity: str | None,
    time_to_remediation_seconds: int,
    tenant_id: str,
    environment: str,
    trace_id: str | None = None,
    exception_id: str | None = None,
    exception_ttl_expires_at: str | None = None,
    c04_commission_id: str | None = None,
    revocation_proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build a conformant gate.discovery.agent_remediation_outcome event.

    outcome must be one of: enrolled, terminated, exception.

    When outcome is "exception", both exception_id and
    exception_ttl_expires_at are required. The schema enforces this;
    we raise here so the caller gets an immediate error rather than a
    schema-validation failure downstream.
    """
    valid_outcomes = {"enrolled", "terminated", "exception"}
    if outcome not in valid_outcomes:
        raise ValueError(f"outcome must be one of {valid_outcomes}")
    if outcome == "exception":
        if not (exception_id and exception_ttl_expires_at):
            raise ValueError(
                "exception_id and exception_ttl_expires_at are required "
                "when outcome is 'exception'"
            )

    event: dict[str, Any] = {
        "schema_version": "v1",
        "event_type": "gate.discovery.agent_remediation_outcome",
        "time": _now_iso(),
        "tenant_id": tenant_id,
        "environment": environment,
        "candidate_hash": candidate_hash,
        "outcome": outcome,
        "owner_identity": owner_identity,
        "time_to_remediation_seconds": time_to_remediation_seconds,
    }
    if trace_id:
        event["trace_id"] = trace_id
    if exception_id:
        event["exception_id"] = exception_id
    if exception_ttl_expires_at:
        event["exception_ttl_expires_at"] = exception_ttl_expires_at
    if c04_commission_id:
        event["c04_commission_id"] = c04_commission_id
    if revocation_proof:
        event["revocation_proof"] = revocation_proof
    return event


def verify_classifier_coverage(
    total_identities: int,
    scanned_identities: int,
) -> float:
    """
    Compute classifier coverage percentage for Check16.

    Returns 100.0 if total_identities is 0 (vacuously true - no
    identities to cover).
    """
    if total_identities < 0 or scanned_identities < 0:
        raise ValueError("counts must be non-negative")
    if scanned_identities > total_identities:
        raise ValueError(
            "scanned_identities cannot exceed total_identities"
        )
    if total_identities == 0:
        return 100.0
    return round((scanned_identities / total_identities) * 100, 2)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "build_agent_discovered_event",
    "build_remediation_outcome_event",
    "verify_classifier_coverage",
]
