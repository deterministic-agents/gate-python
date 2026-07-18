"""
gate.invariants.break_glass
===========================
Construction and verification of GATE C09 break-glass records.

A break-glass record is a signed authorisation artifact (not an event)
covering an emergency override of a C09 invariant halt. The record is
defined by break_glass_record.schema.json in gate-contracts v1.2.0.
Dual approval is enforced at schema level (approver_ids minItems 2,
uniqueItems true). The verification policy at
policies/invariants/c09_break_glass_verification.rego in gate-policies
v1.2.0 is authoritative for runtime override decisions; the Python
helpers here mirror the same surface so callers can fail-fast at the
SDK boundary before issuing or honouring a record.

The schema-level cross-field invariants this module enforces:

  - exception_scope=time_window requires time_window_start.
  - exception_scope=specific_run forbids time_window_start.
  - approver_ids has 2+ distinct entries.

The schema-deferred invariants this module ALSO checks as
defence-in-depth (the policy is the authoritative source; this is
duplicated logic):

  - signing_key_ids and signatures arrays have equal length.
  - For time_window scope, time_window_start strictly earlier than
    exception_expires_at.
  - exception_expires_at has not passed at evaluation time.

This module does NOT enforce halt-event correspondence (tenant /
environment / invariant_rule_id match between record and the halt
event). Those are evaluated by the policy because they require the
halt event as a second input and the policy is the natural place for
that cross-document check.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


_VALID_SCOPES: frozenset[str] = frozenset({"specific_run", "time_window"})
_VALID_ENVIRONMENTS: frozenset[str] = frozenset({"dev", "test", "prod"})


def build_break_glass_record(
    *,
    invariant_halt_event_id: str,
    invariant_rule_id: str,
    tenant_id: str,
    environment: str,
    approver_ids: list[str],
    justification: str,
    exception_scope: str,
    exception_expires_at: str,
    gate_version: str,
    time_window_start: str | None = None,
    signing_key_ids: list[str] | None = None,
    signatures: list[str] | None = None,
    record_id: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """
    Build a conformant break_glass_record dict.

    Returns an unsigned record (signing_key_ids and signatures empty by
    default) ready for the signing workflow. Callers attach signatures
    and signing_key_ids before persisting, or pass them in via the
    optional parameters when they have been prepared upstream.

    Raises ValueError when:

      - approver_ids has fewer than 2 distinct entries (schema invariant).
      - exception_scope=time_window without time_window_start.
      - exception_scope=specific_run with time_window_start.
      - exception_scope is unrecognised.
      - environment is unrecognised.
      - justification is shorter than 50 characters (schema invariant).
    """
    if environment not in _VALID_ENVIRONMENTS:
        raise ValueError(
            f"environment must be one of {set(_VALID_ENVIRONMENTS)}; "
            f"got {environment!r}"
        )
    if exception_scope not in _VALID_SCOPES:
        raise ValueError(
            f"exception_scope must be one of {set(_VALID_SCOPES)}; "
            f"got {exception_scope!r}"
        )

    distinct_approvers = set(approver_ids)
    if len(distinct_approvers) < 2:
        raise ValueError(
            "approver_ids must contain at least 2 distinct entries "
            "(dual approval is the schema invariant)"
        )

    if len(justification) < 50:
        raise ValueError(
            "justification must be at least 50 characters "
            "(schema invariant; document the operational reason)"
        )

    if exception_scope == "time_window" and time_window_start is None:
        raise ValueError(
            "exception_scope=time_window requires time_window_start"
        )
    if exception_scope == "specific_run" and time_window_start is not None:
        raise ValueError(
            "exception_scope=specific_run forbids time_window_start"
        )

    record: dict[str, Any] = {
        "schema_version": "v1",
        "record_id": record_id or str(uuid.uuid4()),
        "invariant_halt_event_id": invariant_halt_event_id,
        "invariant_rule_id": invariant_rule_id,
        "tenant_id": tenant_id,
        "environment": environment,
        "approver_ids": list(approver_ids),
        "justification": justification,
        "exception_scope": exception_scope,
        "exception_expires_at": exception_expires_at,
        "signing_key_ids": list(signing_key_ids or []),
        "signatures": list(signatures or []),
        "created_at": created_at or _now_iso(),
        "gate_version": gate_version,
    }
    if exception_scope == "time_window":
        record["time_window_start"] = time_window_start
    return record


def verify_break_glass_record(
    record: dict[str, Any],
    current_time: str,
) -> tuple[bool, str]:
    """
    Verify a break-glass record against current_time.

    Pure function. Returns (valid, reason). The reason is a short
    stable string suitable for ledger filters and conformance scoring,
    matching the reason_codes convention used by
    policies/invariants/c09_break_glass_verification.rego.

    Checks (in evaluation order, first failure returned):

      - record present and invariant_rule_id non-empty
        (record_malformed)
      - approver_ids has 2+ distinct entries
        (dual_approval_violated)
      - signing_key_ids and signatures present and non-empty
        (signatures_missing)
      - signing_key_ids and signatures arrays have equal length
        (key_signature_length_mismatch)
      - for time_window scope: time_window_start strictly earlier than
        exception_expires_at (window_start_after_expiry)
      - exception_expires_at has not passed at current_time
        (exception_expired)

    Returns ("valid", "ok") when all checks pass. The policy is the
    authoritative override decision; this helper covers the same
    surface as defence-in-depth so the SDK caller does not have to
    plumb a Rego runtime to fail-fast on a malformed record.
    """
    if not isinstance(record, dict):
        return False, "record_malformed"

    rule_id = record.get("invariant_rule_id")
    if not rule_id:
        return False, "record_malformed"

    approvers = record.get("approver_ids") or []
    if len(set(approvers)) < 2:
        return False, "dual_approval_violated"

    signing_key_ids = record.get("signing_key_ids") or []
    signatures = record.get("signatures") or []
    if not signing_key_ids or not signatures:
        return False, "signatures_missing"
    if len(signing_key_ids) != len(signatures):
        return False, "key_signature_length_mismatch"

    expires_at = record.get("exception_expires_at")
    if not expires_at:
        return False, "record_malformed"

    scope = record.get("exception_scope")
    if scope == "time_window":
        window_start = record.get("time_window_start")
        if not window_start:
            return False, "record_malformed"
        if _parse_iso(window_start) >= _parse_iso(expires_at):
            return False, "window_start_after_expiry"

    if _parse_iso(current_time) >= _parse_iso(expires_at):
        return False, "exception_expired"

    return True, "ok"


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "build_break_glass_record",
    "verify_break_glass_record",
]
