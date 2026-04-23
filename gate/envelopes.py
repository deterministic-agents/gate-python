"""
gate.envelopes
==============
Construction of GATE Tool Gateway request and response envelopes.

These are the primary wire format for tool calls traversing the Tool
Gateway. Every ToolRequestEnvelope carries identity claims, bundle
hashes, and a request_hash so the gateway can produce a verifiable
PolicyDecisionRecord. Every ToolResponseEnvelope carries the matching
response_hash and a pointer to the immutable snapshot.

The ``build_request`` and ``build_response`` functions are what you call
inside your Tool Gateway SDK wrapper or sidecar interceptor.

Schema: contracts/tool_envelope.schema.json
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .hashing import canonical_json_str, gate_hash


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "v1"
TOOL_CATEGORIES = frozenset(
    ["read_only", "reversible_write", "irreversible_write",
     "financial", "infrastructure", "multi_agent"]
)
RISK_TIERS = frozenset(["low", "medium", "high", "critical"])
ENVIRONMENTS = frozenset(["dev", "test", "prod"])


# ---------------------------------------------------------------------------
# Request envelope
# ---------------------------------------------------------------------------

def build_request(
    *,
    # Correlation
    run_id: str,
    trace_id: str,
    tenant_id: str,
    environment: str,
    # Agent identity
    agent_instance_id: str,
    agent_name: str,
    agent_version: str,
    attested: bool,
    image_digest: str | None = None,
    config_hash: str | None = None,
    toolset_hash: str | None = None,
    # Tool
    tool_name: str,
    tool_category: str,
    risk_tier: str,
    payload: dict[str, Any],
    idempotency_key: str | None = None,
    # Bundles
    policy_bundle_hash: str,
    prompt_bundle_hash: str | None = None,
    tool_schema_hash: str,
    # Runtime context
    orm_risk_score: float = 0.0,
    tokens_remaining: int = 0,
    tool_calls_remaining: int = 0,
    cost_usd_remaining: float = 0.0,
    source_labels: list[str] | None = None,
    # Optional
    span_id: str | None = None,
    control_plane_version: str | None = None,
) -> dict[str, Any]:
    """
    Build a conformant ToolRequestEnvelope.

    The ``request_hash`` is computed automatically over the canonical
    JSON of the ``inputs.payload`` object. Store the returned envelope;
    pass it to the policy engine; include the ``request_hash`` in your
    PolicyDecisionRecord.

    Parameters
    ----------
    run_id:
        UUID identifying the agent run or workflow.
    trace_id:
        OpenTelemetry-compatible distributed trace ID.
    tenant_id:
        Tenant identifier for multi-tenant deployments.
    environment:
        One of ``"dev"``, ``"test"``, ``"prod"``.
    agent_instance_id:
        SPIFFE URI with run suffix, e.g.
        ``"spiffe://org/agent/planner#run-123"``.
    agent_name:
        Short human-readable agent name.
    agent_version:
        SemVer string, e.g. ``"2.1.0"``.
    attested:
        Whether hardware or software attestation was performed.
    image_digest:
        SHA-256 of the agent container image (``"sha256:<hex>"``).
    config_hash:
        SHA-256 of the agent configuration bundle.
    toolset_hash:
        SHA-256 of the agent toolset manifest.
    tool_name:
        The tool being invoked, e.g. ``"crm.update_contact"``.
    tool_category:
        One of ``"read_only"``, ``"reversible_write"``,
        ``"irreversible_write"``, ``"financial"``,
        ``"infrastructure"``, ``"multi_agent"``.
    risk_tier:
        One of ``"low"``, ``"medium"``, ``"high"``, ``"critical"``.
    payload:
        The tool input parameters. Must be JSON-serialisable.
        The ``request_hash`` is computed over this object.
    idempotency_key:
        Optional stable key for at-most-once execution semantics.
    policy_bundle_hash:
        ``"sha256:<hex>"`` of the active OPA policy bundle.
    prompt_bundle_hash:
        ``"sha256:<hex>"`` of the prompt/system config bundle.
    tool_schema_hash:
        ``"sha256:<hex>"`` of the tool JSON schema used for validation.
    orm_risk_score:
        Current ORM risk score (0.0–1.0).
    tokens_remaining:
        Token budget remaining for this run.
    tool_calls_remaining:
        Tool call quota remaining for this run.
    cost_usd_remaining:
        Cost budget remaining for this run (USD).
    source_labels:
        List of origin labels, e.g. ``["user_input", "retrieved_doc"]``.
    span_id:
        Optional OTel span ID.
    control_plane_version:
        Version string of the deployed GATE gateway.

    Returns
    -------
    dict
        A conformant ToolRequestEnvelope ready for schema validation.

    Examples
    --------
    >>> env = build_request(
    ...     run_id=str(uuid.uuid4()),
    ...     trace_id="trace-abc",
    ...     tenant_id="acme",
    ...     environment="prod",
    ...     agent_instance_id="spiffe://org/agent/support#run-1",
    ...     agent_name="customer-support",
    ...     agent_version="1.0.0",
    ...     attested=True,
    ...     tool_name="read_ticket",
    ...     tool_category="read_only",
    ...     risk_tier="low",
    ...     payload={"ticket_id": "TKT-001"},
    ...     policy_bundle_hash="sha256:" + "a" * 64,
    ...     tool_schema_hash="sha256:" + "b" * 64,
    ... )
    >>> env["event_type"]
    'gate.tool.request'
    >>> "request_hash" in env["hashes"]
    True
    """
    if environment not in ENVIRONMENTS:
        raise ValueError(f"environment must be one of {ENVIRONMENTS}")
    if tool_category not in TOOL_CATEGORIES:
        raise ValueError(f"tool_category must be one of {TOOL_CATEGORIES}")
    if risk_tier not in RISK_TIERS:
        raise ValueError(f"risk_tier must be one of {RISK_TIERS}")
    if not (0.0 <= orm_risk_score <= 1.0):
        raise ValueError(f"orm_risk_score must be between 0.0 and 1.0")

    request_hash = gate_hash(payload)

    identity_claims: dict[str, Any] = {}
    if image_digest:
        identity_claims["image_digest"] = image_digest
    if config_hash:
        identity_claims["config_hash"] = config_hash
    if toolset_hash:
        identity_claims["toolset_hash"] = toolset_hash

    bundles: dict[str, str] = {
        "policy_bundle_hash": policy_bundle_hash,
        "tool_schema_hash": tool_schema_hash,
    }
    if prompt_bundle_hash:
        bundles["prompt_bundle_hash"] = prompt_bundle_hash

    tool_entry: dict[str, Any] = {
        "name": tool_name,
        "category": tool_category,
        "risk_tier": risk_tier,
    }
    if idempotency_key:
        tool_entry["idempotency_key"] = idempotency_key

    envelope: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_type": "gate.tool.request",
        "time": _now_iso(),
        "run_id": run_id,
        "trace_id": trace_id,
        "tenant_id": tenant_id,
        "environment": environment,
        "agent": {
            "agent_instance_id": agent_instance_id,
            "agent_name": agent_name,
            "agent_version": agent_version,
            "identity": {
                "subject": agent_instance_id.split("#")[0],
                "attested": attested,
                **({"claims": identity_claims} if identity_claims else {}),
            },
        },
        "tool": tool_entry,
        "inputs": {
            "content_type": "application/json",
            "payload": payload,
            "payload_hash": gate_hash(payload),
        },
        "bundles": bundles,
        "hashes": {
            "request_hash": request_hash,
        },
        "context": {
            "orm_risk_score": round(orm_risk_score, 4),
            "budgets": {
                "tokens_remaining": tokens_remaining,
                "tool_calls_remaining": tool_calls_remaining,
                "cost_usd_remaining": round(cost_usd_remaining, 4),
            },
            "source_labels": source_labels or [],
            "approval": {
                "required": False,
                "approval_id": None,
            },
        },
    }

    if span_id:
        envelope["span_id"] = span_id
    if control_plane_version:
        envelope["control_plane_version"] = control_plane_version

    return envelope


# ---------------------------------------------------------------------------
# Response envelope
# ---------------------------------------------------------------------------

def build_response(
    *,
    request_envelope: dict[str, Any],
    tool_output: dict[str, Any],
    status: str,
    duration_ms: int,
    decision_id: str,
    decision: str,
    obligations: list[str],
    policy_bundle_hash: str,
    ledger_event_id: str,
    snapshot_uri: str | None = None,
    replay_trace_step_id: str | None = None,
    error_code: str | None = None,
) -> dict[str, Any]:
    """
    Build a conformant ToolResponseEnvelope.

    Call this after the tool executes (or after a deny decision is made).
    The ``response_hash`` is computed over the canonical JSON of
    ``tool_output``. Store the snapshot URI so the response can be
    replayed later without calling the live tool.

    Parameters
    ----------
    request_envelope:
        The original ToolRequestEnvelope (from ``build_request``).
        Correlation IDs are copied from it.
    tool_output:
        The raw tool response payload. Must be JSON-serialisable.
        Will be stored in ``outputs.payload_redacted`` — redact
        sensitive fields before passing here.
    status:
        One of ``"success"``, ``"error"``, ``"denied"``, ``"timeout"``.
    duration_ms:
        Wall-clock time for the tool execution in milliseconds.
    decision_id:
        UUID of the PolicyDecisionRecord for this call.
    decision:
        The policy decision: ``"allow"``, ``"deny"``, or
        ``"invariant_halt"``.
    obligations:
        List of obligation type strings that were enforced.
    policy_bundle_hash:
        ``"sha256:<hex>"`` of the policy bundle used.
    ledger_event_id:
        UUID of the LedgerEvent committed for this call.
    snapshot_uri:
        Immutable storage URI for the full response snapshot.
        Required for high-impact tools (financial, irreversible_write,
        infrastructure). Used by the replay harness.
    replay_trace_step_id:
        ID of the step in the replay trace for this call.
    error_code:
        Error code if status is ``"error"`` or ``"denied"``.

    Returns
    -------
    dict
        A conformant ToolResponseEnvelope.
    """
    valid_statuses = {"success", "error", "denied", "timeout"}
    if status not in valid_statuses:
        raise ValueError(f"status must be one of {valid_statuses}")

    response_hash = gate_hash(tool_output)

    outputs: dict[str, Any] = {
        "content_type": "application/json",
        "payload_redacted": tool_output,
        "payload_hash": response_hash,
    }
    if snapshot_uri:
        outputs["snapshot_uri"] = snapshot_uri

    tool_entry: dict[str, Any] = {
        "name": request_envelope["tool"]["name"],
        "status": status,
        "duration_ms": duration_ms,
    }
    if error_code:
        tool_entry["error_code"] = error_code

    evidence: dict[str, Any] = {"ledger_event_id": ledger_event_id}
    if replay_trace_step_id:
        evidence["replay_trace_step_id"] = replay_trace_step_id

    envelope: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_type": "gate.tool.response",
        "time": _now_iso(),
        "run_id": request_envelope["run_id"],
        "trace_id": request_envelope["trace_id"],
        "tenant_id": request_envelope["tenant_id"],
        "environment": request_envelope["environment"],
        "tool": tool_entry,
        "outputs": outputs,
        "hashes": {
            "response_hash": response_hash,
        },
        "policy": {
            "decision_id": decision_id,
            "decision": decision,
            "obligations": obligations,
            "policy_bundle_hash": policy_bundle_hash,
        },
        "evidence": evidence,
    }

    if "span_id" in request_envelope:
        envelope["span_id"] = request_envelope["span_id"]

    return envelope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_request_hash(envelope: dict[str, Any]) -> str:
    """Extract the request_hash from a ToolRequestEnvelope."""
    return envelope["hashes"]["request_hash"]


def extract_response_hash(envelope: dict[str, Any]) -> str:
    """Extract the response_hash from a ToolResponseEnvelope."""
    return envelope["hashes"]["response_hash"]


def redact_payload(
    payload: dict[str, Any],
    sensitive_fields: list[str] | None = None,
) -> dict[str, Any]:
    """
    Return a copy of *payload* with sensitive fields replaced by
    ``"[REDACTED]"``.

    The default sensitive field list matches the GATE baseline policy
    obligation ``redact_fields`` params.

    Parameters
    ----------
    payload:
        The original tool input or output payload.
    sensitive_fields:
        Field names to redact. Defaults to
        ``["pan", "cvv", "ssn", "password", "secret", "token"]``.
    """
    defaults = ["pan", "cvv", "ssn", "password", "secret", "token",
                "api_key", "private_key", "access_token", "refresh_token"]
    fields = set(sensitive_fields or defaults)

    def _redact(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                k: "[REDACTED]" if k in fields else _redact(v)
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [_redact(item) for item in obj]
        return obj

    return _redact(payload)
