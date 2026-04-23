"""
gate.replay
===========
Replay trace construction and step recording.

A ReplayTrace captures all non-determinism at the tool/memory boundary
sufficient to reproduce a run without live dependencies. A run is
"replay-deterministic" if, given its trace and stored snapshots, the
system reproduces the same sequence of tool and memory operations with
matching request/response hashes.

Usage pattern
-------------
1. At run start, call ``ReplayRecorder(...)`` with model and bundle config.
2. For each tool call, call ``recorder.record_tool_call(...)`` or
   ``recorder.record_invariant_halt(...)``.
3. For each context retrieval, call ``recorder.record_retrieve_context(...)``.
4. At run end, call ``recorder.record_final_output(...)`` and
   ``recorder.to_dict()`` to export the trace.
5. Store the trace in your replay store (linked to the audit ledger).

Schema: contracts/replay_trace.schema.json
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .hashing import gate_hash


STEP_TYPES = frozenset([
    "retrieve_context",
    "tool_call",
    "tool_deny",
    "invariant_halt",
    "memory_read",
    "memory_write",
    "hitl_gate",
    "breaker_trigger",
    "final_output",
])


# ---------------------------------------------------------------------------
# Replay recorder
# ---------------------------------------------------------------------------

class ReplayRecorder:
    """
    Records a GATE replay trace for a single agent run.

    Instantiate at run start with model and bundle configuration.
    Call the ``record_*`` methods as each governed boundary operation
    occurs. Export with ``to_dict()`` at run end.

    Parameters
    ----------
    run_id:
        UUID of this agent run.
    trace_id:
        OTel-compatible distributed trace ID.
    tenant_id:
        Tenant identifier.
    environment:
        One of ``"dev"``, ``"test"``, ``"prod"``.
    agent_instance_id:
        SPIFFE URI with run suffix.
    agent_name:
        Short agent name.
    agent_version:
        SemVer string.
    model_id:
        Provider + model identifier, e.g. ``"openai/gpt-4o"``.
    model_version:
        Pinned model version string.
    temperature:
        Model temperature at run time.
    seed:
        RNG seed if set, else None.
    decoding:
        One of ``"greedy"``, ``"sampled"``, ``"beam"``.
    max_tokens:
        Maximum tokens for this run.
    policy_bundle_hash:
        ``"sha256:<hex>"`` of the active policy bundle.
    prompt_bundle_hash:
        ``"sha256:<hex>"`` of the prompt bundle.
    tool_schema_hash:
        ``"sha256:<hex>"`` of the tool schema bundle.

    Examples
    --------
    >>> recorder = ReplayRecorder(
    ...     run_id=str(uuid.uuid4()),
    ...     trace_id="trace-abc",
    ...     tenant_id="acme",
    ...     environment="prod",
    ...     agent_instance_id="spiffe://org/agent/support#run-1",
    ...     agent_name="customer-support",
    ...     agent_version="1.0.0",
    ...     model_id="openai/gpt-4o",
    ...     model_version="2024-11-01",
    ...     temperature=0.1,
    ...     seed=None,
    ...     policy_bundle_hash="sha256:" + "a" * 64,
    ...     prompt_bundle_hash="sha256:" + "b" * 64,
    ...     tool_schema_hash="sha256:" + "c" * 64,
    ... )
    """

    def __init__(
        self,
        *,
        run_id: str,
        trace_id: str,
        tenant_id: str,
        environment: str,
        agent_instance_id: str,
        agent_name: str,
        agent_version: str,
        model_id: str,
        model_version: str,
        temperature: float,
        seed: int | None,
        decoding: str = "sampled",
        max_tokens: int | None = None,
        policy_bundle_hash: str,
        prompt_bundle_hash: str,
        tool_schema_hash: str,
    ) -> None:
        self.run_id = run_id
        self.trace_id = trace_id
        self.tenant_id = tenant_id
        self.environment = environment
        self._created_at = _now_iso()
        self._steps: list[dict[str, Any]] = []
        self._step_index = 0

        self._agent = {
            "agent_instance_id": agent_instance_id,
            "agent_name": agent_name,
            "agent_version": agent_version,
        }

        self._model: dict[str, Any] = {
            "model_id": model_id,
            "model_version": model_version,
            "temperature": temperature,
            "seed": seed,
            "decoding": decoding,
        }
        if max_tokens is not None:
            self._model["max_tokens"] = max_tokens

        self._bundles = {
            "prompt_bundle_hash": prompt_bundle_hash,
            "policy_bundle_hash": policy_bundle_hash,
            "tool_schema_hash": tool_schema_hash,
        }

    # -----------------------------------------------------------------------
    # Step recorders
    # -----------------------------------------------------------------------

    def record_retrieve_context(
        self,
        *,
        documents: list[dict[str, Any]],
        provenance_refs: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Record a context retrieval step.

        Parameters
        ----------
        documents:
            List of retrieved document dicts. Their canonical JSON hashes
            are computed and stored; the raw content is NOT stored in the
            trace (only hashes, for privacy and size reasons).
        provenance_refs:
            List of provenance URIs corresponding to each document.

        Returns
        -------
        dict
            The recorded step.
        """
        context_hashes = [gate_hash(doc) for doc in documents]
        step = self._new_step("retrieve_context")
        step["retrieved_context_hashes"] = context_hashes
        if provenance_refs:
            step["provenance_refs"] = provenance_refs
        self._steps.append(step)
        return step

    def record_tool_call(
        self,
        *,
        tool_name: str,
        request_payload: dict[str, Any],
        response_payload: dict[str, Any],
        policy_decision_id: str,
        ledger_event_id: str,
        snapshot_uri: str | None = None,
        duration_ms: int | None = None,
    ) -> dict[str, Any]:
        """
        Record a successful tool call step.

        Both ``request_hash`` and ``response_hash`` are computed from
        their payloads using canonical JSON. The snapshot_uri allows
        the replay harness to serve the response without calling the
        live tool.

        Parameters
        ----------
        tool_name:
            The tool that was invoked.
        request_payload:
            The tool input payload (same object used to compute
            ``request_hash`` in the ToolRequestEnvelope).
        response_payload:
            The raw tool response payload.
        policy_decision_id:
            UUID of the PolicyDecisionRecord for this call.
        ledger_event_id:
            UUID of the LedgerEvent for this call.
        snapshot_uri:
            Immutable storage URI for the full response snapshot.
        duration_ms:
            Execution time in milliseconds.
        """
        step = self._new_step("tool_call")
        step["tool_name"] = tool_name
        step["request_hash"] = gate_hash(request_payload)
        step["response_hash"] = gate_hash(response_payload)
        step["policy_decision_id"] = policy_decision_id
        step["ledger_event_id"] = ledger_event_id
        if snapshot_uri:
            step["response_snapshot_uri"] = snapshot_uri
        if duration_ms is not None:
            step["duration_ms"] = duration_ms
        self._steps.append(step)
        return step

    def record_tool_deny(
        self,
        *,
        tool_name: str,
        request_payload: dict[str, Any],
        policy_decision_id: str,
        ledger_event_id: str,
        reason_codes: list[str],
    ) -> dict[str, Any]:
        """Record a tool call that was denied by policy."""
        step = self._new_step("tool_deny")
        step["tool_name"] = tool_name
        step["request_hash"] = gate_hash(request_payload)
        step["policy_decision_id"] = policy_decision_id
        step["ledger_event_id"] = ledger_event_id
        step["reason_codes"] = reason_codes
        self._steps.append(step)
        return step

    def record_invariant_halt(
        self,
        *,
        tool_name: str,
        request_payload: dict[str, Any],
        invariant_rule_id: str,
        policy_decision_id: str,
        ledger_event_id: str,
    ) -> dict[str, Any]:
        """
        Record an invariant halt step (C09).

        These steps are critical for forensic replay — they explain why
        a tool call that policy permitted was still blocked.
        """
        step = self._new_step("invariant_halt")
        step["tool_name"] = tool_name
        step["request_hash"] = gate_hash(request_payload)
        step["invariant_rule_id"] = invariant_rule_id
        step["policy_decision_id"] = policy_decision_id
        step["ledger_event_id"] = ledger_event_id
        self._steps.append(step)
        return step

    def record_memory_read(
        self,
        *,
        partition: str,
        query_payload: dict[str, Any],
        result_hashes: list[str],
        policy_decision_id: str,
        ledger_event_id: str,
    ) -> dict[str, Any]:
        """Record a memory gateway read operation."""
        step = self._new_step("memory_read")
        step["partition"] = partition
        step["query_hash"] = gate_hash(query_payload)
        step["result_hashes"] = result_hashes
        step["policy_decision_id"] = policy_decision_id
        step["ledger_event_id"] = ledger_event_id
        self._steps.append(step)
        return step

    def record_hitl_gate(
        self,
        *,
        tool_name: str,
        approval_id: str | None,
        approved: bool,
        ledger_event_id: str,
    ) -> dict[str, Any]:
        """Record a HITL gate step (approved, denied, or pending)."""
        step = self._new_step("hitl_gate")
        step["tool_name"] = tool_name
        step["hitl_approval_id"] = approval_id
        step["approved"] = approved
        step["ledger_event_id"] = ledger_event_id
        self._steps.append(step)
        return step

    def record_final_output(
        self,
        *,
        output: Any,
    ) -> dict[str, Any]:
        """
        Record the final agent output step.

        Must be the last step recorded before exporting the trace.
        """
        step = self._new_step("final_output")
        step["output_hash"] = gate_hash(output)
        self._steps.append(step)
        return step

    # -----------------------------------------------------------------------
    # Export
    # -----------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """
        Export the complete replay trace as a dict.

        Suitable for YAML serialisation or JSON storage.
        """
        return {
            "schema_version": "v1",
            "trace_id": self.trace_id,
            "run_id": self.run_id,
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "created_at": self._created_at,
            "agent": self._agent,
            "model": self._model,
            "bundles": self._bundles,
            "steps": self._steps,
            "replay_metadata": {
                "replay_mode": "mock_all",
                "harness_version": "gate-python/1.0.0",
            },
        }

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _new_step(self, step_type: str) -> dict[str, Any]:
        self._step_index += 1
        return {
            "step_index": self._step_index,
            "step_type": step_type,
            "timestamp": _now_iso(),
        }


# ---------------------------------------------------------------------------
# Replay verification
# ---------------------------------------------------------------------------

class ReplayVerificationResult:
    """Result of verifying a replay trace against recorded hashes."""

    def __init__(
        self,
        passed: bool,
        steps_total: int,
        steps_matched: int,
        mismatches: list[dict[str, Any]],
    ) -> None:
        self.passed = passed
        self.steps_total = steps_total
        self.steps_matched = steps_matched
        self.mismatches = mismatches

    def __repr__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"ReplayVerificationResult(status={status}, "
            f"steps_total={self.steps_total}, "
            f"steps_matched={self.steps_matched}, "
            f"mismatches={len(self.mismatches)})"
        )


def verify_replay(
    trace: dict[str, Any],
    *,
    actual_requests: dict[int, dict[str, Any]],
    actual_responses: dict[int, dict[str, Any]],
) -> ReplayVerificationResult:
    """
    Verify a replay trace against re-executed tool call payloads.

    In a real replay harness, you re-run the agent with tool responses
    served from snapshots. This function verifies that the replayed
    request/response hashes match the originally recorded ones.

    Parameters
    ----------
    trace:
        The original ReplayTrace dict (from ``ReplayRecorder.to_dict()``).
    actual_requests:
        Mapping of ``step_index`` → request payload dict from the replay.
    actual_responses:
        Mapping of ``step_index`` → response payload dict from the replay.

    Returns
    -------
    ReplayVerificationResult
    """
    steps = trace.get("steps", [])
    tool_steps = [
        s for s in steps
        if s.get("step_type") in ("tool_call", "tool_deny", "invariant_halt")
    ]

    mismatches: list[dict[str, Any]] = []
    matched = 0

    for step in tool_steps:
        idx = step["step_index"]
        recorded_req_hash = step.get("request_hash")
        recorded_res_hash = step.get("response_hash")

        # Verify request hash
        if recorded_req_hash and idx in actual_requests:
            actual_req_hash = gate_hash(actual_requests[idx])
            if actual_req_hash != recorded_req_hash:
                mismatches.append({
                    "step_index": idx,
                    "field": "request_hash",
                    "recorded": recorded_req_hash,
                    "actual": actual_req_hash,
                })
            else:
                matched += 1

        # Verify response hash (only for tool_call steps)
        if (
            step.get("step_type") == "tool_call"
            and recorded_res_hash
            and idx in actual_responses
        ):
            actual_res_hash = gate_hash(actual_responses[idx])
            if actual_res_hash != recorded_res_hash:
                mismatches.append({
                    "step_index": idx,
                    "field": "response_hash",
                    "recorded": recorded_res_hash,
                    "actual": actual_res_hash,
                })
            else:
                matched += 1

    return ReplayVerificationResult(
        passed=len(mismatches) == 0,
        steps_total=len(tool_steps),
        steps_matched=matched,
        mismatches=mismatches,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
