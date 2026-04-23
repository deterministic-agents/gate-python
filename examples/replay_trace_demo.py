#!/usr/bin/env python3
"""
GATE Python Examples - Replay Trace Demo
=========================================
Demonstrates recording a multi-step agent run and verifying the replay
trace - including an invariant_halt step.

Scenario: An invoice reconciliation agent runs three tool calls and
encounters an invariant halt on a fourth (delete operation).

  Step 1: retrieve_context  - retrieves 2 documents
  Step 2: tool_call         - read_erp_po
  Step 3: tool_call         - read_erp_invoice
  Step 4: invariant_halt    - delete_erp_record blocked by INV-DELETE-001
  Step 5: tool_call         - create_dispute_case
  Step 6: final_output

The example then:
  - Exports the trace to YAML
  - Verifies hashes against "replayed" payloads
  - Shows what a mismatched hash looks like

Run: python examples/replay_trace_demo.py
"""

import json
import sys
import uuid
import yaml
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gate.replay import ReplayRecorder, verify_replay
from gate.hashing import gate_hash


def separator(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def main() -> None:
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║     GATE Replay Trace Demo                           ║")
    print("╚══════════════════════════════════════════════════════╝")

    run_id  = str(uuid.uuid4())
    trace_id = "trace-" + str(uuid.uuid4())[:8]

    # ── Initialise recorder ───────────────────────────────────────────────────
    recorder = ReplayRecorder(
        run_id=run_id,
        trace_id=trace_id,
        tenant_id="acme-corp",
        environment="prod",
        agent_instance_id="spiffe://org/agent/invoice-recon#run-" + run_id[:8],
        agent_name="invoice-reconciliation-agent",
        agent_version="2.1.0",
        model_id="provider/model",
        model_version="2025-11-01",
        temperature=0.1,
        seed=12345,  # pinned seed for determinism
        decoding="greedy",
        policy_bundle_hash="sha256:" + "d4e5" * 16,
        prompt_bundle_hash="sha256:" + "b2c3" * 16,
        tool_schema_hash="sha256:" + "e5f6" * 16,
    )

    separator("Step 1: retrieve_context")
    doc_po = {
        "po_id": "PO-2026-0318",
        "vendor_id": "ACME-VENDOR-442",
        "amount_usd": 2500,
        "status": "approved",
    }
    doc_inv = {
        "invoice_id": "INV-2026-0441",
        "vendor_id": "ACME-VENDOR-442",
        "amount_usd": 2500,
        "due_date": "2026-04-30",
    }
    step1 = recorder.record_retrieve_context(
        documents=[doc_po, doc_inv],
        provenance_refs=[
            "prov://erp/PO-2026-0318",
            "prov://erp/INV-2026-0441",
        ],
    )
    print(f"  step_index: {step1['step_index']}")
    print(f"  docs retrieved: 2")
    print(f"  context_hashes: {step1['retrieved_context_hashes']}")

    separator("Step 2: tool_call — read_erp_po")
    req_po = {"po_id": "PO-2026-0318", "fields": ["vendor_id", "amount_usd", "status"]}
    res_po = {"po_id": "PO-2026-0318", "vendor_id": "ACME-VENDOR-442", "amount_usd": 2500, "status": "approved"}
    step2 = recorder.record_tool_call(
        tool_name="read_erp_po",
        request_payload=req_po,
        response_payload=res_po,
        policy_decision_id=str(uuid.uuid4()),
        ledger_event_id=str(uuid.uuid4()),
        snapshot_uri=f"immutable://snapshots/read_erp_po/{run_id}/step-2.json",
        duration_ms=45,
    )
    print(f"  step_index:    {step2['step_index']}")
    print(f"  request_hash:  {step2['request_hash']}")
    print(f"  response_hash: {step2['response_hash']}")

    separator("Step 3: tool_call — read_erp_invoice")
    req_inv = {"invoice_id": "INV-2026-0441"}
    res_inv = {"invoice_id": "INV-2026-0441", "vendor_id": "ACME-VENDOR-442", "amount_usd": 2500, "matched_po": "PO-2026-0318"}
    step3 = recorder.record_tool_call(
        tool_name="read_erp_invoice",
        request_payload=req_inv,
        response_payload=res_inv,
        policy_decision_id=str(uuid.uuid4()),
        ledger_event_id=str(uuid.uuid4()),
        snapshot_uri=f"immutable://snapshots/read_erp_invoice/{run_id}/step-3.json",
        duration_ms=38,
    )
    print(f"  step_index:    {step3['step_index']}")
    print(f"  request_hash:  {step3['request_hash']}")
    print(f"  response_hash: {step3['response_hash']}")

    separator("Step 4: invariant_halt — delete_erp_record blocked")
    print("  Agent proposed: delete_erp_record (old duplicate invoice)")
    print("  Invariant INV-DELETE-001: env=prod → deny(delete_*) unless exception_id present")
    print("  exception_id: None → HALT")
    req_del = {"record_id": "INV-2026-0099", "reason": "duplicate"}
    step4 = recorder.record_invariant_halt(
        tool_name="delete_erp_record",
        request_payload=req_del,
        invariant_rule_id="INV-DELETE-001",
        policy_decision_id=str(uuid.uuid4()),
        ledger_event_id=str(uuid.uuid4()),
    )
    print(f"  step_index:        {step4['step_index']}")
    print(f"  step_type:         {step4['step_type']}")
    print(f"  invariant_rule_id: {step4['invariant_rule_id']}")
    print(f"  request_hash:      {step4['request_hash']}")
    print("  → Tool execution blocked. No side effect occurred.")

    separator("Step 5: tool_call — create_dispute_case")
    req_disp = {
        "invoice_id": "INV-2026-0441",
        "po_id": "PO-2026-0318",
        "reason": "amount_mismatch",
        "idempotency_key": "idem-" + str(uuid.uuid4()),
    }
    res_disp = {
        "dispute_id": "DISP-" + str(uuid.uuid4())[:8].upper(),
        "status": "open",
        "created_at": "2026-04-13T14:25:00Z",
    }
    step5 = recorder.record_tool_call(
        tool_name="create_dispute_case",
        request_payload=req_disp,
        response_payload=res_disp,
        policy_decision_id=str(uuid.uuid4()),
        ledger_event_id=str(uuid.uuid4()),
        snapshot_uri=f"immutable://snapshots/create_dispute_case/{run_id}/step-5.json",
        duration_ms=127,
    )
    print(f"  step_index:    {step5['step_index']}")
    print(f"  dispute_id:    {res_disp['dispute_id']}")
    print(f"  request_hash:  {step5['request_hash']}")
    print(f"  response_hash: {step5['response_hash']}")

    separator("Step 6: final_output")
    final_output = {
        "run_id": run_id,
        "status": "completed",
        "invoices_processed": 1,
        "disputes_created": 1,
        "invariant_halts": 1,
        "summary": "Invoice INV-2026-0441 matched to PO-2026-0318. Dispute created for review.",
    }
    step6 = recorder.record_final_output(output=final_output)
    print(f"  step_index:  {step6['step_index']}")
    print(f"  output_hash: {step6['output_hash']}")

    # ── Export trace ──────────────────────────────────────────────────────────
    separator("Exporting replay trace")
    trace = recorder.to_dict()
    print(f"  run_id:      {trace['run_id']}")
    print(f"  trace_id:    {trace['trace_id']}")
    print(f"  agent:       {trace['agent']['agent_name']} v{trace['agent']['agent_version']}")
    print(f"  model:       {trace['model']['model_id']} ({trace['model']['model_version']})")
    print(f"  seed:        {trace['model']['seed']}")
    print(f"  steps:       {len(trace['steps'])}")
    print(f"\n  Steps:")
    for step in trace["steps"]:
        tool = step.get("tool_name", "")
        inv  = step.get("invariant_rule_id", "")
        extra = f" [{inv}]" if inv else (f" → {tool}" if tool else "")
        print(f"    [{step['step_index']}] {step['step_type']:<20}{extra}")

    # ── Verify replay ─────────────────────────────────────────────────────────
    separator("Replay verification — all hashes match")

    # Simulate replaying: serving tool responses from snapshots
    # In a real harness, these come from snapshot_uri reads
    actual_requests = {
        step2["step_index"]: req_po,
        step3["step_index"]: req_inv,
        step4["step_index"]: req_del,   # invariant_halt — request_hash only
        step5["step_index"]: req_disp,
    }
    actual_responses = {
        step2["step_index"]: res_po,
        step3["step_index"]: res_inv,
        step5["step_index"]: res_disp,
        # step4 has no response (halted before execution)
    }

    result = verify_replay(
        trace,
        actual_requests=actual_requests,
        actual_responses=actual_responses,
    )

    print(f"  Status:          {'PASS ✓' if result.passed else 'FAIL ✗'}")
    print(f"  Steps total:     {result.steps_total}")
    print(f"  Steps matched:   {result.steps_matched}")
    print(f"  Mismatches:      {len(result.mismatches)}")
    assert result.passed, f"Replay should pass: {result.mismatches}"

    # ── Demonstrate mismatch detection ────────────────────────────────────────
    separator("Replay verification — tampered response detected")
    print("  Simulating: snapshot for read_erp_po was modified...")

    tampered_responses = dict(actual_responses)
    tampered_responses[step2["step_index"]] = {
        **res_po,
        "amount_usd": 3000,  # attacker changed the amount
    }

    tampered_result = verify_replay(
        trace,
        actual_requests=actual_requests,
        actual_responses=tampered_responses,
    )

    print(f"  Status:  {'PASS' if tampered_result.passed else 'FAIL — mismatch detected ✓'}")
    for mismatch in tampered_result.mismatches:
        print(f"  ✗ step [{mismatch['step_index']}] {mismatch['field']}:")
        print(f"      recorded: ...{mismatch['recorded'][-16:]}")
        print(f"      actual:   ...{mismatch['actual'][-16:]}")

    assert not tampered_result.passed, "Tampered replay should fail!"
    print("\n  ✓ Snapshot tampering correctly detected")

    # ── YAML export ───────────────────────────────────────────────────────────
    separator("Trace excerpt (YAML — first 3 steps)")
    excerpt = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run_id"],
        "model": trace["model"],
        "bundles": trace["bundles"],
        "steps": trace["steps"][:3],
    }
    print(yaml.dump(excerpt, default_flow_style=False, sort_keys=False))

    print("  Replay trace demo complete. ✓\n")


if __name__ == "__main__":
    main()
