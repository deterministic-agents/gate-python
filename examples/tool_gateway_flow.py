#!/usr/bin/env python3
"""
GATE Python Examples - Tool Gateway Flow
=========================================
End-to-end simulation of a tool call traversing a GATE Tool Gateway.

This example shows the complete flow for a transfer_funds tool call:

  1. Agent proposes a tool call → ToolRequestEnvelope built
  2. Tool Gateway evaluates policy (simulated) → PolicyDecisionRecord
  3. Invariant check (simulated) → passes
  4. HITL obligation fired → approval simulated
  5. Tool executes → response captured
  6. ToolResponseEnvelope built with snapshot_uri
  7. LedgerEvent built and chain-linked
  8. Action signed for non-repudiation
  9. ReplayTrace step recorded
 10. All evidence hashes verified end-to-end

Run: python examples/tool_gateway_flow.py
"""

import json
import sys
import uuid
from pathlib import Path

# Allow running from the gate-python/ root
sys.path.insert(0, str(Path(__file__).parent.parent))

from gate.hashing import gate_hash, verify_hash, canonical_json_str
from gate.envelopes import build_request, build_response, redact_payload
from gate.ledger import LedgerChain, verify_chain, GENESIS
from gate.replay import ReplayRecorder, verify_replay
from gate.signing import generate_signing_key, sign_action, verify_signature, KeyRegistry


# ─────────────────────────────────────────────────────────────────────────────
# Configuration (would come from ABOM / environment in production)
# ─────────────────────────────────────────────────────────────────────────────

AGENT_INSTANCE_ID = "spiffe://org/agent/treasury#run-" + str(uuid.uuid4())[:8]
TENANT_ID = "acme-corp"
ENVIRONMENT = "prod"
RUN_ID = str(uuid.uuid4())
TRACE_ID = "trace-" + str(uuid.uuid4())[:8]

# Simulated bundle hashes (in production: sha256sum of actual bundle files)
POLICY_BUNDLE_HASH = "sha256:" + "d4e5" * 16
PROMPT_BUNDLE_HASH = "sha256:" + "b2c3" * 16
TOOL_SCHEMA_HASH   = "sha256:" + "e5f6" * 16
INVARIANT_BUNDLE_HASH = "sha256:" + "f6a1" * 16

IMAGE_DIGEST = "sha256:" + "a1b2" * 16
CONFIG_HASH  = "sha256:" + "b2c3" * 16
TOOLSET_HASH = "sha256:" + "c3d4" * 16

SIGNING_KEY_ID = "kid-treasury-2026-04"


def separator(title: str) -> None:
    width = 60
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}")


def pprint(label: str, obj: object) -> None:
    print(f"\n{label}:")
    print(json.dumps(obj, indent=2))


# ─────────────────────────────────────────────────────────────────────────────
# Main flow
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║     GATE Tool Gateway Flow — transfer_funds          ║")
    print("╚══════════════════════════════════════════════════════╝")

    # ── Keys ─────────────────────────────────────────────────────────────────
    separator("Step 0: Key setup")
    signing_key = generate_signing_key()
    registry = KeyRegistry()
    registry.register_private(SIGNING_KEY_ID, signing_key)
    print(f"  ✓ Generated P-256 signing key: {SIGNING_KEY_ID}")

    # ── Ledger chain ─────────────────────────────────────────────────────────
    chain = LedgerChain(
        tenant_id=TENANT_ID,
        environment=ENVIRONMENT,
        sink_uri="worm://audit/prod/2026/04/13/",
        retention_class="prod_hot_365d",
        initial_prev_hash=GENESIS,
    )

    # ── Replay recorder ──────────────────────────────────────────────────────
    recorder = ReplayRecorder(
        run_id=RUN_ID,
        trace_id=TRACE_ID,
        tenant_id=TENANT_ID,
        environment=ENVIRONMENT,
        agent_instance_id=AGENT_INSTANCE_ID,
        agent_name="treasury",
        agent_version="2.1.0",
        model_id="provider/model",
        model_version="2025-11-01",
        temperature=0.1,
        seed=42,
        policy_bundle_hash=POLICY_BUNDLE_HASH,
        prompt_bundle_hash=PROMPT_BUNDLE_HASH,
        tool_schema_hash=TOOL_SCHEMA_HASH,
    )

    # ── Step 1: Context retrieval ─────────────────────────────────────────────
    separator("Step 1: Agent retrieves context")
    docs = [
        {"vendor_id": "ACME-VENDOR-442", "verified": True, "approved_limit_usd": 10000},
        {"invoice_id": "INV-2026-0441",  "amount_usd": 2500, "po_ref": "PO-2026-0318"},
    ]
    retrieve_step = recorder.record_retrieve_context(
        documents=docs,
        provenance_refs=["prov://vendor-registry/ACME-VENDOR-442", "prov://erp/INV-2026-0441"],
    )
    print(f"  ✓ Retrieved {len(docs)} documents")
    print(f"  ✓ Context hashes: {retrieve_step['retrieved_context_hashes']}")

    # ── Step 2: Build tool request envelope ───────────────────────────────────
    separator("Step 2: Build ToolRequestEnvelope")
    tool_payload = {
        "destination_account": "ACME-VENDOR-442",
        "amount_usd": 2500,
        "currency": "USD",
        "reference": "INV-2026-0441",
        "destination_verified": True,
        "idempotency_key": "idem-" + str(uuid.uuid4()),
    }

    request_env = build_request(
        run_id=RUN_ID,
        trace_id=TRACE_ID,
        tenant_id=TENANT_ID,
        environment=ENVIRONMENT,
        agent_instance_id=AGENT_INSTANCE_ID,
        agent_name="treasury",
        agent_version="2.1.0",
        attested=True,
        image_digest=IMAGE_DIGEST,
        config_hash=CONFIG_HASH,
        toolset_hash=TOOLSET_HASH,
        tool_name="transfer_funds",
        tool_category="financial",
        risk_tier="high",
        payload=tool_payload,
        idempotency_key=tool_payload["idempotency_key"],
        policy_bundle_hash=POLICY_BUNDLE_HASH,
        prompt_bundle_hash=PROMPT_BUNDLE_HASH,
        tool_schema_hash=TOOL_SCHEMA_HASH,
        orm_risk_score=0.58,
        tokens_remaining=15000,
        tool_calls_remaining=45,
        cost_usd_remaining=12.50,
        source_labels=["user_input", "retrieved_doc"],
    )

    request_hash = request_env["hashes"]["request_hash"]
    print(f"  ✓ event_type: {request_env['event_type']}")
    print(f"  ✓ tool:       {request_env['tool']['name']} ({request_env['tool']['category']})")
    print(f"  ✓ request_hash: {request_hash}")
    print(f"  ✓ attested:   {request_env['agent']['identity']['attested']}")
    print(f"  ✓ orm_score:  {request_env['context']['orm_risk_score']}")

    # Verify the hash is correct
    assert verify_hash(tool_payload, request_hash), "request_hash mismatch!"
    print("  ✓ request_hash verified against payload ✓")

    # ── Step 3: Policy evaluation (simulated) ─────────────────────────────────
    separator("Step 3: Policy evaluation (OPA/Rego — simulated)")
    decision_id = str(uuid.uuid4())
    policy_decision = {
        "schema_version": "v1",
        "event_type": "gate.policy.decision",
        "decision_id": decision_id,
        "run_id": RUN_ID,
        "trace_id": TRACE_ID,
        "tenant_id": TENANT_ID,
        "environment": ENVIRONMENT,
        "subject": {
            "agent_instance_id": AGENT_INSTANCE_ID,
            "subject_id": AGENT_INSTANCE_ID.split("#")[0],
            "attested": True,
        },
        "action": {
            "type": "tool.invoke",
            "tool_name": "transfer_funds",
            "tool_category": "financial",
            "risk_tier": "high",
        },
        "inputs": {
            "request_hash": request_hash,
            "orm_risk_score": 0.58,
        },
        "bundles": {
            "policy_bundle_hash": POLICY_BUNDLE_HASH,
            "tool_schema_hash": TOOL_SCHEMA_HASH,
        },
        "result": {
            "decision": "allow",
            "reason_codes": ["ALLOWLIST_MATCH", "BUDGET_OK"],
            "obligations": [
                {"type": "audit_log",              "required": True},
                {"type": "sign_action",            "required": True},
                {"type": "hitl_approval",          "required": True},
                {"type": "verify_destination",     "required": True},
                {"type": "snapshot_response",      "required": True},
                {"type": "require_idempotency_key","required": True},
            ],
        },
    }
    print(f"  ✓ decision:      {policy_decision['result']['decision']}")
    print(f"  ✓ reason_codes:  {policy_decision['result']['reason_codes']}")
    print(f"  ✓ obligations:   {[o['type'] for o in policy_decision['result']['obligations']]}")

    # ── Step 4: Invariant check (simulated) ───────────────────────────────────
    separator("Step 4: Invariant check (C09 — simulated)")
    # In production: send request to OPA invariant bundle evaluation
    # Simulated: amount_usd 2500 < hard limit 10000 → PASS
    amount = tool_payload["amount_usd"]
    hard_limit = 10000
    assert amount <= hard_limit, f"INV-FINANCIAL-001: {amount} > {hard_limit}"
    assert tool_payload["destination_verified"], "INV-FINANCIAL-002: destination not verified"
    print(f"  ✓ INV-FINANCIAL-001: {amount} ≤ {hard_limit} → PASS")
    print(f"  ✓ INV-FINANCIAL-002: destination_verified = True → PASS")
    print(f"  ✓ All invariants passed — proceeding to HITL gate")

    # ── Step 5: HITL approval (simulated) ─────────────────────────────────────
    separator("Step 5: HITL approval gate (obligation: hitl_approval)")
    approval_id = str(uuid.uuid4())

    # Simulate the HITL approval decision and sign it
    hitl_decision_payload = {
        "approver_id": "user:treasury.manager@acme.com",
        "action": "approve",
        "justification": "Vendor verified, invoice matched, within single transaction limit.",
        "conditions": ["must_use_account:primary", "max_amount_usd:2500"],
    }
    hitl_signature = sign_action(
        payload=hitl_decision_payload,
        private_key=signing_key,
        key_id=SIGNING_KEY_ID,
    )
    print(f"  ✓ Approval ID:   {approval_id}")
    print(f"  ✓ Approver:      {hitl_decision_payload['approver_id']}")
    print(f"  ✓ Action:        {hitl_decision_payload['action']}")
    print(f"  ✓ Signature alg: {hitl_signature['algorithm']}")

    hitl_sig_valid = registry.verify(
        payload=hitl_decision_payload,
        signature_record=hitl_signature,
    )
    assert hitl_sig_valid, "HITL signature verification failed!"
    print(f"  ✓ HITL signature verified ✓")

    # Record HITL gate in replay trace
    hitl_ledger_id = str(uuid.uuid4())
    recorder.record_hitl_gate(
        tool_name="transfer_funds",
        approval_id=approval_id,
        approved=True,
        ledger_event_id=hitl_ledger_id,
    )

    # ── Step 6: Tool executes → response ─────────────────────────────────────
    separator("Step 6: Tool execution")
    raw_response = {
        "transaction_id": "TXN-" + str(uuid.uuid4())[:8].upper(),
        "status": "completed",
        "amount_usd": 2500,
        "destination": "ACME-VENDOR-442",
        "settled_at": "2026-04-13T14:24:45Z",
        # Simulated sensitive field that would be redacted in logs:
        "bank_reference": "BREF-9A8B7C",
    }

    # Redact sensitive fields before logging
    redacted_response = redact_payload(
        raw_response,
        sensitive_fields=["bank_reference"],
    )
    response_hash = gate_hash(raw_response)  # Hash the FULL response
    snapshot_uri = f"immutable://snapshots/transfer_funds/{RUN_ID}/step-5.json"

    print(f"  ✓ transaction_id: {raw_response['transaction_id']}")
    print(f"  ✓ status:         {raw_response['status']}")
    print(f"  ✓ response_hash:  {response_hash}")
    print(f"  ✓ redacted:       {redacted_response}")

    # ── Step 7: Build LedgerEvent ─────────────────────────────────────────────
    separator("Step 7: Build and sign LedgerEvent")
    ledger_event = chain.append(
        run_id=RUN_ID,
        action_type="tool.invoke",
        policy_decision_id=decision_id,
        tool_request_hash=request_hash,
        tool_response_hash=response_hash,
        trace_id=TRACE_ID,
        hitl_approval_id=approval_id,
        invariant_bundle_hash=INVARIANT_BUNDLE_HASH,
        tool_name="transfer_funds",
        agent_instance_id=AGENT_INSTANCE_ID,
    )

    event_hash = ledger_event["hash_chain"]["event_hash"]
    print(f"  ✓ ledger_event_id: {ledger_event['ledger_event_id']}")
    print(f"  ✓ sequence_number: {ledger_event['sequence_number']}")
    print(f"  ✓ prev_event_hash: {ledger_event['hash_chain']['prev_event_hash']}")
    print(f"  ✓ event_hash:      {event_hash}")

    # Sign the event hash
    event_sig = sign_action(
        payload={"event_hash": event_hash},
        private_key=signing_key,
        key_id=SIGNING_KEY_ID,
    )
    ledger_event["signatures"] = event_sig
    print(f"  ✓ Signed event hash with {SIGNING_KEY_ID}")

    event_sig_valid = registry.verify(
        payload={"event_hash": event_hash},
        signature_record=event_sig,
    )
    assert event_sig_valid, "Event signature verification failed!"
    print(f"  ✓ Event signature verified ✓")

    # ── Step 8: Build ToolResponseEnvelope ───────────────────────────────────
    separator("Step 8: Build ToolResponseEnvelope")
    replay_step_id = f"step-{recorder._step_index + 1}"
    response_env = build_response(
        request_envelope=request_env,
        tool_output=redacted_response,
        status="success",
        duration_ms=312,
        decision_id=decision_id,
        decision="allow",
        obligations=["audit_log", "sign_action", "hitl_approval",
                     "verify_destination", "snapshot_response",
                     "require_idempotency_key"],
        policy_bundle_hash=POLICY_BUNDLE_HASH,
        ledger_event_id=ledger_event["ledger_event_id"],
        snapshot_uri=snapshot_uri,
        replay_trace_step_id=replay_step_id,
    )
    print(f"  ✓ event_type:     {response_env['event_type']}")
    print(f"  ✓ tool status:    {response_env['tool']['status']}")
    print(f"  ✓ response_hash:  {response_env['hashes']['response_hash']}")
    print(f"  ✓ snapshot_uri:   {response_env['outputs']['snapshot_uri']}")

    # ── Step 9: Record tool call in replay trace ──────────────────────────────
    separator("Step 9: Record replay trace step")
    tool_step = recorder.record_tool_call(
        tool_name="transfer_funds",
        request_payload=tool_payload,
        response_payload=raw_response,  # hash over FULL response
        policy_decision_id=decision_id,
        ledger_event_id=ledger_event["ledger_event_id"],
        snapshot_uri=snapshot_uri,
        duration_ms=312,
    )
    print(f"  ✓ step_index:     {tool_step['step_index']}")
    print(f"  ✓ step_type:      {tool_step['step_type']}")
    print(f"  ✓ request_hash:   {tool_step['request_hash']}")
    print(f"  ✓ response_hash:  {tool_step['response_hash']}")

    # Record final output
    recorder.record_final_output(output={"status": "completed", "run_id": RUN_ID})

    # ── Step 10: End-to-end evidence verification ─────────────────────────────
    separator("Step 10: End-to-end evidence verification")

    # 1. Verify request_hash links payload → envelope
    assert verify_hash(tool_payload, request_hash), "FAIL: request_hash"
    print("  ✓ request_hash verified (payload → envelope)")

    # 2. Verify response_hash links response → envelope
    assert verify_hash(raw_response, response_hash), "FAIL: response_hash"
    print("  ✓ response_hash verified (response → envelope)")

    # 3. Verify request_hash in policy decision matches envelope
    assert policy_decision["inputs"]["request_hash"] == request_hash, \
        "FAIL: policy decision request_hash mismatch"
    print("  ✓ PolicyDecisionRecord.request_hash == ToolRequestEnvelope.request_hash")

    # 4. Verify tool_request_hash in ledger matches envelope
    assert ledger_event["references"]["tool_request_hash"] == request_hash, \
        "FAIL: ledger tool_request_hash mismatch"
    print("  ✓ LedgerEvent.tool_request_hash == ToolRequestEnvelope.request_hash")

    # 5. Verify ledger chain integrity
    chain_result = verify_chain(chain.events)
    assert chain_result.passed, f"FAIL: ledger chain: {chain_result.errors}"
    print(f"  ✓ Ledger chain verified ({chain_result.events_verified} events, PASS)")

    # 6. Verify replay trace
    replay_result = verify_replay(
        recorder.to_dict(),
        actual_requests={tool_step["step_index"]: tool_payload},
        actual_responses={tool_step["step_index"]: raw_response},
    )
    assert replay_result.passed, f"FAIL: replay: {replay_result.mismatches}"
    print(f"  ✓ Replay trace verified ({replay_result.steps_matched} steps matched, PASS)")

    # 7. Verify event signature
    assert event_sig_valid, "FAIL: event signature"
    print("  ✓ LedgerEvent signature verified")

    # 8. Verify HITL signature
    assert hitl_sig_valid, "FAIL: HITL signature"
    print("  ✓ HITL decision signature verified")

    # ── Complete summary ──────────────────────────────────────────────────────
    separator("Complete — Evidence chain summary")
    trace = recorder.to_dict()
    print(f"""
  run_id:                {RUN_ID}
  trace_id:              {TRACE_ID}
  tool:                  transfer_funds ($2,500)
  decision:              allow
  obligations enforced:  audit_log, sign_action, hitl_approval,
                         verify_destination, snapshot_response,
                         require_idempotency_key
  request_hash:          {request_hash}
  response_hash:         {response_hash}
  event_hash:            {event_hash}
  ledger events:         {chain.length}
  replay steps:          {len(trace['steps'])}
  chain integrity:       PASS
  replay verification:   PASS
  event signature:       PASS
  HITL signature:        PASS

  Evidence traversal:
    ToolRequest.request_hash
      → PolicyDecision.inputs.request_hash     ✓
      → LedgerEvent.references.tool_request_hash ✓
      → ReplayTrace step.request_hash           ✓
""")
    print("  All checks passed. ✓\n")


if __name__ == "__main__":
    main()
