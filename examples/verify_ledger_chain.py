#!/usr/bin/env python3
"""
GATE Python Examples - Ledger Chain Verification
==================================================
Demonstrates building a multi-event ledger chain, verifying it, and
detecting tampering.

This covers the Check05 conformance test: "Immutable, tamper-evident
audit ledger." The scenario:

  1. Build a chain of 5 ledger events across two agent runs
  2. Verify the chain passes (PASS)
  3. Simulate tampering with event 3
  4. Verify the chain detects the tamper (FAIL at event 3)
  5. Show the integrity report format

Run: python examples/verify_ledger_chain.py
"""

import copy
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gate.ledger import LedgerChain, verify_chain, verify_single_event, GENESIS


def separator(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def main() -> None:
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║     GATE Ledger Chain Verification Demo              ║")
    print("╚══════════════════════════════════════════════════════╝")

    # ── Build a chain of events ───────────────────────────────────────────────
    separator("Building ledger chain: 5 events across 2 runs")

    chain = LedgerChain(
        tenant_id="acme-corp",
        environment="prod",
        sink_uri="worm://audit/prod/2026/04/13/",
        retention_class="prod_hot_365d",
        initial_prev_hash=GENESIS,
    )

    # Run A: 3 events
    run_a = str(uuid.uuid4())
    events_meta = [
        ("tool.invoke", "read_erp_po",       "sha256:" + "a1b2" * 16, "sha256:" + "b2c3" * 16),
        ("tool.invoke", "read_erp_invoice",   "sha256:" + "c3d4" * 16, "sha256:" + "d4e5" * 16),
        ("tool.invoke", "create_dispute_case","sha256:" + "e5f6" * 16, "sha256:" + "f6a1" * 16),
    ]

    for action_type, tool_name, req_hash, res_hash in events_meta:
        ev = chain.append(
            run_id=run_a,
            action_type=action_type,
            policy_decision_id=str(uuid.uuid4()),
            tool_request_hash=req_hash,
            tool_response_hash=res_hash,
            trace_id="trace-run-a",
            tool_name=tool_name,
            agent_instance_id="spiffe://org/agent/invoice-recon#run-a",
        )
        print(f"  [{ev['sequence_number']}] {tool_name:<30} hash: ...{ev['hash_chain']['event_hash'][-8:]}")

    # Run B: 2 events (different agent, chain continues)
    run_b = str(uuid.uuid4())
    for action_type, tool_name, req_hash, res_hash in [
        ("tool.invoke", "read_crm_contact", "sha256:" + "1a2b" * 16, "sha256:" + "2b3c" * 16),
        ("tool.invoke", "create_ticket",    "sha256:" + "3c4d" * 16, "sha256:" + "4d5e" * 16),
    ]:
        ev = chain.append(
            run_id=run_b,
            action_type=action_type,
            policy_decision_id=str(uuid.uuid4()),
            tool_request_hash=req_hash,
            tool_response_hash=res_hash,
            trace_id="trace-run-b",
            tool_name=tool_name,
            agent_instance_id="spiffe://org/agent/customer-support#run-b",
        )
        print(f"  [{ev['sequence_number']}] {tool_name:<30} hash: ...{ev['hash_chain']['event_hash'][-8:]}")

    print(f"\n  Chain length: {chain.length} events")
    print(f"  Head hash:   ...{chain.head_hash[-16:]}")

    # ── Verify the intact chain ───────────────────────────────────────────────
    separator("Verification 1: Intact chain")
    result = verify_chain(chain.events)
    print(f"  Status:          {'PASS ✓' if result.passed else 'FAIL ✗'}")
    print(f"  Events verified: {result.events_verified}")
    print(f"  Errors:          {len(result.errors)}")

    assert result.passed, "Intact chain should pass!"

    # ── Single event verification ─────────────────────────────────────────────
    separator("Verification 2: Single event self-consistency check")
    for i, ev in enumerate(chain.events):
        valid = verify_single_event(ev)
        status = "✓" if valid else "✗"
        print(f"  Event [{i+1}] {ev.get('governed_action', {}).get('tool_name', 'unknown'):<30} {status}")

    # ── Simulate tampering ────────────────────────────────────────────────────
    separator("Verification 3: Tampered chain detection")
    print("  Simulating: attacker modifies event [3] tool_response_hash...")

    tampered_events = copy.deepcopy(chain.events)

    # Attacker changes the response hash in event 3 (index 2)
    original_hash = tampered_events[2]["references"]["tool_response_hash"]
    tampered_hash = "sha256:" + "deadbeef" * 8
    tampered_events[2]["references"]["tool_response_hash"] = tampered_hash

    print(f"  Original:  ...{original_hash[-16:]}")
    print(f"  Tampered:  ...{tampered_hash[-16:]}")

    tampered_result = verify_chain(tampered_events)
    print(f"\n  Status:          {'PASS' if tampered_result.passed else 'FAIL — tampering detected ✓'}")
    print(f"  Events verified: {tampered_result.events_verified}")
    print(f"  Errors:          {len(tampered_result.errors)}")

    for err in tampered_result.errors:
        print(f"\n  ✗ Error at index {err.event_index} (event_id: {err.event_id[:8]}...):")
        print(f"    {err}")

    assert not tampered_result.passed, "Tampered chain should fail!"
    assert tampered_result.errors[0].event_index == 2, \
        "Error should be at event index 2"
    print("\n  ✓ Tampering correctly detected at event [3]")

    # ── Simulate gap in sequence numbers ────────────────────────────────────
    separator("Verification 4: Sequence number gap detection")
    print("  Simulating: sequence number jump from 2 to 4 (event 3 missing)...")

    # Remove event at index 2 to simulate a missing event in the chain
    gapped_events = copy.deepcopy(chain.events)
    gapped_events.pop(2)  # Remove event 3

    gap_result = verify_chain(gapped_events)
    print(f"  Status:  {'PASS' if gap_result.passed else 'FAIL — gap detected ✓'}")
    print(f"  Errors:  {len(gap_result.errors)}")
    for err in gap_result.errors:
        print(f"  ✗ {err}")

    assert not gap_result.passed, "Chain with gap should fail!"
    print("\n  ✓ Sequence gap correctly detected")

    # ── Integrity report format ───────────────────────────────────────────────
    separator("Conformance report: ledger integrity (Check05)")

    # This is the format a conformance runner would produce
    report = {
        "check_id": "Check05",
        "title": "Immutable, tamper-evident audit ledger",
        "control": "C11",
        "assessment_period": "2026-04-13T00:00:00Z / 2026-04-13T23:59:59Z",
        "tenant_id": "acme-corp",
        "environment": "prod",
        "result": {
            "status": "PASS" if result.passed else "FAIL",
            "events_verified": result.events_verified,
            "chain_errors": len(result.errors),
            "sequence_gaps": 0,
            "tamper_simulation": "DETECTED",
        },
        "evidence_refs": [
            "worm://audit/prod/2026/04/13/integrity_report.json",
        ],
        "notes": (
            "Intact chain: PASS. "
            "Tamper simulation at event [3]: correctly detected. "
            "Sequence gap simulation: correctly detected."
        ),
    }

    print(json.dumps(report, indent=2))
    print("\n  All checks passed. Ledger chain is tamper-evident. ✓\n")


if __name__ == "__main__":
    main()
