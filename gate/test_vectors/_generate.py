"""
Generator for canonical_json_vectors.json.

Run from the repo root:

    python gate/test_vectors/_generate.py

Writes gate/test_vectors/canonical_json_vectors.json deterministically.
Each vector pairs an input value with the canonical JSON bytes and the
GATE-format sha256 hash computed via the existing gate.hashing module.
The resulting file is the cross-language compatibility source consumed
by gate-rust (Workstream 6) and verified inside this repo by
tests/test_canonical_json_vectors.py on every test run.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

# Allow running this script directly from a checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from gate.hashing import canonical_json, gate_hash  # noqa: E402


VECTORS: list[dict] = [
    {
        "id": "v001_empty_object",
        "description": "Empty object",
        "input": {},
    },
    {
        "id": "v002_empty_array",
        "description": "Empty array",
        "input": [],
    },
    {
        "id": "v003_keys_require_sort",
        "description": "Top-level keys requiring sort by Unicode code point",
        "input": {"z": 1, "a": 2, "m": 3},
    },
    {
        "id": "v004_nested_keys_require_sort",
        "description": "Nested objects with keys requiring sort",
        "input": {
            "z": {"z": 1, "a": 2},
            "a": {"z": 3, "a": 4, "m": {"y": 5, "x": 6}},
        },
    },
    {
        "id": "v005_unicode_keys_and_values",
        "description": "Non-ASCII keys and values including non-BMP emoji",
        "input": {
            "ascii": "value",
            "héllo": "world",
            "emoji": "rocket \U0001f680",
            "中文": "test",
        },
    },
    {
        "id": "v006_number_boundaries",
        "description": "Integer / float distinction, large integers, negative zero",
        "input": {
            "int_zero": 0,
            "int_negative": -42,
            "int_large": 9007199254740992,
            "float_simple": 1.5,
            "float_negative_zero": -0.0,
            "float_small_positive": 0.1,
        },
    },
    {
        "id": "v007_string_escapes",
        "description": "Strings with backslash, quote, and control characters",
        "input": {
            "backslash": "a\\b",
            "quote": "a\"b",
            "newline": "line1\nline2",
            "tab": "col1\tcol2",
            "control_null_byte_safe": "okend",
        },
    },
    {
        "id": "v008_boolean_and_null",
        "description": "Boolean true / false and null literals",
        "input": {"yes": True, "no": False, "absent": None},
    },
    {
        "id": "v009_array_order_preserved",
        "description": "Array element order is preserved (not sorted)",
        "input": {"arr": [3, 1, 2, 5, 4]},
    },
    {
        "id": "v010_nested_arrays_objects",
        "description": "Mixed arrays of objects with sorted-key requirement",
        "input": [
            {"z": 1, "a": 2},
            {"b": [3, 1, 2], "a": {"y": 1, "x": 2}},
        ],
    },
    {
        "id": "v011_tool_request_envelope_shape",
        "description": "ToolRequestEnvelope-shaped payload (subset)",
        "input": {
            "schema_version": "v1",
            "event_type": "gate.tool.request",
            "run_id": "11111111-1111-1111-1111-111111111111",
            "trace_id": "trace-abc",
            "tenant_id": "acme",
            "environment": "prod",
            "agent": {
                "agent_instance_id": "spiffe://org/agent/test#run-1",
                "agent_name": "test-agent",
                "agent_version": "1.0.0",
                "identity": {
                    "subject": "spiffe://org/agent/test",
                    "attested": True,
                },
            },
            "tool": {
                "name": "read_ticket",
                "category": "read_only",
                "risk_tier": "low",
            },
            "inputs": {
                "content_type": "application/json",
                "payload": {"ticket_id": "TKT-001"},
            },
        },
    },
    {
        "id": "v012_break_glass_record_body",
        "description": "Break-glass record body (signatures excluded; v1.4 shape)",
        "input": {
            "schema_version": "v1",
            "record_id": "22222222-2222-2222-2222-222222222222",
            "invariant_halt_event_id": "33333333-3333-3333-3333-333333333333",
            "invariant_rule_id": "INV-DELETE-001",
            "tenant_id": "acme",
            "environment": "prod",
            "approver_ids": ["role:sec-lead/u-alice", "role:eng-vp/u-bob"],
            "justification": "Emergency override for incident #4421; halt at 02:13 UTC blocks recovery of customer-impacting deploy rollback per runbook RB-09.",
            "exception_scope": "specific_run",
            "exception_expires_at": "2026-06-23T03:00:00Z",
            "signing_key_ids": ["kid-sec-lead-2026", "kid-eng-vp-2026"],
            "created_at": "2026-06-23T02:15:00Z",
            "gate_version": "1.4",
        },
    },
    {
        "id": "v013_output_classification_event_body",
        "description": "Output classification event body (v1.4 shape)",
        "input": {
            "schema_version": "v1",
            "event_type": "gate.output.classification",
            "time": "2026-06-23T02:00:00Z",
            "run_id": "44444444-4444-4444-4444-444444444444",
            "trace_id": "trace-out-1",
            "tenant_id": "acme",
            "environment": "prod",
            "output_hash": "sha256:" + "a" * 64,
            "classification": {
                "sensitivity_tier": "high",
                "regulated_categories": ["medical"],
                "confidence_score": 0.87,
                "requires_human_review": True,
            },
            "obligations": ["hitl_review", "redact_fields"],
            "bundle_hash": "sha256:" + "b" * 64,
            "ledger_event_id": "55555555-5555-5555-5555-555555555555",
        },
    },
]


def build_vectors() -> dict:
    out: list[dict] = []
    for entry in VECTORS:
        canonical_bytes = canonical_json(entry["input"])
        sha256 = gate_hash(entry["input"])
        out.append(
            {
                "id": entry["id"],
                "description": entry["description"],
                "input": entry["input"],
                "canonical_json_base64": base64.b64encode(
                    canonical_bytes
                ).decode("ascii"),
                "sha256": sha256,
            }
        )
    return {
        "version": "1.0",
        "description": (
            "Canonical JSON + sha256 vectors. Inputs paired with their "
            "RFC 8785 canonical-JSON bytes (base64-encoded) and GATE-format "
            "sha256 hashes. Authoritative cross-language compatibility source "
            "for the gate.hashing module; consumed by gate-rust (Workstream 6)."
        ),
        "vectors": out,
    }


def main() -> int:
    output_path = Path(__file__).parent / "canonical_json_vectors.json"
    data = build_vectors()
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {len(data['vectors'])} vectors to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
