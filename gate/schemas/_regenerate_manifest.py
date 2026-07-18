"""
Regenerator for gate/schemas/MANIFEST.yaml.

Run from the repo root:

    python gate/schemas/_regenerate_manifest.py

Computes the GATE-format sha256 hash over the canonical-JSON
serialisation of each bundled schema (matching gate.hashing for cross-
language consistency with the test vectors) and writes the MANIFEST.

The signing identity and signature fields are left as placeholders;
operators populate them at release time.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from a checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from gate.hashing import gate_hash  # noqa: E402


SCHEMA_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = SCHEMA_DIR / "MANIFEST.yaml"


# (filename, introduced_in, used_by_control). Order is the order the
# entries appear in the manifest.
SCHEMAS: list[tuple[str, str | None, str | None]] = [
    # v1.0.0 schemas (carried forward unchanged; re-pin from
    # gate-contracts v1.2.0 at release time).
    ("tool_envelope.schema.json", None, None),
    ("policy_decision_record.schema.json", None, None),
    ("audit_ledger_event.schema.json", None, None),
    ("replay_trace.schema.json", None, None),
    ("hitl_decision_record.schema.json", None, None),
    ("multi_agent_envelope.schema.json", None, None),

    # v1.3 / v1.1.0 additions (unchanged in v1.2.0).
    ("agent_discovered.schema.json", "1.1.0", "C17"),
    ("agent_remediation_outcome.schema.json", "1.1.0", "C17"),
    ("behavioural_baseline.schema.json", "1.1.0", "C19"),
    ("drift_decision.schema.json", "1.1.0", "C19"),
    ("response_action.schema.json", "1.1.0", "C19"),
    ("memory_item.schema.json", "1.1.0", "C18"),
    ("memory_request.schema.json", "1.1.0", "C18"),
    ("memory_response.schema.json", "1.1.0", "C18"),

    # v1.4 / v1.2.0 extensions (existing schemas bumped to v1.2.0).
    ("agent_state.schema.json", "1.1.0", "C04"),
    ("abom.schema.json", "1.1.0", "C04"),
    ("quality_decision.schema.json", "1.1.0", "C18"),

    # v1.4 / v1.2.0 new schemas.
    ("break_glass_record.schema.json", "1.2.0", "C09"),
    ("auto_enrolment_policy.schema.json", "1.2.0", "C17"),
    ("output_classification_event.schema.json", "1.2.0", "C20"),
    ("approved_feed_registry.schema.json", "1.2.0", "C18"),
]


def _hash_schema(filename: str) -> str | None:
    path = SCHEMA_DIR / filename
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        schema = json.load(f)
    return gate_hash(schema)


def build_manifest() -> str:
    lines: list[str] = []
    lines.append("# gate-python embedded schema bundle - v1.2.0")
    lines.append("#")
    lines.append("# Schemas bundled with gate-python so the validation module can run")
    lines.append("# without depending on the gate-contracts repo at runtime. Hashes")
    lines.append("# below are pinned at release time; if the bundled schemas drift")
    lines.append("# from gate-contracts the validator will silently disagree with")
    lines.append("# peers.")
    lines.append("#")
    lines.append("# Hash function: gate.hashing.gate_hash over the canonical JSON of")
    lines.append("# each schema, matching gate/test_vectors/canonical_json_vectors.json.")
    lines.append("")
    lines.append('gate_contracts_version: "1.2.0"')
    lines.append(
        'gate_contracts_source: '
        '"https://github.com/deterministic-agents/gate-contracts/releases/tag/v1.2.0"'
    )
    lines.append("")
    lines.append("# Signing identity and signature fields populated at release time.")
    lines.append('signing_key_id: "PENDING_AT_RELEASE"')
    lines.append('signature: "PENDING_AT_RELEASE"')
    lines.append("")
    lines.append("schemas:")

    for filename, introduced_in, used_by in SCHEMAS:
        digest = _hash_schema(filename)
        if digest is None:
            lines.append(f"  - filename: {filename}")
            lines.append(f"    sha256:   PENDING_AT_RELEASE")
            if introduced_in:
                lines.append(f'    introduced_in: "{introduced_in}"')
            if used_by:
                lines.append(f"    used_by_control: {used_by}")
        else:
            lines.append(f"  - filename: {filename}")
            lines.append(f"    sha256:   {digest}")
            if introduced_in:
                lines.append(f'    introduced_in: "{introduced_in}"')
            if used_by:
                lines.append(f"    used_by_control: {used_by}")

    return "\n".join(lines) + "\n"


def main() -> int:
    content = build_manifest()
    MANIFEST_PATH.write_text(content, encoding="utf-8")
    print(f"wrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
