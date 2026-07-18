"""
Backward-compatibility regression test.

Walks tests/fixtures/v1_1_0/ and validates every fixture against the
corresponding v1.2.0 schema. Every v1.1.0 fixture MUST pass v1.2.0
validation. A failure here is a v1.2.0 design bug: a non-additive
schema change slipped through and must be reverted before v1.2.0
ships.

Minimum coverage (per the W5 brief): agent_state, abom,
quality_decision (the three surfaces with extension diffs). Plus
agent_discovered, agent_remediation_outcome, drift_decision, and
response_action (the other v1.1.0 schemas the v1.1.0 tests exercised).

Run: pytest tests/test_v1_1_0_compatibility.py -v
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gate.validation import GATEValidator


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "v1_1_0"


# Fixture filename -> schema filename mapping. Operators add new
# fixtures by extending this map.
FIXTURE_SCHEMA_MAP: dict[str, str] = {
    "agent_state_run_v1_1_0.json": "agent_state.schema.json",
    "agent_state_discovered_v1_1_0.json": "agent_state.schema.json",
    "agent_state_commissioned_v1_1_0.json": "agent_state.schema.json",
    "abom_v1_1_0.json": "abom.schema.json",
    "quality_decision_v1_1_0_pass.json": "quality_decision.schema.json",
    "quality_decision_v1_1_0_flag.json": "quality_decision.schema.json",
    "agent_discovered_v1_1_0.json": "agent_discovered.schema.json",
    "agent_remediation_outcome_v1_1_0.json": "agent_remediation_outcome.schema.json",
    "drift_decision_v1_1_0.json": "drift_decision.schema.json",
    "response_action_v1_1_0.json": "response_action.schema.json",
}


@pytest.fixture(scope="module")
def validator():
    # Use the bundled gate/schemas/ directory (the v1.2.0 schemas).
    schema_dir = Path(__file__).resolve().parent.parent / "gate" / "schemas"
    return GATEValidator(schema_dir=schema_dir)


def test_all_fixtures_present():
    found = {p.name for p in FIXTURE_DIR.glob("*.json")}
    missing = set(FIXTURE_SCHEMA_MAP) - found
    assert not missing, f"missing fixture files: {sorted(missing)}"
    extra = found - set(FIXTURE_SCHEMA_MAP)
    # Extras are not a failure; the operator may add new fixtures
    # without immediately mapping them. Surface as informational.
    if extra:
        pytest.fail(
            f"fixture files present but not mapped to a schema: "
            f"{sorted(extra)}. Add an entry to FIXTURE_SCHEMA_MAP."
        )


@pytest.mark.parametrize(
    "fixture_filename,schema_filename",
    sorted(FIXTURE_SCHEMA_MAP.items()),
    ids=sorted(FIXTURE_SCHEMA_MAP),
)
def test_v1_1_0_fixture_validates_against_v1_2_0_schema(
    validator, fixture_filename, schema_filename
):
    fixture_path = FIXTURE_DIR / fixture_filename
    with fixture_path.open(encoding="utf-8") as f:
        instance = json.load(f)
    result = validator.validate_any(instance, schema_filename)
    assert result.valid, (
        f"v1.1.0 fixture {fixture_filename} fails v1.2.0 validation "
        f"against {schema_filename}. This indicates a non-additive "
        f"schema change in v1.2.0 that breaks backward compatibility:\n"
        f"{result.summary()}"
    )
