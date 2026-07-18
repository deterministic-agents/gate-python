# CHANGELOG - gate-python

## v1.2.0

Released: 2026-07-18
Previous version: v1.1.0
GATE framework version: v1.4
gate-contracts version: v1.2.0

Library changes accompanying the GATE v1.4 framework release.
Cross-reference: the framework-level CHANGELOG entry in the v1.4 paper
(paper-updates/10-changelog-v1.4.md) carries the full release story
including the new repos (gate-rust, gate-fuzz, gate-knowledge), the
contracts and policy updates, and the v1.5 deferral notes. This entry
is scoped to library-level changes in gate-python.

### Added (new modules)

- `gate.output` for the C20 output classification surface. Public
  surface: `build_output_classification_event`,
  `evaluate_output_sensitivity`, `apply_output_action_matrix`,
  `select_retention_class`, and the `OutputClassificationBundle`
  class. The action matrix is configuration-driven (no obligation
  values hardcoded in the library); the fail-closed high-privilege
  guardrail in `apply_output_action_matrix` mirrors the
  `enforce_default_high_privilege_hold` rule in
  `policies/output/c20_output_classification.rego` in gate-policies
  v1.2.0. Per-entry `retention_class` selection follows Erratum 2 /
  Erratum 3 in `v1.4/paper-updates/01-C20-errata.md`: a matched
  entry's value wins; absent entries fall back to the per-tier
  default (`sandbox_hot_30d` at sandbox, `prod_cold_6y_worm` at
  bounded and high-privilege).

- `gate.invariants.break_glass` for the C09 contracted break-glass
  record. Public surface: `build_break_glass_record`,
  `verify_break_glass_record`. The builder enforces the schema-level
  invariants (dual-approval cardinality, scope-discriminator
  cross-fields, 50-character justification floor). The verify helper
  catches the same surface as defence-in-depth before a record reaches
  the authoritative policy in
  `policies/invariants/c09_break_glass_verification.rego`; the policy
  remains authoritative for the cross-document checks (halt-event
  tenant/environment/rule match) that need both the record and the
  halt event as inputs.

### Added (new files)

- `gate/test_vectors/canonical_json_vectors.json` (v1.0). Cross-
  language hash-compatibility source. Thirteen vectors covering empty
  containers, sorted-key requirements, non-BMP Unicode, number
  boundaries, string escapes, mixed nested structures, and real
  contract shapes (ToolRequestEnvelope, break_glass_record body,
  output_classification_event body). Generated and round-tripped by
  `gate/test_vectors/_generate.py`; verified inside this repo by
  `tests/test_canonical_json_vectors.py` on every test run. Consumed
  by gate-rust (Workstream 6) as the authoritative source for
  `canonical_json` and `gate_hash` cross-language compatibility.

- `pyproject.toml` (new in v1.4). Hatchling build backend. Package
  metadata mirrors the existing `requirements.txt` dependency set:
  `cryptography>=42`, `jsonschema>=4`, `pyyaml>=6`, `requests>=2.31`.
  Optional extras: `assurance` (scipy for C19 drift score), `dev`
  (pytest, pytest-cov, scipy). PyPI publication is deferred to v1.5;
  the install line in the README points at the tagged git ref
  (`pip install git+https://github.com/deterministic-agents/gate-python.git@v1.2.0`).

- `tests/fixtures/v1_1_0/` (ten JSON fixtures) plus
  `tests/test_v1_1_0_compatibility.py`. The compatibility test loads
  every v1.1.0 fixture and asserts it validates against the v1.2.0
  schema bundled in `gate/schemas/`. A failure here is a v1.2.0
  design bug: a non-additive schema change slipped through and must
  be reverted before v1.2.0 ships.

### Changed (extensions)

- `gate/schemas/agent_state.schema.json` v1.1.0 -> v1.2.0.
  AutoEnrolled state added; `auto_enrolment_policy_hash` and
  `enrolment_mode` optional fields added; two new `allOf` branches
  enforce `state=AutoEnrolled implies enrolment_mode=automated` and
  `enrolment_mode=automated implies auto_enrolment_policy_hash
  present`. Backward-compatible per the regression test
  (v1.1.0 fixtures validate cleanly).

- `gate/schemas/abom.schema.json` v1.1.0 -> v1.2.0. Optional
  `output_classification_bundle_hash` and `auto_enrolment_eligible`
  (default `false`) fields added. Backward-compatible.

- `gate/schemas/quality_decision.schema.json` v1.1.0 -> v1.2.0.
  Optional `source_registry_hash` and `feed_registry_hash` fields
  added; `provenance_unregistered` added to the `flags_set` enum.
  Backward-compatible.

- `gate/schemas/MANIFEST.yaml` regenerated. `gate_contracts_version`
  bumped to `1.2.0`. Hashes recomputed via
  `gate/schemas/_regenerate_manifest.py`, using the same
  canonical_json + sha256 used by `gate.hashing` for cross-language
  consistency with the test vectors. v1.0.0 schemas
  (tool_envelope, policy_decision_record, audit_ledger_event,
  replay_trace, hitl_decision_record, multi_agent_envelope) remain
  `PENDING_AT_RELEASE` matching the v1.1.0 manifest convention; these
  schemas are not bundled in `gate/schemas/`.

- `gate/validation.py` extended with four new validators:
  `validate_output_classification_event`,
  `validate_break_glass_record`,
  `validate_auto_enrolment_policy`,
  `validate_approved_feed_registry`. Each follows the existing
  `validate_*` pattern (SCHEMA_ constant, GATEValidator method,
  module-level convenience function). Cosmetic: the v1.1.0
  `ValidationResult.summary()` em-dashes in the PASS / FAIL formatter
  strings replaced with spaced hyphens to match v1.4 style discipline;
  no behavioural change. The extension is also delivered as a
  paste-ready diff at `gate/validation-v1.2.0-diff.md`.

- `gate/__init__.py` `__version__` bumped to `1.2.0`,
  `__gate_version__` bumped to `1.4`. Module list updated to include
  `gate.output` and `gate.invariants.break_glass`.

### Convention notes

- **No pydantic dependency.** The C20 spec named
  `class OutputClassificationBundle(BaseModel)` (Pydantic BaseModel
  shape). The existing gate-python v1.1.0 library has no pydantic
  dependency; the codebase uses plain classes and dicts. The v1.2.0
  module ships `OutputClassificationBundle` as a plain class with
  load / verify_signature / apply / bundle_hash methods, matching the
  v1.1.0 idiom. Introducing pydantic would be a substantial new
  dependency; deferring to v1.5 if a future contract shape demands it.

- **Cross-language test vectors live in gate-python (W5), consumed by
  gate-rust (W6).** No internal handoff to gate-policies (W3). The
  vectors are generated deterministically from `gate.hashing`; any
  change in `gate.hashing` requires the operator to re-run
  `gate/test_vectors/_generate.py` and bump the version field if the
  shape changes.

- **Backward-compatibility regression is normative.**
  `tests/test_v1_1_0_compatibility.py` is the contract-enforcement
  test for the gate-python release. If a v1.1.0 fixture fails on a
  future v1.2.0+ release build, that is a design bug to surface, not
  a test to relax. New fixture coverage is added by dropping a JSON
  file under `tests/fixtures/v1_1_0/` and adding the mapping to
  `FIXTURE_SCHEMA_MAP`.

- **PyPI publication deferred to v1.5.** v1.4 ships gate-python as a
  git-installable package only. The pyproject.toml metadata avoids
  any `[project.urls]` entry that suggests PyPI presence; the
  Documentation URL points at `https://deterministicagents.ai/`.

### Backward compatibility

All v1.2.0 library changes are backward-compatible with v1.1.0.
Existing import paths continue to work. The two new modules
(`gate.output`, `gate.invariants.break_glass`) are additive. The
extended schemas in `gate/schemas/` validate v1.1.0 fixtures cleanly
per the regression test. The validation.py extensions add four new
methods and four new module-level functions; existing methods and
functions are unchanged.

### Test summary

- 195 tests pass (all 137 v1.1.0 tests plus 58 v1.2.0 tests; scipy
  installed). 191 pass / 1 skip without scipy (the C19 drift-score
  scipy helper test).
- Coverage: `gate.output` 100%, `gate.invariants.break_glass` 100%,
  `gate.hashing` (canonical vectors regression) 100% of vector
  coverage.
