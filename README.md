# gate-python

Reference Python library for GATE v1.4 control-plane contracts.

GATE (Governed Agent Trust Environment) is the deterministic-agents framework
for governing autonomous AI agents. This library is the reference
implementation of the GATE contract surface: canonical hashing, envelopes,
hash-chained ledger events, replay traces, signing, and JSON Schema
validation for every contract type the framework defines.

## Status

- Library version: 1.2.0
- GATE framework version: 1.4
- Schemas: gate-contracts v1.2.0 (bundled under `gate/schemas/`)

## Install

PyPI publication is deferred to gate-python v1.3 (GATE v1.5). For v1.4,
install from the tagged git ref:

```
pip install git+https://github.com/deterministic-agents/gate-python.git@v1.2.0
```

Optional extras:

- `gate-python[assurance]` adds scipy for the C19 drift-score helper.
- `gate-python[dev]` adds pytest and scipy for the full test suite.

## Modules

- `gate.hashing` Canonical JSON serialisation and SHA-256 hashing
- `gate.envelopes` Tool request and response envelope construction
- `gate.ledger` Hash-chained audit ledger event construction and verification
- `gate.replay` Replay trace construction and step recording
- `gate.signing` ES256 action signing and signature verification
- `gate.validation` JSON Schema validation for all GATE contract types
- `gate.discovery` C17 agent discovery event builders
- `gate.memory.quality` C18 quality gate evaluation and event builder
- `gate.assurance.behaviour` C19 drift detection event builders
- `gate.output` C20 output classification event builder and matrix (new in v1.4)
- `gate.invariants.break_glass` C09 break-glass record builder and verifier (new in v1.4)

## What's new in v1.2.0

- `gate.output` for the C20 output classification surface
- `gate.invariants.break_glass` for the C09 contracted break-glass record
- Four new schemas bundled under `gate/schemas/`:
  `output_classification_event`, `break_glass_record`,
  `auto_enrolment_policy`, `approved_feed_registry`
- Three extended schemas: `agent_state` v1.2.0, `abom` v1.2.0,
  `quality_decision` v1.2.0
- Four new validators on `gate.validation`
- `gate/test_vectors/canonical_json_vectors.json` as the cross-language
  hash-compatibility source consumed by gate-rust

See `CHANGELOG-v1.2.0.md` for the full release entry.

## Documentation

Framework and contract documentation: https://deterministicagents.ai/

License: MIT (see LICENSE).
