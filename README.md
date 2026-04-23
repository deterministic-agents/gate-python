# GATE Python Reference Library

Reference implementation of the GATE control plane contracts in Python.

**Governed Agent Trust Environment (GATE) **  
https://deterministicagents.ai · https://codeberg.org/Deterministic_Agents/GATE  
License: CC BY 4.0 — Andrew Stevens

---

## What this is

A set of composable primitives for building a GATE-conformant Tool Gateway.
Not a full SDK - the modules are independently useful and carry no mandatory
framework dependency. Pick what you need.

| Module | What it does                                                                                |
|---|---------------------------------------------------------------------------------------------|
| `gate.hashing` | Canonical JSON (RFC 8785) + SHA-256 hashing - the foundation of all GATE evidence integrity |
| `gate.envelopes` | `ToolRequestEnvelope` and `ToolResponseEnvelope` construction                               |
| `gate.ledger` | Hash-chained `LedgerEvent` construction and chain verification                              |
| `gate.replay` | `ReplayTrace` construction and step recording                                               |
| `gate.signing` | ES256 action signing and signature verification                                             |
| `gate.validation` | JSON Schema validation for all GATE contract types                                          |

## Requirements

```
cryptography >= 42.0.0
jsonschema   >= 4.21.0   (optional - only needed for gate.validation)
pyyaml       >= 6.0.1    (optional - only needed for examples)
pytest       >= 8.0.0    (for running the test suite)
```

Install:
```bash
pip install -r requirements.txt
```

## Quickstart

```python
from gate.hashing import gate_hash, verify_hash
from gate.envelopes import build_request, build_response
from gate.ledger import LedgerChain, verify_chain, GENESIS
from gate.signing import generate_signing_key, sign_event_hash, verify_event_hash_signature

# 1. Build a tool request envelope
request = build_request(
    run_id="...", trace_id="...", tenant_id="acme", environment="prod",
    agent_instance_id="spiffe://org/agent/support#run-1",
    agent_name="customer-support", agent_version="1.0.0", attested=True,
    tool_name="read_ticket", tool_category="read_only", risk_tier="low",
    payload={"ticket_id": "TKT-001"},
    policy_bundle_hash="sha256:<your-policy-hash>",
    tool_schema_hash="sha256:<your-schema-hash>",
)

# 2. Verify the request hash (done by the Tool Gateway before policy eval)
assert verify_hash({"ticket_id": "TKT-001"}, request["hashes"]["request_hash"])

# 3. Build a ledger chain and add events
chain = LedgerChain(
    tenant_id="acme", environment="prod",
    sink_uri="worm://audit/prod/", retention_class="prod_hot_365d",
)
event = chain.append(
    run_id=request["run_id"],
    action_type="tool.invoke",
    policy_decision_id="<decision-uuid>",
    tool_request_hash=request["hashes"]["request_hash"],
    tool_response_hash="sha256:<response-hash>",
)

# 4. Verify the chain
result = verify_chain(chain.events)
assert result.passed   # True

# 5. Sign the event hash
key = generate_signing_key()
sig = sign_event_hash(
    event_hash=event["hash_chain"]["event_hash"],
    private_key=key, key_id="kid-prod-2026-04",
)
assert verify_event_hash_signature(
    event_hash=event["hash_chain"]["event_hash"],
    signature_record=sig, public_key=key.public_key(),
)
```

## Examples

Three runnable examples covering the full evidence chain:

```bash
# End-to-end gateway flow: transfer_funds with HITL, invariants, signing
python examples/tool_gateway_flow.py

# Ledger chain building, verification, and tamper detection
python examples/verify_ledger_chain.py

# Replay trace recording, export, and hash verification
python examples/replay_trace_demo.py
```

## Tests

```bash
# Run the full test suite (requires pytest)
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=gate --cov-report=term-missing
```

## Critical: canonicalization

All hashes in GATE are computed over **canonical JSON** (RFC 8785):
keys sorted by Unicode code point, no whitespace, UTF-8 encoded.

`gate.hashing.canonical_json()` implements this correctly.  
`gate.hashing.gate_hash()` wraps it with SHA-256 and the `sha256:` prefix.

Do not use `json.dumps()` directly - it does not sort keys by default
and will produce different hashes across implementations.

See `contracts/canonical_json.md` in the artifacts bundle for the full
specification including implementations in Node.js and Go.

## Key management note

`gate.signing.generate_signing_key()` generates P-256 keys for **testing
and local development only**. In production, agent signing keys are:

- Derived from or bound to the SPIFFE workload identity
- Short-lived (rotated with the workload identity TTL)
- Stored in a KMS, HSM, or TEE — never in the agent runtime

## Structure

```
gate-python/
├── gate/
│   ├── __init__.py
│   ├── hashing.py      # canonical JSON + SHA-256
│   ├── envelopes.py    # ToolRequestEnvelope + ToolResponseEnvelope
│   ├── ledger.py       # LedgerEvent construction + chain verification
│   ├── replay.py       # ReplayTrace + ReplayRecorder
│   ├── signing.py      # ES256 signing + verification
│   └── validation.py   # JSON Schema validation
├── examples/
│   ├── tool_gateway_flow.py     # end-to-end gateway flow
│   ├── verify_ledger_chain.py   # chain build + tamper detection
│   └── replay_trace_demo.py     # trace recording + verification
├── tests/
│   └── test_gate.py             # full test suite (70+ tests)
└── requirements.txt
```
