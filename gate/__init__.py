"""
GATE Python Reference Library
==============================
Governed Agent Trust Environment (GATE) v1.3
https://deterministicagents.ai

A reference implementation of the GATE control plane contracts.
Not a full SDK — these are the primitives you build a Tool Gateway with.

Modules
-------
gate.hashing     Canonical JSON serialisation and SHA-256 hashing
gate.envelopes   ToolRequestEnvelope and ToolResponseEnvelope construction
gate.ledger      Hash-chained audit ledger event construction and verification
gate.replay      Replay trace construction and step recording
gate.signing     ES256 action signing and signature verification
gate.validation  JSON Schema validation for all GATE contract types
gate.discovery               C17 agent discovery event builders
gate.memory.quality          C18 quality gate evaluation + event builder
gate.assurance.behaviour     C19 drift detection event builders + scipy helper

License: CC BY 4.0 — Andrew Stevens / deterministicagents.ai
"""

__version__ = "1.1.0"
__gate_version__ = "1.3"
