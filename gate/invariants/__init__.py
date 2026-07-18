"""
gate.invariants
===============
GATE C09 invariant-plane helpers.

v1.4 adds gate.invariants.break_glass for constructing and verifying
the contracted break-glass record introduced in gate-contracts v1.2.0.
The verification policy at
policies/invariants/c09_break_glass_verification.rego in gate-policies
v1.2.0 is the authoritative runtime check; the Python verify helper
here covers the same shape as defence-in-depth for callers that want
to fail-fast at the SDK boundary.
"""
