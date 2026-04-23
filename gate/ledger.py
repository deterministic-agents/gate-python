"""
gate.ledger
===========
Hash-chained audit ledger event construction and chain verification.

The GATE audit ledger is the tamper-evident backbone of the evidence
chain. Every governed action produces a LedgerEvent. Events are linked
by their ``hash_chain.prev_event_hash`` field. Any modification to a
past event - even a single character - breaks the chain at that point
and is detectable by ``verify_chain``.

The ledger must be committed to WORM (Write Once Read Many) storage.
This library handles event construction and chain mathematics; your
infrastructure layer handles the actual commit.

Schema: contracts/audit_ledger_event.schema.json
"""

from __future__ import annotations

import copy
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from .hashing import canonical_json, gate_hash, _assert_hash_format


# Sentinel for the first event in a new ledger partition.
GENESIS = "GENESIS"

RETENTION_CLASSES = frozenset([
    "sandbox_hot_30d",
    "prod_hot_365d",
    "prod_cold_6y_worm",
    "regulated_cold_7y_plus",
])


# ---------------------------------------------------------------------------
# Event construction
# ---------------------------------------------------------------------------

def build_event(
    *,
    run_id: str,
    tenant_id: str,
    environment: str,
    action_type: str,
    policy_decision_id: str,
    tool_request_hash: str,
    tool_response_hash: str,
    prev_event_hash: str,
    sink_uri: str,
    retention_class: str,
    # Optional cross-references
    trace_id: str | None = None,
    replay_trace_step_id: str | None = None,
    hitl_approval_id: str | None = None,
    invariant_bundle_hash: str | None = None,
    tool_name: str | None = None,
    agent_instance_id: str | None = None,
    sequence_number: int | None = None,
) -> dict[str, Any]:
    """
    Build a conformant LedgerEvent with a correct hash chain link.

    The ``event_hash`` is computed over the canonical JSON of the event
    *excluding* the ``hash_chain.event_hash`` field itself. This is the
    same pattern used by certificate transparency logs and blockchain
    structures: you hash everything except the hash you are about to
    write.

    Parameters
    ----------
    run_id:
        UUID of the agent run this event belongs to.
    tenant_id:
        Tenant identifier.
    environment:
        One of ``"dev"``, ``"test"``, ``"prod"``.
    action_type:
        One of ``"tool.invoke"``, ``"memory.read"``, ``"memory.write"``,
        ``"hitl.decision"``, ``"breaker.trigger"``,
        ``"agent.lifecycle"``.
    policy_decision_id:
        UUID of the PolicyDecisionRecord for this action.
    tool_request_hash:
        ``"sha256:<hex>"`` of the ToolRequestEnvelope payload.
    tool_response_hash:
        ``"sha256:<hex>"`` of the ToolResponseEnvelope payload.
    prev_event_hash:
        Hash of the immediately preceding event. Use ``GENESIS``
        (the module-level constant) for the first event in a partition.
    sink_uri:
        WORM storage URI where this event will be committed.
    retention_class:
        One of the GATE retention class strings.
    trace_id:
        OTel trace ID for correlation.
    replay_trace_step_id:
        ID of the matching step in the replay trace.
    hitl_approval_id:
        UUID of the HITL decision record, if applicable.
    invariant_bundle_hash:
        Hash of the invariant bundle evaluated, if applicable.
    tool_name:
        Tool name for the ``governed_action`` summary field.
    agent_instance_id:
        Agent instance identity for the ``governed_action`` field.
    sequence_number:
        Monotonically increasing sequence number within this partition.
        Gaps in sequence numbers indicate tampering or missing events.

    Returns
    -------
    dict
        A conformant LedgerEvent with ``hash_chain.event_hash`` set.

    Raises
    ------
    ValueError
        If ``retention_class`` is not a known GATE retention class.
    """
    if retention_class not in RETENTION_CLASSES:
        raise ValueError(
            f"retention_class must be one of {RETENTION_CLASSES}; "
            f"got: {retention_class!r}"
        )

    ledger_event_id = str(uuid.uuid4())

    references: dict[str, Any] = {
        "policy_decision_id": policy_decision_id,
        "tool_request_hash": tool_request_hash,
        "tool_response_hash": tool_response_hash,
    }
    if trace_id:
        references["trace_id"] = trace_id
    if replay_trace_step_id:
        references["replay_trace_step_id"] = replay_trace_step_id
    if hitl_approval_id:
        references["hitl_approval_id"] = hitl_approval_id
    if invariant_bundle_hash:
        references["invariant_bundle_hash"] = invariant_bundle_hash

    governed_action: dict[str, Any] = {"action_type": action_type}
    if tool_name:
        governed_action["tool_name"] = tool_name
    if agent_instance_id:
        governed_action["agent_instance_id"] = agent_instance_id

    committed_at = _now_iso()

    # Build the event body without the event_hash field first.
    # We compute event_hash over this body, then add it.
    event_body: dict[str, Any] = {
        "schema_version": "v1",
        "event_type": "gate.ledger.event",
        "time": committed_at,
        "ledger_event_id": ledger_event_id,
        "run_id": run_id,
        "tenant_id": tenant_id,
        "environment": environment,
        "governed_action": governed_action,
        "references": references,
        "hash_chain": {
            "prev_event_hash": prev_event_hash,
            # event_hash not yet set
        },
        # signatures intentionally omitted here — added AFTER event_hash
        # is computed so they do not affect the hash input.
        "immutability": {
            "sink_uri": sink_uri,
            "retention_class": retention_class,
            "committed_at": committed_at,
        },
    }

    if sequence_number is not None:
        event_body["sequence_number"] = sequence_number

    # Compute event_hash over the body (which includes prev_event_hash
    # but not event_hash itself — that would be circular).
    # Signatures are NOT in the body at this point — they are added
    # after the hash is computed so they don't affect it.
    event_hash = gate_hash(event_body)
    event_body["hash_chain"]["event_hash"] = event_hash

    # Add signature placeholder AFTER hashing. Signing layer populates
    # these fields. _compute_event_hash strips them before re-hashing.
    event_body["signatures"] = {
        "signing_key_id": "",
        "algorithm": "ES256",
        "signature": "",
    }

    return event_body


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

class ChainVerificationError(Exception):
    """Raised when ledger chain verification finds an integrity failure."""

    def __init__(self, message: str, event_index: int, event_id: str) -> None:
        super().__init__(message)
        self.event_index = event_index
        self.event_id = event_id


class ChainVerificationResult:
    """Result of a ``verify_chain`` call."""

    def __init__(
        self,
        passed: bool,
        events_verified: int,
        errors: list[ChainVerificationError],
    ) -> None:
        self.passed = passed
        self.events_verified = events_verified
        self.errors = errors

    def __repr__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"ChainVerificationResult(status={status}, "
            f"events_verified={self.events_verified}, "
            f"errors={len(self.errors)})"
        )

    def raise_on_failure(self) -> None:
        """Raise the first ChainVerificationError if the chain failed."""
        if self.errors:
            raise self.errors[0]


def verify_chain(
    events: list[dict[str, Any]],
    expected_first_prev_hash: str = GENESIS,
) -> ChainVerificationResult:
    """
    Verify the integrity of a sequence of LedgerEvents.

    Checks:
    1. Each event's ``event_hash`` matches the canonical JSON of the
       event body (excluding ``event_hash`` itself).
    2. Each event's ``prev_event_hash`` matches the ``event_hash`` of
       the preceding event.
    3. The first event's ``prev_event_hash`` matches
       *expected_first_prev_hash*.
    4. Sequence numbers (if present) are contiguous with no gaps.

    Parameters
    ----------
    events:
        Ordered list of LedgerEvent dicts, oldest first.
    expected_first_prev_hash:
        The expected ``prev_event_hash`` of the first event in the
        sequence. Defaults to ``GENESIS`` for a fresh partition.
        Pass the hash of the last verified event when verifying a
        continuation of a previously verified chain.

    Returns
    -------
    ChainVerificationResult
        Contains ``passed``, ``events_verified``, and ``errors``.

    Examples
    --------
    >>> result = verify_chain(events)
    >>> result.passed
    True
    >>> result.events_verified
    42
    """
    errors: list[ChainVerificationError] = []
    prev_hash = expected_first_prev_hash
    prev_sequence: int | None = None

    for idx, event in enumerate(events):
        event_id = event.get("ledger_event_id", f"<unknown-{idx}>")

        # --- Check 1: event_hash is correct ---
        stored_event_hash = event.get("hash_chain", {}).get("event_hash", "")
        recomputed = _compute_event_hash(event)
        if recomputed != stored_event_hash:
            errors.append(ChainVerificationError(
                f"event_hash mismatch at index {idx} "
                f"(event_id={event_id}): "
                f"stored={stored_event_hash!r}, "
                f"recomputed={recomputed!r}",
                event_index=idx,
                event_id=event_id,
            ))

        # --- Check 2: prev_event_hash links correctly ---
        stored_prev = event.get("hash_chain", {}).get("prev_event_hash", "")
        if stored_prev != prev_hash:
            errors.append(ChainVerificationError(
                f"prev_event_hash mismatch at index {idx} "
                f"(event_id={event_id}): "
                f"expected={prev_hash!r}, stored={stored_prev!r}",
                event_index=idx,
                event_id=event_id,
            ))

        # --- Check 3: sequence number continuity ---
        seq = event.get("sequence_number")
        if seq is not None:
            if prev_sequence is not None and seq != prev_sequence + 1:
                errors.append(ChainVerificationError(
                    f"sequence_number gap at index {idx} "
                    f"(event_id={event_id}): "
                    f"expected={prev_sequence + 1}, got={seq}",
                    event_index=idx,
                    event_id=event_id,
                ))
            prev_sequence = seq

        # Advance the chain using the stored event_hash
        # (not the recomputed one — if they differ we already recorded
        # the error; using stored keeps the chain traversal consistent)
        prev_hash = stored_event_hash

    return ChainVerificationResult(
        passed=len(errors) == 0,
        events_verified=len(events),
        errors=errors,
    )


def verify_single_event(event: dict[str, Any]) -> bool:
    """
    Verify that a single LedgerEvent's ``event_hash`` is correct.

    Does NOT verify the chain link to the previous event. Use
    ``verify_chain`` for full chain verification.

    Returns
    -------
    bool
        True if the event_hash is valid.
    """
    stored = event.get("hash_chain", {}).get("event_hash", "")
    return _compute_event_hash(event) == stored


# ---------------------------------------------------------------------------
# Chain building helpers
# ---------------------------------------------------------------------------

class LedgerChain:
    """
    Stateful helper for building a sequence of linked LedgerEvents.

    Tracks the ``prev_event_hash`` automatically so callers don't have
    to manage it manually.

    Examples
    --------
    >>> chain = LedgerChain(tenant_id="acme", environment="prod",
    ...                     sink_uri="worm://audit/prod/",
    ...                     retention_class="prod_hot_365d")
    >>> ev1 = chain.append(run_id="...", action_type="tool.invoke", ...)
    >>> ev2 = chain.append(run_id="...", action_type="tool.invoke", ...)
    >>> result = verify_chain(chain.events)
    >>> result.passed
    True
    """

    def __init__(
        self,
        tenant_id: str,
        environment: str,
        sink_uri: str,
        retention_class: str,
        initial_prev_hash: str = GENESIS,
    ) -> None:
        self.tenant_id = tenant_id
        self.environment = environment
        self.sink_uri = sink_uri
        self.retention_class = retention_class
        self._prev_hash = initial_prev_hash
        self._sequence = 0
        self.events: list[dict[str, Any]] = []

    def append(self, **kwargs: Any) -> dict[str, Any]:
        """
        Build and append a new LedgerEvent to the chain.

        Accepts all keyword arguments that ``build_event`` accepts,
        except ``prev_event_hash``, ``tenant_id``, ``environment``,
        ``sink_uri``, ``retention_class``, and ``sequence_number``
        — these are managed by the chain.

        Returns the constructed event dict.
        """
        self._sequence += 1
        event = build_event(
            tenant_id=self.tenant_id,
            environment=self.environment,
            sink_uri=self.sink_uri,
            retention_class=self.retention_class,
            prev_event_hash=self._prev_hash,
            sequence_number=self._sequence,
            **kwargs,
        )
        self._prev_hash = event["hash_chain"]["event_hash"]
        self.events.append(event)
        return event

    @property
    def head_hash(self) -> str:
        """The event_hash of the most recently appended event."""
        return self._prev_hash

    @property
    def length(self) -> int:
        return len(self.events)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_event_hash(event: dict[str, Any]) -> str:
    """
    Recompute the event_hash for a LedgerEvent.

    Strips both ``event_hash`` from ``hash_chain`` AND the entire
    ``signatures`` block before hashing, exactly as ``build_event``
    does when originally computing it (signatures are added after the
    hash is computed, so they must be absent during verification too).
    """
    body = copy.deepcopy(event)
    # Remove event_hash — it's what we're computing
    body.get("hash_chain", {}).pop("event_hash", None)
    # Remove signatures entirely — they are added post-hash
    body.pop("signatures", None)
    return gate_hash(body)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
