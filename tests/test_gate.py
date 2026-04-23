"""
GATE Python — Test Suite
========================
Run: pytest tests/ -v
     pytest tests/ -v --cov=gate --cov-report=term-missing
"""

import copy
import uuid
import pytest

from gate.hashing import (
    canonical_json,
    canonical_json_str,
    gate_hash,
    gate_hash_bytes,
    verify_hash,
    verify_hash_bytes,
    _assert_hash_format,
)
from gate.envelopes import (
    build_request,
    build_response,
    redact_payload,
    extract_request_hash,
    extract_response_hash,
)
from gate.ledger import (
    LedgerChain,
    build_event,
    verify_chain,
    verify_single_event,
    GENESIS,
    ChainVerificationError,
)
from gate.replay import ReplayRecorder, verify_replay
from gate.signing import (
    generate_signing_key,
    sign_action,
    sign_event_hash,
    verify_signature,
    verify_event_hash_signature,
    KeyRegistry,
    private_key_to_pem,
    public_key_to_pem,
    load_private_key_pem,
    load_public_key_pem,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def run_id():
    return str(uuid.uuid4())


@pytest.fixture
def trace_id():
    return "trace-" + str(uuid.uuid4())[:8]


@pytest.fixture
def tenant_id():
    return "acme-corp"


@pytest.fixture
def fake_hash():
    """A valid-format GATE hash with fake content."""
    return "sha256:" + "a1b2c3d4" * 8


@pytest.fixture
def signing_key():
    return generate_signing_key()


@pytest.fixture
def key_registry(signing_key):
    reg = KeyRegistry()
    reg.register_private("kid-test-001", signing_key)
    return reg


@pytest.fixture
def basic_request(run_id, trace_id, fake_hash):
    return build_request(
        run_id=run_id,
        trace_id=trace_id,
        tenant_id="acme-corp",
        environment="prod",
        agent_instance_id="spiffe://org/agent/test#run-1",
        agent_name="test-agent",
        agent_version="1.0.0",
        attested=True,
        tool_name="read_ticket",
        tool_category="read_only",
        risk_tier="low",
        payload={"ticket_id": "TKT-001"},
        policy_bundle_hash=fake_hash,
        tool_schema_hash=fake_hash,
    )


@pytest.fixture
def ledger_chain(tenant_id):
    return LedgerChain(
        tenant_id=tenant_id,
        environment="prod",
        sink_uri="worm://audit/prod/",
        retention_class="prod_hot_365d",
        initial_prev_hash=GENESIS,
    )


@pytest.fixture
def recorder(run_id, trace_id, tenant_id, fake_hash):
    return ReplayRecorder(
        run_id=run_id,
        trace_id=trace_id,
        tenant_id=tenant_id,
        environment="prod",
        agent_instance_id="spiffe://org/agent/test#run-1",
        agent_name="test-agent",
        agent_version="1.0.0",
        model_id="provider/model",
        model_version="2025-11-01",
        temperature=0.1,
        seed=42,
        policy_bundle_hash=fake_hash,
        prompt_bundle_hash=fake_hash,
        tool_schema_hash=fake_hash,
    )


# ─────────────────────────────────────────────────────────────────────────────
# gate.hashing
# ─────────────────────────────────────────────────────────────────────────────

class TestCanonicalJson:
    def test_keys_sorted(self):
        result = canonical_json({"z": 1, "a": 2, "m": 3})
        assert result == b'{"a":2,"m":3,"z":1}'

    def test_nested_keys_sorted(self):
        result = canonical_json({"z": {"z": 1, "a": 2}, "a": {"z": 3, "a": 4}})
        assert result == b'{"a":{"a":4,"z":3},"z":{"a":2,"z":1}}'

    def test_no_whitespace(self):
        result = canonical_json({"key": "value"})
        assert b" " not in result
        assert b"\n" not in result

    def test_array_order_preserved(self):
        result = canonical_json({"arr": [3, 1, 2]})
        assert result == b'{"arr":[3,1,2]}'

    def test_string_output(self):
        assert canonical_json_str({"a": 1}) == '{"a":1}'

    def test_null(self):
        assert canonical_json(None) == b"null"

    def test_bool(self):
        assert canonical_json(True) == b"true"
        assert canonical_json(False) == b"false"

    def test_utf8(self):
        result = canonical_json({"key": "héllo"})
        assert "héllo".encode("utf-8") in result

    def test_same_object_same_hash(self):
        obj = {"b": 2, "a": 1, "c": [3, 1, 2]}
        assert canonical_json(obj) == canonical_json(obj)

    def test_different_key_order_same_output(self):
        a = canonical_json({"z": 1, "a": 2})
        b = canonical_json({"a": 2, "z": 1})
        assert a == b


class TestGateHash:
    def test_format(self):
        h = gate_hash({"key": "value"})
        assert h.startswith("sha256:")
        assert len(h) == 71
        assert all(c in "0123456789abcdef" for c in h[7:])

    def test_deterministic(self):
        obj = {"tool": "transfer_funds", "amount": 500}
        assert gate_hash(obj) == gate_hash(obj)

    def test_different_objects_different_hash(self):
        assert gate_hash({"a": 1}) != gate_hash({"a": 2})

    def test_key_order_invariant(self):
        assert gate_hash({"b": 2, "a": 1}) == gate_hash({"a": 1, "b": 2})

    def test_gate_hash_bytes(self):
        data = b"hello world"
        h = gate_hash_bytes(data)
        assert h.startswith("sha256:")
        assert len(h) == 71

    def test_verify_hash_true(self):
        obj = {"tool": "read_ticket"}
        h = gate_hash(obj)
        assert verify_hash(obj, h) is True

    def test_verify_hash_false_tampered(self):
        obj = {"amount": 500}
        h = gate_hash(obj)
        tampered = {"amount": 999}
        assert verify_hash(tampered, h) is False

    def test_verify_hash_raises_bad_format(self):
        with pytest.raises(ValueError, match="sha256:"):
            verify_hash({}, "not-a-hash")

    def test_verify_hash_bytes(self):
        data = b"test data"
        h = gate_hash_bytes(data)
        assert verify_hash_bytes(data, h) is True
        assert verify_hash_bytes(b"different", h) is False

    def test_assert_hash_format_valid(self):
        _assert_hash_format("sha256:" + "a" * 64, "field")

    def test_assert_hash_format_invalid(self):
        with pytest.raises(ValueError):
            _assert_hash_format("bad", "field")


# ─────────────────────────────────────────────────────────────────────────────
# gate.envelopes
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildRequest:
    def test_returns_dict(self, basic_request):
        assert isinstance(basic_request, dict)

    def test_event_type(self, basic_request):
        assert basic_request["event_type"] == "gate.tool.request"

    def test_schema_version(self, basic_request):
        assert basic_request["schema_version"] == "v1"

    def test_request_hash_present(self, basic_request):
        assert "request_hash" in basic_request["hashes"]

    def test_request_hash_format(self, basic_request):
        h = basic_request["hashes"]["request_hash"]
        assert h.startswith("sha256:")
        assert len(h) == 71

    def test_request_hash_matches_payload(self, basic_request):
        payload = basic_request["inputs"]["payload"]
        assert verify_hash(payload, basic_request["hashes"]["request_hash"])

    def test_attested_true(self, basic_request):
        assert basic_request["agent"]["identity"]["attested"] is True

    def test_subject_stripped_of_run_suffix(self, basic_request):
        subject = basic_request["agent"]["identity"]["subject"]
        assert "#" not in subject

    def test_invalid_environment_raises(self, run_id, trace_id, fake_hash):
        with pytest.raises(ValueError, match="environment"):
            build_request(
                run_id=run_id, trace_id=trace_id,
                tenant_id="t", environment="INVALID",
                agent_instance_id="spiffe://org/a#1",
                agent_name="a", agent_version="1.0.0", attested=True,
                tool_name="read", tool_category="read_only", risk_tier="low",
                payload={}, policy_bundle_hash=fake_hash, tool_schema_hash=fake_hash,
            )

    def test_invalid_category_raises(self, run_id, trace_id, fake_hash):
        with pytest.raises(ValueError, match="tool_category"):
            build_request(
                run_id=run_id, trace_id=trace_id,
                tenant_id="t", environment="prod",
                agent_instance_id="spiffe://org/a#1",
                agent_name="a", agent_version="1.0.0", attested=True,
                tool_name="read", tool_category="INVALID", risk_tier="low",
                payload={}, policy_bundle_hash=fake_hash, tool_schema_hash=fake_hash,
            )

    def test_orm_score_out_of_range_raises(self, run_id, trace_id, fake_hash):
        with pytest.raises(ValueError, match="orm_risk_score"):
            build_request(
                run_id=run_id, trace_id=trace_id,
                tenant_id="t", environment="prod",
                agent_instance_id="spiffe://org/a#1",
                agent_name="a", agent_version="1.0.0", attested=True,
                tool_name="read", tool_category="read_only", risk_tier="low",
                payload={}, policy_bundle_hash=fake_hash, tool_schema_hash=fake_hash,
                orm_risk_score=1.5,
            )

    def test_claims_present_when_image_digest_given(self, run_id, trace_id, fake_hash):
        env = build_request(
            run_id=run_id, trace_id=trace_id,
            tenant_id="t", environment="prod",
            agent_instance_id="spiffe://org/a#1",
            agent_name="a", agent_version="1.0.0", attested=True,
            tool_name="read", tool_category="read_only", risk_tier="low",
            payload={}, policy_bundle_hash=fake_hash, tool_schema_hash=fake_hash,
            image_digest=fake_hash,
        )
        assert "claims" in env["agent"]["identity"]
        assert env["agent"]["identity"]["claims"]["image_digest"] == fake_hash

    def test_extract_request_hash(self, basic_request):
        h = extract_request_hash(basic_request)
        assert h == basic_request["hashes"]["request_hash"]


class TestBuildResponse:
    def test_event_type(self, basic_request, fake_hash):
        resp = build_response(
            request_envelope=basic_request,
            tool_output={"result": "ok"},
            status="success",
            duration_ms=42,
            decision_id=str(uuid.uuid4()),
            decision="allow",
            obligations=["audit_log"],
            policy_bundle_hash=fake_hash,
            ledger_event_id=str(uuid.uuid4()),
        )
        assert resp["event_type"] == "gate.tool.response"

    def test_response_hash_matches_output(self, basic_request, fake_hash):
        output = {"result": "ok", "id": 123}
        resp = build_response(
            request_envelope=basic_request,
            tool_output=output,
            status="success",
            duration_ms=42,
            decision_id=str(uuid.uuid4()),
            decision="allow",
            obligations=[],
            policy_bundle_hash=fake_hash,
            ledger_event_id=str(uuid.uuid4()),
        )
        assert verify_hash(output, resp["hashes"]["response_hash"])

    def test_correlation_ids_copied(self, basic_request, fake_hash):
        resp = build_response(
            request_envelope=basic_request,
            tool_output={},
            status="success",
            duration_ms=1,
            decision_id=str(uuid.uuid4()),
            decision="allow",
            obligations=[],
            policy_bundle_hash=fake_hash,
            ledger_event_id=str(uuid.uuid4()),
        )
        assert resp["run_id"] == basic_request["run_id"]
        assert resp["trace_id"] == basic_request["trace_id"]
        assert resp["tenant_id"] == basic_request["tenant_id"]

    def test_invalid_status_raises(self, basic_request, fake_hash):
        with pytest.raises(ValueError, match="status"):
            build_response(
                request_envelope=basic_request,
                tool_output={},
                status="INVALID",
                duration_ms=1,
                decision_id=str(uuid.uuid4()),
                decision="allow",
                obligations=[],
                policy_bundle_hash=fake_hash,
                ledger_event_id=str(uuid.uuid4()),
            )

    def test_snapshot_uri_in_outputs(self, basic_request, fake_hash):
        uri = "immutable://snapshots/test/1.json"
        resp = build_response(
            request_envelope=basic_request,
            tool_output={},
            status="success",
            duration_ms=1,
            decision_id=str(uuid.uuid4()),
            decision="allow",
            obligations=[],
            policy_bundle_hash=fake_hash,
            ledger_event_id=str(uuid.uuid4()),
            snapshot_uri=uri,
        )
        assert resp["outputs"]["snapshot_uri"] == uri


class TestRedactPayload:
    def test_redacts_default_fields(self):
        payload = {"account": "12345", "password": "secret123", "amount": 500}
        redacted = redact_payload(payload)
        assert redacted["password"] == "[REDACTED]"
        assert redacted["account"] == "12345"
        assert redacted["amount"] == 500

    def test_redacts_custom_fields(self):
        payload = {"name": "Alice", "ssn": "123-45-6789", "bank_ref": "BR-001"}
        redacted = redact_payload(payload, sensitive_fields=["ssn", "bank_ref"])
        assert redacted["ssn"] == "[REDACTED]"
        assert redacted["bank_ref"] == "[REDACTED]"
        assert redacted["name"] == "Alice"

    def test_nested_redaction(self):
        payload = {"user": {"password": "x", "name": "Bob"}}
        redacted = redact_payload(payload)
        assert redacted["user"]["password"] == "[REDACTED]"
        assert redacted["user"]["name"] == "Bob"

    def test_does_not_mutate_original(self):
        payload = {"password": "secret"}
        original = dict(payload)
        redact_payload(payload)
        assert payload == original


# ─────────────────────────────────────────────────────────────────────────────
# gate.ledger
# ─────────────────────────────────────────────────────────────────────────────

class TestLedgerChain:
    def test_genesis_prev_hash(self, ledger_chain, fake_hash):
        ev = ledger_chain.append(
            run_id=str(uuid.uuid4()),
            action_type="tool.invoke",
            policy_decision_id=str(uuid.uuid4()),
            tool_request_hash=fake_hash,
            tool_response_hash=fake_hash,
        )
        assert ev["hash_chain"]["prev_event_hash"] == GENESIS

    def test_second_event_links_to_first(self, ledger_chain, fake_hash):
        ev1 = ledger_chain.append(
            run_id=str(uuid.uuid4()),
            action_type="tool.invoke",
            policy_decision_id=str(uuid.uuid4()),
            tool_request_hash=fake_hash,
            tool_response_hash=fake_hash,
        )
        ev2 = ledger_chain.append(
            run_id=str(uuid.uuid4()),
            action_type="tool.invoke",
            policy_decision_id=str(uuid.uuid4()),
            tool_request_hash=fake_hash,
            tool_response_hash=fake_hash,
        )
        assert ev2["hash_chain"]["prev_event_hash"] == ev1["hash_chain"]["event_hash"]

    def test_sequence_numbers_increment(self, ledger_chain, fake_hash):
        for _ in range(5):
            ledger_chain.append(
                run_id=str(uuid.uuid4()),
                action_type="tool.invoke",
                policy_decision_id=str(uuid.uuid4()),
                tool_request_hash=fake_hash,
                tool_response_hash=fake_hash,
            )
        seqs = [ev["sequence_number"] for ev in ledger_chain.events]
        assert seqs == list(range(1, 6))

    def test_event_hash_format(self, ledger_chain, fake_hash):
        ev = ledger_chain.append(
            run_id=str(uuid.uuid4()),
            action_type="tool.invoke",
            policy_decision_id=str(uuid.uuid4()),
            tool_request_hash=fake_hash,
            tool_response_hash=fake_hash,
        )
        h = ev["hash_chain"]["event_hash"]
        assert h.startswith("sha256:")
        assert len(h) == 71

    def test_invalid_retention_class_raises(self, tenant_id):
        with pytest.raises(ValueError, match="retention_class"):
            LedgerChain(
                tenant_id=tenant_id,
                environment="prod",
                sink_uri="worm://x/",
                retention_class="invalid_class",
            )


class TestVerifyChain:
    def _build_chain(self, n, tenant_id, fake_hash):
        chain = LedgerChain(
            tenant_id=tenant_id,
            environment="prod",
            sink_uri="worm://x/",
            retention_class="prod_hot_365d",
        )
        for _ in range(n):
            chain.append(
                run_id=str(uuid.uuid4()),
                action_type="tool.invoke",
                policy_decision_id=str(uuid.uuid4()),
                tool_request_hash=fake_hash,
                tool_response_hash=fake_hash,
            )
        return chain

    def test_intact_chain_passes(self, tenant_id, fake_hash):
        chain = self._build_chain(5, tenant_id, fake_hash)
        result = verify_chain(chain.events)
        assert result.passed
        assert result.events_verified == 5
        assert len(result.errors) == 0

    def test_single_event_passes(self, tenant_id, fake_hash):
        chain = self._build_chain(1, tenant_id, fake_hash)
        result = verify_chain(chain.events)
        assert result.passed

    def test_empty_chain_passes(self):
        result = verify_chain([])
        assert result.passed
        assert result.events_verified == 0

    def test_tampered_event_hash_detected(self, tenant_id, fake_hash):
        chain = self._build_chain(3, tenant_id, fake_hash)
        events = copy.deepcopy(chain.events)
        # Tamper with event at index 1
        events[1]["references"]["tool_response_hash"] = "sha256:" + "dead" * 16
        result = verify_chain(events)
        assert not result.passed
        assert any(e.event_index == 1 for e in result.errors)

    def test_tampered_prev_hash_detected(self, tenant_id, fake_hash):
        chain = self._build_chain(3, tenant_id, fake_hash)
        events = copy.deepcopy(chain.events)
        events[2]["hash_chain"]["prev_event_hash"] = "sha256:" + "beef" * 16
        result = verify_chain(events)
        assert not result.passed

    def test_sequence_gap_detected(self, tenant_id, fake_hash):
        chain = self._build_chain(4, tenant_id, fake_hash)
        events = copy.deepcopy(chain.events)
        events.pop(1)  # Remove event 2
        result = verify_chain(events)
        assert not result.passed

    def test_verify_single_event_valid(self, tenant_id, fake_hash):
        chain = self._build_chain(1, tenant_id, fake_hash)
        assert verify_single_event(chain.events[0]) is True

    def test_verify_single_event_tampered(self, tenant_id, fake_hash):
        chain = self._build_chain(1, tenant_id, fake_hash)
        ev = copy.deepcopy(chain.events[0])
        ev["run_id"] = "tampered"
        assert verify_single_event(ev) is False

    def test_raise_on_failure(self, tenant_id, fake_hash):
        chain = self._build_chain(2, tenant_id, fake_hash)
        events = copy.deepcopy(chain.events)
        events[0]["run_id"] = "tampered"
        result = verify_chain(events)
        with pytest.raises(ChainVerificationError):
            result.raise_on_failure()


# ─────────────────────────────────────────────────────────────────────────────
# gate.replay
# ─────────────────────────────────────────────────────────────────────────────

class TestReplayRecorder:
    def test_to_dict_structure(self, recorder):
        trace = recorder.to_dict()
        assert trace["schema_version"] == "v1"
        assert "run_id" in trace
        assert "model" in trace
        assert "bundles" in trace
        assert "steps" in trace

    def test_step_indices_sequential(self, recorder, fake_hash):
        recorder.record_retrieve_context(documents=[{"doc": 1}])
        recorder.record_tool_call(
            tool_name="read_ticket",
            request_payload={"ticket_id": "TKT-001"},
            response_payload={"status": "open"},
            policy_decision_id=str(uuid.uuid4()),
            ledger_event_id=str(uuid.uuid4()),
        )
        trace = recorder.to_dict()
        indices = [s["step_index"] for s in trace["steps"]]
        assert indices == list(range(1, len(indices) + 1))

    def test_retrieve_context_hashes_documents(self, recorder):
        docs = [{"key": "val1"}, {"key": "val2"}]
        step = recorder.record_retrieve_context(documents=docs)
        expected = [gate_hash(d) for d in docs]
        assert step["retrieved_context_hashes"] == expected

    def test_tool_call_hashes_payloads(self, recorder):
        req = {"ticket_id": "TKT-001"}
        res = {"status": "open"}
        step = recorder.record_tool_call(
            tool_name="read_ticket",
            request_payload=req,
            response_payload=res,
            policy_decision_id=str(uuid.uuid4()),
            ledger_event_id=str(uuid.uuid4()),
        )
        assert step["request_hash"] == gate_hash(req)
        assert step["response_hash"] == gate_hash(res)

    def test_invariant_halt_step(self, recorder):
        step = recorder.record_invariant_halt(
            tool_name="delete_record",
            request_payload={"record_id": "R-001"},
            invariant_rule_id="INV-DELETE-001",
            policy_decision_id=str(uuid.uuid4()),
            ledger_event_id=str(uuid.uuid4()),
        )
        assert step["step_type"] == "invariant_halt"
        assert step["invariant_rule_id"] == "INV-DELETE-001"

    def test_final_output_step(self, recorder):
        output = {"status": "done"}
        step = recorder.record_final_output(output=output)
        assert step["step_type"] == "final_output"
        assert step["output_hash"] == gate_hash(output)


class TestVerifyReplay:
    def test_matching_hashes_pass(self, recorder):
        req = {"ticket_id": "TKT-001"}
        res = {"status": "open"}
        step = recorder.record_tool_call(
            tool_name="read_ticket",
            request_payload=req,
            response_payload=res,
            policy_decision_id=str(uuid.uuid4()),
            ledger_event_id=str(uuid.uuid4()),
        )
        trace = recorder.to_dict()
        result = verify_replay(
            trace,
            actual_requests={step["step_index"]: req},
            actual_responses={step["step_index"]: res},
        )
        assert result.passed
        assert result.steps_matched > 0

    def test_tampered_response_detected(self, recorder):
        req = {"ticket_id": "TKT-001"}
        res = {"status": "open"}
        step = recorder.record_tool_call(
            tool_name="read_ticket",
            request_payload=req,
            response_payload=res,
            policy_decision_id=str(uuid.uuid4()),
            ledger_event_id=str(uuid.uuid4()),
        )
        trace = recorder.to_dict()
        result = verify_replay(
            trace,
            actual_requests={step["step_index"]: req},
            actual_responses={step["step_index"]: {"status": "closed"}},  # tampered
        )
        assert not result.passed
        assert any(m["field"] == "response_hash" for m in result.mismatches)

    def test_tampered_request_detected(self, recorder):
        req = {"ticket_id": "TKT-001"}
        res = {"status": "open"}
        step = recorder.record_tool_call(
            tool_name="read_ticket",
            request_payload=req,
            response_payload=res,
            policy_decision_id=str(uuid.uuid4()),
            ledger_event_id=str(uuid.uuid4()),
        )
        trace = recorder.to_dict()
        result = verify_replay(
            trace,
            actual_requests={step["step_index"]: {"ticket_id": "TKT-TAMPERED"}},
            actual_responses={step["step_index"]: res},
        )
        assert not result.passed
        assert any(m["field"] == "request_hash" for m in result.mismatches)

    def test_invariant_halt_request_hash_verified(self, recorder):
        req = {"record_id": "R-001"}
        step = recorder.record_invariant_halt(
            tool_name="delete_record",
            request_payload=req,
            invariant_rule_id="INV-DELETE-001",
            policy_decision_id=str(uuid.uuid4()),
            ledger_event_id=str(uuid.uuid4()),
        )
        trace = recorder.to_dict()
        result = verify_replay(
            trace,
            actual_requests={step["step_index"]: req},
            actual_responses={},
        )
        assert result.passed


# ─────────────────────────────────────────────────────────────────────────────
# gate.signing
# ─────────────────────────────────────────────────────────────────────────────

class TestSigning:
    def test_sign_and_verify(self, signing_key):
        payload = {"tool": "transfer_funds", "amount": 500}
        sig = sign_action(payload=payload, private_key=signing_key, key_id="k1")
        assert verify_signature(
            payload=payload,
            signature_record=sig,
            public_key=signing_key.public_key(),
        )

    def test_tampered_payload_fails(self, signing_key):
        payload = {"amount": 500}
        sig = sign_action(payload=payload, private_key=signing_key, key_id="k1")
        assert not verify_signature(
            payload={"amount": 999},
            signature_record=sig,
            public_key=signing_key.public_key(),
        )

    def test_wrong_key_fails(self, signing_key):
        other_key = generate_signing_key()
        payload = {"tool": "test"}
        sig = sign_action(payload=payload, private_key=signing_key, key_id="k1")
        assert not verify_signature(
            payload=payload,
            signature_record=sig,
            public_key=other_key.public_key(),
        )

    def test_sign_event_hash_and_verify(self, signing_key):
        event_hash = "sha256:" + "a1b2" * 16
        sig = sign_event_hash(
            event_hash=event_hash,
            private_key=signing_key,
            key_id="k1",
        )
        assert verify_event_hash_signature(
            event_hash=event_hash,
            signature_record=sig,
            public_key=signing_key.public_key(),
        )

    def test_signature_record_fields(self, signing_key):
        sig = sign_action(
            payload={"a": 1},
            private_key=signing_key,
            key_id="kid-test",
        )
        assert sig["signing_key_id"] == "kid-test"
        assert sig["algorithm"] == "ES256"
        assert isinstance(sig["signature"], str)
        assert len(sig["signature"]) > 0

    def test_pem_roundtrip(self, signing_key):
        pem = private_key_to_pem(signing_key)
        loaded = load_private_key_pem(pem)
        # Verify they produce the same signatures
        payload = {"test": 1}
        sig1 = sign_action(payload=payload, private_key=signing_key, key_id="k")
        sig2 = sign_action(payload=payload, private_key=loaded, key_id="k")
        # Both should verify against original public key
        pub = signing_key.public_key()
        assert verify_signature(payload=payload, signature_record=sig1, public_key=pub)
        assert verify_signature(payload=payload, signature_record=sig2, public_key=pub)

    def test_public_key_pem_roundtrip(self, signing_key):
        pem = public_key_to_pem(signing_key)
        loaded_pub = load_public_key_pem(pem)
        payload = {"test": 1}
        sig = sign_action(payload=payload, private_key=signing_key, key_id="k")
        assert verify_signature(
            payload=payload,
            signature_record=sig,
            public_key=loaded_pub,
        )


class TestKeyRegistry:
    def test_register_and_verify(self, signing_key, key_registry):
        payload = {"tool": "test"}
        sig = sign_action(payload=payload, private_key=signing_key, key_id="kid-test-001")
        assert key_registry.verify(payload=payload, signature_record=sig)

    def test_unknown_key_returns_false(self, key_registry):
        sig = {
            "signing_key_id": "kid-unknown",
            "algorithm": "ES256",
            "signature": "dGVzdA==",
        }
        assert not key_registry.verify(payload={"a": 1}, signature_record=sig)

    def test_get_registered_key(self, signing_key, key_registry):
        pub = key_registry.get("kid-test-001")
        assert pub is not None

    def test_get_unregistered_raises(self, key_registry):
        with pytest.raises(KeyError):
            key_registry.get("kid-does-not-exist")

    def test_register_private_extracts_public(self, signing_key):
        reg = KeyRegistry()
        reg.register_private("k1", signing_key)
        pub = reg.get("k1")
        # Verify we can use the extracted public key
        payload = {"test": 1}
        sig = sign_action(payload=payload, private_key=signing_key, key_id="k1")
        assert verify_signature(payload=payload, signature_record=sig, public_key=pub)


# ─────────────────────────────────────────────────────────────────────────────
# Integration: full evidence chain
# ─────────────────────────────────────────────────────────────────────────────

class TestFullEvidenceChain:
    """
    End-to-end test verifying the complete evidence chain:
    ToolRequest → PolicyDecision → LedgerEvent → ReplayTrace → Signature
    """

    def test_complete_chain_integrity(self, run_id, trace_id, tenant_id, fake_hash, signing_key):
        # Build request
        payload = {"ticket_id": "TKT-INT-001"}
        request_env = build_request(
            run_id=run_id, trace_id=trace_id,
            tenant_id=tenant_id, environment="prod",
            agent_instance_id="spiffe://org/agent/test#run-1",
            agent_name="test", agent_version="1.0.0", attested=True,
            tool_name="read_ticket", tool_category="read_only", risk_tier="low",
            payload=payload,
            policy_bundle_hash=fake_hash, tool_schema_hash=fake_hash,
        )
        request_hash = request_env["hashes"]["request_hash"]

        # Verify request hash is correct
        assert verify_hash(payload, request_hash)

        # Build response
        output = {"status": "open", "priority": "high"}
        response_env = build_response(
            request_envelope=request_env,
            tool_output=output,
            status="success",
            duration_ms=55,
            decision_id=str(uuid.uuid4()),
            decision="allow",
            obligations=["audit_log"],
            policy_bundle_hash=fake_hash,
            ledger_event_id=str(uuid.uuid4()),
        )
        response_hash = response_env["hashes"]["response_hash"]
        assert verify_hash(output, response_hash)

        # Build ledger event
        chain = LedgerChain(
            tenant_id=tenant_id, environment="prod",
            sink_uri="worm://x/", retention_class="prod_hot_365d",
        )
        ev = chain.append(
            run_id=run_id,
            action_type="tool.invoke",
            policy_decision_id=str(uuid.uuid4()),
            tool_request_hash=request_hash,
            tool_response_hash=response_hash,
            trace_id=trace_id,
        )

        # Ledger references match envelopes
        assert ev["references"]["tool_request_hash"] == request_hash
        assert ev["references"]["tool_response_hash"] == response_hash

        # Chain verifies
        result = verify_chain(chain.events)
        assert result.passed

        # Sign event hash
        event_hash = ev["hash_chain"]["event_hash"]
        sig = sign_event_hash(
            event_hash=event_hash,
            private_key=signing_key,
            key_id="kid-test",
        )
        assert verify_event_hash_signature(
            event_hash=event_hash,
            signature_record=sig,
            public_key=signing_key.public_key(),
        )

        # Record replay trace and verify
        recorder = ReplayRecorder(
            run_id=run_id, trace_id=trace_id,
            tenant_id=tenant_id, environment="prod",
            agent_instance_id="spiffe://org/agent/test#run-1",
            agent_name="test", agent_version="1.0.0",
            model_id="provider/model", model_version="2025-11-01",
            temperature=0.1, seed=None,
            policy_bundle_hash=fake_hash,
            prompt_bundle_hash=fake_hash,
            tool_schema_hash=fake_hash,
        )
        step = recorder.record_tool_call(
            tool_name="read_ticket",
            request_payload=payload,
            response_payload=output,
            policy_decision_id=str(uuid.uuid4()),
            ledger_event_id=ev["ledger_event_id"],
        )

        replay_result = verify_replay(
            recorder.to_dict(),
            actual_requests={step["step_index"]: payload},
            actual_responses={step["step_index"]: output},
        )
        assert replay_result.passed
