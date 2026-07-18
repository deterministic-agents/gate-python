"""
Cross-language canonical JSON / hash regression test.

Walks every vector in gate/test_vectors/canonical_json_vectors.json,
recomputes the canonical bytes and the GATE-format sha256 hash via the
existing gate.hashing module, and asserts byte-exact equality with the
stored values. This is the test that fails if gate.hashing ever
regresses, breaking compatibility with gate-rust (Workstream 6) and
with any other consumer of the vector file.

Run: pytest tests/test_canonical_json_vectors.py -v
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from gate.hashing import canonical_json, gate_hash


VECTORS_PATH = (
    Path(__file__).resolve().parent.parent
    / "gate"
    / "test_vectors"
    / "canonical_json_vectors.json"
)


def _load_doc() -> dict:
    with VECTORS_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def _load_vectors() -> list[dict]:
    return _load_doc()["vectors"]


def _load_negative_vectors() -> list[dict]:
    return _load_doc().get("negative_vectors", [])


_VECTORS = _load_vectors()
_NEGATIVE_VECTORS = _load_negative_vectors()


def test_vectors_file_present():
    assert VECTORS_PATH.exists(), (
        f"canonical_json_vectors.json missing at {VECTORS_PATH}"
    )


def test_vectors_file_has_minimum_coverage():
    # The W5 brief specifies at least 12 vectors.
    assert len(_VECTORS) >= 12


@pytest.mark.parametrize(
    "vector",
    _VECTORS,
    ids=[v["id"] for v in _VECTORS],
)
def test_vector_canonical_bytes_match(vector):
    expected = base64.b64decode(vector["canonical_json_base64"])
    actual = canonical_json(vector["input"])
    assert actual == expected, (
        f"canonical JSON mismatch for {vector['id']}: "
        f"expected {expected!r}, got {actual!r}"
    )


@pytest.mark.parametrize(
    "vector",
    _VECTORS,
    ids=[v["id"] for v in _VECTORS],
)
def test_vector_hash_matches(vector):
    expected = vector["sha256"]
    actual = gate_hash(vector["input"])
    assert actual == expected, (
        f"sha256 mismatch for {vector['id']}: "
        f"expected {expected}, got {actual}"
    )


# ---------------------------------------------------------------------------
# Negative vectors: exponent-range floats that MUST NOT enter a hashed
# surface raw. After round4 normalisation both serialisers agree. The
# Rust suite asserts the same normalised bytes/hash, and its own raw
# serialisation against raw_rust_canonical.
# ---------------------------------------------------------------------------

from gate.rounding import round4  # noqa: E402


def test_negative_vectors_present():
    assert len(_NEGATIVE_VECTORS) >= 5


@pytest.mark.parametrize(
    "vector",
    _NEGATIVE_VECTORS,
    ids=[v["id"] for v in _NEGATIVE_VECTORS],
)
def test_negative_vector_raw_serialisation(vector):
    # input is a decimal string so both languages parse identical text.
    # Python's own raw canonical serialisation is what raw_python_canonical
    # records. Where raw_diverges is true it differs from raw_rust_canonical.
    raw = float(vector["input"])
    actual = canonical_json(raw).decode("utf-8")
    assert actual == vector["raw_python_canonical"], (
        f"{vector['id']}: raw python canonical drifted from recorded value"
    )
    if vector["raw_diverges"]:
        assert vector["raw_python_canonical"] != vector["raw_rust_canonical"]


@pytest.mark.parametrize(
    "vector",
    _NEGATIVE_VECTORS,
    ids=[v["id"] for v in _NEGATIVE_VECTORS],
)
def test_negative_vector_normalised_agrees(vector):
    # After round4 the value is in the hashable subspace and its canonical
    # bytes/hash match the recorded values (which gate-rust also asserts).
    normalised = round4(float(vector["input"]))
    expected_bytes = base64.b64decode(vector["normalised_canonical_base64"])  # noqa: E501
    assert canonical_json(normalised) == expected_bytes
    assert gate_hash(normalised) == vector["normalised_sha256"]


# ---------------------------------------------------------------------------
# Non-finite floats and non-string dict keys are rejected up front.
# See canonical_json.md and gate-rust's serde_json config for the shared
# boundary with the Rust side of the language boundary.
# ---------------------------------------------------------------------------

def test_canonical_json_rejects_nan():
    """NaN silently hashed by json.dumps default is not canonical JSON."""
    import math
    with pytest.raises(ValueError):
        from gate.hashing import canonical_json
        canonical_json(float("nan"))
    with pytest.raises(ValueError):
        from gate.hashing import canonical_json
        canonical_json({"x": math.nan})


def test_canonical_json_rejects_infinity():
    with pytest.raises(ValueError):
        from gate.hashing import canonical_json
        canonical_json(float("inf"))
    with pytest.raises(ValueError):
        from gate.hashing import canonical_json
        canonical_json(float("-inf"))


def test_canonical_json_rejects_non_string_keys():
    """Python silently coerces {1:'a'} to {'1':'a'}; that is not canonical JSON."""
    from gate.hashing import canonical_json
    with pytest.raises(TypeError):
        canonical_json({1: "a"})
    with pytest.raises(TypeError):
        canonical_json({True: "a"})
    with pytest.raises(TypeError):
        canonical_json({None: "a"})
    # Nested case
    with pytest.raises(TypeError):
        canonical_json({"outer": {2: "b"}})
    # Inside a list
    with pytest.raises(TypeError):
        canonical_json({"arr": [{3: "c"}]})
