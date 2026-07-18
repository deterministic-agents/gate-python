"""
Tests for gate.rounding.round4 (half-away-from-zero, four decimal places).

round4 must reproduce gate-rust's ``round4`` bit-for-bit. The tie cases
below are the ones where Python's built-in banker's rounding diverges
from Rust's half-away-from-zero, including the float-representation ties
(the f64 value of 0.00005 is not exactly 0.00005), which is why the
implementation must not go through ``decimal.Decimal(x)`` on the float or
a naive ``floor(x + 0.5)``.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

from gate.rounding import round4

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "gate"
    / "test_vectors"
    / "round4_differential_cases.json"
)


def test_round4_basic():
    assert round4(0.12345) == 0.1235
    assert round4(0.123449999) == 0.1234
    assert round4(0.99995) == 1.0
    assert round4(0.0) == 0.0
    assert round4(1.0) == 1.0


def test_round4_float_representation_ties():
    # The f64 value of 0.00005 is 5.0000000000000002e-05; scaled by 10000
    # it lands just above 0.5 and rounds up. 0.00015 lands just below 1.5
    # and rounds down. -0.00025 is an exact half and rounds away from zero.
    # These match gate-rust's round4 exactly; the committed differential
    # fixture round4_differential_cases.json (iterated below and by the
    # gate-rust suite, byte-identical copies asserted by CI in both repos)
    # is the cross-language evidence.
    assert round4(0.00005) == 0.0001
    assert round4(0.00015) == 0.0001
    assert round4(-0.00025) == -0.0003
    assert round4(0.00025) == 0.0003


def test_round4_half_away_from_zero_not_bankers():
    # Banker's rounding (Python's round) would send 2.50005 and 2.50015 to
    # the nearest even fourth decimal; round4 rounds ties away from zero.
    assert round4(0.50005) == 0.5001
    assert round4(-0.50005) == -0.5001


def test_round4_confidence_range():
    # Confidence scores live in [0, 1]; spot-check the boundary values.
    assert round4(0.5) == 0.5
    assert 0.0 <= round4(0.876543) <= 1.0
    assert round4(0.876543) == 0.8765


def test_round4_negative_zero_normalised():
    # Inputs in (-0.00005, 0.0] and -0.0 itself must return positive
    # zero, never -0.0. json.dumps serialises -0.0 as "-0.0", which
    # would diverge from a +0.0 on the other side of the language
    # boundary; gate-rust's round4 normalises -0.0 to +0.0 for the
    # same reason.
    for value in (-0.00003, -0.0, 0.0):
        result = round4(value)
        assert result == 0.0
        assert math.copysign(1.0, result) == 1.0, (
            f"round4({value!r}) returned negative zero"
        )


def test_round4_differential_fixture():
    # Shared cross-language fixture; a byte-identical copy is committed
    # in gate-rust (src/test_vectors/) and iterated by its test suite.
    # CI asserts the SHA-256 of both copies in lockstep. Input and
    # expected are decimal strings (negative_vectors precedent) so both
    # languages parse identical text with correctly rounded parsers.
    with FIXTURE_PATH.open(encoding="utf-8") as f:
        doc = json.load(f)
    cases = doc["cases"]
    assert len(cases) >= 60
    for case in cases:
        actual = round4(float(case["input"]))
        expected = float(case["expected"])
        assert actual == expected, (
            f"{case['id']}: round4({case['input']!r}) = {actual!r}, "
            f"expected {expected!r}"
        )
        # Bit-exact zero check: any zero result must be +0.0.
        assert math.copysign(1.0, actual) == math.copysign(1.0, expected), (
            f"{case['id']}: sign mismatch for {actual!r} vs {expected!r}"
        )
