"""
scipy-dependent tests for gate.assurance.behaviour.compute_drift_score.

These are skipped when scipy is not installed (install with the
[assurance] extra).
"""
from __future__ import annotations

import pytest

scipy = pytest.importorskip("scipy")

from gate.assurance.behaviour import compute_drift_score


def test_ks_identical_distributions_high_p_value():
    samples = [1.0, 2.0, 3.0, 4.0, 5.0] * 100
    stat, p = compute_drift_score(samples, list(samples), "ks")
    assert stat == 0.0
    assert p == pytest.approx(1.0, abs=1e-9)


def test_ks_shifted_distributions_detects_drift():
    a = [float(x) for x in range(0, 1000)]
    b = [float(x + 500) for x in range(0, 1000)]
    stat, p = compute_drift_score(a, b, "ks")
    assert stat > 0.4
    assert p < 0.001


def test_chi2_identical_categorical_returns_low_statistic():
    a = {"x": 100, "y": 100, "z": 100}
    b = {"x": 100, "y": 100, "z": 100}
    stat, p = compute_drift_score(a, b, "chi2")
    assert stat == pytest.approx(0.0, abs=1e-9)
    assert p == pytest.approx(1.0, abs=1e-9)


def test_chi2_invalid_test_type_raises():
    with pytest.raises(ValueError):
        compute_drift_score([1, 2], [1, 2], "not_a_test")
