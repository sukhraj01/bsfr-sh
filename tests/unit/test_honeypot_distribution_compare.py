"""`honeypot.distribution_compare`: the two-sample KS wrapper. M7-7."""

from __future__ import annotations

import numpy as np

from bsfr_sh.honeypot.distribution_compare import compare_distributions


def test_identical_distributions_have_a_tiny_statistic_and_a_large_p_value() -> None:
    rng = np.random.default_rng(0)
    sample = rng.normal(size=500)
    result = compare_distributions("x", sample, sample.copy())
    assert result.statistic == 0.0
    assert result.p_value == 1.0


def test_clearly_different_distributions_have_a_large_statistic_and_a_tiny_p_value() -> None:
    rng = np.random.default_rng(0)
    synthetic = rng.normal(loc=0.0, size=500)
    real = rng.normal(loc=10.0, size=500)
    result = compare_distributions("x", synthetic, real)
    assert result.statistic > 0.9
    assert result.p_value < 0.001


def test_result_carries_sample_sizes_and_means() -> None:
    synthetic = np.array([1.0, 2.0, 3.0])
    real = np.array([4.0, 5.0])
    result = compare_distributions("y", synthetic, real)
    assert result.n_synthetic == 3
    assert result.n_real == 2
    assert result.synthetic_mean == 2.0
    assert result.real_mean == 4.5
