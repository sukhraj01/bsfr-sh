"""`detection.metrics`: both metric sets, and the baselines that make them readable. DEV-06."""

from __future__ import annotations

import numpy as np
import pytest

from bsfr_sh.detection.metrics import (
    analytic_constant_positive,
    baselines,
    honest_metrics,
    paper_metrics,
)


def _labels(positive_fraction: float, n: int = 10_000) -> np.ndarray:
    positives = round(n * positive_fraction)
    return np.array([1] * positives + [0] * (n - positives), dtype=np.int8)


# -- the baseline the paper's split hands out for free -----------------------------------------
def test_the_analytic_constant_positive_baseline_on_the_papers_split() -> None:
    accuracy, f1 = analytic_constant_positive(0.90)
    assert accuracy == pytest.approx(0.900)
    assert f1 == pytest.approx(0.9474, abs=0.0001)


def test_the_analytic_baseline_is_confirmed_empirically() -> None:
    """RESULTS.md carries this as analytic; here is the empirical confirmation."""
    y_true = _labels(0.90)
    measured = baselines(y_true, seed=0).constant_positive
    accuracy, f1 = analytic_constant_positive(0.90)
    assert measured.accuracy == pytest.approx(accuracy, abs=0.001)
    assert measured.f1 == pytest.approx(f1, abs=0.001)


def test_constant_positive_beats_most_of_table_two_while_knowing_nothing() -> None:
    """0.900 accuracy from a classifier that never looks at a feature — DEV-06's whole point."""
    measured = baselines(_labels(0.90)).constant_positive
    assert measured.accuracy > 0.89
    assert measured.f1 > 0.94


# -- the inversion at the natural rate ----------------------------------------------------------
def test_never_predicting_ransomware_scores_98_percent_at_the_natural_rate() -> None:
    y_true = _labels(0.0142)
    negative = baselines(y_true).constant_negative
    assert negative.accuracy == pytest.approx(0.9858, abs=0.001)
    assert negative.f1 == 0.0


def test_that_baseline_finds_nothing_which_is_what_honest_mode_reports() -> None:
    y_true = _labels(0.0142)
    honest = baselines(y_true).constant_negative_honest
    assert honest.recall == 0.0
    assert honest.precision == 0.0
    assert honest.f1_minority == 0.0
    assert honest.mcc == 0.0
    _tn, fp, fn, tp = honest.confusion
    assert (tp, fp) == (0, 0)
    assert fn == int(y_true.sum())
    # The number that looks good and means nothing, reported beside the ones that do not.
    assert honest.accuracy_for_contrast > 0.98


def test_the_stratified_random_baseline_is_near_the_class_rate() -> None:
    y_true = _labels(0.0142, n=50_000)
    honest = baselines(y_true, seed=5).stratified_random_honest
    assert honest.precision == pytest.approx(0.0142, abs=0.01)
    assert honest.recall == pytest.approx(0.0142, abs=0.01)


# -- metric mechanics ---------------------------------------------------------------------------
def test_a_perfect_prediction_scores_one_everywhere() -> None:
    y_true = _labels(0.30, n=1000)
    assert paper_metrics(y_true, y_true).accuracy == 1.0
    assert paper_metrics(y_true, y_true).f1 == 1.0
    honest = honest_metrics(y_true, y_true)
    assert (honest.precision, honest.recall, honest.f1_minority) == (1.0, 1.0, 1.0)
    assert honest.mcc == pytest.approx(1.0)


def test_the_confusion_matrix_counts_what_it_says() -> None:
    y_true = np.array([0, 0, 1, 1], dtype=np.int8)
    y_pred = np.array([0, 1, 0, 1], dtype=np.int8)
    tn, fp, fn, tp = honest_metrics(y_true, y_pred).confusion
    assert (tn, fp, fn, tp) == (1, 1, 1, 1)


def test_pr_auc_uses_scores_when_they_are_given() -> None:
    y_true = np.array([0, 0, 1, 1], dtype=np.int8)
    strong = honest_metrics(y_true, y_true, np.array([0.1, 0.2, 0.9, 0.95]))
    weak = honest_metrics(y_true, y_true, np.array([0.9, 0.95, 0.1, 0.2]))
    assert strong.pr_auc > weak.pr_auc


def test_an_impossible_class_balance_is_refused() -> None:
    with pytest.raises(ValueError, match="positive_fraction"):
        analytic_constant_positive(1.5)
