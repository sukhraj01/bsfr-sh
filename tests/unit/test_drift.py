"""`detection.drift` — Welford's running stats, Mahalanobis and Page-Hinkley scoring. M7-12."""

from __future__ import annotations

import itertools

import numpy as np
import pytest

from bsfr_sh.detection.drift import DriftDetector, DriftMethod, DriftPolicy, RunningStats


def _constant_batches(value: float, n_features: int = 4, batch_size: int = 20) -> np.ndarray:
    return np.full((batch_size, n_features), value, dtype=float)


def _noisy_batch(
    rng: np.random.Generator, mean: float, n_features: int = 4, batch_size: int = 20
) -> np.ndarray:
    return rng.normal(mean, 0.05, size=(batch_size, n_features))


# -- RunningStats ------------------------------------------------------------------------------


def test_running_stats_mean_and_variance_match_numpy() -> None:
    rng = np.random.default_rng(0)
    values = rng.normal(3.0, 2.0, size=500)
    stats = RunningStats()
    for v in values:
        stats.update(float(v))
    assert stats.mean == pytest.approx(float(values.mean()), abs=1e-9)
    assert stats.variance == pytest.approx(float(values.var(ddof=1)), abs=1e-6)


def test_running_stats_merge_batch_matches_row_by_row_update() -> None:
    rng = np.random.default_rng(1)
    values = rng.normal(-1.0, 3.0, size=300)
    row_by_row = RunningStats()
    for v in values:
        row_by_row.update(float(v))
    merged = RunningStats()
    merged.merge_batch(float(values.mean()), float(values.var(ddof=1)), len(values))
    assert merged.mean == pytest.approx(row_by_row.mean, abs=1e-9)
    assert merged.variance == pytest.approx(row_by_row.variance, abs=1e-6)


def test_running_stats_merge_batch_is_associative_across_chunks() -> None:
    rng = np.random.default_rng(2)
    values = rng.normal(5.0, 1.5, size=400)
    whole = RunningStats()
    whole.merge_batch(float(values.mean()), float(values.var(ddof=1)), len(values))
    chunked = RunningStats()
    for chunk in np.array_split(values, 5):
        chunked.merge_batch(float(chunk.mean()), float(chunk.var(ddof=1)), len(chunk))
    assert chunked.mean == pytest.approx(whole.mean, abs=1e-6)
    assert chunked.variance == pytest.approx(whole.variance, rel=1e-3)


# -- DriftDetector: cold start -------------------------------------------------------------------


def test_score_batch_before_min_history_never_flags_drift() -> None:
    policy = DriftPolicy(min_history=5)
    detector = DriftDetector(3, policy=policy)
    # Even a wildly different batch cannot be judged with no profile to compare against.
    shifted = np.full((10, 3), 1000.0)
    report = detector.score_batch(shifted)
    assert report.drift_detected is False
    assert report.n_history_batches == 0


# -- DriftDetector: constant stream -> no drift ---------------------------------------------------


@pytest.mark.parametrize("method", [DriftMethod.MAHALANOBIS, DriftMethod.PAGE_HINKLEY])
def test_constant_stream_never_flags_drift(method: DriftMethod) -> None:
    policy = DriftPolicy(method=method, min_history=3)
    detector = DriftDetector(4, policy=policy)
    for _ in range(30):
        batch = _constant_batches(1.0)
        report = detector.score_batch(batch)
        assert report.drift_detected is False
        detector.update(batch)


# -- DriftDetector: injected shift is detected ---------------------------------------------------


@pytest.mark.parametrize("method", [DriftMethod.MAHALANOBIS, DriftMethod.PAGE_HINKLEY])
def test_injected_shifted_batch_is_detected(method: DriftMethod) -> None:
    rng = np.random.default_rng(42)
    policy = DriftPolicy(method=method, min_history=5, threshold=3.0, ph_threshold=4.0)
    detector = DriftDetector(4, policy=policy)
    for _ in range(10):
        batch = _noisy_batch(rng, mean=0.0)
        assert detector.score_batch(batch).drift_detected is False
        detector.update(batch)
    shifted = _noisy_batch(rng, mean=10.0)
    report = detector.score_batch(shifted)
    assert report.drift_detected is True
    assert report.method is method


def test_offending_features_names_the_shifted_column_only() -> None:
    rng = np.random.default_rng(7)
    policy = DriftPolicy(min_history=5, threshold=1.5, feature_threshold=1.5)
    detector = DriftDetector(3, feature_names=("a", "b", "c"), policy=policy)
    for _ in range(10):
        batch = _noisy_batch(rng, mean=0.0, n_features=3)
        detector.update(batch)
    shifted = _noisy_batch(rng, mean=0.0, n_features=3)
    shifted[:, 1] += 5.0  # only column "b" moves
    report = detector.score_batch(shifted)
    assert "b" in report.offending_features
    assert "a" not in report.offending_features
    assert "c" not in report.offending_features


# -- threshold monotonicity ----------------------------------------------------------------------


def test_detection_rate_is_monotone_in_the_threshold() -> None:
    thresholds = [0.5, 1.0, 2.0, 4.0, 8.0, 16.0]
    detection_counts = []
    for threshold in thresholds:
        policy = DriftPolicy(min_history=5, threshold=threshold)
        detector = DriftDetector(4, policy=policy)
        rng_local = np.random.default_rng(11)
        for _ in range(5):
            detector.update(_noisy_batch(rng_local, mean=0.0))
        hits = 0
        for shift in np.linspace(0.0, 6.0, 20):
            batch = _noisy_batch(rng_local, mean=float(shift))
            if detector.score_batch(batch).drift_detected:
                hits += 1
        detection_counts.append(hits)
    for earlier, later in itertools.pairwise(detection_counts):
        assert later <= earlier


# -- score_batch never mutates state ---------------------------------------------------------------


def test_score_batch_does_not_mutate_state() -> None:
    rng = np.random.default_rng(3)
    detector = DriftDetector(4, policy=DriftPolicy(min_history=3))
    for _ in range(5):
        detector.update(_noisy_batch(rng, mean=0.0))
    before = detector.n_history_batches
    detector.score_batch(_noisy_batch(rng, mean=50.0))
    detector.score_batch(_noisy_batch(rng, mean=50.0))
    assert detector.n_history_batches == before


# -- validation ------------------------------------------------------------------------------------


def test_rejects_wrong_column_count() -> None:
    detector = DriftDetector(4)
    with pytest.raises(ValueError, match="columns"):
        detector.score_batch(np.zeros((3, 2)))


def test_rejects_empty_batch() -> None:
    detector = DriftDetector(4)
    with pytest.raises(ValueError, match="at least one row"):
        detector.score_batch(np.zeros((0, 4)))


def test_feature_names_length_must_match() -> None:
    with pytest.raises(ValueError, match="feature_names"):
        DriftDetector(3, feature_names=("a", "b"))
