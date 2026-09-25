"""`detection.poisoning`: label-flip, feature-poison, and anchor-point training attacks. M7-11."""

from __future__ import annotations

import numpy as np
from m3b_harness import clean_draw, feature_matrix

from bsfr_sh.detection.poisoning import (
    anchor_point_injection,
    feature_poison,
    label_flip,
)


def _draw(count: int = 200, seed: int = 4242) -> tuple[np.ndarray, np.ndarray]:
    x, y, _missing = feature_matrix(clean_draw(count=count, seed=seed))
    return x, y


# -- label_flip ------------------------------------------------------------------------------


def test_label_flip_zero_budget_is_a_no_op() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = label_flip(x, y, 0.0, rng=rng)
    assert result.x is x
    assert result.y is y
    assert result.n_poisoned == 0
    assert result.poisoned_row_indices == ()


def test_label_flip_row_count_is_unchanged() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = label_flip(x, y, 0.5, rng=rng)
    assert len(result.x) == len(x)
    assert len(result.y) == len(y)
    assert result.x is x  # features are never touched by this strategy


def test_label_flip_flips_the_expected_fraction_of_positives() -> None:
    x, y = _draw()
    n_positive = int((y == 1).sum())
    rng = np.random.default_rng(0)
    result = label_flip(x, y, 0.5, rng=rng)
    assert result.n_poisoned == round(0.5 * n_positive)
    # every flipped row was originally positive and is now negative
    for index in result.poisoned_row_indices:
        assert y[index] == 1
        assert result.y[index] == 0
    # class counts moved by exactly n_poisoned
    assert int((result.y == 1).sum()) == n_positive - result.n_poisoned


def test_label_flip_never_touches_negative_rows() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = label_flip(x, y, 0.5, rng=rng)
    for index in result.poisoned_row_indices:
        assert y[index] == 1  # only originally-positive rows are ever chosen


def test_label_flip_original_arrays_are_not_mutated() -> None:
    x, y = _draw()
    y_before = y.copy()
    rng = np.random.default_rng(0)
    label_flip(x, y, 0.5, rng=rng)
    assert np.array_equal(y, y_before)


def test_label_flip_full_budget_flips_every_positive() -> None:
    x, y = _draw()
    n_positive = int((y == 1).sum())
    rng = np.random.default_rng(0)
    result = label_flip(x, y, 1.0, rng=rng)
    assert result.n_poisoned == n_positive
    assert int((result.y == 1).sum()) == 0


# -- feature_poison ---------------------------------------------------------------------------


def test_feature_poison_zero_budget_is_a_no_op() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = feature_poison(x, y, 0.0, rng=rng)
    assert result.x is x
    assert result.y is y


def test_feature_poison_row_count_grows_by_expected_amount() -> None:
    x, y = _draw()
    n_positive = int((y == 1).sum())
    rng = np.random.default_rng(0)
    result = feature_poison(x, y, 0.2, rng=rng)
    n_inject = round(0.2 * n_positive)
    assert len(result.x) == len(x) + n_inject
    assert result.n_poisoned == n_inject


def test_feature_poison_injected_rows_are_labelled_ransomware() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = feature_poison(x, y, 0.2, rng=rng)
    injected_y = result.y[len(y) :]
    assert np.all(injected_y == 1)


def test_feature_poison_injected_features_come_from_real_benign_rows() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = feature_poison(x, y, 0.2, rng=rng)
    injected_x = result.x[len(x) :]
    negative_rows = x[y == 0]
    for row in injected_x:
        assert any(np.array_equal(row, benign_row) for benign_row in negative_rows)


def test_feature_poison_original_rows_are_untouched() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = feature_poison(x, y, 0.2, rng=rng)
    assert np.array_equal(result.x[: len(x)], x)
    assert np.array_equal(result.y[: len(y)], y)


# -- anchor_point_injection ---------------------------------------------------------------------


def test_anchor_zero_budget_is_a_no_op() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = anchor_point_injection(x, y, 0.0, rng=rng)
    assert result.x is x
    assert result.y is y


def test_anchor_row_count_grows_by_expected_amount() -> None:
    x, y = _draw()
    n_positive = int((y == 1).sum())
    rng = np.random.default_rng(0)
    result = anchor_point_injection(x, y, 0.2, rng=rng)
    n_inject = round(0.2 * n_positive)
    assert len(result.x) == len(x) + n_inject
    assert result.n_poisoned == n_inject


def test_anchor_injected_rows_are_labelled_benign() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = anchor_point_injection(x, y, 0.2, rng=rng)
    injected_y = result.y[len(y) :]
    assert np.all(injected_y == 0)


def test_anchor_injected_features_sit_between_the_two_centroids() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = anchor_point_injection(x, y, 0.3, rng=rng)
    injected_x = result.x[len(x) :]
    benign_centroid = x[y == 0].mean(axis=0)
    malicious_centroid = x[y == 1].mean(axis=0)
    # every injected row's mean position is roughly at the interpolated anchor, not pinned to
    # either original centroid -- checked on the injected batch's own mean to average out jitter
    injected_mean = injected_x.mean(axis=0)
    expected_anchor = benign_centroid + 0.5 * (malicious_centroid - benign_centroid)
    assert np.allclose(injected_mean, expected_anchor, rtol=0.05, atol=0.5)


def test_anchor_injected_rows_are_not_literally_identical() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = anchor_point_injection(x, y, 0.3, rng=rng)
    injected_x = result.x[len(x) :]
    assert len(injected_x) >= 2
    assert not np.array_equal(injected_x[0], injected_x[1])


def test_anchor_original_rows_are_untouched() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    result = anchor_point_injection(x, y, 0.2, rng=rng)
    assert np.array_equal(result.x[: len(x)], x)
    assert np.array_equal(result.y[: len(y)], y)


# -- shared determinism property, all three strategies -----------------------------------------


def test_same_seed_is_deterministic_for_every_strategy() -> None:
    x, y = _draw()
    for fn in (label_flip, feature_poison, anchor_point_injection):
        r1 = fn(x, y, 0.3, rng=np.random.default_rng(11))
        r2 = fn(x, y, 0.3, rng=np.random.default_rng(11))
        assert np.array_equal(r1.x, r2.x)
        assert np.array_equal(r1.y, r2.y)
