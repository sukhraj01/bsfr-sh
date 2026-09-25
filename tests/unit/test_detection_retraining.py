"""`detection.retraining`: augmenting the training draw with perturbed positive copies. M7-8."""

from __future__ import annotations

import numpy as np
from m3b_harness import clean_draw, feature_matrix

from bsfr_sh.detection.adversarial import FEATURE_BOUNDS
from bsfr_sh.detection.retraining import augment_positive_rows
from bsfr_sh.honeypot import features as ft

_FEATURE_INDEX = {name: i for i, name in enumerate(ft.FEATURE_NAMES)}
_TOP5 = list(FEATURE_BOUNDS)
_INDICES = [_FEATURE_INDEX[name] for name in _TOP5]
_BOUNDS = [FEATURE_BOUNDS[name] for name in _TOP5]


def _draw(count: int = 200, seed: int = 4242) -> tuple[np.ndarray, np.ndarray]:
    x, y, _missing = feature_matrix(clean_draw(count=count, seed=seed))
    return x, y


def test_max_perturbation_zero_is_a_no_op() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    x_aug, y_aug = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=5, max_perturbation=0.0, rng=rng
    )
    assert x_aug is x
    assert y_aug is y


def test_k_zero_is_a_no_op() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    x_aug, y_aug = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=0, max_perturbation=0.5, rng=rng
    )
    assert x_aug is x
    assert y_aug is y


def test_row_count_is_original_plus_k_times_positives() -> None:
    x, y = _draw()
    n_positive = int((y == 1).sum())
    rng = np.random.default_rng(0)
    k = 5
    x_aug, y_aug = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=k, max_perturbation=0.5, rng=rng
    )
    assert len(x_aug) == len(x) + k * n_positive
    assert len(y_aug) == len(y) + k * n_positive
    assert x_aug.shape[1] == x.shape[1]


def test_appended_rows_are_all_labelled_positive() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    _x_aug, y_aug = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=3, max_perturbation=0.5, rng=rng
    )
    appended = y_aug[len(y) :]
    assert np.all(appended == 1)
    assert len(appended) == 3 * int((y == 1).sum())


def test_original_rows_are_untouched() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    x_aug, y_aug = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=3, max_perturbation=0.5, rng=rng
    )
    assert np.array_equal(x_aug[: len(x)], x)
    assert np.array_equal(y_aug[: len(y)], y)


def test_perturbed_features_stay_between_original_value_and_bound() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    x_aug, _y_aug = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=4, max_perturbation=1.0, rng=rng
    )
    appended = x_aug[len(x) :]
    positive_originals = x[y == 1]
    tiled = np.tile(positive_originals, (4, 1))
    for index, fb in zip(_INDICES, _BOUNDS, strict=True):
        lo = np.minimum(tiled[:, index], fb.bound)
        hi = np.maximum(tiled[:, index], fb.bound)
        assert np.all(appended[:, index] >= lo - 1e-9)
        assert np.all(appended[:, index] <= hi + 1e-9)


def test_non_top5_features_are_never_perturbed() -> None:
    x, y = _draw()
    rng = np.random.default_rng(0)
    x_aug, _y_aug = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=2, max_perturbation=1.0, rng=rng
    )
    appended = x_aug[len(x) :]
    positive_originals = x[y == 1]
    tiled = np.tile(positive_originals, (2, 1))
    other_columns = [i for i in range(x.shape[1]) if i not in _INDICES]
    assert np.array_equal(appended[:, other_columns], tiled[:, other_columns])


def test_same_seed_is_deterministic() -> None:
    x, y = _draw()
    x_aug1, _ = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=3, max_perturbation=0.5, rng=np.random.default_rng(7)
    )
    x_aug2, _ = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=3, max_perturbation=0.5, rng=np.random.default_rng(7)
    )
    assert np.array_equal(x_aug1, x_aug2)


def test_different_seeds_diverge() -> None:
    x, y = _draw()
    x_aug1, _ = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=3, max_perturbation=0.5, rng=np.random.default_rng(7)
    )
    x_aug2, _ = augment_positive_rows(
        x, y, _INDICES, _BOUNDS, k=3, max_perturbation=0.5, rng=np.random.default_rng(8)
    )
    assert not np.array_equal(x_aug1, x_aug2)
