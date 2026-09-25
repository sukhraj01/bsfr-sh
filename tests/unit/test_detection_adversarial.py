"""`detection.adversarial`: feature-space evasion primitives shared by M7-3 and M7-8."""

from __future__ import annotations

import numpy as np
from m3b_harness import SEED, clean_draw, feature_matrix
from pbft_harness import REPO_ROOT

from bsfr_sh.detection.adversarial import (
    FEATURE_BOUNDS,
    STEPS,
    FeatureBound,
    adaptive_evasion,
    apply_perturbation,
    balanced_accuracy,
    combined_curve,
    ensemble_predict,
    select_best_importance_model,
    single_feature_curves,
    top_feature_importances,
)
from bsfr_sh.detection.detector import DetectionModule
from bsfr_sh.detection.models import train_all
from bsfr_sh.detection.profiles import build
from bsfr_sh.honeypot import features as ft
from bsfr_sh.util.config import load_config

CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
_FEATURE_INDEX = {name: i for i, name in enumerate(ft.FEATURE_NAMES)}
_TOP5 = list(FEATURE_BOUNDS)


def _detector(count: int = 300, seed: int = SEED) -> tuple[DetectionModule, np.ndarray, np.ndarray]:
    x, y, _missing = feature_matrix(clean_draw(count=count, seed=seed))
    models = train_all(x, y, CONFIG, seed=seed)
    normal, abnormal = build(models, x, y, feature_names=ft.FEATURE_NAMES)
    return DetectionModule(models=models, normal=normal, abnormal=abnormal), x, y


def test_balanced_accuracy_matches_sklearn() -> None:
    from sklearn.metrics import balanced_accuracy_score

    rng = np.random.default_rng(1)
    y_true = rng.integers(0, 2, size=200)
    y_pred = rng.integers(0, 2, size=200)
    assert balanced_accuracy(y_true, y_pred) == balanced_accuracy_score(y_true, y_pred)


def test_apply_perturbation_only_touches_positive_rows() -> None:
    x, y, _missing = feature_matrix(clean_draw(count=50))
    idx = _FEATURE_INDEX[_TOP5[0]]
    fb = FEATURE_BOUNDS[_TOP5[0]]
    perturbed = apply_perturbation(x, y, [idx], [fb], frac=1.0)
    negative = y == 0
    assert np.array_equal(perturbed[negative], x[negative])


def test_apply_perturbation_frac_zero_is_identity() -> None:
    x, y, _missing = feature_matrix(clean_draw(count=50))
    idx = _FEATURE_INDEX[_TOP5[0]]
    fb = FEATURE_BOUNDS[_TOP5[0]]
    perturbed = apply_perturbation(x, y, [idx], [fb], frac=0.0)
    assert np.array_equal(perturbed, x)


def test_apply_perturbation_frac_one_reaches_the_bound_exactly() -> None:
    x, y, _missing = feature_matrix(clean_draw(count=50))
    idx = _FEATURE_INDEX[_TOP5[0]]
    fb = FEATURE_BOUNDS[_TOP5[0]]
    perturbed = apply_perturbation(x, y, [idx], [fb], frac=1.0)
    positive = y == 1
    assert np.allclose(perturbed[positive, idx], fb.bound)


def test_ensemble_predict_matches_decide_called_row_by_row() -> None:
    detector, x, _y = _detector()
    batched = ensemble_predict(detector, x)
    row_by_row = np.array(
        [int(detector.decide(str(i), row).is_ransomware) for i, row in enumerate(x)]
    )
    assert np.array_equal(batched, row_by_row)


def test_single_feature_curves_start_at_the_unperturbed_baseline() -> None:
    detector, x, y = _detector()
    baseline = balanced_accuracy(y, ensemble_predict(detector, x))
    curves = single_feature_curves(detector, x, y, _TOP5, _FEATURE_INDEX)
    assert set(curves) == set(_TOP5)
    for curve in curves.values():
        assert len(curve) == len(STEPS)
        assert curve[0] == baseline


def test_combined_curve_starts_at_the_unperturbed_baseline() -> None:
    detector, x, y = _detector()
    baseline = balanced_accuracy(y, ensemble_predict(detector, x))
    curve = combined_curve(detector, x, y, _TOP5, _FEATURE_INDEX)
    assert len(curve) == len(STEPS)
    assert curve[0] == baseline


def test_adaptive_evasion_minima_are_bounded_and_ordered() -> None:
    detector, x, y = _detector(count=400)
    result = adaptive_evasion(detector, x, y, _TOP5, _FEATURE_INDEX)
    minima = np.array(result["minima"])
    assert result["n_positive"] == int((y == 1).sum())
    assert len(minima) == result["n_positive"]
    assert np.all((minima >= 0.0) & (minima <= 1.0))
    assert result["p10"] <= result["median"] <= result["p90"]


def test_select_best_importance_model_returns_the_higher_scoring_candidate() -> None:
    x, y, _missing = feature_matrix(clean_draw(count=300))
    x_eval, y_eval, _m = feature_matrix(clean_draw(count=150, seed=SEED + 1))
    name, model, score = select_best_importance_model(CONFIG, x, y, x_eval, y_eval, seed=SEED)
    assert name in ("random_forest", "decision_tree")
    assert score == balanced_accuracy(y_eval, model.predict(x_eval))


def test_top_feature_importances_returns_n_sorted_descending() -> None:
    x, y, _missing = feature_matrix(clean_draw(count=300))
    _name, model, _score = select_best_importance_model(CONFIG, x, y, x, y, seed=SEED)
    top = top_feature_importances(model, ft.FEATURE_NAMES, 5)
    assert len(top) == 5
    values = [v for _n, v in top]
    assert values == sorted(values, reverse=True)


def test_feature_bounds_table_has_a_justification_for_every_entry() -> None:
    for name, fb in FEATURE_BOUNDS.items():
        assert isinstance(fb, FeatureBound)
        assert fb.direction in (-1.0, 1.0)
        assert fb.justification
        assert name in ft.FEATURE_NAMES
