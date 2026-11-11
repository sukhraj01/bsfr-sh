"""P2-B: `detection.fair` — preprocessing is train-only, trees are unaffected, metrics are right."""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier

from bsfr_sh.detection.fair import balanced_accuracy, build_fair_estimator, false_positive_rate

NAMES = ("year", "day", "length", "weight", "count", "looped", "neighbors", "income")


def _data(seed: int = 0, n: int = 400) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    x = np.column_stack(
        [
            rng.integers(2011, 2019, n),
            rng.integers(1, 366, n),
            rng.integers(0, 145, n),
            rng.random(n) * 10,
            rng.integers(1, 5000, n),
            rng.integers(0, 50, n),
            rng.integers(1, 20, n),
            rng.lognormal(20, 3, n),  # heavy-tailed, like `income`
        ]
    ).astype(np.float64)
    y = (np.log(x[:, 7]) + rng.normal(0, 1, n) > 21).astype(int)
    return x, y


def test_scaler_is_fitted_on_training_rows_only() -> None:
    x, y = _data()
    model = build_fair_estimator(LogisticRegression(), NAMES, preprocessing="log_scaled")
    model.fit(x[:300], y[:300])
    scaler = model.named_steps["prep"].named_transformers_["calendar"]
    assert scaler.mean_ == pytest.approx(x[:300, :2].mean(axis=0))
    assert scaler.mean_ != pytest.approx(x[:, :2].mean(axis=0))


def test_monotone_preprocessing_leaves_a_decision_tree_almost_unchanged() -> None:
    """Same partition of the training rows; only unseen values *between* two training values can
    land on the other side, because a threshold sits at the midpoint and log moves the midpoint."""
    x, y = _data(1)
    raw = build_fair_estimator(DecisionTreeClassifier(random_state=0), NAMES, preprocessing="raw")
    scaled = build_fair_estimator(
        DecisionTreeClassifier(random_state=0), NAMES, preprocessing="log_scaled"
    )
    raw.fit(x[:300], y[:300])
    scaled.fit(x[:300], y[:300])
    assert np.array_equal(raw.predict(x[:300]), scaled.predict(x[:300]))
    assert np.mean(raw.predict(x[300:]) == scaled.predict(x[300:])) >= 0.9


def test_balanced_sets_class_weight_where_supported_and_skips_knn() -> None:
    lr = build_fair_estimator(LogisticRegression(), NAMES, preprocessing="raw", balanced=True)
    assert lr.get_params()["class_weight"] == "balanced"
    knn = build_fair_estimator(KNeighborsClassifier(), NAMES, preprocessing="raw", balanced=True)
    assert "class_weight" not in knn.get_params()


def test_original_estimator_is_not_mutated() -> None:
    base = LogisticRegression()
    build_fair_estimator(base, NAMES, preprocessing="log_scaled", balanced=True)
    assert base.get_params()["class_weight"] is None


def test_unknown_preprocessing_is_rejected() -> None:
    with pytest.raises(ValueError, match="preprocessing"):
        build_fair_estimator(LogisticRegression(), NAMES, preprocessing="minmax")


def test_fpr_and_balanced_accuracy_hand_computed() -> None:
    y_true = np.array([0, 0, 0, 0, 1, 1])
    y_pred = np.array([1, 0, 0, 0, 1, 0])
    assert false_positive_rate(y_true, y_pred) == pytest.approx(0.25)
    assert balanced_accuracy(y_true, y_pred) == pytest.approx((0.75 + 0.5) / 2)
    # a constant classifier is exactly chance on balanced accuracy, whatever the class balance
    assert balanced_accuracy(y_true, np.ones_like(y_true)) == pytest.approx(0.5)
