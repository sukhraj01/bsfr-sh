"""Phase 2 / P2-B: a fair four-model comparison on BitcoinHeist.

Phase 1 ran every model on raw feature values (`detection.models.build_model`), which is fine for
the two tree models and unfair to the other two:

* BitcoinHeist's `income` is in satoshi (up to ~5e13) while `looped` is a small count and `weight`
  is a fraction. K-nearest-neighbours measures Euclidean distance, so on raw values the distance is
  essentially "difference in income" and the other seven features barely matter. Logistic
  regression's optimiser has the same scale problem (it was the model that "occasionally flips to
  all-negative", `RESULTS.md` M7-6 H3a).
* The amount features are heavy-tailed, so even after standardising, a few huge addresses dominate.
  `log1p` first, then standardise, is the textbook fix.
* At the natural 1.42% ransomware rate, an unweighted logistic regression minimises its loss by
  predicting "benign" for everyone (Phase 1 honest_mode: recall 0.0). `class_weight="balanced"`
  makes a missed ransomware row cost as much in total as all the benign rows.

Decision trees and random forests split on thresholds, so a monotone transform (log, standardise)
changes *where* a threshold sits but not *which training rows* fall on each side. (A threshold is
the midpoint between two training values, and log moves the midpoint, so an unseen test value
lying between them can flip.) Their scores should barely move, and that is reported as a sanity
check rather than assumed.

Everything here is fitted on the training rows only: the scaler is a step inside an sklearn
`Pipeline`, so test rows never influence the transform.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

import numpy as np
from sklearn.base import BaseEstimator, clone
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

__all__ = [
    "CALENDAR_FEATURES",
    "PREPROCESSING",
    "balanced_accuracy",
    "build_fair_estimator",
    "false_positive_rate",
]

#: Not heavy-tailed amounts: `year` is 2011-2018 and `day` is day-of-year. Standardised, not logged.
CALENDAR_FEATURES: Final = ("year", "day")

#: `raw` = Phase 1 exactly. `log_scaled` = log1p on amount features, then standardise everything.
PREPROCESSING: Final = ("raw", "log_scaled")


def _log_scaler(feature_names: Sequence[str]) -> ColumnTransformer:
    names = list(feature_names)
    amount_idx = [i for i, n in enumerate(names) if n not in CALENDAR_FEATURES]
    calendar_idx = [i for i, n in enumerate(names) if n in CALENDAR_FEATURES]
    transformers: list[tuple[str, Any, list[int]]] = [
        (
            "log_amounts",
            Pipeline(
                [
                    ("log1p", FunctionTransformer(np.log1p, validate=False)),
                    ("scale", StandardScaler()),
                ]
            ),
            amount_idx,
        )
    ]
    if calendar_idx:
        transformers.append(("calendar", StandardScaler(), calendar_idx))
    return ColumnTransformer(transformers)


def build_fair_estimator(
    estimator: BaseEstimator,
    feature_names: Sequence[str],
    *,
    preprocessing: str,
    balanced: bool = False,
) -> BaseEstimator:
    """Wrap a Phase 1 estimator with P2-B's preprocessing and, optionally, class weighting.

    `balanced=True` sets `class_weight="balanced"` when the estimator supports it (LR, RF, DT).
    KNN has no class weights; it is returned unweighted and the caller records that.
    """
    if preprocessing not in PREPROCESSING:
        raise ValueError(f"preprocessing must be one of {PREPROCESSING}, got {preprocessing!r}")
    model = clone(estimator)
    if balanced and "class_weight" in model.get_params():
        model.set_params(class_weight="balanced")
    if preprocessing == "raw":
        return model
    return Pipeline([("prep", _log_scaler(feature_names)), ("model", model)])


def false_positive_rate(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """Share of truly benign rows flagged as ransomware: FP / (FP + TN)."""
    benign = np.asarray(y_true) == 0
    if not benign.any():
        return 0.0
    return float(np.mean(np.asarray(y_pred)[benign] == 1))


def balanced_accuracy(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """Mean of recall on each class. A constant classifier always scores exactly 0.5."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    recalls = [float(np.mean(y_pred[y_true == c] == c)) for c in (0, 1) if (y_true == c).any()]
    return float(np.mean(recalls))
