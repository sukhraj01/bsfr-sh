"""The four estimators Table II compares, with every hyperparameter declared. Target 1.

The paper names Random Forest, Logistic Regression, Decision Tree and KNN and reports **no
hyperparameter for any of them** — not a depth, not a `k`, not a solver. Silently taking
scikit-learn's defaults would bury our choices inside a number presented as theirs, so every
value comes from `configs/ml.yaml`, and `random_state` is injected from the run's seed rather than
hard-coded.

Compute, before it bites (CLAUDE.md §6)
---------------------------------------
`paper_mode` is ~46K rows and runs anywhere. `honest_mode` at 2.9M rows is a different machine's
problem, and KNN is the specific hazard: it has *no* training cost and all of its cost at predict
time, O(n_train x n_query) distance computations per fold, with a neighbour structure over the
training half. `knn_projection()` estimates the peak before anything is launched, so a run that
cannot fit is named and deferred to Ada instead of discovered by an OOM ninety minutes in.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

import numpy as np
from sklearn.base import BaseEstimator
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier

from bsfr_sh.util.config import Config

__all__ = [
    "MODEL_NAMES",
    "FittedModel",
    "ModelError",
    "build_model",
    "build_models",
    "fit_and_score",
    "fits_in_memory",
    "knn_projection",
    "train_all",
]

#: The four algorithms Table II requires, in the order `configs/ml.yaml` declares them.
MODEL_NAMES: Final = (
    "random_forest",
    "logistic_regression",
    "decision_tree",
    "k_nearest_neighbours",
)


class ModelError(ValueError):
    """Raised when a model cannot be built from the declared configuration."""


def _params(config: Config, name: str) -> dict[str, Any]:
    models = config.require("models", dict)
    if name not in models:
        raise ModelError(f"configs/ml.yaml declares no {name!r}; Table II needs all four")
    declared = dict(models[name])
    declared.pop("enabled", None)
    return declared


def build_model(config: Config, name: str, *, seed: int) -> BaseEstimator:
    """One estimator, built from the declared hyperparameters with the seed injected."""
    params = _params(config, name)
    if name == "random_forest":
        return RandomForestClassifier(random_state=seed, **params)
    if name == "logistic_regression":
        return LogisticRegression(random_state=seed, **params)
    if name == "decision_tree":
        return DecisionTreeClassifier(random_state=seed, **params)
    if name == "k_nearest_neighbours":
        return KNeighborsClassifier(**params)  # deterministic; takes no random_state
    raise ModelError(f"unknown model {name!r}; expected one of {MODEL_NAMES}")


def build_models(config: Config, *, seed: int) -> dict[str, BaseEstimator]:
    """Every enabled model, in declaration order."""
    models = config.require("models", dict)
    return {
        name: build_model(config, name, seed=seed)
        for name in MODEL_NAMES
        if models.get(name, {}).get("enabled", True)
    }


def train_all(
    x_train: np.ndarray, y_train: np.ndarray, config: Config, *, seed: int
) -> dict[str, BaseEstimator]:
    """Implements Alg. 3, line 2: fit every enabled model on one draw. `DM_CSl`, trained.

    Unlike `fit_and_score`, this fits and stops — Phase 3 line 2 is "train", not "evaluate", and
    the fitted estimators are what `detection.profiles.build()` and `detection.detector` both
    consume next.
    """
    models = build_models(config, seed=seed)
    for estimator in models.values():
        estimator.fit(x_train, y_train)
    return models


@dataclass(frozen=True)
class FittedModel:
    """One fit/predict cycle, with the wall times the sidecar records separately."""

    name: str
    predictions: np.ndarray
    scores: np.ndarray | None
    fit_seconds: float
    predict_seconds: float
    n_train: int
    n_test: int

    def as_dict(self) -> dict[str, object]:
        return {
            "model": self.name,
            "fit_seconds": self.fit_seconds,
            "predict_seconds": self.predict_seconds,
            "n_train": self.n_train,
            "n_test": self.n_test,
        }


def fit_and_score(
    estimator: BaseEstimator,
    name: str,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_test: np.ndarray,
    y_test: np.ndarray,  # noqa: ARG001 - kept so callers read as (train, test) pairs
) -> FittedModel:
    """Fit, predict, and time the two halves separately — KNN's cost is all in the second."""
    started = time.perf_counter()
    estimator.fit(x_train, y_train)
    fit_seconds = time.perf_counter() - started

    started = time.perf_counter()
    predictions = estimator.predict(x_test)
    predict_seconds = time.perf_counter() - started

    scores: np.ndarray | None = None
    if hasattr(estimator, "predict_proba"):
        probabilities = estimator.predict_proba(x_test)
        if probabilities.shape[1] == 2:
            scores = probabilities[:, 1]
    return FittedModel(
        name=name,
        predictions=np.asarray(predictions),
        scores=scores,
        fit_seconds=fit_seconds,
        predict_seconds=predict_seconds,
        n_train=len(y_train),
        n_test=len(x_test),
    )


def knn_projection(
    n_train: int, n_query: int, n_features: int, *, n_jobs: int = 1, dtype_bytes: int = 8
) -> dict[str, float]:
    """Project KNN's peak memory and distance count before running it. CLAUDE.md §6.

    The stored training matrix is `n_train x n_features`; scikit-learn's brute/tree query works in
    chunks, but each parallel worker holds its own chunk of the distance block, so the term that
    actually grows is `chunk x n_train` per job. The distance *count* — `n_train x n_query` — is
    what makes the wall time impossible long before memory does.
    """
    train_bytes = n_train * n_features * dtype_bytes
    chunk = min(n_query, 1024)
    distance_bytes = chunk * n_train * dtype_bytes * max(1, n_jobs)
    return {
        "train_matrix_gb": train_bytes / 1024**3,
        "distance_block_gb": distance_bytes / 1024**3,
        "peak_gb": (train_bytes + distance_bytes) / 1024**3,
        "distance_computations": float(n_train) * float(n_query),
    }


def fits_in_memory(
    projection: Mapping[str, float], *, ceiling_gb: float = 8.0, headroom: float = 0.6
) -> bool:
    """Whether a projected peak leaves room for the interpreter, the data and the OS."""
    return projection["peak_gb"] <= ceiling_gb * headroom
