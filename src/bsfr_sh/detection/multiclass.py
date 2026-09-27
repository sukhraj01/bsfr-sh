"""Multi-class ransomware family detection over BitcoinHeist. M7-16.

The binary detector (`detection.dataset`/`detection.models`/`detection.metrics`, M4a onward)
answers "is this address ransomware?" BitcoinHeist's `label` column already carries *which* of 28
named families it is — information the binary evaluation has never used. This module asks whether
the same 8 address-level graph features (`detection.dataset.FEATURE_COLUMNS`) that support the
binary boundary also support 28+1 separate ones. The finding decides two things: whether
Algorithm 4's mitigation could plausibly dispatch a response by family (different families imply
different decryption tools and kill-chain speeds), and whether `honeypot.features`'s missing
family label (docs/ARCHITECTURE.md §honeypot) is a real gap in the synthetic pipeline or a moot
one.

Rare families are merged, never dropped
------------------------------------------
Eleven of the 28 families have fewer than `MIN_FAMILY_SAMPLES` addresses in the whole dataset (one
has exactly 1). A held-out fold with 1-2 examples of a class produces a precision/recall number
that is pure sampling noise, and a stratified split cannot even guarantee a training example
survives. `merge_rare_families` folds every family below the threshold into `OTHER_RANSOMWARE` —
the detector still gets to say "this is ransomware, family unclear" for those rows, which is
exactly what the binary detector already claims for them, so nothing already-claimed is lost, only
named as unresolvable at this sample size rather than silently mis-scored.

One-vs-rest is a stated design choice for `logistic_regression`, not a limitation
------------------------------------------------------------------------------------
scikit-learn's `LogisticRegression` supports a native multinomial objective; the M7-16 brief calls
for one-vs-rest specifically, so `build_multiclass_model` wraps it in `OneVsRestClassifier` rather
than passing `multi_class="multinomial"`. LR's per-class probabilities therefore come from
19 independent binary classifiers (one per surviving class, after the merge above), each answering
"is it *this* family versus everything else" — closer in spirit to how a real per-family dispatch
decision would be built incrementally than one shared softmax would be.

Per-family feature importance is its own small model, not a slice of the big one
------------------------------------------------------------------------------------
A fitted multi-class `RandomForestClassifier`'s `feature_importances_` is global — it does not
decompose by class. `per_family_feature_signal` fits a small, fast one-vs-rest binary forest
(`family` vs. everything else, size-capped) per large family instead, so "which features
distinguish CryptoLocker from the rest" is a real per-family measurement, not an approximation
read off the shared model.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Final

import numpy as np
from sklearn.base import BaseEstimator
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    top_k_accuracy_score,
)
from sklearn.multiclass import OneVsRestClassifier

from bsfr_sh.detection.dataset import BENIGN_LABEL
from bsfr_sh.detection.metrics import HonestMetrics, honest_metrics
from bsfr_sh.detection.models import MODEL_NAMES, ModelError, build_model
from bsfr_sh.util.config import Config

__all__ = [
    "LARGE_FAMILY_THRESHOLD",
    "MIN_FAMILY_SAMPLES",
    "OTHER_RANSOMWARE",
    "BinaryCollapse",
    "FamilyReport",
    "MulticlassFit",
    "binary_collapse",
    "build_multiclass_model",
    "build_multiclass_models",
    "class_distribution",
    "confusion",
    "fit_and_score_multiclass",
    "macro_f1",
    "merge_rare_families",
    "most_confused_with",
    "per_class_report",
    "per_family_feature_signal",
    "top_k_accuracy",
    "weighted_f1",
]

#: Below this many samples (whole dataset, not per fold), a family is folded into
#: `OTHER_RANSOMWARE` rather than scored on its own — see the module docstring.
MIN_FAMILY_SAMPLES: Final = 10
OTHER_RANSOMWARE: Final = "other_ransomware"
#: Threshold for the per-family deep-dive (feature signal). Every surviving family gets a row in
#: the confusion matrix and the per-class report regardless of size; only families at or above
#: this size get their own one-vs-rest importance fit (M7-16 brief step 4).
LARGE_FAMILY_THRESHOLD: Final = 100


def class_distribution(labels: np.ndarray) -> dict[str, int]:
    """Class sizes, largest first. Reported before any model runs (M7-16 brief step 1) — the
    imbalance is itself a finding, not a preamble to skip past."""
    values, counts = np.unique(labels, return_counts=True)
    order = np.argsort(counts)[::-1]
    return {str(values[i]): int(counts[i]) for i in order}


def merge_rare_families(
    labels: np.ndarray, *, min_count: int = MIN_FAMILY_SAMPLES, benign_label: str = BENIGN_LABEL
) -> tuple[np.ndarray, tuple[str, ...]]:
    """Fold every ransomware family below `min_count` into `OTHER_RANSOMWARE`.

    `benign_label` is never merged regardless of its count — it is not one of the rare ones on
    this dataset, but the rule should not depend on that happening to be true.

    Returns the merged label array and the names that were folded in, so a caller (and
    `tests/unit/test_detection_multiclass.py`) can check that only families below the threshold
    moved.
    """
    counts = class_distribution(labels)
    merged_names = tuple(
        name for name, count in counts.items() if name != benign_label and count < min_count
    )
    if not merged_names:
        return labels.copy(), merged_names
    # `dtype=object`, not `labels.copy()`: a fixed-width numpy string array (e.g. built from a
    # Python list via `np.array([...])`, as callers in a hurry and every test here do) sizes
    # itself to the *longest string present at construction* and silently truncates anything
    # wider assigned into it later — `OTHER_RANSOMWARE` (17 chars) would come back as `"other"`.
    # Object dtype has no such width to overflow.
    merged = labels.astype(object)
    merged[np.isin(merged, merged_names)] = OTHER_RANSOMWARE
    return merged, merged_names


@dataclass(frozen=True)
class MulticlassFit:
    """One model's fit/predict cycle over family labels, keeping what top-k accuracy needs."""

    name: str
    classes_: tuple[str, ...]
    predictions: np.ndarray
    #: `(n_test, len(classes_))`, aligned to `classes_` — `None` for a model with no
    #: `predict_proba` (none of the four declared models lack one, but the type stays honest).
    probabilities: np.ndarray | None
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


def build_multiclass_model(config: Config, name: str, *, seed: int) -> BaseEstimator:
    """RF/DT/KNN unchanged from `detection.models.build_model` — all three are natively
    multi-class. `logistic_regression` is wrapped in `OneVsRestClassifier`; see the module
    docstring for why that is a stated choice, not a fallback from a missing multinomial option.
    """
    if name == "logistic_regression":
        return OneVsRestClassifier(build_model(config, name, seed=seed))
    return build_model(config, name, seed=seed)


def build_multiclass_models(config: Config, *, seed: int) -> dict[str, BaseEstimator]:
    """Every enabled model (Table II's four, per `configs/ml.yaml`), multi-class variants."""
    models = config.require("models", dict)
    return {
        name: build_multiclass_model(config, name, seed=seed)
        for name in MODEL_NAMES
        if models.get(name, {}).get("enabled", True)
    }


def fit_and_score_multiclass(
    estimator: BaseEstimator,
    name: str,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_test: np.ndarray,
) -> MulticlassFit:
    """Fit, predict, and time the two halves separately — mirrors `detection.models.fit_and_score`
    but keeps the full probability matrix (for top-k) rather than collapsing to one score column.
    """
    started = time.perf_counter()
    estimator.fit(x_train, y_train)
    fit_seconds = time.perf_counter() - started

    started = time.perf_counter()
    predictions = estimator.predict(x_test)
    predict_seconds = time.perf_counter() - started

    classes_ = tuple(str(c) for c in getattr(estimator, "classes_", np.unique(y_train)))
    probabilities = None
    if hasattr(estimator, "predict_proba"):
        probabilities = np.asarray(estimator.predict_proba(x_test))

    return MulticlassFit(
        name=name,
        classes_=classes_,
        predictions=np.asarray(predictions),
        probabilities=probabilities,
        fit_seconds=fit_seconds,
        predict_seconds=predict_seconds,
        n_train=len(y_train),
        n_test=len(x_test),
    )


# --------------------------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------------------------
def macro_f1(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """Every family weighted equally regardless of size — the metric a rare family can move."""
    return float(f1_score(y_true, y_pred, average="macro", zero_division=0))


def weighted_f1(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """Families weighted by their own size — dominated by `white` and the largest families."""
    return float(f1_score(y_true, y_pred, average="weighted", zero_division=0))


def confusion(y_true: np.ndarray, y_pred: np.ndarray, labels: tuple[str, ...]) -> np.ndarray:
    return np.asarray(confusion_matrix(y_true, y_pred, labels=list(labels)))


def most_confused_with(matrix: np.ndarray, labels: tuple[str, ...]) -> dict[str, str | None]:
    """For each true class (row), the column with the largest off-diagonal count — what the model
    says instead when it is wrong. `None` when the row has no off-diagonal mass at all (perfect
    recall, or no test examples of that class)."""
    result: dict[str, str | None] = {}
    for i, label in enumerate(labels):
        row = matrix[i].copy()
        row[i] = 0
        result[label] = labels[int(np.argmax(row))] if row.sum() > 0 else None
    return result


@dataclass(frozen=True)
class FamilyReport:
    """Per-family precision/recall/support, plus what a wrong prediction was mistaken for."""

    precision: dict[str, float]
    recall: dict[str, float]
    support: dict[str, int]
    most_confused_with: dict[str, str | None]

    def as_dict(self) -> dict[str, object]:
        return {
            "precision": self.precision,
            "recall": self.recall,
            "support": self.support,
            "most_confused_with": self.most_confused_with,
        }


def per_class_report(
    y_true: np.ndarray, y_pred: np.ndarray, labels: tuple[str, ...]
) -> FamilyReport:
    precision, recall, _, support = precision_recall_fscore_support(
        y_true, y_pred, labels=list(labels), zero_division=0
    )
    matrix = confusion(y_true, y_pred, labels)
    return FamilyReport(
        precision=dict(zip(labels, (float(p) for p in precision), strict=True)),
        recall=dict(zip(labels, (float(r) for r in recall), strict=True)),
        support=dict(zip(labels, (int(s) for s in support), strict=True)),
        most_confused_with=most_confused_with(matrix, labels),
    )


def top_k_accuracy(
    y_true: np.ndarray, probabilities: np.ndarray | None, classes_: tuple[str, ...], *, k: int = 3
) -> float:
    """Is the correct family among the model's top `k` predictions, by probability."""
    if probabilities is None:
        raise ModelError("top_k_accuracy requires predict_proba output")
    return float(top_k_accuracy_score(y_true, probabilities, k=k, labels=list(classes_)))


@dataclass(frozen=True)
class BinaryCollapse:
    """The multi-class predictions collapsed to ransomware-vs-benign, scored the same way
    `detection.metrics.honest_metrics` scores the binary detector — directly comparable to the
    existing full-scale `honest_mode` numbers in `RESULTS.md` (M7-16 brief step 3)."""

    honest: HonestMetrics

    def as_dict(self) -> dict[str, object]:
        return self.honest.as_dict()


def binary_collapse(
    y_true_family: np.ndarray, y_pred_family: np.ndarray, *, benign_label: str = BENIGN_LABEL
) -> BinaryCollapse:
    """Collapse family predictions/labels to binary and score with `honest_metrics`.

    No score/probability column is passed through — `HonestMetrics.pr_auc` falls back to the
    binarized hard predictions in that case (`detection.metrics.honest_metrics`'s own fallback),
    which is the correct comparison here: the multi-class model was not asked to produce a binary
    score, only a family label, and PR-AUC should read what actually happened, not a re-derived
    one-vs-rest score that no caller has.
    """
    y_true_bin = (y_true_family != benign_label).astype(np.int8)
    y_pred_bin = (y_pred_family != benign_label).astype(np.int8)
    return BinaryCollapse(honest=honest_metrics(y_true_bin, y_pred_bin))


def per_family_feature_signal(
    x: np.ndarray,
    y: np.ndarray,
    feature_names: tuple[str, ...],
    family: str,
    *,
    seed: int,
    max_rows: int = 20_000,
    n_estimators: int = 50,
) -> dict[str, float]:
    """Feature importance for telling `family` apart from every other row (benign and every other
    family alike) — a small one-vs-rest `RandomForestClassifier`, not a slice of the shared
    multi-class model (whose `feature_importances_` is global and does not decompose by class).

    Sized down deliberately: `max_rows`/`n_estimators` are far below the production `random_forest`
    config, because this fits once per large family (M7-16 brief step 4) and ranking 8 features
    does not need a 2.9M-row forest — a fast, size-capped, class-balanced fit answers "which
    features distinguish this family" without repeating the full training cost per family.
    """
    rng = np.random.default_rng(seed)
    is_family = y == family
    n_family = int(is_family.sum())
    if n_family < 2:
        raise ModelError(f"{family!r} has {n_family} rows; per_family_feature_signal needs >= 2")
    family_idx = np.flatnonzero(is_family)
    other_idx = np.flatnonzero(~is_family)
    take_family = min(n_family, max_rows // 2)
    take_other = min(len(other_idx), max_rows - take_family)
    chosen = np.concatenate(
        [
            rng.choice(family_idx, size=take_family, replace=False),
            rng.choice(other_idx, size=take_other, replace=False),
        ]
    )
    model = RandomForestClassifier(n_estimators=n_estimators, random_state=seed, n_jobs=-1)
    model.fit(x[chosen], is_family[chosen].astype(np.int8))
    return dict(zip(feature_names, (float(v) for v in model.feature_importances_), strict=True))
