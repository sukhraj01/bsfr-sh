"""Both metric sets, and the baselines that make them readable. DEV-06.

The paper reports accuracy and F1 on a split it resampled to 90% ransomware. On that split a
classifier that answers "ransomware" to everything scores **0.900 accuracy and 0.947 F1** without
looking at the data. So accuracy and F1 alone cannot distinguish a detector from a constant, and
any reproduction that prints them without the baseline beside them is misleading — which is why
`baselines()` is computed *before* any model is fitted and travels with every result.

`honest_mode` inverts the trap. At the natural 1.42% positive rate, a classifier that never
predicts ransomware scores ≈98.58% accuracy — higher than the paper's headline 98.98% is
impressive-sounding — while finding nothing at all. There, accuracy is not reported: precision,
recall, PR-AUC, MCC and the minority-class F1 are, because those are the ones that move when the
minority class is actually found.

Everything in here is a pure function of `(y_true, y_pred)` (plus scores for PR-AUC), so the
numbers are reproducible from the arrays alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
)

__all__ = [
    "BaselineSet",
    "HonestMetrics",
    "PaperMetrics",
    "analytic_constant_positive",
    "baselines",
    "honest_metrics",
    "paper_metrics",
]


@dataclass(frozen=True)
class PaperMetrics:
    """What Table II reports: accuracy and F1, nothing else."""

    accuracy: float
    f1: float

    def as_dict(self) -> dict[str, float]:
        return {"accuracy": self.accuracy, "f1": self.f1}


@dataclass(frozen=True)
class HonestMetrics:
    """What the natural class balance requires (DEV-06). Accuracy is deliberately absent."""

    precision: float
    recall: float
    pr_auc: float
    mcc: float
    f1_minority: float
    confusion: tuple[int, int, int, int]  # tn, fp, fn, tp
    #: Reported only to sit beside the others as the number that looks good and means nothing.
    accuracy_for_contrast: float

    def as_dict(self) -> dict[str, object]:
        tn, fp, fn, tp = self.confusion
        return {
            "precision": self.precision,
            "recall": self.recall,
            "pr_auc": self.pr_auc,
            "mcc": self.mcc,
            "f1_minority": self.f1_minority,
            "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            "accuracy_for_contrast": self.accuracy_for_contrast,
        }


def paper_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> PaperMetrics:
    """Accuracy and F1 exactly as Table II reports them."""
    return PaperMetrics(
        accuracy=float(accuracy_score(y_true, y_pred)),
        f1=float(f1_score(y_true, y_pred, zero_division=0)),
    )


def honest_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray | None = None
) -> HonestMetrics:
    """The minority-aware set. `y_score` enables PR-AUC; without it it falls back to `y_pred`."""
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in matrix.ravel())
    scores = y_pred if y_score is None else y_score
    return HonestMetrics(
        precision=float(precision_score(y_true, y_pred, zero_division=0)),
        recall=float(recall_score(y_true, y_pred, zero_division=0)),
        pr_auc=float(average_precision_score(y_true, scores))
        if len(np.unique(y_true)) > 1
        else 0.0,
        mcc=float(matthews_corrcoef(y_true, y_pred)) if len(np.unique(y_pred)) > 1 else 0.0,
        f1_minority=float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        confusion=(tn, fp, fn, tp),
        accuracy_for_contrast=float(accuracy_score(y_true, y_pred)),
    )


# --------------------------------------------------------------------------------------------
# Baselines — computed before any model is fitted
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class BaselineSet:
    """Three classifiers that look at nothing, scored the same way the models are."""

    constant_positive: PaperMetrics
    constant_negative: PaperMetrics
    stratified_random: PaperMetrics
    constant_positive_honest: HonestMetrics = field(repr=False)
    constant_negative_honest: HonestMetrics = field(repr=False)
    stratified_random_honest: HonestMetrics = field(repr=False)

    def as_dict(self) -> dict[str, object]:
        return {
            "constant_positive": {
                **self.constant_positive.as_dict(),
                **self.constant_positive_honest.as_dict(),
            },
            "constant_negative": {
                **self.constant_negative.as_dict(),
                **self.constant_negative_honest.as_dict(),
            },
            "stratified_random": {
                **self.stratified_random.as_dict(),
                **self.stratified_random_honest.as_dict(),
            },
        }


def analytic_constant_positive(positive_fraction: float) -> tuple[float, float]:
    """Accuracy and F1 of "everything is ransomware", from the class balance alone.

    Accuracy is the positive share `p`; precision is `p`, recall is 1, so `F1 = 2p / (1 + p)`.
    At the paper's `p = 0.9`: 0.900 and 0.947. This is the number Table II has to beat before it
    means anything, and it needs no data to compute.
    """
    if not 0.0 <= positive_fraction <= 1.0:
        raise ValueError(f"positive_fraction must be in [0, 1], got {positive_fraction}")
    f1 = 2 * positive_fraction / (1 + positive_fraction) if positive_fraction else 0.0
    return positive_fraction, f1


def baselines(y_true: np.ndarray, *, seed: int = 0) -> BaselineSet:
    """Score the three no-information classifiers on the same labels the models will face."""
    rng = np.random.default_rng(seed)
    positives = np.ones_like(y_true)
    negatives = np.zeros_like(y_true)
    rate = float(np.asarray(y_true).mean())
    random = (rng.random(len(y_true)) < rate).astype(y_true.dtype)
    return BaselineSet(
        constant_positive=paper_metrics(y_true, positives),
        constant_negative=paper_metrics(y_true, negatives),
        stratified_random=paper_metrics(y_true, random),
        constant_positive_honest=honest_metrics(y_true, positives),
        constant_negative_honest=honest_metrics(y_true, negatives),
        stratified_random_honest=honest_metrics(y_true, random),
    )
