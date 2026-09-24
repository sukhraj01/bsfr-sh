"""M7-6: pure logic for the three untested Q10 gap-closure hypotheses. DEV-06 follow-up.

Q10 (`docs/DEVIATIONS.md` DEV-06) tested two leakage candidates -- `address` kept as a feature,
and a non-grouped split -- and found the best of the resulting four cells (0.9540, random forest,
address kept x random split) still 3.58 accuracy points under the published 0.9898. The report's
FLAW-4 called the residual gap "unexplained" after testing only two of at least five testable
candidates. This module holds the pure, testable logic for three more: an undisclosed
decision-tree configuration (H1), an undisclosed resample strategy (H2), and undisclosed feature
handling of `year`/`day` (H4). `scripts/m7_6_gap_closure.py` is the thin orchestrator that loads
data, calls these functions, fits models via `detection.models`, and writes `RESULTS.md` lines
plus a sidecar per hypothesis. H3 (single-split variance vs. cross-validation) and H5 (the
stacked worst case) need no new pure logic beyond what is here and in `detection.dataset` -- they
compose these pieces at run time.
"""

from __future__ import annotations

from typing import Final

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier

from bsfr_sh.detection.dataset import DatasetError, LoadedDataset, Resample

__all__ = [
    "DAY_PERIOD",
    "DECISION_TREE_CRITERIA",
    "FEATURE_VARIANTS",
    "build_decision_tree_variant",
    "engineer_features",
    "grouped_stratified_kfold",
    "oversample_resample",
    "undersample_resample",
]

#: H1 -- the paper says "decision tree" and nothing else. scikit-learn's own defaults
#: (`max_depth=None, min_samples_split=2, min_samples_leaf=1`) already grow the tree fully, so
#: the "explicit fully grown" cell is the identical estimator to the "default" cell for a given
#: criterion. `build_decision_tree_variant` only varies `criterion`; the identity is asserted in
#: `tests/unit/test_detection_gap_closure.py`, not assumed.
DECISION_TREE_CRITERIA: Final = ("gini", "entropy")

FEATURE_VARIANTS: Final = ("raw", "year_dropped", "day_cyclical", "year_day_interaction")

#: BitcoinHeist's `day` is day-of-year (1-365, 366 in a leap year); 365.25 averages both.
DAY_PERIOD: Final = 365.25


def build_decision_tree_variant(criterion: str, *, seed: int) -> DecisionTreeClassifier:
    """One H1 cell's estimator. Every hyperparameter besides `criterion` stays at scikit-learn's
    default, which is already fully grown -- see the module docstring."""
    if criterion not in DECISION_TREE_CRITERIA:
        raise DatasetError(f"criterion must be one of {DECISION_TREE_CRITERIA}, got {criterion!r}")
    return DecisionTreeClassifier(criterion=criterion, random_state=seed)


def oversample_resample(
    data: LoadedDataset, *, total: int, positive_fraction: float, seed: int
) -> Resample:
    """H2(b): duplicate ransomware rows (bootstrap, with replacement) up to `positive_fraction`
    of `total`; subsample benign rows down to the remainder, without replacement.

    `total` is a free parameter the paper never states. Unlike `paper_mode_resample`, whose size
    is bounded at ~46,014 rows by the 41,413 real ransomware rows that exist, oversampling has no
    such ceiling -- `total` is chosen by the caller to be larger than that bound, so the resulting
    resample is a genuinely different experiment, not a rounding variant of the same one.
    """
    if not 0.0 < positive_fraction < 1.0:
        raise DatasetError(f"positive_fraction must be in (0, 1), got {positive_fraction}")
    n_pos = round(total * positive_fraction)
    n_neg = total - n_pos
    if n_neg > data.n_negative:
        raise DatasetError(
            f"oversample needs {n_neg} benign rows without replacement, "
            f"only {data.n_negative} exist"
        )
    rng = np.random.default_rng(seed)
    positive_pool = np.flatnonzero(data.labels == 1)
    negative_pool = np.flatnonzero(data.labels == 0)
    pos_index = rng.choice(positive_pool, size=n_pos, replace=True)
    neg_index = rng.choice(negative_pool, size=n_neg, replace=False)
    index = np.concatenate([pos_index, neg_index])
    return Resample(
        features=data.features.iloc[index].reset_index(drop=True),
        labels=data.labels[index],
        n_rows=total,
        n_positive=n_pos,
        n_negative=n_neg,
        positive_fraction=positive_fraction,
        drawn_from=data.n_rows,
        groups=data.groups[index] if data.groups is not None else None,
    )


def undersample_resample(
    data: LoadedDataset, *, benign_fraction_of_positive: float, seed: int
) -> Resample:
    """H2(c): keep every ransomware row (as `paper_mode_resample` does), but size the benign
    class as a fraction *of the ransomware count* rather than of the resample total -- a second
    reading of "10% benign" the paper's silence does not rule out. At 0.10 this yields a smaller
    resample than `paper_mode_resample`'s 46,014 rows (45,554 at the full dataset's 41,413
    positives): `paper_mode_resample` sizes benign to 10% of the *output* total, this sizes it to
    10% of the *positive count* directly, and the two are not the same arithmetic.
    """
    if not 0.0 < benign_fraction_of_positive < 1.0:
        raise DatasetError(
            f"benign_fraction_of_positive must be in (0, 1), got {benign_fraction_of_positive}"
        )
    n_pos = data.n_positive
    n_neg = round(n_pos * benign_fraction_of_positive)
    if n_neg > data.n_negative:
        raise DatasetError(f"need {n_neg} benign rows, only {data.n_negative} exist")
    rng = np.random.default_rng(seed)
    positive_index = np.flatnonzero(data.labels == 1)
    negative_index = rng.choice(np.flatnonzero(data.labels == 0), size=n_neg, replace=False)
    index = np.sort(np.concatenate([positive_index, negative_index]))
    return Resample(
        features=data.features.iloc[index].reset_index(drop=True),
        labels=data.labels[index],
        n_rows=n_pos + n_neg,
        n_positive=n_pos,
        n_negative=n_neg,
        positive_fraction=n_pos / (n_pos + n_neg),
        drawn_from=data.n_rows,
        groups=data.groups[index] if data.groups is not None else None,
    )


def engineer_features(features: pd.DataFrame, variant: str) -> pd.DataFrame:
    """H4: four readings of how `year`/`day` might have been fed to the paper's models.

    Pure and row-order-preserving: row count, row order, and every column besides `year`/`day`
    are untouched, so calling this after a resample/split never moves a row's class or its side
    of a train/test boundary (`test_detection_gap_closure.py::test_engineer_features_*`).
    """
    if variant not in FEATURE_VARIANTS:
        raise DatasetError(f"variant must be one of {FEATURE_VARIANTS}, got {variant!r}")
    if "year" not in features.columns or "day" not in features.columns:
        raise DatasetError("engineer_features requires 'year' and 'day' columns")
    out = features.copy()
    if variant == "raw":
        return out
    if variant == "year_dropped":
        return out.drop(columns=["year"])
    if variant == "day_cyclical":
        angle = 2 * np.pi * out["day"].to_numpy(dtype=np.float64) / DAY_PERIOD
        out = out.drop(columns=["day"])
        out["day_sin"] = np.sin(angle)
        out["day_cos"] = np.cos(angle)
        return out
    # year_day_interaction: added alongside the raw columns, not in place of them.
    out["year_day_interaction"] = out["year"].to_numpy(dtype=np.float64) * out["day"].to_numpy(
        dtype=np.float64
    )
    return out


def grouped_stratified_kfold(
    labels: np.ndarray, groups: np.ndarray, *, folds: int, seed: int
) -> list[tuple[np.ndarray, np.ndarray]]:
    """H3(b): `folds`-fold CV that keeps one address's rows on one side of every fold, the same
    rationale as `detection.dataset.grouped_stratified_holdout` (Q10) applied to k-fold instead of
    a single holdout. Wraps `sklearn.model_selection.StratifiedGroupKFold` rather than
    reimplementing it -- unlike the single-holdout case, k-fold group-balancing has no simple
    closed form worth owning, and scikit-learn's own version is already tested.
    """
    if folds < 2:
        raise DatasetError(f"folds must be at least 2, got {folds}")
    splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)
    return list(splitter.split(np.zeros(len(labels)), labels, groups))
