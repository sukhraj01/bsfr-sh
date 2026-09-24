"""`detection.gap_closure`: the pure logic behind M7-6's three new Q10 gap-closure hypotheses.

Synthetic `LoadedDataset`s throughout -- these functions never touch the CSV, so none of this
needs `make data`.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from bsfr_sh.detection.dataset import DatasetError, LoadedDataset
from bsfr_sh.detection.gap_closure import (
    DECISION_TREE_CRITERIA,
    FEATURE_VARIANTS,
    build_decision_tree_variant,
    engineer_features,
    grouped_stratified_kfold,
    oversample_resample,
    undersample_resample,
)


def _loaded(*, n_pos: int, n_neg: int, seed: int = 0, with_groups: bool = True) -> LoadedDataset:
    rng = np.random.default_rng(seed)
    total = n_pos + n_neg
    labels = np.array([1] * n_pos + [0] * n_neg, dtype=np.int8)
    order = rng.permutation(total)
    labels = labels[order]
    features = pd.DataFrame(
        {
            "year": rng.integers(2011, 2019, total).astype("int16"),
            "day": rng.integers(1, 366, total).astype("int16"),
            "length": rng.integers(0, 144, total).astype("int32"),
        }
    )
    groups = None
    if with_groups:
        # A handful of addresses, each repeated a few times, so grouping is observable.
        n_groups = max(2, total // 4)
        groups = rng.integers(0, n_groups, total).astype(np.int64)
    return LoadedDataset(
        features=features,
        labels=labels,
        source=Path(__file__),
        n_rows=total,
        n_positive=n_pos,
        n_negative=n_neg,
        matches_paper_counts=False,
        families=1,
        groups=groups,
    )


# -- H2: resample strategies --------------------------------------------------------------------
def test_oversample_resample_arithmetic_and_duplication() -> None:
    data = _loaded(n_pos=100, n_neg=5000)
    resample = oversample_resample(data, total=2000, positive_fraction=0.9, seed=1)
    assert resample.n_rows == 2000
    assert resample.n_positive == 1800
    assert resample.n_negative == 200
    assert len(resample.labels) == 2000
    assert int(resample.labels.sum()) == 1800
    # Only 100 unique positives exist; reaching 1800 requires duplication.
    assert resample.groups is not None
    n_unique_groups_among_positive = len(set(resample.groups[resample.labels == 1]))
    assert n_unique_groups_among_positive <= 100


def test_oversample_resample_rejects_infeasible_benign_count() -> None:
    data = _loaded(n_pos=100, n_neg=10)
    with pytest.raises(DatasetError, match="only 10 exist"):
        oversample_resample(data, total=2000, positive_fraction=0.5, seed=1)


def test_undersample_resample_arithmetic_keeps_every_positive() -> None:
    data = _loaded(n_pos=41413, n_neg=200000, with_groups=False)
    resample = undersample_resample(data, benign_fraction_of_positive=0.10, seed=2)
    assert resample.n_positive == 41413
    assert resample.n_negative == round(41413 * 0.10) == 4141
    assert resample.n_rows == 41413 + 4141
    assert int(resample.labels.sum()) == 41413
    assert len(resample.labels) == resample.n_rows


def test_undersample_resample_differs_from_paper_mode_arithmetic() -> None:
    # paper_mode_resample sizes benign at 10% of the OUTPUT total; undersample_resample sizes it
    # at 10% of the POSITIVE count. For 41,413 positives these are 4,601 vs 4,141 -- not equal.
    data = _loaded(n_pos=41413, n_neg=200000, with_groups=False)
    resample = undersample_resample(data, benign_fraction_of_positive=0.10, seed=2)
    paper_mode_style_negative = round(41413 * (1 - 0.90) / 0.90)
    assert resample.n_negative != paper_mode_style_negative


# -- H1: decision tree variants ------------------------------------------------------------------
def test_decision_tree_variants_are_fully_grown_by_construction() -> None:
    for criterion in DECISION_TREE_CRITERIA:
        estimator = build_decision_tree_variant(criterion, seed=7)
        params = estimator.get_params()
        assert params["criterion"] == criterion
        assert params["max_depth"] is None
        assert params["min_samples_split"] == 2
        assert params["min_samples_leaf"] == 1


def test_decision_tree_variant_rejects_unknown_criterion() -> None:
    with pytest.raises(DatasetError, match="criterion must be one of"):
        build_decision_tree_variant("chi2", seed=7)


# -- H4: feature engineering ----------------------------------------------------------------------
def _features() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "year": [2014, 2015, 2016],
            "day": [1, 180, 365],
            "length": [10, 20, 30],
        }
    )


@pytest.mark.parametrize("variant", FEATURE_VARIANTS)
def test_engineer_features_preserves_row_count_and_order(variant: str) -> None:
    features = _features()
    out = engineer_features(features, variant)
    assert len(out) == len(features)
    assert list(out["length"]) == list(features["length"])  # untouched column, same order


def test_engineer_features_year_dropped_removes_only_year() -> None:
    out = engineer_features(_features(), "year_dropped")
    assert "year" not in out.columns
    assert "day" in out.columns


def test_engineer_features_day_cyclical_is_bounded_and_drops_raw_day() -> None:
    out = engineer_features(_features(), "day_cyclical")
    assert "day" not in out.columns
    assert "year" in out.columns
    assert out["day_sin"].between(-1.0, 1.0).all()
    assert out["day_cos"].between(-1.0, 1.0).all()


def test_engineer_features_year_day_interaction_matches_manual_product() -> None:
    features = _features()
    out = engineer_features(features, "year_day_interaction")
    expected = features["year"].to_numpy() * features["day"].to_numpy()
    assert list(out["year_day_interaction"]) == list(expected.astype(float))
    assert "year" in out.columns and "day" in out.columns  # additive, not a replacement


def test_engineer_features_unknown_variant_raises() -> None:
    with pytest.raises(DatasetError, match="variant must be one of"):
        engineer_features(_features(), "bogus")


def test_engineer_features_requires_year_and_day_columns() -> None:
    with pytest.raises(DatasetError, match="requires 'year' and 'day'"):
        engineer_features(pd.DataFrame({"length": [1, 2, 3]}), "raw")


# -- H3(b): grouped stratified k-fold --------------------------------------------------------------
def test_grouped_stratified_kfold_is_disjoint_and_group_pure() -> None:
    data = _loaded(n_pos=200, n_neg=800, seed=3)
    folds = grouped_stratified_kfold(data.labels, data.groups, folds=5, seed=3)
    assert len(folds) == 5
    seen_test_rows: set[int] = set()
    for train_idx, test_idx in folds:
        assert not (set(train_idx.tolist()) & set(test_idx.tolist()))
        # Every group in the test fold is entirely absent from the train fold.
        test_groups = set(data.groups[test_idx].tolist())
        train_groups = set(data.groups[train_idx].tolist())
        assert not (test_groups & train_groups)
        seen_test_rows.update(test_idx.tolist())
    # Every row appears in exactly one test fold across the 5 folds.
    assert seen_test_rows == set(range(data.n_rows))


def test_grouped_stratified_kfold_rejects_too_few_folds() -> None:
    data = _loaded(n_pos=10, n_neg=10, seed=4)
    with pytest.raises(DatasetError, match="folds must be at least 2"):
        grouped_stratified_kfold(data.labels, data.groups, folds=1, seed=4)
