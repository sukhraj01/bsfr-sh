"""`detection.dataset`: the loader, the §VII anchor, and both modes' splits. Target 2, DEV-06.

Most of these run on a synthetic frame with BitcoinHeist's schema, so the pipeline is testable on
a machine that has not fetched 2.9M rows. The one test that needs the real file skips when it is
absent and asserts §VII's exact counts when it is present.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from bsfr_sh.detection.dataset import (
    DROPPED_COLUMNS,
    EXPECTED_RANSOMWARE,
    EXPECTED_ROWS,
    EXPECTED_WHITE,
    DatasetError,
    DatasetSpec,
    class_rate,
    load_bitcoinheist,
    paper_mode_arithmetic,
    paper_mode_resample,
    stratified_folds,
    stratified_holdout,
    verify_counts,
)

FAMILIES = ("montrealCryptoLocker", "princetonCerber", "paduaCryptoWall")


def _write_csv(path, *, n_benign: int, n_ransom: int, seed: int = 0):
    """A frame with BitcoinHeist's ten columns, `address` included so dropping it is observable."""
    rng = np.random.default_rng(seed)
    total = n_benign + n_ransom
    frame = pd.DataFrame(
        {
            "address": [f"addr{i:07d}" for i in range(total)],
            "year": rng.integers(2011, 2019, total).astype("int16"),
            "day": rng.integers(1, 366, total).astype("int16"),
            "length": rng.integers(0, 144, total).astype("int32"),
            "weight": rng.random(total).astype("float32"),
            "count": rng.integers(1, 1000, total).astype("int32"),
            "looped": rng.integers(0, 100, total).astype("int32"),
            "neighbors": rng.integers(1, 20, total).astype("int32"),
            "income": rng.random(total) * 1e10,
            "label": ["white"] * n_benign + [FAMILIES[i % len(FAMILIES)] for i in range(n_ransom)],
        }
    )
    frame.to_csv(path, index=False)
    return path


def _spec(path, **overrides) -> DatasetSpec:
    return DatasetSpec(path=path, **overrides)


# -- the §VII anchor ---------------------------------------------------------------------------
def test_the_paper_counts_are_the_anchor() -> None:
    verify_counts(EXPECTED_ROWS, EXPECTED_RANSOMWARE, EXPECTED_WHITE)


@pytest.mark.parametrize(
    ("rows", "positive", "negative"),
    [
        (EXPECTED_ROWS - 1, EXPECTED_RANSOMWARE, EXPECTED_WHITE),
        (EXPECTED_ROWS, EXPECTED_RANSOMWARE + 1, EXPECTED_WHITE),
        (EXPECTED_ROWS, EXPECTED_RANSOMWARE, EXPECTED_WHITE - 1),
    ],
)
def test_counts_that_are_not_the_papers_stop_the_run(rows, positive, negative) -> None:
    with pytest.raises(DatasetError, match="do not match the paper"):
        verify_counts(rows, positive, negative)


def test_a_missing_dataset_says_how_to_get_it(tmp_path) -> None:
    with pytest.raises(DatasetError, match="make data"):
        load_bitcoinheist(_spec(tmp_path / "nope.csv"))


# -- loading -----------------------------------------------------------------------------------
def test_address_never_reaches_the_feature_matrix(tmp_path) -> None:
    """It is an identifier: a model that sees it memorises labels instead of learning."""
    path = _write_csv(tmp_path / "bh.csv", n_benign=500, n_ransom=20)
    data = load_bitcoinheist(_spec(path), verify=False)
    assert "address" not in data.columns
    for dropped in DROPPED_COLUMNS:
        assert dropped not in data.columns
    assert data.columns == (
        "year",
        "day",
        "length",
        "weight",
        "count",
        "looped",
        "neighbors",
        "income",
    )


def test_the_label_becomes_binary_and_families_are_counted(tmp_path) -> None:
    path = _write_csv(tmp_path / "bh.csv", n_benign=500, n_ransom=30)
    data = load_bitcoinheist(_spec(path), verify=False)
    assert set(np.unique(data.labels)) <= {0, 1}
    assert (data.n_positive, data.n_negative, data.n_rows) == (30, 500, 530)
    assert data.families == len(FAMILIES)
    assert data.positive_rate == pytest.approx(30 / 530)


def test_a_synthetic_file_is_refused_when_verification_is_on(tmp_path) -> None:
    path = _write_csv(tmp_path / "bh.csv", n_benign=50, n_ransom=5)
    with pytest.raises(DatasetError, match="do not match the paper"):
        load_bitcoinheist(_spec(path), verify=True)


def test_subsampling_keeps_the_class_rate_and_is_marked(tmp_path) -> None:
    path = _write_csv(tmp_path / "bh.csv", n_benign=2000, n_ransom=200)
    data = load_bitcoinheist(_spec(path, subsample_rows=500), verify=False, seed=7)
    assert data.n_rows == 500
    assert data.positive_rate == pytest.approx(200 / 2200, abs=0.02)
    assert not data.matches_paper_counts


# -- paper_mode --------------------------------------------------------------------------------
def test_the_resample_is_bounded_by_the_positives_that_exist() -> None:
    """41,413 positives at 90% is ~46K rows, not 2.9M. The paper never says so."""
    n_total, n_pos, n_neg = paper_mode_arithmetic(EXPECTED_RANSOMWARE, 0.90)
    assert (n_pos, n_neg, n_total) == (41_413, 4_601, 46_014)
    assert n_total / EXPECTED_ROWS < 0.016


@pytest.mark.parametrize("fraction", [0.5, 0.75, 0.9])
def test_the_resample_hits_its_ratio(fraction) -> None:
    n_total, n_pos, _ = paper_mode_arithmetic(1000, fraction)
    assert n_pos / n_total == pytest.approx(fraction, abs=0.001)


@pytest.mark.parametrize("fraction", [0.0, 1.0, -0.1, 1.5])
def test_an_impossible_ratio_is_refused(fraction) -> None:
    with pytest.raises(DatasetError):
        paper_mode_arithmetic(1000, fraction)


def test_resampling_produces_the_n_the_arithmetic_predicts(tmp_path) -> None:
    path = _write_csv(tmp_path / "bh.csv", n_benign=5000, n_ransom=300)
    data = load_bitcoinheist(_spec(path), verify=False)
    expected = paper_mode_arithmetic(data.n_positive, 0.90)
    resample = paper_mode_resample(data, positive_fraction=0.90, seed=1)
    assert (resample.n_rows, resample.n_positive, resample.n_negative) == expected
    assert len(resample.labels) == resample.n_rows
    assert class_rate(resample.labels) == pytest.approx(0.90, abs=0.001)
    assert resample.drawn_from == data.n_rows


def test_the_resample_uses_every_positive_row(tmp_path) -> None:
    path = _write_csv(tmp_path / "bh.csv", n_benign=5000, n_ransom=300)
    data = load_bitcoinheist(_spec(path), verify=False)
    resample = paper_mode_resample(data, seed=2)
    assert int(resample.labels.sum()) == data.n_positive


# -- splits ------------------------------------------------------------------------------------
def test_train_and_test_never_share_a_row() -> None:
    labels = np.array([0] * 900 + [1] * 100, dtype=np.int8)
    train, test = stratified_holdout(labels, test_size=0.3, seed=3)
    assert not set(train) & set(test)
    assert len(train) + len(test) == len(labels)


def test_the_holdout_preserves_the_class_rate() -> None:
    labels = np.array([0] * 900 + [1] * 100, dtype=np.int8)
    train, test = stratified_holdout(labels, test_size=0.3, seed=3)
    assert class_rate(labels[test]) == pytest.approx(0.10, abs=0.01)
    assert class_rate(labels[train]) == pytest.approx(0.10, abs=0.01)


def test_every_fold_holds_the_class_rate_and_is_disjoint_from_its_training_half() -> None:
    labels = np.array([0] * 986 + [1] * 14, dtype=np.int8)  # ~1.4%, the natural rate
    folds = list(stratified_folds(labels, folds=5, seed=4))
    assert len(folds) == 5
    seen: set[int] = set()
    for train, test in folds:
        assert not set(train) & set(test)
        assert len(train) + len(test) == len(labels)
        assert class_rate(labels[test]) == pytest.approx(0.014, abs=0.006)
        seen |= set(test)
    assert seen == set(range(len(labels))), "every row is tested exactly once"


def test_too_few_folds_is_refused() -> None:
    with pytest.raises(DatasetError, match="folds"):
        list(stratified_folds(np.array([0, 1, 0, 1]), folds=1, seed=0))


# -- the real file, when it is here ------------------------------------------------------------
def test_the_real_dataset_matches_the_paper_exactly() -> None:
    """Skips when `make data` has not been run; asserts §VII's counts when it has."""
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "data" / "raw" / "BitcoinHeistData.csv"
    if not path.exists():
        pytest.skip("data/raw/BitcoinHeistData.csv absent; run `make data`")
    data = load_bitcoinheist(_spec(path), verify=True)
    assert (data.n_rows, data.n_negative, data.n_positive) == (
        EXPECTED_ROWS,
        EXPECTED_WHITE,
        EXPECTED_RANSOMWARE,
    )
    assert data.matches_paper_counts
    assert "address" not in data.columns
