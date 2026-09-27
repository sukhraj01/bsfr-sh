"""`detection.multiclass` — rare-family merging, multi-class models, and multi-class metrics.
M7-16.

Most tests run on synthetic data so the pipeline is testable without the real 2.9M-row file. The
tests that need the real file skip when it is absent and check the M7-16 brief's own invariants
against it when present: no family with >=10 samples merged away, `other_ransomware` holds only
families under the threshold, and the grouped split keeps every address on one side.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from pbft_harness import REPO_ROOT
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier

from bsfr_sh.detection.dataset import (
    DatasetSpec,
    grouped_stratified_holdout,
    load_bitcoinheist_families,
)
from bsfr_sh.detection.models import ModelError
from bsfr_sh.detection.multiclass import (
    MIN_FAMILY_SAMPLES,
    OTHER_RANSOMWARE,
    binary_collapse,
    build_multiclass_model,
    class_distribution,
    confusion,
    fit_and_score_multiclass,
    macro_f1,
    merge_rare_families,
    most_confused_with,
    per_class_report,
    per_family_feature_signal,
    top_k_accuracy,
    weighted_f1,
)
from bsfr_sh.util.config import load_config

CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")


def _config():
    return CONFIG


def _write_family_csv(path, *, per_family: dict[str, int], seed: int = 0):
    """A frame with BitcoinHeist's ten columns and an arbitrary family-size mix, one address per
    row so `grouped_stratified_holdout` has something to group."""
    rng = np.random.default_rng(seed)
    labels: list[str] = []
    for family, count in per_family.items():
        labels.extend([family] * count)
    total = len(labels)
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
            "label": labels,
        }
    )
    frame.to_csv(path, index=False)
    return path


# --------------------------------------------------------------------------------------------
# class_distribution / merge_rare_families
# --------------------------------------------------------------------------------------------
def test_class_distribution_is_sorted_largest_first() -> None:
    labels = np.array(["white"] * 10 + ["a"] * 3 + ["b"] * 5)
    dist = class_distribution(labels)
    assert list(dist.items()) == [("white", 10), ("b", 5), ("a", 3)]


def test_merge_rare_families_folds_only_families_under_the_threshold() -> None:
    labels = np.array(["white"] * 100 + ["big"] * 20 + ["small"] * 3 + ["tiny"] * 1)
    merged, merged_names = merge_rare_families(labels, min_count=10)
    assert set(merged_names) == {"small", "tiny"}
    assert "small" not in merged
    assert "tiny" not in merged
    assert (merged == "big").sum() == 20
    assert (merged == OTHER_RANSOMWARE).sum() == 4
    assert (merged == "white").sum() == 100


def test_merge_rare_families_never_merges_benign_even_if_rare() -> None:
    labels = np.array(["white"] * 3 + ["big"] * 20)
    merged, merged_names = merge_rare_families(labels, min_count=10, benign_label="white")
    assert "white" not in merged_names
    assert (merged == "white").sum() == 3


def test_merge_rare_families_is_a_noop_when_nothing_is_rare() -> None:
    labels = np.array(["white"] * 50 + ["a"] * 20 + ["b"] * 15)
    merged, merged_names = merge_rare_families(labels, min_count=10)
    assert merged_names == ()
    assert np.array_equal(merged, labels)


# --------------------------------------------------------------------------------------------
# models
# --------------------------------------------------------------------------------------------
def test_logistic_regression_is_wrapped_one_vs_rest() -> None:
    model = build_multiclass_model(_config(), "logistic_regression", seed=0)
    assert isinstance(model, OneVsRestClassifier)
    assert isinstance(model.estimator, LogisticRegression)


@pytest.mark.parametrize("name", ["random_forest", "decision_tree", "k_nearest_neighbours"])
def test_natively_multiclass_models_are_not_wrapped(name) -> None:
    model = build_multiclass_model(_config(), name, seed=0)
    assert not isinstance(model, OneVsRestClassifier)


def _toy_multiclass_data(seed: int = 0):
    rng = np.random.default_rng(seed)
    classes = np.array(["white", "fam_a", "fam_b"])
    n_per_class = 60
    x = np.concatenate(
        [rng.normal(loc=i * 5.0, scale=0.5, size=(n_per_class, 4)) for i in range(len(classes))]
    )
    y = np.concatenate([[c] * n_per_class for c in classes])
    shuffle = rng.permutation(len(y))
    return x[shuffle], y[shuffle]


def test_fit_and_score_multiclass_reports_classes_and_probabilities() -> None:
    x, y = _toy_multiclass_data()
    x_train, x_test = x[:120], x[120:]
    y_train, y_test = y[:120], y[120:]
    model = build_multiclass_model(_config(), "random_forest", seed=0)
    fitted = fit_and_score_multiclass(model, "random_forest", x_train, y_train, x_test)
    assert set(fitted.classes_) == {"white", "fam_a", "fam_b"}
    assert fitted.probabilities is not None
    assert fitted.probabilities.shape == (len(y_test), 3)
    # well-separated clusters: a 10-tree forest should recover the true family for nearly all rows
    accuracy = (fitted.predictions == y_test).mean()
    assert accuracy > 0.9


def test_top_k_accuracy_is_at_least_top_1_accuracy() -> None:
    x, y = _toy_multiclass_data()
    model = build_multiclass_model(_config(), "random_forest", seed=0)
    fitted = fit_and_score_multiclass(model, "random_forest", x, y, x)
    top1 = top_k_accuracy(y, fitted.probabilities, fitted.classes_, k=1)
    top2 = top_k_accuracy(y, fitted.probabilities, fitted.classes_, k=2)
    assert top1 == pytest.approx((fitted.predictions == y).mean())
    assert top2 >= top1


def test_top_k_accuracy_requires_probabilities() -> None:
    with pytest.raises(ModelError, match="predict_proba"):
        top_k_accuracy(np.array(["a"]), None, ("a", "b"))


# --------------------------------------------------------------------------------------------
# metrics: macro/weighted F1, per-class report, confusion, most-confused-with, binary collapse
# --------------------------------------------------------------------------------------------
def test_macro_f1_weights_every_class_equally() -> None:
    # 90 correct "white", 10 "rare" all wrong -> weighted F1 (dominated by the 90-strong class)
    # stays well above macro F1 (which gives "rare"'s 0.0 F1 equal weight to "white"'s ~0.95).
    y_true = np.array(["white"] * 90 + ["rare"] * 10)
    y_pred = np.array(["white"] * 90 + ["white"] * 10)
    assert weighted_f1(y_true, y_pred) > 0.8
    assert macro_f1(y_true, y_pred) < 0.6


def test_perfect_predictions_score_one_on_both_f1_variants() -> None:
    y = np.array(["a", "b", "c", "a", "b"])
    assert macro_f1(y, y) == pytest.approx(1.0)
    assert weighted_f1(y, y) == pytest.approx(1.0)


def test_most_confused_with_finds_the_dominant_off_diagonal_class() -> None:
    labels = ("a", "b", "c")
    y_true = np.array(["a"] * 10 + ["b"] * 10)
    y_pred = np.array(["c"] * 8 + ["a"] * 2 + ["b"] * 10)  # "a" is mostly confused with "c"
    matrix = confusion(y_true, y_pred, labels)
    confused = most_confused_with(matrix, labels)
    assert confused["a"] == "c"
    assert confused["b"] is None  # "b" always predicted correctly, no off-diagonal mass
    assert confused["c"] is None  # no true "c" rows at all


def test_per_class_report_matches_manual_precision_recall() -> None:
    labels = ("a", "b")
    y_true = np.array(["a", "a", "a", "b", "b"])
    y_pred = np.array(["a", "a", "b", "b", "b"])
    report = per_class_report(y_true, y_pred, labels)
    assert report.recall["a"] == pytest.approx(2 / 3)
    assert report.precision["a"] == pytest.approx(1.0)
    assert report.recall["b"] == pytest.approx(1.0)
    assert report.support == {"a": 3, "b": 2}


def test_binary_collapse_matches_manual_binarization() -> None:
    y_true = np.array(["white", "fam_a", "fam_b", "white"])
    y_pred = np.array(["white", "white", "fam_b", "fam_a"])
    result = binary_collapse(y_true, y_pred)
    # true positives: fam_b row (correctly flagged ransomware); fam_a true row predicted white
    # (false negative); white row predicted fam_a (false positive); white row correct (TN).
    tn, fp, fn, tp = result.honest.confusion
    assert (tn, fp, fn, tp) == (1, 1, 1, 1)


# --------------------------------------------------------------------------------------------
# per_family_feature_signal
# --------------------------------------------------------------------------------------------
def test_per_family_feature_signal_ranks_the_informative_feature_highest() -> None:
    rng = np.random.default_rng(0)
    n = 400
    # feature 0 separates "target" from everything else; features 1-2 are pure noise.
    is_target = np.zeros(n, dtype=bool)
    is_target[:100] = True
    x = rng.normal(size=(n, 3))
    x[is_target, 0] += 8.0
    y = np.where(is_target, "target", "other")
    signal = per_family_feature_signal(x, y, ("f0", "f1", "f2"), "target", seed=0, max_rows=n)
    assert max(signal, key=signal.get) == "f0"


def test_per_family_feature_signal_rejects_a_family_with_too_few_rows() -> None:
    x = np.zeros((10, 2))
    y = np.array(["only_one"] + ["other"] * 9)
    with pytest.raises(ModelError, match="only_one"):
        per_family_feature_signal(x, y, ("f0", "f1"), "only_one", seed=0)


# --------------------------------------------------------------------------------------------
# Real-data invariants (M7-16 TESTS section) — skip when the 2.9M-row file is absent.
# --------------------------------------------------------------------------------------------
def _real_spec():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    path = root / "data" / "raw" / "BitcoinHeistData.csv"
    if not path.exists():
        pytest.skip("data/raw/BitcoinHeistData.csv not present in this environment")
    return DatasetSpec(
        path=path,
        group_column="address",
        subsample_rows=None,
    )


def test_real_data_no_large_family_is_dropped_by_the_merge() -> None:
    spec = _real_spec()
    data = load_bitcoinheist_families(spec, verify=True)
    raw_dist = class_distribution(data.family_labels)
    _, merged_names = merge_rare_families(data.family_labels, min_count=MIN_FAMILY_SAMPLES)
    for name, count in raw_dist.items():
        if name == "white":
            continue
        if count >= MIN_FAMILY_SAMPLES:
            assert name not in merged_names, f"{name} (n={count}) should not have been merged"
    for name in merged_names:
        assert raw_dist[name] < MIN_FAMILY_SAMPLES


def test_real_data_other_ransomware_contains_only_rare_families() -> None:
    spec = _real_spec()
    data = load_bitcoinheist_families(spec, verify=True)
    raw_dist = class_distribution(data.family_labels)
    _, merged_names = merge_rare_families(data.family_labels, min_count=MIN_FAMILY_SAMPLES)
    assert len(merged_names) > 0  # known from the real corpus: 11 families under 10 samples
    for name in merged_names:
        assert raw_dist[name] < MIN_FAMILY_SAMPLES
        assert name != "white"


def test_real_data_grouped_split_keeps_every_address_on_one_side() -> None:
    spec = _real_spec()
    data = load_bitcoinheist_families(spec, verify=True)
    merged, _ = merge_rare_families(data.family_labels, min_count=MIN_FAMILY_SAMPLES)
    train_idx, test_idx = grouped_stratified_holdout(merged, data.groups, test_size=0.30, seed=0)
    train_addresses = set(data.groups[train_idx])
    test_addresses = set(data.groups[test_idx])
    assert train_addresses.isdisjoint(test_addresses)
    assert len(train_idx) + len(test_idx) == data.n_rows
