"""`detection.federated` — majority vote and disagreement analysis over N independent detector
replicas. M7-15."""

from __future__ import annotations

import numpy as np
import pytest

from bsfr_sh.detection.federated import (
    analyze_disagreement,
    majority_vote,
    vote,
)

# --------------------------------------------------------------------------------------------
# majority_vote / vote
# --------------------------------------------------------------------------------------------


def test_majority_vote_with_no_dissent_reproduces_the_single_model_prediction() -> None:
    """No poisoning, no disagreement: every node predicts identically, so majority voting must
    reproduce exactly what any one of them (equivalently, a single-server deployment) would have
    decided on its own."""
    pred = np.array([0, 1, 1, 0, 1, 0, 0, 1], dtype=np.int8)
    per_node = {f"CS_{i}": pred.copy() for i in range(4)}
    result = majority_vote(per_node)
    assert np.array_equal(result, pred)


def test_majority_vote_of_three_overrides_one_dissenter() -> None:
    honest = np.array([0, 1, 0, 1, 1], dtype=np.int8)
    dissenter = np.array([1, 0, 1, 0, 0], dtype=np.int8)  # disagrees on every sample
    per_node = {
        "CS_1": honest.copy(),
        "CS_2": honest.copy(),
        "CS_3": honest.copy(),
        "CS_poisoner": dissenter,
    }
    result = majority_vote(per_node)
    assert np.array_equal(result, honest)


def test_majority_vote_ties_resolve_to_benign() -> None:
    a = np.array([1, 0])
    b = np.array([1, 0])
    c = np.array([0, 1])
    d = np.array([0, 1])
    result = majority_vote({"n1": a, "n2": b, "n3": c, "n4": d})
    assert np.array_equal(result, np.array([0, 0], dtype=np.int8))


def test_majority_vote_rejects_an_empty_input() -> None:
    with pytest.raises(ValueError, match="no node predictions"):
        majority_vote({})


def test_vote_flags_a_node_whose_disagreement_exceeds_the_threshold() -> None:
    honest = np.zeros(20, dtype=np.int8)
    dissenter = np.zeros(20, dtype=np.int8)
    dissenter[:5] = 1  # disagrees on 25% of samples
    per_node = {"CS_1": honest, "CS_2": honest.copy(), "CS_3": honest.copy(), "CS_4": dissenter}
    result = vote(per_node, flag_threshold=0.10)
    assert result.flagged_nodes == ("CS_4",)
    assert result.disagreement_fraction["CS_4"] == pytest.approx(0.25)
    assert result.disagreement_fraction["CS_1"] == pytest.approx(0.0)


def test_vote_flags_nothing_when_every_node_agrees() -> None:
    pred = np.array([0, 0, 1, 1], dtype=np.int8)
    per_node = {f"CS_{i}": pred.copy() for i in range(4)}
    result = vote(per_node)
    assert result.flagged_nodes == ()


# --------------------------------------------------------------------------------------------
# analyze_disagreement
# --------------------------------------------------------------------------------------------


def test_disagreement_analyzer_identifies_the_divergent_node() -> None:
    honest = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1], dtype=np.int8)
    divergent = 1 - honest
    per_node = {
        "CS_1": honest.copy(),
        "CS_2": honest.copy(),
        "CS_3": honest.copy(),
        "CS_4": divergent,
    }
    report = analyze_disagreement(per_node)
    assert report.outlier_node == "CS_4"
    assert report.agreement_rate["CS_4"] == pytest.approx(0.0)
    assert report.agreement_rate["CS_1"] == pytest.approx(1.0)


def test_disagreement_analyzer_reports_no_outlier_on_perfect_agreement() -> None:
    pred = np.array([1, 0, 1, 0], dtype=np.int8)
    per_node = {f"CS_{i}": pred.copy() for i in range(4)}
    report = analyze_disagreement(per_node)
    assert report.outlier_node is None


def test_disagreement_analyzer_reports_no_outlier_on_an_exact_tie() -> None:
    a = np.array([1, 0, 1, 0])
    b = np.array([0, 1, 0, 1])  # disagrees with majority on all 4, same as node c
    c = np.array([0, 1, 0, 1])
    d = np.array([1, 0, 1, 0])
    report = analyze_disagreement({"n1": a, "n2": b, "n3": c, "n4": d})
    # majority is a tie -> resolves to benign (0,0,0,0); a/d disagree on 2, b/c disagree on 2 too
    assert report.outlier_node is None


def test_scenario_a_irony_the_outlier_is_the_node_with_the_highest_individual_accuracy() -> None:
    """Scenario A: three honest nodes trained on poisoned data are all *wrong* on the same
    samples; the one node that trained on a clean view is *right* on those same samples. Voting
    identifies the accurate node as the outlier -- disagreement, not correctness, is what this
    module measures -- and the report must make that visible via `individual_accuracy`, not hide
    it behind the "outlier" label."""
    y_true = np.array([1, 1, 0, 0, 1, 0, 1, 0, 1, 0], dtype=np.int8)
    honest_wrong = np.array([0, 0, 0, 0, 1, 0, 1, 0, 1, 0], dtype=np.int8)  # wrong on rows 0,1
    poisoner_correct = y_true.copy()  # the poisoner's own clean-trained model: perfectly correct
    per_node = {
        "CS_honest_1": honest_wrong.copy(),
        "CS_honest_2": honest_wrong.copy(),
        "CS_honest_3": honest_wrong.copy(),
        "CS_poisoner": poisoner_correct,
    }
    report = analyze_disagreement(per_node, y_true=y_true)
    assert report.outlier_node == "CS_poisoner"
    assert report.individual_accuracy is not None
    outlier_accuracy = report.individual_accuracy["CS_poisoner"]
    other_accuracies = [v for k, v in report.individual_accuracy.items() if k != "CS_poisoner"]
    assert outlier_accuracy > max(other_accuracies)
    # majority followed the three (wrong) honest nodes, so majority accuracy is the degraded one
    assert report.majority_accuracy is not None
    assert report.majority_accuracy < outlier_accuracy
    # excluding the outlier leaves only the three identical honest nodes -- no change, since the
    # outlier was already a minority of one and majority voting had already suppressed it.
    assert report.excluding_outlier_improves is False


def test_algorithm_diverse_ensemble_is_never_worse_than_the_worst_individual_model() -> None:
    """Scenario B: four different algorithms fit on the *same* poisoned data disagree because
    they respond differently to it, not because their training data differs. Majority voting
    over genuinely diverse errors must not score below the single worst individual model."""
    y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=np.int8)
    rf = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=np.int8)  # perfect
    dt = np.array([1, 1, 1, 0, 0, 0, 0, 0], dtype=np.int8)  # one miss
    knn = np.array([1, 1, 0, 1, 0, 0, 0, 1], dtype=np.int8)  # two misses
    lr = np.array([0, 1, 1, 1, 1, 1, 0, 0], dtype=np.int8)  # worst model, three misses
    per_node = {"rf": rf, "dt": dt, "knn": knn, "lr": lr}
    report = analyze_disagreement(per_node, y_true=y_true)
    assert report.individual_accuracy is not None
    worst_individual = min(report.individual_accuracy.values())
    assert report.majority_accuracy is not None
    assert report.majority_accuracy >= worst_individual


def test_analyze_disagreement_rejects_empty_input() -> None:
    with pytest.raises(ValueError, match="no node predictions"):
        analyze_disagreement({})
