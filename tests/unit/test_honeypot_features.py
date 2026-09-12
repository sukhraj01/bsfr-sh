"""`honeypot.features`: the schema, and the checks that keep M4's future numbers meaningful.

The three that matter are at the bottom: the classes overlap, no single feature gives the answer
away, and a simple baseline lands near the corpus's intended difficulty rather than at ceiling.
If any of them fails, the generator is broken in a way that would make M4 report a triumphant
number about nothing.
"""

from __future__ import annotations

import dataclasses

import numpy as np
import pytest
from m3b_harness import (
    baseline_balanced_accuracy,
    clean_draw,
    feature_matrix,
    separability,
)

from bsfr_sh.honeypot.collector import BENIGN, MALICIOUS, OBSERVABLE_STAGES
from bsfr_sh.honeypot.corpus import EXPECTED_BAYES_ACCURACY
from bsfr_sh.honeypot.features import FEATURE_GROUPS, FEATURE_NAMES, SCHEMA, FeatureVector, build

TRAIN = clean_draw(1200, seed=11)
EVAL = clean_draw(1200, seed=12)
X_TRAIN, Y_TRAIN, MISSING_TRAIN = feature_matrix(TRAIN)
X_EVAL, Y_EVAL, _ = feature_matrix(EVAL)

#: A single feature at or above this is the label in disguise.
MAX_SINGLE_FEATURE = 0.90


# -- schema ------------------------------------------------------------------------------------
def test_the_schema_is_the_seven_declared_groups() -> None:
    assert [group for group, _ in FEATURE_GROUPS] == [
        "filesystem",
        "entropy",
        "crypto_api",
        "process",
        "network",
        "persistence",
        "kill_chain",
    ]
    assert len(FEATURE_NAMES) == 22
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)
    assert SCHEMA == "ft_rw.v1"


def test_a_vector_must_match_the_schema_length() -> None:
    with pytest.raises(ValueError, match="features"):
        FeatureVector(values=(0.0,), missing_mask=0)


def test_extraction_is_deterministic() -> None:
    assert build(TRAIN[0]) == build(TRAIN[0])


def test_unobserved_features_are_flagged_and_zeroed_not_imputed() -> None:
    sample = dataclasses.replace(
        TRAIN[0],
        counters={k: v for k, v in TRAIN[0].counters.items() if k != "dns_entropy"},
        missing=frozenset({*TRAIN[0].missing, "dns_entropy"}),
    )
    vector = build(sample)
    assert "dns_entropy" in vector.missing()
    assert vector.as_dict()["dns_entropy"] == 0.0


def test_the_label_is_not_among_the_features() -> None:
    assert "label" not in FEATURE_NAMES
    assert not hasattr(build(TRAIN[0]), "label")


# -- the kill-chain decision (DEV-27) -----------------------------------------------------------
def test_the_kill_chain_feature_is_truncated_to_the_observable_prefix() -> None:
    values = X_TRAIN[:, FEATURE_NAMES.index("observed_stages")]
    assert values.max() <= OBSERVABLE_STAGES


def test_both_classes_reach_the_top_of_the_truncated_chain() -> None:
    """The whole point of truncating: the top value must not belong to one class alone."""
    column = FEATURE_NAMES.index("observed_stages")
    top = X_TRAIN[:, column].max()
    assert (X_TRAIN[Y_TRAIN == 1, column] == top).any()
    assert (X_TRAIN[Y_TRAIN == 0, column] == top).any()


# -- the three that keep M4 honest ---------------------------------------------------------------
def test_every_feature_overlaps_between_the_classes() -> None:
    for index, name in enumerate(FEATURE_NAMES):
        malicious, benign = X_TRAIN[Y_TRAIN == 1, index], X_TRAIN[Y_TRAIN == 0, index]
        assert min(malicious.max(), benign.max()) > max(malicious.min(), benign.min()), (
            f"{name} separates the classes cleanly at its extremes"
        )


def test_no_single_feature_gives_the_answer_away() -> None:
    scores = {
        name: separability(X_TRAIN[:, index], Y_TRAIN) for index, name in enumerate(FEATURE_NAMES)
    }
    worst, score = max(scores.items(), key=lambda item: item[1])
    assert score < MAX_SINGLE_FEATURE, f"{worst} alone separates the classes ({score:.3f})"
    assert max(scores.values()) > 0.55, "no feature carries any signal; the corpus is noise"


def test_missingness_does_not_encode_the_label() -> None:
    gaps = [
        abs(MISSING_TRAIN[Y_TRAIN == 1, i].mean() - MISSING_TRAIN[Y_TRAIN == 0, i].mean())
        for i in range(len(FEATURE_NAMES))
    ]
    assert max(gaps) < 0.06


def test_a_simple_baseline_lands_near_the_intended_difficulty_not_at_ceiling() -> None:
    """Trained on one draw, scored on another — never a shuffle of one draw."""
    accuracy = baseline_balanced_accuracy((X_TRAIN, Y_TRAIN), (X_EVAL, Y_EVAL))
    assert 0.70 < accuracy < 0.92, f"baseline balanced accuracy {accuracy:.3f}"
    assert accuracy < 0.95
    assert abs(accuracy - EXPECTED_BAYES_ACCURACY) < 0.12


def test_the_classes_are_not_separable_by_a_single_threshold_on_any_group_mean() -> None:
    """Group-level aggregates must not do what no single feature can."""
    for group, names in FEATURE_GROUPS:
        columns = [FEATURE_NAMES.index(name) for name in names]
        aggregate = np.log1p(np.clip(X_TRAIN[:, columns], 0, None)).mean(axis=1)
        assert separability(aggregate, Y_TRAIN) < MAX_SINGLE_FEATURE, group


def test_the_corpus_holds_both_classes_after_cleaning() -> None:
    assert {s.label for s in TRAIN} == {MALICIOUS, BENIGN}
