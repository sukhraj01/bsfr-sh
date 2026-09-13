"""`detection.profiles`: `NProf`/`AProf` as `DM_CSl`'s fitted class-conditional descriptions."""

from __future__ import annotations

import numpy as np
import pytest
from m3b_harness import SEED, clean_draw, feature_matrix
from pbft_harness import REPO_ROOT

from bsfr_sh.detection.models import train_all
from bsfr_sh.detection.profiles import (
    AbnormalProfile,
    NormalProfile,
    ProfileError,
    build,
    ensemble_score,
)
from bsfr_sh.honeypot.collector import BENIGN, MALICIOUS
from bsfr_sh.util.config import load_config

CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")


def _trained(count: int = 300, seed: int = SEED):
    x, y, _missing = feature_matrix(clean_draw(count=count, seed=seed))
    models = train_all(x, y, CONFIG, seed=seed)
    return models, x, y


def test_build_returns_normal_and_abnormal_profiles_labelled_correctly() -> None:
    models, x, y = _trained()
    names = tuple(f"f{i}" for i in range(x.shape[1]))
    normal, abnormal = build(models, x, y, feature_names=names)
    assert isinstance(normal, NormalProfile)
    assert isinstance(abnormal, AbnormalProfile)
    assert normal.label == BENIGN
    assert abnormal.label == MALICIOUS
    assert normal.n_samples == int((y == 0).sum())
    assert abnormal.n_samples == int((y == 1).sum())
    assert normal.n_samples + abnormal.n_samples == len(y)
    assert normal.feature_names == names


def test_ensemble_score_is_bounded_like_a_probability() -> None:
    models, x, _y = _trained()
    scores = ensemble_score(models, x)
    assert scores.shape == (len(x),)
    assert np.all((scores >= 0.0) & (scores <= 1.0))


def test_ensemble_score_refuses_an_empty_model_set() -> None:
    with pytest.raises(ProfileError, match="no trained models"):
        ensemble_score({}, np.zeros((3, 2)))


def test_membership_favours_each_class_on_average() -> None:
    """Not a tautology: membership is a fitted z-score, and this checks it discriminates."""
    models, x, y = _trained()
    names = tuple(range(x.shape[1]))
    normal, abnormal = build(models, x, y, feature_names=names)
    scores = ensemble_score(models, x)
    advantage = np.array([abnormal.membership(s) - normal.membership(s) for s in scores])
    assert advantage[y == 1].mean() > advantage[y == 0].mean()


def test_build_refuses_a_training_draw_missing_the_malicious_class() -> None:
    models, x, y = _trained()
    only_benign = y == 0
    with pytest.raises(ProfileError, match="RW"):
        build(models, x[only_benign], y[only_benign], feature_names=tuple(range(x.shape[1])))


def test_build_refuses_a_training_draw_missing_the_benign_class() -> None:
    models, x, y = _trained()
    only_malicious = y == 1
    with pytest.raises(ProfileError, match="benign"):
        build(models, x[only_malicious], y[only_malicious], feature_names=tuple(range(x.shape[1])))


def test_build_refuses_mismatched_x_and_y() -> None:
    models, x, y = _trained()
    with pytest.raises(ProfileError, match="rows"):
        build(models, x, y[:-1], feature_names=tuple(range(x.shape[1])))
