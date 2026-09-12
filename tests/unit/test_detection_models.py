"""`detection.models`: declared hyperparameters, and the KNN projection that keeps M4a honest."""

from __future__ import annotations

import numpy as np
import pytest
from pbft_harness import REPO_ROOT

from bsfr_sh.detection.models import (
    MODEL_NAMES,
    ModelError,
    build_model,
    build_models,
    fit_and_score,
    fits_in_memory,
    knn_projection,
)
from bsfr_sh.util.config import load_config

CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")


def test_all_four_of_table_twos_algorithms_are_built() -> None:
    models = build_models(CONFIG, seed=11)
    assert tuple(models) == MODEL_NAMES


@pytest.mark.parametrize(
    ("name", "attribute", "key"),
    [
        ("random_forest", "n_estimators", "models.random_forest.n_estimators"),
        ("logistic_regression", "max_iter", "models.logistic_regression.max_iter"),
        ("decision_tree", "criterion", "models.decision_tree.criterion"),
        ("k_nearest_neighbours", "n_neighbors", "models.k_nearest_neighbours.n_neighbors"),
    ],
)
def test_hyperparameters_come_from_the_config_not_from_sklearn_defaults(
    name, attribute, key
) -> None:
    """The paper reports none, so ours are declared — never silently defaulted."""
    model = build_model(CONFIG, name, seed=3)
    assert getattr(model, attribute) == CONFIG.get(key)


def test_the_seed_is_injected_where_the_estimator_has_one() -> None:
    for name in ("random_forest", "logistic_regression", "decision_tree"):
        assert build_model(CONFIG, name, seed=1234).random_state == 1234
    # KNN is deterministic and takes no random_state; asking for one would be a lie.
    assert not hasattr(build_model(CONFIG, "k_nearest_neighbours", seed=1234), "random_state")


def test_a_model_the_config_does_not_declare_is_refused() -> None:
    with pytest.raises(ModelError, match="declares no"):
        build_model(CONFIG, "gradient_boosting", seed=0)


def test_fit_and_score_times_the_two_halves_separately() -> None:
    rng = np.random.default_rng(0)
    x = rng.random((200, 4))
    y = (x[:, 0] > 0.5).astype(np.int8)
    fitted = fit_and_score(
        build_model(CONFIG, "decision_tree", seed=0),
        "decision_tree",
        x[:150],
        y[:150],
        x[150:],
        y[150:],
    )
    assert fitted.n_train == 150
    assert fitted.n_test == 50
    assert fitted.fit_seconds >= 0.0
    assert fitted.predict_seconds >= 0.0
    assert fitted.scores is not None  # a tree exposes predict_proba
    assert len(fitted.predictions) == 50


# -- the compute projection (CLAUDE.md §6) -------------------------------------------------------
def test_the_projection_scales_with_the_training_half() -> None:
    small = knn_projection(10_000, 10_000, 8)
    large = knn_projection(1_000_000, 1_000_000, 8)
    assert large["peak_gb"] > small["peak_gb"]
    assert large["distance_computations"] == pytest.approx(1e12)


def test_paper_mode_sized_knn_fits_and_full_scale_knn_does_not() -> None:
    """~46K rows runs anywhere; 2.9M is the run that gets prepared as an Ada job instead."""
    paper_mode = knn_projection(32_210, 13_804, 8)
    full_scale = knn_projection(2_333_358, 583_339, 8, n_jobs=1)
    assert fits_in_memory(paper_mode)
    assert full_scale["distance_computations"] > 1e12
    assert not fits_in_memory(full_scale, ceiling_gb=8.0)
