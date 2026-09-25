"""M7-8 end-to-end checks against the committed honeypot corpus (DEV-27's fixed dataset).

These exercise the real `data/honeypot/corpus_{train,eval}.csv` files the M7-8 script reads —
the generic augmentation mechanics are already covered array-agnostically in
`test_detection_retraining.py`; this file is specifically the session's own exit tests, run
against the real committed data so a regression in the actual pipeline (not just the primitive)
would be caught.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from pbft_harness import REPO_ROOT

from bsfr_sh.detection import models as detection_models
from bsfr_sh.detection import profiles as detection_profiles
from bsfr_sh.detection.adversarial import (
    FEATURE_BOUNDS,
    TOP_N,
    balanced_accuracy,
    ensemble_predict,
    select_best_importance_model,
    top_feature_importances,
)
from bsfr_sh.detection.detector import DetectionModule
from bsfr_sh.detection.retraining import augment_positive_rows
from bsfr_sh.honeypot import features as ft
from bsfr_sh.util.config import load_config
from bsfr_sh.util.seeding import numpy_generator

SEED = 20260912
CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
#: M7-3's established CSV-path baseline (`RESULTS.md` M7-3, `20260922T155316Z-3ce801ca`), not
#: `RESULTS.md`'s chain-path M4b entry of 0.8422 -- `docs/DEVIATIONS.md` DEV-27's amendment
#: explains the 0.0014 gap (`corpus.write_corpus` rounds to 6 significant figures; the chain path
#: does not). Every number here is relative to the CSV-path number, same as M7-3.
CSV_PATH_BASELINE_BAL_ACC = 0.8408


def _load(name: str) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.read_csv(REPO_ROOT / "data" / "honeypot" / f"corpus_{name}.csv")
    x = frame[list(ft.FEATURE_NAMES)].to_numpy(dtype=np.float64)
    y = (frame["label"] == "RW").to_numpy(dtype=np.int8)
    return x, y


def _fit_detector(x_train: np.ndarray, y_train: np.ndarray) -> DetectionModule:
    models = detection_models.train_all(x_train, y_train, CONFIG, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    return DetectionModule(models=models, normal=normal, abnormal=abnormal)


@pytest.fixture(scope="module")
def corpus() -> tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]]:
    return _load("train"), _load("eval")


@pytest.fixture(scope="module")
def top5(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
) -> list[str]:
    (x_train, y_train), (x_eval, y_eval) = corpus
    _name, model, _score = select_best_importance_model(
        CONFIG, x_train, y_train, x_eval, y_eval, seed=SEED
    )
    pairs = top_feature_importances(model, ft.FEATURE_NAMES, TOP_N)
    names = [n for n, _v in pairs]
    assert set(names) == set(FEATURE_BOUNDS), (
        "the committed-seed top-5 changed; M7-8 reuses M7-3's FEATURE_BOUNDS and needs them "
        "to match the current top-5 exactly"
    )
    return names


@pytest.mark.slow
def test_csv_path_baseline_reproduces_m7_3(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
) -> None:
    (x_train, y_train), (x_eval, y_eval) = corpus
    detector = _fit_detector(x_train, y_train)
    bal_acc = balanced_accuracy(y_eval, ensemble_predict(detector, x_eval))
    assert bal_acc == pytest.approx(CSV_PATH_BASELINE_BAL_ACC, abs=1e-4)


@pytest.mark.slow
def test_augmented_training_set_has_expected_row_count(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]], top5: list[str]
) -> None:
    (x_train, y_train), _eval = corpus
    indices = [ft.FEATURE_NAMES.index(n) for n in top5]
    bounds = [FEATURE_BOUNDS[n] for n in top5]
    n_positive = int((y_train == 1).sum())
    rng = numpy_generator(SEED)
    k = 5
    x_aug, y_aug = augment_positive_rows(
        x_train, y_train, indices, bounds, k=k, max_perturbation=0.5, rng=rng
    )
    assert len(x_aug) == len(x_train) + k * n_positive
    assert len(y_aug) == len(y_train) + k * n_positive


@pytest.mark.slow
def test_eval_set_is_never_perturbed(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]], top5: list[str]
) -> None:
    """Augmentation only ever reads/writes the training arrays; the eval CSV on disk (and the
    array reloaded from it) must be bit-identical before and after."""
    (x_train, y_train), (x_eval, y_eval) = corpus
    indices = [ft.FEATURE_NAMES.index(n) for n in top5]
    bounds = [FEATURE_BOUNDS[n] for n in top5]
    rng = numpy_generator(SEED)
    augment_positive_rows(x_train, y_train, indices, bounds, k=5, max_perturbation=1.0, rng=rng)
    x_eval_reloaded, y_eval_reloaded = _load("eval")
    assert np.array_equal(x_eval, x_eval_reloaded)
    assert np.array_equal(y_eval, y_eval_reloaded)


@pytest.mark.slow
def test_hardened_model_at_max_perturbation_zero_reproduces_the_original_exactly(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]], top5: list[str]
) -> None:
    """The degenerate case: `max_perturbation=0.0` must train on the identical draw the original
    model saw (`retraining.augment_positive_rows`'s no-op path), so the fit -- and every metric
    computed from it -- is exactly, not approximately, the original model's."""
    (x_train, y_train), (x_eval, y_eval) = corpus
    indices = [ft.FEATURE_NAMES.index(n) for n in top5]
    bounds = [FEATURE_BOUNDS[n] for n in top5]

    original = _fit_detector(x_train, y_train)
    original_bal_acc = balanced_accuracy(y_eval, ensemble_predict(original, x_eval))
    assert original_bal_acc == pytest.approx(CSV_PATH_BASELINE_BAL_ACC, abs=1e-4)

    rng = numpy_generator(SEED)
    x_aug, y_aug = augment_positive_rows(
        x_train, y_train, indices, bounds, k=5, max_perturbation=0.0, rng=rng
    )
    assert len(x_aug) == len(x_train)  # no rows added at the degenerate budget

    hardened = _fit_detector(x_aug, y_aug)
    hardened_bal_acc = balanced_accuracy(y_eval, ensemble_predict(hardened, x_eval))
    assert hardened_bal_acc == original_bal_acc


@pytest.mark.slow
def test_original_model_is_unaffected_by_building_an_augmented_set(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]], top5: list[str]
) -> None:
    """No contamination: fitting/evaluating the *original* model, after augmentation code has
    run elsewhere, still reproduces the CSV-path baseline -- confirms `augment_positive_rows`
    never mutates its inputs in place."""
    (x_train, y_train), (x_eval, y_eval) = corpus
    indices = [ft.FEATURE_NAMES.index(n) for n in top5]
    bounds = [FEATURE_BOUNDS[n] for n in top5]
    rng = numpy_generator(SEED + 999)
    augment_positive_rows(x_train, y_train, indices, bounds, k=5, max_perturbation=1.0, rng=rng)

    detector = _fit_detector(x_train, y_train)
    bal_acc = balanced_accuracy(y_eval, ensemble_predict(detector, x_eval))
    assert bal_acc == pytest.approx(CSV_PATH_BASELINE_BAL_ACC, abs=1e-4)


@pytest.mark.slow
def test_hardened_model_at_a_nonzero_budget_is_a_genuinely_different_model(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]], top5: list[str]
) -> None:
    """0% perturbation *applied at eval time* to a model hardened at a nonzero training budget
    is that model's own clean accuracy, not the original 0.8408 -- it is a different fit."""
    (x_train, y_train), (x_eval, y_eval) = corpus
    indices = [ft.FEATURE_NAMES.index(n) for n in top5]
    bounds = [FEATURE_BOUNDS[n] for n in top5]

    original = _fit_detector(x_train, y_train)
    original_pred = ensemble_predict(original, x_eval)

    rng = numpy_generator(SEED + 500)
    x_aug, y_aug = augment_positive_rows(
        x_train, y_train, indices, bounds, k=5, max_perturbation=0.5, rng=rng
    )
    hardened = _fit_detector(x_aug, y_aug)
    hardened_pred = ensemble_predict(hardened, x_eval)
    hardened_bal_acc = balanced_accuracy(y_eval, hardened_pred)

    assert 0.0 <= hardened_bal_acc <= 1.0
    assert not np.array_equal(original_pred, hardened_pred)
