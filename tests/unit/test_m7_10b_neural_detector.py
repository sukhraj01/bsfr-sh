"""M7-10b end-to-end checks against the committed honeypot corpus (DEV-27's fixed dataset).

Mirrors `test_m7_8_adversarial_retraining.py`'s pattern: the generic augmentation mechanics are
already covered array-agnostically in `test_detection_retraining.py` and the MLP wiring in
`test_mlp_model.py`; this file is M7-10's own exit tests, run against the real committed data so a
regression in the actual pipeline (not just the primitives) would be caught. Session brief's TESTS
section: "MLP on the 0%-budget augmented corpus reproduces its own clean accuracy (degenerate
case)", "the RF model loaded for comparison still produces [the established baseline] on the
synthetic eval corpus", "perturbation at 0% reproduces clean accuracy for both models."
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
    STEPS,
    balanced_accuracy,
    combined_curve,
    ensemble_predict,
)
from bsfr_sh.detection.detector import DetectionModule
from bsfr_sh.detection.mlp_model import train_mlp
from bsfr_sh.detection.retraining import augment_positive_rows
from bsfr_sh.honeypot import features as ft
from bsfr_sh.util.config import load_config
from bsfr_sh.util.seeding import numpy_generator

SEED = 20260912
CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
#: M7-3's established CSV-path baseline (`RESULTS.md` M7-3), not the chain-path 0.8422 (DEV-27's
#: amendment explains the 0.0014 gap) -- same reference every measured honeypot number in this
#: project (M7-3/M7-7/M7-8) uses.
CSV_PATH_BASELINE_BAL_ACC = 0.8408
#: M7-3's own top-5, reused verbatim by M7-10b -- never re-derived from the MLP, which has no
#: `.feature_importances_` in the first place (module docstring, `scripts/m7_10b_neural_detector.py`
#: explains why).
TOP5 = tuple(FEATURE_BOUNDS.keys())


def _load(name: str) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.read_csv(REPO_ROOT / "data" / "honeypot" / f"corpus_{name}.csv")
    x = frame[list(ft.FEATURE_NAMES)].to_numpy(dtype=np.float64)
    y = (frame["label"] == "RW").to_numpy(dtype=np.int8)
    return x, y


def _fit_rf_detector(x_train: np.ndarray, y_train: np.ndarray) -> DetectionModule:
    models = detection_models.train_all(x_train, y_train, CONFIG, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    return DetectionModule(models=models, normal=normal, abnormal=abnormal)


def _fit_mlp_detector(x_train: np.ndarray, y_train: np.ndarray) -> DetectionModule:
    models = train_mlp(x_train, y_train, CONFIG, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    return DetectionModule(models=models, normal=normal, abnormal=abnormal)


@pytest.fixture(scope="module")
def corpus() -> tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]]:
    return _load("train"), _load("eval")


@pytest.mark.slow
def test_rf_csv_path_baseline_still_reproduces_m7_3(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
) -> None:
    (x_train, y_train), (x_eval, y_eval) = corpus
    detector = _fit_rf_detector(x_train, y_train)
    bal_acc = balanced_accuracy(y_eval, ensemble_predict(detector, x_eval))
    assert bal_acc == pytest.approx(CSV_PATH_BASELINE_BAL_ACC, abs=1e-4)


@pytest.mark.slow
def test_mlp_zero_perturbation_reproduces_its_own_clean_accuracy(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
) -> None:
    """`combined_curve` at `frac=0.0` (`STEPS[0]`) must equal the unperturbed clean balanced
    accuracy -- the degradation sweep's own degenerate case, for the MLP exactly as for RF."""
    (x_train, y_train), (x_eval, y_eval) = corpus
    detector = _fit_mlp_detector(x_train, y_train)
    clean_bal_acc = balanced_accuracy(y_eval, ensemble_predict(detector, x_eval))
    feature_index = {name: i for i, name in enumerate(ft.FEATURE_NAMES)}
    curve = combined_curve(detector, x_eval, y_eval, list(TOP5), feature_index)
    assert STEPS[0] == 0.0
    assert curve[0] == pytest.approx(clean_bal_acc)


@pytest.mark.slow
def test_mlp_at_max_perturbation_zero_training_budget_reproduces_the_original_exactly(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
) -> None:
    """The degenerate retraining case for the MLP: `max_perturbation=0.0` must train on the
    identical draw the original MLP saw (`retraining.augment_positive_rows`'s no-op path), so
    the fit -- and every metric computed from it -- is exactly the original MLP's."""
    (x_train, y_train), (x_eval, y_eval) = corpus
    indices = [ft.FEATURE_NAMES.index(n) for n in TOP5]
    bounds = [FEATURE_BOUNDS[n] for n in TOP5]

    original = _fit_mlp_detector(x_train, y_train)
    original_bal_acc = balanced_accuracy(y_eval, ensemble_predict(original, x_eval))

    rng = numpy_generator(SEED)
    x_aug, y_aug = augment_positive_rows(
        x_train, y_train, indices, bounds, k=5, max_perturbation=0.0, rng=rng
    )
    assert np.array_equal(x_aug, x_train)
    assert np.array_equal(y_aug, y_train)

    degenerate = _fit_mlp_detector(x_aug, y_aug)
    degenerate_bal_acc = balanced_accuracy(y_eval, ensemble_predict(degenerate, x_eval))
    assert degenerate_bal_acc == pytest.approx(original_bal_acc)


@pytest.mark.slow
def test_mlp_eval_set_is_never_perturbed(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
) -> None:
    (x_train, y_train), (x_eval, y_eval) = corpus
    indices = [ft.FEATURE_NAMES.index(n) for n in TOP5]
    bounds = [FEATURE_BOUNDS[n] for n in TOP5]
    rng = numpy_generator(SEED)
    augment_positive_rows(x_train, y_train, indices, bounds, k=5, max_perturbation=1.0, rng=rng)
    x_eval_reloaded, y_eval_reloaded = _load("eval")
    assert np.array_equal(x_eval, x_eval_reloaded)
    assert np.array_equal(y_eval, y_eval_reloaded)
