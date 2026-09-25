"""M7-11 end-to-end checks against the committed honeypot corpus (DEV-27's fixed dataset).

Mirrors `test_m7_8_adversarial_retraining.py`'s pattern: the generic poisoning mechanics are
already covered array-agnostically in `test_detection_poisoning.py`; this file is M7-11's own
exit tests, run against the real committed data so a regression in the actual pipeline (not just
the primitives) would be caught. Session brief's TESTS section: "clean baseline reproduces
0.8422" (this project's CSV-path convention is 0.8408, DEV-27 -- see
`scripts/m7_11_honeypot_poisoning.py`'s module docstring), "poisoned training sets have the
expected row counts and label distributions", "at 0% poisoning budget, the detector reproduces
its clean accuracy", "at 100% label-flipping budget, balanced accuracy should approach 0.50 or
worse".
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from pbft_harness import REPO_ROOT

from bsfr_sh.detection import models as detection_models
from bsfr_sh.detection import profiles as detection_profiles
from bsfr_sh.detection.adversarial import balanced_accuracy, ensemble_predict
from bsfr_sh.detection.detector import DetectionModule
from bsfr_sh.detection.poisoning import (
    anchor_point_injection,
    feature_poison,
    label_flip,
)
from bsfr_sh.honeypot import features as ft
from bsfr_sh.util.config import load_config
from bsfr_sh.util.seeding import numpy_generator

SEED = 20260912
CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
#: M7-3's established CSV-path baseline (`RESULTS.md` M7-3), not the chain-path 0.8422 the
#: session brief names -- DEV-27's amendment explains the gap; every M7-x poisoning/retraining
#: experiment in this project checks against this number.
CSV_PATH_BASELINE_BAL_ACC = 0.8408
STRATEGIES = (label_flip, feature_poison, anchor_point_injection)


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


@pytest.mark.slow
def test_csv_path_baseline_reproduces_m7_3(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
) -> None:
    (x_train, y_train), (x_eval, y_eval) = corpus
    detector = _fit_detector(x_train, y_train)
    bal_acc = balanced_accuracy(y_eval, ensemble_predict(detector, x_eval))
    assert bal_acc == pytest.approx(CSV_PATH_BASELINE_BAL_ACC, abs=1e-4)


@pytest.mark.slow
@pytest.mark.parametrize("strategy", STRATEGIES)
def test_zero_budget_reproduces_clean_accuracy_exactly(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
    strategy: object,
) -> None:
    """The degenerate case, per strategy: `budget=0.0` must train on the identical draw the
    unpoisoned model saw, so the fit -- and every metric computed from it -- is exactly, not
    approximately, the original model's."""
    (x_train, y_train), (x_eval, y_eval) = corpus
    original = _fit_detector(x_train, y_train)
    original_bal_acc = balanced_accuracy(y_eval, ensemble_predict(original, x_eval))

    rng = numpy_generator(SEED)
    result = strategy(x_train, y_train, 0.0, rng=rng)  # type: ignore[operator]
    assert result.x is x_train
    assert result.y is y_train

    poisoned = _fit_detector(result.x, result.y)
    poisoned_bal_acc = balanced_accuracy(y_eval, ensemble_predict(poisoned, x_eval))
    assert poisoned_bal_acc == pytest.approx(original_bal_acc)


@pytest.mark.slow
def test_poisoned_training_sets_have_expected_row_counts_and_label_distributions(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
) -> None:
    (x_train, y_train), _eval = corpus
    n_train = len(x_train)
    n_positive = int((y_train == 1).sum())
    rng = numpy_generator(SEED)

    flip = label_flip(x_train, y_train, 0.2, rng=rng)
    assert len(flip.y) == n_train  # label flipping never changes row count
    assert int((flip.y == 1).sum()) == n_positive - round(0.2 * n_positive)

    poison = feature_poison(x_train, y_train, 0.2, rng=numpy_generator(SEED))
    n_inject = round(0.2 * n_positive)
    assert len(poison.y) == n_train + n_inject
    assert int((poison.y == 1).sum()) == n_positive + n_inject  # injected rows are all "RW"

    anchor = anchor_point_injection(x_train, y_train, 0.2, rng=numpy_generator(SEED))
    assert len(anchor.y) == n_train + n_inject
    assert int((anchor.y == 0).sum()) == (n_train - n_positive) + n_inject  # injected are benign


@pytest.mark.slow
def test_eval_set_is_never_perturbed_by_any_strategy(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
) -> None:
    (x_train, y_train), (x_eval, y_eval) = corpus
    for strategy in STRATEGIES:
        strategy(x_train, y_train, 0.5, rng=numpy_generator(SEED))  # type: ignore[operator]
        x_eval_reloaded, y_eval_reloaded = _load("eval")
        assert np.array_equal(x_eval, x_eval_reloaded)
        assert np.array_equal(y_eval, y_eval_reloaded)


@pytest.mark.slow
def test_full_budget_label_flip_leaves_zero_positive_training_rows(
    corpus: tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]],
) -> None:
    """At 100% budget every ransomware row is relabelled benign -- the training set has no
    positive examples left, which is the measured basis for "balanced accuracy approaches 0.50":
    no classifier can be fit past "always benign", which scores exactly 0.50 on a balanced eval
    set by construction (`scripts/m7_11_honeypot_poisoning.py`'s own handling of this case)."""
    (x_train, y_train), _eval = corpus
    result = label_flip(x_train, y_train, 1.0, rng=numpy_generator(SEED))
    assert int((result.y == 1).sum()) == 0
    assert len(result.y) == len(y_train)
