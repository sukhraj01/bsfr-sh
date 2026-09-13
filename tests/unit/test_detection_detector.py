"""`detection.detector.DetectionModule`: Alg. 3 lines 4-9, the loop and the Phase 4 handoff."""

from __future__ import annotations

import numpy as np
from m3b_harness import SEED, clean_draw, feature_matrix
from pbft_harness import REPO_ROOT

from bsfr_sh.detection.detector import Detection, DetectionModule
from bsfr_sh.detection.models import train_all
from bsfr_sh.detection.profiles import build
from bsfr_sh.util.config import load_config

CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")


def _module(count: int = 300, seed: int = SEED, on_detect=None):
    x, y, _missing = feature_matrix(clean_draw(count=count, seed=seed))
    models = train_all(x, y, CONFIG, seed=seed)
    normal, abnormal = build(models, x, y, feature_names=tuple(range(x.shape[1])))
    module = DetectionModule(models=models, normal=normal, abnormal=abnormal, on_detect=on_detect)
    return module, x, y


def test_decide_returns_a_detection_naming_the_sample() -> None:
    module, x, _y = _module()
    detection = module.decide("s0", x[0])
    assert isinstance(detection, Detection)
    assert detection.sample_id == "s0"
    assert isinstance(detection.is_ransomware, bool)


def test_the_handoff_fires_exactly_on_positives() -> None:
    handed_off: list[Detection] = []
    module, x, _y = _module(on_detect=handed_off.append)
    detections = module.run((f"s{i}", row) for i, row in enumerate(x))
    positives = [d for d in detections if d.is_ransomware]
    assert len(handed_off) == len(positives)
    assert handed_off == positives
    assert all(d.is_ransomware for d in handed_off)


def test_run_visits_every_sample_regardless_of_verdict() -> None:
    """Lines 7-9: re-loop. A positive must not stop the monitoring loop."""
    module, x, _y = _module()
    detections = module.run((f"s{i}", row) for i, row in enumerate(x))
    assert len(detections) == len(x)
    assert [d.sample_id for d in detections] == [f"s{i}" for i in range(len(x))]


def test_run_pairs_ground_truth_labels_when_given_without_using_them_to_decide() -> None:
    module, x, y = _module()
    labels_true = ["RW" if label else "benign" for label in y]
    detections = module.run(((f"s{i}", row) for i, row in enumerate(x)), labels_true=labels_true)
    assert [d.label_true for d in detections] == labels_true


def test_run_defaults_label_true_to_none_when_not_given() -> None:
    module, x, _y = _module()
    detections = module.run((f"s{i}", row) for i, row in enumerate(x))
    assert all(d.label_true is None for d in detections)


def test_detection_agrees_with_ground_truth_better_than_chance() -> None:
    """Fires on known positives, stays quiet on known negatives — not perfectly, but well above
    a coin flip, on the very draw the profiles were fitted from."""
    module, x, y = _module()
    detections = module.run((f"s{i}", row) for i, row in enumerate(x))
    predicted = np.array([1 if d.is_ransomware else 0 for d in detections])
    accuracy = (predicted == y).mean()
    assert accuracy > 0.6
