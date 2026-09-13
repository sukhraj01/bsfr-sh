"""Phase 3: Alg. 3, ML-based ransomware detection through `BC_SigRW`. Output: a verdict per
honeypot sample, ready to hand off to Phase 4 (M5).

* **line 1**, decrypt `BC_SigRW` into `Sig_RW`/`FT_RW`: `detection.dataset.load_from_chain()`,
  called once on a training chain and once on an evaluation chain — two independent draws, never
  one chain playing both roles (the same train/eval hygiene `honeypot.corpus` enforces on disk).
* **line 2**, train `DM_CSl` on RFor/LReg/DTree/KNN: `detection.models.train_all()`.
* **line 3**, build `NProf`/`AProf`: `detection.profiles.build()`.
* **line 4**, start detection: `detection.detector.DetectionModule.run()`.
* **lines 5-9**, hand off on a positive, else re-loop: `DetectionModule` itself, via `on_detect`;
  this module just wires the pieces together and reports what happened.

FLAW-2, closed for the framework's own path
--------------------------------------------
`docs/PAPER_NOTES.md` §IV-C: the paper describes Phase 3 consuming honeypot program features and
then evaluates on Bitcoin addresses instead — the framework half and the evaluation half never
connect. M4a reproduced the evaluation half (`scripts/run_detection.py`,
`detection.dataset.BitcoinHeistBackend`). This module is the framework half: `train_chain` and
`eval_chain` are `BC_SigRW` chains a caller built with `framework.phase2_collection.run()` (or an
equivalent harness) — this module never reads the committed CSV corpus directly. Those files are
Q9's fixed dataset for reproducible offline experiments; this phase only ever sees what Phase 2
put on the chain, which is the thing the paper's own sequence diagram (Fig. 3) requires and never
demonstrates.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from bsfr_sh.blockchain.chain import Chain
from bsfr_sh.detection import metrics as detection_metrics
from bsfr_sh.detection import models as detection_models
from bsfr_sh.detection import profiles as detection_profiles
from bsfr_sh.detection.dataset import Decryptor, DetectionDataset, load_from_chain
from bsfr_sh.detection.detector import Detection, DetectionModule, Phase4Handoff
from bsfr_sh.util.config import Config

__all__ = ["Phase3Report", "run"]


@dataclass(frozen=True)
class Phase3Report:
    """What one Phase 3 run trained on, profiled, and detected."""

    train: DetectionDataset
    evaluation: DetectionDataset
    detections: tuple[Detection, ...]
    honest: detection_metrics.HonestMetrics
    baselines: detection_metrics.BaselineSet

    @property
    def positives_detected(self) -> int:
        return sum(1 for detection in self.detections if detection.is_ransomware)

    def as_dict(self) -> dict[str, object]:
        return {
            "train": self.train.as_dict(),
            "evaluation": self.evaluation.as_dict(),
            "positives_detected": self.positives_detected,
            "honest": self.honest.as_dict(),
            "baselines": self.baselines.as_dict(),
        }


def run(
    *,
    train_chain: Chain,
    eval_chain: Chain,
    decrypt: Decryptor,
    config: Config,
    seed: int,
    on_detect: Phase4Handoff | None = None,
) -> Phase3Report:
    """Implements Alg. 3, lines 1-9, end to end from two already-built `BC_SigRW` chains.

    `train_chain` and `eval_chain` must already hold the two draws (Phase 2's job, or a test
    harness standing in for it) — this function only reads them; it never runs a honeypot, signs
    a sample, or touches consensus (`test_detection_does_not_orchestrate` pins that boundary for
    `detection/`, and this module keeps the same discipline even though `framework/` is allowed
    more).
    """
    train = load_from_chain(train_chain, decrypt)
    evaluation = load_from_chain(eval_chain, decrypt)

    models = detection_models.train_all(train.features, train.labels, config, seed=seed)
    normal, abnormal = detection_profiles.build(
        models, train.features, train.labels, feature_names=train.feature_names
    )
    detector = DetectionModule(models=models, normal=normal, abnormal=abnormal, on_detect=on_detect)

    labels_true = ["RW" if label else "benign" for label in evaluation.labels]
    detections = detector.run(
        zip(evaluation.sample_ids, evaluation.features, strict=True), labels_true=labels_true
    )

    predictions = np.array(
        [1 if detection.is_ransomware else 0 for detection in detections], dtype=np.int8
    )
    scores = np.array(
        [detection.abnormal_membership - detection.normal_membership for detection in detections]
    )
    baselines = detection_metrics.baselines(evaluation.labels, seed=seed)
    honest = detection_metrics.honest_metrics(evaluation.labels, predictions, scores)
    return Phase3Report(
        train=train,
        evaluation=evaluation,
        detections=detections,
        honest=honest,
        baselines=baselines,
    )
