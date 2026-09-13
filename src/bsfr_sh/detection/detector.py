"""`DM_CSl`'s real-time loop. Implements Alg. 3, lines 4-9.

Line 4 starts detection; lines 5-9 are "if `RW` detected, call Algorithm 4 (mitigation), else
loop back to line 4." Phase 4 does not exist yet (M5), so a positive cannot call into it. What
"call Algorithm 4" becomes here is an interface, `Phase4Handoff` — a callable Phase 4 will
eventually implement — plus the `Detection` event handed to it. `DetectionModule` never imports
`mitigation` and does not need to: this module raises the event, the eventual caller decides what
happens next. The loop itself never stops on a positive, honest or not — "call Algorithm 4, else
loop" is per-sample, not "stop monitoring once something is found."
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

import numpy as np
from sklearn.base import BaseEstimator

from bsfr_sh.detection.profiles import AbnormalProfile, NormalProfile, ensemble_score

__all__ = ["Detection", "DetectionModule", "Phase4Handoff"]


@dataclass(frozen=True)
class Detection:
    """Alg. 3's verdict for one sample — the event a positive hands to Phase 4.

    `label_true` is carried only for audits and metrics (it is what let this session compute
    precision/recall/MCC at all); the decision in `is_ransomware` never reads it.
    """

    sample_id: str
    is_ransomware: bool
    score: float
    normal_membership: float
    abnormal_membership: float
    label_true: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "sample_id": self.sample_id,
            "is_ransomware": self.is_ransomware,
            "score": self.score,
            "normal_membership": self.normal_membership,
            "abnormal_membership": self.abnormal_membership,
            "label_true": self.label_true,
        }


#: What Phase 4 will implement (M5). Called on every positive detection; never a call into
#: `mitigation` from here — that module does not exist yet, and `detection`/`framework.phase3`
#: must not reach for it before it does.
Phase4Handoff = Callable[[Detection], None]


@dataclass
class DetectionModule:
    """`DM_CSl`. Implements Alg. 3, lines 4-9: consume, decide via `NProf`/`AProf`, hand off."""

    models: Mapping[str, BaseEstimator]
    normal: NormalProfile
    abnormal: AbnormalProfile
    on_detect: Phase4Handoff | None = field(default=None)

    def decide(self, sample_id: str, x: np.ndarray, *, label_true: str | None = None) -> Detection:
        """Implements Alg. 3, line 4: one sample, scored against `NProf` and `AProf`.

        Detection is nearest-profile membership, not a raw model prediction — line 4 says
        "detect via NProf and AProf," and a call straight to `estimator.predict()` here would
        make the profiles built in line 3 decorative.
        """
        score = float(ensemble_score(self.models, np.asarray(x).reshape(1, -1))[0])
        normal_membership = self.normal.membership(score)
        abnormal_membership = self.abnormal.membership(score)
        detection = Detection(
            sample_id=sample_id,
            is_ransomware=abnormal_membership > normal_membership,
            score=score,
            normal_membership=normal_membership,
            abnormal_membership=abnormal_membership,
            label_true=label_true,
        )
        if detection.is_ransomware and self.on_detect is not None:
            self.on_detect(detection)  # lines 5-6: "call Algorithm 4" — the handoff interface
        return detection  # lines 7-9: re-loop regardless; monitoring never stops on one verdict

    def run(
        self,
        samples: Iterable[tuple[str, np.ndarray]],
        *,
        labels_true: Iterable[str | None] | None = None,
    ) -> tuple[Detection, ...]:
        """Implements Alg. 3, lines 4-9: the loop, over as many samples as it is given."""
        truths: Iterable[str | None] = (
            labels_true if labels_true is not None else itertools.repeat(None)
        )
        return tuple(
            self.decide(sample_id, x, label_true=truth)
            for (sample_id, x), truth in zip(samples, truths, strict=False)
        )
