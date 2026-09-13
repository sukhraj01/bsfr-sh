"""`NProf` / `AProf` — Alg. 3, line 3. `docs/NOTATION.md`: `NormalProfile`, `AbnormalProfile`.

The paper says only that these are "definitions of normal and abnormal files... built via the
four algorithms" and never says what a definition *is*. Collapsing them into "whatever the
classifier predicts" would make line 3 disappear into line 2, and line 4's "detect via NProf and
AProf" would have nothing to detect *via*. So here a profile is the fitted class-conditional
description of `DM_CSl`'s own behaviour on one class's training rows: the mean and spread of the
four trained models' soft-vote score, plus that class's mean feature vector for interpretability.

Detection (`detection.detector`) then asks which profile a sample's score sits closer to —
nearest-profile membership, not a bare threshold pulled from nowhere. That is what ties line 2
(the four algorithms), line 3 (the profiles) and line 4 (detection through them) into one
mechanism instead of three unrelated steps. This is our design, not the paper's, in the same
spirit as `honeypot`'s DEV-03/DEV-26/DEV-27: named here so the next session does not have to infer
it from the code.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

import numpy as np
from sklearn.base import BaseEstimator

from bsfr_sh.honeypot.collector import BENIGN, MALICIOUS

__all__ = ["AbnormalProfile", "NormalProfile", "Profile", "ProfileError", "build", "ensemble_score"]

_EPS: Final = 1e-9


class ProfileError(ValueError):
    """Raised when a profile cannot be built from the training draw given."""


def ensemble_score(models: Mapping[str, BaseEstimator], x: np.ndarray) -> np.ndarray:
    """`DM_CSl`'s soft-vote P(malicious) per row: the mean predicted probability across every
    trained model that reports one, falling back to the hard label for one that does not.

    All four of `configs/ml.yaml`'s declared models expose `predict_proba`, so the fallback is
    defensive rather than load-bearing — the same posture `models.fit_and_score` takes.
    """
    if not models:
        raise ProfileError("no trained models to score with; call detection.models.train_all first")
    votes: list[np.ndarray] = []
    for estimator in models.values():
        if hasattr(estimator, "predict_proba"):
            proba = estimator.predict_proba(x)
            votes.append(proba[:, 1] if proba.shape[1] == 2 else proba[:, 0])
        else:
            votes.append(estimator.predict(x).astype(np.float64))
    result: np.ndarray = np.mean(np.vstack(votes), axis=0)
    return result


@dataclass(frozen=True)
class Profile:
    """Shared shape of `NormalProfile` (`NProf`) and `AbnormalProfile` (`AProf`)."""

    label: str
    n_samples: int
    score_mean: float
    score_std: float
    feature_means: tuple[float, ...]
    feature_names: tuple[str, ...]

    def membership(self, score: float) -> float:
        """How consistent one ensemble score is with this profile. Higher is a closer match.

        Negative squared z-score under this profile's fitted score distribution: 0 at the
        profile's own mean, falling off as the score moves away from it in either direction.
        """
        spread = max(self.score_std, _EPS)
        return -(((score - self.score_mean) / spread) ** 2)

    def as_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "n_samples": self.n_samples,
            "score_mean": self.score_mean,
            "score_std": self.score_std,
        }


@dataclass(frozen=True)
class NormalProfile(Profile):
    """`NProf` — the benign class's fitted description."""


@dataclass(frozen=True)
class AbnormalProfile(Profile):
    """`AProf` — the malicious class's fitted description."""


def build(
    models: Mapping[str, BaseEstimator],
    x_train: np.ndarray,
    y_train: np.ndarray,
    *,
    feature_names: tuple[str, ...],
) -> tuple[NormalProfile, AbnormalProfile]:
    """Implements Alg. 3, line 3: `NProf` and `AProf`, fitted from `DM_CSl`'s trained models.

    `models` must already be fitted (`detection.models.train_all`); this function only reads
    their predictions, it does not train anything.
    """
    if len(x_train) != len(y_train):
        raise ProfileError(f"x_train has {len(x_train)} rows, y_train has {len(y_train)}")
    scores = ensemble_score(models, x_train)
    x = np.asarray(x_train)

    def _fit(class_value: int, label: str) -> tuple[int, float, float, tuple[float, ...]]:
        mask = y_train == class_value
        if not mask.any():
            raise ProfileError(
                f"no {label!r} rows in the training draw; cannot build a profile for it"
            )
        means = tuple(float(v) for v in x[mask].mean(axis=0))
        return int(mask.sum()), float(scores[mask].mean()), float(scores[mask].std()), means

    n_benign, mean_benign, std_benign, features_benign = _fit(0, BENIGN)
    normal = NormalProfile(
        label=BENIGN,
        n_samples=n_benign,
        score_mean=mean_benign,
        score_std=std_benign,
        feature_means=features_benign,
        feature_names=feature_names,
    )
    n_malicious, mean_malicious, std_malicious, features_malicious = _fit(1, MALICIOUS)
    abnormal = AbnormalProfile(
        label=MALICIOUS,
        n_samples=n_malicious,
        score_mean=mean_malicious,
        score_std=std_malicious,
        feature_means=features_malicious,
        feature_names=feature_names,
    )
    return normal, abnormal
