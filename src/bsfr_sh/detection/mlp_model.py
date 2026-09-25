"""A small MLP detector, plugged into the same `NProf`/`AProf` machinery as Table II's four
algorithms. M7-10, DEV-36.

M7-8 found that Random-Forest adversarial retraining hardens against M7-3's attack at 50%/100%
training budget, but by learning "values near the evasion bound" as its own signature rather than
a more robust representation — the 100%-budget model's combined-evasion curve *rises* with
perturbation instead of degrading. The open question this module exists to help answer: is that a
property of tree ensembles specifically, or of the 22-feature space itself? A tree ensemble's
axis-aligned splits can memorize a boundary region in a way a distributed representation might not
— or might, just as easily; this module supplies the second detector so `scripts/
m7_10b_neural_detector.py` can measure the difference rather than assume it.

Design: `detection.profiles.ensemble_score` already averages `predict_proba` across whatever is
in the `models` mapping it is given; with exactly one entry, that average is just the one model's
own score. So `train_mlp` below returns `{"mlp": <fitted MLPClassifier>}` in the same shape
`detection.models.train_all` returns for the four-model ensemble, and every downstream consumer
(`detection.profiles.build`, `detection.detector.DetectionModule`, `detection.adversarial`,
`detection.retraining.augment_positive_rows`) runs completely unchanged against it. This is
`detection/`'s only supported way to compare a different model against the paper's four without
forking any of that machinery (same "reuse, don't fork" posture M7-3/M7-7/M7-8 established).

Kept as its own module rather than folded into `detection.models` because `models.MODEL_NAMES` is
Table II's exact four algorithms (CLAUDE.md §7); an MLP is not one of them and must never become a
silent fifth entrant into that table.
"""

from __future__ import annotations

from typing import Any

from sklearn.neural_network import MLPClassifier

from bsfr_sh.util.config import Config

__all__ = ["MODEL_NAME", "build_mlp", "train_mlp"]

#: The single key `train_mlp`'s returned mapping uses — mirrors `detection.models.MODEL_NAMES`'s
#: role for the four-model ensemble, but there is exactly one name here by construction.
MODEL_NAME = "mlp"


def build_mlp(config: Config, *, seed: int) -> MLPClassifier:
    """One `MLPClassifier`, built from `configs/ml.yaml`'s declared `mlp_detector` hyperparameters
    with the seed injected — same posture as `detection.models.build_model`."""
    params: dict[str, Any] = dict(config.require("mlp_detector", dict))
    params.pop("enabled", None)
    return MLPClassifier(random_state=seed, **params)


def train_mlp(x_train: Any, y_train: Any, config: Config, *, seed: int) -> dict[str, MLPClassifier]:
    """Fit one MLP and return it as a single-entry `models` mapping — the same shape
    `detection.models.train_all` returns for the four-model ensemble, so `detection.profiles.
    build` and everything downstream of it need no change to consume either."""
    model = build_mlp(config, seed=seed)
    model.fit(x_train, y_train)
    return {MODEL_NAME: model}
