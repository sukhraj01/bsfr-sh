"""Adversarial retraining: augmenting the training draw with perturbed positive copies. M7-8.

M7-3 (`detection.adversarial`) measures the attack: how far an adversary can move the top-5
Random-Forest-important features before the ensemble collapses. This module builds the training
side of the defense the same session's own exit criterion asks for — does fitting on perturbed
positives make the fragile samples robust, and at what cost on clean data?

Only positive (ransomware) training rows are perturbed. The adversary this module simulates is
the attacker trying to evade detection, not a defender trying to poison the corpus — perturbing
benign rows would be a different (data-poisoning) threat model this session does not test.
The eval corpus is never touched here; augmentation only ever reads/writes training arrays passed
in by the caller, which per DEV-27's "committed corpus is the fixed dataset" convention are always
the committed `corpus_train.csv`, never `corpus_eval.csv`.
"""

from __future__ import annotations

import numpy as np

from bsfr_sh.detection.adversarial import FeatureBound

__all__ = ["augment_positive_rows"]


def augment_positive_rows(
    x_train: np.ndarray,
    y_train: np.ndarray,
    feature_indices: list[int],
    bounds: list[FeatureBound],
    *,
    k: int,
    max_perturbation: float,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray]:
    """`k` perturbed copies of every positive (`y_train == 1`) row, appended to the training set.

    Each copy draws one perturbation fraction per feature, independently, from
    `Uniform(0, max_perturbation)` — not a single shared fraction across all five features (that
    is `detection.adversarial.combined_curve`'s L-inf-ball model, the right shape for measuring
    *an* attacker's worst case; this is instead meant to expose the hardened model to the whole
    diversity of partial-evasion attempts a population of attackers might produce). Each feature
    moves toward its own evasion bound by that fraction, exactly as `apply_perturbation` does.

    `max_perturbation <= 0.0` is a no-op: `x_train`/`y_train` are returned unchanged rather than
    with `k` exact-duplicate copies of every positive row appended. Appending duplicates would
    still change the training multiset (and, through `RandomForestClassifier`'s bootstrap
    resampling, the fitted trees) even though every one of those duplicate rows carries zero new
    information — the degenerate "no augmentation" case should train on the *same* draw the
    original model saw, not a class-rebalanced one, so it reproduces the same fit.
    """
    if k <= 0 or max_perturbation <= 0.0:
        return x_train, y_train

    positive_idx = np.flatnonzero(y_train == 1)
    n_positive = len(positive_idx)
    base = x_train[positive_idx]

    copies = []
    for _ in range(k):
        fracs = rng.uniform(0.0, max_perturbation, size=(n_positive, len(feature_indices)))
        rows = base.copy()
        for col, (index, fb) in enumerate(zip(feature_indices, bounds, strict=True)):
            original = rows[:, index]
            rows[:, index] = original + fracs[:, col] * (fb.bound - original)
        copies.append(rows)

    x_aug = np.concatenate([x_train, *copies], axis=0)
    y_aug = np.concatenate([y_train, np.ones(k * n_positive, dtype=y_train.dtype)])
    return x_aug, y_aug
