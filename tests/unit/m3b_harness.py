"""M3b test harness: honeypot nodes, shared draws, and the two statistics the leakage tests need.

Not a test module. The AUC and baseline helpers live here rather than in `src/` on purpose: they
exist to *audit the generator*, not to detect anything, and M4 is where detection is built.
"""

from __future__ import annotations

import numpy as np
from m3a_harness import make_server
from pbft_harness import POLICY

from bsfr_sh.crypto.ecdsa import keypair_from_secret
from bsfr_sh.framework._block_pipeline import PipelinePolicy
from bsfr_sh.framework.entities import HoneypotNode
from bsfr_sh.honeypot import features as ft
from bsfr_sh.honeypot.collector import BENIGN, MALICIOUS, Honeypot, RawSample, synthesize
from bsfr_sh.honeypot.preprocess import CleanSample, clean

SEED = 4242
#: Small blocks so a handful of records still exercises the multi-block path.
SMALL = PipelinePolicy(transactions_per_block=4, wait_s=15 * POLICY.view_change_timeout_s)


def make_node(index: int = 1, *, seed: int = SEED) -> HoneypotNode:
    """`HP_RW`'s network side, with a honeypot attached and not yet deployed."""
    return HoneypotNode(
        identity=f"HP_{index}",
        keypair=keypair_from_secret(0x40F0_0000 + index),
        honeypot=Honeypot(honeypot_id=f"HP_{index}", seed=seed),
    )


def raw_draw(
    count: int = 400, *, seed: int = SEED, malicious_fraction: float = 0.5
) -> tuple[RawSample, ...]:
    return synthesize(count, seed=seed, malicious_fraction=malicious_fraction)


def clean_draw(count: int = 400, *, seed: int = SEED) -> tuple[CleanSample, ...]:
    return clean(raw_draw(count, seed=seed))[0]


def feature_matrix(samples: tuple[CleanSample, ...]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """(features, labels, missing-mask bits) for a cleaned draw."""
    vectors = [ft.build(sample) for sample in samples]
    x = np.array([v.values for v in vectors], dtype=float)
    y = np.array([1 if s.label == MALICIOUS else 0 for s in samples], dtype=int)
    missing = np.array(
        [[(v.missing_mask >> i) & 1 for i in range(len(ft.FEATURE_NAMES))] for v in vectors],
        dtype=int,
    )
    return x, y, missing


def auc(values: np.ndarray, labels: np.ndarray) -> float:
    """Rank AUC with ties averaged. 0.5 means the feature says nothing about the label."""
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(len(values), dtype=float)
    ranks[order] = np.arange(1, len(values) + 1, dtype=float)
    _, inverse = np.unique(values, return_inverse=True)
    inverse = inverse.ravel()
    sums = np.bincount(inverse, weights=ranks)
    counts = np.bincount(inverse)
    ranks = (sums / counts)[inverse]
    positives = int(labels.sum())
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return 0.5
    return float(
        (ranks[labels == 1].sum() - positives * (positives + 1) / 2) / (positives * negatives)
    )


def separability(values: np.ndarray, labels: np.ndarray) -> float:
    """How far one feature is from useless, on [0.5, 1.0]. 1.0 would be a perfect giveaway."""
    return abs(auc(values, labels) - 0.5) + 0.5


def baseline_balanced_accuracy(
    train: tuple[np.ndarray, np.ndarray], evaluate: tuple[np.ndarray, np.ndarray]
) -> float:
    """A diagonal Gaussian scorer fitted on one draw and scored on another.

    Deliberately the simplest thing that can work: this measures the *data*, and anything
    cleverer would start measuring the model instead — which is M4's job, not this session's.
    """
    x_train, y_train = train
    x_eval, y_eval = evaluate
    logx_train, logx_eval = np.log1p(np.clip(x_train, 0, None)), np.log1p(np.clip(x_eval, 0, None))
    means = np.array([logx_train[y_train == c].mean(axis=0) for c in (0, 1)])
    variances = np.array([logx_train[y_train == c].var(axis=0) + 1e-6 for c in (0, 1)])
    scores = np.array(
        [
            -0.5
            * (((logx_eval - means[c]) ** 2) / variances[c] + np.log(2 * np.pi * variances[c])).sum(
                axis=1
            )
            for c in (0, 1)
        ]
    )
    predicted = scores.argmax(axis=0)
    return float(
        0.5 * ((predicted[y_eval == 1] == 1).mean() + (predicted[y_eval == 0] == 0).mean())
    )


__all__ = [
    "BENIGN",
    "MALICIOUS",
    "SEED",
    "SMALL",
    "auc",
    "baseline_balanced_accuracy",
    "clean_draw",
    "feature_matrix",
    "make_node",
    "make_server",
    "raw_draw",
    "separability",
]
