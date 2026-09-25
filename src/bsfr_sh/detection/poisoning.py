"""Honeypot training-data poisoning: three attacks a Tier-2 adversary could stage against
`BC_SigRW`. M7-11, DEV-37, `docs/THREAT_MODEL.md` Gap 1.

M7-9's threat model named this gap without measuring it: a Tier-2 adversary who controls the
honeypot's own collection process can feed false training data into `Sig_RW`/`FT_RW`, and once
committed to `BC_SigRW`, the chain's own immutability certifies the poison as tamper-proof rather
than flagging it as false — the paper's central selling point (Algorithm 2 appends, nothing
deletes) works against the defender here, not for them. This module supplies the attack side —
three strategies modelling different adversary goals, each a pure function on the training arrays
`detection.retraining.augment_positive_rows` already established the pattern for — so
`scripts/m7_11_honeypot_poisoning.py` can sweep a budget against each and measure the damage. The
chain-commit and permanence argument (this gap's other half) live in that script, not here: this
module never touches `blockchain/` or `consensus/`, it only manipulates the arrays a detector is
fit on, same "no changes to the chain" posture the session's own OUT OF SCOPE line requires.

Budget convention: every strategy's `budget` is a fraction of the training set's positive
(ransomware) row count — "N% of the training corpus's ransomware samples" is the brief's own
phrasing for strategy (a), and the other two strategies use the same unit so a budget is
comparable across strategies. `budget <= 0.0` is a no-op for all three, returning the *original*
`x_train`/`y_train` objects unchanged rather than copies with zero effective poisoning — the same
degenerate-case convention `retraining.augment_positive_rows` established, so a 0%-budget cell
reproduces the unpoisoned fit exactly, not approximately.

The eval set is never touched by anything in this module — these are training-time attacks; a
poisoned detector is still evaluated against the real, unpoisoned distribution it will actually
face in deployment.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

__all__ = [
    "PoisonResult",
    "anchor_point_injection",
    "feature_poison",
    "label_flip",
]


@dataclass(frozen=True)
class PoisonResult:
    """One poisoning strategy's output: the (possibly larger) training arrays, and how much of
    it is the adversary's own contribution."""

    x: np.ndarray
    y: np.ndarray
    n_poisoned: int
    #: Row indices *within the returned `x`/`y`* that are the adversary's contribution — for
    #: label flipping these are relabeled originals; for the two injection strategies these are
    #: newly-appended rows, always at the tail.
    poisoned_row_indices: tuple[int, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "n_rows": len(self.y),
            "n_poisoned": self.n_poisoned,
            "n_positive": int((self.y == 1).sum()),
            "n_negative": int((self.y == 0).sum()),
        }


def _n_from_budget(budget: float, n_positive: int) -> int:
    return round(budget * n_positive) if budget > 0.0 else 0


def label_flip(
    x_train: np.ndarray, y_train: np.ndarray, budget: float, *, rng: np.random.Generator
) -> PoisonResult:
    """Strategy (a): relabel `budget` fraction of ransomware training rows as benign.

    Features are untouched — the adversary's injected "benign" samples are real ransomware
    behavioural traces, teaching the detector that ransomware behaviour is normal. The simplest
    attack, and per the session brief, the one most likely to succeed: it does not need the
    adversary to fabricate any feature values at all, only to mislabel real ones.
    """
    positive_idx = np.flatnonzero(y_train == 1)
    n_flip = _n_from_budget(budget, len(positive_idx))
    if n_flip <= 0:
        return PoisonResult(x_train, y_train, 0, ())
    flip_idx = rng.choice(positive_idx, size=n_flip, replace=False)
    y = y_train.copy()
    y[flip_idx] = 0
    return PoisonResult(x_train, y, n_flip, tuple(sorted(int(i) for i in flip_idx)))


def feature_poison(
    x_train: np.ndarray, y_train: np.ndarray, budget: float, *, rng: np.random.Generator
) -> PoisonResult:
    """Strategy (b): inject synthetic rows labelled ransomware with benign-looking features.

    Each injected row's features are resampled (with replacement) from the real *benign* training
    rows, then relabelled ransomware. This teaches the detector a wrong definition of ransomware —
    it learns to associate the ransomware label with feature patterns that are actually benign,
    which both raises false positives on real benign traffic that resembles the injected rows and
    (more importantly for an attacker) blurs the profile `AProf` fits, diluting its ability to
    recognise real ransomware feature patterns.
    """
    positive_idx = np.flatnonzero(y_train == 1)
    negative_idx = np.flatnonzero(y_train == 0)
    n_inject = _n_from_budget(budget, len(positive_idx))
    if n_inject <= 0:
        return PoisonResult(x_train, y_train, 0, ())
    source_idx = rng.choice(negative_idx, size=n_inject, replace=True)
    injected_x = x_train[source_idx]
    injected_y = np.ones(n_inject, dtype=y_train.dtype)
    x = np.concatenate([x_train, injected_x], axis=0)
    y = np.concatenate([y_train, injected_y])
    return PoisonResult(x, y, n_inject, tuple(range(len(x_train), len(x))))


#: How far from the benign centroid toward the ransomware centroid the injected anchor points
#: sit. 0.5 is the naive linear midpoint between the two classes' own per-feature means — points
#: an unpoisoned model would treat as maximally ambiguous. Labelling them benign teaches the
#: model that even the region right at the boundary is benign, which is exactly "push the
#: boundary toward the ransomware centroid": the effective region the model will still call
#: ransomware shrinks to sit closer to the ransomware centroid than the true midpoint.
ANCHOR_INTERPOLATION: float = 0.5
#: Small jitter (as a fraction of each feature's benign-class standard deviation) so `n_inject`
#: anchor points are not literally identical rows — identical rows are an unrealistic attacker
#: footprint and would give KNN/RF pathological, all-or-nothing neighbour behaviour on one exact
#: point rather than a modelled region.
ANCHOR_JITTER_FRACTION: float = 0.05


def anchor_point_injection(
    x_train: np.ndarray, y_train: np.ndarray, budget: float, *, rng: np.random.Generator
) -> PoisonResult:
    """Strategy (c): inject samples at the inter-class boundary, labelled to push the decision
    boundary toward the ransomware centroid.

    Unlike (a)/(b), this does not flip a real label or fabricate an obviously-wrong feature
    vector — every injected row sits at a physically plausible point *between* the two classes'
    own observed centroids, jittered so no two are identical, and labelled benign. This is the
    most sophisticated of the three attacks: it does not lie about what a specific sample is, it
    lies about where the line between the classes should be drawn.
    """
    positive_idx = np.flatnonzero(y_train == 1)
    negative_idx = np.flatnonzero(y_train == 0)
    n_inject = _n_from_budget(budget, len(positive_idx))
    if n_inject <= 0:
        return PoisonResult(x_train, y_train, 0, ())
    benign_centroid = x_train[negative_idx].mean(axis=0)
    malicious_centroid = x_train[positive_idx].mean(axis=0)
    anchor = benign_centroid + ANCHOR_INTERPOLATION * (malicious_centroid - benign_centroid)
    noise_scale = x_train[negative_idx].std(axis=0) * ANCHOR_JITTER_FRACTION
    jitter = rng.normal(0.0, 1.0, size=(n_inject, x_train.shape[1])) * noise_scale
    injected_x = anchor + jitter
    injected_y = np.zeros(n_inject, dtype=y_train.dtype)
    x = np.concatenate([x_train, injected_x], axis=0)
    y = np.concatenate([y_train, injected_y])
    return PoisonResult(x, y, n_inject, tuple(range(len(x_train), len(x))))
