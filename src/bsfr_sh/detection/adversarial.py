"""Feature-space evasion primitives against the honeypot ensemble. M7-3 / M7-8.

The paper implicitly assumes `FT_RW` is unconditionally robust: Alg. 3 observes it, but nothing
in Alg. 3-4 asks whether a rational attacker could adjust their program's *observable* behaviour
to defeat detection. Only having built `FT_RW` ourselves (DEV-03, DEV-27) makes that question
answerable, since it needs a defined, differentiable feature pipeline the paper never provides
(FLAW-2). This module holds the mechanics — perturbation, batched ensemble scoring, degradation
curves, per-sample adaptive search — so two experiments can share one tested implementation:
`scripts/run_adversarial_robustness.py` (M7-3, measures the attack) and
`scripts/m7_8_adversarial_retraining.py` (M7-8, measures a defense against it). M7-3's own script
predates this module and keeps its own equivalent inline (an already-published, numbered result;
left untouched to avoid regression risk); this module is the same logic, factored out so M7-8 can
reuse and unit-test it rather than re-deriving or duplicating it wholesale.

Safety (CLAUDE.md §2): every perturbation here is arithmetic on a `numpy.ndarray` of floats — a
row of `FT_RW`. No malware is generated, modified, or executed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

import numpy as np

from bsfr_sh.detection import profiles as detection_profiles
from bsfr_sh.detection.detector import DetectionModule

__all__ = [
    "FEATURE_BOUNDS",
    "IMPORTANCE_CANDIDATES",
    "STEPS",
    "TOP_N",
    "USELESS_THRESHOLD",
    "FeatureBound",
    "adaptive_evasion",
    "apply_perturbation",
    "balanced_accuracy",
    "combined_curve",
    "ensemble_predict",
    "select_best_importance_model",
    "single_feature_curves",
    "top_feature_importances",
]

#: Constant-positive on the committed eval draw is exactly 0.50 (mean of 100% sensitivity on
#: positives, 0% specificity on negatives).
USELESS_THRESHOLD: Final = 0.50
#: 0%, 10%, ..., 100% of each feature's evasion range.
STEPS: Final = tuple(round(i / 10, 1) for i in range(11))
_ADAPTIVE_GRID = 101
_ADAPTIVE_BISECT_TOL = 1e-4

#: Two candidates for 'the best model' (whichever scores higher individually is used for feature
#: importance) — the only two of `configs/ml.yaml`'s four with `.feature_importances_`.
IMPORTANCE_CANDIDATES: Final = ("random_forest", "decision_tree")
TOP_N: Final = 5


@dataclass(frozen=True)
class FeatureBound:
    """One feature's evasion direction and physical bound, and why.

    `direction` is `-1.0` (attacker decreases the feature toward the bound) or `+1.0` (increases).
    `bound` is the value 100% perturbation reaches; `justification` is the one-sentence physical
    argument for why that bound, and no further, is reachable.
    """

    direction: float
    bound: float
    justification: str


#: Grounded in `honeypot/collector.py`'s own generator distributions and the committed corpus's
#: own observed range (train + eval) — never an arbitrary constant. Identical to
#: `scripts/run_adversarial_robustness.py::FEATURE_BOUNDS` (M7-3); kept in lockstep by
#: construction so M7-8's hardening budget is measured against the same attack M7-3 measured.
FEATURE_BOUNDS: dict[str, FeatureBound] = {
    "observed_stages": FeatureBound(
        direction=-1.0,
        bound=0.0,
        justification=(
            "An attacker throttles the kill-chain's progression (a low-and-slow variant, "
            "already one of the generator's own malicious profiles) so fewer of the four "
            "observable stages complete inside the honeypot's finite dwell time; floor 0 is the "
            "honeypot observing none of them, which also means nothing was encrypted yet."
        ),
    ),
    "extension_change_rate": FeatureBound(
        direction=-1.0,
        bound=0.0,
        justification=(
            "An attacker renames files less aggressively (or not at all, e.g. in-place "
            "encryption with no extension change); floor 0 is not renaming anything, which "
            "weakens the attack's own after-the-fact leverage but is physically reachable."
        ),
    ),
    "rename_rate_per_s": FeatureBound(
        direction=-1.0,
        bound=0.0,
        justification=(
            "An attacker throttles the encryption/rename loop to blend into ordinary "
            "filesystem I/O rates; floor 0 is renaming nothing per second."
        ),
    ),
    "write_entropy_var": FeatureBound(
        direction=+1.0,
        bound=6.5494,
        justification=(
            "Ransomware writes are consistently near-maximal entropy (low variance across "
            "blocks); benign software's writes are heterogeneous (mixed compressible/"
            "incompressible data, headers, metadata). An attacker raises variance by "
            "interleaving some deliberately low-entropy writes among the ciphertext. The bound "
            "is not arbitrary: it is the highest write_entropy_var the generator's own benign "
            "profiles are ever observed to produce in the committed corpus (train + eval) — "
            "an attacker cannot manufacture heterogeneity beyond what a real, non-malicious "
            "write pattern in this environment exhibits."
        ),
    ),
    "crypto_ngram_novelty": FeatureBound(
        direction=-1.0,
        bound=0.0,
        justification=(
            "An attacker mimics a common, previously-seen crypto-API call sequence (e.g. a "
            "standard TLS/disk-encryption library's pattern) instead of a distinctive one; "
            "floor 0 is a call sequence indistinguishable from known, whitelisted patterns."
        ),
    ),
}


def balanced_accuracy(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """Mean of per-class recall — matches `sklearn.metrics.balanced_accuracy_score` for binary
    labels, computed locally so this module's only sklearn dependency stays the estimators."""
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    sensitivity = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    return (sensitivity + specificity) / 2.0


def select_best_importance_model(
    config: Any,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    *,
    seed: int,
) -> tuple[str, Any, float]:
    """Fit RF and DT individually; return the name/estimator/bal_acc of whichever scores higher."""
    from bsfr_sh.detection import models as detection_models

    best_name = ""
    best_model: Any = None
    best_score = -1.0
    for name in IMPORTANCE_CANDIDATES:
        model = detection_models.build_model(config, name, seed=seed)
        model.fit(x_train, y_train)
        score = balanced_accuracy(y_eval, model.predict(x_eval))
        if score > best_score:
            best_name, best_model, best_score = name, model, score
    return best_name, best_model, best_score


def top_feature_importances(
    model: Any, feature_names: tuple[str, ...], n: int
) -> list[tuple[str, float]]:
    importances = model.feature_importances_
    order = np.argsort(importances)[::-1]
    return [(feature_names[i], float(importances[i])) for i in order[:n]]


def apply_perturbation(
    x: np.ndarray,
    y: np.ndarray,
    feature_indices: list[int],
    bounds: list[FeatureBound],
    frac: float,
) -> np.ndarray:
    """Move every malicious row's chosen features `frac` of the way to their evasion bound.

    Benign rows (`y == 0`) are never touched. Linear interpolation: `frac=0` is the original
    value, `frac=1` is exactly the bound.
    """
    perturbed = x.copy()
    positive = y == 1
    for index, fb in zip(feature_indices, bounds, strict=True):
        original = x[positive, index]
        perturbed[positive, index] = original + frac * (fb.bound - original)
    return perturbed


def ensemble_predict(detector: DetectionModule, x: np.ndarray) -> np.ndarray:
    """Batched equivalent of calling `DetectionModule.decide()` once per row.

    `detection.profiles.ensemble_score` already vectorizes over rows; the two `Profile.membership`
    calls it feeds are a scalar formula (`-(((score-mean)/std)**2`) applied elementwise here
    rather than through `Profile.membership` itself, computing exactly what `decide()` computes,
    batched, with no change to `detection/`.
    """
    scores = detection_profiles.ensemble_score(detector.models, x)
    normal_spread = max(detector.normal.score_std, 1e-9)
    abnormal_spread = max(detector.abnormal.score_std, 1e-9)
    normal_membership = -(((scores - detector.normal.score_mean) / normal_spread) ** 2)
    abnormal_membership = -(((scores - detector.abnormal.score_mean) / abnormal_spread) ** 2)
    return (abnormal_membership > normal_membership).astype(np.int8)


def single_feature_curves(
    detector: DetectionModule,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    top5: list[str],
    feature_index: dict[str, int],
) -> dict[str, list[float]]:
    curves: dict[str, list[float]] = {}
    for name in top5:
        fb = FEATURE_BOUNDS[name]
        idx = feature_index[name]
        curve = []
        for frac in STEPS:
            perturbed = apply_perturbation(x_eval, y_eval, [idx], [fb], frac)
            pred = ensemble_predict(detector, perturbed)
            curve.append(balanced_accuracy(y_eval, pred))
        curves[name] = curve
    return curves


def combined_curve(
    detector: DetectionModule,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    top5: list[str],
    feature_index: dict[str, int],
) -> list[float]:
    indices = [feature_index[name] for name in top5]
    bounds = [FEATURE_BOUNDS[name] for name in top5]
    curve = []
    for frac in STEPS:
        perturbed = apply_perturbation(x_eval, y_eval, indices, bounds, frac)
        pred = ensemble_predict(detector, perturbed)
        curve.append(balanced_accuracy(y_eval, pred))
    return curve


def adaptive_evasion(
    detector: DetectionModule,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    top5: list[str],
    feature_index: dict[str, int],
) -> dict[str, Any]:
    """Per positive sample: the minimum combined-perturbation fraction `t` in [0, 1] that flips
    the ensemble's verdict, at every one of the top-5 features moved by the same `t` toward its
    bound simultaneously (the L-inf ball of radius `t`).

    A coarse grid first, then bisection between the last non-flip and first-flip grid points,
    because the ensemble's membership functions are downward parabolas and are not guaranteed
    globally monotonic in `t` — the grid scan catches that; only the final local refinement
    assumes monotonicity, over an interval small enough (1/100 of the range) that it holds.
    """
    indices = [feature_index[name] for name in top5]
    bounds_arr = np.array([FEATURE_BOUNDS[name].bound for name in top5])
    positive_rows = np.flatnonzero(y_eval == 1)
    x_pos = x_eval[positive_rows]
    orig = x_pos[:, indices]
    n_positive = len(positive_rows)

    def batched_pred(t_vec: np.ndarray) -> np.ndarray:
        moved = x_pos.copy()
        moved[:, indices] = orig + t_vec.reshape(-1, 1) * (bounds_arr - orig)
        return ensemble_predict(detector, moved)

    grid = np.linspace(0.0, 1.0, _ADAPTIVE_GRID)
    last_positive_t = np.zeros(n_positive)
    flip_t = np.full(n_positive, np.nan)
    flipped = np.zeros(n_positive, dtype=bool)
    for t in grid:
        pred = batched_pred(np.full(n_positive, t))
        newly_flipped = (pred == 0) & ~flipped
        flip_t[newly_flipped] = t
        flipped |= newly_flipped
        last_positive_t[(pred == 1) & ~flipped] = t
        if flipped.all():
            break

    lo = last_positive_t.copy()
    hi = np.where(flipped, flip_t, 1.0)
    active = flipped.copy()
    while active.any():
        idx = np.flatnonzero(active)
        if float(np.max(hi[idx] - lo[idx])) <= _ADAPTIVE_BISECT_TOL:
            break
        mid_full = np.zeros(n_positive)
        mid_full[idx] = (lo[idx] + hi[idx]) / 2.0
        pred = batched_pred(mid_full)
        still_ransomware = pred[idx] == 1
        lo[idx] = np.where(still_ransomware, mid_full[idx], lo[idx])
        hi[idx] = np.where(still_ransomware, hi[idx], mid_full[idx])
        active[idx[(hi[idx] - lo[idx]) <= _ADAPTIVE_BISECT_TOL]] = False

    minima = np.where(flipped, hi, 1.0)
    survivors = np.flatnonzero(~flipped)
    return {
        "n_positive": int(n_positive),
        "minima": minima.tolist(),
        "median": float(np.median(minima)),
        "p10": float(np.percentile(minima, 10)),
        "p90": float(np.percentile(minima, 90)),
        "n_survivors_at_t1": len(survivors),
        "survivor_row_indices": [int(positive_rows[i]) for i in survivors],
    }
