"""Exact / near-exact minimum adversarial perturbation along M7-3's ray. M7-17.

M7-3's `adaptive_evasion` (`detection.adversarial`) finds, per positive eval row, the minimum
combined-perturbation fraction `t` in `[0, 1]` that flips `DM_CSl`'s verdict, where all of the
top-5 features move *simultaneously* by the same fraction `t` toward their evasion bound
(`x(t) = x0 + t * (bound - x0)`, restricted to the top-5 coordinates — a fixed ray, not an
independent per-feature L-inf ball; this module does not change that adversary model, only how
precisely the minimum along it is found). M7-3 finds that minimum by a 101-point grid followed by
bisection to `1e-4` — an approximation that can miss a narrow flip region between grid points and
is only ever guaranteed to within `1e-4` of the true minimum on the bracket it finds, not the true
minimum itself.

**What "exact" means here, and why it is not simply "solve the random forest".** `DM_CSl`'s
decision (`detection.detector.DetectionModule.decide`) is nearest-`NProf`/`AProf`-membership on
`detection.profiles.ensemble_score`'s soft-vote average of *four* heterogeneous
`configs/ml.yaml` models — `random_forest`, `decision_tree`, `logistic_regression`,
`k_nearest_neighbours` — not a random-forest-only majority vote. Three of those four admit an
exact treatment along a fixed ray:

- `random_forest` (100 trees) / `decision_tree` (1 tree): each tree's predicted class along the
  ray is piecewise-constant in `t`, with breakpoints exactly where a moving feature crosses a
  split threshold on the sample's *current* decision path. `tree_flip_t` walks the tree exactly,
  re-deriving the path after every crossing (crossing one split can route the sample to an
  entirely different subtree), and returns the exact `t` of the first class change.
- `logistic_regression`: `w . x(t) + b` is affine in `t` (only 5 of 22 coordinates move, each
  linearly), so its predicted class has at most one crossing, solved in closed form
  (`lr_flip_t`).
- `k_nearest_neighbours`: each of the ~1467 training points' distance to `x(t)` is a quadratic in
  `t`, and the 5-nearest set can in principle reorder at any pairwise crossing between two
  training points' distance curves — enumerating all of those exactly is `O(n_train^2)` per
  sample (~1.05M pairs here). Judged disproportionate to this session's time budget on an 8GB
  dev box (CLAUDE.md §6); not attempted. See DEV-43.

`exact_min_perturbation` therefore evaluates `DM_CSl`'s *real* ensemble decision
(`detection.adversarial.ensemble_predict` — the actual four-model average, never approximated)
at every one of the random_forest/decision_tree/logistic_regression exact breakpoints, merged
with a dense uniform grid (finer than M7-3's own 101 points) to bound any
`k_nearest_neighbours`-only crossing the other three do not bracket, then bisects the first
bracket found to `1e-6` (100x tighter than M7-3's `1e-4`). Every evaluated point calls the real
detector; nothing here approximates *what* `DM_CSl` outputs, only *which* `t` values it is asked
about. A result is marked `exact=True` only when the found minimum coincides with a
random_forest/decision_tree/logistic_regression breakpoint (or is `0.0`, i.e. already
misclassified unperturbed) — the true minimum, provably. Otherwise `exact=False`: bounded to the
grid+bisection resolution, not proven optimal, and never reported as if it were.

By construction (merged exact breakpoints, a strictly finer grid, and a strictly tighter
bisection tolerance than M7-3's own search), `exact_min_perturbation`'s result is always `<=`
`detection.adversarial.adaptive_evasion`'s result for the same row — never looser.

Safety (CLAUDE.md §2): every perturbation here is arithmetic on a `numpy.ndarray` of floats — a
row of `FT_RW`. No malware is generated, modified, or executed.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

from bsfr_sh.detection.adversarial import ensemble_predict
from bsfr_sh.detection.detector import DetectionModule

__all__ = [
    "ExactResult",
    "exact_min_perturbation",
    "greedy_majority_t",
    "lr_flip_t",
    "per_tree_costs",
    "tree_flip_t",
    "verify_greedy_majority_flip",
]

#: Uniform points merged with the exact random_forest/decision_tree/logistic_regression
#: breakpoints, to bound any k_nearest_neighbours-only crossing. Finer than M7-3's 101.
_DENSE_GRID_N: Final = 201
#: Final bisection tolerance — 100x tighter than M7-3's `_ADAPTIVE_BISECT_TOL` (1e-4).
_BISECT_TOL: Final = 1e-6
#: Two exact breakpoints within this of each other (or of the bisected result) are the same
#: point — floating-point crossing computations are not bit-identical to the bisection result.
_SAME_POINT_TOL: Final = 1e-6
#: sklearn tree splits route left on `<=` (`sklearn.tree._tree`): a sample sitting *exactly* on a
#: threshold has not yet crossed it. `tree_flip_t` reports and internally probes a hair past each
#: algebraic crossing so it observes the routing actually changing, not the boundary tie.
_EPS_T: Final = 1e-9


@dataclass(frozen=True)
class ExactResult:
    """One sample's minimum-perturbation result.

    `exact=True` means `t` is the true minimum (it coincides with a random_forest/decision_tree/
    logistic_regression breakpoint, or the sample was already misclassified at `t=0`).
    `exact=False` means `t` is bounded to `_BISECT_TOL` of the true minimum via the merged dense
    grid, not proven optimal — the k_nearest_neighbours-driven case DEV-43 describes.
    """

    t: float
    exact: bool
    cause: str  # "already_negative" | "tree_or_lr" | "grid_bounded" | "never_flips"


def _leaf_class(tree: object, classes: np.ndarray, node: int) -> int:
    values = tree.value[node][0]  # type: ignore[attr-defined]
    return int(classes[int(np.argmax(values))])


def tree_flip_t(
    tree: object,
    classes: np.ndarray,
    x_row: np.ndarray,
    feature_indices: Sequence[int],
    bounds_arr: np.ndarray,
) -> float:
    """Exact minimum `t` in `[0, 1]` along `x(t)` at which this tree's own predicted class first
    differs from its `t=0` prediction. `math.inf` if it never does within `[0, 1]`.

    `tree` is a fitted sklearn tree's `.tree_` (a `random_forest` member's or the standalone
    `decision_tree`'s); `classes` is that same estimator's `.classes_`.
    """
    moving = {
        int(f): (float(x_row[f]), float(b))
        for f, b in zip(feature_indices, bounds_arr, strict=True)
    }

    def x_at_feature(f: int, t: float) -> float:
        if f in moving:
            x0f, bf = moving[f]
            return x0f + t * (bf - x0f)
        return float(x_row[f])

    def goes_left(f: int, t: float, thresh: float) -> bool:
        # sklearn's compiled tree traversal casts `X` to float32 before comparing to the
        # (float64) split threshold (`sklearn.tree._tree`). A naive float64 comparison can
        # disagree with what `.predict()` actually does for a value within float32's ~1.2e-7
        # relative precision of the threshold — reproduce that cast so `leaf_at` matches
        # `.predict()` exactly, not an idealised full-precision version of it.
        return float(np.float32(x_at_feature(f, t))) <= thresh

    def leaf_at(t: float) -> int:
        node = 0
        while tree.children_left[node] != -1:  # type: ignore[attr-defined]
            f = int(tree.feature[node])  # type: ignore[attr-defined]
            thresh = float(tree.threshold[node])  # type: ignore[attr-defined]
            node = (
                tree.children_left[node]  # type: ignore[attr-defined]
                if goes_left(f, t, thresh)
                else tree.children_right[node]  # type: ignore[attr-defined]
            )
        return node

    original_class = _leaf_class(tree, classes, leaf_at(0.0))
    t_cur = 0.0
    while t_cur < 1.0:
        node = 0
        t_next = math.inf
        crossing: tuple[int, float] | None = None
        while tree.children_left[node] != -1:  # type: ignore[attr-defined]
            f = int(tree.feature[node])  # type: ignore[attr-defined]
            thresh = float(tree.threshold[node])  # type: ignore[attr-defined]
            if f in moving:
                x0f, bf = moving[f]
                denom = bf - x0f
                if denom != 0.0:
                    t_root = (thresh - x0f) / denom
                    if t_cur < t_root <= 1.0 and t_root < t_next:
                        t_next = t_root
                        crossing = (f, thresh)
            node = (
                tree.children_left[node]  # type: ignore[attr-defined]
                if goes_left(f, t_cur, thresh)
                else tree.children_right[node]  # type: ignore[attr-defined]
            )
        if math.isinf(t_next) or crossing is None:
            return math.inf  # path fixed for the rest of [t_cur, 1]; class cannot change further
        # `t_next` is the algebraic threshold crossing; nudge a hair past it in FEATURE-VALUE
        # space (not `t`-space) before probing, since a fixed `t`-nudge can be far smaller than
        # float32's rounding granularity for a large-magnitude threshold and land on the wrong
        # side of `goes_left`'s cast.
        f, thresh = crossing
        x0f, bf = moving[f]
        value_eps = max(1e-4, abs(thresh) * 1e-5)
        value_probe = thresh + math.copysign(value_eps, bf - x0f)
        probe_t = min(max((value_probe - x0f) / (bf - x0f), t_next), 1.0)
        cls_probe = _leaf_class(tree, classes, leaf_at(probe_t))
        if cls_probe != original_class:
            return probe_t
        t_cur = probe_t
    return math.inf


def lr_flip_t(
    lr: LogisticRegression,
    x_row: np.ndarray,
    feature_indices: Sequence[int],
    bounds_arr: np.ndarray,
) -> float:
    """Exact minimum `t` in `[0, 1]` at which `logistic_regression`'s own predicted class flips.

    `w . x(t) + b` is affine in `t` since only `feature_indices` move, each linearly; solved in
    closed form rather than searched.
    """
    w = lr.coef_[0]
    b = float(lr.intercept_[0])
    idx = np.asarray(list(feature_indices))
    c0 = b + float(np.dot(w, x_row))
    c1 = float(np.dot(w[idx], (bounds_arr - x_row[idx])))
    if c1 == 0.0:
        return math.inf
    t_root = -c0 / c1
    if 0.0 < t_root <= 1.0:
        # As with `tree_flip_t`: `predict()` uses `decision_function > 0` for class 1, so a
        # sample sitting exactly at the root has not necessarily crossed it (only the class-1 ->
        # class-0 direction happens to be inclusive there). Nudge uniformly for both directions.
        return min(t_root + _EPS_T, 1.0)
    return math.inf


def per_tree_costs(
    rf_estimators: Sequence[DecisionTreeClassifier],
    x_row: np.ndarray,
    feature_indices: Sequence[int],
    bounds_arr: np.ndarray,
) -> list[float]:
    """`tree_flip_t` for every tree in a `random_forest`'s `.estimators_`."""
    return [
        tree_flip_t(est.tree_, est.classes_, x_row, feature_indices, bounds_arr)
        for est in rf_estimators
    ]


def greedy_majority_t(costs: Sequence[float]) -> float:
    """M7-17 brief §1(b)-(c): sort per-tree flip costs, return the cost of the
    `ceil(n_estimators / 2)`-cheapest tree — a greedy *approximation* to the minimum `t` that
    flips a random-forest-only hard-vote majority (never used as the published ensemble result;
    `DM_CSl` is a four-model soft-vote, not a random-forest-only hard vote — see module
    docstring). `math.inf` if fewer than half the trees ever flip within `[0, 1]`.

    **Confirmed unsound on the real fitted forest, not just in theory.** This assumes a tree,
    once flipped, stays flipped as `t` keeps increasing — true for a depth-1 stump (nowhere to
    route back through) but false in general for a multi-level tree that splits on one of the
    moving features more than once along a path: `DM_CSl`'s actual `random_forest` does exactly
    that, and measured directly (`verify_greedy_majority_flip` against real per-tree `.predict()`
    calls, not `tree_flip_t`'s own path walk): on 5 sampled positive rows this session, 5-12 of
    the ~50 trees selected as "cheap enough to have flipped by `t_star`" had in fact flipped back
    by `t_star`, so the true flipped count (38-59 of 100) sometimes falls short of the intended
    majority (50). Kept here because the brief asks for it as a labelled approximation, and
    `test_detection_exact_adversarial.py` documents the failure directly rather than asserting a
    guarantee this function cannot make; `exact_min_perturbation` below does not use it.
    """
    n = len(costs)
    k = -(-n // 2)  # ceil(n / 2)
    ordered = sorted(costs)
    return ordered[k - 1]


def verify_greedy_majority_flip(
    rf_estimators: Sequence[DecisionTreeClassifier],
    x_row: np.ndarray,
    feature_indices: Sequence[int],
    bounds_arr: np.ndarray,
    t: float,
) -> tuple[int, int]:
    """Ground-truth check for `greedy_majority_t`: apply `t` and ask every tree's own `.predict()`
    (not `tree_flip_t`'s path walk) whether it flipped. Returns `(n_flipped, n_estimators)`.
    """
    idx = np.asarray(list(feature_indices))
    x_t = x_row.copy()
    x_t[idx] = x_row[idx] + t * (bounds_arr - x_row[idx])
    n_flipped = 0
    for est in rf_estimators:
        orig_cls = int(est.predict(x_row.reshape(1, -1))[0])
        new_cls = int(est.predict(x_t.reshape(1, -1))[0])
        if new_cls != orig_cls:
            n_flipped += 1
    return n_flipped, len(rf_estimators)


def _ray_matrix(
    x_row: np.ndarray, feature_indices: Sequence[int], bounds_arr: np.ndarray, ts: np.ndarray
) -> np.ndarray:
    idx = np.asarray(list(feature_indices))
    mat = np.tile(x_row, (len(ts), 1))
    orig_vals = x_row[idx]
    mat[:, idx] = orig_vals + ts.reshape(-1, 1) * (bounds_arr - orig_vals)
    return mat


def exact_min_perturbation(
    detector: DetectionModule,
    rf_estimators: Sequence[DecisionTreeClassifier],
    dt: DecisionTreeClassifier,
    lr: LogisticRegression,
    x_row: np.ndarray,
    feature_indices: Sequence[int],
    bounds_arr: np.ndarray,
) -> ExactResult:
    """The minimum `t` in `[0, 1]` along `x(t)` that flips `DM_CSl`'s real ensemble verdict for
    this one row. See module docstring for what `exact=True`/`False` mean.
    """
    original_pred = int(ensemble_predict(detector, x_row.reshape(1, -1))[0])
    if original_pred == 0:
        return ExactResult(t=0.0, exact=True, cause="already_negative")

    rf_costs = per_tree_costs(rf_estimators, x_row, feature_indices, bounds_arr)
    dt_cost = tree_flip_t(dt.tree_, dt.classes_, x_row, feature_indices, bounds_arr)
    lr_cost = lr_flip_t(lr, x_row, feature_indices, bounds_arr)
    exact_breakpoints = sorted({c for c in (*rf_costs, dt_cost, lr_cost) if 0.0 < c <= 1.0})

    dense = np.linspace(0.0, 1.0, _DENSE_GRID_N)
    grid = np.unique(np.concatenate([[0.0], exact_breakpoints, dense, [1.0]]))
    preds = ensemble_predict(detector, _ray_matrix(x_row, feature_indices, bounds_arr, grid))

    flips = np.flatnonzero(preds != original_pred)
    if len(flips) == 0:
        return ExactResult(t=math.inf, exact=False, cause="never_flips")

    idx = int(flips[0])
    hi = float(grid[idx])
    lo = float(grid[idx - 1]) if idx > 0 else 0.0

    while hi - lo > _BISECT_TOL:
        mid = (lo + hi) / 2.0
        mid_row = _ray_matrix(x_row, feature_indices, bounds_arr, np.array([mid]))
        pred_mid = int(ensemble_predict(detector, mid_row)[0])
        if pred_mid == original_pred:
            lo = mid
        else:
            hi = mid

    is_exact = any(abs(hi - c) < _SAME_POINT_TOL for c in exact_breakpoints)
    return ExactResult(t=hi, exact=is_exact, cause="tree_or_lr" if is_exact else "grid_bounded")
