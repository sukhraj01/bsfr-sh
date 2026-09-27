"""`detection.exact_adversarial`: exact/near-exact minimum perturbation. M7-17.

Fast unit tests only (CLAUDE.md §5, `make test`) — the full 353-positive-row x 101-tree
exhaustive check the M7-17 brief asks for runs in `scripts/m7_17_exact_min_perturbation.py`
itself and is reported in `RESULTS.md`/the session file, not re-run here on every `make test`.
These tests verify the same properties on a small fixture instead.
"""

from __future__ import annotations

import math

import numpy as np
from m3b_harness import SEED, clean_draw, feature_matrix
from pbft_harness import REPO_ROOT

from bsfr_sh.detection.adversarial import (
    FEATURE_BOUNDS,
    adaptive_evasion,
    ensemble_predict,
    select_best_importance_model,
)
from bsfr_sh.detection.detector import DetectionModule
from bsfr_sh.detection.exact_adversarial import (
    exact_min_perturbation,
    greedy_majority_t,
    lr_flip_t,
    per_tree_costs,
    tree_flip_t,
    verify_greedy_majority_flip,
)
from bsfr_sh.detection.models import train_all
from bsfr_sh.detection.profiles import build
from bsfr_sh.honeypot import features as ft
from bsfr_sh.util.config import load_config

CONFIG = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
_FEATURE_INDEX = {name: i for i, name in enumerate(ft.FEATURE_NAMES)}
_TOP5 = list(FEATURE_BOUNDS)
_FEATURE_INDICES = [_FEATURE_INDEX[name] for name in _TOP5]
_BOUNDS_ARR = np.array([FEATURE_BOUNDS[name].bound for name in _TOP5])


def _fitted(
    count: int = 400, seed: int = SEED
) -> tuple[DetectionModule, dict, np.ndarray, np.ndarray]:
    x, y, _missing = feature_matrix(clean_draw(count=count, seed=seed))
    models = train_all(x, y, CONFIG, seed=seed)
    normal, abnormal = build(models, x, y, feature_names=ft.FEATURE_NAMES)
    detector = DetectionModule(models=models, normal=normal, abnormal=abnormal)
    return detector, models, x, y


def _positive_rows(x: np.ndarray, y: np.ndarray, n: int) -> np.ndarray:
    positive = np.flatnonzero(y == 1)
    return x[positive[:n]]


def test_tree_flip_t_is_exact_for_every_tree_on_every_sample() -> None:
    """Applying `tree_flip_t`'s own reported `t` (plus a hair past it, since the boundary itself
    is the crossing point) must change exactly that tree's prediction — verified against
    sklearn's own `.predict()`, independent of `tree_flip_t`'s internal path walk, for every tree
    on every sample in this fixture (not a subsample)."""
    _detector, models, x, y = _fitted()
    rf = models["random_forest"]
    rows = _positive_rows(x, y, n=8)
    for row in rows:
        for est in rf.estimators_:
            t_flip = tree_flip_t(est.tree_, est.classes_, row, _FEATURE_INDICES, _BOUNDS_ARR)
            orig_cls = int(est.predict(row.reshape(1, -1))[0])
            if math.isinf(t_flip):
                # Never flips within [0, 1]: confirm the class truly holds at t=1.0 too.
                idx = np.asarray(_FEATURE_INDICES)
                x1 = row.copy()
                x1[idx] = _BOUNDS_ARR
                assert int(est.predict(x1.reshape(1, -1))[0]) == orig_cls
                continue
            idx = np.asarray(_FEATURE_INDICES)
            x_flip = row.copy()
            x_flip[idx] = row[idx] + t_flip * (_BOUNDS_ARR - row[idx])
            flipped_cls = int(est.predict(x_flip.reshape(1, -1))[0])
            assert flipped_cls != orig_cls, (
                f"tree_flip_t reported t={t_flip} but the tree's own predict() did not change"
            )


def test_tree_flip_t_finds_a_known_single_split_threshold() -> None:
    """A depth-1 stump: split on feature 0 at some threshold. The exact flip `t` must match the
    closed-form crossing computed independently of the module under test."""
    from sklearn.tree import DecisionTreeClassifier

    rng = np.random.default_rng(0)
    x = np.zeros((20, 22))
    x[:, 0] = rng.uniform(0, 10, size=20)
    y = (x[:, 0] > 5.0).astype(int)
    tree = DecisionTreeClassifier(max_depth=1, random_state=0)
    tree.fit(x, y)

    row = np.zeros(22)
    row[0] = 8.0  # class 1 side
    bounds = np.array([0.0])
    t_flip = tree_flip_t(tree.tree_, tree.classes_, row, [0], bounds)
    threshold = float(tree.tree_.threshold[0])
    expected_t = (threshold - row[0]) / (bounds[0] - row[0])
    # `tree_flip_t` reports the crossing plus a value-space epsilon (sklearn casts `X` to float32
    # before comparing to the threshold, so a sub-float32-precision nudge would not reliably be
    # observed as routed past it) — see `tree_flip_t`'s `value_eps`.
    assert math.isclose(t_flip, expected_t, abs_tol=5e-4)


def test_lr_flip_t_matches_closed_form_hyperplane_crossing() -> None:
    from sklearn.linear_model import LogisticRegression

    rng = np.random.default_rng(1)
    x = rng.normal(size=(200, 22))
    y = (x[:, 0] + x[:, 1] > 0).astype(int)
    lr = LogisticRegression().fit(x, y)

    row = np.zeros(22)
    row[0] = 3.0  # strongly positive-class side
    idx = [0, 1]
    bounds = np.array([-3.0, -3.0])
    t_flip = lr_flip_t(lr, row, idx, bounds)
    assert 0.0 <= t_flip <= 1.0
    x_before = row.copy()
    x_after = row.copy()
    eps = 1e-6
    x_before[idx] = row[np.asarray(idx)] + max(t_flip - eps, 0.0) * (bounds - row[np.asarray(idx)])
    x_after[idx] = row[np.asarray(idx)] + min(t_flip + eps, 1.0) * (bounds - row[np.asarray(idx)])
    assert int(lr.predict(x_before.reshape(1, -1))[0]) != int(lr.predict(x_after.reshape(1, -1))[0])


def test_greedy_majority_t_flips_at_least_half_the_trees_when_stumps_are_monotonic() -> None:
    """`greedy_majority_t` sorts each tree's own first-flip cost and picks the
    `ceil(n/2)`-cheapest — sound *only if* a tree, once flipped, stays flipped as `t` keeps
    increasing to 1.0. A depth-1 stump (single split) is monotonic by construction: there is
    nowhere else in the tree to route back through. Verified here against a controlled ensemble
    of stumps, all guaranteed monotonic, so the assumption's mechanics can be checked in
    isolation from whether it holds on `DM_CSl`'s actual (non-monotonic — see the module docstring
    and DEV-43) fitted forest."""
    from sklearn.tree import DecisionTreeClassifier

    rng = np.random.default_rng(7)
    x = np.zeros((60, 22))
    x[:, 0] = rng.uniform(0, 10, size=60)
    y = (x[:, 0] > 5.0).astype(int)
    stumps = [DecisionTreeClassifier(max_depth=1, random_state=s).fit(x, y) for s in range(21)]

    row = np.zeros(22)
    row[0] = 9.0  # firmly class-1 side
    bounds = np.array([0.0])
    costs = per_tree_costs(stumps, row, [0], bounds)
    t_star = greedy_majority_t(costs)
    assert not math.isinf(t_star)
    n_flipped, n_estimators = verify_greedy_majority_flip(stumps, row, [0], bounds, t_star)
    assert n_flipped >= math.ceil(n_estimators / 2)


def test_greedy_majority_t_can_undercount_on_the_real_non_monotonic_forest() -> None:
    """The real, fitted `random_forest` has deeper trees that split on the same moving feature
    more than once along a path, so a tree flipped by `tree_flip_t`'s reported cost can flip
    *back* before `t_star` — `greedy_majority_t` is a documented, not-always-sound heuristic
    (M7-17 brief §1(c): "a greedy approximation — not exact for the ensemble"), which is exactly
    why `exact_min_perturbation` never uses it for the published result. This test only asserts
    the function still returns a well-formed `t_star` (a valid fraction, or `inf`) on real trees
    — not majority-flip correctness, which the real forest does not guarantee."""
    _detector, models, x, y = _fitted()
    rf = models["random_forest"]
    rows = _positive_rows(x, y, n=5)
    for row in rows:
        costs = per_tree_costs(rf.estimators_, row, _FEATURE_INDICES, _BOUNDS_ARR)
        t_star = greedy_majority_t(costs)
        assert math.isinf(t_star) or 0.0 <= t_star <= 1.0
        n_flipped, n_estimators = verify_greedy_majority_flip(
            rf.estimators_, row, _FEATURE_INDICES, _BOUNDS_ARR, t_star
        )
        assert 0 <= n_flipped <= n_estimators


def test_exact_min_perturbation_never_exceeds_binary_search() -> None:
    """The tighter method must never report a larger minimum than M7-3's binary search — it is a
    strict refinement of the same search (merged exact breakpoints + a finer grid + a tighter
    bisection tolerance), never a different, possibly-worse one."""
    detector, models, x, y = _fitted(count=500)
    binary_search = adaptive_evasion(detector, x, y, _TOP5, _FEATURE_INDEX)
    positive_rows = np.flatnonzero(y == 1)
    rf = models["random_forest"]
    dt = models["decision_tree"]
    lr = models["logistic_regression"]
    for i, row_idx in enumerate(positive_rows[:15]):
        row = x[row_idx]
        binary_t = binary_search["minima"][i]
        result = exact_min_perturbation(
            detector, rf.estimators_, dt, lr, row, _FEATURE_INDICES, _BOUNDS_ARR
        )
        exact_t = 1.0 if math.isinf(result.t) else result.t
        assert exact_t <= binary_t + 1e-6, (row_idx, exact_t, binary_t)


def test_exact_min_perturbation_zero_perturbation_matches_original_prediction() -> None:
    """A sample already misclassified at t=0 (`cause="already_negative"`) must indeed already be
    predicted benign by the real ensemble, not merely assumed to be."""
    detector, models, x, y = _fitted(count=500)
    rf = models["random_forest"]
    dt = models["decision_tree"]
    lr = models["logistic_regression"]
    positive_rows = np.flatnonzero(y == 1)
    for row_idx in positive_rows[:20]:
        row = x[row_idx]
        result = exact_min_perturbation(
            detector, rf.estimators_, dt, lr, row, _FEATURE_INDICES, _BOUNDS_ARR
        )
        if result.cause == "already_negative":
            assert result.t == 0.0
            assert int(ensemble_predict(detector, row.reshape(1, -1))[0]) == 0


def test_select_best_importance_model_still_used_for_top5_selection() -> None:
    """M7-17 reuses M7-3's top-5 feature selection unchanged (out of scope: no new feature
    selection); this just confirms the shared import path still resolves and behaves."""
    x, y, _m = feature_matrix(clean_draw(count=300))
    x_eval, y_eval, _m2 = feature_matrix(clean_draw(count=150, seed=SEED + 1))
    name, _model, score = select_best_importance_model(CONFIG, x, y, x_eval, y_eval, seed=SEED)
    assert name in ("random_forest", "decision_tree")
    assert 0.0 <= score <= 1.0
