"""M7-17: exact minimum adversarial perturbation, and how much M7-3's approximation mattered.

M7-3 (`scripts/run_adversarial_robustness.py`) found the minimum combined-perturbation fraction
that flips each positive eval row by a 101-point grid plus bisection to `1e-4` — an approximation.
This script re-measures every one of the same 353 positive eval rows with
`detection.exact_adversarial.exact_min_perturbation`: exact for the `random_forest`/
`decision_tree`/`logistic_regression` share of `DM_CSl`'s four-model soft-vote decision, bounded
to `1e-6` (vs. M7-3's `1e-4`) for the residual `k_nearest_neighbours`-only cases (see that
module's docstring and DEV-43 for why `k_nearest_neighbours` alone is not solved exactly here).

It also re-measures M7-8's three hardened models (25%/50%/100% training budget) with the same
exact method, to check whether M7-8's headline findings (the 25%-budget robustness *backfire*,
and the 50%/100%-budget bound-memorisation) survive tighter bounds. Per the session brief: no new
training budgets, no retraining protocol changes — only a tighter measurement of evasion cost on
the models M7-8 already fit.

Safety (CLAUDE.md §2): every perturbation here is arithmetic on a `numpy.ndarray` of floats. No
malware is generated, modified, or executed; nothing here touches `honeypot/collector.py`'s
generator or `detection/detector.py`.

Usage::

    python scripts/m7_17_exact_min_perturbation.py
"""

from __future__ import annotations

import json
import math
import platform
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, config_hash  # noqa: E402
from bsfr_sh.detection import models as detection_models  # noqa: E402
from bsfr_sh.detection import profiles as detection_profiles  # noqa: E402
from bsfr_sh.detection.adversarial import (  # noqa: E402
    FEATURE_BOUNDS,
    adaptive_evasion,
    balanced_accuracy,
    ensemble_predict,
    select_best_importance_model,
    top_feature_importances,
)
from bsfr_sh.detection.detector import DetectionModule  # noqa: E402
from bsfr_sh.detection.exact_adversarial import ExactResult, exact_min_perturbation  # noqa: E402
from bsfr_sh.detection.retraining import augment_positive_rows  # noqa: E402
from bsfr_sh.honeypot import features as ft  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import numpy_generator, seed_all  # noqa: E402

#: Matches M7-3/M7-8's fitted-model seed — every measured honeypot number in this project's own.
SEED = 20260912
CSV_PATH_REFERENCE_BAL_ACC = 0.8408
_REPRODUCTION_TOLERANCE = 1e-4
K_COPIES = 5
#: A binary-search result this much or more above the exact result is "loose" — a full 10 points
#: of the [0, 1] evasion-fraction range, not a relative percentage of a possibly-tiny number.
_LOOSE_THRESHOLD = 0.10
#: M7-8's Pareto-sweep budgets (its own degenerate 0.0 case is skipped — it reproduces the
#: original model exactly by construction, nothing new to re-measure).
_M7_8_BUDGETS = (0.25, 0.5, 1.0)

_COLOR_BINARY = "#c7ccd1"
_COLOR_EXACT = "#e34948"


def _load_corpus(name: str) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.read_csv(REPO_ROOT / "data" / "honeypot" / f"corpus_{name}.csv")
    x = frame[list(ft.FEATURE_NAMES)].to_numpy(dtype=np.float64)
    y = (frame["label"] == "RW").to_numpy(dtype=np.int8)
    return x, y


def _fit_detector(x_train: np.ndarray, y_train: np.ndarray, ml_config: Any) -> DetectionModule:
    models = detection_models.train_all(x_train, y_train, ml_config, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    return DetectionModule(models=models, normal=normal, abnormal=abnormal)


def _exact_minima_for_positives(
    detector: DetectionModule,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    feature_indices: list[int],
    bounds_arr: np.ndarray,
) -> list[ExactResult]:
    rf = detector.models["random_forest"]
    dt = detector.models["decision_tree"]
    lr = detector.models["logistic_regression"]
    positive_rows = np.flatnonzero(y_eval == 1)
    return [
        exact_min_perturbation(
            detector, rf.estimators_, dt, lr, x_eval[i], feature_indices, bounds_arr
        )
        for i in positive_rows
    ]


_STABILITY_GRID_N = 200


def _stability_diagnostics(
    detector: DetectionModule,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    feature_indices: list[int],
    bounds_arr: np.ndarray,
    results: list[ExactResult],
) -> dict[str, Any]:
    """`exact_min_perturbation` reports the FIRST `t` at which the ensemble's verdict flips —
    exactly what "minimum perturbation to evade" means. But `DM_CSl`'s decision surface is not
    guaranteed monotonic (`detection.adversarial`'s own docstring already says so), and a flip
    can be a razor-thin, transient dip that reverts to the correct verdict almost immediately,
    rather than a stable region an attacker could actually land in. This distinguishes the two:
    for every real (non-`already_negative`, non-`never_flips`) flip, checks the verdict at `t=1.0`
    and, if it has reverted, finds the approximate recovery point on a fine grid — the dip's
    width. Reported per-model, since M7-8's 100%-budget model shows this far more than the
    original (see DEV-43 and RESULTS.md M7-17).
    """
    idx = np.asarray(feature_indices)
    positive_rows = np.flatnonzero(y_eval == 1)
    n_stable = 0
    n_transient = 0
    widths: list[float] = []
    for row_idx, result in zip(positive_rows, results, strict=True):
        if result.cause in ("already_negative", "never_flips"):
            continue
        row = x_eval[row_idx]
        x1 = row.copy()
        x1[idx] = bounds_arr
        pred_at_1 = int(ensemble_predict(detector, x1.reshape(1, -1))[0])
        if pred_at_1 == 1:  # reverted to the correct (malicious) verdict by t=1.0
            n_transient += 1
            grid = np.linspace(result.t, 1.0, _STABILITY_GRID_N)
            mat = np.tile(row, (len(grid), 1))
            mat[:, idx] = row[idx] + grid.reshape(-1, 1) * (bounds_arr - row[idx])
            preds = ensemble_predict(detector, mat)
            recovered = np.flatnonzero(preds == 1)
            if len(recovered):
                widths.append(float(grid[recovered[0]] - result.t))
        else:
            n_stable += 1
    width_stats = (
        {
            "min": float(np.min(widths)),
            "median": float(np.median(widths)),
            "max": float(np.max(widths)),
            "mean": float(np.mean(widths)),
        }
        if widths
        else None
    )
    return {
        "n_stable_flip": n_stable,
        "n_transient_dip": n_transient,
        "dip_width": width_stats,
    }


def _percentiles(values: list[float]) -> dict[str, float]:
    capped = np.array([1.0 if math.isinf(v) else v for v in values])
    return {
        "p10": float(np.percentile(capped, 10)),
        "median": float(np.median(capped)),
        "p90": float(np.percentile(capped, 90)),
    }


def _emit_histogram_figure(
    binary_minima: np.ndarray, exact_minima: np.ndarray, out_dir: Path
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    bins = list(np.linspace(0.0, 1.0, 21))
    ax.hist(
        binary_minima,
        bins=bins,
        alpha=0.55,
        color=_COLOR_BINARY,
        label="M7-3 binary search (grid + 1e-4 bisection)",
    )
    ax.hist(
        exact_minima,
        bins=bins,
        alpha=0.55,
        color=_COLOR_EXACT,
        label="M7-17 exact / near-exact (1e-6 bisection)",
    )
    ax.set_xlabel("minimum perturbation fraction to evade")
    ax.set_ylabel("positive eval rows")
    ax.set_title("Minimum adversarial perturbation: approximation vs. exact")
    ax.legend(loc="upper center")
    fig.tight_layout()
    path = out_dir / "fig_m7_17_exact_vs_binary_search_histogram.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _reexamine_m7_8_budget(
    budget: float,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    top5: list[str],
    feature_index: dict[str, int],
    feature_indices: list[int],
    bounds_arr: np.ndarray,
    ml_config: Any,
    logger: Any,
) -> dict[str, Any]:
    indices = [feature_index[name] for name in top5]
    bounds = [FEATURE_BOUNDS[name] for name in top5]
    rng = numpy_generator(SEED + round(budget * 1000))
    x_aug, y_aug = augment_positive_rows(
        x_train, y_train, indices, bounds, k=K_COPIES, max_perturbation=budget, rng=rng
    )
    detector = _fit_detector(x_aug, y_aug, ml_config)
    binary = adaptive_evasion(detector, x_eval, y_eval, top5, feature_index)
    exact_results = _exact_minima_for_positives(
        detector, x_eval, y_eval, feature_indices, bounds_arr
    )
    exact_minima = np.array([1.0 if math.isinf(r.t) else r.t for r in exact_results])
    binary_percentiles = {"p10": binary["p10"], "median": binary["median"], "p90": binary["p90"]}
    exact_percentiles = _percentiles([r.t for r in exact_results])
    shift_pp = 100 * abs(exact_percentiles["median"] - binary_percentiles["median"])
    stability = _stability_diagnostics(
        detector, x_eval, y_eval, feature_indices, bounds_arr, exact_results
    )
    log.event(
        logger,
        "m7_8_budget_reexamined",
        budget=budget,
        binary_median=round(binary_percentiles["median"], 4),
        exact_median=round(exact_percentiles["median"], 4),
        median_shift_pp=round(shift_pp, 2),
        n_stable_flip=stability["n_stable_flip"],
        n_transient_dip=stability["n_transient_dip"],
        dip_width_median=(
            round(stability["dip_width"]["median"], 4) if stability["dip_width"] else None
        ),
    )
    return {
        "budget": budget,
        "train_n": len(x_aug),
        "binary_search": binary_percentiles,
        "exact": exact_percentiles,
        "median_shift_pp": shift_pp,
        "exact_minima": exact_minima.tolist(),
        "stability": stability,
    }


def main() -> None:
    started = time.perf_counter()
    seed_all(SEED)
    ml_config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    run_id = log.configure()
    logger = log.get_logger(__name__)

    x_train, y_train = _load_corpus("train")
    x_eval, y_eval = _load_corpus("eval")
    feature_names = list(ft.FEATURE_NAMES)
    feature_index = {name: i for i, name in enumerate(feature_names)}

    best_name, best_model, best_score = select_best_importance_model(
        ml_config, x_train, y_train, x_eval, y_eval, seed=SEED
    )
    top5_pairs = top_feature_importances(best_model, tuple(feature_names), 5)
    top5 = [name for name, _ in top5_pairs]
    missing = [name for name in top5 if name not in FEATURE_BOUNDS]
    if missing:
        raise SystemExit(f"FEATURE_BOUNDS has no entry for {missing!r}; top-5 changed since M7-3.")
    feature_indices = [feature_index[name] for name in top5]
    bounds_arr = np.array([FEATURE_BOUNDS[name].bound for name in top5])
    log.event(
        logger, "top5_selected", model=best_name, individual_bal_acc=round(best_score, 4), top5=top5
    )

    # --- Original model: reproduce M7-3's baseline, then measure both ways ---------------------
    detector = _fit_detector(x_train, y_train, ml_config)
    baseline_pred = ensemble_predict(detector, x_eval)
    baseline_bal_acc = balanced_accuracy(y_eval, baseline_pred)
    if abs(baseline_bal_acc - CSV_PATH_REFERENCE_BAL_ACC) > _REPRODUCTION_TOLERANCE:
        raise SystemExit(
            f"original model bal_acc={baseline_bal_acc:.4f} does not reproduce M7-3's "
            f"{CSV_PATH_REFERENCE_BAL_ACC}; not safe to compare against its published numbers."
        )
    log.event(logger, "baseline_reproduced", bal_acc=round(baseline_bal_acc, 4))

    binary = adaptive_evasion(detector, x_eval, y_eval, top5, feature_index)
    log.event(
        logger,
        "binary_search_measured",
        p10=round(binary["p10"], 4),
        median=round(binary["median"], 4),
        p90=round(binary["p90"], 4),
        n_survivors_at_t1=binary["n_survivors_at_t1"],
    )

    exact_started = time.perf_counter()
    exact_results = _exact_minima_for_positives(
        detector, x_eval, y_eval, feature_indices, bounds_arr
    )
    exact_seconds = time.perf_counter() - exact_started
    exact_minima_list = [r.t for r in exact_results]
    exact_percentiles = _percentiles(exact_minima_list)
    n_exact = sum(1 for r in exact_results if r.exact)
    cause_counts: dict[str, int] = {}
    for r in exact_results:
        cause_counts[r.cause] = cause_counts.get(r.cause, 0) + 1
    log.event(
        logger,
        "exact_measured",
        p10=round(exact_percentiles["p10"], 4),
        median=round(exact_percentiles["median"], 4),
        p90=round(exact_percentiles["p90"], 4),
        n_exact=n_exact,
        n_total=len(exact_results),
        cause_counts=cause_counts,
        wall_seconds=round(exact_seconds, 1),
    )

    # --- Per-sample delta vs. M7-3's binary search ----------------------------------------------
    binary_minima = np.array(binary["minima"])
    exact_minima = np.array([1.0 if math.isinf(v) else v for v in exact_minima_list])
    if bool(np.any(exact_minima > binary_minima + 1e-6)):
        bad = np.flatnonzero(exact_minima > binary_minima + 1e-6)
        raise SystemExit(
            f"exact_min_perturbation reported a LARGER minimum than M7-3's binary search for "
            f"{len(bad)} row(s) — this should never happen (the exact search strictly refines "
            f"the binary search's own grid); investigate before trusting any number below."
        )
    delta = binary_minima - exact_minima
    n_loose = int(np.sum(delta >= _LOOSE_THRESHOLD))

    # --- Did any of M7-3's 28 "never flips at t=1.0" survivors actually flip? -------------------
    survivor_indices = binary["survivor_row_indices"]
    positive_rows = np.flatnonzero(y_eval == 1)
    survivor_pos_in_order = [
        int(np.flatnonzero(positive_rows == idx)[0]) for idx in survivor_indices
    ]
    newly_flipped = [i for i in survivor_pos_in_order if not math.isinf(exact_minima_list[i])]
    log.event(
        logger,
        "survivor_recheck",
        n_survivors_m7_3=len(survivor_indices),
        n_newly_flipped_under_exact=len(newly_flipped),
    )

    original_stability = _stability_diagnostics(
        detector, x_eval, y_eval, feature_indices, bounds_arr, exact_results
    )
    log.event(
        logger,
        "original_stability",
        n_stable_flip=original_stability["n_stable_flip"],
        n_transient_dip=original_stability["n_transient_dip"],
        dip_width_median=(
            round(original_stability["dip_width"]["median"], 4)
            if original_stability["dip_width"]
            else None
        ),
    )

    figures_dir = REPO_ROOT / "results" / "figures"
    fig_path = _emit_histogram_figure(binary_minima, exact_minima, figures_dir)

    # --- M7-8 re-examination ---------------------------------------------------------------------
    m7_8_results = [
        _reexamine_m7_8_budget(
            budget,
            x_train,
            y_train,
            x_eval,
            y_eval,
            top5,
            feature_index,
            feature_indices,
            bounds_arr,
            ml_config,
            logger,
        )
        for budget in _M7_8_BUDGETS
    ]
    max_shift_pp = max((entry["median_shift_pp"] for entry in m7_8_results), default=0.0)
    log.event(logger, "m7_8_reexamined", max_median_shift_pp=round(max_shift_pp, 2))

    wall_seconds = time.perf_counter() - started
    host = {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }
    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "seed": SEED,
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "host": host,
        "wall_seconds": round(wall_seconds, 2),
        "top5": top5,
        "baseline_bal_acc": baseline_bal_acc,
        "binary_search": {"p10": binary["p10"], "median": binary["median"], "p90": binary["p90"]},
        "exact": exact_percentiles,
        "exact_wall_seconds": round(exact_seconds, 1),
        "n_exact": n_exact,
        "n_total": len(exact_results),
        "cause_counts": cause_counts,
        "n_loose_ge_10pp": n_loose,
        "loose_threshold": _LOOSE_THRESHOLD,
        "n_survivors_m7_3": len(survivor_indices),
        "n_newly_flipped_under_exact": len(newly_flipped),
        "per_sample_binary_minima": binary_minima.tolist(),
        "per_sample_exact_minima": exact_minima.tolist(),
        "per_sample_exact_cause": [r.cause for r in exact_results],
        "original_stability": original_stability,
        "m7_8_reexamined": m7_8_results,
        "figure": str(fig_path.relative_to(REPO_ROOT)),
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")
    log.event(
        logger,
        "summary",
        run_id=run_id,
        baseline_bal_acc=round(baseline_bal_acc, 4),
        binary_p10=round(binary["p10"], 4),
        binary_median=round(binary["median"], 4),
        binary_p90=round(binary["p90"], 4),
        exact_p10=round(exact_percentiles["p10"], 4),
        exact_median=round(exact_percentiles["median"], 4),
        exact_p90=round(exact_percentiles["p90"], 4),
        n_exact=n_exact,
        n_total=len(exact_results),
        cause_counts=cause_counts,
        n_loose_ge_10pp=n_loose,
        n_survivors_m7_3=len(survivor_indices),
        n_newly_flipped_under_exact=len(newly_flipped),
        original_n_transient_dip=original_stability["n_transient_dip"],
        m7_8_median_shifts_pp=[round(e["median_shift_pp"], 2) for e in m7_8_results],
        m7_8_n_transient_dip=[e["stability"]["n_transient_dip"] for e in m7_8_results],
        figure=str(fig_path.relative_to(REPO_ROOT)),
        wall_seconds=round(wall_seconds, 1),
    )


if __name__ == "__main__":
    main()
