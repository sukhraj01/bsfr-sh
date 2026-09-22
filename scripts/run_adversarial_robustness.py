"""M7-3: adversarial robustness of the honeypot detector against feature-space evasion.

The paper implicitly assumes `FT_RW`'s behavioural features are robust — that a ransomware
author cannot adjust their program's *observable* behaviour to evade detection — and never tests
this. We can, because we built the feature pipeline it never defines (FLAW-2, DEV-03, DEV-27).
This script is the test: how far can an adversary move the top-5 most important features within
physically plausible bounds before the ensemble detector's balanced accuracy collapses to the
constant-positive baseline (0.50)?

Data and model, and why they are not `run_phase3_detection.py`'s
-------------------------------------------------------------------
DEV-27's M4a amendment: "the committed corpus is the fixed dataset — experiments never
regenerate it." This script reads `data/honeypot/corpus_{train,eval}.csv` directly, never the
live chain path. That matters here for a reason beyond convention: `corpus.write_corpus` formats
every feature at 6 significant figures (`f"{value:.6g}"`), so the committed CSV is *not* bit-
identical to the full-precision features `run_phase3_detection.py` reconstructed through
`BC_SigRW` for the `RESULTS.md` M4b entry (bal_acc=0.8422, run `20260913T134602Z-ab45ac90`).
Measured here, at 0% perturbation, on the committed CSVs: **bal_acc=0.8408** — 0.0014 below
0.8422, entirely attributable to that rounding, not to any bug in the perturbation framework
below (verified: reading the CSV and immediately scoring it, with no perturbation code in the
path at all, already reproduces 0.8408, not 0.8422). This session's baseline is 0.8408; every
degradation threshold below is relative to that measured number, not to 0.8422.

Detection decision: the ensemble, not a single model's `.predict()`
----------------------------------------------------------------------
0.8422/0.8408 are `DetectionModule.decide()` outputs — nearest-`NProf`/`AProf`-membership on the
soft-vote `ensemble_score()` of all four `configs/ml.yaml` models (`detection/detector.py`,
`detection/profiles.py`), not a raw `estimator.predict()`. Every balanced-accuracy number in this
script's steps 3-5 uses that same `DetectionModule`, fit once on the committed training corpus
and never retrained — "retrain nothing" per the session brief. Feature importances (step 1) come
from a single tree-based model instead, since `LogisticRegression`/`KNeighborsClassifier` expose
no `.feature_importances_`; that model only *selects which features to perturb*, the ensemble
*decides the outcome*.

Safety (CLAUDE.md §2)
----------------------
Every perturbation here is arithmetic on a `numpy.ndarray` of floats — a row of `FT_RW`. No
malware is generated, modified, or executed; nothing here touches `honeypot/collector.py`'s
generator or produces executable content. The adversary model is "change numbers in a table."

Usage::

    python scripts/run_adversarial_robustness.py
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import time
from dataclasses import dataclass
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
from bsfr_sh.detection.detector import DetectionModule  # noqa: E402
from bsfr_sh.honeypot import features as ft  # noqa: E402
from bsfr_sh.honeypot.corpus import EXPECTED_BAYES_ACCURACY  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

#: Matches `data/honeypot/manifest.json`'s train-draw seed and `run_phase3_detection.py`'s
#: `--seed` default, so the fitted models here are the same models that path fits.
SEED = 20260912
#: Constant-positive on this eval draw — sklearn's `balanced_accuracy_score` of "always ransomware"
#: is exactly 0.50 by construction (mean of 100% recall on positives, 0% on negatives).
USELESS_THRESHOLD = 0.50
#: 0%, 10%, ..., 100% of each feature's evasion range.
STEPS = tuple(round(i / 10, 1) for i in range(11))
#: Grid resolution for the per-sample adaptive search (step 5), refined by bisection after.
_ADAPTIVE_GRID = 101
_ADAPTIVE_BISECT_TOL = 1e-4

_COLOR_SINGLE = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4")
_COLOR_COMBINED = "#e34948"
_COLOR_CONTEXT = "#c7ccd1"
_COLOR_BASELINE = "#4a3aa7"


@dataclass(frozen=True)
class FeatureBound:
    """One top-5 feature's evasion direction and physical bound, and why.

    `direction` is `-1.0` (attacker decreases the feature toward the bound) or `+1.0` (increases).
    `bound` is the value 100% perturbation reaches; `justification` is the one-sentence physical
    argument for why that bound, and no further, is reachable.
    """

    direction: float
    bound: float
    justification: str


#: Grounded in `honeypot/collector.py`'s own generator distributions and the committed corpus's
#: own observed range (train + eval) — never an arbitrary constant. See the report section for
#: the full argument; this table is the two numbers (direction, bound) that argument produces.
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

#: Two candidates for 'the best model' (whichever scores higher individually is used for feature
#: importance, step 1) — the only two of `configs/ml.yaml`'s four with `.feature_importances_`.
_IMPORTANCE_CANDIDATES = ("random_forest", "decision_tree")
TOP_N = 5


def _git_rev() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=REPO_ROOT,
        )
    except (OSError, subprocess.CalledProcessError):
        return "<unknown>"
    return result.stdout.strip()


def _load_corpus(name: str) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.read_csv(REPO_ROOT / "data" / "honeypot" / f"corpus_{name}.csv")
    x = frame[list(ft.FEATURE_NAMES)].to_numpy(dtype=np.float64)
    y = (frame["label"] == "RW").to_numpy(dtype=np.int8)
    return x, y


def _balanced_accuracy(y_true: np.ndarray, y_pred: np.ndarray) -> float:
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
    config: Any, x_train: np.ndarray, y_train: np.ndarray, x_eval: np.ndarray, y_eval: np.ndarray
) -> tuple[str, Any, float]:
    """Fit RF and DT individually; return the name/estimator/bal_acc of whichever scores higher.

    Neither `RESULTS.md`'s M4b entry nor any other measured run in this project reports a
    per-model breakdown on the honeypot corpus (only the four-model ensemble's 0.8422/0.8408).
    "Whichever scored highest in the M4b honeypot run" is read here as: fit both candidates on
    this same committed corpus and compare them directly, since that is the only faithful
    instantiation of the instruction this project's recorded numbers support.
    """
    best_name = ""
    best_model: Any = None
    best_score = -1.0
    for name in _IMPORTANCE_CANDIDATES:
        model = detection_models.build_model(config, name, seed=SEED)
        model.fit(x_train, y_train)
        score = _balanced_accuracy(y_eval, model.predict(x_eval))
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

    Benign rows (`y == 0`) are never touched — the adversary only disguises their own positive
    samples. Linear interpolation: `frac=0` is the original value, `frac=1` is exactly the bound.
    """
    perturbed = x.copy()
    positive = y == 1
    for index, fb in zip(feature_indices, bounds, strict=True):
        original = x[positive, index]
        perturbed[positive, index] = original + frac * (fb.bound - original)
    return perturbed


def ensemble_predict(detector: DetectionModule, x: np.ndarray) -> np.ndarray:
    """Batched equivalent of calling `DetectionModule.decide()` once per row.

    `DetectionModule.decide()` reshapes and scores one row at a time, which is the right shape
    for the live Phase-3 loop but far too slow for a perturbation sweep (thousands of rows x
    tens of fractions x four models' `predict_proba`, each call paying sklearn's per-call
    overhead). `detection.profiles.ensemble_score` already vectorizes over rows; the two
    `Profile.membership` calls it feeds are a scalar formula (`-(((score-mean)/std)**2`) applied
    elementwise here rather than through `Profile.membership` itself, so this function computes
    exactly what `decide()` computes, batched, with no change to `detection/`.
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
            curve.append(_balanced_accuracy(y_eval, pred))
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
        curve.append(_balanced_accuracy(y_eval, pred))
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
    bound simultaneously (the L-inf ball of radius `t` over the 5 normalized evasion ranges; each
    feature is monotonically pushed toward its own benign-looking bound, so the adversary's
    optimal use of an L-inf budget `t` is to spend all of it on every coordinate, reducing the
    per-sample optimization to a scalar search over `t`).

    A coarse grid first (cheap: tree-ensemble predictions are microseconds, ~350 positive rows),
    then bisection between the last non-flip and first-flip grid points, because the ensemble's
    membership functions are downward parabolas and are not guaranteed globally monotonic in `t`
    (an overshoot past `NProf`'s own mean can, in principle, swing the verdict back) — the grid
    scan catches that; only the final local refinement assumes monotonicity, over an interval
    small enough (1/100 of the range) that it holds.
    """
    indices = [feature_index[name] for name in top5]
    bounds_arr = np.array([FEATURE_BOUNDS[name].bound for name in top5])
    positive_rows = np.flatnonzero(y_eval == 1)
    x_pos = x_eval[positive_rows]
    orig = x_pos[:, indices]
    n_positive = len(positive_rows)

    def batched_pred(t_vec: np.ndarray) -> np.ndarray:
        """`t_vec[i]` is row `i`'s perturbation fraction; every row moves at its own `t`, all
        top-5 features at once — one batched ensemble score for the whole cohort at once."""
        moved = x_pos.copy()
        moved[:, indices] = orig + t_vec.reshape(-1, 1) * (bounds_arr - orig)
        return ensemble_predict(detector, moved)

    # Coarse grid, batched over all rows per step (not per row per step): up to _ADAPTIVE_GRID
    # ensemble scorings of the whole cohort, instead of n_positive * _ADAPTIVE_GRID individual
    # `decide()` calls — the difference between seconds and the run that timed out at 120s.
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

    # Local bisection refine, batched across all still-active (flipped, not yet converged) rows.
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


def _first_crossing(
    steps: tuple[float, ...], curve: list[float], threshold: float = USELESS_THRESHOLD
) -> float | None:
    for frac, value in zip(steps, curve, strict=True):
        if value <= threshold + 1e-9:
            return frac
    return None


def emit_single_feature_figure(
    curves: dict[str, list[float]], top5: list[str], figures_dir: Path, run_meta: dict[str, Any]
) -> tuple[Path, Path]:
    fig, ax = plt.subplots(figsize=(6.4, 4.4), dpi=150)
    for name, color in zip(top5, _COLOR_SINGLE, strict=True):
        ax.plot(
            STEPS, curves[name], marker="o", markersize=3.5, linewidth=1.8, color=color, label=name
        )
    ax.axhline(
        USELESS_THRESHOLD,
        color=_COLOR_COMBINED,
        linestyle="--",
        linewidth=1.3,
        label=f"useless detector ({USELESS_THRESHOLD:.2f})",
    )
    ax.set_title(
        "Single-feature evasion — balanced accuracy vs. perturbation", fontsize=10.5, loc="left"
    )
    ax.set_xlabel("perturbation magnitude (fraction of each feature's evasion range)")
    ax.set_ylabel("balanced accuracy")
    ax.set_ylim(0.0, 1.0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7.5, loc="lower left")
    fig.tight_layout()

    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig7a_single_feature_degradation.png"
    fig.savefig(path)
    plt.close(fig)
    sidecar = _write_sidecar(
        path,
        run_meta,
        purpose="M7-3 Fig. 7(a) — degradation of ensemble balanced accuracy as each of the top-5 "
        "features is perturbed independently toward its evasion bound, 0-100% in 10 steps. "
        "Positive (malicious) eval rows only; models fit once and never retrained.",
    )
    return path, sidecar


def emit_combined_figure(
    curves: dict[str, list[float]],
    combined: list[float],
    top5: list[str],
    figures_dir: Path,
    run_meta: dict[str, Any],
) -> tuple[Path, Path]:
    fig, ax = plt.subplots(figsize=(6.4, 4.4), dpi=150)
    for name in top5:
        ax.plot(STEPS, curves[name], linewidth=1.0, color=_COLOR_CONTEXT, zorder=1)
    ax.plot(
        STEPS,
        combined,
        marker="o",
        markersize=4,
        linewidth=2.2,
        color=_COLOR_COMBINED,
        label="combined (all 5 at once)",
        zorder=3,
    )
    ax.axhline(
        USELESS_THRESHOLD,
        color=_COLOR_BASELINE,
        linestyle="--",
        linewidth=1.3,
        label=f"useless detector ({USELESS_THRESHOLD:.2f})",
        zorder=2,
    )
    ax.set_title("Combined evasion vs. single-feature context", fontsize=10.5, loc="left")
    ax.set_xlabel("perturbation magnitude (fraction of each feature's evasion range)")
    ax.set_ylabel("balanced accuracy")
    ax.set_ylim(0.0, 1.0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7.5, loc="lower left")
    fig.tight_layout()

    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig7b_combined_evasion.png"
    fig.savefig(path)
    plt.close(fig)
    sidecar = _write_sidecar(
        path,
        run_meta,
        purpose="M7-3 Fig. 7(b) — all top-5 features perturbed simultaneously, same fraction "
        "per step (bold), against the five single-feature curves as light context on the same "
        "axes. Tests whether evasion compounds across features.",
    )
    return path, sidecar


def emit_adaptive_figure(
    adaptive: dict[str, Any], figures_dir: Path, run_meta: dict[str, Any]
) -> tuple[Path, Path]:
    arr = np.array(adaptive["minima"])
    fig, ax = plt.subplots(figsize=(6.4, 4.4), dpi=150)
    ax.hist(
        arr, bins=20, range=(0.0, 1.0), color=_COLOR_SINGLE[0], edgecolor="white", linewidth=0.6
    )
    for value, color, label in (
        (adaptive["p10"], _COLOR_COMBINED, f"p10={adaptive['p10']:.3f}"),
        (adaptive["median"], _COLOR_BASELINE, f"median={adaptive['median']:.3f}"),
        (adaptive["p90"], _COLOR_SINGLE[2], f"p90={adaptive['p90']:.3f}"),
    ):
        ax.axvline(value, color=color, linestyle="--", linewidth=1.4, label=label)
    ax.set_title(
        "Adaptive evasion — minimum L-inf perturbation to flip each sample",
        fontsize=10.5,
        loc="left",
    )
    ax.set_xlabel("minimum perturbation fraction (L-inf over top-5 features)")
    ax.set_ylabel(f"positive eval samples (n={adaptive['n_positive']})")
    ax.set_xlim(0.0, 1.0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=8, loc="upper right")
    fig.tight_layout()

    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig7c_adaptive_evasion_histogram.png"
    fig.savefig(path)
    plt.close(fig)
    sidecar = _write_sidecar(
        path,
        run_meta,
        purpose="M7-3 Fig. 7(c) — per-sample minimum L-inf perturbation (top-5 features, each "
        "normalized to its own evasion range) that flips the ensemble's verdict from ransomware "
        "to benign, over every positive row in the committed eval corpus.",
    )
    return path, sidecar


def _write_sidecar(path: Path, run_meta: dict[str, Any], *, purpose: str) -> Path:
    sidecar_path = path.with_suffix(path.suffix + ".json")
    payload = {
        "run_id": run_meta["run_id"],
        "purpose": purpose,
        "seed": run_meta["seed"],
        "config_hash": run_meta["config_hash"],
        "config_hash_scheme": run_meta["config_hash_scheme"],
        "git_rev": run_meta["git_rev"],
        "host": run_meta["host"],
    }
    sidecar_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    return sidecar_path


def main() -> int:
    started = time.perf_counter()
    ml_config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    seed_all(SEED)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    x_train, y_train = _load_corpus("train")
    x_eval, y_eval = _load_corpus("eval")
    feature_names = list(ft.FEATURE_NAMES)
    feature_index = {name: i for i, name in enumerate(feature_names)}

    # --- Step 1: feature importance ranking ---------------------------------------------------
    best_name, best_model, best_score = select_best_importance_model(
        ml_config, x_train, y_train, x_eval, y_eval
    )
    top5_pairs = top_feature_importances(best_model, tuple(feature_names), TOP_N)
    top5 = [name for name, _ in top5_pairs]
    missing = [name for name in top5 if name not in FEATURE_BOUNDS]
    if missing:
        raise SystemExit(
            f"FEATURE_BOUNDS has no entry for {missing!r}; the committed-seed top-5 changed. "
            "Add a physically-grounded bound before rerunning (see the module docstring)."
        )
    log.event(
        logger,
        "top5_selected",
        model=best_name,
        individual_bal_acc=round(best_score, 4),
        top5=top5_pairs,
    )

    # --- Ensemble fit once, retrained nowhere below --------------------------------------------
    models = detection_models.train_all(x_train, y_train, ml_config, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=tuple(feature_names)
    )
    detector = DetectionModule(models=models, normal=normal, abnormal=abnormal)

    baseline_pred = ensemble_predict(detector, x_eval)
    baseline_bal_acc = _balanced_accuracy(y_eval, baseline_pred)
    log.event(
        logger,
        "baseline_measured",
        bal_acc=round(baseline_bal_acc, 4),
        train_n=len(x_train),
        eval_n=len(x_eval),
        positive_n=int(y_eval.sum()),
        note="0% perturbation; compare to RESULTS.md M4b bal_acc=0.8422 (chain path, "
        "different float precision — see module docstring)",
    )

    # --- Step 3: single-feature evasion --------------------------------------------------------
    single_curves = single_feature_curves(detector, x_eval, y_eval, top5, feature_index)
    single_crossings = {
        name: _first_crossing(STEPS, curve) for name, curve in single_curves.items()
    }

    # --- Step 4: combined evasion ---------------------------------------------------------------
    combined = combined_curve(detector, x_eval, y_eval, top5, feature_index)
    combined_crossing = _first_crossing(STEPS, combined)

    # --- Step 5: adaptive evasion -----------------------------------------------------------------
    adaptive = adaptive_evasion(detector, x_eval, y_eval, top5, feature_index)
    log.event(
        logger,
        "adaptive_evasion",
        median=round(adaptive["median"], 4),
        p10=round(adaptive["p10"], 4),
        p90=round(adaptive["p90"], 4),
        n_survivors=adaptive["n_survivors_at_t1"],
    )

    # --- Figures ----------------------------------------------------------------------------------
    host = {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }
    run_meta = {
        "run_id": run_id,
        "seed": SEED,
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": host,
    }
    figures_dir = REPO_ROOT / "results" / "figures"
    fig_a, _side_a = emit_single_feature_figure(single_curves, top5, figures_dir, run_meta)
    fig_b, _side_b = emit_combined_figure(single_curves, combined, top5, figures_dir, run_meta)
    fig_c, _side_c = emit_adaptive_figure(adaptive, figures_dir, run_meta)

    wall_seconds = time.perf_counter() - started

    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-3 — adversarial robustness of the honeypot detector, feature-space evasion",
        "seed": SEED,
        "config_hash": run_meta["config_hash"],
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": run_meta["git_rev"],
        "host": host,
        "wall_seconds": wall_seconds,
        "train_n": len(x_train),
        "eval_n": len(x_eval),
        "eval_positive_n": int(y_eval.sum()),
        "importance_model": best_name,
        "importance_model_individual_bal_acc": best_score,
        "top5": top5_pairs,
        "feature_bounds": {
            name: {"direction": fb.direction, "bound": fb.bound, "justification": fb.justification}
            for name, fb in FEATURE_BOUNDS.items()
            if name in top5
        },
        "baseline_bal_acc": baseline_bal_acc,
        "expected_bayes_accuracy": EXPECTED_BAYES_ACCURACY,
        "reference_chain_path_bal_acc": 0.8422,
        "single_feature_curves": single_curves,
        "single_feature_crossings": single_crossings,
        "combined_curve": combined,
        "combined_crossing": combined_crossing,
        "adaptive_evasion": adaptive,
        "steps": list(STEPS),
        "figures": [str(p.relative_to(REPO_ROOT)) for p in (fig_a, fig_b, fig_c)],
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(
        run_id,
        best_name,
        best_score,
        top5_pairs,
        baseline_bal_acc,
        single_crossings,
        combined_crossing,
        adaptive,
    )
    return 0


def _print_results_lines(
    run_id: str,
    importance_model: str,
    importance_score: float,
    top5_pairs: list[tuple[str, float]],
    baseline_bal_acc: float,
    single_crossings: dict[str, float | None],
    combined_crossing: float | None,
    adaptive: dict[str, Any],
) -> None:
    date = time.strftime("%Y-%m-%d")
    top5_str = ", ".join(f"{n}={v:.4f}" for n, v in top5_pairs)
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    sys.stdout.write(
        f"{date} | detection/honeypot-adversarial | feature importances, {importance_model} "
        f"(individual bal_acc={importance_score:.4f}) | top5: {top5_str} | measured | {run_id} | "
        "M7-3\n"
    )
    sys.stdout.write(
        f"{date} | detection/honeypot-adversarial | ensemble baseline, committed corpus, 0% "
        f"perturbation | bal_acc={baseline_bal_acc:.4f} | measured | {run_id} | M7-3, cf. M4b "
        "0.8422 (chain-path float precision, see script docstring)\n"
    )
    for name, crossing in single_crossings.items():
        value = f"{crossing:.1f}" if crossing is not None else "never (<=1.0)"
        sys.stdout.write(
            f"{date} | detection/honeypot-adversarial | single-feature evasion, {name} | "
            f"crosses 0.50 at frac={value} | measured | {run_id} | M7-3\n"
        )
    combined_value = (
        f"{combined_crossing:.1f}" if combined_crossing is not None else "never (<=1.0)"
    )
    sys.stdout.write(
        f"{date} | detection/honeypot-adversarial | combined evasion, top-5 simultaneous | "
        f"crosses 0.50 at frac={combined_value} | measured | {run_id} | M7-3\n"
    )
    sys.stdout.write(
        f"{date} | detection/honeypot-adversarial | adaptive evasion, n={adaptive['n_positive']} "
        f"positive eval rows | p10={adaptive['p10']:.4f} median={adaptive['median']:.4f} "
        f"p90={adaptive['p90']:.4f} survivors={adaptive['n_survivors_at_t1']} | measured | "
        f"{run_id} | M7-3\n"
    )


if __name__ == "__main__":
    raise SystemExit(main())
