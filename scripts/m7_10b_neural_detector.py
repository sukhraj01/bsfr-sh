"""M7-10 Part B: is M7-8's adversarial-retraining failure mode a property of tree ensembles, or
of the feature set?

M7-8 (`scripts/m7_8_adversarial_retraining.py`) found that adversarially retraining the
Random-Forest-led four-model ensemble hardens it against M7-3's attack at 50%/100% training
budget, but the 100%-budget model's combined-evasion curve *rises* with perturbation instead of
degrading — evidence it learned "values near the evasion bound" as its own signature rather than a
more robust representation, and the 25%-budget model is *worse* than no hardening at all on both
axes. This script runs the identical protocol (M7-3's perturbation sweep, M7-8's retraining
budgets, same top-5 features and evasion bounds) against a small MLP (`detection.mlp_model`,
DEV-36) instead of the tree ensemble, refitting the RF ensemble fresh in the same run so every
number is directly comparable rather than spliced from two sidecars.

Same top-5 features, same bounds, not re-derived
--------------------------------------------------
The session brief is explicit: this measures architecture, not a new attack. `detection.
adversarial.FEATURE_BOUNDS` (5 features, M7-3's physically-grounded evasion bounds) and its keys
as the top-5 are reused verbatim for both models — this script never asks the MLP (which has no
`.feature_importances_` in the first place) which features it thinks matter for attack purposes.

Feature-importance shift, adapted for a model with no `.feature_importances_`
---------------------------------------------------------------------------------
M7-8 fit a fresh Random Forest on the augmented draw and read `.feature_importances_` (Gini
importance) to check whether the top-5's combined importance collapsed. An `MLPClassifier` has no
such attribute. Both models are instead compared with **permutation importance computed on the
actual fitted detector** (`detection.adversarial.ensemble_predict` — the same NProf/AProf decision
every other number in this script uses, not a proxy model's `.predict()`): shuffle one feature
column at a time across the eval set, re-score, and the balanced-accuracy drop is that feature's
importance. This is a deliberate methodological change from M7-8's Gini-importance number
(documented as DEV-36's second decision) — Gini importance describes a tree's own split structure
and has no equivalent for an MLP; permutation importance measures the same thing (how much a
feature's information matters to the fitted decision) for any model type, which is what makes RF
and MLP comparable on this axis here.

EMBER transfer (step 5)
------------------------
Only runs if `data/external/ember/test_features.jsonl` exists (M7-10a's prerequisite download).
Skipped, not faked, if it does not — the sidecar records which happened. Never retrains on EMBER.

Usage::

    python scripts/m7_10b_neural_detector.py
"""

from __future__ import annotations

import json
import platform
import subprocess
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
from bsfr_sh.detection import metrics as detection_metrics  # noqa: E402
from bsfr_sh.detection import models as detection_models  # noqa: E402
from bsfr_sh.detection import profiles as detection_profiles  # noqa: E402
from bsfr_sh.detection.adversarial import (  # noqa: E402
    FEATURE_BOUNDS,
    STEPS,
    balanced_accuracy,
    combined_curve,
    ensemble_predict,
    single_feature_curves,
)
from bsfr_sh.detection.adversarial import (  # noqa: E402
    adaptive_evasion as run_adaptive_evasion,
)
from bsfr_sh.detection.detector import DetectionModule  # noqa: E402
from bsfr_sh.detection.mlp_model import train_mlp  # noqa: E402
from bsfr_sh.detection.retraining import augment_positive_rows  # noqa: E402
from bsfr_sh.honeypot import features as ft  # noqa: E402
from bsfr_sh.honeypot.ember_mapping import build_from_ember_row  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import numpy_generator, seed_all  # noqa: E402

SEED = 20260912
CSV_PATH_REFERENCE_BAL_ACC = 0.8408  # M7-3's established CSV-path baseline
_REPRODUCTION_TOLERANCE = 1e-4
K_COPIES = 5
TRAINING_BUDGETS = (0.0, 0.25, 0.5, 1.0)
PARETO_BUDGETS = (0.25, 0.5, 1.0)
#: M7-3's own top-5, in `FEATURE_BOUNDS` order — reused verbatim, never re-derived (see docstring).
TOP5 = tuple(FEATURE_BOUNDS.keys())
_PERMUTATION_REPEATS = 20
EMBER_TEST_JSONL = REPO_ROOT / "data" / "external" / "ember" / "test_features.jsonl"

_COLOR_RF = "#4a3aa7"
_COLOR_MLP = "#1baf7a"
_COLOR_BUDGETS_RF = {0.25: "#8577d1", 0.5: "#6e5dc4", 1.0: "#4a3aa7"}
_COLOR_BUDGETS_MLP = {0.25: "#8fe0bd", 0.5: "#4bc794", 1.0: "#1baf7a"}
_COLOR_BASELINE = "#e34948"


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


def _load_ember_mapped() -> tuple[np.ndarray, np.ndarray] | None:
    if not EMBER_TEST_JSONL.exists():
        return None
    values: list[list[float]] = []
    labels: list[int] = []
    with EMBER_TEST_JSONL.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            label = row.get("label")
            if label not in (0, 1):
                continue
            vector = build_from_ember_row(row)
            values.append(list(vector.values))
            labels.append(int(label))
    return np.array(values, dtype=np.float64), np.array(labels, dtype=np.int8)


def fit_rf_detector(x_train: np.ndarray, y_train: np.ndarray, ml_config: Any) -> DetectionModule:
    models = detection_models.train_all(x_train, y_train, ml_config, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    return DetectionModule(models=models, normal=normal, abnormal=abnormal)


def fit_mlp_detector(x_train: np.ndarray, y_train: np.ndarray, ml_config: Any) -> DetectionModule:
    models = train_mlp(x_train, y_train, ml_config, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    return DetectionModule(models=models, normal=normal, abnormal=abnormal)


def clean_metrics(
    detector: DetectionModule, x_eval: np.ndarray, y_eval: np.ndarray
) -> dict[str, float]:
    scores = detection_profiles.ensemble_score(detector.models, x_eval)
    predictions = ensemble_predict(detector, x_eval)
    honest = detection_metrics.honest_metrics(y_eval, predictions, scores)
    return {
        "balanced_accuracy": balanced_accuracy(y_eval, predictions),
        "precision": honest.precision,
        "recall": honest.recall,
        "mcc": honest.mcc,
        "pr_auc": honest.pr_auc,
    }


def permutation_importance_top5(
    detector: DetectionModule,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    rng: np.random.Generator,
) -> dict[str, float]:
    """Balanced-accuracy drop from shuffling one feature column at a time, against the fitted
    detector's own NProf/AProf decision -- the model-agnostic stand-in for `.feature_importances_`
    this module's docstring explains. Computed for every feature; callers read the top-5 sum."""
    baseline = balanced_accuracy(y_eval, ensemble_predict(detector, x_eval))
    importances: dict[str, float] = {}
    for index, name in enumerate(ft.FEATURE_NAMES):
        drops = []
        for _ in range(_PERMUTATION_REPEATS):
            x_perm = x_eval.copy()
            x_perm[:, index] = rng.permutation(x_perm[:, index])
            drops.append(baseline - balanced_accuracy(y_eval, ensemble_predict(detector, x_perm)))
        importances[name] = float(np.mean(drops))
    return importances


def measure_model(
    label: str,
    fit_fn: Any,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    ml_config: Any,
    feature_index: dict[str, int],
    perm_rng: np.random.Generator,
) -> dict[str, Any]:
    """Original model: clean metrics, single/combined degradation curves, adaptive evasion,
    permutation importance. Same measurement set for RF and MLP (and, inside the caller's
    budget loop, for every hardened variant of each)."""
    detector = fit_fn(x_train, y_train, ml_config)
    metrics = clean_metrics(detector, x_eval, y_eval)
    combined = combined_curve(detector, x_eval, y_eval, list(TOP5), feature_index)
    single = single_feature_curves(detector, x_eval, y_eval, list(TOP5), feature_index)
    adaptive = run_adaptive_evasion(detector, x_eval, y_eval, list(TOP5), feature_index)
    importances = permutation_importance_top5(detector, x_eval, y_eval, perm_rng)
    log.get_logger(__name__)
    return {
        "label": label,
        "detector": detector,
        "clean_metrics": metrics,
        "combined_curve": combined,
        "single_feature_curves": single,
        "adaptive_evasion": adaptive,
        "permutation_importance": importances,
        "top5_importance_sum": sum(importances[name] for name in TOP5),
    }


# --- Figures ------------------------------------------------------------------------------------


def emit_clean_accuracy_figure(
    rf_original: dict[str, Any], mlp_original: dict[str, Any], figures_dir: Path
) -> Path:
    labels = ("balanced_accuracy", "precision", "recall", "mcc", "pr_auc")
    fig, ax = plt.subplots(figsize=(7.6, 4.2), dpi=150)
    x_pos = np.arange(len(labels))
    width = 0.35
    ax.bar(
        x_pos - width / 2,
        [rf_original["clean_metrics"][k] for k in labels],
        width,
        color=_COLOR_RF,
        label="RF ensemble (Table II)",
    )
    ax.bar(
        x_pos + width / 2,
        [mlp_original["clean_metrics"][k] for k in labels],
        width,
        color=_COLOR_MLP,
        label="MLP (M7-10b)",
    )
    ax.set_xticks(x_pos, labels, rotation=15, fontsize=8.5)
    ax.set_ylim(min(-0.1, ax.get_ylim()[0]), 1.0)
    ax.axhline(0.0, color="#333333", linewidth=0.7)
    ax.set_title("Clean-eval accuracy: RF ensemble vs. MLP", fontsize=10.5, loc="left")
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig10c_mlp_vs_rf_clean_accuracy.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_combined_overlay_figure(
    rf_original: dict[str, Any], mlp_original: dict[str, Any], figures_dir: Path
) -> Path:
    fig, ax = plt.subplots(figsize=(6.6, 4.4), dpi=150)
    ax.plot(
        STEPS,
        rf_original["combined_curve"],
        marker="o",
        markersize=3.5,
        linewidth=2.0,
        color=_COLOR_RF,
        label="RF ensemble",
    )
    ax.plot(
        STEPS,
        mlp_original["combined_curve"],
        marker="s",
        markersize=3.5,
        linewidth=2.0,
        color=_COLOR_MLP,
        label="MLP",
    )
    ax.axhline(
        0.50, color=_COLOR_BASELINE, linestyle="--", linewidth=1.2, label="useless detector (0.50)"
    )
    ax.set_title("Combined evasion: RF vs. MLP, no hardening", fontsize=10.5, loc="left")
    ax.set_xlabel("perturbation magnitude (fraction of each top-5 feature's evasion range)")
    ax.set_ylabel("balanced accuracy")
    ax.set_ylim(0.0, 1.0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=8, loc="lower left")
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig10d_mlp_vs_rf_combined_degradation.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_retraining_comparison_figure(
    rf_by_budget: dict[float, dict[str, Any]],
    mlp_by_budget: dict[float, dict[str, Any]],
    figures_dir: Path,
) -> Path:
    fig, axes = plt.subplots(1, 2, figsize=(11.2, 4.4), dpi=150)
    for ax, by_budget, colors, title in (
        (axes[0], rf_by_budget, _COLOR_BUDGETS_RF, "RF ensemble"),
        (axes[1], mlp_by_budget, _COLOR_BUDGETS_MLP, "MLP"),
    ):
        rows = [("original", by_budget[0.0])] + [
            (f"@{int(b * 100)}%", by_budget[b]) for b in PARETO_BUDGETS
        ]
        x_pos = np.arange(len(rows))
        width = 0.25
        for offset, key, color in (
            (-width, "p10", "#c7ccd1"),
            (0.0, "median", None),
            (width, "p90", "#eb6834"),
        ):
            values = [r[1]["adaptive_evasion"][key] for r in rows]
            bar_color = color if color else list(colors.values())[-1]
            ax.bar(x_pos + offset, values, width, label=key, color=bar_color)
        ax.set_xticks(x_pos, [r[0] for r in rows], fontsize=8.5)
        ax.set_ylim(0.0, 1.05)
        ax.set_title(f"{title}: adaptive evasion by training budget", fontsize=9.5, loc="left")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.grid(axis="y", linewidth=0.5, alpha=0.4)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("minimum L-inf perturbation to flip")
    axes[0].legend(frameon=False, fontsize=7.5)
    fig.suptitle("Adversarial retraining: RF vs. MLP, p10/median/p90", fontsize=10.5)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig10e_mlp_vs_rf_retraining_adaptive.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_importance_shift_figure(
    rf_by_budget: dict[float, dict[str, Any]],
    mlp_by_budget: dict[float, dict[str, Any]],
    figures_dir: Path,
) -> Path:
    fig, ax = plt.subplots(figsize=(6.6, 4.4), dpi=150)
    budgets = [0.0, *PARETO_BUDGETS]
    x_pos = np.arange(len(budgets))
    width = 0.35
    ax.bar(
        x_pos - width / 2,
        [rf_by_budget[b]["top5_importance_sum"] for b in budgets],
        width,
        color=_COLOR_RF,
        label="RF ensemble",
    )
    ax.bar(
        x_pos + width / 2,
        [mlp_by_budget[b]["top5_importance_sum"] for b in budgets],
        width,
        color=_COLOR_MLP,
        label="MLP",
    )
    ax.set_xticks(x_pos, [f"{int(b * 100)}%" for b in budgets], fontsize=8.5)
    ax.set_xlabel("adversarial-retraining training budget")
    ax.set_ylabel("top-5 permutation importance, summed")
    ax.set_title(
        "Does reliance on the top-5 attacked features collapse under hardening?",
        fontsize=10,
        loc="left",
    )
    ax.legend(frameon=False, fontsize=8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig10f_mlp_vs_rf_importance_shift.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def _entry_for_sidecar(entry: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in entry.items() if k != "detector"}


def main() -> int:
    started = time.perf_counter()
    ml_config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    seed_all(SEED)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    x_train, y_train = _load_corpus("train")
    x_eval, y_eval = _load_corpus("eval")
    feature_index = {name: i for i, name in enumerate(ft.FEATURE_NAMES)}
    indices = [feature_index[name] for name in TOP5]
    bounds = [FEATURE_BOUNDS[name] for name in TOP5]

    # --- Original models: RF sanity-checked against M7-3's established baseline ----------------
    perm_rng_rf = numpy_generator(SEED)
    rf_original = measure_model(
        "rf_original",
        fit_rf_detector,
        x_train,
        y_train,
        x_eval,
        y_eval,
        ml_config,
        feature_index,
        perm_rng_rf,
    )
    drift = abs(rf_original["clean_metrics"]["balanced_accuracy"] - CSV_PATH_REFERENCE_BAL_ACC)
    if drift > _REPRODUCTION_TOLERANCE:
        raise SystemExit(
            f"RF bal_acc={rf_original['clean_metrics']['balanced_accuracy']:.4f} does not "
            f"reproduce M7-3's {CSV_PATH_REFERENCE_BAL_ACC}; not safe to compare MLP against it."
        )
    log.event(
        logger,
        "rf_original_measured",
        bal_acc=round(rf_original["clean_metrics"]["balanced_accuracy"], 4),
    )

    perm_rng_mlp = numpy_generator(SEED + 1)
    mlp_original = measure_model(
        "mlp_original",
        fit_mlp_detector,
        x_train,
        y_train,
        x_eval,
        y_eval,
        ml_config,
        feature_index,
        perm_rng_mlp,
    )
    log.event(
        logger,
        "mlp_original_measured",
        bal_acc=round(mlp_original["clean_metrics"]["balanced_accuracy"], 4),
        adaptive_median=round(mlp_original["adaptive_evasion"]["median"], 4),
    )

    # --- Retraining sweep, both models, same budgets --------------------------------------------
    rf_by_budget: dict[float, dict[str, Any]] = {0.0: rf_original}
    mlp_by_budget: dict[float, dict[str, Any]] = {0.0: mlp_original}
    for budget in PARETO_BUDGETS:
        rng = numpy_generator(SEED + round(budget * 1000))
        x_aug, y_aug = augment_positive_rows(
            x_train, y_train, indices, bounds, k=K_COPIES, max_perturbation=budget, rng=rng
        )

        perm_rng_rf_b = numpy_generator(SEED + round(budget * 1000) + 1)
        rf_entry = measure_model(
            f"rf_{budget}",
            fit_rf_detector,
            x_aug,
            y_aug,
            x_eval,
            y_eval,
            ml_config,
            feature_index,
            perm_rng_rf_b,
        )
        rf_entry["train_n"] = len(x_aug)
        rf_by_budget[budget] = rf_entry

        perm_rng_mlp_b = numpy_generator(SEED + round(budget * 1000) + 2)
        mlp_entry = measure_model(
            f"mlp_{budget}",
            fit_mlp_detector,
            x_aug,
            y_aug,
            x_eval,
            y_eval,
            ml_config,
            feature_index,
            perm_rng_mlp_b,
        )
        mlp_entry["train_n"] = len(x_aug)
        mlp_by_budget[budget] = mlp_entry

        log.event(
            logger,
            "budget_measured",
            budget=budget,
            rf_bal_acc=round(rf_entry["clean_metrics"]["balanced_accuracy"], 4),
            rf_adaptive_median=round(rf_entry["adaptive_evasion"]["median"], 4),
            mlp_bal_acc=round(mlp_entry["clean_metrics"]["balanced_accuracy"], 4),
            mlp_adaptive_median=round(mlp_entry["adaptive_evasion"]["median"], 4),
        )

    # --- EMBER transfer (step 5), only if M7-10a's download/extraction is already done ---------
    ember_transfer: dict[str, Any] | None = None
    ember_data = _load_ember_mapped()
    if ember_data is not None:
        x_ember, y_ember = ember_data
        rf_ember_metrics = clean_metrics(rf_original["detector"], x_ember, y_ember)
        mlp_ember_metrics = clean_metrics(mlp_original["detector"], x_ember, y_ember)
        ember_transfer = {
            "n": len(y_ember),
            "n_positive": int(y_ember.sum()),
            "rf": rf_ember_metrics,
            "mlp": mlp_ember_metrics,
        }
        log.event(
            logger,
            "ember_transfer_measured",
            rf_bal_acc=round(rf_ember_metrics["balanced_accuracy"], 4),
            mlp_bal_acc=round(mlp_ember_metrics["balanced_accuracy"], 4),
        )
    else:
        log.event(logger, "ember_transfer_skipped", reason="test_features.jsonl not present yet")

    # --- Figures ----------------------------------------------------------------------------------
    figures_dir = REPO_ROOT / "results" / "figures"
    fig_a = emit_clean_accuracy_figure(rf_original, mlp_original, figures_dir)
    fig_b = emit_combined_overlay_figure(rf_original, mlp_original, figures_dir)
    fig_c = emit_retraining_comparison_figure(rf_by_budget, mlp_by_budget, figures_dir)
    fig_d = emit_importance_shift_figure(rf_by_budget, mlp_by_budget, figures_dir)

    wall_seconds = time.perf_counter() - started
    host = {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }
    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-10b -- neural (MLP) vs. tree-ensemble (RF) detector: clean accuracy, "
        "M7-3's adversarial sweep, M7-8's retraining protocol, EMBER transfer if available",
        "seed": SEED,
        "top5": list(TOP5),
        "k_copies": K_COPIES,
        "training_budgets": list(TRAINING_BUDGETS),
        "permutation_repeats": _PERMUTATION_REPEATS,
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": host,
        "wall_seconds": wall_seconds,
        "train_n": len(x_train),
        "eval_n": len(x_eval),
        "rf": {str(b): _entry_for_sidecar(e) for b, e in rf_by_budget.items()},
        "mlp": {str(b): _entry_for_sidecar(e) for b, e in mlp_by_budget.items()},
        "ember_transfer": ember_transfer,
        "steps": list(STEPS),
        "figures": [str(p.relative_to(REPO_ROOT)) for p in (fig_a, fig_b, fig_c, fig_d)],
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(run_id, rf_by_budget, mlp_by_budget, ember_transfer)
    return 0


def _print_results_lines(
    run_id: str,
    rf_by_budget: dict[float, dict[str, Any]],
    mlp_by_budget: dict[float, dict[str, Any]],
    ember_transfer: dict[str, Any] | None,
) -> None:
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    for model_name, by_budget in (("rf", rf_by_budget), ("mlp", mlp_by_budget)):
        for budget in (0.0, *PARETO_BUDGETS):
            entry = by_budget[budget]
            cm = entry["clean_metrics"]
            pct = int(budget * 100)
            tag = "original" if budget == 0.0 else f"hardened @{pct}%"
            sys.stdout.write(
                f"{date} | detection/honeypot-m7-10b-neural | {model_name} {tag}, clean eval | "
                f"bal_acc={cm['balanced_accuracy']:.4f} prec={cm['precision']:.4f} rec={cm['recall']:.4f} "
                f"mcc={cm['mcc']:.4f} pr_auc={cm['pr_auc']:.4f} | measured | {run_id} | M7-10b\n"
            )
            adaptive = entry["adaptive_evasion"]
            sys.stdout.write(
                f"{date} | detection/honeypot-m7-10b-neural | {model_name} {tag}, adaptive evasion "
                f"| p10={adaptive['p10']:.4f} median={adaptive['median']:.4f} p90={adaptive['p90']:.4f} "
                f"| measured | {run_id} | M7-10b\n"
            )
            sys.stdout.write(
                f"{date} | detection/honeypot-m7-10b-neural | {model_name} {tag}, top-5 permutation "
                f"importance sum | sum={entry['top5_importance_sum']:.4f} | measured | {run_id} | M7-10b\n"
            )
    if ember_transfer is not None:
        sys.stdout.write(
            f"{date} | detection/honeypot-m7-10b-neural | EMBER transfer, n={ember_transfer['n']} | "
            f"rf_bal_acc={ember_transfer['rf']['balanced_accuracy']:.4f} "
            f"mlp_bal_acc={ember_transfer['mlp']['balanced_accuracy']:.4f} | measured | {run_id} | M7-10b\n"
        )
    sys.stdout.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
