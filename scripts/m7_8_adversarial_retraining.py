"""M7-8: does adversarial retraining harden the honeypot detector against M7-3's attack?

M7-3 (`scripts/run_adversarial_robustness.py`) measured the attack: a median adaptive adversary
needs only ~32% of the top-5 features' evasion range, and a quarter of malicious eval rows evade
with <=5% perturbation. This script measures the defense: augment the committed training corpus
with perturbed copies of its own positive rows (never negatives -- the adversary being simulated
is an evader, not a corpus-poisoner), fit the same declared Random-Forest ensemble on the
augmented draw, and re-run M7-3's exact degradation curves and adaptive search against it.

Data and model, and why this is not a chain-path or a re-tuned model
----------------------------------------------------------------------
Same posture as M7-3 and M7-7: this reads `data/honeypot/corpus_{train,eval}.csv` directly (never
the chain path, DEV-27's "committed corpus is the fixed dataset"), and never modifies those files
-- augmentation always operates on an in-memory copy. `configs/ml.yaml`'s declared hyperparameters
are reused unchanged; only the training *data* differs between "original" and "hardened". The
eval corpus is never perturbed at training time or evaluation time in the clean-accuracy numbers
(3a) -- comparability with M7-3's 0.8408 baseline requires it.

Three training budgets are swept (`TRAINING_BUDGETS`): 25%, 50%, 100% of each top-5 feature's own
evasion range, plus the degenerate 0% case as a pure sanity check (`retraining.
augment_positive_rows`'s no-op path -- see that module's docstring for why 0% must add zero rows,
not `K` exact duplicates, to reproduce the original fit exactly).

All reusable mechanics (perturbation, batched ensemble scoring, degradation curves, adaptive
search) live in `detection.adversarial` (shared with M7-3's own inline copy, both kept in
lockstep by construction); the augmentation-for-training logic lives in `detection.retraining`.
This script is the thin orchestrator (CLAUDE.md §3).

Safety (CLAUDE.md §2): every perturbation is arithmetic on a `numpy.ndarray` of floats. No
malware is generated, modified, or executed.

Usage::

    python scripts/m7_8_adversarial_retraining.py
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
    TOP_N,
    balanced_accuracy,
    combined_curve,
    ensemble_predict,
    select_best_importance_model,
    single_feature_curves,
    top_feature_importances,
)
from bsfr_sh.detection.adversarial import (  # noqa: E402
    adaptive_evasion as run_adaptive_evasion,
)
from bsfr_sh.detection.detector import DetectionModule  # noqa: E402
from bsfr_sh.detection.retraining import augment_positive_rows  # noqa: E402
from bsfr_sh.honeypot import features as ft  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import numpy_generator, seed_all  # noqa: E402

#: Matches M7-3's `SEED` and `run_phase3_detection.py`'s default -- the same fitted-model seed
#: every measured honeypot number in this project uses.
SEED = 20260912
#: M7-3's established CSV-path baseline (`RESULTS.md` M7-3, `20260922T155316Z-3ce801ca`), not
#: `RESULTS.md`'s chain-path M4b entry of 0.8422 -- DEV-27's amendment explains the 0.0014 gap.
#: Every number below is relative to this, same as M7-3.
CSV_PATH_REFERENCE_BAL_ACC = 0.8408
_REPRODUCTION_TOLERANCE = 1e-4
#: Perturbed copies per positive training row, at every nonzero budget.
K_COPIES = 5
#: 0.0 is the degenerate sanity check (see module docstring); 0.25/0.5/1.0 are the Pareto sweep
#: the session brief asks for.
TRAINING_BUDGETS = (0.0, 0.25, 0.5, 1.0)
PARETO_BUDGETS = (0.25, 0.5, 1.0)

_COLOR_ORIGINAL = "#4a3aa7"
_COLOR_BUDGETS = {0.25: "#2a78d6", 0.5: "#1baf7a", 1.0: "#eb6834"}
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


def fit_detector(x_train: np.ndarray, y_train: np.ndarray, ml_config: Any) -> DetectionModule:
    """Alg. 3 lines 2-3: train all four models, build `NProf`/`AProf`, on whatever draw is given.

    Identical machinery for the original and every hardened model -- only `x_train`/`y_train`
    differ. Never touches the eval set.
    """
    models = detection_models.train_all(x_train, y_train, ml_config, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    return DetectionModule(models=models, normal=normal, abnormal=abnormal)


def clean_metrics(detector: DetectionModule, x_eval: np.ndarray, y_eval: np.ndarray) -> dict[str, float]:
    """Balanced accuracy plus the honest-mode set (precision/recall/MCC/PR-AUC), on the
    untouched eval corpus -- comparable across the original and every hardened model."""
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


def feature_importance_shift(
    ml_config: Any,
    x_aug: np.ndarray,
    y_aug: np.ndarray,
    top5: list[str],
    baseline_importances: dict[str, float],
) -> dict[str, Any]:
    """Fits a fresh Random Forest on the augmented draw (the same importance-bearing model M7-3
    step 1 used) and checks whether the top-5 features' importance collapsed toward zero -- the
    "hardening by ignoring the perturbed features" failure mode the session brief names.
    """
    model = detection_models.build_model(ml_config, "random_forest", seed=SEED)
    model.fit(x_aug, y_aug)
    importances = dict(zip(ft.FEATURE_NAMES, (float(v) for v in model.feature_importances_), strict=True))
    new_top5 = top_feature_importances(model, ft.FEATURE_NAMES, TOP_N)
    return {
        "original_top5_importance_before": {name: baseline_importances[name] for name in top5},
        "original_top5_importance_after": {name: importances[name] for name in top5},
        "original_top5_importance_sum_before": sum(baseline_importances[name] for name in top5),
        "original_top5_importance_sum_after": sum(importances[name] for name in top5),
        "new_top5_by_importance": new_top5,
    }


def emit_clean_accuracy_figure(
    original_metrics: dict[str, float],
    hardened_metrics: dict[float, dict[str, float]],
    figures_dir: Path,
) -> Path:
    labels = ("balanced_accuracy", "precision", "recall", "mcc", "pr_auc")
    budgets = PARETO_BUDGETS
    fig, ax = plt.subplots(figsize=(8.0, 4.4), dpi=150)
    n_bars = 1 + len(budgets)
    width = 0.8 / n_bars
    x_pos = np.arange(len(labels))
    ax.bar(
        x_pos - 0.4 + width / 2,
        [original_metrics[k] for k in labels],
        width,
        color=_COLOR_ORIGINAL,
        label="original (0% training budget)",
    )
    for i, budget in enumerate(budgets, start=1):
        ax.bar(
            x_pos - 0.4 + width / 2 + i * width,
            [hardened_metrics[budget][k] for k in labels],
            width,
            color=_COLOR_BUDGETS[budget],
            label=f"hardened @{int(budget * 100)}%",
        )
    ax.set_xticks(x_pos, labels, rotation=15, fontsize=8.5)
    ax.set_ylim(min(-0.1, ax.get_ylim()[0]), 1.0)
    ax.axhline(0.0, color="#333333", linewidth=0.7)
    ax.set_title("Clean-eval cost of adversarial retraining", fontsize=10.5, loc="left")
    ax.legend(frameon=False, fontsize=7.5, loc="lower right")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig9a_clean_accuracy_cost.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_combined_overlay_figure(
    original_combined: list[float],
    hardened_combined: dict[float, list[float]],
    figures_dir: Path,
) -> Path:
    fig, ax = plt.subplots(figsize=(6.4, 4.4), dpi=150)
    ax.plot(
        STEPS,
        original_combined,
        marker="o",
        markersize=3.5,
        linewidth=2.0,
        color=_COLOR_ORIGINAL,
        label="original (M7-3)",
    )
    for budget, curve in hardened_combined.items():
        ax.plot(
            STEPS,
            curve,
            marker="s",
            markersize=3,
            linewidth=1.8,
            color=_COLOR_BUDGETS[budget],
            label=f"hardened @{int(budget * 100)}%",
        )
    ax.axhline(0.50, color=_COLOR_BASELINE, linestyle="--", linewidth=1.2, label="useless detector (0.50)")
    ax.set_title("Combined evasion: original vs. hardened", fontsize=10.5, loc="left")
    ax.set_xlabel("perturbation magnitude (fraction of each feature's evasion range, at eval time)")
    ax.set_ylabel("balanced accuracy")
    ax.set_ylim(0.0, 1.0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7.5, loc="lower left")
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig9b_combined_degradation_overlay.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_adaptive_comparison_figure(
    original_adaptive: dict[str, Any],
    hardened_adaptive: dict[float, dict[str, Any]],
    figures_dir: Path,
) -> Path:
    fig, ax = plt.subplots(figsize=(7.2, 4.4), dpi=150)
    rows = [("original", original_adaptive, _COLOR_ORIGINAL)]
    rows += [
        (f"hardened @{int(b * 100)}%", hardened_adaptive[b], _COLOR_BUDGETS[b])
        for b in PARETO_BUDGETS
    ]
    x_pos = np.arange(len(rows))
    width = 0.25
    for offset, key in ((-width, "p10"), (0.0, "median"), (width, "p90")):
        ax.bar(
            x_pos + offset,
            [r[1][key] for r in rows],
            width,
            label=key,
            color={"p10": "#c7ccd1", "median": "#4a3aa7", "p90": "#eb6834"}[key],
        )
    ax.set_xticks(x_pos, [r[0] for r in rows], fontsize=8.5)
    ax.set_ylim(0.0, 1.05)
    ax.set_ylabel("minimum L-inf perturbation to flip")
    ax.set_title("Adaptive evasion: p10/median/p90, original vs. hardened", fontsize=10.5, loc="left")
    ax.legend(frameon=False, fontsize=8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig9c_adaptive_evasion_comparison.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_pareto_figure(
    original_bal_acc: float,
    original_median_adaptive: float,
    hardened_metrics: dict[float, dict[str, float]],
    hardened_adaptive: dict[float, dict[str, Any]],
    figures_dir: Path,
) -> Path:
    fig, ax = plt.subplots(figsize=(6.0, 4.6), dpi=150)
    ax.scatter(
        [original_bal_acc],
        [original_median_adaptive],
        marker="*",
        s=180,
        color=_COLOR_ORIGINAL,
        label="original (no hardening)",
        zorder=3,
    )
    for budget in PARETO_BUDGETS:
        ax.scatter(
            [hardened_metrics[budget]["balanced_accuracy"]],
            [hardened_adaptive[budget]["median"]],
            marker="o",
            s=90,
            color=_COLOR_BUDGETS[budget],
            label=f"hardened @{int(budget * 100)}%",
            zorder=3,
        )
    ax.set_xlabel("clean balanced accuracy")
    ax.set_ylabel("median adaptive perturbation to evade")
    ax.set_title("Clean accuracy vs. robustness trade-off", fontsize=10.5, loc="left")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=8, loc="best")
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig9d_pareto_clean_vs_robustness.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def main() -> int:
    started = time.perf_counter()
    ml_config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    seed_all(SEED)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    x_train, y_train = _load_corpus("train")
    x_eval, y_eval = _load_corpus("eval")
    feature_index = {name: i for i, name in enumerate(ft.FEATURE_NAMES)}

    # --- Step 1: top-5 features, same procedure as M7-3, must land on the same table -----------
    importance_name, importance_model, importance_score = select_best_importance_model(
        ml_config, x_train, y_train, x_eval, y_eval, seed=SEED
    )
    top5_pairs = top_feature_importances(importance_model, ft.FEATURE_NAMES, TOP_N)
    top5 = [name for name, _ in top5_pairs]
    baseline_importances = dict(top5_pairs)
    missing = [name for name in top5 if name not in FEATURE_BOUNDS]
    if missing:
        raise SystemExit(
            f"FEATURE_BOUNDS has no entry for {missing!r}; the committed-seed top-5 changed "
            "since M7-3. Add a physically-grounded bound before rerunning."
        )
    indices = [feature_index[name] for name in top5]
    bounds = [FEATURE_BOUNDS[name] for name in top5]
    log.event(logger, "top5_selected", model=importance_name, top5=top5_pairs)

    # --- Original model: fit once, sanity-check against M7-3's established baseline ------------
    original_detector = fit_detector(x_train, y_train, ml_config)
    original_metrics = clean_metrics(original_detector, x_eval, y_eval)
    if abs(original_metrics["balanced_accuracy"] - CSV_PATH_REFERENCE_BAL_ACC) > _REPRODUCTION_TOLERANCE:
        raise SystemExit(
            f"original model bal_acc={original_metrics['balanced_accuracy']:.4f} does not "
            f"reproduce M7-3's {CSV_PATH_REFERENCE_BAL_ACC}; not safe to compare hardened models "
            "against it."
        )
    original_combined = combined_curve(original_detector, x_eval, y_eval, top5, feature_index)
    original_single = single_feature_curves(original_detector, x_eval, y_eval, top5, feature_index)
    original_adaptive = run_adaptive_evasion(original_detector, x_eval, y_eval, top5, feature_index)
    log.event(
        logger,
        "original_measured",
        bal_acc=round(original_metrics["balanced_accuracy"], 4),
        adaptive_median=round(original_adaptive["median"], 4),
        adaptive_p10=round(original_adaptive["p10"], 4),
        adaptive_p90=round(original_adaptive["p90"], 4),
    )

    # --- Step 2-5: hardened models, one per training budget --------------------------------------
    per_budget: dict[float, dict[str, Any]] = {}
    for budget in TRAINING_BUDGETS:
        rng = numpy_generator(SEED + round(budget * 1000))
        x_aug, y_aug = augment_positive_rows(
            x_train, y_train, indices, bounds, k=K_COPIES, max_perturbation=budget, rng=rng
        )
        hardened_detector = fit_detector(x_aug, y_aug, ml_config)
        hardened_metrics = clean_metrics(hardened_detector, x_eval, y_eval)

        entry: dict[str, Any] = {
            "budget": budget,
            "train_n": len(x_aug),
            "clean_metrics": hardened_metrics,
        }

        if budget == 0.0:
            # Degenerate sanity check only -- not part of the Pareto sweep.
            exact_match = hardened_metrics["balanced_accuracy"] == original_metrics["balanced_accuracy"]
            entry["degenerate_reproduces_original_exactly"] = exact_match
            log.event(
                logger,
                "degenerate_budget_checked",
                bal_acc=round(hardened_metrics["balanced_accuracy"], 4),
                matches_original_exactly=exact_match,
            )
        else:
            entry["combined_curve"] = combined_curve(
                hardened_detector, x_eval, y_eval, top5, feature_index
            )
            entry["single_feature_curves"] = single_feature_curves(
                hardened_detector, x_eval, y_eval, top5, feature_index
            )
            entry["adaptive_evasion"] = run_adaptive_evasion(
                hardened_detector, x_eval, y_eval, top5, feature_index
            )
            entry["feature_importance_shift"] = feature_importance_shift(
                ml_config, x_aug, y_aug, top5, baseline_importances
            )
            log.event(
                logger,
                "hardened_budget_measured",
                budget=budget,
                bal_acc=round(hardened_metrics["balanced_accuracy"], 4),
                adaptive_median=round(entry["adaptive_evasion"]["median"], 4),
                adaptive_p10=round(entry["adaptive_evasion"]["p10"], 4),
                adaptive_p90=round(entry["adaptive_evasion"]["p90"], 4),
                top5_importance_sum_before=round(
                    entry["feature_importance_shift"]["original_top5_importance_sum_before"], 4
                ),
                top5_importance_sum_after=round(
                    entry["feature_importance_shift"]["original_top5_importance_sum_after"], 4
                ),
            )
        per_budget[budget] = entry

    # --- Figures ----------------------------------------------------------------------------------
    hardened_metrics_by_budget = {b: per_budget[b]["clean_metrics"] for b in PARETO_BUDGETS}
    hardened_combined_by_budget = {b: per_budget[b]["combined_curve"] for b in PARETO_BUDGETS}
    hardened_adaptive_by_budget = {b: per_budget[b]["adaptive_evasion"] for b in PARETO_BUDGETS}

    figures_dir = REPO_ROOT / "results" / "figures"
    fig_a = emit_clean_accuracy_figure(original_metrics, hardened_metrics_by_budget, figures_dir)
    fig_b = emit_combined_overlay_figure(original_combined, hardened_combined_by_budget, figures_dir)
    fig_c = emit_adaptive_comparison_figure(original_adaptive, hardened_adaptive_by_budget, figures_dir)
    fig_d = emit_pareto_figure(
        original_metrics["balanced_accuracy"],
        original_adaptive["median"],
        hardened_metrics_by_budget,
        hardened_adaptive_by_budget,
        figures_dir,
    )

    wall_seconds = time.perf_counter() - started
    host = {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }
    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-8 -- adversarial retraining: does hardening the honeypot detector on "
        "perturbed positives buy robustness, and what does it cost on clean data?",
        "seed": SEED,
        "k_copies": K_COPIES,
        "training_budgets": list(TRAINING_BUDGETS),
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": host,
        "wall_seconds": wall_seconds,
        "train_n": len(x_train),
        "eval_n": len(x_eval),
        "eval_positive_n": int(y_eval.sum()),
        "importance_model": importance_name,
        "importance_model_individual_bal_acc": importance_score,
        "top5": top5_pairs,
        "original": {
            "clean_metrics": original_metrics,
            "combined_curve": original_combined,
            "single_feature_curves": original_single,
            "adaptive_evasion": original_adaptive,
            "reference_csv_path_bal_acc": CSV_PATH_REFERENCE_BAL_ACC,
        },
        "hardened": {str(b): entry for b, entry in per_budget.items()},
        "steps": list(STEPS),
        "figures": [str(p.relative_to(REPO_ROOT)) for p in (fig_a, fig_b, fig_c, fig_d)],
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(run_id, top5_pairs, original_metrics, original_adaptive, per_budget)
    return 0


def _print_results_lines(
    run_id: str,
    top5_pairs: list[tuple[str, float]],
    original_metrics: dict[str, float],
    original_adaptive: dict[str, Any],
    per_budget: dict[float, dict[str, Any]],
) -> None:
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    sys.stdout.write(
        f"{date} | detection/honeypot-adversarial-retraining | original model, clean eval | "
        f"bal_acc={original_metrics['balanced_accuracy']:.4f} prec={original_metrics['precision']:.4f} "
        f"rec={original_metrics['recall']:.4f} mcc={original_metrics['mcc']:.4f} "
        f"pr_auc={original_metrics['pr_auc']:.4f} | measured | {run_id} | M7-8, cf. M7-3 0.8408\n"
    )
    sys.stdout.write(
        f"{date} | detection/honeypot-adversarial-retraining | original model, adaptive evasion "
        f"| p10={original_adaptive['p10']:.4f} median={original_adaptive['median']:.4f} "
        f"p90={original_adaptive['p90']:.4f} | measured | {run_id} | M7-8, reproduces M7-3\n"
    )
    for budget in TRAINING_BUDGETS:
        entry = per_budget[budget]
        cm = entry["clean_metrics"]
        pct = int(budget * 100)
        sys.stdout.write(
            f"{date} | detection/honeypot-adversarial-retraining | hardened model @{pct}% "
            f"training budget, clean eval, train_n={entry['train_n']} | "
            f"bal_acc={cm['balanced_accuracy']:.4f} prec={cm['precision']:.4f} rec={cm['recall']:.4f} "
            f"mcc={cm['mcc']:.4f} pr_auc={cm['pr_auc']:.4f} | measured | {run_id} | M7-8\n"
        )
        if budget == 0.0:
            sys.stdout.write(
                f"{date} | detection/honeypot-adversarial-retraining | degenerate check @0% | "
                f"reproduces_original_exactly={entry['degenerate_reproduces_original_exactly']} "
                f"| measured | {run_id} | M7-8\n"
            )
        else:
            adaptive = entry["adaptive_evasion"]
            sys.stdout.write(
                f"{date} | detection/honeypot-adversarial-retraining | hardened model @{pct}% "
                f"training budget, adaptive evasion | p10={adaptive['p10']:.4f} "
                f"median={adaptive['median']:.4f} p90={adaptive['p90']:.4f} | measured | {run_id} | M7-8\n"
            )
            shift = entry["feature_importance_shift"]
            sys.stdout.write(
                f"{date} | detection/honeypot-adversarial-retraining | hardened model @{pct}% "
                "training budget, top-5 importance shift | sum_before="
                f"{shift['original_top5_importance_sum_before']:.4f} sum_after="
                f"{shift['original_top5_importance_sum_after']:.4f} | measured | {run_id} | M7-8\n"
            )


if __name__ == "__main__":
    raise SystemExit(main())
