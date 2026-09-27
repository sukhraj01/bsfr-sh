"""M7-15: federated detection — does cross-replica disagreement catch what statistics (M7-12) and
protocol restriction (M7-14) both measured null for?

The paper's own architecture already replicates `BC_SigRW` identically across four cloud servers
(`docs/ARCHITECTURE.md` §consensus, `n=4`), each holding a decryption key
(`docs/THREAT_MODEL.md` Trust Assumption 6) and capable of running Alg. 3 independently. Nothing
about that requires a new protocol message: it is redundancy the paper already pays for and never
uses. `detection.federated` supplies the generic mechanism (majority vote, disagreement scoring,
outlier identification); this script measures it against exactly M7-11's three strategies at
5/10/20% budgets, under three scenarios that each answer "why would replicas trained on the same
chain ever disagree?" differently:

Scenario A — the poisoner trains on a different view than it commits.
    Rational for an attacker who wants to degrade *others'* detection, not its own: it commits
    poisoned data (so three honest nodes train on it) but fits its own model on the pre-poison,
    clean view. The measured irony this scenario exists to state plainly: the node disagreement
    identifies is the one with the *better* model, not the worse one.

Scenario B — algorithm diversity.
    All four nodes train on the identical poisoned draw; each runs a different one of
    `configs/ml.yaml`'s four declared algorithms (RF/DT/KNN/LR). Disagreement here comes from
    differential model sensitivity to the same poison, not from any difference in training data.

Scenario C — a private, never-committed holdout.
    Not in the paper's Algorithm 3 (which trains exclusively on `BC_SigRW`) — this project's own
    extension of the idea. Each of four nodes reserves 10% of its own contribution before it is
    ever committed, fits on the (possibly poisoned) committed 90%, and scores itself against its
    own held-back 10%. No cross-node communication is needed for this one; the question is
    whether a single node can notice its own degradation without any vote at all.

Safety (CLAUDE.md §2): arithmetic on `FT_RW` feature arrays and 0/1 prediction vectors. No new
model architecture, no malware, no live attack. `detection/poisoning.py` is called unmodified
(OUT OF SCOPE line 1); this script trains multiple detector *instances* over its outputs, it does
not change what any of them compute.

Usage::

    python scripts/m7_15_federated_detection.py
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
from bsfr_sh.detection.adversarial import balanced_accuracy, ensemble_predict  # noqa: E402
from bsfr_sh.detection.detector import DetectionModule  # noqa: E402
from bsfr_sh.detection.federated import analyze_disagreement, vote  # noqa: E402
from bsfr_sh.detection.poisoning import (  # noqa: E402
    PoisonResult,
    anchor_point_injection,
    feature_poison,
    label_flip,
)
from bsfr_sh.honeypot import features as ft  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import numpy_generator, seed_all  # noqa: E402

#: Kept identical to M7-11/12/14's own `SEED` -- the CSV-path reference (0.8408) below was
#: established at this seed, and a different seed's baseline drifts by exactly the CSV-vs-chain
#: gap DEV-27 already explains, which would misattribute seed sensitivity to a real effect.
SEED = 20260912
CSV_PATH_REFERENCE_BAL_ACC = 0.8408  # RESULTS.md M7-3/M7-11's own established reference
_REPRODUCTION_TOLERANCE = 1e-4
STRATEGIES = ("label_flip", "feature_poison", "anchor_point_injection")
_STRATEGY_FN = {
    "label_flip": label_flip,
    "feature_poison": feature_poison,
    "anchor_point_injection": anchor_point_injection,
}
#: Narrower than M7-11/12/14's five-budget sweep -- the session brief asks for exactly these
#: three, the mid-to-high end of the range where poisoning's own damage is measurable at all.
BUDGETS = (0.05, 0.10, 0.20)
#: Scenario B's four nodes, one algorithm each -- `configs/ml.yaml`'s own declared four.
SCENARIO_B_ALGORITHMS = (
    "random_forest",
    "decision_tree",
    "k_nearest_neighbours",
    "logistic_regression",
)
#: Scenario C: each of four nodes reserves this fraction of its own contribution before
#: committing, per the session brief's own number.
SCENARIO_C_HOLDOUT_FRACTION = 0.10
SCENARIO_C_N_NODES = 4


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


def fit_detector(
    x_train: np.ndarray, y_train: np.ndarray, ml_config: Any, *, seed: int
) -> DetectionModule:
    """Alg. 3 lines 2-3, on whatever training draw (and however many enabled models) it is given."""
    models = detection_models.train_all(x_train, y_train, ml_config, seed=seed)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    return DetectionModule(models=models, normal=normal, abnormal=abnormal)


def fit_single_algorithm_detector(
    x_train: np.ndarray, y_train: np.ndarray, ml_config: Any, algorithm: str, *, seed: int
) -> DetectionModule:
    """Scenario B: one node, one declared algorithm, same NProf/AProf machinery as `fit_detector`
    but scored through a single model's soft-vote (`profiles.ensemble_score` over a one-entry
    `models` mapping degenerates to that model's own `predict_proba`)."""
    estimator = detection_models.build_model(ml_config, algorithm, seed=seed)
    estimator.fit(x_train, y_train)
    models = {algorithm: estimator}
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


def _stratified_holdout_split(
    x: np.ndarray, y: np.ndarray, holdout_fraction: float, rng: np.random.Generator
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Split `(x, y)` into a committed majority and a private holdout minority, stratified so
    both halves keep the same class balance the full set has -- an unstratified split risks a
    holdout with too few positive rows to score anything on."""
    committed_idx: list[int] = []
    holdout_idx: list[int] = []
    for class_value in (0, 1):
        class_idx = np.flatnonzero(y == class_value)
        shuffled = rng.permutation(class_idx)
        n_holdout = round(holdout_fraction * len(shuffled))
        holdout_idx.extend(int(i) for i in shuffled[:n_holdout])
        committed_idx.extend(int(i) for i in shuffled[n_holdout:])
    committed = np.array(sorted(committed_idx))
    holdout = np.array(sorted(holdout_idx))
    return x[committed], y[committed], x[holdout], y[holdout]


# ================================================================================================
# Scenario A -- the poisoner trains on a different (clean) view than it commits
# ================================================================================================


def run_scenario_a(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    ml_config: Any,
    poisoner_predictions: np.ndarray,
    poisoner_bal_acc: float,
) -> dict[str, dict[float, dict[str, Any]]]:
    results: dict[str, dict[float, dict[str, Any]]] = {s: {} for s in STRATEGIES}
    for strategy in STRATEGIES:
        fn = _STRATEGY_FN[strategy]
        for budget in BUDGETS:
            rng = numpy_generator(SEED + round(budget * 10_000) + hash(("a", strategy)) % 1000)
            poisoned: PoisonResult = fn(x_train, y_train, budget, rng=rng)
            honest_detector = fit_detector(poisoned.x, poisoned.y, ml_config, seed=SEED)
            honest_pred = ensemble_predict(honest_detector, x_eval)
            honest_bal_acc = balanced_accuracy(y_eval, honest_pred)

            per_node = {
                "CS_honest_1": honest_pred,
                "CS_honest_2": honest_pred.copy(),
                "CS_honest_3": honest_pred.copy(),
                "CS_poisoner": poisoner_predictions,
            }
            report = analyze_disagreement(per_node, y_true=y_eval)
            outlier_is_poisoner = report.outlier_node == "CS_poisoner"
            irony = poisoner_bal_acc > honest_bal_acc

            results[strategy][budget] = {
                "n_poisoned": poisoned.n_poisoned,
                "honest_bal_acc": honest_bal_acc,
                "poisoner_bal_acc": poisoner_bal_acc,
                "majority_bal_acc": report.majority_accuracy,
                "disagreement_rate": float(np.mean(poisoner_predictions != honest_pred)),
                "outlier_node": report.outlier_node,
                "outlier_is_poisoner": outlier_is_poisoner,
                "irony_poisoner_more_accurate": irony,
                "accuracy_excluding_outlier": report.accuracy_excluding_outlier,
                "excluding_outlier_improves": report.excluding_outlier_improves,
            }
    return results


# ================================================================================================
# Scenario B -- algorithm diversity over one shared poisoned draw
# ================================================================================================


def run_scenario_b(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    ml_config: Any,
) -> dict[str, dict[float, dict[str, Any]]]:
    results: dict[str, dict[float, dict[str, Any]]] = {s: {} for s in STRATEGIES}
    for strategy in STRATEGIES:
        fn = _STRATEGY_FN[strategy]
        for budget in BUDGETS:
            rng = numpy_generator(SEED + round(budget * 10_000) + hash(("b", strategy)) % 1000)
            poisoned: PoisonResult = fn(x_train, y_train, budget, rng=rng)

            per_node: dict[str, np.ndarray] = {}
            individual_bal_acc: dict[str, float] = {}
            for algorithm in SCENARIO_B_ALGORITHMS:
                detector = fit_single_algorithm_detector(
                    poisoned.x, poisoned.y, ml_config, algorithm, seed=SEED
                )
                pred = ensemble_predict(detector, x_eval)
                per_node[algorithm] = pred
                individual_bal_acc[algorithm] = balanced_accuracy(y_eval, pred)

            report = analyze_disagreement(per_node, y_true=y_eval)
            voting = vote(per_node)
            worst_individual = min(individual_bal_acc.values())
            majority_acc = report.majority_accuracy
            assert majority_acc is not None
            results[strategy][budget] = {
                "n_poisoned": poisoned.n_poisoned,
                "individual_bal_acc": individual_bal_acc,
                "majority_bal_acc": majority_acc,
                "worst_individual_bal_acc": worst_individual,
                "recovers_worst_model": majority_acc >= worst_individual,
                "disagreement_fraction": voting.disagreement_fraction,
                "flagged_nodes": list(voting.flagged_nodes),
                "outlier_node": report.outlier_node,
            }
    return results


# ================================================================================================
# Scenario C -- a private, never-committed holdout per node
# ================================================================================================


def run_scenario_c(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    ml_config: Any,
) -> dict[str, dict[float, dict[str, Any]]]:
    results: dict[str, dict[float, dict[str, Any]]] = {s: {} for s in STRATEGIES}
    for strategy in STRATEGIES:
        fn = _STRATEGY_FN[strategy]
        for budget in BUDGETS:
            per_node_drop: list[float] = []
            per_node_holdout_baseline: list[float] = []
            per_node_holdout_poisoned: list[float] = []
            per_node_eval_poisoned: list[float] = []
            for node_index in range(SCENARIO_C_N_NODES):
                split_rng = numpy_generator(SEED + 500_000 + node_index)
                x_committed, y_committed, x_holdout, y_holdout = _stratified_holdout_split(
                    x_train, y_train, SCENARIO_C_HOLDOUT_FRACTION, split_rng
                )

                baseline_detector = fit_detector(x_committed, y_committed, ml_config, seed=SEED)
                holdout_baseline = balanced_accuracy(
                    y_holdout, ensemble_predict(baseline_detector, x_holdout)
                )

                poison_rng = numpy_generator(
                    SEED + round(budget * 10_000) + hash(("c", strategy, node_index)) % 1000
                )
                poisoned: PoisonResult = fn(x_committed, y_committed, budget, rng=poison_rng)
                poisoned_detector = fit_detector(poisoned.x, poisoned.y, ml_config, seed=SEED)
                holdout_poisoned = balanced_accuracy(
                    y_holdout, ensemble_predict(poisoned_detector, x_holdout)
                )
                eval_poisoned = balanced_accuracy(
                    y_eval, ensemble_predict(poisoned_detector, x_eval)
                )

                per_node_holdout_baseline.append(holdout_baseline)
                per_node_holdout_poisoned.append(holdout_poisoned)
                per_node_eval_poisoned.append(eval_poisoned)
                per_node_drop.append(holdout_baseline - holdout_poisoned)

            drop_arr = np.array(per_node_drop)
            mean_drop = float(drop_arr.mean())
            std_drop = float(drop_arr.std(ddof=1)) if len(drop_arr) > 1 else 0.0
            # Detectable, stated as a criterion rather than eyeballed: the mean drop across the
            # four independent private-holdout splits must be positive (real degradation, not
            # noise pointing the wrong way) AND must not contain zero within one node-to-node
            # standard deviation -- the same "does zero sit inside the band" convention M7-14
            # used for its own robustness check.
            detectable = mean_drop > 0.0 and (mean_drop - std_drop) > 0.0

            results[strategy][budget] = {
                "n_nodes": SCENARIO_C_N_NODES,
                "holdout_baseline_bal_acc": per_node_holdout_baseline,
                "holdout_poisoned_bal_acc": per_node_holdout_poisoned,
                "eval_poisoned_bal_acc": per_node_eval_poisoned,
                "per_node_drop": per_node_drop,
                "mean_drop": mean_drop,
                "std_drop": std_drop,
                "detectable_by_private_holdout": detectable,
            }
    return results


# ================================================================================================
# Figures + comparison table
# ================================================================================================

_STRATEGY_TITLE = {
    "label_flip": "label flipping",
    "feature_poison": "feature poisoning",
    "anchor_point_injection": "anchor-point injection",
}
_COLOR = {
    "label_flip": "#e34948",
    "feature_poison": "#eb6834",
    "anchor_point_injection": "#4a3aa7",
}


def emit_scenario_figure(
    scenario_a: dict[str, dict[float, dict[str, Any]]],
    scenario_b: dict[str, dict[float, dict[str, Any]]],
    original_bal_acc: float,
    figures_dir: Path,
) -> Path:
    fig, axes = plt.subplots(1, 2, figsize=(11.0, 4.4), dpi=150, sharey=True)
    budgets_pct = [b * 100 for b in BUDGETS]

    ax = axes[0]
    for strategy in STRATEGIES:
        curve = [scenario_a[strategy][b]["majority_bal_acc"] for b in BUDGETS]
        ax.plot(
            budgets_pct,
            curve,
            marker="o",
            markersize=4,
            linewidth=2.0,
            color=_COLOR[strategy],
            label=_STRATEGY_TITLE[strategy],
        )
    ax.axhline(original_bal_acc, color="#333333", linestyle=":", linewidth=1.1)
    ax.set_title("Scenario A: majority (3 honest + 1 clean poisoner)", fontsize=9.5, loc="left")
    ax.set_xlabel("poisoning budget (%)")
    ax.set_ylabel("balanced accuracy on clean eval")
    ax.set_ylim(0.45, 0.90)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)

    ax2 = axes[1]
    for strategy in STRATEGIES:
        majority_curve = [scenario_b[strategy][b]["majority_bal_acc"] for b in BUDGETS]
        worst_curve = [scenario_b[strategy][b]["worst_individual_bal_acc"] for b in BUDGETS]
        ax2.plot(
            budgets_pct,
            majority_curve,
            marker="o",
            markersize=4,
            linewidth=2.0,
            color=_COLOR[strategy],
            label=f"{_STRATEGY_TITLE[strategy]} (majority)",
        )
        ax2.plot(
            budgets_pct,
            worst_curve,
            marker="x",
            markersize=5,
            linewidth=1.2,
            linestyle="--",
            color=_COLOR[strategy],
            alpha=0.6,
        )
    ax2.set_title(
        "Scenario B: algorithm-diverse majority vs. worst individual", fontsize=9.5, loc="left"
    )
    ax2.set_xlabel("poisoning budget (%)")
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)
    ax2.grid(axis="y", linewidth=0.5, alpha=0.4)

    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="lower center",
        ncol=3,
        frameon=False,
        fontsize=8,
        bbox_to_anchor=(0.5, -0.02),
    )
    fig.suptitle(
        "M7-15: federated detection under honeypot poisoning", fontsize=10.5, x=0.02, ha="left"
    )
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig15a_federated_scenarios.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def build_comparison_table(
    scenario_b: dict[str, dict[float, dict[str, Any]]],
) -> dict[str, dict[str, str]]:
    """The capstone table the report wants: M7-11 (no defense) / M7-12 (statistical) /
    M7-14 (commit-reveal) / M7-15 (federated, scenario B's majority vote -- the one scenario that
    needs no assumption about who trains on what) at the 10% budget, cited from each session's own
    already-published `RESULTS.md` numbers except the M7-15 row, measured here."""
    cited_m7_11 = {
        "label_flip": 0.8279,
        "feature_poison": 0.8396,
        "anchor_point_injection": 0.8468,
    }
    cited_m7_12 = {
        "label_flip": "not prevented (maha=0.3244)",
        "feature_poison": "not prevented (maha=0.2828)",
        "anchor_point_injection": "not prevented (maha=0.0083)",
    }
    cited_m7_14 = {
        "label_flip": 0.8153,
        "feature_poison": 0.8478,
        "anchor_point_injection": 0.8412,
    }
    table: dict[str, dict[str, str]] = {
        "M7-11 (no defense)": {s: f"bal_acc={cited_m7_11[s]:.4f}" for s in STRATEGIES},
        "M7-12 (statistical)": dict(cited_m7_12),
        "M7-14 (commit-reveal)": {s: f"bal_acc={cited_m7_14[s]:.4f}" for s in STRATEGIES},
        "M7-15 (federated, scenario B majority)": {
            s: f"bal_acc={scenario_b[s][0.10]['majority_bal_acc']:.4f}" for s in STRATEGIES
        },
    }
    return table


def main() -> int:
    started = time.perf_counter()
    ml_config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    seed_all(SEED)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    x_train, y_train = _load_corpus("train")
    x_eval, y_eval = _load_corpus("eval")

    original_detector = fit_detector(x_train, y_train, ml_config, seed=SEED)
    original_metrics = clean_metrics(original_detector, x_eval, y_eval)
    drift = abs(original_metrics["balanced_accuracy"] - CSV_PATH_REFERENCE_BAL_ACC)
    if drift > _REPRODUCTION_TOLERANCE:
        raise SystemExit(
            f"baseline bal_acc={original_metrics['balanced_accuracy']:.4f} does not reproduce "
            f"the established {CSV_PATH_REFERENCE_BAL_ACC} (drift={drift:.4f})"
        )
    log.event(logger, "baseline_measured", bal_acc=round(original_metrics["balanced_accuracy"], 4))

    # The poisoner's own clean-trained model in scenario A: constant across every strategy/budget
    # cell since it never sees poisoned data at all.
    poisoner_predictions = ensemble_predict(original_detector, x_eval)
    poisoner_bal_acc = balanced_accuracy(y_eval, poisoner_predictions)

    scenario_a = run_scenario_a(
        x_train, y_train, x_eval, y_eval, ml_config, poisoner_predictions, poisoner_bal_acc
    )
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            cell = scenario_a[strategy][budget]
            log.event(
                logger,
                "scenario_a_cell",
                strategy=strategy,
                budget=budget,
                honest_bal_acc=round(cell["honest_bal_acc"], 4),
                poisoner_bal_acc=round(cell["poisoner_bal_acc"], 4),
                outlier_is_poisoner=cell["outlier_is_poisoner"],
                irony=cell["irony_poisoner_more_accurate"],
            )

    scenario_b = run_scenario_b(x_train, y_train, x_eval, y_eval, ml_config)
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            cell = scenario_b[strategy][budget]
            log.event(
                logger,
                "scenario_b_cell",
                strategy=strategy,
                budget=budget,
                majority_bal_acc=round(cell["majority_bal_acc"], 4),
                worst_individual=round(cell["worst_individual_bal_acc"], 4),
                recovers=cell["recovers_worst_model"],
            )

    scenario_c = run_scenario_c(x_train, y_train, x_eval, y_eval, ml_config)
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            cell = scenario_c[strategy][budget]
            log.event(
                logger,
                "scenario_c_cell",
                strategy=strategy,
                budget=budget,
                mean_drop=round(cell["mean_drop"], 4),
                std_drop=round(cell["std_drop"], 4),
                detectable=cell["detectable_by_private_holdout"],
            )

    comparison_table = build_comparison_table(scenario_b)

    figures_dir = REPO_ROOT / "results" / "figures"
    fig_a = emit_scenario_figure(
        scenario_a, scenario_b, original_metrics["balanced_accuracy"], figures_dir
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
        "purpose": "M7-15 -- federated detection via cross-replica disagreement: 3 scenarios x "
        "3 poisoning strategies x 3 budgets",
        "seed": SEED,
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": host,
        "wall_seconds": wall_seconds,
        "csv_path_reference_bal_acc": CSV_PATH_REFERENCE_BAL_ACC,
        "original_metrics": original_metrics,
        "budgets": list(BUDGETS),
        "scenario_a": {s: {str(b): scenario_a[s][b] for b in BUDGETS} for s in STRATEGIES},
        "scenario_b": {s: {str(b): scenario_b[s][b] for b in BUDGETS} for s in STRATEGIES},
        "scenario_c": {
            s: {
                str(b): {
                    k: (v if not isinstance(v, list) else [float(x) for x in v])
                    for k, v in scenario_c[s][b].items()
                }
                for b in BUDGETS
            }
            for s in STRATEGIES
        },
        "comparison_table": comparison_table,
        "figures": [str(fig_a.relative_to(REPO_ROOT))],
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(
        run_id, original_metrics, scenario_a, scenario_b, scenario_c, comparison_table
    )
    return 0


def _print_results_lines(
    run_id: str,
    original_metrics: dict[str, float],
    scenario_a: dict[str, dict[float, dict[str, Any]]],
    scenario_b: dict[str, dict[float, dict[str, Any]]],
    scenario_c: dict[str, dict[float, dict[str, Any]]],
    comparison_table: dict[str, dict[str, str]],
) -> None:
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-15-federated | unpoisoned baseline, clean eval | "
        f"bal_acc={original_metrics['balanced_accuracy']:.4f} | measured | {run_id} | "
        "M7-15, cf. M7-3/M7-11/M7-14 0.8408\n"
    )
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            pct = int(budget * 100)
            a = scenario_a[strategy][budget]
            sys.stdout.write(
                f"{date} | detection/honeypot-m7-15-scenario-a | {strategy} @{pct}% budget | "
                f"honest_bal_acc={a['honest_bal_acc']:.4f} "
                f"poisoner_bal_acc={a['poisoner_bal_acc']:.4f} "
                f"majority_bal_acc={a['majority_bal_acc']:.4f} "
                f"disagreement_rate={a['disagreement_rate']:.4f} "
                f"outlier_node={a['outlier_node']} outlier_is_poisoner={a['outlier_is_poisoner']} "
                f"irony={a['irony_poisoner_more_accurate']} excluding_outlier_improves="
                f"{a['excluding_outlier_improves']} | measured | {run_id} | M7-15\n"
            )
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            pct = int(budget * 100)
            b = scenario_b[strategy][budget]
            individual = " ".join(f"{k}={v:.4f}" for k, v in b["individual_bal_acc"].items())
            sys.stdout.write(
                f"{date} | detection/honeypot-m7-15-scenario-b | {strategy} @{pct}% budget | "
                f"majority_bal_acc={b['majority_bal_acc']:.4f} "
                f"worst_individual={b['worst_individual_bal_acc']:.4f} "
                f"recovers_worst_model={b['recovers_worst_model']} {individual} | measured | "
                f"{run_id} | M7-15\n"
            )
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            pct = int(budget * 100)
            c = scenario_c[strategy][budget]
            sys.stdout.write(
                f"{date} | detection/honeypot-m7-15-scenario-c | {strategy} @{pct}% budget, "
                f"n_nodes={c['n_nodes']} | mean_drop={c['mean_drop']:+.4f} "
                f"std_drop={c['std_drop']:.4f} "
                f"detectable_by_private_holdout={c['detectable_by_private_holdout']} | "
                f"measured | {run_id} | M7-15\n"
            )
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-15-comparison-table | four-defense comparison @10% budget "
        f"| {json.dumps(comparison_table, sort_keys=True)} | measured+cited | {run_id} | "
        "M7-15, cites M7-11/M7-12/M7-14's own already-published RESULTS.md lines\n"
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
