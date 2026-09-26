"""M7-14: does committing before seeing the honest distribution degrade honeypot poisoning?

M7-12 (DEV-38) measured that statistical drift detection cannot catch anchor-point injection at
any budget, for a structural reason: the attack's engineered midpoint between the two class
centroids sits, in a roughly class-balanced corpus, almost exactly at the *population* mean, so
the batch designed to look most like an attack looks the least anomalous of the three. That
midpoint is only computable because `detection.poisoning.anchor_point_injection` reads the
*current* `x_train`/`y_train` centroids directly — the adversary sees the honest distribution it
is about to poison before deciding what to submit. This script measures what happens when that
visibility is removed at the protocol level (`consensus.commit_reveal`, DEV-40): the adversary
must commit to a batch computed from a *historical* view only, before this round's honest
contribution is revealed.

The information constraint, modelled explicitly (not just argued)
---------------------------------------------------------------------
Every M7-11 strategy is still called completely unmodified (`detection/poisoning.py`, OUT OF
SCOPE line 1) — this script constrains what it is *given* to operate on, not how it operates.
`x_train`/`y_train` (the committed corpus, same as every other M7-x poisoning experiment) is split
once, deterministically, into a **historical** partition (85%, what the chain already holds when
the adversary must commit) and **this round's honest contribution** (15%, not yet revealed at
commit time). The adversary's strategy function is called on the historical partition only; its
poisoned output is then merged with this round's (unmodified) honest contribution, and *that*
merged set is what the detector is actually fit on — the same total corpus content M7-11 fits on,
reshuffled only by which 15% is temporarily withheld from the adversary's view. `n_poisoned` is
therefore computed against the *historical* positive-row count, not the full corpus's — reported
plainly per cell rather than silently forced to match M7-11's own count, since a real adversary
committing early genuinely has a smaller pool to draw budget from.

Four measurements, in order (items 3-5 of the session brief)
------------------------------------------------------------
1. The 15-cell table: for each (strategy, budget), defended (commit-reveal) balanced accuracy
   against M7-11's already-measured undefended number (cited, not recomputed — same posture
   M7-13 used for its ClaMP/EMBER reference dicts).
2. Failure mode (a): 10 sequential commit-reveal rounds, anchor-point injection only, the
   adversary's historical view growing (and including its own prior poison) each round. Does the
   measured damage per round strengthen?
3. Failure mode (b): collusion. Argued, not measured — see the module docstring's own citation of
   `tests/unit/test_pbft_byzantine.py`'s existing `f<n/3` result. No code in this script models a
   second colluding replica; item 4b of the brief asks for a bound, not a new experiment.
4. Failure mode (c): withholding. A `consensus.commit_reveal.WithholdTracker` simulation: an
   adversary that always withholds is permanently excluded after exactly
   `DEFAULT_MAX_CONSECUTIVE_WITHHOLDS` rounds — deterministic, reported directly.
5. Combination with M7-12: every defended cell's poisoned rows scored by the identical
   `detection.drift.DriftDetector`/`DriftPolicy` M7-12 used, against M7-12's own 15 reference
   Mahalanobis scores (cited) — does commit-reveal's degraded anchor-point estimate become newly
   visible to statistical drift detection where the full-information version was not?

Safety (CLAUDE.md §2): arithmetic on `FT_RW` feature arrays and cryptographic commitments over
synthetic honeypot records. No malware, no live attack, no network call outside this process.

Usage::

    python scripts/m7_14_commit_reveal_defense.py
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

from bsfr_sh.consensus.commit_reveal import (  # noqa: E402
    CommitRevealRound,
    Reveal,
    WithholdTracker,
    commit_batch,
)
from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, config_hash  # noqa: E402
from bsfr_sh.detection import metrics as detection_metrics  # noqa: E402
from bsfr_sh.detection import models as detection_models  # noqa: E402
from bsfr_sh.detection import profiles as detection_profiles  # noqa: E402
from bsfr_sh.detection.adversarial import balanced_accuracy, ensemble_predict  # noqa: E402
from bsfr_sh.detection.detector import DetectionModule  # noqa: E402
from bsfr_sh.detection.drift import DriftDetector, DriftMethod, DriftPolicy  # noqa: E402
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

#: Matches every other measured honeypot number in this project (M7-3/M7-7/M7-8/M7-11/M7-12).
SEED = 20260912
CSV_PATH_REFERENCE_BAL_ACC = 0.8408
_REPRODUCTION_TOLERANCE = 1e-4
STRATEGIES = ("label_flip", "feature_poison", "anchor_point_injection")
_STRATEGY_FN = {
    "label_flip": label_flip,
    "feature_poison": feature_poison,
    "anchor_point_injection": anchor_point_injection,
}
BUDGETS = (0.01, 0.05, 0.10, 0.20, 0.50)
#: A fixed per-strategy seed offset. M7-11/M7-12 used `hash(strategy) % 1000` for the equivalent
#: role; `hash()` on a `str` is process-randomized (`PYTHONHASHSEED`, consumed at interpreter
#: start-up -- `util.seeding`'s own documented caveat: setting it mid-run does not make `hash()`
#: reproducible within that run). This script's own numbers are new, not a re-citation of a
#: settled figure, so they are made byte-reproducible across runs rather than inheriting that
#: latent non-determinism.
_STRATEGY_SEED_OFFSET: dict[str, int] = {
    "label_flip": 0,
    "feature_poison": 1,
    "anchor_point_injection": 2,
}
#: What fraction of the committed corpus is "already on the chain" (visible to the adversary at
#: commit time) vs. "this round's honest contribution" (revealed only after commit). Chosen large
#: enough that the historical partition alone is a reliable estimate of the true class centroids
#: (the realistic case for a chain with real submission history) -- a *small* historical partition
#: would make the constraint trivially binding for the wrong reason (too little data to estimate
#: anything, not "the adversary genuinely cannot see this round").
HISTORICAL_FRACTION = 0.85
#: A second, deliberately much smaller historical partition -- an "early chain" scenario, where
#: relatively little has been committed yet and each round's honest contribution is large
#: relative to what already exists. Run only for `anchor_point_injection` (the one strategy the
#: constraint is designed to bind on) as a sensitivity check on `HISTORICAL_FRACTION`'s own
#: choice: if the mature-chain result (0.85) shows little effect because 85% of a stationary
#: corpus already estimates the same centroid the full corpus would, this checks whether a
#: genuinely small historical view binds the constraint harder.
EARLY_CHAIN_HISTORICAL_FRACTION = 0.15

#: M7-11's own established undefended numbers (`RESULTS.md` M7-11, `20260925T193933Z-3d53aee9`),
#: cited rather than recomputed -- same posture M7-13 used for its ClaMP/EMBER reference dicts.
UNDEFENDED_BAL_ACC: dict[str, dict[float, float]] = {
    "label_flip": {0.01: 0.8259, 0.05: 0.8277, 0.10: 0.8279, 0.20: 0.7908, 0.50: 0.6680},
    "feature_poison": {0.01: 0.8342, 0.05: 0.8350, 0.10: 0.8396, 0.20: 0.8261, 0.50: 0.8378},
    "anchor_point_injection": {
        0.01: 0.8464,
        0.05: 0.8438,
        0.10: 0.8468,
        0.20: 0.8415,
        0.50: 0.8284,
    },
}
#: M7-12's own established undefended Mahalanobis scores, all 15 cells (`RESULTS.md` M7-12,
#: `20260926T041840Z-670ec207`), cited for the combination experiment (item 5).
UNDEFENDED_MAHALANOBIS: dict[str, dict[float, float]] = {
    "label_flip": {0.01: 0.5693, 0.05: 0.3660, 0.10: 0.3244, 0.20: 0.3236, 0.50: 0.3256},
    "feature_poison": {0.01: 0.5015, 0.05: 0.3229, 0.10: 0.2828, 0.20: 0.3271, 0.50: 0.3268},
    "anchor_point_injection": {
        0.01: 0.0162,
        0.05: 0.0084,
        0.10: 0.0083,
        0.20: 0.0078,
        0.50: 0.0085,
    },
}
MAHALANOBIS_POLICY = DriftPolicy(method=DriftMethod.MAHALANOBIS, threshold=3.0, min_history=5)
CHUNK_SIZE = 25
#: Item 4a: how many sequential commit-reveal rounds the adversary gets to refine its estimate.
N_REPEATED_ROUNDS = 10
#: Item 4a: fixed per-round budget (fraction of that round's *historical* positive-row count) --
#: not swept, since the question is round-over-round strengthening, not budget sensitivity (the
#: 15-cell sweep above already covers budget).
REPEATED_ROUND_BUDGET = 0.20

_COLOR_UNDEFENDED = "#9b9b9b"
_COLOR_DEFENDED = "#2a9d5c"
_COLOR_BASELINE = "#333333"


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
    models = detection_models.train_all(x_train, y_train, ml_config, seed=SEED)
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


def _historical_split(
    x_train: np.ndarray, y_train: np.ndarray, *, historical_fraction: float, seed: int
) -> tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]]:
    """A fixed, seeded partition of the training corpus into "already on the chain" (historical,
    visible to the adversary at commit time) and "this round's honest contribution" (revealed
    only after commit). The same partition is reused for every (strategy, budget) cell so results
    are comparable across the sweep."""
    rng = numpy_generator(seed)
    order = rng.permutation(len(y_train))
    n_hist = round(historical_fraction * len(y_train))
    hist_idx, round_idx = order[:n_hist], order[n_hist:]
    return (x_train[hist_idx], y_train[hist_idx]), (x_train[round_idx], y_train[round_idx])


def run_defended_sweep(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    original_metrics: dict[str, float],
    ml_config: Any,
    *,
    historical_fraction: float = HISTORICAL_FRACTION,
    strategies: tuple[str, ...] = STRATEGIES,
    split_seed_offset: int = 555_001,
) -> dict[str, dict[float, dict[str, Any]]]:
    """Item 3: the 15-cell defended-vs-undefended table. The adversary's strategy function is
    called on the historical partition only; the poisoned historical rows are then merged with
    this round's (unpoisoned) honest contribution and fit exactly as M7-11 fits its own draw.

    `historical_fraction`/`strategies` are overridable so the same logic can run the low-history
    ("early chain") sensitivity check in `run_low_history_sensitivity` without duplicating it.
    """
    (x_hist, y_hist), (x_round, y_round) = _historical_split(
        x_train, y_train, historical_fraction=historical_fraction, seed=SEED + split_seed_offset
    )
    sweep: dict[str, dict[float, dict[str, Any]]] = {s: {} for s in strategies}
    for strategy in strategies:
        fn = _STRATEGY_FN[strategy]
        for budget in BUDGETS:
            rng = numpy_generator(SEED + round(budget * 10_000) + _STRATEGY_SEED_OFFSET[strategy])
            result: PoisonResult = fn(x_hist, y_hist, budget, rng=rng)
            x_final = np.concatenate([result.x, x_round], axis=0)
            y_final = np.concatenate([result.y, y_round])
            detector = fit_detector(x_final, y_final, ml_config)
            metrics = clean_metrics(detector, x_eval, y_eval)
            poisoned_rows = (
                result.x[np.array(result.poisoned_row_indices, dtype=int)]
                if result.poisoned_row_indices
                else np.empty((0, x_train.shape[1]))
            )
            sweep[strategy][budget] = {
                "n_poisoned": result.n_poisoned,
                "n_historical_positive": int((y_hist == 1).sum()),
                "defended_bal_acc": metrics["balanced_accuracy"],
                "defended_metrics": metrics,
                "defended_delta": metrics["balanced_accuracy"]
                - original_metrics["balanced_accuracy"],
                "undefended_bal_acc": UNDEFENDED_BAL_ACC[strategy][budget],
                "undefended_delta": UNDEFENDED_BAL_ACC[strategy][budget]
                - original_metrics["balanced_accuracy"],
                "damage_prevented": abs(
                    UNDEFENDED_BAL_ACC[strategy][budget] - original_metrics["balanced_accuracy"]
                )
                - abs(metrics["balanced_accuracy"] - original_metrics["balanced_accuracy"]),
                "poisoned_rows": poisoned_rows,
            }
    return sweep


def run_low_history_sensitivity(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    original_metrics: dict[str, float],
    ml_config: Any,
) -> dict[float, dict[str, Any]]:
    """Sensitivity check on `HISTORICAL_FRACTION`: rerun `anchor_point_injection` only, with a
    much smaller historical partition (`EARLY_CHAIN_HISTORICAL_FRACTION`), to see whether the
    mature-chain result's small `damage_prevented` reflects the *protocol* providing little
    protection, or reflects this *corpus* being stationary enough that 85% of it already
    estimates the same centroid the full corpus would."""
    low_history_sweep = run_defended_sweep(
        x_train,
        y_train,
        x_eval,
        y_eval,
        original_metrics,
        ml_config,
        historical_fraction=EARLY_CHAIN_HISTORICAL_FRACTION,
        strategies=("anchor_point_injection",),
        split_seed_offset=555_003,
    )
    return low_history_sweep["anchor_point_injection"]


#: How many independent (historical/round split, injection draw) repeats
#: `run_anchor_point_robustness` averages over, to tell "damage_prevented is genuinely near
#: zero" apart from "one unlucky/lucky random split made it look that way."
N_ROBUSTNESS_REPEATS = 8


def run_anchor_point_robustness(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    original_metrics: dict[str, float],
    ml_config: Any,
) -> dict[float, dict[str, float]]:
    """`run_defended_sweep`'s single-seed `damage_prevented` per anchor-point cell swings sign
    (measured: +0.0026 to -0.0041 across the five budgets, at `HISTORICAL_FRACTION` alone) --
    consistent with a genuinely near-zero effect, but a single random historical/round split and
    a single injection draw cannot distinguish that from "one particular unlucky split." This
    repeats both draws `N_ROBUSTNESS_REPEATS` times per budget (independent seeds for the split
    and for the injection each repeat) and reports the mean and standard deviation of
    `damage_prevented`, so the "no significant protection measured" reading in the write-up rests
    on a spread, not one point.
    """
    results: dict[float, list[float]] = {b: [] for b in BUDGETS}
    for repeat in range(N_ROBUSTNESS_REPEATS):
        (x_hist, y_hist), (x_round, y_round) = _historical_split(
            x_train, y_train, historical_fraction=HISTORICAL_FRACTION, seed=SEED + 900_000 + repeat
        )
        for budget in BUDGETS:
            rng = numpy_generator(SEED + 910_000 + repeat * 100 + round(budget * 1000))
            result = anchor_point_injection(x_hist, y_hist, budget, rng=rng)
            x_final = np.concatenate([result.x, x_round], axis=0)
            y_final = np.concatenate([result.y, y_round])
            detector = fit_detector(x_final, y_final, ml_config)
            metrics = clean_metrics(detector, x_eval, y_eval)
            undefended_gap = abs(
                UNDEFENDED_BAL_ACC["anchor_point_injection"][budget]
                - original_metrics["balanced_accuracy"]
            )
            defended_gap = abs(metrics["balanced_accuracy"] - original_metrics["balanced_accuracy"])
            results[budget].append(undefended_gap - defended_gap)
    return {
        budget: {
            "mean_damage_prevented": float(np.mean(values)),
            "std_damage_prevented": float(np.std(values)),
            "n_repeats": len(values),
        }
        for budget, values in results.items()
    }


def run_repeated_rounds_experiment(
    x_train: np.ndarray, y_train: np.ndarray, x_eval: np.ndarray, y_eval: np.ndarray, ml_config: Any
) -> list[dict[str, Any]]:
    """Item 4a: does anchor-point injection strengthen across sequential commit-reveal rounds, as
    the adversary's historical view (which now includes its own earlier poison) grows?

    The corpus is split into 11 equal chunks: chunk 0 seeds the initial historical view
    (never attacked, so round 1 has *something* to estimate centroids from); chunks 1-10 are the
    10 rounds' honest contributions. At round r, the adversary poisons using only the historical
    accumulator as it stood after round r-1 (which includes every prior round's honest data AND
    the adversary's own already-committed poison from rounds 1..r-1 -- "it's on the chain").
    """
    rng_split = numpy_generator(SEED + 555_002)
    order = rng_split.permutation(len(y_train))
    chunks = np.array_split(order, N_REPEATED_ROUNDS + 1)
    accum_x, accum_y = x_train[chunks[0]], y_train[chunks[0]]

    rounds: list[dict[str, Any]] = []
    for round_index in range(1, N_REPEATED_ROUNDS + 1):
        historical_size_before_round = len(accum_y)
        this_round_x = x_train[chunks[round_index]]
        this_round_y = y_train[chunks[round_index]]
        rng = numpy_generator(SEED + 700_000 + round_index)
        result = anchor_point_injection(accum_x, accum_y, REPEATED_ROUND_BUDGET, rng=rng)
        accum_x = np.concatenate([result.x, this_round_x], axis=0)
        accum_y = np.concatenate([result.y, this_round_y])

        detector = fit_detector(accum_x, accum_y, ml_config)
        metrics = clean_metrics(detector, x_eval, y_eval)
        rounds.append(
            {
                "round": round_index,
                "historical_size_before_round": historical_size_before_round,
                "n_poisoned_this_round": result.n_poisoned,
                "cumulative_rows": len(accum_x),
                "bal_acc": metrics["balanced_accuracy"],
            }
        )
    return rounds


def run_withholding_experiment(*, max_consecutive_withholds: int, n_rounds: int) -> dict[str, Any]:
    """Item 4c: how many rounds can an always-withholding adversary go before permanent
    exclusion? `CS_honest` commits and reveals every round; `CS_adversary` commits but never
    reveals (the worst case: it withholds every single round, not just some). Deterministic given
    `max_consecutive_withholds` -- this experiment exists to demonstrate the mechanism actually
    behaves as specified, not to discover a number. Batch content is irrelevant here (empty
    batches throughout): this measures the exclusion bookkeeping, not poisoning damage.
    """
    tracker = WithholdTracker(max_consecutive_withholds=max_consecutive_withholds)
    all_participants = ("CS_honest", "CS_adversary")
    excluded_at_round: int | None = None
    per_round: list[dict[str, Any]] = []
    for round_index in range(1, n_rounds + 1):
        eligible = tracker.eligible_participants(all_participants)
        round_ = CommitRevealRound(eligible)
        blinding: dict[str, bytes] = {}
        for node_id in eligible:
            commitment, r = commit_batch(node_id, ())
            round_.submit_commitment(commitment)
            blinding[node_id] = r
        if "CS_honest" in eligible:
            round_.submit_reveal(
                Reveal(node_id="CS_honest", batch=(), blinding_factor=blinding["CS_honest"])
            )
        # CS_adversary commits every round but never reveals -- the always-withholding case.
        result = round_.finalize()
        tracker.record_round(result)
        per_round.append(
            {
                "round": round_index,
                "eligible_participants": list(eligible),
                "excluded_this_round": list(result.excluded_node_ids),
                "permanently_excluded_so_far": sorted(tracker.permanently_excluded),
            }
        )
        if excluded_at_round is None and "CS_adversary" in tracker.permanently_excluded:
            excluded_at_round = round_index
    return {
        "max_consecutive_withholds": max_consecutive_withholds,
        "n_rounds_run": n_rounds,
        "excluded_at_round": excluded_at_round,
        "per_round": per_round,
    }


def run_combination_experiment(
    x_train: np.ndarray, defended_sweep: dict[str, dict[float, dict[str, Any]]]
) -> dict[str, dict[float, dict[str, Any]]]:
    """Item 5: score every defended cell's poisoned rows with the identical drift detector M7-12
    used, against M7-12's own undefended reference scores -- does commit-reveal's constrained
    (historical-only) estimate become newly visible to statistical drift detection?"""
    detector = DriftDetector(
        x_train.shape[1], feature_names=ft.FEATURE_NAMES, policy=MAHALANOBIS_POLICY
    )
    for i in range(0, len(x_train) - CHUNK_SIZE + 1, CHUNK_SIZE):
        detector.update(x_train[i : i + CHUNK_SIZE])

    combination: dict[str, dict[float, dict[str, Any]]] = {s: {} for s in STRATEGIES}
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            poisoned_rows = defended_sweep[strategy][budget]["poisoned_rows"]
            if len(poisoned_rows) == 0:
                continue
            report = detector.score_batch(poisoned_rows)
            combination[strategy][budget] = {
                "defended_maha_score": report.score,
                "defended_detected": report.drift_detected,
                "undefended_maha_score": UNDEFENDED_MAHALANOBIS[strategy][budget],
                "undefended_detected": UNDEFENDED_MAHALANOBIS[strategy][budget]
                >= MAHALANOBIS_POLICY.threshold,
                "newly_detected": report.drift_detected
                and UNDEFENDED_MAHALANOBIS[strategy][budget] < MAHALANOBIS_POLICY.threshold,
            }
    return combination


def emit_sweep_figure(
    sweep: dict[str, dict[float, dict[str, Any]]], original_bal_acc: float, figures_dir: Path
) -> Path:
    fig, axes = plt.subplots(1, 3, figsize=(13.0, 4.2), dpi=150, sharey=True)
    budgets_pct = [b * 100 for b in BUDGETS]
    for ax, strategy in zip(axes, STRATEGIES, strict=True):
        undefended = [sweep[strategy][b]["undefended_bal_acc"] for b in BUDGETS]
        defended = [sweep[strategy][b]["defended_bal_acc"] for b in BUDGETS]
        ax.axhline(original_bal_acc, color=_COLOR_BASELINE, linestyle=":", linewidth=1.0)
        ax.plot(
            budgets_pct, undefended, marker="o", color=_COLOR_UNDEFENDED, label="direct (M7-11)"
        )
        ax.plot(
            budgets_pct, defended, marker="s", color=_COLOR_DEFENDED, label="commit-reveal (M7-14)"
        )
        ax.set_title(strategy.replace("_", " "), fontsize=9.5)
        ax.set_xlabel("budget (%)")
        ax.set_ylim(0.4, 1.0)
    axes[0].set_ylabel("balanced accuracy")
    axes[0].legend(fontsize=7.5, loc="lower left")
    fig.suptitle("M7-14: direct submission vs. commit-reveal, all 15 cells", fontsize=10.5)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig14a_commit_reveal_sweep.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_repeated_rounds_figure(
    rounds: list[dict[str, Any]], original_bal_acc: float, figures_dir: Path
) -> Path:
    fig, ax = plt.subplots(figsize=(7.0, 4.2), dpi=150)
    xs = [r["round"] for r in rounds]
    ys = [r["bal_acc"] for r in rounds]
    ax.axhline(
        original_bal_acc, color=_COLOR_BASELINE, linestyle=":", linewidth=1.0, label="baseline"
    )
    ax.plot(xs, ys, marker="o", color=_COLOR_DEFENDED)
    ax.set_xlabel("commit-reveal round")
    ax.set_ylabel("balanced accuracy after this round's commit")
    ax.set_title(
        "M7-14 item 4a: anchor-point injection over 10 sequential rounds", fontsize=10, loc="left"
    )
    ax.legend(fontsize=8)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig14b_repeated_rounds.png"
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

    original_detector = fit_detector(x_train, y_train, ml_config)
    original_metrics = clean_metrics(original_detector, x_eval, y_eval)
    drift = abs(original_metrics["balanced_accuracy"] - CSV_PATH_REFERENCE_BAL_ACC)
    if drift > _REPRODUCTION_TOLERANCE:
        raise SystemExit(
            f"baseline bal_acc={original_metrics['balanced_accuracy']:.4f} does not reproduce "
            f"the established {CSV_PATH_REFERENCE_BAL_ACC} (drift={drift:.4f})."
        )
    log.event(logger, "baseline_measured", bal_acc=round(original_metrics["balanced_accuracy"], 4))

    sweep = run_defended_sweep(x_train, y_train, x_eval, y_eval, original_metrics, ml_config)
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            log.event(
                logger,
                "cell_measured",
                strategy=strategy,
                budget=budget,
                defended_bal_acc=round(sweep[strategy][budget]["defended_bal_acc"], 4),
                undefended_bal_acc=round(sweep[strategy][budget]["undefended_bal_acc"], 4),
            )

    low_history = run_low_history_sensitivity(
        x_train, y_train, x_eval, y_eval, original_metrics, ml_config
    )
    robustness = run_anchor_point_robustness(
        x_train, y_train, x_eval, y_eval, original_metrics, ml_config
    )
    repeated_rounds = run_repeated_rounds_experiment(x_train, y_train, x_eval, y_eval, ml_config)
    withholding = run_withholding_experiment(max_consecutive_withholds=3, n_rounds=6)
    combination = run_combination_experiment(x_train, sweep)

    figures_dir = REPO_ROOT / "results" / "figures"
    fig_a = emit_sweep_figure(sweep, original_metrics["balanced_accuracy"], figures_dir)
    fig_b = emit_repeated_rounds_figure(
        repeated_rounds, original_metrics["balanced_accuracy"], figures_dir
    )

    wall_seconds = time.perf_counter() - started
    host = {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }

    def _strip_arrays(cell: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in cell.items() if k != "poisoned_rows"}

    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-14 -- commit-then-reveal defense against honeypot poisoning",
        "seed": SEED,
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": host,
        "wall_seconds": wall_seconds,
        "historical_fraction": HISTORICAL_FRACTION,
        "early_chain_historical_fraction": EARLY_CHAIN_HISTORICAL_FRACTION,
        "original_metrics": original_metrics,
        "sweep": {s: {str(b): _strip_arrays(sweep[s][b]) for b in BUDGETS} for s in STRATEGIES},
        "low_history_sensitivity": {str(b): _strip_arrays(low_history[b]) for b in BUDGETS},
        "anchor_point_robustness": {str(b): robustness[b] for b in BUDGETS},
        "repeated_rounds": repeated_rounds,
        "withholding": withholding,
        "combination": {s: {str(b): combination[s][b] for b in combination[s]} for s in STRATEGIES},
        "figures": [str(fig_a.relative_to(REPO_ROOT)), str(fig_b.relative_to(REPO_ROOT))],
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(
        run_id,
        original_metrics,
        sweep,
        low_history,
        robustness,
        repeated_rounds,
        withholding,
        combination,
    )
    return 0


def _print_results_lines(
    run_id: str,
    original_metrics: dict[str, float],
    sweep: dict[str, dict[float, dict[str, Any]]],
    low_history: dict[float, dict[str, Any]],
    robustness: dict[float, dict[str, float]],
    repeated_rounds: list[dict[str, Any]],
    withholding: dict[str, Any],
    combination: dict[str, dict[float, dict[str, Any]]],
) -> None:
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-14-commit-reveal | unpoisoned baseline, clean eval | "
        f"bal_acc={original_metrics['balanced_accuracy']:.4f} | measured | {run_id} | "
        "M7-14, reproduces M7-3/M7-11's 0.8408\n"
    )
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            cell = sweep[strategy][budget]
            pct = int(budget * 100)
            sys.stdout.write(
                f"{date} | detection/honeypot-m7-14-commit-reveal | {strategy} @{pct}% budget | "
                f"undefended_bal_acc={cell['undefended_bal_acc']:.4f} "
                f"defended_bal_acc={cell['defended_bal_acc']:.4f} "
                f"damage_prevented={cell['damage_prevented']:+.4f} "
                f"n_poisoned={cell['n_poisoned']} (historical positives="
                f"{cell['n_historical_positive']}) | measured | {run_id} | M7-14\n"
            )
    for budget in BUDGETS:
        cell = low_history[budget]
        pct = int(budget * 100)
        sys.stdout.write(
            f"{date} | detection/honeypot-m7-14-low-history | anchor_point_injection @{pct}% "
            f"budget, historical_fraction={EARLY_CHAIN_HISTORICAL_FRACTION} | "
            f"undefended_bal_acc={cell['undefended_bal_acc']:.4f} "
            f"defended_bal_acc={cell['defended_bal_acc']:.4f} "
            f"damage_prevented={cell['damage_prevented']:+.4f} "
            f"n_poisoned={cell['n_poisoned']} (historical positives="
            f"{cell['n_historical_positive']}) | measured | {run_id} | M7-14 sensitivity check\n"
        )
    for budget in BUDGETS:
        cell = robustness[budget]
        pct = int(budget * 100)
        sys.stdout.write(
            f"{date} | detection/honeypot-m7-14-robustness | anchor_point_injection @{pct}% "
            f"budget, {cell['n_repeats']} repeats | "
            f"mean_damage_prevented={cell['mean_damage_prevented']:+.4f} "
            f"std_damage_prevented={cell['std_damage_prevented']:.4f} | measured | {run_id} | "
            "M7-14, independent historical-split and injection-draw seeds per repeat\n"
        )
    for r in repeated_rounds:
        sys.stdout.write(
            f"{date} | detection/honeypot-m7-14-repeated-rounds | round {r['round']} | "
            f"bal_acc={r['bal_acc']:.4f} n_poisoned_this_round={r['n_poisoned_this_round']} "
            f"cumulative_rows={r['cumulative_rows']} | measured | {run_id} | M7-14 item 4a\n"
        )
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-14-withholding | always-withholding adversary, "
        f"max_consecutive_withholds={withholding['max_consecutive_withholds']} | "
        f"excluded_at_round={withholding['excluded_at_round']} of "
        f"{withholding['n_rounds_run']} run | measured | {run_id} | M7-14 item 4c\n"
    )
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            combo_cell = combination[strategy].get(budget)
            if combo_cell is None:
                continue
            pct = int(budget * 100)
            sys.stdout.write(
                f"{date} | detection/honeypot-m7-14-combination | {strategy} @{pct}% budget | "
                f"undefended_maha={combo_cell['undefended_maha_score']:.4f} "
                f"(detected={combo_cell['undefended_detected']}) "
                f"defended_maha={combo_cell['defended_maha_score']:.4f} "
                f"(detected={combo_cell['defended_detected']}) "
                f"newly_detected={combo_cell['newly_detected']} "
                f"| measured | {run_id} | M7-14 item 5\n"
            )
    sys.stdout.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
