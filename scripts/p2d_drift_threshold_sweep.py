"""Phase 2 / P2-D: the poisoning alarm (M7-12) was tested at one threshold. Sweep it.

M7-12's Mahalanobis drift detector was shipped with `threshold=3.0`, chosen before anything was
measured. Its own logged scores (`RESULTS.md` M7-12) never exceed ~1.2 for any batch, clean or
poisoned, so at 3.0 the alarm can never ring: "0/15 attacks prevented, 0/30 false alarms" is a
statement about the threshold, not about the detector.

This script asks the threshold-free question instead: *can the score tell a poisoned batch apart
from an innocent batch of the same size at all?* For each poisoning strategy and budget it draws
30 independent poisoned batches and compares their scores with 300 clean batches of the same
size, drawn from the evaluation corpus (never used to build the profile), of three kinds:

* `mixed`     — a random clean batch (the usual benign/ransomware mix);
* `rw_only`   — a clean batch of genuine ransomware rows, i.e. an honest outbreak;
* `benign_only` — a clean batch of genuine benign rows.

The detector sees features only, never labels. Label flipping's rows *are* genuine ransomware
features; feature poisoning's rows *are* genuine benign features. So the fair "innocent twin" for
each is the matching single-class batch, and the question is whether the alarm can tell poison
from its twin.

Reported per cell: AUC (probability a poisoned batch scores above an innocent one; 0.5 = cannot
tell) against each null, and the detection rate at a threshold set to give a 5% false-alarm rate
on `mixed` batches of that size.

Usage::

    python scripts/p2d_drift_threshold_sweep.py --seed 20260912
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bsfr_sh.detection.drift import DriftDetector, DriftMethod, DriftPolicy  # noqa: E402
from bsfr_sh.detection.poisoning import (  # noqa: E402
    anchor_point_injection,
    feature_poison,
    label_flip,
)
from bsfr_sh.honeypot import features as ft  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

STRATEGIES = {
    "label_flip": label_flip,
    "feature_poison": feature_poison,
    "anchor_point_injection": anchor_point_injection,
}
BUDGETS = (0.05, 0.10, 0.20)
ATTACK_REPEATS = 30
NULL_TRIALS = 300
CHUNK_SIZE = 25  # identical to M7-12
PHASE1_THRESHOLD = 3.0  # M7-12's shipped value
POLICY = DriftPolicy(
    method=DriftMethod.MAHALANOBIS, threshold=PHASE1_THRESHOLD, feature_threshold=3.0,
    min_history=5,
)  # fmt: skip


def _load(name: str) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.read_csv(REPO_ROOT / "data" / "honeypot" / f"corpus_{name}.csv")
    return (
        frame[list(ft.FEATURE_NAMES)].to_numpy(dtype=np.float64),
        (frame["label"] == "RW").to_numpy(dtype=np.int8),
    )


def auc(attack: np.ndarray, null: np.ndarray) -> float:
    """P(attack score > null score) + 0.5 * P(tie). The Mann-Whitney U statistic, normalised."""
    a = attack[:, None]
    n = null[None, :]
    return float(np.mean(a > n) + 0.5 * np.mean(a == n))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260912)
    args = parser.parse_args()
    seed_all(args.seed)
    run_id = log.configure()
    rng = np.random.default_rng(args.seed)

    x_train, y_train = _load("train")
    x_eval, y_eval = _load("eval")
    detector = DriftDetector(x_train.shape[1], feature_names=ft.FEATURE_NAMES, policy=POLICY)
    for i in range(0, len(x_train), CHUNK_SIZE):
        detector.update(x_train[i : i + CHUNK_SIZE])

    pools = {
        "mixed": np.arange(len(x_eval)),
        "rw_only": np.flatnonzero(y_eval == 1),
        "benign_only": np.flatnonzero(y_eval == 0),
    }
    null_cache: dict[tuple[str, int], np.ndarray] = {}

    def null_scores(kind: str, n: int) -> np.ndarray:
        if (kind, n) not in null_cache:
            pool = pools[kind]
            null_cache[(kind, n)] = np.array([
                detector.score_batch(x_eval[rng.choice(pool, size=n, replace=n > len(pool))]).score
                for _ in range(NULL_TRIALS)
            ])  # fmt: skip
        return null_cache[(kind, n)]

    cells: list[dict[str, Any]] = []
    attack_scores: dict[str, dict[float, list[float]]] = {s: {} for s in STRATEGIES}
    for strategy, fn in STRATEGIES.items():
        for budget in BUDGETS:
            scores, n_rows = [], 0
            for r in range(ATTACK_REPEATS):
                res = fn(x_train, y_train, budget, rng=np.random.default_rng(args.seed + 1000 * r))
                rows = res.x[np.array(res.poisoned_row_indices, dtype=int)]
                n_rows = len(rows)
                scores.append(detector.score_batch(rows).score)
            a = np.array(scores)
            attack_scores[strategy][budget] = scores
            mixed = null_scores("mixed", n_rows)
            thr95 = float(np.percentile(mixed, 95))
            cell = {
                "strategy": strategy,
                "budget": budget,
                "n_rows": n_rows,
                "attack_median": float(np.median(a)),
                "mixed_null_median": float(np.median(mixed)),
                "auc_vs_mixed": auc(a, mixed),
                "auc_vs_rw_only": auc(a, null_scores("rw_only", n_rows)),
                "auc_vs_benign_only": auc(a, null_scores("benign_only", n_rows)),
                "threshold_at_5pct_false_alarm": thr95,
                "detection_rate_at_5pct_false_alarm": float(np.mean(a > thr95)),
                "rw_outbreak_alarm_rate_at_that_threshold": float(
                    np.mean(null_scores("rw_only", n_rows) > thr95)
                ),
                # two-sided alarm: also fire when a batch is *too* close to the profile mean
                # (2.5% false alarms in each tail, 5% total, on clean mixed batches)
                "two_sided_detection_rate": float(
                    np.mean((a < np.percentile(mixed, 2.5)) | (a > np.percentile(mixed, 97.5)))
                ),
                "two_sided_outbreak_alarm_rate": float(
                    np.mean(
                        (null_scores("rw_only", n_rows) < np.percentile(mixed, 2.5))
                        | (null_scores("rw_only", n_rows) > np.percentile(mixed, 97.5))
                    )
                ),
                "detection_rate_at_phase1_threshold": float(np.mean(a >= PHASE1_THRESHOLD)),
                "max_score_any_batch": float(
                    max(a.max(), *(null_scores(k, n_rows).max() for k in pools))
                ),
            }
            cells.append(cell)
            sys.stderr.write(
                f"{strategy:<24} {budget:>4.0%} n={n_rows:<4} "
                f"AUC mixed={cell['auc_vs_mixed']:.2f} rw={cell['auc_vs_rw_only']:.2f} "
                f"benign={cell['auc_vs_benign_only']:.2f} | det@5%FA="
                f"{cell['detection_rate_at_5pct_false_alarm']:.2f} "
                f"outbreak-alarm={cell['rw_outbreak_alarm_rate_at_that_threshold']:.2f} | "
                f"2-sided det={cell['two_sided_detection_rate']:.2f} | "
                f"det@3.0={cell['detection_rate_at_phase1_threshold']:.2f} "
                f"max={cell['max_score_any_batch']:.2f}\n"
            )

    cols = list(cells[0])
    lines = [",".join(cols)] + [
        ",".join(f"{c[k]:.4f}" if isinstance(c[k], float) else str(c[k]) for k in cols)
        for c in cells
    ]
    (REPO_ROOT / "results" / "tables" / "p2d_drift_threshold_sweep.csv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    sidecar = {
        "run_id": run_id,
        "purpose": "P2-D: threshold-free evaluation of M7-12's drift alarm",
        "seed": args.seed,
        "git_rev": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                                  text=True, cwd=REPO_ROOT).stdout.strip(),  # fmt: skip
        "host": log.env_snapshot(),
        "protocol": {"attack_repeats": ATTACK_REPEATS, "null_trials": NULL_TRIALS,
                     "chunk_size": CHUNK_SIZE, "phase1_threshold": PHASE1_THRESHOLD},  # fmt: skip
        "cells": cells,
        "attack_scores": attack_scores,
    }
    (REPO_ROOT / "results" / "logs" / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, default=float) + "\n", encoding="utf-8"
    )
    _figure(attack_scores, null_scores, cells)
    print(json.dumps({"run_id": run_id}))
    return 0


def _figure(attack_scores: dict[str, dict[float, list[float]]], null_scores: Any,
            cells: list[dict[str, Any]]) -> None:  # fmt: skip
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    budget = 0.10
    fig, axes = plt.subplots(1, 3, figsize=(13, 4), sharey=False)
    titles = {"label_flip": "Label flipping", "feature_poison": "Feature poisoning",
              "anchor_point_injection": "Anchor-point injection"}  # fmt: skip
    for ax, strategy in zip(axes, STRATEGIES, strict=True):
        cell = next(c for c in cells if c["strategy"] == strategy and c["budget"] == budget)
        n = cell["n_rows"]
        data = [attack_scores[strategy][budget], null_scores("mixed", n),
                null_scores("rw_only", n), null_scores("benign_only", n)]  # fmt: skip
        ax.boxplot(data, showfliers=False)
        ax.set_xticks([1, 2, 3, 4], ["poisoned", "clean\nmixed", "clean\noutbreak", "clean\nbenign"])
        ax.axhline(cell["threshold_at_5pct_false_alarm"], color="#1f4e9c", ls="--", lw=1,
                   label="threshold @ 5% false alarms")  # fmt: skip
        ax.set_title(f"{titles[strategy]} (10% budget, n={n})", fontsize=10)
        ax.set_ylabel("drift score")
        ax.grid(alpha=0.3, axis="y")
    axes[0].legend(loc="center right", fontsize=8)
    fig.suptitle(f"Phase 1's alarm threshold was {PHASE1_THRESHOLD}: every batch below scores "
                 "under 0.6, so it could never fire", x=0.01, ha="left", fontsize=11)  # fmt: skip
    fig.tight_layout()
    fig.savefig(REPO_ROOT / "results" / "figures" / "p2d_drift_threshold_sweep.png", dpi=150)


if __name__ == "__main__":
    raise SystemExit(main())
