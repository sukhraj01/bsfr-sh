"""Phase 2 / P2-B: a fair four-model comparison (see `bsfr_sh.detection.fair` for the why).

Part 1 — paper setting: the 90/10 resample, address dropped, address-grouped 70/30 split (the
Phase 1 production protocol that gave 0.9442 for RF). Each model raw (= Phase 1) and log+scaled.
5 seeds. Adds the two numbers Table II never shows: false-positive rate and balanced accuracy.

Part 2 — natural class balance (1.42% ransomware): a stratified 400k-row subsample (so KNN fits
in memory on an 8-16 GB box), address-grouped 70/30 split, 3 seeds. Each model raw, log+scaled,
and log+scaled+class-weighted.

Usage::

    python scripts/p2b_fair_models.py --seed 20260912
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, config_hash  # noqa: E402
from bsfr_sh.detection.dataset import (  # noqa: E402
    DatasetSpec,
    grouped_stratified_holdout,
    load_bitcoinheist,
    paper_mode_resample,
    subsample_index,
)
from bsfr_sh.detection.fair import (  # noqa: E402
    balanced_accuracy,
    build_fair_estimator,
    false_positive_rate,
)
from bsfr_sh.detection.metrics import honest_metrics, paper_metrics  # noqa: E402
from bsfr_sh.detection.models import MODEL_NAMES, build_model, fit_and_score  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

TEST_SIZE = 0.30
PAPER_SEEDS = 5
HONEST_SEEDS = 3
HONEST_ROWS = 400_000
PAPER_VARIANTS = (("raw", False), ("log_scaled", False))
HONEST_VARIANTS = (("raw", False), ("log_scaled", False), ("log_scaled", True))


def _variant_name(prep: str, balanced: bool) -> str:
    return prep + ("+balanced" if balanced else "")


def _summ(vals: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(vals),
        "sd": statistics.stdev(vals) if len(vals) > 1 else 0.0,
        "min": min(vals),
        "max": max(vals),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260912)
    parser.add_argument("--part", choices=("paper", "honest", "both"), default="both")
    args = parser.parse_args()

    config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    seed_all(args.seed)
    run_id = log.configure()
    spec = DatasetSpec(
        path=REPO_ROOT / "data" / "raw" / "BitcoinHeistData.csv",
        feature_columns=tuple(config.require("dataset.feature_columns", list)),
        label_column=config.require("dataset.label_column", str),
        benign_label=config.require("dataset.benign_label", str),
        drop_columns=(),
        group_column="address",
    )
    data = load_bitcoinheist(spec, verify=True, seed=args.seed)
    names = data.columns
    x_all = data.features.to_numpy(dtype=np.float64)
    assert data.groups is not None

    raw_rows: list[dict[str, Any]] = []

    def run_cell(part: str, seed: int, x: np.ndarray, y: np.ndarray, groups: np.ndarray,
                 variants: tuple[tuple[str, bool], ...]) -> None:  # fmt: skip
        tr, te = grouped_stratified_holdout(y, groups, test_size=TEST_SIZE, seed=seed)
        for model_name in MODEL_NAMES:
            for prep, balanced in variants:
                if balanced and model_name == "k_nearest_neighbours":
                    continue  # no class weights in KNN; recorded by omission
                est = build_fair_estimator(
                    build_model(config, model_name, seed=seed), names,
                    preprocessing=prep, balanced=balanced,
                )  # fmt: skip
                t0 = time.perf_counter()
                fitted = fit_and_score(est, model_name, x[tr], y[tr], x[te], y[te])
                pm = paper_metrics(y[te], fitted.predictions)
                hm = honest_metrics(y[te], fitted.predictions, fitted.scores)
                row = {
                    "part": part, "seed": seed, "model": model_name,
                    "variant": _variant_name(prep, balanced),
                    "n_train": len(tr), "n_test": len(te), "test_pos_rate": float(y[te].mean()),
                    "accuracy": pm.accuracy, "f1": pm.f1,
                    "balanced_accuracy": balanced_accuracy(y[te], fitted.predictions),
                    "fpr": false_positive_rate(y[te], fitted.predictions),
                    "precision": hm.precision, "recall": hm.recall, "pr_auc": hm.pr_auc,
                    "mcc": hm.mcc, "f1_minority": hm.f1_minority,
                    "seconds": time.perf_counter() - t0,
                }  # fmt: skip
                raw_rows.append(row)
                sys.stderr.write(
                    f"[{part} seed={seed}] {model_name:<22} {row['variant']:<20} "
                    f"acc={row['accuracy']:.4f} bal={row['balanced_accuracy']:.4f} "
                    f"fpr={row['fpr']:.3f} rec={row['recall']:.3f} prec={row['precision']:.3f} "
                    f"prauc={row['pr_auc']:.3f} ({row['seconds']:.0f}s)\n"
                )

    if args.part in ("paper", "both"):
        for k in range(PAPER_SEEDS):
            seed = args.seed + k
            rs = paper_mode_resample(data, positive_fraction=0.90, seed=seed)
            run_cell("paper", seed, rs.features.to_numpy(dtype=np.float64), rs.labels,
                     rs.groups, PAPER_VARIANTS)  # fmt: skip

    if args.part in ("honest", "both"):
        for k in range(HONEST_SEEDS):
            seed = args.seed + k
            sub = subsample_index(data.labels, HONEST_ROWS, stratified=True, seed=seed)
            run_cell("honest", seed, x_all[sub], data.labels[sub], data.groups[sub],
                     HONEST_VARIANTS)  # fmt: skip

    # aggregate -------------------------------------------------------------------------------
    metrics = ("accuracy", "f1", "balanced_accuracy", "fpr", "precision", "recall", "pr_auc",
               "mcc", "f1_minority")  # fmt: skip
    summary: dict[str, Any] = {}
    for part in sorted({r["part"] for r in raw_rows}):
        for model in MODEL_NAMES:
            for variant in sorted({r["variant"] for r in raw_rows}):
                cell = [r for r in raw_rows
                        if (r["part"], r["model"], r["variant"]) == (part, model, variant)]  # fmt: skip
                if cell:
                    summary[f"{part}|{model}|{variant}"] = {
                        m: _summ([r[m] for r in cell]) for m in metrics
                    } | {"n_seeds": len(cell)}

    out_csv = REPO_ROOT / "results" / "tables" / "p2b_fair_models.csv"
    lines = ["part,model,variant,n_seeds," + ",".join(f"{m}_mean,{m}_sd" for m in metrics)]
    for key, s in summary.items():
        lines.append(
            key.replace("|", ",") + f",{s['n_seeds']},"
            + ",".join(f"{s[m]['mean']:.4f},{s[m]['sd']:.4f}" for m in metrics)
        )
    out_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")

    sidecar = {
        "run_id": run_id,
        "purpose": "P2-B: fair four-model comparison (log+scale, class weighting)",
        "seed": args.seed,
        "config_hash": config_hash(config.kind, config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                                  text=True, cwd=REPO_ROOT).stdout.strip(),  # fmt: skip
        "host": log.env_snapshot(),
        "protocol": {"test_size": TEST_SIZE, "paper_seeds": PAPER_SEEDS,
                     "honest_seeds": HONEST_SEEDS, "honest_rows": HONEST_ROWS,
                     "split": "address-grouped stratified holdout", "address": "dropped"},  # fmt: skip
        "summary": summary,
        "rows": raw_rows,
    }
    (REPO_ROOT / "results" / "logs" / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, default=float) + "\n", encoding="utf-8"
    )
    print(json.dumps({"run_id": run_id}, indent=2))
    for key, s in summary.items():
        print(f"{key:<55} " + " ".join(f"{m}={s[m]['mean']:.4f}" for m in metrics))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
