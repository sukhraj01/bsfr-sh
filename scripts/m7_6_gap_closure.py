"""M7-6: test the three Q10 gap-closure hypotheses left untested (docs/DEVIATIONS.md DEV-06).

Q10 tested two leakage candidates (`address` kept, non-grouped split) and found the best of four
cells (0.9540, random forest, address kept x random split) still 3.58 accuracy points under the
published 0.9898. This script tests three more, each against `configs/ml.yaml`'s declared
baseline unless the hypothesis itself varies that axis:

  H1 -- decision tree splitting criterion (gini/entropy), both splits, address dropped.
  H2 -- resample strategy (oversample ransomware / undersample benign-relative-to-positive),
        random forest + decision tree, both splits.
  H3a -- 20-seed variance of the current production protocol (address dropped, grouped split,
         all four models) and of Q10's best single cell (address kept, random split, RF).
  H3b -- 5-fold group-stratified CV on the 90/10 resample, all four models.
  H4 -- year/day feature engineering, random forest, both splits, address dropped.
  H5 -- the stacked worst case: whichever H1/H2/H4 cell scored highest, picked programmatically
        (never by hand), combined with address kept and a random (non-grouped) split.

All pure resample/feature logic lives in `detection.gap_closure`, tested independently in
`tests/unit/test_detection_gap_closure.py`; this script is the thin orchestrator (CLAUDE.md §3).

Usage::

    python scripts/m7_6_gap_closure.py --seed 20260912
"""

from __future__ import annotations

import argparse
import json
import platform
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
    LoadedDataset,
    Resample,
    grouped_stratified_holdout,
    load_bitcoinheist,
    paper_mode_resample,
    stratified_holdout,
)
from bsfr_sh.detection.gap_closure import (  # noqa: E402
    DECISION_TREE_CRITERIA,
    FEATURE_VARIANTS,
    build_decision_tree_variant,
    engineer_features,
    grouped_stratified_kfold,
    oversample_resample,
    undersample_resample,
)
from bsfr_sh.detection.metrics import paper_metrics  # noqa: E402
from bsfr_sh.detection.models import build_model, build_models, fit_and_score  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import Config, load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

REFERENCE_SEED = 20260912
PUBLISHED_ACCURACY = 0.9898
PUBLISHED_F1 = 0.990
Q10_BEST_ACCURACY = 0.9540
Q10_BEST_F1 = 0.9749
TEST_SIZE = 0.30

#: H2(b) — a total large enough that reaching it requires duplicating the 41,413 real positives.
OVERSAMPLE_TOTAL = 200_000
OVERSAMPLE_POSITIVE_FRACTION = 0.90
#: H2(c) — benign sized as 10% of the positive count, not of the resample total (see gap_closure).
UNDERSAMPLE_BENIGN_FRACTION = 0.10
#: H3a — 20 consecutive seeds starting at the reference seed every prior Q10/M4a number used.
SEED_SWEEP = tuple(range(REFERENCE_SEED, REFERENCE_SEED + 20))
CV_FOLDS = 5


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


def _host() -> dict[str, Any]:
    return {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }


def _load(*, address_kept: bool, config: Config, seed: int) -> LoadedDataset:
    """Same shape as `q10_leakage_ablation.py`'s loader: `drop_columns=()` because `address` is
    managed via `group_column`/`encode_group_as_feature`, not the config-driven drop check."""
    spec = DatasetSpec(
        path=REPO_ROOT / "data" / "raw" / "BitcoinHeistData.csv",
        feature_columns=tuple(config.require("dataset.feature_columns", list)),
        label_column=config.require("dataset.label_column", str),
        benign_label=config.require("dataset.benign_label", str),
        drop_columns=(),
        group_column="address",
        encode_group_as_feature=address_kept,
    )
    return load_bitcoinheist(spec, verify=True, seed=seed)


def _split(
    *, split: str, labels: np.ndarray, groups: np.ndarray | None, seed: int
) -> tuple[np.ndarray, np.ndarray]:
    if split == "random":
        train_idx, test_idx = stratified_holdout(labels, test_size=TEST_SIZE, seed=seed)
    elif split == "grouped":
        train_idx, test_idx = grouped_stratified_holdout(
            labels, groups, test_size=TEST_SIZE, seed=seed
        )
    else:
        raise ValueError(f"split must be 'random' or 'grouped', got {split!r}")
    assert not (set(train_idx.tolist()) & set(test_idx.tolist())), "train/test overlap"
    return train_idx, test_idx


def _fit_score(
    estimator: Any, resample: Resample, train_idx: np.ndarray, test_idx: np.ndarray
) -> tuple[float, float]:
    x = resample.features.to_numpy(dtype=np.float64)
    y = resample.labels
    fitted = fit_and_score(
        estimator, "adhoc", x[train_idx], y[train_idx], x[test_idx], y[test_idx]
    )
    metrics = paper_metrics(y[test_idx], fitted.predictions)
    return metrics.accuracy, metrics.f1


def _write_sidecar(name: str, run_id: str, payload: dict[str, Any]) -> None:
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    sys.stderr.write(f"[{name}] sidecar written: results/logs/{run_id}.json\n")


def _sidecar_base(purpose: str, run_id: str, config_hash_value: str, seed: int) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "purpose": purpose,
        "reference_run_id": "20260913T014037Z-47d61ade",  # Q10's best cell, address kept x random
        "published_accuracy": PUBLISHED_ACCURACY,
        "published_f1": PUBLISHED_F1,
        "q10_best_accuracy": Q10_BEST_ACCURACY,
        "q10_best_f1": Q10_BEST_F1,
        "seed": seed,
        "config_hash": config_hash_value,
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": _host(),
    }


# ==================================================================================================
# H1 — decision tree splitting criterion
# ==================================================================================================
def run_h1(config: Config, seed: int, config_hash_value: str) -> dict[str, dict[str, float]]:
    data = _load(address_kept=False, config=config, seed=seed)
    resample = paper_mode_resample(data, positive_fraction=0.90, seed=seed)
    run_id = log.configure()
    cells: dict[str, dict[str, float]] = {}
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- H1: decision tree splitting criterion ---\n")
    for label, criterion in (
        ("gini_default", "gini"),
        ("entropy_default", "entropy"),
        ("gini_full", "gini"),
        ("entropy_full", "entropy"),
    ):
        for split in ("grouped", "random"):
            key = f"{label} x {split}"
            train_idx, test_idx = _split(
                split=split, labels=resample.labels, groups=resample.groups, seed=seed
            )
            estimator = build_decision_tree_variant(criterion, seed=seed)
            accuracy, f1 = _fit_score(estimator, resample, train_idx, test_idx)
            cells[key] = {"accuracy": accuracy, "f1": f1, "n": resample.n_rows}
            sys.stdout.write(
                f"{date} | detection/bitcoinheist-m7-6-h1 | decision_tree {key}, n={resample.n_rows} "
                f"| acc={accuracy:.4f} f1={f1:.4f} d_pub={accuracy - PUBLISHED_ACCURACY:+.4f} "
                f"| measured | {run_id} | H1 splitting-criterion ablation\n"
            )
    # (a)==(c) and (b)==(d) by construction — asserted here, not just claimed in prose.
    assert cells["gini_default x grouped"] == cells["gini_full x grouped"]
    assert cells["gini_default x random"] == cells["gini_full x random"]
    assert cells["entropy_default x grouped"] == cells["entropy_full x grouped"]
    assert cells["entropy_default x random"] == cells["entropy_full x random"]
    _write_sidecar(
        "H1",
        run_id,
        {
            **_sidecar_base("M7-6 H1 — decision tree splitting criterion", run_id, config_hash_value, seed),
            "dataset": data.as_dict(),
            "resample": resample.as_dict(),
            "cells": cells,
        },
    )
    return cells


# ==================================================================================================
# H2 — resample strategy
# ==================================================================================================
def run_h2(config: Config, seed: int, config_hash_value: str) -> dict[str, dict[str, float]]:
    data = _load(address_kept=False, config=config, seed=seed)
    run_id = log.configure()
    cells: dict[str, dict[str, float]] = {}
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- H2: resample strategy ---\n")
    strategies: dict[str, Resample] = {
        "oversample": oversample_resample(
            data, total=OVERSAMPLE_TOTAL, positive_fraction=OVERSAMPLE_POSITIVE_FRACTION, seed=seed
        ),
        "undersample": undersample_resample(
            data, benign_fraction_of_positive=UNDERSAMPLE_BENIGN_FRACTION, seed=seed
        ),
    }
    for strategy_name, resample in strategies.items():
        assert resample.n_positive + resample.n_negative == resample.n_rows
        for model_name in ("random_forest", "decision_tree"):
            for split in ("grouped", "random"):
                key = f"{strategy_name} x {model_name} x {split}"
                train_idx, test_idx = _split(
                    split=split, labels=resample.labels, groups=resample.groups, seed=seed
                )
                estimator = build_model(config, model_name, seed=seed)
                accuracy, f1 = _fit_score(estimator, resample, train_idx, test_idx)
                cells[key] = {
                    "accuracy": accuracy,
                    "f1": f1,
                    "n": resample.n_rows,
                    "n_positive": resample.n_positive,
                    "n_negative": resample.n_negative,
                }
                sys.stdout.write(
                    f"{date} | detection/bitcoinheist-m7-6-h2 | {key}, "
                    f"n={resample.n_rows} (pos={resample.n_positive} neg={resample.n_negative}) "
                    f"| acc={accuracy:.4f} f1={f1:.4f} d_pub={accuracy - PUBLISHED_ACCURACY:+.4f} "
                    f"| measured | {run_id} | H2 resample-strategy ablation\n"
                )
    _write_sidecar(
        "H2",
        run_id,
        {
            **_sidecar_base("M7-6 H2 — resample strategy", run_id, config_hash_value, seed),
            "dataset": data.as_dict(),
            "strategies": {name: r.as_dict() for name, r in strategies.items()},
            "cells": cells,
        },
    )
    return cells


# ==================================================================================================
# H3a — single-split seed variance
# ==================================================================================================
def run_h3a(config: Config, config_hash_value: str) -> dict[str, dict[str, float]]:
    run_id = log.configure()
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- H3a: 20-seed variance, current production protocol ---\n")

    # Current production protocol: address dropped, grouped split, all four models.
    per_model_accuracy: dict[str, list[float]] = {name: [] for name in ("random_forest",
        "logistic_regression", "decision_tree", "k_nearest_neighbours")}
    per_model_f1: dict[str, list[float]] = {name: [] for name in per_model_accuracy}
    for seed in SEED_SWEEP:
        data = _load(address_kept=False, config=config, seed=seed)
        resample = paper_mode_resample(data, positive_fraction=0.90, seed=seed)
        train_idx, test_idx = _split(
            split="grouped", labels=resample.labels, groups=resample.groups, seed=seed
        )
        for model_name, estimator in build_models(config, seed=seed).items():
            accuracy, f1 = _fit_score(estimator, resample, train_idx, test_idx)
            per_model_accuracy[model_name].append(accuracy)
            per_model_f1[model_name].append(f1)

    summary: dict[str, dict[str, float]] = {}
    for model_name, accuracies in per_model_accuracy.items():
        arr = np.array(accuracies)
        summary[f"production_protocol x {model_name}"] = {
            "min": float(arr.min()),
            "max": float(arr.max()),
            "mean": float(arr.mean()),
            "std": float(arr.std()),
            "n_seeds": len(arr),
        }
        sys.stdout.write(
            f"{date} | detection/bitcoinheist-m7-6-h3a | production_protocol x {model_name}, "
            f"n_seeds={len(arr)} | acc_min={arr.min():.4f} acc_max={arr.max():.4f} "
            f"acc_mean={arr.mean():.4f} acc_std={arr.std():.4f} | measured | {run_id} | "
            "H3a seed-variance sweep\n"
        )

    # Q10's single best cell: address kept, random split, random forest.
    sys.stdout.write("\n--- H3a (bonus): 20-seed variance, Q10's best cell ---\n")
    best_cell_accuracy: list[float] = []
    best_cell_f1: list[float] = []
    for seed in SEED_SWEEP:
        data_kept = _load(address_kept=True, config=config, seed=seed)
        resample = paper_mode_resample(data_kept, positive_fraction=0.90, seed=seed)
        train_idx, test_idx = _split(
            split="random", labels=resample.labels, groups=resample.groups, seed=seed
        )
        estimator = build_model(config, "random_forest", seed=seed)
        accuracy, f1 = _fit_score(estimator, resample, train_idx, test_idx)
        best_cell_accuracy.append(accuracy)
        best_cell_f1.append(f1)
    arr = np.array(best_cell_accuracy)
    summary["q10_best_cell x random_forest"] = {
        "min": float(arr.min()),
        "max": float(arr.max()),
        "mean": float(arr.mean()),
        "std": float(arr.std()),
        "n_seeds": len(arr),
    }
    sys.stdout.write(
        f"{date} | detection/bitcoinheist-m7-6-h3a | q10_best_cell(address_kept x random) x "
        f"random_forest, n_seeds={len(arr)} | acc_min={arr.min():.4f} acc_max={arr.max():.4f} "
        f"acc_mean={arr.mean():.4f} acc_std={arr.std():.4f} | measured | {run_id} | "
        "H3a seed-variance sweep, best known cell\n"
    )

    _write_sidecar(
        "H3a",
        run_id,
        {
            **_sidecar_base("M7-6 H3a — single-split seed variance", run_id, config_hash_value, SEED_SWEEP[0]),
            "seeds": list(SEED_SWEEP),
            "production_protocol_per_model_accuracy": per_model_accuracy,
            "production_protocol_per_model_f1": per_model_f1,
            "q10_best_cell_accuracy": best_cell_accuracy,
            "q10_best_cell_f1": best_cell_f1,
            "summary": summary,
        },
    )
    return summary


# ==================================================================================================
# H3b — 5-fold group-stratified cross-validation
# ==================================================================================================
def run_h3b(config: Config, seed: int, config_hash_value: str) -> dict[str, dict[str, float]]:
    data = _load(address_kept=False, config=config, seed=seed)
    resample = paper_mode_resample(data, positive_fraction=0.90, seed=seed)
    assert resample.groups is not None
    run_id = log.configure()
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- H3b: 5-fold group-stratified CV ---\n")

    folds = grouped_stratified_kfold(resample.labels, resample.groups, folds=CV_FOLDS, seed=seed)
    summary: dict[str, dict[str, float]] = {}
    for model_name in ("random_forest", "logistic_regression", "decision_tree",
                       "k_nearest_neighbours"):
        fold_accuracy: list[float] = []
        fold_f1: list[float] = []
        for train_idx, test_idx in folds:
            estimator = build_model(config, model_name, seed=seed)
            accuracy, f1 = _fit_score(estimator, resample, train_idx, test_idx)
            fold_accuracy.append(accuracy)
            fold_f1.append(f1)
        acc_arr, f1_arr = np.array(fold_accuracy), np.array(fold_f1)
        summary[model_name] = {
            "mean_accuracy": float(acc_arr.mean()),
            "std_accuracy": float(acc_arr.std()),
            "mean_f1": float(f1_arr.mean()),
            "std_f1": float(f1_arr.std()),
        }
        sys.stdout.write(
            f"{date} | detection/bitcoinheist-m7-6-h3b | {model_name}, {CV_FOLDS}-fold group-cv "
            f"n={resample.n_rows} | acc_mean={acc_arr.mean():.4f} acc_std={acc_arr.std():.4f} "
            f"f1_mean={f1_arr.mean():.4f} f1_std={f1_arr.std():.4f} | measured | {run_id} | "
            "H3b group-stratified 5-fold CV\n"
        )
    _write_sidecar(
        "H3b",
        run_id,
        {
            **_sidecar_base("M7-6 H3b — 5-fold group-stratified CV", run_id, config_hash_value, seed),
            "dataset": data.as_dict(),
            "resample": resample.as_dict(),
            "folds": CV_FOLDS,
            "summary": summary,
        },
    )
    return summary


# ==================================================================================================
# H4 — year/day feature engineering
# ==================================================================================================
def run_h4(config: Config, seed: int, config_hash_value: str) -> dict[str, dict[str, float]]:
    data = _load(address_kept=False, config=config, seed=seed)
    resample = paper_mode_resample(data, positive_fraction=0.90, seed=seed)
    run_id = log.configure()
    date = time.strftime("%Y-%m-%d")
    cells: dict[str, dict[str, float]] = {}
    sys.stdout.write("\n--- H4: year/day feature engineering ---\n")
    for variant in FEATURE_VARIANTS:
        engineered = engineer_features(resample.features, variant)
        for split in ("grouped", "random"):
            key = f"{variant} x {split}"
            train_idx, test_idx = _split(
                split=split, labels=resample.labels, groups=resample.groups, seed=seed
            )
            # Feature engineering must never touch the label array.
            assert len(engineered) == len(resample.labels)
            x = engineered.to_numpy(dtype=np.float64)
            estimator = build_model(config, "random_forest", seed=seed)
            fitted = fit_and_score(
                estimator,
                "random_forest",
                x[train_idx],
                resample.labels[train_idx],
                x[test_idx],
                resample.labels[test_idx],
            )
            metrics = paper_metrics(resample.labels[test_idx], fitted.predictions)
            cells[key] = {"accuracy": metrics.accuracy, "f1": metrics.f1, "n": resample.n_rows}
            sys.stdout.write(
                f"{date} | detection/bitcoinheist-m7-6-h4 | random_forest {key}, n={resample.n_rows} "
                f"| acc={metrics.accuracy:.4f} f1={metrics.f1:.4f} "
                f"d_pub={metrics.accuracy - PUBLISHED_ACCURACY:+.4f} | measured | {run_id} | "
                "H4 feature-engineering ablation\n"
            )
    _write_sidecar(
        "H4",
        run_id,
        {
            **_sidecar_base("M7-6 H4 — year/day feature engineering", run_id, config_hash_value, seed),
            "dataset": data.as_dict(),
            "resample": resample.as_dict(),
            "cells": cells,
        },
    )
    return cells


# ==================================================================================================
# H5 — stacked worst case, winners picked programmatically
# ==================================================================================================
def run_h5(
    config: Config,
    seed: int,
    config_hash_value: str,
    h1_cells: dict[str, dict[str, float]],
    h2_cells: dict[str, dict[str, float]],
    h4_cells: dict[str, dict[str, float]],
) -> dict[str, Any]:
    run_id = log.configure()
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- H5: stacked worst case (winners chosen programmatically) ---\n")

    # Winning decision-tree criterion (H1): the two distinct criteria, best of the two splits.
    dt_scores = {c: h1_cells[f"{c}_default x random"]["accuracy"] for c in ("gini", "entropy")}
    best_criterion = max(dt_scores, key=lambda c: dt_scores[c])

    # Winning resample strategy (H2): best single cell across strategy x model x split.
    best_h2_key = max(h2_cells, key=lambda k: h2_cells[k]["accuracy"])
    best_strategy = best_h2_key.split(" x ")[0]

    # Winning feature variant (H4): best single cell across variant x split.
    best_h4_key = max(h4_cells, key=lambda k: h4_cells[k]["accuracy"])
    best_variant = best_h4_key.split(" x ")[0]

    sys.stdout.write(
        f"Winners identified programmatically: decision-tree criterion={best_criterion!r} "
        f"(gini={dt_scores['gini']:.4f}, entropy={dt_scores['entropy']:.4f}); "
        f"resample strategy={best_strategy!r} (from cell {best_h2_key!r}, "
        f"acc={h2_cells[best_h2_key]['accuracy']:.4f}); "
        f"feature variant={best_variant!r} (from cell {best_h4_key!r}, "
        f"acc={h4_cells[best_h4_key]['accuracy']:.4f})\n"
    )

    data_kept = _load(address_kept=True, config=config, seed=seed)
    if best_strategy == "oversample":
        resample = oversample_resample(
            data_kept, total=OVERSAMPLE_TOTAL, positive_fraction=OVERSAMPLE_POSITIVE_FRACTION,
            seed=seed,
        )
    else:
        resample = undersample_resample(
            data_kept, benign_fraction_of_positive=UNDERSAMPLE_BENIGN_FRACTION, seed=seed
        )
    engineered = engineer_features(resample.features, best_variant)
    train_idx, test_idx = _split(
        split="random", labels=resample.labels, groups=resample.groups, seed=seed
    )
    estimator = build_decision_tree_variant(best_criterion, seed=seed)
    x = engineered.to_numpy(dtype=np.float64)
    fitted = fit_and_score(
        estimator, "decision_tree", x[train_idx], resample.labels[train_idx],
        x[test_idx], resample.labels[test_idx],
    )
    metrics = paper_metrics(resample.labels[test_idx], fitted.predictions)
    result = {
        "criterion": best_criterion,
        "resample_strategy": best_strategy,
        "feature_variant": best_variant,
        "split": "random",
        "address": "kept",
        "n": resample.n_rows,
        "n_positive": resample.n_positive,
        "n_negative": resample.n_negative,
        "accuracy": metrics.accuracy,
        "f1": metrics.f1,
        "delta_vs_published": metrics.accuracy - PUBLISHED_ACCURACY,
    }
    sys.stdout.write(
        f"{date} | detection/bitcoinheist-m7-6-h5 | stacked "
        f"({best_criterion} x {best_strategy} x {best_variant} x address_kept x random_split), "
        f"n={resample.n_rows} | acc={metrics.accuracy:.4f} f1={metrics.f1:.4f} "
        f"d_pub={metrics.accuracy - PUBLISHED_ACCURACY:+.4f} | measured | {run_id} | "
        "H5 stacked worst case\n"
    )
    _write_sidecar(
        "H5",
        run_id,
        {
            **_sidecar_base("M7-6 H5 — stacked worst case", run_id, config_hash_value, seed),
            "result": result,
        },
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=REFERENCE_SEED)
    args = parser.parse_args()

    config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    seed_all(args.seed)
    config_hash_value = config_hash(config.kind, config.data)

    h1_cells = run_h1(config, args.seed, config_hash_value)
    h2_cells = run_h2(config, args.seed, config_hash_value)
    run_h3a(config, config_hash_value)
    run_h3b(config, args.seed, config_hash_value)
    h4_cells = run_h4(config, args.seed, config_hash_value)
    h5_result = run_h5(config, args.seed, config_hash_value, h1_cells, h2_cells, h4_cells)

    best_overall = max(
        [(k, v["accuracy"]) for k, v in h1_cells.items()]
        + [(k, v["accuracy"]) for k, v in h2_cells.items()]
        + [(k, v["accuracy"]) for k, v in h4_cells.items()]
        + [("h5_stacked", h5_result["accuracy"]), ("q10_best", Q10_BEST_ACCURACY)],
        key=lambda pair: pair[1],
    )
    sys.stdout.write(
        f"\n=== Best cell across every M7-6 hypothesis + Q10: {best_overall[0]!r} at "
        f"{best_overall[1]:.4f}, {best_overall[1] - PUBLISHED_ACCURACY:+.4f} vs. published "
        f"{PUBLISHED_ACCURACY} ===\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
