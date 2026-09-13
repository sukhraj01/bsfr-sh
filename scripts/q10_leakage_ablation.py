"""Q10: does `address` and/or a random split explain BitcoinHeist's non-reproduction?

M4a reproduced 0.9479/0.9717 (RF, `paper_mode`) against the paper's published 0.9898/0.990 —
`docs/PAPER_NOTES.md` §VII, `docs/DEVIATIONS.md` DEV-06, run `20260912T172708Z-6d35b415`. That
run used `address` dropped and a row-level stratified split — `stratified_holdout`, which
stratifies by label only and never looks at `address`. So the honest position it measured is
"address dropped x random split", not grouped.

Two leakage candidates could each explain part of the gap:

1. `address` kept as an explicit feature — we drop it at load.
2. Splitting randomly rather than grouping by address — BitcoinHeist rows are
   `(address, year, day)` tuples, every address carries one label end to end, and
   weight/length/count/looped/neighbors/income are address-level graph features, so rows sharing
   an address are near duplicates. Since M4a already split randomly, candidate 2's leakage is
   already inside the 0.9479 we have.

This script runs the 2x2 — {address dropped, kept} x {random, grouped} split — `paper_mode`
only, all four models, with the same declared hyperparameters and seed as the reference run, so
all five numbers are directly comparable. It writes one sidecar and prints one `RESULTS.md` line
per model per cell. It does not change what `docs/EXPERIMENTS.md` Target 1 reports: the reported
figure stays address-dropped, and — per the session brief — grouped-split, once this run
establishes that as the honest baseline instead of the random-split one M4a used.

Usage::

    python scripts/q10_leakage_ablation.py --seed 20260912
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
    grouped_stratified_holdout,
    load_bitcoinheist,
    paper_mode_resample,
    stratified_holdout,
)
from bsfr_sh.detection.metrics import baselines, honest_metrics, paper_metrics  # noqa: E402
from bsfr_sh.detection.models import build_models, fit_and_score  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import Config, load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

#: What every cell's accuracy/F1 delta is measured against — DEV-06's amendment and Table II.
REFERENCE_RUN_ID = "20260912T172708Z-6d35b415"
REFERENCE_BEST_ACCURACY = 0.9479
REFERENCE_BEST_F1 = 0.9717
PUBLISHED_ACCURACY = 0.9898
PUBLISHED_F1 = 0.990

CELLS: tuple[tuple[bool, str], ...] = (
    (False, "grouped"),
    (False, "random"),
    (True, "grouped"),
    (True, "random"),
)


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


def _load_cell_data(*, address_kept: bool, config: Config, seed: int) -> LoadedDataset:
    """Load the full file for one address-encoding variant. `verify=True` — always the whole file.

    `drop_columns=()` because this loader manages `address` itself via `group_column` rather than
    through the config-driven drop check; `address` still never reaches the feature matrix unless
    `encode_group_as_feature` asks for it.
    """
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


def _run_cell(
    *, address_kept: bool, split: str, data: LoadedDataset, config: Config, seed: int, logger: Any
) -> dict[str, Any]:
    """One point in the 2x2: a resample, a split, all four models. Mirrors `run_detection.py`."""
    fraction = float(config.get("modes.paper_mode.positive_fraction", 0.90))
    test_size = float(config.get("modes.paper_mode.test_size", 0.30))
    resample = paper_mode_resample(data, positive_fraction=fraction, seed=seed)

    if split == "random":
        train_idx, test_idx = stratified_holdout(resample.labels, test_size=test_size, seed=seed)
    else:
        train_idx, test_idx = grouped_stratified_holdout(
            resample.labels, resample.groups, test_size=test_size, seed=seed
        )

    x = resample.features.to_numpy(dtype=np.float64)
    y = resample.labels
    x_train, x_test = x[train_idx], x[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    base = baselines(y_test, seed=seed)
    log.event(
        logger,
        "baselines_computed",
        address_kept=address_kept,
        split=split,
        constant_positive_accuracy=round(base.constant_positive.accuracy, 4),
    )

    results: dict[str, Any] = {}
    for name, estimator in build_models(config, seed=seed).items():
        fitted = fit_and_score(estimator, name, x_train, y_train, x_test, y_test)
        paper = paper_metrics(y_test, fitted.predictions)
        honest = honest_metrics(y_test, fitted.predictions, fitted.scores)
        results[name] = {
            **fitted.as_dict(),
            **paper.as_dict(),
            "honest": honest.as_dict(),
            "delta_vs_m4a_best": paper.accuracy - REFERENCE_BEST_ACCURACY,
            "delta_vs_published": paper.accuracy - PUBLISHED_ACCURACY,
        }
        log.event(
            logger,
            "model_scored",
            address_kept=address_kept,
            split=split,
            model=name,
            accuracy=round(paper.accuracy, 4),
            f1=round(paper.f1, 4),
        )

    return {
        "address_kept": address_kept,
        "split": split,
        "feature_columns": list(data.columns),
        "resample": resample.as_dict(),
        "test_size": test_size,
        "n_train": len(train_idx),
        "n_test": len(test_idx),
        "achieved_train_positive_rate": float(y_train.mean()),
        "achieved_test_positive_rate": float(y_test.mean()),
        "baselines": base.as_dict(),
        "models": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260912)
    args = parser.parse_args()

    config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    seed_all(args.seed)
    hash_value = config_hash(config.kind, config.data)

    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    date = time.strftime("%Y-%m-%d")

    # Load once per address-encoding variant; both splits reuse that load (same frame, same RNG
    # seed passed independently into each split function).
    loaded: dict[bool, LoadedDataset] = {}

    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    for address_kept, split in CELLS:
        run_id = log.configure()
        logger = log.get_logger(__name__)

        if address_kept not in loaded:
            started = time.perf_counter()
            loaded[address_kept] = _load_cell_data(
                address_kept=address_kept, config=config, seed=args.seed
            )
            log.event(
                logger,
                "dataset_loaded",
                address_kept=address_kept,
                seconds=round(time.perf_counter() - started, 2),
            )
        data = loaded[address_kept]

        started = time.perf_counter()
        cell = _run_cell(
            address_kept=address_kept,
            split=split,
            data=data,
            config=config,
            seed=args.seed,
            logger=logger,
        )
        wall_seconds = time.perf_counter() - started

        sidecar: dict[str, Any] = {
            "run_id": run_id,
            "purpose": "Q10 — address / split leakage ablation, paper_mode only (DEV-06)",
            "reference_run_id": REFERENCE_RUN_ID,
            "reference_best_accuracy": REFERENCE_BEST_ACCURACY,
            "reference_best_f1": REFERENCE_BEST_F1,
            "published_accuracy": PUBLISHED_ACCURACY,
            "published_f1": PUBLISHED_F1,
            "seed": args.seed,
            "config_hash": hash_value,
            "config_hash_scheme": CONFIG_HASH_SCHEME,
            "git_rev": _git_rev(),
            "host": {
                "machine": platform.machine(),
                "processor": platform.processor() or platform.machine(),
                "system": f"{platform.system()} {platform.release()}",
                **log.env_snapshot(),
            },
            "dataset": data.as_dict(),
            "wall_seconds": wall_seconds,
            "cell": cell,
        }
        (out_dir / f"{run_id}.json").write_text(
            json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
        )
        log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

        label = f"address_{'kept' if address_kept else 'dropped'} x {split}_split"
        n = cell["resample"]["n_rows"]
        for name, row in cell["models"].items():
            sys.stdout.write(
                f"{date} | detection/bitcoinheist-q10 | {label}, {name}, n={n} | "
                f"acc={row['accuracy']:.4f} f1={row['f1']:.4f} "
                f"d_m4a={row['delta_vs_m4a_best']:+.4f} d_pub={row['delta_vs_published']:+.4f} | "
                f"measured | {run_id} | Q10 ablation\n"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
