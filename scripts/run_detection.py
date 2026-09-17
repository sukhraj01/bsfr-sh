"""Run the BitcoinHeist evaluation: both modes, all four models, baselines first. M4a, M4b/D6.

Thin wrapper. The loading, splitting, metrics and models are `bsfr_sh.detection`; this script
sequences them, times them, writes the sidecar and prints the `RESULTS.md` lines.

Three rules it enforces rather than assumes:

* **Baselines before models.** `baselines()` runs on each mode's labels before a single estimator
  is fitted, so no model number can be reported without the no-information number beside it
  (DEV-06).
* **`paper_mode` splits by address, not by row.** `configs/ml.yaml` sets `dataset.group_column`
  and `_run_paper_mode` calls `grouped_stratified_holdout`, so this is the honest 0.9442/0.9697
  figure (DEV-06's Q10 amendment), not the earlier 0.9479/0.9717 a row-random split produced.
  M4b/D6 retired the disagreement between this script and `scripts/q10_leakage_ablation.py`.
* **Project before you run.** `honest_mode` at full scale is where KNN stops being feasible, so
  `knn_projection()` decides *in advance* whether a model runs locally or is recorded as deferred
  to Ada. A run that cannot fit is named, never silently skipped and never attempted first
  (CLAUDE.md §6).

Usage::

    python scripts/run_detection.py --seed 20260912                 # subsampled honest_mode
    python scripts/run_detection.py --seed 20260912 --full          # 2.9M rows, expect Ada
    python scripts/run_detection.py --seed 20260912 --mode paper --full
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
    EXPECTED_RANSOMWARE,
    DatasetError,
    DatasetSpec,
    LoadedDataset,
    grouped_stratified_holdout,
    load_bitcoinheist,
    paper_mode_resample,
    stratified_folds,
    subsample_index,
)
from bsfr_sh.detection.metrics import baselines, honest_metrics, paper_metrics  # noqa: E402
from bsfr_sh.detection.models import (  # noqa: E402
    build_models,
    fit_and_score,
    fits_in_memory,
    knn_projection,
    largest_feasible_n,
)
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402


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


def _run_paper_mode(data: LoadedDataset, config: Any, seed: int, logger: Any) -> dict[str, Any]:
    """§VII's 90/10 resample, an address-grouped holdout, and all four models.

    D6/DEV-06 (Q10 amendment): split by `grouped_stratified_holdout` rather than the row-random
    `stratified_holdout` this used through M4a. BitcoinHeist rows sharing an address are near
    duplicates, so a random split leaks a near-duplicate across the train/test boundary; grouping
    keeps every address on one side. This is the change that retired D6 — before it, this script
    and `scripts/q10_leakage_ablation.py` disagreed on `paper_mode`'s honest figure.
    """
    fraction = float(config.get("modes.paper_mode.positive_fraction", 0.90))
    test_size = float(config.get("modes.paper_mode.test_size", 0.30))
    resample = paper_mode_resample(data, positive_fraction=fraction, seed=seed)
    log.event(
        logger,
        "paper_mode_resampled",
        n=resample.n_rows,
        positives=resample.n_positive,
        negatives=resample.n_negative,
        share_of_dataset=round(resample.n_rows / data.n_rows, 5),
    )
    if resample.groups is None:
        raise DatasetError(
            "paper_mode requires a grouped split (D6); configs/ml.yaml must set "
            "dataset.group_column"
        )

    x = resample.features.to_numpy(dtype=np.float64)
    y = resample.labels
    train_idx, test_idx = grouped_stratified_holdout(
        y, resample.groups, test_size=test_size, seed=seed
    )
    x_train, x_test = x[train_idx], x[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    # Baselines first, on the labels the models will be scored against.
    base = baselines(y_test, seed=seed)
    log.event(
        logger,
        "baselines_computed",
        mode="paper_mode",
        constant_positive_accuracy=round(base.constant_positive.accuracy, 4),
        constant_positive_f1=round(base.constant_positive.f1, 4),
    )

    results: dict[str, Any] = {}
    for name, estimator in build_models(config, seed=seed).items():
        fitted = fit_and_score(estimator, name, x_train, y_train, x_test, y_test)
        paper = paper_metrics(y_test, fitted.predictions)
        honest = honest_metrics(y_test, fitted.predictions, fitted.scores)
        results[name] = {**fitted.as_dict(), **paper.as_dict(), "honest": honest.as_dict()}
        log.event(
            logger,
            "model_scored",
            mode="paper_mode",
            model=name,
            accuracy=round(paper.accuracy, 4),
            f1=round(paper.f1, 4),
            fit_seconds=round(fitted.fit_seconds, 3),
        )
    return {
        "resample": resample.as_dict(),
        "split": "grouped_stratified_holdout",
        "test_size": test_size,
        "n_train": len(train_idx),
        "n_test": len(test_idx),
        "baselines": base.as_dict(),
        "models": results,
    }


def _fit_folds(
    config: Any, name: str, seed: int, x: np.ndarray, y: np.ndarray, splits: list[Any]
) -> dict[str, Any]:
    """Run one model over pre-computed `(train_idx, test_idx)` folds; pool out-of-fold scores."""
    predictions = np.zeros_like(y)
    scores = np.zeros(len(y), dtype=np.float64)
    fit_seconds = predict_seconds = 0.0
    for train_idx, test_idx in splits:
        fitted = fit_and_score(
            build_models(config, seed=seed)[name],
            name,
            x[train_idx],
            y[train_idx],
            x[test_idx],
            y[test_idx],
        )
        predictions[test_idx] = fitted.predictions
        if fitted.scores is not None:
            scores[test_idx] = fitted.scores
        fit_seconds += fitted.fit_seconds
        predict_seconds += fitted.predict_seconds
    honest = honest_metrics(y, predictions, scores)
    return {"fit_seconds": fit_seconds, "predict_seconds": predict_seconds, **honest.as_dict()}


def _run_honest_mode(
    data: LoadedDataset,
    config: Any,
    seed: int,
    folds: int,
    logger: Any,
    *,
    memory_ceiling_gb: float = 8.0,
    memory_headroom: float = 0.6,
) -> dict[str, Any]:
    """Natural class balance, stratified k-fold, out-of-fold predictions pooled once.

    `memory_ceiling_gb`/`memory_headroom` parameterise `fits_in_memory` (CLAUDE.md §6's "project
    before you run") rather than hard-coding the 8 GB dev-box default — M6b's Ada run passes the
    cluster's real allocation. If KNN still does not fit at the given ceiling,
    `largest_feasible_n` finds the largest row count that does, and KNN runs on a stratified
    subsample of exactly that size rather than being skipped outright — the run is named as
    reduced-scale, not silently smaller (CLAUDE.md §2).
    """
    x = data.features.to_numpy(dtype=np.float64)
    y = data.labels
    base = baselines(y, seed=seed)
    log.event(
        logger,
        "baselines_computed",
        mode="honest_mode",
        constant_negative_accuracy=round(base.constant_negative.accuracy, 4),
        note="a classifier that never predicts ransomware",
    )

    splits = list(stratified_folds(y, folds=folds, seed=seed))
    n_train = len(splits[0][0])
    n_query = len(splits[0][1])

    results: dict[str, Any] = {}
    deferred: dict[str, Any] = {}
    for name in build_models(config, seed=seed):
        if name == "k_nearest_neighbours":
            projection = knn_projection(n_train, n_query, x.shape[1])
            if not fits_in_memory(
                projection, ceiling_gb=memory_ceiling_gb, headroom=memory_headroom
            ):
                n_knn = largest_feasible_n(
                    x.shape[1], folds, ceiling_gb=memory_ceiling_gb, headroom=memory_headroom
                )
                if n_knn < folds * 2:
                    deferred[name] = {
                        "reason": f"projected peak exceeds the {memory_ceiling_gb:.0f} GB "
                        f"ceiling (headroom={memory_headroom}) even at the smallest workable "
                        "sample; CLAUDE.md §6",
                        "projection": projection,
                        "where": "Ada HPC batch job",
                    }
                    log.event(
                        logger,
                        "model_deferred",
                        mode="honest_mode",
                        model=name,
                        peak_gb=round(projection["peak_gb"], 2),
                        distance_computations=projection["distance_computations"],
                    )
                    continue
                sub_idx = subsample_index(y, n_knn, stratified=True, seed=seed)
                x_knn, y_knn = x[sub_idx], y[sub_idx]
                sub_splits = list(stratified_folds(y_knn, folds=folds, seed=seed))
                sub_projection = knn_projection(
                    len(sub_splits[0][0]), len(sub_splits[0][1]), x.shape[1]
                )
                log.event(
                    logger,
                    "model_subsampled_for_memory",
                    mode="honest_mode",
                    model=name,
                    n_full=len(y),
                    n_knn=n_knn,
                    ceiling_gb=memory_ceiling_gb,
                    headroom=memory_headroom,
                    peak_gb=round(sub_projection["peak_gb"], 2),
                )
                results[name] = {
                    "folds": folds,
                    "n_rows": n_knn,
                    "full_n_rows": len(y),
                    "subsampled_for_memory": True,
                    "ceiling_gb": memory_ceiling_gb,
                    "headroom": memory_headroom,
                    "projection_at_full_scale": projection,
                    **_fit_folds(config, name, seed, x_knn, y_knn, sub_splits),
                }
                log.event(
                    logger,
                    "model_scored",
                    mode="honest_mode",
                    model=name,
                    n_rows=n_knn,
                    recall=round(results[name]["recall"], 4),
                    precision=round(results[name]["precision"], 4),
                )
                continue

        row = {"folds": folds, "n_rows": len(y), **_fit_folds(config, name, seed, x, y, splits)}
        results[name] = row
        log.event(
            logger,
            "model_scored",
            mode="honest_mode",
            model=name,
            recall=round(row["recall"], 4),
            precision=round(row["precision"], 4),
            pr_auc=round(row["pr_auc"], 4),
            mcc=round(row["mcc"], 4),
        )

    return {
        "folds": folds,
        "n_rows": data.n_rows,
        "positive_rate": data.positive_rate,
        "baselines": base.as_dict(),
        "models": results,
        "deferred": deferred,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260912)
    parser.add_argument("--mode", choices=("paper", "honest", "both"), default="both")
    parser.add_argument("--folds", type=int, default=None)
    parser.add_argument(
        "--full",
        action="store_true",
        help="use all 2.9M rows for honest_mode instead of the configured subsample",
    )
    parser.add_argument(
        "--memory-ceiling-gb",
        type=float,
        default=8.0,
        help="KNN memory ceiling for fits_in_memory (default: the 8 GB dev box, CLAUDE.md §6; "
        "Ada's sbatch passes its real allocation)",
    )
    parser.add_argument(
        "--memory-headroom",
        type=float,
        default=0.6,
        help="fraction of --memory-ceiling-gb usable before interpreter/OS/pandas overhead",
    )
    args = parser.parse_args()

    config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    folds = args.folds or int(config.get("modes.honest_mode.cross_validation.folds", 5))
    seed_all(args.seed)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    spec = DatasetSpec.from_config(config, root=REPO_ROOT, subsample=not args.full)
    started = time.perf_counter()
    try:
        data = load_bitcoinheist(spec, verify=True, seed=args.seed)
    except DatasetError as exc:
        log.event(logger, "dataset_unavailable", error=str(exc))
        sys.stderr.write(f"{exc}\n")
        return 2
    load_seconds = time.perf_counter() - started
    log.event(
        logger,
        "dataset_loaded",
        rows=data.n_rows,
        positives=data.n_positive,
        positive_rate=round(data.positive_rate, 6),
        matches_paper_counts=data.matches_paper_counts,
        seconds=round(load_seconds, 2),
    )

    # paper_mode uses *every* ransomware row, so resampling from a subsample silently runs a
    # different, much smaller experiment than the one Table II reports. Refuse rather than report
    # a number that looks like the paper's and is not.
    if args.mode in ("paper", "both") and not data.matches_paper_counts:
        message = (
            "paper_mode must resample from the whole dataset: it uses every ransomware row, and "
            f"this load holds {data.n_positive} of {EXPECTED_RANSOMWARE}. Re-run with --full, "
            "or use --mode honest."
        )
        log.event(logger, "paper_mode_refused", reason=message)
        sys.stderr.write(message + "\n")
        return 2

    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M4a — BitcoinHeist reproduction (Targets 1-2, DEV-06)",
        "seed": args.seed,
        "config_hash": config_hash(config.kind, config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "dataset": data.as_dict(),
        "load_seconds": load_seconds,
        "full_scale": args.full,
        "host": {
            "machine": platform.machine(),
            "processor": platform.processor() or platform.machine(),
            "system": f"{platform.system()} {platform.release()}",
            **log.env_snapshot(),
        },
    }

    if args.mode in ("paper", "both"):
        started = time.perf_counter()
        sidecar["paper_mode"] = _run_paper_mode(data, config, args.seed, logger)
        sidecar["paper_mode"]["wall_seconds"] = time.perf_counter() - started
    if args.mode in ("honest", "both"):
        started = time.perf_counter()
        sidecar["honest_mode"] = _run_honest_mode(
            data,
            config,
            args.seed,
            folds,
            logger,
            memory_ceiling_gb=args.memory_ceiling_gb,
            memory_headroom=args.memory_headroom,
        )
        sidecar["honest_mode"]["wall_seconds"] = time.perf_counter() - started

    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(sidecar, run_id)
    _emit_reports(sidecar, run_id, logger)
    return 0


def _emit_reports(sidecar: dict[str, Any], run_id: str, logger: Any) -> None:
    """Table II (+ Figs. 4-5 for paper_mode) from whichever mode(s) this run produced.

    Imported lazily — `matplotlib` is only needed here, not for a `--mode honest` run that never
    touches `bench.emit`'s figure code (paper_mode's chart needs the technique comparison; there
    is no honest_mode figure per the M6b brief).
    """
    from bsfr_sh.bench import emit

    tables_dir = REPO_ROOT / "results" / "tables"
    figures_dir = REPO_ROOT / "results" / "figures"
    written: list[str] = []

    if "paper_mode" in sidecar:
        table_path = emit.emit_table2_paper_mode(sidecar["paper_mode"], tables_dir=tables_dir)
        written.append(str(table_path.relative_to(REPO_ROOT)))
        run_meta = {
            "run_id": run_id,
            "seed": sidecar["seed"],
            "config_hash": sidecar["config_hash"],
            "config_hash_scheme": sidecar["config_hash_scheme"],
            "git_rev": sidecar["git_rev"],
            "host": sidecar["host"],
            "started_at": sidecar.get("started_at", 0.0),
            "wall_seconds": sidecar["paper_mode"].get("wall_seconds", 0.0),
        }
        report = emit.emit_fig4_5(sidecar["paper_mode"], figures_dir=figures_dir, run_meta=run_meta)
        written.extend(str(p.relative_to(REPO_ROOT)) for p in report.figures)

    if "honest_mode" in sidecar:
        table_path = emit.emit_table2_honest_mode(sidecar["honest_mode"], tables_dir=tables_dir)
        written.append(str(table_path.relative_to(REPO_ROOT)))

    log.event(logger, "reports_emitted", paths=written)


def _print_results_lines(sidecar: dict[str, Any], run_id: str) -> None:
    """RESULTS.md lines, ready to paste. One per run, `measured`, with the run_id."""
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    if "paper_mode" in sidecar:
        n = sidecar["paper_mode"]["resample"]["n_rows"]
        for name, row in sidecar["paper_mode"]["models"].items():
            sys.stdout.write(
                f"{date} | detection/bitcoinheist-paper | {name}, 90/10 n={n}, grouped split | "
                f"acc={row['accuracy']:.4f} f1={row['f1']:.4f} | measured | {run_id} | "
                f"Table II target, D6 retired (DEV-06)\n"
            )
        base = sidecar["paper_mode"]["baselines"]["constant_positive"]
        sys.stdout.write(
            f"{date} | detection/bitcoinheist-paper | constant-positive, 90/10 n={n}, grouped "
            f"split | acc={base['accuracy']:.4f} f1={base['f1']:.4f} | measured | {run_id} | "
            f"baseline, looks at nothing\n"
        )
    if "honest_mode" in sidecar:
        for name, row in sidecar["honest_mode"]["models"].items():
            rows = row["n_rows"]
            note = (
                f"DEV-06 honest mode, subsampled for memory (full n={row['full_n_rows']}, "
                f"ceiling={row['ceiling_gb']}GB)"
                if row.get("subsampled_for_memory")
                else "DEV-06 honest mode"
            )
            sys.stdout.write(
                f"{date} | detection/bitcoinheist-honest | {name}, natural {rows} rows | "
                f"prec={row['precision']:.4f} rec={row['recall']:.4f} pr_auc={row['pr_auc']:.4f} "
                f"mcc={row['mcc']:.4f} f1min={row['f1_minority']:.4f} | measured | {run_id} | "
                f"{note}\n"
            )
        for name, row in sidecar["honest_mode"]["deferred"].items():
            sys.stdout.write(
                f"{date} | detection/bitcoinheist-honest | {name} | DEFERRED | — | {run_id} | "
                f"{row['reason']}\n"
            )


if __name__ == "__main__":
    raise SystemExit(main())
