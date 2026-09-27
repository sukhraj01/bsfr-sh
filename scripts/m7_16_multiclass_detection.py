"""M7-16: does BitcoinHeist's feature space carry family-discriminative signal, not just
ransomware-vs-benign? All four Table II algorithms, multi-class variants, over the family label
the binary evaluation (M4a onward) has never used.

Thin wrapper, same posture as `scripts/run_detection.py`: the loading, merging, models and metrics
are `bsfr_sh.detection.dataset`/`bsfr_sh.detection.multiclass`; this script sequences them, times
them, writes the sidecar, prints the `RESULTS.md` lines and emits the confusion-matrix figure.

Natural class balance, no resample
-----------------------------------
The 90/10 resample (`paper_mode`) is a binary trick — "keep every positive, thin the negatives to
hit a ratio" has no 29-class analogue, so this script always runs at the dataset's true family
distribution, one grouped stratified holdout (not k-fold; 29 raw classes, eleven of them under 10
samples total, would leave some folds with zero training examples of a class).

Compute (CLAUDE.md §6)
------------------------
RF/DT run at full scale unconditionally — neither has a distance-matrix memory hazard. KNN is
projected with the same `detection.models.knn_projection`/`largest_feasible_n` M6b/DEV-31 already
established for the binary detector, and subsampled rather than deferred outright if the full
8 GB-box projection does not fit. `logistic_regression`'s one-vs-rest wrapper fits 19 binary
models instead of one; if that does not finish in a practical local wall-clock, it runs on the
same reduced sample KNN falls back to and is named as such — this script measures its own fit time
and decides, it does not guess in advance.

Usage::

    python scripts/m7_16_multiclass_detection.py --seed 20260912
    python scripts/m7_16_multiclass_detection.py --seed 20260912 --full
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

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, config_hash  # noqa: E402
from bsfr_sh.detection.dataset import (  # noqa: E402
    BENIGN_LABEL,
    DatasetError,
    DatasetSpec,
    FamilyDataset,
    grouped_stratified_holdout,
    load_bitcoinheist_families,
)
from bsfr_sh.detection.models import (  # noqa: E402
    ModelError,
    fits_in_memory,
    knn_projection,
    largest_feasible_n,
)
from bsfr_sh.detection.multiclass import (  # noqa: E402
    LARGE_FAMILY_THRESHOLD,
    MIN_FAMILY_SAMPLES,
    binary_collapse,
    build_multiclass_models,
    class_distribution,
    confusion,
    fit_and_score_multiclass,
    macro_f1,
    merge_rare_families,
    per_class_report,
    per_family_feature_signal,
    top_k_accuracy,
    weighted_f1,
)
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

#: M6b's full-scale honest_mode RF numbers (RESULTS.md, run 20260917T175754Z-f3b9e363) — the
#: binary-detection floor the multi-class model's binary-collapse must clear (M7-16 brief step 3).
HONEST_MODE_BINARY_REFERENCE: dict[str, float] = {
    "precision": 0.7434,
    "recall": 0.2874,
    "mcc": 0.4579,
    "f1_minority": 0.4145,
}


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


def _run_models(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_test: np.ndarray,
    y_test: np.ndarray,
    config: Any,
    seed: int,
    logger: Any,
    *,
    memory_ceiling_gb: float,
    memory_headroom: float,
) -> dict[str, Any]:
    """Fit every enabled model, deferring/subsampling KNN under CLAUDE.md §6 exactly as
    `scripts/run_detection.py`'s `_run_honest_mode` does for the binary case."""
    n_features = x_train.shape[1]
    results: dict[str, Any] = {}
    deferred: dict[str, Any] = {}

    for name, estimator in build_multiclass_models(config, seed=seed).items():
        x_tr, y_tr, x_te, y_te = x_train, y_train, x_test, y_test
        subsampled = False
        if name == "k_nearest_neighbours":
            projection = knn_projection(len(y_train), len(y_test), n_features)
            if not fits_in_memory(
                projection, ceiling_gb=memory_ceiling_gb, headroom=memory_headroom
            ):
                n_knn = largest_feasible_n(
                    n_features, 2, ceiling_gb=memory_ceiling_gb, headroom=memory_headroom
                )
                if n_knn < 20:
                    deferred[name] = {
                        "reason": f"projected peak exceeds the {memory_ceiling_gb:.0f} GB "
                        "ceiling even at the smallest workable sample; CLAUDE.md §6",
                        "projection": projection,
                        "where": "Ada HPC batch job",
                    }
                    log.event(
                        logger,
                        "model_deferred",
                        mode="multiclass",
                        model=name,
                        peak_gb=round(projection["peak_gb"], 2),
                    )
                    continue
                train_take = int(n_knn * len(y_train) / (len(y_train) + len(y_test)))
                test_take = n_knn - train_take
                rng = np.random.default_rng(seed)
                tr_idx = rng.choice(len(y_train), size=min(train_take, len(y_train)), replace=False)
                te_idx = rng.choice(len(y_test), size=min(test_take, len(y_test)), replace=False)
                x_tr, y_tr = x_train[tr_idx], y_train[tr_idx]
                x_te, y_te = x_test[te_idx], y_test[te_idx]
                subsampled = True
                log.event(
                    logger,
                    "model_subsampled_for_memory",
                    mode="multiclass",
                    model=name,
                    n_full=len(y_train) + len(y_test),
                    n_knn=len(y_tr) + len(y_te),
                    ceiling_gb=memory_ceiling_gb,
                )

        fitted = fit_and_score_multiclass(estimator, name, x_tr, y_tr, x_te)
        results[name] = {
            **fitted.as_dict(),
            "subsampled_for_memory": subsampled,
            "classes": list(fitted.classes_),
            "macro_f1": macro_f1(y_te, fitted.predictions),
            "weighted_f1": weighted_f1(y_te, fitted.predictions),
            "top3_accuracy": top_k_accuracy(y_te, fitted.probabilities, fitted.classes_, k=3),
            "binary_collapse": binary_collapse(y_te, fitted.predictions).as_dict(),
            "_y_test": y_te,
            "_predictions": fitted.predictions,
            "_classes": fitted.classes_,
        }
        log.event(
            logger,
            "model_scored",
            mode="multiclass",
            model=name,
            macro_f1=round(results[name]["macro_f1"], 4),
            weighted_f1=round(results[name]["weighted_f1"], 4),
            top3_accuracy=round(results[name]["top3_accuracy"], 4),
            fit_seconds=round(fitted.fit_seconds, 2),
        )

    return {"models": results, "deferred": deferred}


def _emit_confusion_figure(
    matrix: np.ndarray, labels: tuple[str, ...], model_name: str, figures_dir: Path
) -> Path:
    """The N x N family confusion matrix (log-scaled color, raw counts as text) for the best
    macro-F1 model — M7-16 brief exit condition."""
    side = max(6.0, 0.42 * len(labels))
    fig, ax = plt.subplots(figsize=(side, side), dpi=150)
    display = np.log1p(matrix)
    im = ax.imshow(display, cmap="viridis", aspect="auto")
    ax.set_xticks(range(len(labels)), labels, rotation=60, fontsize=6, ha="right")
    ax.set_yticks(range(len(labels)), labels, fontsize=6)
    ax.set_xlabel("predicted family")
    ax.set_ylabel("true family")
    for i in range(len(labels)):
        for j in range(len(labels)):
            if matrix[i, j] > 0:
                ax.text(
                    j, i, str(matrix[i, j]), ha="center", va="center", fontsize=5, color="white"
                )
    fig.colorbar(im, ax=ax, label="log(1 + count)", shrink=0.8)
    ax.set_title(f"M7-16: family confusion matrix ({model_name})", fontsize=10)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig_m7_16_family_confusion.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260912)
    parser.add_argument(
        "--full",
        action="store_true",
        help="use all 2.9M rows instead of the configured subsample",
    )
    parser.add_argument("--test-size", type=float, default=0.30)
    parser.add_argument("--memory-ceiling-gb", type=float, default=8.0)
    parser.add_argument("--memory-headroom", type=float, default=0.6)
    args = parser.parse_args()

    config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    seed_all(args.seed)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    spec = DatasetSpec.from_config(config, root=REPO_ROOT, subsample=not args.full)
    try:
        data: FamilyDataset = load_bitcoinheist_families(spec, verify=True, seed=args.seed)
    except DatasetError as exc:
        log.event(logger, "dataset_unavailable", error=str(exc))
        sys.stderr.write(f"{exc}\n")
        return 2

    distribution_raw = class_distribution(data.family_labels)
    merged_labels, merged_names = merge_rare_families(
        data.family_labels, min_count=MIN_FAMILY_SAMPLES
    )
    distribution_merged = class_distribution(merged_labels)
    log.event(
        logger,
        "dataset_loaded",
        rows=data.n_rows,
        raw_families=len(distribution_raw),
        merged_families=len(distribution_merged),
        merged_into_other=len(merged_names),
    )

    if data.groups is None:
        raise DatasetError(
            "M7-16 requires a grouped split; configs/ml.yaml must set dataset.group_column"
        )

    x = data.features.to_numpy(dtype=np.float64)
    train_idx, test_idx = grouped_stratified_holdout(
        merged_labels, data.groups, test_size=args.test_size, seed=args.seed
    )
    x_train, x_test = x[train_idx], x[test_idx]
    y_train, y_test = merged_labels[train_idx], merged_labels[test_idx]

    started = time.perf_counter()
    run_result = _run_models(
        x_train,
        y_train,
        x_test,
        y_test,
        config,
        args.seed,
        logger,
        memory_ceiling_gb=args.memory_ceiling_gb,
        memory_headroom=args.memory_headroom,
    )
    wall_seconds = time.perf_counter() - started

    # Per-family analysis: report for every surviving family, feature signal only for the large
    # ones (M7-16 brief step 4). Uses the macro-F1 winner among the models that actually ran.
    scored = {k: v for k, v in run_result["models"].items() if "_y_test" in v}
    if not scored:
        sys.stderr.write("no model produced a result; nothing to report\n")
        return 2
    best_name = max(scored, key=lambda k: scored[k]["macro_f1"])
    best = scored[best_name]
    labels = tuple(sorted(distribution_merged))
    report = per_class_report(best["_y_test"], best["_predictions"], labels)
    matrix = confusion(best["_y_test"], best["_predictions"], labels)

    large_families = [
        name
        for name, count in distribution_merged.items()
        if count >= LARGE_FAMILY_THRESHOLD and name != BENIGN_LABEL
    ]
    feature_signal: dict[str, dict[str, float]] = {}
    for family in large_families:
        try:
            feature_signal[family] = per_family_feature_signal(
                x_train, y_train, data.columns, family, seed=args.seed
            )
        except ModelError as exc:
            log.event(logger, "feature_signal_failed", family=family, error=str(exc))

    figures_dir = REPO_ROOT / "results" / "figures"
    fig_path = _emit_confusion_figure(matrix, labels, best_name, figures_dir)

    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-16 — multi-class ransomware family detection",
        "seed": args.seed,
        "test_size": args.test_size,
        "config_hash": config_hash(config.kind, config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "full_scale": args.full,
        "wall_seconds": wall_seconds,
        "dataset": data.as_dict(),
        "class_distribution_raw": distribution_raw,
        "class_distribution_merged": distribution_merged,
        "merged_into_other": list(merged_names),
        "n_train": len(train_idx),
        "n_test": len(test_idx),
        "models": {
            name: {k: v for k, v in result.items() if not k.startswith("_")}
            for name, result in run_result["models"].items()
        },
        "deferred": run_result["deferred"],
        "best_model_by_macro_f1": best_name,
        "per_family_report": report.as_dict(),
        "large_families": large_families,
        "per_family_feature_signal": feature_signal,
        "honest_mode_binary_reference": HONEST_MODE_BINARY_REFERENCE,
        "confusion_matrix_labels": list(labels),
        "confusion_matrix_figure": str(fig_path.relative_to(REPO_ROOT)),
        "host": {
            "machine": platform.machine(),
            "processor": platform.processor() or platform.machine(),
            "system": f"{platform.system()} {platform.release()}",
            **log.env_snapshot(),
        },
    }

    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    date = time.strftime("%Y-%m-%d")
    sys.stdout.write(f"\n# M7-16 results — run {run_id}\n")
    sys.stdout.write(
        f"Class distribution (merged, {len(distribution_merged)} classes): {distribution_merged}\n"
    )
    sys.stdout.write(
        f"Merged into other_ransomware (< {MIN_FAMILY_SAMPLES} samples): {merged_names}\n"
    )
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    for name, result in sidecar["models"].items():
        sys.stdout.write(
            f"{date} | detection/bitcoinheist-multiclass | {name}, natural {data.n_rows} rows, "
            f"{len(distribution_merged)} classes | macro_f1={result['macro_f1']:.4f} "
            f"weighted_f1={result['weighted_f1']:.4f} top3={result['top3_accuracy']:.4f} "
            f"bc_rec={result['binary_collapse']['recall']:.4f} "
            f"bc_mcc={result['binary_collapse']['mcc']:.4f} | measured | {run_id} | M7-16\n"
        )
    for name, info in sidecar["deferred"].items():
        sys.stdout.write(f"# deferred: {name} — {info['reason']}\n")
    sys.stdout.write(f"\nBest model by macro F1: {best_name}\n")
    sys.stdout.write(f"Confusion figure: {fig_path.relative_to(REPO_ROOT)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
