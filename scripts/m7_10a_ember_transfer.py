"""M7-10 Part A: does a richer static dataset change M7-7's ClaMP finding?

M7-7 (`scripts/m7_7_real_malware_transfer.py`, DEV-34) scored the synthetic-trained honeypot
ensemble on ClaMP (5210 PE files, 3/22 `FT_RW` features mapped) and got bal_acc=0.5000 exactly —
a clean failure attributed to 86% of the feature space collapsing to a mapping artifact of zero.
EMBER (`honeypot.ember_mapping`, DEV-35) maps 6/22 features instead, using richer raw data (a
256-bin whole-file byte histogram, every PE section's own entropy and read/write/execute flags,
a full per-DLL import table) that ClaMP's fixed header floats did not carry. This script measures
whether that better-grounded mapping changes the transfer result, using the identical fitted
ensemble (same seed, same committed corpus, never retrained) and the identical sanity-check /
KS-test protocol M7-7 established.

Data and model, and why this is not a chain-path or a re-tuned model
----------------------------------------------------------------------
Same posture as M7-3/M7-7/M7-8: reads `data/honeypot/corpus_{train,eval}.csv` directly, never
`run_phase3_detection.py`'s chain path (DEV-27's CSV-vs-chain 0.8408-vs-0.8422 precision gap).
EMBER is read from its raw JSONL feature files (`ember_dataset_2018_2.tar.bz2`, downloaded per
`data/external/ember/README.md`) and used for **evaluation only** — it never fits or tunes
anything in `honeypot/` or `detection/`. The fully-labelled `test_features.jsonl` split is used in
full (no EMBER data crosses into any training set, and using the whole labelled test split avoids
an arbitrary subsample-size choice).

Usage::

    python scripts/m7_10a_ember_transfer.py
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
from sklearn.metrics import balanced_accuracy_score  # noqa: E402

from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, config_hash  # noqa: E402
from bsfr_sh.detection import metrics as detection_metrics  # noqa: E402
from bsfr_sh.detection import models as detection_models  # noqa: E402
from bsfr_sh.detection import profiles as detection_profiles  # noqa: E402
from bsfr_sh.detection.detector import DetectionModule  # noqa: E402
from bsfr_sh.honeypot import features as ft  # noqa: E402
from bsfr_sh.honeypot.distribution_compare import compare_distributions  # noqa: E402
from bsfr_sh.honeypot.ember_mapping import (  # noqa: E402
    EMBER_MAPPING,
    MappingKind,
    build_from_ember_row,
    mapping_summary,
)
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

#: Matches every other measured honeypot number in this project (M7-3/M7-7/M7-8).
SEED = 20260912
#: M7-3's established CSV-path baseline (`RESULTS.md` M7-3, `20260922T155316Z-3ce801ca`).
CSV_PATH_REFERENCE_BAL_ACC = 0.8408
_REPRODUCTION_TOLERANCE = 1e-4
EMBER_DIR = REPO_ROOT / "data" / "external" / "ember"
EMBER_TEST_JSONL = EMBER_DIR / "test_features.jsonl"
#: The 6 `FT_RW` features `honeypot.ember_mapping` grounds in real data (vs. ClaMP's 3).
MAPPED_FEATURES = (
    "write_entropy_mean",
    "write_entropy_var",
    "entropy_delta",
    "crypto_call_rate",
    "key_generation_events",
    "read_write_ratio",
)
#: M7-7's established ClaMP transfer result (`RESULTS.md` M7-7, `20260925T041117Z-672f7572`) —
#: cited for the side-by-side comparison this script's own docstring promises, not recomputed.
CLAMP_REFERENCE = {
    "balanced_accuracy": 0.5000,
    "precision": 0.0000,
    "recall": 0.0000,
    "mcc": 0.0000,
    "pr_auc": 0.4612,
}

_COLOR_SYNTHETIC = "#2a78d6"
_COLOR_REAL = "#eb6834"
_COLOR_CLAMP = "#9b9b9b"


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


def _load_synthetic(name: str) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.read_csv(REPO_ROOT / "data" / "honeypot" / f"corpus_{name}.csv")
    x = frame[list(ft.FEATURE_NAMES)].to_numpy(dtype=np.float64)
    y = (frame["label"] == "RW").to_numpy(dtype=np.int8)
    return x, y


def _load_ember_test() -> tuple[np.ndarray, np.ndarray, int]:
    """Every row of EMBER's fully-labelled test split, mapped to `FT_RW`. The `missing_mask` is
    identical for every row (the mapping is structural, not per-sample), so it is returned once
    rather than per row -- same check `m7_7_real_malware_transfer.py::_load_clamp` makes."""
    if not EMBER_TEST_JSONL.exists():
        raise SystemExit(
            f"{EMBER_TEST_JSONL} is missing; see data/external/ember/README.md to download and "
            "extract ember_dataset_2018_2.tar.bz2 first."
        )
    values: list[list[float]] = []
    labels: list[int] = []
    masks: set[int] = set()
    with EMBER_TEST_JSONL.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            label = row.get("label")
            if label not in (0, 1):
                continue  # EMBER's -1 marks an unlabelled row; never used here
            vector = build_from_ember_row(row)
            values.append(list(vector.values))
            labels.append(int(label))
            masks.add(vector.missing_mask)
    if not values:
        raise SystemExit(f"{EMBER_TEST_JSONL} produced zero labelled rows")
    assert len(masks) == 1, "the mapping is structural; every row should share one missing_mask"
    x = np.array(values, dtype=np.float64)
    y = np.array(labels, dtype=np.int8)
    return x, y, masks.pop()


def ensemble_predict_and_score(
    detector: DetectionModule, x: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    """Matches `m7_7_real_malware_transfer.py`'s helper of the same name exactly, so this
    script's numbers are directly comparable to M7-7's."""
    scores = detection_profiles.ensemble_score(detector.models, x)
    normal_spread = max(detector.normal.score_std, 1e-9)
    abnormal_spread = max(detector.abnormal.score_std, 1e-9)
    normal_membership = -(((scores - detector.normal.score_mean) / normal_spread) ** 2)
    abnormal_membership = -(((scores - detector.abnormal.score_mean) / abnormal_spread) ** 2)
    predictions = (abnormal_membership > normal_membership).astype(np.int8)
    return predictions, scores


def _score_set(detector: DetectionModule, x: np.ndarray, y: np.ndarray) -> dict[str, float]:
    predictions, scores = ensemble_predict_and_score(detector, x)
    honest = detection_metrics.honest_metrics(y, predictions, scores)
    return {
        "balanced_accuracy": float(balanced_accuracy_score(y, predictions)),
        "precision": honest.precision,
        "recall": honest.recall,
        "mcc": honest.mcc,
        "pr_auc": honest.pr_auc,
        "n": len(y),
        "n_positive": int(y.sum()),
    }


def emit_distribution_figure(
    synthetic_x: np.ndarray, real_x: np.ndarray, figures_dir: Path
) -> Path:
    fig, axes = plt.subplots(2, 3, figsize=(13.0, 7.4), dpi=150)
    for ax, name in zip(axes.flat, MAPPED_FEATURES, strict=True):
        index = ft.FEATURE_NAMES.index(name)
        syn_vals = synthetic_x[:, index]
        real_vals = real_x[:, index]
        bins = np.linspace(
            min(syn_vals.min(), real_vals.min()), max(syn_vals.max(), real_vals.max()), 30
        )
        ax.hist(
            syn_vals, bins=bins, density=True, alpha=0.55, color=_COLOR_SYNTHETIC, label="synthetic"
        )
        ax.hist(
            real_vals, bins=bins, density=True, alpha=0.55, color=_COLOR_REAL, label="EMBER-mapped"
        )
        ax.set_title(name, fontsize=9.5)
        ax.set_xlabel("value")
    axes[0, 0].set_ylabel("density")
    axes[1, 0].set_ylabel("density")
    axes[0, -1].legend(fontsize=8, loc="upper right")
    fig.suptitle(
        "M7-10a: synthetic vs. real distributions, the 6 EMBER-mapped features", fontsize=10.5
    )
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig10a_ember_feature_distributions.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_transfer_comparison_figure(
    synthetic_metrics: dict[str, float], ember_metrics: dict[str, float], figures_dir: Path
) -> Path:
    fig, (ax_left, ax_right) = plt.subplots(1, 2, figsize=(10.2, 4.2), dpi=150)
    labels_left = ("balanced_accuracy", "precision", "recall")
    x_pos = np.arange(len(labels_left))
    width = 0.25
    ax_left.bar(
        x_pos - width,
        [synthetic_metrics[k] for k in labels_left],
        width,
        color=_COLOR_SYNTHETIC,
        label="synthetic (CSV baseline)",
    )
    ax_left.bar(
        x_pos,
        [CLAMP_REFERENCE[k] for k in labels_left],
        width,
        color=_COLOR_CLAMP,
        label="ClaMP transfer (M7-7)",
    )
    ax_left.bar(
        x_pos + width,
        [ember_metrics[k] for k in labels_left],
        width,
        color=_COLOR_REAL,
        label="EMBER transfer (M7-10a)",
    )
    ax_left.set_xticks(x_pos, labels_left, rotation=15, fontsize=8)
    ax_left.set_ylim(0, 1.0)
    ax_left.set_title("bounded-[0,1] metrics", fontsize=9.5)
    ax_left.legend(fontsize=7, loc="upper right")

    labels_right = ("mcc", "pr_auc")
    x_pos2 = np.arange(len(labels_right))
    ax_right.bar(
        x_pos2 - width, [synthetic_metrics[k] for k in labels_right], width, color=_COLOR_SYNTHETIC
    )
    ax_right.bar(x_pos2, [CLAMP_REFERENCE[k] for k in labels_right], width, color=_COLOR_CLAMP)
    ax_right.bar(x_pos2 + width, [ember_metrics[k] for k in labels_right], width, color=_COLOR_REAL)
    ax_right.set_xticks(x_pos2, labels_right, fontsize=8)
    ax_right.axhline(0.0, color="#333333", linewidth=0.8)
    ax_right.set_ylim(-1.0, 1.0)
    ax_right.set_title("MCC / PR-AUC", fontsize=9.5)

    fig.suptitle("M7-10a: synthetic baseline vs. ClaMP (M7-7) vs. EMBER transfer", fontsize=10.5)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig10b_ember_transfer_metrics.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def main() -> int:
    started = time.perf_counter()
    ml_config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    seed_all(SEED)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    x_train, y_train = _load_synthetic("train")
    x_eval, y_eval = _load_synthetic("eval")
    models = detection_models.train_all(x_train, y_train, ml_config, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    detector = DetectionModule(models=models, normal=normal, abnormal=abnormal)

    synthetic_metrics = _score_set(detector, x_eval, y_eval)
    drift = abs(synthetic_metrics["balanced_accuracy"] - CSV_PATH_REFERENCE_BAL_ACC)
    if drift > _REPRODUCTION_TOLERANCE:
        raise SystemExit(
            f"synthetic-eval balanced_accuracy={synthetic_metrics['balanced_accuracy']:.4f} does "
            f"not reproduce the established {CSV_PATH_REFERENCE_BAL_ACC} (drift={drift:.4f}); the "
            "mapping/evaluation code below must not be trusted until this is fixed."
        )
    log.event(
        logger,
        "reproduction_check_passed",
        balanced_accuracy=round(synthetic_metrics["balanced_accuracy"], 4),
    )

    x_real, y_real, real_missing_mask = _load_ember_test()
    ember_metrics = _score_set(detector, x_real, y_real)
    summary = mapping_summary()
    log.event(
        logger,
        "transfer_measured",
        balanced_accuracy=round(ember_metrics["balanced_accuracy"], 4),
        n=ember_metrics["n"],
        n_positive=ember_metrics["n_positive"],
        missing_mask=real_missing_mask,
        clamp_reference=CLAMP_REFERENCE["balanced_accuracy"],
    )

    x_synthetic_all = np.concatenate([x_train, x_eval], axis=0)
    ks_results = []
    for index, name in enumerate(ft.FEATURE_NAMES):
        result = compare_distributions(name, x_synthetic_all[:, index], x_real[:, index])
        ks_results.append((name, EMBER_MAPPING[name].kind, result))

    figures_dir = REPO_ROOT / "results" / "figures"
    fig_a = emit_distribution_figure(x_synthetic_all, x_real, figures_dir)
    fig_b = emit_transfer_comparison_figure(synthetic_metrics, ember_metrics, figures_dir)

    wall_seconds = time.perf_counter() - started
    host = {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }
    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-10a -- EMBER transfer evaluation, richer static mapping than M7-7's ClaMP",
        "seed": SEED,
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": host,
        "wall_seconds": wall_seconds,
        "synthetic_csv_baseline": synthetic_metrics,
        "ember_transfer": ember_metrics,
        "clamp_reference": CLAMP_REFERENCE,
        "ember_missing_mask": real_missing_mask,
        "mapping_summary": summary,
        "mapped_feature_count": {"ember": 6, "clamp": 3},
        "ks_tests": [
            {"feature": name, "kind": kind.value, **result.as_dict()}
            for name, kind, result in ks_results
        ],
        "figures": [str(fig_a.relative_to(REPO_ROOT)), str(fig_b.relative_to(REPO_ROOT))],
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-10a-ember-transfer | synthetic CSV baseline (sanity "
        f"check), n={synthetic_metrics['n']} | bal_acc={synthetic_metrics['balanced_accuracy']:.4f} "
        f"prec={synthetic_metrics['precision']:.4f} rec={synthetic_metrics['recall']:.4f} "
        f"mcc={synthetic_metrics['mcc']:.4f} pr_auc={synthetic_metrics['pr_auc']:.4f} | measured | "
        f"{run_id} | reproduces M7-3's 0.8408\n"
    )
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-10a-ember-transfer | EMBER real-data transfer (6/22 "
        f"features mapped, test_features.jsonl), n={ember_metrics['n']} "
        f"(pos={ember_metrics['n_positive']}) | bal_acc={ember_metrics['balanced_accuracy']:.4f} "
        f"prec={ember_metrics['precision']:.4f} rec={ember_metrics['recall']:.4f} "
        f"mcc={ember_metrics['mcc']:.4f} pr_auc={ember_metrics['pr_auc']:.4f} | measured | {run_id} "
        f"| cf. M7-7 ClaMP bal_acc={CLAMP_REFERENCE['balanced_accuracy']:.4f} (3/22 features mapped)\n"
    )
    for name, kind, result in ks_results:
        if kind is MappingKind.MISSING:
            continue
        sys.stdout.write(
            f"{date} | detection/honeypot-m7-10a-ks | {name} ({kind.value}) | "
            f"D={result.statistic:.4f} p={result.p_value:.2e} syn_mean={result.synthetic_mean:.4f} "
            f"real_mean={result.real_mean:.4f} | measured | {run_id} | KS test, synthetic vs. "
            "EMBER-mapped\n"
        )
    sys.stdout.write(f"\nWall time: {wall_seconds:.2f}s\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
