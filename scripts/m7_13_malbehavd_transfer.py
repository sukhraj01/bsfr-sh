"""M7-13: does a dynamic-behavioral dataset change M7-7 (ClaMP)/M7-10a (EMBER)'s transfer story?

M7-7 mapped ClaMP (3/22 `FT_RW` features, entropy only) and got bal_acc=0.5000 exactly. M7-10a
mapped EMBER (6/22, entropy + partial crypto_api/filesystem) and got bal_acc=0.5000 again, with a
weakly-informative-but-discarded continuous score. Both attributed the failure to 16+/22 features
collapsing to the mapping's own structural-missing zero, which the fitted `NProf`/`AProf`
profiles (built where those slots are populated) read as closer to benign almost universally,
regardless of what the few real dimensions say. Both datasets are *static* — neither could ground
the five execution-time groups (filesystem's dynamic half, crypto_api, process, network,
persistence) no matter how much raw data they carried; only entropy, one of the few properties
measurable both statically and dynamically, ever grounded at all.

`honeypot.malbehavd_mapping` (DEV-39) maps MalbehavD-V1 — 2,570 real Windows PE files actually
**executed** in a Cuckoo sandbox — and grounds 12/22 features across 5/7 groups, the inverse
coverage pattern: everything except entropy and kill_chain. This script measures whether that
qualitative shift (not just a bigger coverage fraction, but the *execution-time* groups
specifically) changes the transfer result, using the identical fitted ensemble M7-7/M7-10a used
(same seed, same committed corpus, never retrained), and adds the per-group permutation-importance
comparison (real vs. synthetic) the M7-13 brief asks for that neither prior script computed.

Why the CSV path, not the chain path
-------------------------------------
Same reason as M7-3/M7-7/M7-10a: `corpus.write_corpus` rounds every feature to 6 significant
figures, so the committed CSV is not bit-identical to the full-precision chain path that produced
M4b's 0.8422. Reading the CSV reproduces 0.8408 — re-verified here as this script's own sanity
check before touching real data at all.

Real data is evaluation-only
------------------------------
MalbehavD-V1 (`data/external/malbehavd/README.md`) is never used to fit or tune anything. It is
read, mapped, and scored against the ensemble already fitted on the synthetic corpus.

Usage::

    python scripts/m7_13_malbehavd_transfer.py
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
from scipy.stats import mannwhitneyu

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
from bsfr_sh.honeypot.malbehavd_mapping import (  # noqa: E402
    MALBEHAVD_MAPPING,
    MappingKind,
    build_from_malbehavd_row,
    mapping_summary,
    parse_call_sequence,
)
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import numpy_generator, seed_all  # noqa: E402

#: Matches every other measured honeypot number in this project (M7-3/M7-7/M7-8/M7-10).
SEED = 20260912
#: M7-3's established CSV-path baseline (`RESULTS.md` M7-3, `20260922T155316Z-3ce801ca`).
CSV_PATH_REFERENCE_BAL_ACC = 0.8408
_REPRODUCTION_TOLERANCE = 1e-4
_PERMUTATION_REPEATS = 20
MALBEHAVD_PATH = REPO_ROOT / "data" / "external" / "malbehavd" / "MalBehavD-V1-dataset.csv"
#: The 12 `FT_RW` features `honeypot.malbehavd_mapping` grounds in real data (vs. EMBER's 6,
#: ClaMP's 3).
MAPPED_FEATURES = tuple(
    name for name, mapping in MALBEHAVD_MAPPING.items() if mapping.kind is not MappingKind.MISSING
)
#: M7-7's established ClaMP transfer result (`RESULTS.md` M7-7, `20260925T041117Z-672f7572`).
CLAMP_REFERENCE = {
    "balanced_accuracy": 0.5000,
    "precision": 0.0000,
    "recall": 0.0000,
    "mcc": 0.0000,
    "pr_auc": 0.4612,
}
#: M7-10a's established EMBER transfer result (`RESULTS.md` M7-10, `20260925T160711Z-62498d7b`).
EMBER_REFERENCE = {
    "balanced_accuracy": 0.5000,
    "precision": 0.6667,
    "recall": 0.00002,
    "mcc": 0.0013,
    "pr_auc": 0.6301,
}
#: M7-7's/M7-10a's own KS results, cited for the cross-dataset heatmap (`RESULTS.md` M7-7/M7-10a
#: lines), not recomputed here.
CLAMP_KS: dict[str, float] = {
    "write_entropy_mean": 0.1969,
    "write_entropy_var": 0.4884,
    "entropy_delta": 0.2854,
}
EMBER_KS: dict[str, float] = {
    "read_write_ratio": 0.2959,
    "write_entropy_mean": 0.1694,
    "write_entropy_var": 0.7390,
    "entropy_delta": 0.6065,
    "crypto_call_rate": 0.8127,
    "key_generation_events": 0.6118,
}

_COLOR_SYNTHETIC = "#2a78d6"
_COLOR_REAL = "#eb6834"
_COLOR_CLAMP = "#9b9b9b"
_COLOR_EMBER = "#c9a227"


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


def _load_malbehavd() -> tuple[np.ndarray, np.ndarray, int]:
    """Every MalbehavD-V1 row, mapped to `FT_RW`. The `missing_mask` is identical for every row
    (the mapping is structural, not per-sample), so it is returned once rather than per row --
    same check M7-7's/M7-10a's loaders make."""
    if not MALBEHAVD_PATH.exists():
        raise SystemExit(f"{MALBEHAVD_PATH} is missing; see data/external/malbehavd/README.md")
    frame = pd.read_csv(MALBEHAVD_PATH, dtype=str)
    sequence_columns = [c for c in frame.columns if c not in ("sha256", "labels")]
    values: list[list[float]] = []
    labels: list[int] = []
    masks: set[int] = set()
    for _, row in frame.iterrows():
        calls = parse_call_sequence([row[c] for c in sequence_columns])
        vector = build_from_malbehavd_row({"calls": calls})
        values.append(list(vector.values))
        labels.append(int(row["labels"]))
        masks.add(vector.missing_mask)
    assert len(masks) == 1, "the mapping is structural; every row should share one missing_mask"
    x = np.array(values, dtype=np.float64)
    y = np.array(labels, dtype=np.int8)
    return x, y, masks.pop()


def ensemble_predict_and_score(
    detector: DetectionModule, x: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    """Matches M7-7's/M7-10a's helper of the same name exactly, so this script's numbers are
    directly comparable to both."""
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


def group_permutation_importance(
    detector: DetectionModule, x: np.ndarray, y: np.ndarray, rng: np.random.Generator
) -> dict[str, float]:
    """Balanced-accuracy drop from shuffling every feature in one `FT_RW` group at once (each
    column independently permuted, same random draw applied `_PERMUTATION_REPEATS` times and
    averaged) -- the group-level analogue of `m7_10b_neural_detector.permutation_importance_top5`.
    A group whose columns are all the mapping's own structural-missing zero (e.g. `entropy` on
    MalbehavD-V1) permutes to itself and necessarily scores ~0 -- reported anyway, since a true
    zero is exactly the honest comparison point against the synthetic side's non-zero score for
    the same group.
    """
    baseline = balanced_accuracy_score(y, ensemble_predict_and_score(detector, x)[0])
    importances: dict[str, float] = {}
    for group, names in ft.FEATURE_GROUPS:
        indices = [ft.FEATURE_NAMES.index(name) for name in names]
        drops = []
        for _ in range(_PERMUTATION_REPEATS):
            x_perm = x.copy()
            for index in indices:
                x_perm[:, index] = rng.permutation(x_perm[:, index])
            predictions, _ = ensemble_predict_and_score(detector, x_perm)
            drops.append(baseline - balanced_accuracy_score(y, predictions))
        importances[group] = float(np.mean(drops))
    return importances


def within_real_separation(x_real: np.ndarray, y_real: np.ndarray) -> dict[str, dict[str, float]]:
    """Does MalbehavD-V1 *itself* separate malware from benign on the 12 mapped features, apart
    from whether the synthetic-trained ensemble can detect it? A two-sided Mann-Whitney U test
    per mapped feature, real malware rows vs. real benign rows -- orthogonal to every other
    number in this script (no synthetic corpus involved at all), and the check that distinguishes
    "no real signal exists" from "real signal exists but the fitted profiles cannot see it."
    """
    results: dict[str, dict[str, float]] = {}
    for name in MAPPED_FEATURES:
        index = ft.FEATURE_NAMES.index(name)
        benign = x_real[y_real == 0, index]
        malware = x_real[y_real == 1, index]
        statistic, p_value = mannwhitneyu(malware, benign, alternative="two-sided")
        results[name] = {
            "benign_mean": float(benign.mean()),
            "malware_mean": float(malware.mean()),
            "u_statistic": float(statistic),
            "p_value": float(p_value),
        }
    return results


def emit_coverage_figure(figures_dir: Path) -> Path:
    fig, ax = plt.subplots(figsize=(5.6, 4.0), dpi=150)
    labels = ("ClaMP\n(static)", "EMBER\n(static)", "MalbehavD-V1\n(dynamic)")
    counts = (3, 6, len(MAPPED_FEATURES))
    colors = (_COLOR_CLAMP, _COLOR_EMBER, _COLOR_REAL)
    ax.bar(labels, counts, color=colors)
    for index, count in enumerate(counts):
        ax.text(index, count + 0.3, str(count), ha="center", fontsize=10)
    ax.set_ylabel("FT_RW features mapped (of 22)")
    ax.set_ylim(0, 22)
    ax.axhline(22, color="#999999", linewidth=0.6, linestyle="--")
    ax.set_title("M7-13: real-dataset coverage progression", fontsize=10.5)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig13a_coverage_progression.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_distribution_figure(
    synthetic_x: np.ndarray, real_x: np.ndarray, figures_dir: Path
) -> Path:
    fig, axes = plt.subplots(4, 3, figsize=(13.0, 13.6), dpi=150)
    for ax, name in zip(axes.flat, MAPPED_FEATURES, strict=True):
        index = ft.FEATURE_NAMES.index(name)
        syn_vals = synthetic_x[:, index]
        real_vals = real_x[:, index]
        bins = np.linspace(
            min(syn_vals.min(), real_vals.min()), max(syn_vals.max(), real_vals.max()), 30
        )
        ax.hist(syn_vals, bins=bins, density=True, alpha=0.55, color=_COLOR_SYNTHETIC, label="synthetic")
        ax.hist(real_vals, bins=bins, density=True, alpha=0.55, color=_COLOR_REAL, label="MalbehavD-V1")
        ax.set_title(name, fontsize=9)
    axes.flat[0].legend(fontsize=7, loc="upper right")
    fig.suptitle(
        "M7-13: synthetic vs. real distributions, the 12 MalbehavD-V1-mapped features",
        fontsize=10.5,
    )
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig13b_malbehavd_feature_distributions.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_transfer_comparison_figure(
    synthetic_metrics: dict[str, float], malbehavd_metrics: dict[str, float], figures_dir: Path
) -> Path:
    fig, (ax_left, ax_right) = plt.subplots(1, 2, figsize=(11.0, 4.2), dpi=150)
    labels_left = ("balanced_accuracy", "precision", "recall")
    x_pos = np.arange(len(labels_left))
    width = 0.2
    series = (
        ("synthetic (CSV baseline)", synthetic_metrics, _COLOR_SYNTHETIC, -1.5 * width),
        ("ClaMP (M7-7)", CLAMP_REFERENCE, _COLOR_CLAMP, -0.5 * width),
        ("EMBER (M7-10a)", EMBER_REFERENCE, _COLOR_EMBER, 0.5 * width),
        ("MalbehavD-V1 (M7-13)", malbehavd_metrics, _COLOR_REAL, 1.5 * width),
    )
    for label, metrics, color, offset in series:
        ax_left.bar(x_pos + offset, [metrics[k] for k in labels_left], width, color=color, label=label)
    ax_left.set_xticks(x_pos, labels_left, rotation=15, fontsize=8)
    ax_left.set_ylim(0, 1.0)
    ax_left.set_title("bounded-[0,1] metrics", fontsize=9.5)
    ax_left.legend(fontsize=6.5, loc="upper right")

    labels_right = ("mcc", "pr_auc")
    x_pos2 = np.arange(len(labels_right))
    for _label, metrics, color, offset in series:
        ax_right.bar(x_pos2 + offset, [metrics[k] for k in labels_right], width, color=color)
    ax_right.set_xticks(x_pos2, labels_right, fontsize=8)
    ax_right.axhline(0.0, color="#333333", linewidth=0.8)
    ax_right.set_ylim(-1.0, 1.0)
    ax_right.set_title("MCC / PR-AUC", fontsize=9.5)

    fig.suptitle("M7-13: synthetic baseline vs. ClaMP vs. EMBER vs. MalbehavD-V1 transfer", fontsize=10.5)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig13c_transfer_metrics.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_group_importance_figure(
    synthetic_importance: dict[str, float], real_importance: dict[str, float], figures_dir: Path
) -> Path:
    groups = [group for group, _ in ft.FEATURE_GROUPS]
    x_pos = np.arange(len(groups))
    width = 0.35
    fig, ax = plt.subplots(figsize=(9.0, 4.4), dpi=150)
    ax.bar(x_pos - width / 2, [synthetic_importance[g] for g in groups], width, color=_COLOR_SYNTHETIC, label="synthetic eval")
    ax.bar(x_pos + width / 2, [real_importance[g] for g in groups], width, color=_COLOR_REAL, label="MalbehavD-V1")
    ax.set_xticks(x_pos, groups, rotation=25, fontsize=8, ha="right")
    ax.set_ylabel("balanced-accuracy drop from group permutation")
    ax.axhline(0.0, color="#333333", linewidth=0.6)
    ax.legend(fontsize=8)
    ax.set_title("M7-13: per-group permutation importance, synthetic vs. real", fontsize=10.5)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig13d_group_importance.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def emit_ks_heatmap_figure(
    ks_by_feature: dict[str, float], figures_dir: Path
) -> Path:
    """Every feature any of the three real datasets has ever mapped, D-statistic per dataset,
    blank where that dataset does not map it -- the cross-dataset pattern-at-a-glance the M7-13
    brief asks for."""
    rows = sorted(set(CLAMP_KS) | set(EMBER_KS) | set(ks_by_feature))
    datasets = ("ClaMP", "EMBER", "MalbehavD-V1")
    sources = (CLAMP_KS, EMBER_KS, ks_by_feature)
    matrix = np.full((len(rows), len(datasets)), np.nan)
    for r, feature in enumerate(rows):
        for c, source in enumerate(sources):
            if feature in source:
                matrix[r, c] = source[feature]

    fig, ax = plt.subplots(figsize=(5.6, max(4.0, 0.38 * len(rows))), dpi=150)
    masked = np.ma.masked_invalid(matrix)
    cmap = plt.get_cmap("magma").copy()
    cmap.set_bad(color="#e8e8e8")
    im = ax.imshow(masked, cmap=cmap, vmin=0.0, vmax=1.0, aspect="auto")
    ax.set_xticks(range(len(datasets)), datasets, fontsize=9)
    ax.set_yticks(range(len(rows)), rows, fontsize=8)
    for r in range(len(rows)):
        for c in range(len(datasets)):
            if not np.isnan(matrix[r, c]):
                ax.text(c, r, f"{matrix[r, c]:.2f}", ha="center", va="center", fontsize=7, color="white")
    fig.colorbar(im, ax=ax, label="KS D-statistic", shrink=0.8)
    ax.set_title("KS(synthetic, real) per feature per dataset", fontsize=10)
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig13e_ks_heatmap.png"
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

    x_real, y_real, real_missing_mask = _load_malbehavd()
    malbehavd_metrics = _score_set(detector, x_real, y_real)
    summary = mapping_summary()
    log.event(
        logger,
        "transfer_measured",
        balanced_accuracy=round(malbehavd_metrics["balanced_accuracy"], 4),
        n=malbehavd_metrics["n"],
        n_positive=malbehavd_metrics["n_positive"],
        missing_mask=real_missing_mask,
        clamp_reference=CLAMP_REFERENCE["balanced_accuracy"],
        ember_reference=EMBER_REFERENCE["balanced_accuracy"],
    )

    x_synthetic_all = np.concatenate([x_train, x_eval], axis=0)
    ks_results = []
    ks_by_feature: dict[str, float] = {}
    for index, name in enumerate(ft.FEATURE_NAMES):
        result = compare_distributions(name, x_synthetic_all[:, index], x_real[:, index])
        ks_results.append((name, MALBEHAVD_MAPPING[name].kind, result))
        if MALBEHAVD_MAPPING[name].kind is not MappingKind.MISSING:
            ks_by_feature[name] = result.statistic

    perm_rng_synthetic = numpy_generator(SEED)
    perm_rng_real = numpy_generator(SEED + 1)
    synthetic_importance = group_permutation_importance(detector, x_eval, y_eval, perm_rng_synthetic)
    real_importance = group_permutation_importance(detector, x_real, y_real, perm_rng_real)
    separation = within_real_separation(x_real, y_real)

    figures_dir = REPO_ROOT / "results" / "figures"
    fig_a = emit_coverage_figure(figures_dir)
    fig_b = emit_distribution_figure(x_synthetic_all, x_real, figures_dir)
    fig_c = emit_transfer_comparison_figure(synthetic_metrics, malbehavd_metrics, figures_dir)
    fig_d = emit_group_importance_figure(synthetic_importance, real_importance, figures_dir)
    fig_e = emit_ks_heatmap_figure(ks_by_feature, figures_dir)

    wall_seconds = time.perf_counter() - started
    host = {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }
    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-13 -- MalbehavD-V1 dynamic-behavioral transfer evaluation",
        "seed": SEED,
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": host,
        "wall_seconds": wall_seconds,
        "synthetic_csv_baseline": synthetic_metrics,
        "malbehavd_transfer": malbehavd_metrics,
        "clamp_reference": CLAMP_REFERENCE,
        "ember_reference": EMBER_REFERENCE,
        "malbehavd_missing_mask": real_missing_mask,
        "mapping_summary": summary,
        "mapped_feature_count": {"malbehavd": len(MAPPED_FEATURES), "ember": 6, "clamp": 3},
        "ks_tests": [
            {"feature": name, "kind": kind.value, **result.as_dict()}
            for name, kind, result in ks_results
        ],
        "group_permutation_importance": {
            "synthetic_eval": synthetic_importance,
            "malbehavd_real": real_importance,
        },
        "permutation_repeats": _PERMUTATION_REPEATS,
        "within_real_separation": separation,
        "figures": [str(p.relative_to(REPO_ROOT)) for p in (fig_a, fig_b, fig_c, fig_d, fig_e)],
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
        f"{date} | detection/honeypot-m7-13-malbehavd-transfer | synthetic CSV baseline (sanity "
        f"check), n={synthetic_metrics['n']} | bal_acc={synthetic_metrics['balanced_accuracy']:.4f} "
        f"prec={synthetic_metrics['precision']:.4f} rec={synthetic_metrics['recall']:.4f} "
        f"mcc={synthetic_metrics['mcc']:.4f} pr_auc={synthetic_metrics['pr_auc']:.4f} | measured | "
        f"{run_id} | reproduces M7-3's 0.8408\n"
    )
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-13-malbehavd-transfer | MalbehavD-V1 real-data transfer "
        f"(12/22 features mapped, dynamic Cuckoo traces), n={malbehavd_metrics['n']} "
        f"(pos={malbehavd_metrics['n_positive']}) | "
        f"bal_acc={malbehavd_metrics['balanced_accuracy']:.4f} prec={malbehavd_metrics['precision']:.4f} "
        f"rec={malbehavd_metrics['recall']:.4f} mcc={malbehavd_metrics['mcc']:.4f} "
        f"pr_auc={malbehavd_metrics['pr_auc']:.4f} | measured | {run_id} | cf. M7-7 ClaMP "
        f"bal_acc={CLAMP_REFERENCE['balanced_accuracy']:.4f} (3/22), M7-10a EMBER "
        f"bal_acc={EMBER_REFERENCE['balanced_accuracy']:.4f} (6/22)\n"
    )
    for name, kind, result in ks_results:
        if kind is MappingKind.MISSING:
            continue
        sys.stdout.write(
            f"{date} | detection/honeypot-m7-13-ks | {name} ({kind.value}) | "
            f"D={result.statistic:.4f} p={result.p_value:.2e} syn_mean={result.synthetic_mean:.4f} "
            f"real_mean={result.real_mean:.4f} | measured | {run_id} | KS test, synthetic vs. "
            "MalbehavD-V1-mapped\n"
        )
    for group, _names in ft.FEATURE_GROUPS:
        sys.stdout.write(
            f"{date} | detection/honeypot-m7-13-group-importance | {group} | "
            f"synthetic_drop={synthetic_importance[group]:.4f} "
            f"real_drop={real_importance[group]:.4f} | measured | {run_id} | balanced-accuracy "
            f"drop from permuting the group's features, {_PERMUTATION_REPEATS} repeats\n"
        )
    for name, stats in separation.items():
        sys.stdout.write(
            f"{date} | detection/honeypot-m7-13-separation | {name} | "
            f"benign_mean={stats['benign_mean']:.4f} malware_mean={stats['malware_mean']:.4f} "
            f"p={stats['p_value']:.2e} | measured | {run_id} | Mann-Whitney U, within MalbehavD-V1 "
            "only, no synthetic data involved\n"
        )
    sys.stdout.write(f"\nWall time: {wall_seconds:.2f}s\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
