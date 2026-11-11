"""Phase 2 / P2-C: does the detector learn *what* a ransomware address does, or *when* it was seen?

BitcoinHeist rows carry `year` (2011-2018) and `day`. Ransomware rows are concentrated in a few
years, so a model can score well by learning "which years had ransomware campaigns", a pattern
that cannot carry forward to next year's attacks. Phase 1 (M7-6 H4) saw that dropping `year` costs
~3 points and concluded year is genuine signal. That only shows year is *informative on a random
split*; it does not show the model would work on the future.

The test: train on the past, test on the future (a temporal split), and compare with the usual
random (address-grouped) split, for four feature sets: all 8, no `year`, no `year`/`day` (pure
address-behaviour features), and `year` alone. Same 90/10 resample as the paper. 5 seeds.

Usage::

    python scripts/p2c_year_shortcut.py --seed 20260912
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
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
)
from bsfr_sh.detection.fair import balanced_accuracy, false_positive_rate  # noqa: E402
from bsfr_sh.detection.metrics import paper_metrics  # noqa: E402
from bsfr_sh.detection.models import build_model, fit_and_score  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

SEEDS = 5
TEST_SIZE = 0.30
MODELS = ("random_forest", "decision_tree")
ALL8 = ("year", "day", "length", "weight", "count", "looped", "neighbors", "income")
FEATURE_SETS = {
    "all8": ALL8,
    "no_year": tuple(f for f in ALL8 if f != "year"),
    "no_year_day": tuple(f for f in ALL8 if f not in ("year", "day")),
    "year_only": ("year",),
}
#: train on years <= cut, test on years > cut
TEMPORAL_CUTS = (2015, 2016)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260912)
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

    # per-year picture of the full dataset (why `year` is such a strong shortcut) -------------
    years = data.features["year"].to_numpy()
    per_year = {
        int(yr): {
            "rows": int((years == yr).sum()),
            "ransomware": int(data.labels[years == yr].sum()),
            "ransomware_share_of_year": float(data.labels[years == yr].mean()),
            "share_of_all_ransomware": float(data.labels[years == yr].sum() / data.n_positive),
        }
        for yr in np.unique(years)
    }
    for yr, d in per_year.items():
        sys.stderr.write(f"year {yr}: {d}\n")

    rows: list[dict[str, Any]] = []
    for k in range(SEEDS):
        seed = args.seed + k
        rs = paper_mode_resample(data, positive_fraction=0.90, seed=seed)
        y = rs.labels
        yr = rs.features["year"].to_numpy()
        splits: dict[str, tuple[np.ndarray, np.ndarray]] = {
            "grouped_random": grouped_stratified_holdout(y, rs.groups, test_size=TEST_SIZE,
                                                         seed=seed),  # fmt: skip
        }
        for cut in TEMPORAL_CUTS:
            splits[f"temporal_le{cut}"] = (np.flatnonzero(yr <= cut), np.flatnonzero(yr > cut))
        for split_name, (tr, te) in splits.items():
            for fs_name, cols in FEATURE_SETS.items():
                x = rs.features.loc[:, list(cols)].to_numpy(dtype=np.float64)
                for model_name in MODELS:
                    est = build_model(config, model_name, seed=seed)
                    fitted = fit_and_score(est, model_name, x[tr], y[tr], x[te], y[te])
                    pm = paper_metrics(y[te], fitted.predictions)
                    row = {
                        "seed": seed, "split": split_name, "features": fs_name,
                        "model": model_name, "n_train": len(tr), "n_test": len(te),
                        "test_pos_rate": float(y[te].mean()),
                        "constant_positive_accuracy": float(y[te].mean()),
                        "accuracy": pm.accuracy, "f1": pm.f1,
                        "balanced_accuracy": balanced_accuracy(y[te], fitted.predictions),
                        "recall": float(np.mean(fitted.predictions[y[te] == 1] == 1)),
                        "fpr": false_positive_rate(y[te], fitted.predictions),
                    }  # fmt: skip
                    rows.append(row)
                    sys.stderr.write(
                        f"[seed={seed}] {split_name:<15} {fs_name:<12} {model_name:<14} "
                        f"acc={row['accuracy']:.4f} (const+ {row['constant_positive_accuracy']:.4f}) "
                        f"bal={row['balanced_accuracy']:.4f} rec={row['recall']:.3f} "
                        f"fpr={row['fpr']:.3f}\n"
                    )

    metrics = ("accuracy", "constant_positive_accuracy", "f1", "balanced_accuracy", "recall", "fpr")
    summary: dict[str, Any] = {}
    for split_name in ["grouped_random"] + [f"temporal_le{c}" for c in TEMPORAL_CUTS]:
        for fs_name in FEATURE_SETS:
            for model_name in MODELS:
                cell = [r for r in rows if (r["split"], r["features"], r["model"])
                        == (split_name, fs_name, model_name)]  # fmt: skip
                summary[f"{split_name}|{fs_name}|{model_name}"] = {
                    m: {"mean": statistics.fmean(r[m] for r in cell),
                        "sd": statistics.stdev(r[m] for r in cell)}
                    for m in metrics
                } | {"n_seeds": len(cell), "n_test": cell[0]["n_test"]}  # fmt: skip

    lines = ["split,features,model,n_seeds,n_test," + ",".join(f"{m}_mean,{m}_sd" for m in metrics)]
    for key, s in summary.items():
        lines.append(key.replace("|", ",") + f",{s['n_seeds']},{s['n_test']},"
                     + ",".join(f"{s[m]['mean']:.4f},{s[m]['sd']:.4f}" for m in metrics))  # fmt: skip
    (REPO_ROOT / "results" / "tables" / "p2c_year_shortcut.csv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    sidecar = {
        "run_id": run_id,
        "purpose": "P2-C: year shortcut — random vs temporal split, four feature sets",
        "seed": args.seed,
        "config_hash": config_hash(config.kind, config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                                  text=True, cwd=REPO_ROOT).stdout.strip(),  # fmt: skip
        "host": log.env_snapshot(),
        "per_year": per_year,
        "summary": summary,
        "rows": rows,
    }
    (REPO_ROOT / "results" / "logs" / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, default=float) + "\n", encoding="utf-8"
    )
    print(json.dumps({"run_id": run_id}))
    for key, s in summary.items():
        print(f"{key:<45} " + " ".join(f"{m}={s[m]['mean']:.4f}" for m in metrics))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
