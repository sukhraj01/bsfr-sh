"""Phase 2 / P2-E: P2-C showed the detector fails on future years. Does retraining every year fix it?

P2-C trained once on 2011-2015 and tested on 2016-2018. A real operator would not do that; they
would retrain as new labelled data arrives. This script simulates that, year by year: for each
test year t in 2014-2017 (the years with thousands of ransomware rows; 2018 has 3), train on

* `static`        — 2011-2013 only, never retrained (the "deploy once" baseline);
* `expanding`     — every year before t (retrain yearly, keep all history);
* `sliding_2yr`   — the two years before t only (retrain yearly, forget old campaigns);
* `same_year`     — a random address-grouped 70/30 split *inside* year t (reference only: what
                    the score would be if next year looked exactly like this year, i.e. the
                    random-split world the paper and Phase 1 measured in).

and test on year t. Two feature sets: `no_year` (year cannot help on an unseen year, so this is the
fair one) and `all8`. Same 90/10 resample as the paper and P2-C, 5 seeds, random forest.

It also counts which ransomware *families* make up each year, from the raw label column, because
"a new year" in this dataset largely means "new families".

Usage::

    python scripts/p2e_yearly_retraining.py --seed 20260912
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
import pandas as pd

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
from bsfr_sh.detection.models import build_model, fit_and_score  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

SEEDS = 5
TEST_YEARS = (2014, 2015, 2016, 2017)
STRATEGIES = ("static", "expanding", "sliding_2yr", "same_year")
ALL8 = ("year", "day", "length", "weight", "count", "looped", "neighbors", "income")
FEATURE_SETS = {"no_year": tuple(f for f in ALL8 if f != "year"), "all8": ALL8}
MODEL = "random_forest"


def _train_years(strategy: str, t: int) -> tuple[int, ...]:
    if strategy == "static":
        return (2011, 2012, 2013)
    if strategy == "expanding":
        return tuple(range(2011, t))
    if strategy == "sliding_2yr":
        return (t - 2, t - 1)
    raise ValueError(strategy)


def _family_table(path: Path) -> dict[int, dict[str, int]]:
    raw = pd.read_csv(path, usecols=["year", "label"])
    rw = raw[raw["label"] != "white"]
    out: dict[int, dict[str, int]] = {}
    for yr, grp in rw.groupby("year"):
        counts = grp["label"].value_counts()
        out[int(yr)] = {str(k): int(v) for k, v in counts.items()}
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260912)
    args = parser.parse_args()

    config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    seed_all(args.seed)
    run_id = log.configure()
    csv_path = REPO_ROOT / "data" / "raw" / "BitcoinHeistData.csv"
    spec = DatasetSpec(
        path=csv_path,
        feature_columns=tuple(config.require("dataset.feature_columns", list)),
        label_column=config.require("dataset.label_column", str),
        benign_label=config.require("dataset.benign_label", str),
        drop_columns=(),
        group_column="address",
    )
    data = load_bitcoinheist(spec, verify=True, seed=args.seed)

    families = _family_table(csv_path)
    family_novelty: dict[int, dict[str, float]] = {}
    for t in TEST_YEARS:
        seen = {f for yr, fam in families.items() if yr < t for f in fam}
        this = families.get(t, {})
        total = sum(this.values())
        unseen = sum(v for f, v in this.items() if f not in seen)
        family_novelty[t] = {
            "ransomware_rows": total,
            "families": len(this),
            "share_from_families_never_seen_before": unseen / total if total else 0.0,
        }
        sys.stderr.write(f"{t}: {family_novelty[t]} top={sorted(this.items(), key=lambda x: -x[1])[:3]}\n")

    rows: list[dict[str, Any]] = []
    for k in range(SEEDS):
        seed = args.seed + k
        rs = paper_mode_resample(data, positive_fraction=0.90, seed=seed)
        y = rs.labels
        yr = rs.features["year"].to_numpy()
        assert rs.groups is not None
        for t in TEST_YEARS:
            in_t = np.flatnonzero(yr == t)
            for strategy in STRATEGIES:
                if strategy == "same_year":
                    tr_l, te_l = grouped_stratified_holdout(y[in_t], rs.groups[in_t], test_size=0.30,
                                                            seed=seed)  # fmt: skip
                    tr, te = in_t[tr_l], in_t[te_l]
                else:
                    tr = np.flatnonzero(np.isin(yr, _train_years(strategy, t)))
                    te = in_t
                for fs_name, cols in FEATURE_SETS.items():
                    x = rs.features.loc[:, list(cols)].to_numpy(dtype=np.float64)
                    est = build_model(config, MODEL, seed=seed)
                    fitted = fit_and_score(est, MODEL, x[tr], y[tr], x[te], y[te])
                    pred = fitted.predictions
                    row = {
                        "seed": seed, "test_year": t, "strategy": strategy, "features": fs_name,
                        "n_train": len(tr), "n_test": len(te),
                        "test_pos_rate": float(y[te].mean()),
                        "accuracy": float(np.mean(pred == y[te])),
                        "balanced_accuracy": balanced_accuracy(y[te], pred),
                        "recall": float(np.mean(pred[y[te] == 1] == 1)),
                        "fpr": false_positive_rate(y[te], pred),
                    }  # fmt: skip
                    rows.append(row)
                    sys.stderr.write(
                        f"[seed={seed}] {t} {strategy:<12} {fs_name:<8} n_tr={len(tr):<6} "
                        f"bal={row['balanced_accuracy']:.3f} rec={row['recall']:.3f} "
                        f"fpr={row['fpr']:.3f}\n"
                    )

    metrics = ("accuracy", "balanced_accuracy", "recall", "fpr", "test_pos_rate")
    summary: dict[str, Any] = {}
    for t in TEST_YEARS:
        for strategy in STRATEGIES:
            for fs_name in FEATURE_SETS:
                cell = [r for r in rows if (r["test_year"], r["strategy"], r["features"])
                        == (t, strategy, fs_name)]  # fmt: skip
                summary[f"{t}|{strategy}|{fs_name}"] = {
                    m: {"mean": statistics.fmean(r[m] for r in cell),
                        "sd": statistics.stdev(r[m] for r in cell)}
                    for m in metrics
                } | {"n_seeds": len(cell), "n_train": cell[0]["n_train"],
                     "n_test": cell[0]["n_test"]}  # fmt: skip

    header = "test_year,strategy,features,n_seeds,n_train,n_test," + ",".join(
        f"{m}_mean,{m}_sd" for m in metrics
    )
    lines = [header]
    for key, s in summary.items():
        lines.append(key.replace("|", ",") + f",{s['n_seeds']},{s['n_train']},{s['n_test']},"
                     + ",".join(f"{s[m]['mean']:.4f},{s[m]['sd']:.4f}" for m in metrics))  # fmt: skip
    (REPO_ROOT / "results" / "tables" / "p2e_yearly_retraining.csv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    sidecar = {
        "run_id": run_id,
        "purpose": "P2-E: does yearly retraining rescue the detector on future years?",
        "seed": args.seed,
        "config_hash": config_hash(config.kind, config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                                  text=True, cwd=REPO_ROOT).stdout.strip(),  # fmt: skip
        "host": log.env_snapshot(),
        "families_per_year": families,
        "family_novelty": family_novelty,
        "summary": summary,
        "rows": rows,
    }
    (REPO_ROOT / "results" / "logs" / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, default=float) + "\n", encoding="utf-8"
    )
    print(json.dumps({"run_id": run_id}))
    for key, s in summary.items():
        print(f"{key:<32} bal={s['balanced_accuracy']['mean']:.3f}±{s['balanced_accuracy']['sd']:.3f}"
              f" rec={s['recall']['mean']:.3f} fpr={s['fpr']['mean']:.3f} n_train={s['n_train']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
