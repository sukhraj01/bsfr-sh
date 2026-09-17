"""M6a's Figs. 6(a)-(e), and M6b's Table II / Figs. 4-5, from measured detection/bench output.

M6a — Figs. 6(a)-(e), from `bench.harness`'s output
-----------------------------------------------------
Two artifacts, not one (module docstring of `bench/harness.py`, and the M6a session brief):

* **The reproduction figures**, Figs. 6(a)-(d): our measured median seconds/TPS per case,
  plotted against the paper's own six numbers (`docs/EXPERIMENTS.md` Target 3/4), so a reader
  can see the shape comparison the reproduction claim is actually about (DEV-13 — trend and
  ratio, not absolute seconds).
* **The component-breakdown panel**, our own addition (not in the paper, not compared against
  it): compute, modelled network, index construction and D3's serialization estimate for case-3,
  as separate bars. Summing them into the reproduction figures above would make a `computed`
  number look like a `measured` one — see `bench/harness.py`'s module docstring.

M6b — Table II and Figs. 4-5, from `scripts/run_detection.py`'s output
-------------------------------------------------------------------------
`emit_table2_paper_mode`/`emit_table2_honest_mode` take the result dicts `_run_paper_mode`/
`_run_honest_mode` already build — nothing here re-runs a model. Rows 1-4 (Almashhadani, Hwang,
Sharmeen, Bae) are `paper_reported`, quoted from their own papers on their own, unrelated,
datasets (DEV-07); only the BSFR-SH row is ours to reproduce, and it is joined by every model we
actually ran, not just the one the paper's own "BSFR-SH" label picks out. `emit_fig4_5` draws two
versions of each chart — the paper's shape, and a second with the constant-classifier baseline as
a horizontal line — because the first version alone lets a F1 of 0.960 read as competitive when
it clears "predict nothing" by 0.013 (docs/PAPER_NOTES.md FLAW-1).

Every figure gets a sidecar JSON next to it (`docs/EXPERIMENTS.md`'s "Output contract"): config
hash, scheme, seed, host, CPU, wall time, git rev, taken from the run's own sidecar rather than
recomputed here.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.axes import Axes

from bsfr_sh.bench.harness import BenchPolicy, CaseResult
from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW

__all__ = [
    "PAPER_BSFR_SH_ROW",
    "PAPER_CASE_ORDER",
    "PAPER_TABLE2_ROWS",
    "PAPER_TIME_SECONDS",
    "PAPER_TPS",
    "PAPER_TX_COUNTS",
    "EmitReport",
    "emit_all",
    "emit_fig4_5",
    "emit_table2_honest_mode",
    "emit_table2_paper_mode",
]

#: docs/EXPERIMENTS.md Target 3 — Fig. 6(a)/(b), `{case: (BC_DTBU, BC_SigRW)}` seconds.
PAPER_TIME_SECONDS: dict[str, tuple[float, float]] = {
    "case_1": (3.10, 4.36),
    "case_2": (4.17, 5.54),
    "case_3": (5.71, 6.76),
}
#: docs/EXPERIMENTS.md Target 4 — Fig. 6(c)/(d), `{case: (BC_DTBU, BC_SigRW)}` TPS. Derived, not
#: independently published — `tx / seconds`, verified in EXPERIMENTS.md against all six points.
PAPER_TPS: dict[str, tuple[float, float]] = {
    case: (tx / t[0], tx / t[1])
    for case, t, tx in zip(
        ("case_1", "case_2", "case_3"),
        PAPER_TIME_SECONDS.values(),
        (500, 1000, 1500),
        strict=True,
    )
}
PAPER_TX_COUNTS: dict[str, int] = {"case_1": 500, "case_2": 1000, "case_3": 1500}
PAPER_CASE_ORDER: tuple[str, ...] = ("case_1", "case_2", "case_3")

_CHAIN_LABEL = {BC_DTBU: "BC_DTBU (backup)", BC_SigRW: "BC_SigRW (ransomware sig.)"}
#: A brand-neutral, colorblind-legible pair — measured vs. paper-reported are the only two
#: series any one axes ever needs to tell apart.
_COLOR_MEASURED = "#2f6fed"
_COLOR_PAPER = "#9aa5b1"
_COLOR_COMPONENT = ("#2f6fed", "#f2a541", "#7d5fd6", "#e0526b")


class EmitReport:
    """Paths written, for the caller to log or assert against in a test."""

    def __init__(self) -> None:
        self.figures: list[Path] = []
        self.tables: list[Path] = []
        self.sidecars: list[Path] = []


def _sidecar_for(run_meta: Mapping[str, Any], *, purpose: str) -> dict[str, Any]:
    return {
        "run_id": run_meta["run_id"],
        "purpose": purpose,
        "seed": run_meta["seed"],
        "config_hash": run_meta["config_hash"],
        "config_hash_scheme": run_meta["config_hash_scheme"],
        "git_rev": run_meta["git_rev"],
        "host": run_meta["host"],
        "started_at": run_meta["started_at"],
        "wall_seconds": run_meta["wall_seconds"],
    }


def _write_sidecar(path: Path, run_meta: Mapping[str, Any], *, purpose: str) -> Path:
    sidecar_path = path.with_suffix(path.suffix + ".json")
    sidecar_path.write_text(
        json.dumps(_sidecar_for(run_meta, purpose=purpose), indent=2, sort_keys=True, default=str)
        + "\n",
        encoding="utf-8",
    )
    return sidecar_path


def _style_axes(ax: Axes, *, title: str, ylabel: str, cases: Sequence[str]) -> None:
    ax.set_title(title, fontsize=11, loc="left")
    ax.set_ylabel(ylabel)
    ax.set_xticks(range(len(cases)))
    ax.set_xticklabels([c.replace("case_", "case ") for c in cases])
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)


def _fig_time_or_tps(
    matrix: Mapping[tuple[str, str], CaseResult],
    chain_name: str,
    *,
    cases: Sequence[str],
    metric: str,
    figures_dir: Path,
    run_meta: Mapping[str, Any],
    filename: str,
    fig_letter: str,
) -> tuple[Path, Path]:
    is_time = metric == "time"
    ours = [
        matrix[(case, chain_name)].median_total_seconds
        if is_time
        else matrix[(case, chain_name)].tps
        for case in cases
    ]
    errs = [matrix[(case, chain_name)].stdev_seconds if is_time else 0.0 for case in cases]
    chain_index = 0 if chain_name == BC_DTBU else 1
    paper = [(PAPER_TIME_SECONDS if is_time else PAPER_TPS)[case][chain_index] for case in cases]

    fig, ax = plt.subplots(figsize=(5.2, 3.6), dpi=150)
    x = range(len(cases))
    width = 0.36
    ax.bar(
        [i - width / 2 for i in x],
        ours,
        width=width,
        yerr=errs if is_time else None,
        capsize=3,
        color=_COLOR_MEASURED,
        label="ours (measured)",
    )
    ax.bar(
        [i + width / 2 for i in x],
        paper,
        width=width,
        color=_COLOR_PAPER,
        label="paper (reported)",
    )
    ylabel = "seconds (median, stdev)" if is_time else "transactions / second"
    _style_axes(
        ax,
        title=f"Fig. 6({fig_letter}) — {_CHAIN_LABEL[chain_name]}",
        ylabel=ylabel,
        cases=cases,
    )
    ax.legend(frameon=False, fontsize=8, loc="upper left")
    fig.tight_layout()

    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / filename
    fig.savefig(path)
    plt.close(fig)
    sidecar = _write_sidecar(
        path,
        run_meta,
        purpose=f"Fig. 6({fig_letter}) — {metric} — {chain_name}. Absolute seconds are not the "
        "reproduction target (DEV-13); trend and the paper-vs-ours ratio are.",
    )
    return path, sidecar


def _fig_component_breakdown(
    matrix: Mapping[tuple[str, str], CaseResult],
    policy: BenchPolicy,
    d3: Mapping[str, Mapping[str, float]],
    *,
    figures_dir: Path,
    run_meta: Mapping[str, Any],
) -> tuple[Path, Path]:
    """Our own panel: compute / modelled network / index / D3 for case-3, stacked, per chain.

    Never summed with the reproduction figures above — see the module docstring. The modelled
    network bar uses `configs/bench.yaml`'s declared illustrative delay
    (`network.modelled_delay_s`), stated in the caption; it is `computed`, not `measured`.
    """
    from bsfr_sh.bench.harness import modelled_network_seconds

    case = "case_3"
    blocks = policy.case_blocks[case]
    chains = policy.chains
    compute = [matrix[(case, c)].median_total_seconds for c in chains]
    network = [
        modelled_network_seconds(blocks=blocks, delay_s=policy.modelled_delay_s).total_seconds
        for _ in chains
    ]
    index = [matrix[(case, c)].index_seconds or 0.0 for c in chains]
    d3_seconds = [d3[c]["case3_total_seconds"] for c in chains]

    fig, ax = plt.subplots(figsize=(6.4, 4.0), dpi=150)
    x = range(len(chains))
    bottoms = [0.0] * len(chains)
    for values, color, label in zip(
        (compute, network, index, d3_seconds),
        _COLOR_COMPONENT,
        (
            "compute (measured)",
            f"modelled network (computed, {policy.modelled_delay_s * 1000:.0f} ms/hop)",
            "index construction (measured, BC_DTBU only)",
            "D3 serialization (computed, lower bound)",
        ),
        strict=True,
    ):
        ax.bar(list(x), values, bottom=bottoms, color=color, label=label, width=0.5)
        bottoms = [b + v for b, v in zip(bottoms, values, strict=True)]

    ax.set_title(
        "Component breakdown, case-3 — our own panel, not a paper comparison",
        fontsize=10.5,
        loc="left",
    )
    ax.set_ylabel("seconds")
    ax.set_xticks(list(x))
    ax.set_xticklabels([_CHAIN_LABEL[c] for c in chains])
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7, loc="upper left")
    fig.tight_layout()

    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig6e_component_breakdown.png"
    fig.savefig(path)
    plt.close(fig)
    sidecar = _write_sidecar(
        path,
        run_meta,
        purpose="Component breakdown (our addition, not in the paper): compute, modelled "
        "network, index construction, D3 serialization estimate for case-3. Never summed into "
        "a number comparable to Figs. 6(a)-(d).",
    )
    return path, sidecar


def _write_table_csv(
    matrix: Mapping[tuple[str, str], CaseResult], cases: Sequence[str], tables_dir: Path
) -> Path:
    tables_dir.mkdir(parents=True, exist_ok=True)
    path = tables_dir / "target3_target4.csv"
    rows = ["case,chain,blocks,transactions,seconds_measured,seconds_paper,tps_measured,tps_paper"]
    for case in cases:
        for chain, idx in ((BC_DTBU, 0), (BC_SigRW, 1)):
            r = matrix[(case, chain)]
            rows.append(
                f"{case},{chain},{r.blocks},{r.transaction_count},"
                f"{r.median_total_seconds:.5f},{PAPER_TIME_SECONDS[case][idx]:.2f},"
                f"{r.tps:.2f},{PAPER_TPS[case][idx]:.2f}"
            )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def emit_all(
    *,
    matrix: Mapping[tuple[str, str], CaseResult],
    policy: BenchPolicy,
    sidecar_meta: Mapping[str, Any],
    figures_dir: Path,
    tables_dir: Path,
) -> EmitReport:
    """Write Figs. 6(a)-(d), the component-breakdown panel, and the target3/4 table.

    `sidecar_meta` is the run's own sidecar dict (from `scripts/run_bench.py`, `run_id` field
    included) — figure sidecars borrow its `run_id`/`config_hash`/`seed`/`host`/`git_rev`/wall
    time rather than recomputing them, so a figure and the run that produced it are provably the
    same run.
    """
    report = EmitReport()
    cases = policy.cases
    specs = (
        (BC_DTBU, "time", "fig6a_time_backup.png", "a"),
        (BC_SigRW, "time", "fig6b_time_ransomware.png", "b"),
        (BC_DTBU, "tps", "fig6c_tps_backup.png", "c"),
        (BC_SigRW, "tps", "fig6d_tps_ransomware.png", "d"),
    )
    for chain_name, metric, filename, letter in specs:
        fig_path, sidecar_path = _fig_time_or_tps(
            matrix,
            chain_name,
            cases=cases,
            metric=metric,
            figures_dir=figures_dir,
            run_meta=sidecar_meta,
            filename=filename,
            fig_letter=letter,
        )
        report.figures.append(fig_path)
        report.sidecars.append(sidecar_path)

    d3 = sidecar_meta.get("d3", {})
    breakdown_path, breakdown_sidecar = _fig_component_breakdown(
        matrix, policy, d3, figures_dir=figures_dir, run_meta=sidecar_meta
    )
    report.figures.append(breakdown_path)
    report.sidecars.append(breakdown_sidecar)

    table_path = _write_table_csv(matrix, cases, tables_dir)
    report.tables.append(table_path)

    return report


# ==============================================================================================
# M6b — Table II (docs/EXPERIMENTS.md Target 1) and Figs. 4-5
# ==============================================================================================
#: Target 1 rows 1-4 — quoted from the source papers, on datasets this project has never touched
#: (DEV-07). `paper_reported`, never `measured`.
PAPER_TABLE2_ROWS: tuple[dict[str, object], ...] = (
    {
        "technique": "Almashhadani et al. [11]",
        "accuracy": 0.9708,
        "f1": 0.971,
        "dataset": "network traffic traces (Locky)",
    },
    {
        "technique": "Hwang et al. [12]",
        "accuracy": 0.9730,
        "f1": 0.973,
        "dataset": "dynamic analysis logs",
    },
    {
        "technique": "Sharmeen et al. [13]",
        "accuracy": 0.9596,
        "f1": 0.960,
        "dataset": "semi-supervised, own corpus",
    },
    {
        "technique": "Bae et al. [14]",
        "accuracy": 0.9865,
        "f1": 0.987,
        "dataset": "PE-file features",
    },
)
#: Target 1's headline row as published — the paper's own best of its four algorithms
#: (DecisionTree, per `RESULTS.md`'s `paper_reported` line). Quoted, not measured; every 90/10
#: resample of this dataset is bound at 46,014 rows by `paper_mode_arithmetic` regardless of
#: whether the paper states it (DEV-06).
PAPER_BSFR_SH_ROW: dict[str, object] = {
    "technique": "BSFR-SH (paper, best of 4: DecisionTree)",
    "accuracy": 0.9898,
    "f1": 0.990,
    "dataset": "BitcoinHeist addresses",
    "n": 46_014,
}


def emit_table2_paper_mode(paper_mode: Mapping[str, Any], *, tables_dir: Path) -> Path:
    """`results/tables/table2_paper_mode.csv` — the paper's table, plus the columns we owe it.

    Beyond `technique`/`accuracy`/`f1`: `dataset` (DEV-07), `n` (`unknown` for rows 1-4 — a
    dataset this project has never seen — `46,014` for both BSFR-SH rows, DEV-06), and
    `baseline_accuracy`/`baseline_f1` (the constant-positive score on *this* split — populated
    only where the split is known, never for rows 1-4). Every one of our own models is listed
    too, not only the `random_forest` row `docs/EXPERIMENTS.md` singles out as the reproduction
    figure — the paper names one number as "BSFR-SH"; this table does not have to.
    """
    n_ours = paper_mode["resample"]["n_rows"]
    baseline = paper_mode["baselines"]["constant_positive"]
    rows: list[dict[str, object]] = [
        {
            **row,
            "mode": "paper_reported",
            "n": "unknown",
            "baseline_accuracy": "",
            "baseline_f1": "",
        }
        for row in PAPER_TABLE2_ROWS
    ]
    rows.append(
        {
            **PAPER_BSFR_SH_ROW,
            "mode": "paper_reported",
            "baseline_accuracy": round(baseline["accuracy"], 4),
            "baseline_f1": round(baseline["f1"], 4),
        }
    )
    for name, row in paper_mode["models"].items():
        rows.append(
            {
                "technique": f"BSFR-SH (ours, {name})",
                "accuracy": round(row["accuracy"], 4),
                "f1": round(row["f1"], 4),
                "dataset": "BitcoinHeist addresses",
                "n": n_ours,
                "mode": "measured",
                "baseline_accuracy": round(baseline["accuracy"], 4),
                "baseline_f1": round(baseline["f1"], 4),
            }
        )

    tables_dir.mkdir(parents=True, exist_ok=True)
    path = tables_dir / "table2_paper_mode.csv"
    fields = [
        "technique",
        "mode",
        "accuracy",
        "f1",
        "dataset",
        "n",
        "baseline_accuracy",
        "baseline_f1",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return path


def emit_table2_honest_mode(honest_mode: Mapping[str, Any], *, tables_dir: Path) -> Path:
    """`results/tables/table2_honest_mode.csv` — ours only; the paper reports no honest_mode.

    Balanced accuracy, precision, recall, MCC, PR-AUC, minority-F1 and the full confusion matrix
    per model, with the constant-negative baseline as its own row. Balanced accuracy is not a
    field of `HonestMetrics` — `detection.metrics`'s module docstring says accuracy is
    deliberately absent there — but it is exactly the mean of the two per-class recalls, so it is
    recovered from the confusion matrix here rather than anything being re-fit.
    """

    def _row(label: str, mode: str, m: Mapping[str, Any], n: object) -> dict[str, object]:
        confusion = m["confusion"]
        tn, fp, fn, tp = confusion["tn"], confusion["fp"], confusion["fn"], confusion["tp"]
        sensitivity = tp / (tp + fn) if (tp + fn) else 0.0
        specificity = tn / (tn + fp) if (tn + fp) else 0.0
        return {
            "model": label,
            "mode": mode,
            "n": n,
            "balanced_accuracy": round((sensitivity + specificity) / 2, 4),
            "precision": round(m["precision"], 4),
            "recall": round(m["recall"], 4),
            "mcc": round(m["mcc"], 4),
            "pr_auc": round(m["pr_auc"], 4),
            "f1_minority": round(m["f1_minority"], 4),
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        }

    rows = [
        _row(
            f"{name}{' (subsampled)' if row.get('subsampled_for_memory') else ''}",
            "measured",
            row,
            row["n_rows"],
        )
        for name, row in honest_mode["models"].items()
    ]
    rows.append(
        _row(
            "constant-negative baseline",
            "computed",
            honest_mode["baselines"]["constant_negative"],
            honest_mode["n_rows"],
        )
    )
    for name in honest_mode.get("deferred", {}):
        rows.append(
            {
                "model": name,
                "mode": "deferred",
                "n": "—",
                "balanced_accuracy": "",
                "precision": "",
                "recall": "",
                "mcc": "",
                "pr_auc": "",
                "f1_minority": "",
                "tn": "",
                "fp": "",
                "fn": "",
                "tp": "",
            }
        )

    tables_dir.mkdir(parents=True, exist_ok=True)
    path = tables_dir / "table2_honest_mode.csv"
    fields = [
        "model",
        "mode",
        "n",
        "balanced_accuracy",
        "precision",
        "recall",
        "mcc",
        "pr_auc",
        "f1_minority",
        "tn",
        "fp",
        "fn",
        "tp",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _fig4_or_5(
    paper_mode: Mapping[str, Any],
    *,
    metric: str,
    with_baseline: bool,
    figures_dir: Path,
    run_meta: Mapping[str, Any],
    filename: str,
    fig_number: str,
) -> tuple[Path, Path]:
    labels = [str(row["technique"]) for row in PAPER_TABLE2_ROWS] + [
        "BSFR-SH\n(paper)",
        "BSFR-SH\n(ours, RF)",
    ]
    values = [float(cast(float, row[metric])) for row in PAPER_TABLE2_ROWS] + [
        float(cast(float, PAPER_BSFR_SH_ROW[metric])),
        float(paper_mode["models"]["random_forest"][metric]),
    ]
    colors = [_COLOR_PAPER] * (len(PAPER_TABLE2_ROWS) + 1) + [_COLOR_MEASURED]
    ylabel = "accuracy" if metric == "accuracy" else "F1"

    fig, ax = plt.subplots(figsize=(7.4, 4.4), dpi=150)
    x = range(len(labels))
    ax.bar(list(x), values, color=colors, width=0.6)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=8)
    ax.set_ylim(0.0, 1.08)
    suffix = " — baseline annotated" if with_baseline else ""
    ax.set_title(f"Fig. {fig_number} — {ylabel} across techniques{suffix}", fontsize=11, loc="left")
    ax.set_ylabel(ylabel)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)

    purpose = (
        f"Fig. {fig_number} ({ylabel}), reproduced paper shape. Rows 1-4 and the paper's "
        "BSFR-SH row are paper_reported on unrelated datasets (DEV-07); only 'ours' is measured."
    )
    if with_baseline:
        baseline = float(paper_mode["baselines"]["constant_positive"][metric])
        ax.axhline(
            baseline,
            color="#e0526b",
            linestyle="--",
            linewidth=1.5,
            label=f"constant-positive baseline ({baseline:.3f})",
        )
        ax.legend(frameon=False, fontsize=8, loc="lower right")
        purpose += (
            f" Baseline line added: a classifier that answers 'ransomware' to everything scores "
            f"{baseline:.3f} on this split without looking at the data."
        )
    fig.tight_layout()

    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / filename
    fig.savefig(path)
    plt.close(fig)
    sidecar = _write_sidecar(path, run_meta, purpose=purpose)
    return path, sidecar


def emit_fig4_5(
    paper_mode: Mapping[str, Any], *, figures_dir: Path, run_meta: Mapping[str, Any]
) -> EmitReport:
    """Figs. 4-5: paper-shape accuracy/F1 bar charts, each also emitted with a baseline line.

    The baseline version is the one that makes the result legible (M6b session brief): without
    it, Sharmeen et al.'s published 0.960 F1 reads as a competitive prior technique when it
    clears "predict nothing" by 0.013 (docs/PAPER_NOTES.md FLAW-1, `docs/EXPERIMENTS.md` Target 1).
    """
    report = EmitReport()
    specs = (
        ("accuracy", "4", "fig4_accuracy"),
        ("f1", "5", "fig5_f1"),
    )
    for metric, number, stem in specs:
        for with_baseline, suffix in ((False, ""), (True, "_baseline")):
            path, sidecar = _fig4_or_5(
                paper_mode,
                metric=metric,
                with_baseline=with_baseline,
                figures_dir=figures_dir,
                run_meta=run_meta,
                filename=f"{stem}{suffix}.png",
                fig_number=number,
            )
            report.figures.append(path)
            report.sidecars.append(sidecar)
    return report
