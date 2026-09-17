"""M6a — Figs. 6(a)-(d) and the component-breakdown panel, from `bench.harness`'s output.

Two artifacts, not one (module docstring of `bench/harness.py`, and the M6a session brief):

* **The reproduction figures**, Figs. 6(a)-(d): our measured median seconds/TPS per case,
  plotted against the paper's own six numbers (`docs/EXPERIMENTS.md` Target 3/4), so a reader
  can see the shape comparison the reproduction claim is actually about (DEV-13 — trend and
  ratio, not absolute seconds).
* **The component-breakdown panel**, our own addition (not in the paper, not compared against
  it): compute, modelled network, index construction and D3's serialization estimate for case-3,
  as separate bars. Summing them into the reproduction figures above would make a `computed`
  number look like a `measured` one — see `bench/harness.py`'s module docstring.

Every figure gets a sidecar JSON next to it (`docs/EXPERIMENTS.md`'s "Output contract"): config
hash, scheme, seed, host, CPU, wall time, git rev, taken from the run's own sidecar rather than
recomputed here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.axes import Axes

from bsfr_sh.bench.harness import BenchPolicy, CaseResult
from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW

__all__ = [
    "PAPER_CASE_ORDER",
    "PAPER_TIME_SECONDS",
    "PAPER_TPS",
    "PAPER_TX_COUNTS",
    "EmitReport",
    "emit_all",
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
