"""Phase 2 figures for P2-B and P2-C, drawn from the CSVs their scripts wrote (no recomputation).

P2-A and P2-D draw their own figures inside their scripts.

Usage::

    python scripts/p2_figures.py
"""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
TABLES = REPO_ROOT / "results" / "tables"
FIGS = REPO_ROOT / "results" / "figures"

OURS = "#1f4e9c"  # blue: our measurement
PAPER = "#b22222"  # red: the paper / the "before" state
REF = "#8a8a8a"  # neutral reference line (chance, constant baseline)
INK = "#222222"
MUTED = "#555555"

plt.rcParams.update(
    {
        "font.size": 10,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.edgecolor": "#999999",
        "axes.labelcolor": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
    }
)


def _read(name: str) -> list[dict[str, str]]:
    with (TABLES / name).open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def fig_p2b() -> None:
    """Balanced accuracy before/after log+scale, paper 90/10 setting. 0.5 = no better than chance."""
    rows = {(r["model"], r["variant"]): r for r in _read("p2b_fair_models.csv")
            if r["part"] == "paper"}  # fmt: skip
    models = [("k_nearest_neighbours", "KNN"), ("logistic_regression", "Logistic regression"),
              ("decision_tree", "Decision tree"), ("random_forest", "Random forest")]  # fmt: skip
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    for i, (key, label) in enumerate(models):
        before = float(rows[(key, "raw")]["balanced_accuracy_mean"])
        after = float(rows[(key, "log_scaled")]["balanced_accuracy_mean"])
        ax.plot([before, after], [i, i], color="#bbbbbb", lw=2, zorder=1)
        ax.scatter([before], [i], s=70, color=PAPER, zorder=3, edgecolor="white", linewidth=2)
        ax.scatter([after], [i], s=70, color=OURS, zorder=3, edgecolor="white", linewidth=2)
        dx = after - before
        note = f"{before:.2f} → {after:.2f}" if abs(dx) > 0.01 else f"{after:.2f} (unchanged)"
        ax.text(max(before, after) + 0.012, i, note, va="center", fontsize=9, color=INK)
    ax.axvline(0.5, color=REF, ls="--", lw=1)
    ax.text(0.5, len(models) - 0.45, "chance (0.5)", color=MUTED, fontsize=8, ha="center")
    ax.set_yticks(range(len(models)), [m[1] for m in models])
    ax.set_xlim(0.45, 0.92)
    ax.set_ylim(-0.6, len(models) - 0.3)
    ax.set_xlabel("balanced accuracy (paper's 90/10 data, 5 seeds)")
    ax.scatter([], [], s=50, color=PAPER, label="Phase 1: raw features")
    ax.scatter([], [], s=50, color=OURS, label="Phase 2: log + standardised")
    ax.legend(loc="center", bbox_to_anchor=(0.55, 0.49), fontsize=8, frameon=False)
    ax.set_title("Feature scaling rescues KNN, not logistic regression", loc="left", fontsize=11)
    fig.tight_layout()
    fig.savefig(FIGS / "p2b_fair_models.png", dpi=170)


def fig_p2c() -> None:
    """RF accuracy: random split vs future-years split, with the always-'ransomware' baseline."""
    rows = {(r["split"], r["features"], r["model"]): r for r in _read("p2c_year_shortcut.csv")}
    feature_sets = [("all8", "All 8 features"), ("no_year", "Without year"),
                    ("year_only", "Year only")]  # fmt: skip
    splits = [("grouped_random", "Random split (Phase 1 / paper style)"),
              ("temporal_le2015", "Train 2011–15, test 2016–18")]  # fmt: skip
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8), sharey=True)
    for ax, (split, title) in zip(axes, splits, strict=True):
        vals = [float(rows[(split, fs, "random_forest")]["accuracy_mean"]) * 100
                for fs, _ in feature_sets]  # fmt: skip
        base = float(rows[(split, "all8", "random_forest")]["constant_positive_accuracy_mean"]) * 100
        bars = ax.bar(range(3), vals, width=0.55, color=OURS, edgecolor="white", linewidth=2)
        for b, v in zip(bars, vals, strict=True):
            ax.text(b.get_x() + b.get_width() / 2, v - 3, f"{v:.1f}%", ha="center", va="top",
                    fontsize=10, color="white", fontweight="bold")  # fmt: skip
        ax.axhline(base, color=REF, ls="--", lw=1.2,
                   label=f"always say 'ransomware' = {base:.1f}%")  # fmt: skip
        ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.0), fontsize=8, frameon=False)
        ax.set_xticks(range(3), [f[1] for f in feature_sets])
        ax.set_title(title, fontsize=10, loc="left")
        ax.set_ylim(0, 112)
    axes[0].set_ylabel("accuracy, random forest (%)")
    fig.suptitle("The detector learns which years had ransomware, so it fails on new years",
                 x=0.01, ha="left", fontsize=11)  # fmt: skip
    fig.tight_layout()
    fig.savefig(FIGS / "p2c_year_shortcut.png", dpi=170)


def fig_p2e() -> None:
    """Balanced accuracy per test year: deploy-once vs retrain-yearly vs same-year reference."""
    rows = {(int(r["test_year"]), r["strategy"]): r for r in _read("p2e_yearly_retraining.csv")
            if r["features"] == "no_year"}  # fmt: skip
    years = sorted({y for y, _ in rows})
    series = [
        ("same_year", "if next year looked like this year\n(random split, reference)", REF, "--", 0),
        ("expanding", "retrained every year", OURS, "-", -0.018),
        ("static", "trained once (2011–13)", PAPER, "-", 0.018),
    ]
    fig, ax = plt.subplots(figsize=(8.4, 3.9))
    for key, label, color, ls, dy in series:
        vals = [float(rows[(y, key)]["balanced_accuracy_mean"]) for y in years]
        ax.plot(years, vals, color=color, ls=ls, lw=2, marker="o", markersize=8,
                markeredgecolor="white", markeredgewidth=2, zorder=3)  # fmt: skip
        ax.text(years[-1] + 0.12, vals[-1] + dy, label, va="center", fontsize=8.5, color=INK)
    ax.axhline(0.5, color=REF, ls=":", lw=1)
    ax.text(years[0] - 0.1, 0.505, "chance (0.5)", color=MUTED, fontsize=8, va="bottom")
    ax.set_xticks(years, [str(y) for y in years])
    ax.set_xlim(years[0] - 0.2, years[-1] + 1.55)
    ax.set_ylim(0.4, 0.88)
    ax.set_xlabel("test year (solid lines: model trained only on earlier years)")
    ax.set_ylabel("balanced accuracy, random forest")
    ax.set_title("Retraining every year does not rescue the detector", loc="left", fontsize=11)
    fig.tight_layout()
    fig.savefig(FIGS / "p2e_yearly_retraining.png", dpi=170)


def fig_p2g() -> None:
    """Slow-burn ransomware: share of restored files still encrypted, and files lost before alarm."""
    rows = _read("p2g_slow_burn_timeline.csv")

    def cell(style: str, days: int, policy: str, level: str) -> dict[str, str]:
        return next(r for r in rows if (r["style"], int(r["slow_burn_days"]), r["policy"],
                                        r["level"]) == (style, days, policy, level))  # fmt: skip

    days = sorted({int(r["slow_burn_days"]) for r in rows})
    fig, (ax, bx) = plt.subplots(1, 2, figsize=(11, 4.0), gridspec_kw={"width_ratios": [1.25, 1]})
    series = [
        ("full", "paper_newest", "none", PAPER, "-", "paper: restore newest backup"),
        ("full", "restore_time_screening", "HISTORY", OURS, "-", "with screening (either kind)"),
        ("stripes_10pct_office_only", "backup_time_screening", "HISTORY", REF, "--",
         "with screening, attacker hits\nonly office docs (blind spot)"),
    ]  # fmt: skip
    offsets: dict[str, float] = {}
    for style, policy, level, color, ls, label in series:
        vals = [float(cell(style, d, policy, level)["damaged_share_mean"]) * 100 for d in days]
        ax.plot(days, vals, color=color, ls=ls, lw=2, marker="o", markersize=7,
                markeredgecolor="white", markeredgewidth=1.5, zorder=3)  # fmt: skip
        ax.text(days[-1] + 0.4, vals[-1] + offsets.get(label, 0), label, va="center",
                fontsize=8.5, color=INK)  # fmt: skip
    ax.set_xticks(days, [str(d) for d in days])
    ax.set_xlim(-0.5, days[-1] + 7.5)
    ax.set_ylim(-4, 100)
    ax.set_xlabel("days the ransomware spends encrypting before the ransom note")
    ax.set_ylabel("restored files that are still encrypted (%)")
    ax.set_title("Recovery restores the ransomware's own output", loc="left", fontsize=11)

    d7 = [("paper:\nrestore newest", cell("full", 7, "paper_newest", "none"), PAPER),
          ("screen at\nrestore time", cell("full", 7, "restore_time_screening", "HISTORY"), OURS),
          ("screen at\nbackup time", cell("full", 7, "backup_time_screening", "HISTORY"), OURS)]  # fmt: skip
    ys = range(len(d7))
    vals = [float(c["files_encrypted_mean"]) for _, c, _ in d7]
    bx.barh(list(ys), vals, color=[c for _, _, c in d7], height=0.55, edgecolor="white")
    for y, (_, c, _), v in zip(ys, d7, vals, strict=True):
        lost = float(c["damaged_share_mean"]) * 100
        back = float(c["days_rolled_back_mean"])
        bx.text(v + 1.2, y, f"{v:.0f} files encrypted\n{lost:.0f}% of restore still encrypted\n"
                f"{back:.0f} days of work rolled back", va="center", fontsize=8, color=INK)  # fmt: skip
    bx.set_yticks(list(ys), [n for n, _, _ in d7], fontsize=9)
    bx.invert_yaxis()
    bx.set_xlim(0, 100)
    bx.set_xlabel("files encrypted before it was stopped (7-day attack)")
    bx.set_title("Screening at backup time is also an early alarm", loc="left", fontsize=11)
    fig.tight_layout()
    fig.savefig(FIGS / "p2g_slow_burn_backups.png", dpi=170)


if __name__ == "__main__":
    fig_p2b()
    fig_p2c()
    fig_p2e()
    fig_p2g()
