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


if __name__ == "__main__":
    fig_p2b()
    fig_p2c()
