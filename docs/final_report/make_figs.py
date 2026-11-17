"""Paper-sized figures for the final report, drawn from the committed result tables (no recomputation)."""
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
T = ROOT / "results" / "tables"
OUT = Path(__file__).resolve().parent / "figs"
RED, BLUE, GREY, INK = "#b22222", "#1f4e9c", "#8a8a8a", "#222222"
plt.rcParams.update({"font.size": 7.5, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.edgecolor": "#999999", "legend.frameon": False, "legend.fontsize": 6.8,
                     "axes.titlesize": 7.5, "axes.titlelocation": "left"})
W, H = 3.25, 2.05


def rows(name):
    with (T / name).open() as f:
        return list(csv.DictReader(f))


def save(fig, name):
    fig.tight_layout(pad=0.3)
    fig.savefig(OUT / name, dpi=300)
    plt.close(fig)


# A ---------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(W, H))
x = [5, 10, 15]
for vals, lab, c, ls in [([161, 240, 263], "paper, backup chain", RED, "-"),
                         ([115, 181, 222], "paper, signature chain", RED, "--"),
                         ([771, 859, 883], "ours, whole-program timer", BLUE, "-"),
                         ([1130, 1156, 1147], "ours, per-block timer", GREY, ":")]:
    ax.plot(x, [v / vals[0] for v in vals], color=c, ls=ls, marker="o", ms=3.5, lw=1.4, label=lab)
ax.set_xticks(x)
ax.set_xlabel("blocks committed (paper's cases 1-3)")
ax.set_ylabel("TPS relative to 5 blocks")
ax.legend(loc="upper left")
ax.grid(axis="y", alpha=0.3)
save(fig, "r_tps.png")

# C ---------------------------------------------------------------------------
c = {(r["split"], r["features"], r["model"]): r for r in rows("p2c_year_shortcut.csv")}
fig, ax = plt.subplots(figsize=(W, H + 0.15))
fs = [("all8", "all 8"), ("no_year", "no year"), ("year_only", "year only")]
for k, (split, lab, col) in enumerate([("grouped_random", "random split", GREY),
                                       ("temporal_le2015", "train 2011-15, test 2016-18", RED)]):
    v = [float(c[(split, f, "random_forest")]["accuracy_mean"]) * 100 for f, _ in fs]
    xs = [i + (k - 0.5) * 0.38 for i in range(3)]
    ax.bar(xs, v, 0.36, color=col, label=lab)
    for xx, vv in zip(xs, v):
        ax.text(xx, vv - 3, f"{vv:.1f}", ha="center", va="top", fontsize=6.3, color="white", weight="bold")
ax.axhline(91.8, color=INK, lw=0.8, ls="--", label="always 'ransomware' on 2016-18 (91.8)")
ax.set_xticks(range(3), [l for _, l in fs])
ax.set_ylim(0, 100)
ax.set_ylabel("random forest accuracy (%)")
ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=1, fontsize=6.3)
save(fig, "r_year.png")

# E ---------------------------------------------------------------------------
e = {(int(r["test_year"]), r["strategy"]): r for r in rows("p2e_yearly_retraining.csv") if r["features"] == "no_year"}
yrs = [2014, 2015, 2016, 2017]
fig, ax = plt.subplots(figsize=(W, H))
for key, lab, col, ls in [("same_year", "reference: random split within the year", GREY, "--"),
                          ("expanding", "retrained every year", BLUE, "-"),
                          ("static", "trained once (2011-13)", RED, "-")]:
    ax.plot(yrs, [float(e[(y, key)]["balanced_accuracy_mean"]) for y in yrs], color=col, ls=ls, marker="o", ms=3.5, lw=1.4, label=lab)
ax.axhline(0.5, color=GREY, lw=0.7, ls=":")
ax.set_xticks(yrs)
ax.set_ylim(0.35, 1.12)
ax.set_xlabel("test year (trained only on earlier years)")
ax.set_ylabel("balanced accuracy")
ax.legend(loc="upper left")
save(fig, "r_retrain.png")

# F ---------------------------------------------------------------------------
labels = ["one key\nholder", "key copied\nto all 4", "split\n2 of 4", "split\n3 of 4", "split\n4 of 4"]
lose, leak = [1, 4, 3, 2, 1], [1, 1, 2, 3, 4]
fig, ax = plt.subplots(figsize=(W, H))
xs = range(5)
ax.bar([i - 0.18 for i in xs], lose, 0.34, color=BLUE, label="servers lost before backups are gone")
ax.bar([i + 0.18 for i in xs], leak, 0.34, color=RED, label="servers stolen before backups leak")
ax.set_xticks(list(xs), labels, fontsize=6.5)
ax.set_yticks(range(5))
ax.set_ylim(0, 5.6)
ax.set_ylabel("servers out of 4 (higher = safer)")
ax.legend(loc="upper left")
save(fig, "r_keys.png")

# G ---------------------------------------------------------------------------
g = rows("p2g_slow_burn_timeline.csv")
def gv(style, pol, lev):
    rr = sorted((r for r in g if (r["style"], r["policy"], r["level"]) == (style, pol, lev)), key=lambda r: int(r["slow_burn_days"]))
    return [int(r["slow_burn_days"]) for r in rr], [float(r["damaged_share_mean"]) * 100 for r in rr]
fig, ax = plt.subplots(figsize=(W, H))
for (style, pol, lev), lab, col, ls in [(("full", "paper_newest", "none"), "paper: restore newest backup", RED, "-"),
                                         (("stripes_10pct_office_only", "backup_time_screening", "HISTORY"), "screened, attacker hits only office docs", GREY, "--"),
                                         (("full", "restore_time_screening", "HISTORY"), "screened restore", BLUE, "-")]:
    d, v = gv(style, pol, lev)
    ax.plot(d, v, color=col, ls=ls, marker="o", ms=3.5, lw=1.4, label=lab)
ax.set_xticks([0, 1, 3, 7, 14])
ax.set_ylim(-3, 100)
ax.set_xlabel("days spent encrypting before the ransom note")
ax.set_ylabel("restored files still encrypted (%)")
ax.legend(loc="center right")
save(fig, "r_slowburn.png")
print("ok")
