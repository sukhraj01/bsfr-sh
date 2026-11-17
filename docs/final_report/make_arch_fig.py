"""Architecture diagram for the final report. Run from the repo root."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

RED, BLUE, INK, MUTED = "#b22222", "#1f4e9c", "#1f2937", "#6b7280"
fig, ax = plt.subplots(figsize=(7.0, 2.9))
ax.set_xlim(0, 14); ax.set_ylim(0, 6); ax.axis("off")

def box(x, y, w, h, title, sub, fc="#ffffff", ec="#9ca3af", tc=INK):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.18", fc=fc, ec=ec, lw=1.2))
    ax.text(x + w/2, y + h*0.64, title, ha="center", va="center", fontsize=9, weight="bold", color=tc)
    ax.text(x + w/2, y + h*0.30, sub, ha="center", va="center", fontsize=7.2, color=INK)

def arrow(x1, y1, x2, y2, label=None, lx=None, ly=None, ha="center"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=10, lw=1.1, color="#4b5563"))
    if label:
        ax.text(lx if lx is not None else (x1+x2)/2, ly if ly is not None else (y1+y2)/2 + 0.22, label,
                ha=ha, va="bottom", fontsize=7, color=MUTED)

box(0.05, 3.6, 2.75, 1.5, "Hospital system", "SYS$_i$, patient data")
box(0.05, 0.6, 2.75, 1.5, "Honeypot", "HP$_{RW}$, lures ransomware")
box(3.6, 3.45, 3.0, 1.8, "BC$_{DTBU}$", "backup chain\n4 servers, pBFT ($f=1$)", fc="#e8eef8", ec=BLUE, tc=BLUE)
box(3.6, 0.45, 3.0, 1.8, "BC$_{SigRW}$", "signature chain\n4 servers, pBFT ($f=1$)", fc="#fbecec", ec=RED, tc=RED)
box(7.75, 0.6, 2.6, 1.5, "Detection", "RF, DT, KNN, LR\n(BitcoinHeist)")
box(11.3, 0.6, 2.6, 1.5, "Mitigation", "isolate, then wipe,\nrestore or pay*")
box(11.3, 3.6, 2.6, 1.5, "Recovery", "newest backup\nback to SYS$_i$")
arrow(2.8, 4.35, 3.6, 4.35, "Alg. 1", ly=4.45)
arrow(2.8, 1.35, 3.6, 1.35, "Alg. 2", ly=1.45)
arrow(6.6, 1.35, 7.75, 1.35, "Alg. 3", ly=1.45)
arrow(10.35, 1.35, 11.3, 1.35, "Alg. 4", ly=1.45)
arrow(6.6, 4.35, 11.3, 4.35, "Alg. 5: read + decrypt newest backup", ly=4.45)
arrow(12.6, 2.1, 12.6, 3.6, "Case 2", lx=12.75, ly=2.7, ha="left")
ax.text(5.1, 2.85, "separate genesis blocks\nand server sets", ha="center", va="center", fontsize=7, style="italic", color=MUTED)
fig.tight_layout(pad=0.2)
fig.savefig("docs/final_report/figs/architecture.png", dpi=300)
