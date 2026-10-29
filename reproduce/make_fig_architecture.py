"""Architecture figure (Fig. 2) for the leakdepth paper; same palette and card style as the workflow figure (Fig. 1).
All shapes are drawn here from basic vector primitives. Usage: python make_fig_architecture.py OUT_DIR"""
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle, FancyArrowPatch

INK, MUTED = "#1f2933", "#52606d"
BLUE, TEAL, GREEN, AMBER, RED, VIOLET, GRAY = "#1d4e89", "#0f7c8c", "#2e8540", "#d98c00", "#c0392b", "#6b4c9a", "#9aa5b1"
plt.rcParams.update({"font.family": "DejaVu Sans", "pdf.fonttype": 42})
W, H = 26.0, 14.2
fig = plt.figure(figsize=(7.0, 7.0 * H / W))
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")


def box(x, y, w, h, col, title, lines=(), fill="white", dashed=False, tsize=10.2, lsize=8.6, head=True):
    ls = (0, (4, 2.5)) if dashed else "solid"
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.3", fc=fill, ec=col, lw=1.8, ls=ls))
    if head:
        ax.add_patch(FancyBboxPatch((x, y + h - 0.95), w, 0.95, boxstyle="round,pad=0.02,rounding_size=0.3", fc=col, ec=col, lw=1.8, ls=ls))
        ax.add_patch(Rectangle((x, y + h - 0.95), w, 0.4, fc=col, ec=col))
        ax.text(x + w / 2, y + h - 0.48, title, ha="center", va="center", color="white", fontsize=tsize, fontweight="bold")
        top = y + h - 1.45
    else:
        ax.text(x + w / 2, y + h - 0.5, title, ha="center", va="center", color=col, fontsize=tsize, fontweight="bold")
        top = y + h - 1.15
    for i, t in enumerate(lines):
        ax.text(x + w / 2, top - i * 0.62, t, ha="center", va="center", color=INK, fontsize=lsize)


def arrow(p0, p1, col=MUTED, lw=1.8, ls="solid", rad=0.0, label=None, loff=(0, 0.28)):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle="-|>", mutation_scale=13, lw=lw, color=col, ls=ls,
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=2, shrinkB=2))
    if label:
        ax.text((p0[0] + p1[0]) / 2 + loff[0], (p0[1] + p1[1]) / 2 + loff[1], label, ha="center", va="center",
                fontsize=7.8, color=MUTED, family="DejaVu Sans Mono")


# column headers
for x, t in [(2.75, "INPUTS"), (12.45, "leakdepth PACKAGE"), (22.7, "OUTPUTS")]:
    ax.text(x, H - 0.45, t, ha="center", va="center", fontsize=9, color=MUTED, fontweight="bold")

# package frame
ax.add_patch(FancyBboxPatch((5.9, 2.75), 13.1, 10.45, boxstyle="round,pad=0.02,rounding_size=0.4", fc="#f5f7fa", ec=GRAY, lw=1.2))

# inputs
box(0.3, 9.6, 4.9, 3.5, BLUE, "Flow tables", ["CSV / Parquet", "train, test,", "or two corpora"])
box(0.3, 6.55, 4.9, 2.55, VIOLET, "inject", ["synthetic tables", "+ ground truth"])
box(0.3, 2.75, 4.9, 3.3, BLUE, "Profiles", ["column maps", "opt-in transforms", "(recorded)"])

# core: table and units
box(6.5, 9.75, 5.6, 2.95, TEAL, "FlowTable", ["data frame +", "ColumnMap", "of column roles"])
box(12.8, 9.75, 5.6, 2.95, TEAL, "groups registry", ["row · dup · 5-tuple", "host pair · session:g", "capture · custom"], lsize=8.4)

# analyses
box(6.5, 4.75, 3.85, 4.25, AMBER, "lineage", ["align columns", "match rows", "containment C"], dashed=True, lsize=8.0)
ax.text(8.42, 5.75, "a screen, not a", ha="center", va="center", fontsize=7.2, color=AMBER, style="italic")
ax.text(8.42, 5.32, "provenance test", ha="center", va="center", fontsize=7.2, color=AMBER, style="italic")
box(10.6, 5.2, 3.85, 3.8, GREEN, "audit", ["per-unit overlap", "split validity", "capture checks"], lsize=8.2)
box(14.7, 5.2, 3.85, 3.8, GREEN, "sensitivity", ["group splits", "Δ vs composition", "controls", "seed intervals"], lsize=8.0)

# report object
box(6.5, 2.75, 12.0, 1.9, INK, "Report", ["findings with severity · results · input hashes · config"], tsize=9.0, lsize=7.6)

# outputs
box(20.2, 2.75, 5.3, 3.6, INK, "Report files", ["audit.json", "report.md"])
box(20.2, 7.35, 5.3, 4.85, RED, "gate", [])
for i, (code, lab, c) in enumerate([("0", "pass", GREEN), ("1", "failing finding", RED), ("2", "usage error", GRAY), ("3", "input error", GRAY)]):
    yy = 10.75 - i * 0.74
    ax.add_patch(FancyBboxPatch((20.7, yy - 0.26), 0.62, 0.52, boxstyle="round,pad=0.01,rounding_size=0.15", fc=c, ec="none"))
    ax.text(21.01, yy, code, ha="center", va="center", fontsize=8.6, color="white", fontweight="bold")
    ax.text(21.55, yy, lab, ha="left", va="center", fontsize=8.2, color=INK)
ax.text(22.85, 7.65, "process exit code", ha="center", va="center", fontsize=7.4, color=MUTED)

# arrows
arrow((5.2, 11.3), (6.5, 11.3))
arrow((2.75, 9.1), (2.75, 9.6), col=VIOLET)
arrow((5.2, 4.6), (6.5, 10.0), rad=-0.12)
arrow((12.1, 11.3), (12.8, 11.3))
arrow((14.4, 9.75), (12.52, 9.0))
arrow((16.8, 9.75), (16.62, 9.0))
arrow((8.42, 9.75), (8.42, 9.0), ls=(0, (4, 2.5)), col=AMBER)
for xc in (12.52, 16.62):
    arrow((xc, 5.2), (xc, 4.65))
arrow((8.42, 4.75), (8.42, 4.65), col=AMBER)
arrow((18.5, 3.7), (20.2, 3.7))
arrow((22.85, 6.35), (22.85, 7.35))

# CLI strip and bench harness
ax.add_patch(FancyBboxPatch((5.9, 0.3), 13.1, 1.75, boxstyle="round,pad=0.02,rounding_size=0.3", fc="white", ec=INK, lw=1.2))
ax.text(12.45, 1.45, "command line", ha="center", va="center", fontsize=8.2, color=MUTED)
ax.text(12.45, 0.85, "leakdepth audit | sensitivity | lineage | gate", ha="center", va="center", fontsize=8.8, color=INK,
        family="DejaVu Sans Mono")
ax.add_patch(FancyBboxPatch((0.3, 0.3), 4.9, 1.75, boxstyle="round,pad=0.02,rounding_size=0.3", fc="white", ec=VIOLET, lw=1.4,
                            ls=(0, (4, 2.5))))
ax.text(2.75, 1.45, "bench/ harness", ha="center", va="center", fontsize=8.6, color=VIOLET, fontweight="bold")
ax.text(2.75, 0.85, "runs other tools", ha="center", va="center", fontsize=7.6, color=INK)
ax.add_patch(FancyBboxPatch((20.2, 0.3), 5.3, 1.75, boxstyle="round,pad=0.02,rounding_size=0.3", fc="white", ec=GRAY, lw=1.2,
                            ls=(0, (4, 2.5))))
ax.text(22.85, 1.45, "not installed:", ha="center", va="center", fontsize=7.6, color=MUTED)
ax.text(22.85, 0.85, "bench/, reproduce/", ha="center", va="center", fontsize=7.6, color=MUTED)

out = sys.argv[1] if len(sys.argv) > 1 else "."
fig.savefig(f"{out}/fig_architecture.pdf")
fig.savefig(f"{out}/fig_architecture.png", dpi=220)
print("saved")
