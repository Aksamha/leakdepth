"""Workflow figure (Fig. 1) for the leakdepth paper. All icons are drawn here from basic vector shapes (no external icons)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle, Circle, Ellipse, Polygon, FancyArrowPatch, Arc
from matplotlib.lines import Line2D

INK, MUTED, BG = "#1f2933", "#52606d", "#ffffff"
BLUE, TEAL, GREEN, AMBER, RED, VIOLET, GRAY = "#1d4e89", "#0f7c8c", "#2e8540", "#d98c00", "#c0392b", "#6b4c9a", "#9aa5b1"
plt.rcParams.update({"font.family": "DejaVu Sans"})
W, H = 26.0, 17.0
fig = plt.figure(figsize=(7.0, 7.0 * H / W))
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")

def card(x, y, w, h, col, title, lines):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.35", fc="white", ec=col, lw=2.0))
    ax.add_patch(FancyBboxPatch((x, y + h - 1.15), w, 1.15, boxstyle="round,pad=0.02,rounding_size=0.35", fc=col, ec=col, lw=2.0))
    ax.add_patch(Rectangle((x, y + h - 1.15), w, 0.45, fc=col, ec=col))
    ax.text(x + w / 2, y + h - 0.58, title, ha="center", va="center", color="white", fontsize=12, fontweight="bold")
    for i, t in enumerate(lines):
        ax.text(x + 5.0, y + h - 2.0 - i * 0.85, t, ha="left", va="center", color=INK, fontsize=9.6)

def arrow(p0, p1):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle="-|>", mutation_scale=18, lw=2.4, color=MUTED))

cw, ch = 11.6, 5.0
X = [0.5, 13.9]; Y = [11.4, 4.6]

# 1. flow tables (top left): database
card(X[0], Y[0], cw, ch, BLUE, "1  Flow tables in", ["CSV or Parquet", "column roles: hosts,", "ports, time, capture day"])
cx, yb, yt, rw = X[0] + 2.4, Y[0] + 0.75, Y[0] + 2.85, 1.25
ax.add_patch(Rectangle((cx - rw, yb), 2 * rw, yt - yb, fc="#dbe7f3", ec="none"))
ax.add_line(Line2D([cx - rw] * 2, [yb, yt], color=BLUE, lw=1.5)); ax.add_line(Line2D([cx + rw] * 2, [yb, yt], color=BLUE, lw=1.5))
ax.add_patch(Ellipse((cx, yb), 2 * rw, 0.6, fc="#dbe7f3", ec="none", zorder=0))
ax.add_patch(Arc((cx, yb), 2 * rw, 0.6, theta1=180, theta2=360, ec=BLUE, lw=1.5))
for yy in (yb + (yt - yb) / 3, yb + 2 * (yt - yb) / 3):
    ax.add_patch(Arc((cx, yy), 2 * rw, 0.6, theta1=180, theta2=360, ec=BLUE, lw=1.3))
ax.add_patch(Ellipse((cx, yt), 2 * rw, 0.6, fc="#a9c4e4", ec=BLUE, lw=1.5))

# 2. derived split units (top right)
card(X[1], Y[0], cw, ch, TEAL, "2  Derived split units", ["", "", ""])
for i, u in enumerate(["dup", "5-tuple", "host pair", "session", "capture"]):
    yy = Y[0] + 3.0 - i * 0.62
    ax.add_patch(FancyBboxPatch((X[1] + 0.4, yy), 2.8, 0.46, boxstyle="round,pad=0.01,rounding_size=0.18", fc="#d5eef0", ec=TEAL, lw=1.1))
    ax.text(X[1] + 1.8, yy + 0.23, u, ha="center", va="center", fontsize=8.3, color=INK)
    ok = i != 4
    ax.add_patch(Circle((X[1] + 3.6, yy + 0.23), 0.21, fc=GREEN if ok else AMBER, ec="none"))
    ax.text(X[1] + 3.6, yy + 0.22, "✓" if ok else "!", ha="center", va="center", fontsize=8.5, color="white", fontweight="bold")
for i, t in enumerate(["train/test overlap", "per unit", "split validity", "composition controls"]):
    ax.text(X[1] + 4.6, Y[0] + 3.0 - i * 0.82, t, ha="left", va="center", color=INK, fontsize=10)

# 3. CI gate (bottom right)
card(X[1], Y[1], cw, ch, INK, "3  CI gate", ["saved report →", "exit code; fails on", "the chosen severity"])
sx, sy = X[1] + 2.4, Y[1] + 0.55
ax.add_patch(Polygon([(sx - 1.4, sy + 3.05), (sx + 1.4, sy + 3.05), (sx + 1.4, sy + 1.4), (sx, sy), (sx - 1.4, sy + 1.4)],
                     closed=True, fc="#eef1f4", ec=INK, lw=1.5))
for i, (lab, c) in enumerate([("PASS", GREEN), ("WARN", AMBER), ("FAIL", RED)]):
    yy = sy + 2.6 - i * 0.62
    ax.add_patch(FancyBboxPatch((sx - 0.95, yy - 0.24), 1.9, 0.48, boxstyle="round,pad=0.01,rounding_size=0.22", fc=c, ec="none"))
    ax.text(sx, yy, lab, ha="center", va="center", fontsize=9, color="white", fontweight="bold")

# 4. injection benchmark (bottom left)
card(X[0], Y[1], cw, ch, VIOLET, "4  Injection benchmark", ["synthetic tables with", "planted leaks and ground", "truth; runs other tools"])
tx, ty = X[0] + 2.4, Y[1] + 1.95
for r_, c in [(1.45, "#e7e0f1"), (1.0, "white"), (0.55, "#e7e0f1")]:
    ax.add_patch(Circle((tx, ty), r_, fc=c, ec=VIOLET, lw=1.4))
ax.add_patch(Circle((tx, ty), 0.16, fc=VIOLET, ec="none"))
for (dx, dy) in [(0.7, 0.45), (-0.5, -0.75), (0.25, -1.2), (-1.05, 0.4)]:
    ax.add_patch(Circle((tx + dx, ty + dy), 0.12, fc=RED, ec="white", lw=0.8))

arrow((X[0] + cw + 0.1, Y[0] + ch / 2), (X[1] - 0.1, Y[0] + ch / 2))            # 1 -> 2
arrow((X[1] + cw / 2, Y[0] - 0.1), (X[1] + cw / 2, Y[1] + ch + 0.1))             # 2 -> 3
arrow((X[0] + cw / 2, Y[1] + ch + 0.1), (X[0] + cw / 2, Y[0] - 0.1))             # 4 -> 1 (generates tables)

# lineage screen band
ax.add_patch(FancyBboxPatch((0.5, 0.35), 25.0, 3.55, boxstyle="round,pad=0.02,rounding_size=0.3", fc="#f7f7f9", ec=GRAY, lw=1.6, ls=(0, (5, 3))))
for x0 in (1.1, 2.9):
    for r in range(3):
        ax.add_patch(Rectangle((x0, 0.95 + r * 0.6), 1.35, 0.5, fc="#e4e7eb" if r % 2 else "#d0d5dc", ec=MUTED, lw=0.9))
ax.add_patch(Circle((3.1, 2.15), 0.75, fc=(1, 1, 1, 0.55), ec=INK, lw=2.0))
ax.add_line(Line2D([3.62, 4.25], [1.6, 0.95], color=INK, lw=3.4, solid_capstyle="round"))
ax.add_patch(FancyBboxPatch((5.2, 2.75), 2.75, 0.7, boxstyle="round,pad=0.01,rounding_size=0.25", fc=AMBER, ec="none"))
ax.text(6.575, 3.1, "SCREEN", ha="center", va="center", fontsize=9, color="white", fontweight="bold")
ax.text(8.3, 3.1, "Lineage screen: share of rows of one corpus found in another", ha="left", va="center", fontsize=10, color=INK)
ax.text(5.2, 1.95, "after renamed, reordered or rounded columns. Not a provenance test:", ha="left", va="center", fontsize=10, color=MUTED)
ax.text(5.2, 1.15, "compare with the within-corpus baseline and the second matcher.", ha="left", va="center", fontsize=10, color=MUTED)

for ext in ("pdf", "png"):
    fig.savefig(f"fig_workflow.{ext}", dpi=300, facecolor=BG)
print("written")
