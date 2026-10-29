"""Sensitivity figure (Fig. 3) from the A15 ten-seed summary (results/nb8_summary.json).
Same encoding as the NB8 notebook figure (A15_fig_sensitivity), redrawn at journal column width for legibility.
Usage: python make_fig_sensitivity_a15.py SUMMARY_JSON OUT_DIR"""
import json
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

src, out = sys.argv[1], sys.argv[2]
d = json.load(open(src))
key = [k for k in d if k.startswith("cells[")][0]
cells = d[key]  # [n, mean, sd, bonf_lo, bonf_hi, p_t_holm, p_w_holm, dist, material, F_mean]

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "pdf.fonttype": 42})
LEVELS = ["dup", "5tuple", "hostpair", "session:60", "session:300", "session:1800", "capture"]
LABELS = ["dup", "5-tuple", "host pair", "sess. 60 s", "sess. 300 s", "sess. 1800 s", "capture"]
MODELS = [("hgb", "HGB", "#1f77b4", "o"), ("rf", "RF", "#ff7f0e", "s"), ("lr", "LR", "#2ca02c", "^")]
DS = [("cic", "CIC-IDS2017 (mirror)"), ("unsw", "UNSW-NB15 (mirror)")]

fig, axes = plt.subplots(2, 2, figsize=(7.0, 4.9), sharex=True, gridspec_kw={"hspace": 0.12, "wspace": 0.22})
for j, (ds, title) in enumerate(DS):
    top, bot = axes[0, j], axes[1, j]
    for i, lev in enumerate(LEVELS):
        if not any(f"{ds}|{m}|{lev}" in cells for m, *_ in MODELS):
            for a in (top, bot):
                a.axvspan(i - 0.42, i + 0.42, color="#e3e3e3", zorder=0)
            top.text(i, 0.55, "INVALID", rotation=90, ha="center", va="center", fontsize=7, color="#555")
            continue
        for k, (m, lab, col, mk) in enumerate(MODELS):
            c = cells.get(f"{ds}|{m}|{lev}")
            if c is None:
                continue
            x = i + (k - 1) * 0.2
            top.plot(x, c[9], mk, color=col, ms=5, label=lab if (i == 0 and j == 1) else None)
            bot.plot([x, x], [c[3], c[4]], color=col, lw=1.2)
            bot.plot(x, c[1], mk, ms=5, mec=col, mfc=col if c[7] else "white", mew=1.2)
    top.set_title(title, fontsize=9)
    top.set_ylim(0.4, 1.02)
    bot.axhline(0, color="#777", lw=0.7)
    for a in (top, bot):
        a.set_xlim(-0.6, len(LEVELS) - 0.4)
        a.tick_params(labelsize=7.5)
    bot.set_xticks(range(len(LEVELS)))
    bot.set_xticklabels(LABELS, rotation=40, ha="right")
axes[0, 0].set_ylabel("binary macro-F1\n(mean of 10 seeds)")
axes[1, 0].set_ylabel(r"$\Delta_{\mathrm{full}}$ (mean, Bonferroni" "\n" r"simultaneous 95 % CI)")
axes[0, 1].legend(loc="lower left", fontsize=7.5, frameon=True)
fig.savefig(f"{out}/fig_sensitivity.pdf", bbox_inches="tight")
fig.savefig(f"{out}/fig_sensitivity.png", dpi=220, bbox_inches="tight")
print("saved")
