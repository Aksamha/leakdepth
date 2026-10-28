"""Lineage-control Wilson intervals and the sensitivity figure, from the NB1 summary (results/nb1_summary.json)."""
import json, math, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SUMMARY = "results/nb1_summary.json"
d = json.load(open(SUMMARY))

def wilson(m, n, z=1.959963984540054):
    p = m / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, c - h), min(1.0, c + h)

out = {"positive": [], "negative": []}
for k, v in d.items():
    if not k.startswith("lineage"):
        continue
    kind = "positive" if "positive" in k else "negative"
    for name, m, n, c in v:
        lo, hi = wilson(m, n)
        ok = (c >= 0.99) if kind == "positive" and name.startswith("Ahuja in IoT") else (None if kind == "positive" else c <= 0.01)
        out[kind].append(dict(direction=name, matched=m, n=n, C=c, lo=lo, hi=hi, meets=ok))
os.makedirs("results", exist_ok=True)
json.dump(out, open("results/lineage_controls_wilson.json", "w"), indent=1)
for kind in out:
    for r in out[kind]:
        print(kind, r["direction"], r["matched"], r["n"], f'{r["C"]:.5f} [{r["lo"]:.5f}, {r["hi"]:.5f}]', r["meets"])
print("IoT-DH v1 labelled share (companion audit):", 104345 / 15817209)

LEVELS = ["row", "dup", "5tuple", "hostpair", "session:60", "session:300", "session:1800", "capture"]
LAB = ["row", "dup", "5-tuple", "host pair", "sess. 60 s", "sess. 300 s", "sess. 1800 s", "capture"]
MODELS = [("hgb", "HGB", "o"), ("rf", "RF", "s"), ("lr", "LR", "^")]
B = json.load(open("results/nb5_B_summary.json"))["B"]     # per-seed group-bootstrap intervals (NB5 item B)
fig, ax = plt.subplots(2, 2, figsize=(10, 6.2), sharex=True)
for j, (ds, title) in enumerate([("cic", "CIC-IDS2017 (mirror)"), ("unsw", "UNSW-NB15 (mirror)")]):
    for i, (m, ml, mk) in enumerate(MODELS):
        rows = {r["unit"]: r for r in d[f"{ds}_{m}_sensitivity.json"] if "unit" in r}
        xs = [x for x, L in enumerate(LEVELS) if L in rows]
        off = (i - 1) * 0.12
        F = [rows[LEVELS[x]]["F_mean"] for x in xs]
        ax[0, j].plot([x + off for x in xs], F, marker=mk, ls="none", label=ml)
        xb = [x for x, L in enumerate(LEVELS) if f"{ds}|{m}|{L}" in B]
        for x in xb:
            mean, lo, hi, dist = B[f"{ds}|{m}|{LEVELS[x]}"]
            col = f"C{i}"
            ax[1, j].plot([x + off, x + off], [lo, hi], color=col, lw=1)
            ax[1, j].plot([x + off], [mean], marker=mk, color=col, ls="none",
                          mfc=col if dist != "no" else "white", zorder=3, label=ml if x == xb[0] else None)
    invalid = sorted({r["invalid"] for k, v in d.items() if k.startswith(ds + "_") and k.endswith("sensitivity.json") for r in v if "invalid" in r})
    for L in invalid:
        x = LEVELS.index(L)
        for a in (ax[0, j], ax[1, j]):
            a.axvspan(x - 0.4, x + 0.4, color="0.9", zorder=0)
        ax[0, j].text(x, 0.45, "INVALID", rotation=90, ha="center", va="bottom", fontsize=8, color="0.35")
    ax[0, j].set_title(title, fontsize=10)
    ax[0, j].set_ylim(0.4, 1.02)
    ax[1, j].axhline(0, color="0.5", lw=0.8)
    ax[1, j].set_ylim(-0.12, 1.0)
    ax[1, j].set_xticks(range(len(LEVELS)))
    ax[1, j].set_xticklabels(LAB, rotation=40, ha="right", fontsize=8)
ax[0, 0].set_ylabel("binary macro-F1 (mean of 3 seeds)")
ax[1, 0].set_ylabel(r"$\Delta_{\mathrm{full}}$ (mean; range of per-seed 95% CIs)")
ax[0, 1].legend(fontsize=8, loc="lower left")
fig.tight_layout()
os.makedirs("docs/figures", exist_ok=True)
fig.savefig("docs/figures/fig_sensitivity.pdf")
fig.savefig("docs/figures/fig_sensitivity.png", dpi=150)
print("figure written")
