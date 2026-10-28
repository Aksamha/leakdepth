"""Row-level recovery of planted lineage (descriptive): matched rows vs planted rows.

usage: python bench/lineage_recovery.py --seeds 100-119 --out results/lineage_recovery.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import time

from injection import parse_seeds

from leakdepth import lineage
from leakdepth.inject import EXTRA_TRANSFORMS, TRANSFORMS, plant


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    done = set()
    if os.path.exists(a.out):
        done = {(r["seed"], r["transform"], r["rho"]) for r in map(json.loads, open(a.out))}
    for s in parse_seeds(a.seeds):
        for tf in TRANSFORMS + EXTRA_TRANSFORMS:
            for rho in ((0.0, 0.01, 0.05, 0.2) if tf in EXTRA_TRANSFORMS else (0.01, 0.05, 0.2)):
                if (s, tf, rho) in done:
                    continue
                t0 = time.time()
                p = plant("lineage", rho, s, transform=tf)
                rep = lineage(p.train, p.other, "train", "other")
                c = {r["direction"]: r for r in rep.results["containment"]}.get("other in train", {})
                fired = any(f.severity in ("WARN", "ERROR") for f in rep.findings)
                row = {"seed": s, "transform": tf, "rho": rho, "n_leaked": p.n_leaked, "n_other": len(p.other),
                       "matched": c.get("matched", 0), "aligned": c.get("aligned_columns", 0), "detected": fired,
                       "seconds": round(time.time() - t0, 2)}
                with open(a.out, "a") as f:
                    f.write(json.dumps(row) + "\n")


if __name__ == "__main__":
    main()
