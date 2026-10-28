"""Summarise injection and comparison results into CSV tables (and a compact printout).

usage: python bench/summarize.py results/injection_heldout.jsonl results/compare_heldout.jsonl --out results/
"""
from __future__ import annotations

import argparse
import json
import os

import pandas as pd

from leakdepth.metrics import wilson

LEAKCHECK_SPLIT = ("L1.cross", "L2.near", "L3.cross_contradict")
LEAKCHECK_PREFIX = ("L4.", "L6.")


def rate(s: pd.Series) -> dict:
    s = s.dropna().astype(bool)
    k, n = int(s.sum()), int(len(s))
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci_lo": round(lo, 4), "ci_hi": round(hi, 4)}


def injection_table(path: str) -> pd.DataFrame:
    df = pd.DataFrame([json.loads(x) for x in open(path)])
    df["transform"] = df["transform"].fillna("-")
    df["kind"] = df["rho"].map(lambda r: "FPR (rho=0)" if r == 0 else f"recall rho={r}")
    rows = []
    for (leak, tf, rho), g in df.groupby(["leak", "transform", "rho"]):
        rows.append({"leak": leak, "transform": tf, "rho": rho, **rate(g["detected_type"])})
    return pd.DataFrame(rows)


def secondary(r: dict) -> bool | None:
    if r.get("detected") is None:
        return None
    t = r["tool"]
    if t == "leakcheck":
        fs = (r.get("detail") or {}).get("findings", [])
        return any((f.get("code") in LEAKCHECK_SPLIT or str(f.get("code", "")).startswith(LEAKCHECK_PREFIX))
                   and f.get("severity") in ("medium", "high") for f in fs)
    if t == "deepchecks":
        return r.get("detected_condition")
    return r["detected"]


def compare_table(path: str) -> pd.DataFrame:
    recs = [json.loads(x) for x in open(path)]
    for r in recs:
        r["detected_secondary"] = secondary(r)
    df = pd.DataFrame(recs)
    df["transform"] = df["transform"].fillna("-")
    rows = []
    for (tool, leak, tf, cond, rho), g in df.groupby(["tool", "leak", "transform", "condition", "rho"]):
        app = g[g["applicable"].fillna(True).astype(bool)]
        if app.empty:
            rows.append({"tool": tool, "leak": leak, "transform": tf, "condition": cond, "rho": rho, "status": "n/a"})
            continue
        err = int(app["detected"].isna().sum())
        p, s = rate(app["detected"]), rate(app["detected_secondary"])
        rows.append({"tool": tool, "leak": leak, "transform": tf, "condition": cond, "rho": rho, "n": len(app),
                     "errors": err, "primary": p["rate"], "primary_k": p["k"], "secondary": s["rate"],
                     "median_s": round(float(app["seconds"].median()), 2)})
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("injection")
    ap.add_argument("compare", nargs="?")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    inj = injection_table(a.injection)
    inj.to_csv(os.path.join(a.out, "injection_summary.csv"), index=False)
    with pd.option_context("display.width", 200, "display.max_rows", 200):
        print(inj.to_string(index=False))
    if a.compare and os.path.exists(a.compare):
        cmp_ = compare_table(a.compare)
        cmp_.to_csv(os.path.join(a.out, "compare_summary.csv"), index=False)
        piv = cmp_[cmp_.get("status").isna() if "status" in cmp_ else slice(None)]
        with pd.option_context("display.width", 250, "display.max_rows", 400):
            print(piv.pivot_table(index=["leak", "transform", "condition", "rho"], columns="tool", values="primary").to_string())


if __name__ == "__main__":
    main()
