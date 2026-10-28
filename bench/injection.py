"""Injection benchmark for leakdepth (ground truth from leakdepth.inject).

usage: python bench/injection.py --seeds 0-4 --out results/injection_dev.jsonl
Each configuration is appended to the JSONL file; reruns skip finished ones.
"""
from __future__ import annotations

import argparse
import json
import os
import time

from leakdepth import FlowTable, audit_split, concat, lineage
from leakdepth.inject import COLUMNS, grid, plant

TYPE_FINDING = {"dup": "overlap-dup", "session": "overlap-session", "host": "overlap-hostpair",
                "capture": "overlap-capture", "lineage": "lineage-containment"}


def parse_seeds(s: str) -> list:
    out = []
    for part in s.split(","):
        a, _, b = part.partition("-")
        out += list(range(int(a), int(b) + 1)) if b else [int(a)]
    return out


def key(c: dict) -> str:
    return f"{c['leak']}|{c['rho']}|{c['seed']}|{c['transform']}"


def run_one(c: dict) -> dict:
    t0 = time.time()
    p = plant(c["leak"], c["rho"], c["seed"], transform=c["transform"] or "rename")
    if c["leak"] == "lineage":
        rep = lineage(p.train, p.other, "train", "other", seed=0)
    else:
        t, tr, te = concat(FlowTable(p.train, COLUMNS, "train"), FlowTable(p.test, COLUMNS, "test"))
        rep = audit_split(t, tr, te, cross_capture=True)
    fired = sorted({f.id for f in rep.findings if f.severity in ("WARN", "ERROR")})
    return {**c, "n_leaked": p.n_leaked, "n_test": len(p.test) if p.other is None else len(p.other),
            "fired": fired, "detected_type": TYPE_FINDING[c["leak"]] in fired, "detected_any": bool(fired),
            "seconds": round(time.time() - t0, 2)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    done = set()
    if os.path.exists(a.out):
        with open(a.out) as f:
            done = {key(json.loads(line)) for line in f}
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    n = 0
    for c in grid(parse_seeds(a.seeds)):
        if key(c) in done:
            continue
        r = run_one(c)
        with open(a.out, "a") as f:
            f.write(json.dumps(r) + "\n")
        n += 1
    print(f"{n} new configurations written to {a.out}")


if __name__ == "__main__":
    main()
