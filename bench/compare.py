"""Cross-tool comparison on the injection benchmark.

Each tool runs in its own virtual environment as a long-lived worker process
(bench/compare/run_<tool>.py) that reads jobs as JSON lines. Tools are given the
same CSV files. Conditions:
  defaults - train/test frames as generated (features + metadata + label);
  features - feature columns + label only (metadata dropped);
  oracle   - defaults plus the true unit column `_unit`, passed as the group
             column to tools that accept one.

usage: python bench/compare.py --tools-dir ../tools --seeds 100-109 --out results/compare.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

import numpy as np
import pandas as pd

from leakdepth.inject import plant

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = ("leakdepth", "leakcheck", "splitcheck", "mlleak", "dataleaks_nonear", "splitguard", "deepchecks")
SPLIT_LEAKS = ("dup", "session", "host", "capture")
LINEAGE_TF = ("rename", "round3", "colsubset", "combo", "renameall")
RHOS = (0.0, 0.01, 0.05)
GROUP_TOOLS = ("leakcheck", "splitcheck", "mlleak", "splitguard")
META = ("src_ip", "dst_ip", "src_port", "dst_port", "proto", "ts", "day")


class Worker:
    """Long-lived tool process; a job that exceeds ``timeout`` seconds is recorded as an
    error and the process is restarted."""

    def __init__(self, name: str, python: str, timeout: float = 900):
        self.name, self.python, self.timeout = name, python, timeout
        self._start()

    def _start(self):
        self.p = subprocess.Popen([self.python, "-I", os.path.join(HERE, "compare", f"run_{self.name}.py")],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, bufsize=1)

    def run(self, job: dict) -> dict:
        import select
        self.p.stdin.write(json.dumps(job) + "\n")
        self.p.stdin.flush()
        ready, _, _ = select.select([self.p.stdout], [], [], self.timeout)
        if not ready:
            self.p.kill()
            self.p.wait()
            self._start()
            return {"applicable": True, "detected": None, "detected_any": None,
                    "error": f"timeout > {self.timeout:.0f} s", "seconds": self.timeout}
        while True:
            line = self.p.stdout.readline()
            if not line:
                self._start()
                return {"applicable": True, "detected": None, "detected_any": None, "error": "worker died",
                        "seconds": None}
            if line.startswith("@@leakbench "):
                return json.loads(line[len("@@leakbench "):])

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=30)


def parse_seeds(s):
    out = []
    for part in s.split(","):
        a, _, b = part.partition("-")
        out += list(range(int(a), int(b) + 1)) if b else [int(a)]
    return out


def configs(seeds):
    for s in seeds:
        for leak in SPLIT_LEAKS:
            for rho in RHOS:
                for cond in ("defaults", "features", "oracle"):
                    if cond == "oracle" and leak == "dup":
                        continue
                    yield {"leak": leak, "rho": rho, "seed": s, "transform": None, "condition": cond}
        for tf in LINEAGE_TF:
            for rho in RHOS:
                yield {"leak": "lineage", "rho": rho, "seed": s, "transform": tf, "condition": "defaults"}


def key(c, tool):
    return f"{c['leak']}|{c['rho']}|{c['seed']}|{c['transform']}|{c['condition']}|{tool}"


def unit_column(leak: str, df: pd.DataFrame) -> pd.Series:
    if leak == "session":
        return df["_sid"].astype(str)
    if leak == "host":
        a, b = df["src_ip"].astype(str), df["dst_ip"].astype(str)
        return np.where(a < b, a + "|" + b, b + "|" + a)
    return df["day"].astype(str)  # capture


def materialise(c: dict, wd: str) -> dict:
    p = plant(c["leak"], c["rho"], c["seed"], transform=c["transform"] or "rename", keep_session_id=True)
    tr, te = p.train, p.test
    job = {"mode": "split", "label": "label", "workdir": wd, "group": None}
    if c["leak"] == "lineage":
        tr = tr.drop(columns=["_sid"], errors="ignore")
        other = p.other.drop(columns=[x for x in p.other.columns if x == "_sid"])
        tr.to_csv(os.path.join(wd, "train.csv"), index=False)
        other.to_csv(os.path.join(wd, "other.csv"), index=False)
        return job | {"mode": "lineage", "train": os.path.join(wd, "train.csv"),
                      "other": os.path.join(wd, "other.csv"), "n_leaked": p.n_leaked}
    if c["condition"] == "oracle":
        tr = tr.assign(_unit=unit_column(c["leak"], tr))
        te = te.assign(_unit=unit_column(c["leak"], te))
        job["group"] = "_unit"
    tr, te = tr.drop(columns=["_sid"]), te.drop(columns=["_sid"])
    if c["condition"] == "features":
        tr, te = tr.drop(columns=list(META)), te.drop(columns=list(META))
    tr.to_csv(os.path.join(wd, "train.csv"), index=False)
    te.to_csv(os.path.join(wd, "test.csv"), index=False)
    return job | {"train": os.path.join(wd, "train.csv"), "test": os.path.join(wd, "test.csv"), "n_leaked": p.n_leaked}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools-dir", required=True, help="directory with one virtualenv per tool")
    ap.add_argument("--seeds", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tools", default=",".join(TOOLS))
    ap.add_argument("--timeout", type=float, default=900, help="seconds per tool job")
    ap.add_argument("--leaks", help="comma-separated subset of leak types")
    ap.add_argument("--rhos", help="comma-separated subset of rho values")
    ap.add_argument("--conditions", help="comma-separated subset of conditions")
    a = ap.parse_args()
    tools = a.tools.split(",")
    done = set()
    if os.path.exists(a.out):
        with open(a.out) as f:
            done = {key(r, r["tool"]) for r in map(json.loads, f)}
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    workers = {}
    for t in tools:
        env = t.split("_")[0]
        py = sys.executable if t == "leakdepth" else os.path.join(a.tools_dir, env, "bin", "python")
        workers[t] = Worker(t, py, a.timeout)
    n = 0
    try:
        for c in configs(parse_seeds(a.seeds)):
            if (a.leaks and c["leak"] not in a.leaks.split(",")) or \
                    (a.rhos and c["rho"] not in [float(x) for x in a.rhos.split(",")]) or \
                    (a.conditions and c["condition"] not in a.conditions.split(",")):
                continue
            todo = [t for t in tools if key(c, t) not in done]
            if not todo:
                continue
            with tempfile.TemporaryDirectory() as wd:
                job = materialise(c, wd)
                for t in todo:
                    j = dict(job)
                    if j.get("group") and t not in GROUP_TOOLS:
                        j["group"] = None  # tool has no group option: run as defaults (+ extra column)
                    r = workers[t].run(j)
                    row = {**c, "tool": t, "n_leaked": job["n_leaked"], "group_passed": bool(j.get("group")), **r}
                    row.pop("trace", None)
                    with open(a.out, "a") as f:
                        f.write(json.dumps(row, default=str) + "\n")
                    n += 1
    finally:
        for w in workers.values():
            try:
                w.close()
            except Exception:  # noqa: BLE001
                pass
    print(f"{n} new results written to {a.out}")


if __name__ == "__main__":
    main()
