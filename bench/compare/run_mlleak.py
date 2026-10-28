"""mlleak 0.1.1 report(); detected = a failed duplicate or group check."""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
import mlleak
from _loop import serve


def handle(job):
    tr = pd.read_csv(job["train"], low_memory=False)
    te = pd.read_csv(job["test"] if job["mode"] == "split" else job["other"], low_memory=False)
    target = job["label"] if job["label"] in tr.columns and job["label"] in te.columns else None
    r = mlleak.report(tr, te, target=target, group_cols=[job["group"]] if job.get("group") else None, verbose=False)
    dup = r["duplicate_check"]
    grp = r.get("group_check") or {}
    det = (dup.get("passed") is False) or (grp.get("passed") is False)
    return {"applicable": True, "detected": bool(det), "detected_any": bool(det or r["risk_score"] > 0),
            "detail": {"risk_score": r["risk_score"], "dup_count": dup.get("duplicate_count"),
                       "group_passed": grp.get("passed")}, "error": None}


if __name__ == "__main__":
    serve(handle)
