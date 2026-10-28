"""leakdepth: audit_split (split mode) or lineage; detected = any WARN or ERROR finding."""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from _loop import serve

from leakdepth import ColumnMap, FlowTable, audit_split, concat, lineage

ROLES = {"src": "src_ip", "dst": "dst_ip", "sport": "src_port", "dport": "dst_port", "proto": "proto",
         "time": "ts", "capture": "day"}


def handle(job):
    tr = pd.read_csv(job["train"], low_memory=False)
    if job["mode"] == "split":
        te = pd.read_csv(job["test"], low_memory=False)
        roles = {k: v for k, v in ROLES.items() if v in tr.columns}
        cols = ColumnMap(label=job["label"], exclude=tuple(c for c in (job.get("group"),) if c), **roles)
        t, a, b = concat(FlowTable(tr, cols), FlowTable(te, cols))
        rep = audit_split(t, a, b, cross_capture=True)
    else:
        rep = lineage(tr, pd.read_csv(job["other"], low_memory=False))
    fired = sorted({f.id for f in rep.findings if f.severity in ("WARN", "ERROR")})
    return {"applicable": True, "detected": bool(fired), "detected_any": bool(fired), "detail": {"fired": fired},
            "error": None}


if __name__ == "__main__":
    serve(handle)
