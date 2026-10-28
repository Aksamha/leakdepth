"""splitguard 0.1.0: a pipeline fit on the given split is monitored; detected = any finding.
Model features = numeric non-label columns of the given frame (as a naive pipeline would use)."""
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
import splitguard
from _loop import serve
from sklearn.model_selection import PredefinedSplit
from sklearn.tree import DecisionTreeClassifier


def handle(job):
    if job["mode"] != "split":
        return {"applicable": False, "detected": None, "detected_any": None, "error": None}
    tr = pd.read_csv(job["train"], low_memory=False)
    te = pd.read_csv(job["test"], low_memory=False)
    df = pd.concat([tr, te], ignore_index=True)
    label = job["label"]
    num = [c for c in df.columns if c != label and c != job.get("group") and pd.api.types.is_numeric_dtype(df[c])]
    X = df[num].to_numpy(dtype="float64")
    y = df[label].astype(str).to_numpy()
    fold = np.r_[np.full(len(tr), -1), np.zeros(len(te), dtype=int)]
    with splitguard.guard(policy="log"):
        if job.get("group"):
            splitguard.mark_groups(X, df[job["group"]].astype(str).tolist())
        for a, _b in PredefinedSplit(fold).split(X):
            DecisionTreeClassifier(max_depth=3, random_state=0).fit(X[a], y[a])
        fs = splitguard.report()
    out = [{"pattern": f.pattern, "leaked_rows": f.leaked_rows} for f in fs]
    return {"applicable": True, "detected": bool(out), "detected_any": bool(out), "detail": {"findings": out},
            "error": None}


if __name__ == "__main__":
    serve(handle)
