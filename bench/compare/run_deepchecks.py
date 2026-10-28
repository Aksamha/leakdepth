"""deepchecks 0.19.1 train_test_validation suite (run as a separate process).
detected = a failed condition, or a positive mixed-sample ratio, in the leakage checks."""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from _loop import serve
from deepchecks.tabular import Dataset
from deepchecks.tabular.suites import train_test_validation

LEAK_CHECKS = ("Train Test Samples Mix", "Date Train Test Leakage Duplicates", "Date Train Test Leakage Overlap",
               "Index Train Test Leakage")


def handle(job):
    tr = pd.read_csv(job["train"], low_memory=False)
    te = pd.read_csv(job["test"] if job["mode"] == "split" else job["other"], low_memory=False)
    label = job["label"]
    if label not in te.columns or set(tr.columns) != set(te.columns):
        return {"applicable": True, "detected": None, "detected_any": None,
                "error": "schemas differ (deepchecks needs identical columns and the label)"}
    cats = [c for c in tr.columns if c != label and not pd.api.types.is_numeric_dtype(tr[c])]
    res = train_test_validation().run(Dataset(tr, label=label, cat_features=cats),
                                      Dataset(te[tr.columns], label=label, cat_features=cats))
    failed, ratio = [], None
    for r in res.results:
        name = r.get_header() if hasattr(r, "get_header") else str(r)
        if name not in LEAK_CHECKS or not hasattr(r, "conditions_results"):
            continue
        if any(not c.is_pass() for c in r.conditions_results):
            failed.append(name)
        if name == "Train Test Samples Mix" and isinstance(r.value, dict):
            ratio = r.value.get("ratio")
    det_cond = bool(failed)
    det = det_cond or bool(ratio and ratio > 0)
    return {"applicable": True, "detected": det, "detected_condition": det_cond, "detected_any": det,
            "detail": {"failed_leak_checks": failed, "samples_mix_ratio": ratio}, "error": None}


if __name__ == "__main__":
    serve(handle)
