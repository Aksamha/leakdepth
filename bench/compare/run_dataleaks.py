"""dataleaks 0.1.2 DataLeaks().run(); detected = a finding from a split, temporal or
cross-dataset detector (any severity)."""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from _loop import serve
from dataleaks import DataLeaks
from dataleaks.engine.defaults import build_default_registry
from dataleaks.schemas.config import DataLeaksConfig
from dataleaks.schemas.dataset import DatasetContext

# Variant: the pairwise near-duplicate detector (Python loop over all train x test row pairs)
# does not finish within the time limit on ~10k rows, so the "nonear" variant removes it.
NO_NEAR = os.environ.get("DATALEAKS_NO_NEAR") == "1"


def _registry(data, target, train, test, metadata):
    ctx = DatasetContext(data=data, target=target, train=train, validation=None, test=test, metadata=metadata or {})
    reg = build_default_registry(ctx, DataLeaksConfig())
    reg._detectors = {k: v for k, v in reg._detectors.items() if "near" not in k}
    return reg

LEAK_CATEGORIES = ("split_leakage", "temporal_leakage", "cross_dataset_leakage")


def handle(job):
    tr = pd.read_csv(job["train"], low_memory=False)
    label = job["label"]
    if job["mode"] == "split":
        te = pd.read_csv(job["test"], low_memory=False)
        data = pd.concat([tr, te], ignore_index=True)
        reg = _registry(data, label, tr, te, None) if NO_NEAR else None
        rep = DataLeaks(data, target=label, train=tr, test=te, registry=reg).run()
    else:
        other = pd.read_csv(job["other"], low_memory=False)
        tgt = label if label in other.columns else None
        reg = _registry(other, tgt, other, None, {"reference_data": tr}) if NO_NEAR else None
        rep = DataLeaks(other, target=tgt, metadata={"reference_data": tr}, registry=reg).run()
    fs = [{"detector": getattr(f, "detector", getattr(f, "name", None)), "category": getattr(f, "category", None),
           "severity": getattr(f, "severity", None)} for f in rep.findings]
    det = any(str(f["category"]) in LEAK_CATEGORIES for f in fs)
    return {"applicable": True, "detected": det, "detected_any": bool(fs), "detail": {"findings": fs[:20]},
            "error": None}


if __name__ == "__main__":
    serve(handle)
