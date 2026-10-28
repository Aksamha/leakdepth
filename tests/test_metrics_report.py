import json

import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import f1_score

from leakdepth.metrics import bootstrap_f1, ci, composition_weights, macro_f1, wilson
from leakdepth.report import Finding, Report, file_digest, frame_digest


def test_macro_f1_matches_sklearn():
    r = np.random.default_rng(0)
    y, p = r.integers(0, 2, 500), r.integers(0, 2, 500)
    assert abs(macro_f1(y, p) - f1_score(y, p, average="macro")) < 1e-12
    w = r.random(500)
    assert abs(macro_f1(y, p, w) - f1_score(y, p, average="macro", sample_weight=w)) < 1e-12
    assert macro_f1([1, 1], [1, 1]) == 0.5  # benign class absent: its F1 counts as 0


def test_bootstrap_ci():
    r = np.random.default_rng(0)
    y = r.integers(0, 2, 2000)
    p = np.where(r.random(2000) < 0.9, y, 1 - y)
    lo, hi = ci(bootstrap_f1(y, p, np.arange(2000), n_boot=200))
    assert lo < macro_f1(y, p) < hi and hi - lo < 0.05
    g = np.repeat(np.arange(20), 100)
    lo2, hi2 = ci(bootstrap_f1(y, p, g, n_boot=200))
    assert hi2 - lo2 > 0
    assert np.isnan(ci(np.array([]))[0])


def test_composition_weights():
    ref = np.array(["B"] * 80 + ["X"] * 20)
    tgt = np.array(["B"] * 50 + ["X"] * 50)
    w, miss = composition_weights(ref, tgt)
    assert not miss and abs(w[ref == "X"].sum() / w.sum() - 0.5) < 1e-12
    w, miss = composition_weights(ref, np.array(["B", "Z"]))
    assert miss == ["Z"]


def test_wilson():
    lo, hi = wilson(50, 100)
    assert lo < 0.5 < hi
    assert wilson(0, 10)[0] == 0.0 and np.isnan(wilson(0, 0)[0])


def test_report_roundtrip(tmp_path):
    rep = Report("audit", inputs=[{"name": "x", "rows": 3, "columns": 2, "sha256": "ab" * 32}])
    rep.add(Finding("a", "split-overlap", "warn", "msg", "hostpair", {"v": np.float64(0.5), "n": np.int64(3)}))
    rep.add(Finding("b", "split-overlap", "ERROR", "msg2"))
    rep.results["tab"] = pd.DataFrame({"u": ["x"], "v": [float("nan")]})
    d = json.loads(rep.to_json(str(tmp_path / "r.json")))
    assert d["schema_version"] == "1.0" and d["summary"] == {"INFO": 0, "WARN": 1, "ERROR": 1}
    assert d["results"]["tab"][0]["v"] is None and d["findings"][0]["evidence"]["n"] == 3
    md = rep.to_markdown(str(tmp_path / "r.md"))
    assert "| ERROR | split-overlap" in md and "## tab" in md
    assert rep.max_severity() == "ERROR" and len(rep.failing("WARN")) == 2 and len(rep.failing()) == 1
    assert Report("x").max_severity() is None
    with pytest.raises(ValueError):
        Finding("c", "x", "fatal", "m")
    assert len(file_digest(str(tmp_path / "r.json"))) == 64
    assert frame_digest(pd.DataFrame({"a": [1]})) != frame_digest(pd.DataFrame({"b": [1]}))


def test_wilson_exact_edges():
    # 0.1.1 returned a lower bound of ~2e-19 for k = 0 at some n (e.g. 1000, 1200)
    for n in (1, 7, 10, 1000, 1200, 200_000, 2_097_150):
        assert wilson(0, n)[0] == 0.0
        assert wilson(n, n)[1] == 1.0
        lo, hi = wilson(0, n)
        assert 0.0 < hi < 1.0
