import numpy as np
import pandas as pd
import pytest

from leakdepth import ColumnMap, FlowTable, key_join_containment, lineage
from leakdepth.inject import TRANSFORMS, plant
from leakdepth.lineage import _sig_round, align_columns, detect_decimals, norm_name, profile_columns


def _c(rep, d):
    return [r for r in rep.results["containment"] if r["direction"] == d][0]


@pytest.mark.parametrize("tf", [t for t in TRANSFORMS if t != "noise"])
def test_transforms_recovered(tf):
    p = plant("lineage", 0.05, 11, transform=tf)
    rep = lineage(p.train, p.other, "train", "other")
    c = _c(rep, "other in train")
    assert c["matched"] == p.n_leaked
    assert any(f.severity == "WARN" for f in rep.findings)


def test_noise_not_matched_and_clean_zero():
    p = plant("lineage", 0.05, 12, transform="noise")
    assert _c(lineage(p.train, p.other), "B in A")["matched"] == 0
    p = plant("lineage", 0.0, 12)
    rep = lineage(p.train, p.other)
    assert all(r["matched"] == 0 for r in rep.results["containment"])
    assert all(f.severity == "INFO" for f in rep.findings)


def test_full_identity_is_error_and_subset_direction():
    p = plant("lineage", 0.0, 13)
    a = p.train
    b = pd.concat([a.iloc[:1000], p.other], ignore_index=True)
    rep = lineage(a.iloc[:1000], b, "A", "B")
    assert _c(rep, "A in B")["containment"] == 1.0
    assert any(f.severity == "ERROR" for f in rep.findings)
    assert _c(rep, "B in A")["containment"] < 0.5


def test_sampling_and_chunks():
    p = plant("lineage", 0.2, 14, transform="reorder")
    rep = lineage(p.train, p.other, sample_n=300, chunk=500)
    c = _c(rep, "B in A")
    assert c["sampled_rows"] == 300 and c["ci_lo"] < 0.2 < c["ci_hi"]


def test_not_comparable():
    a = pd.DataFrame({"x": np.arange(10.0), "y": np.arange(10.0) ** 2})
    b = pd.DataFrame({"p": ["u"] * 10, "q": ["v", "w"] * 5})
    rep = lineage(a, b)
    assert rep.findings[0].id == "lineage-not-comparable" and rep.results["containment"] == []


def test_refinement_fixes_swapped_columns():
    r = np.random.default_rng(0)
    n = 3000
    a = pd.DataFrame({f"c{i}": r.normal(0, 1, n) for i in range(6)})
    a["u"], a["v"] = r.normal(5, 2, n), r.normal(5, 2, n)   # same distribution, different values
    b = a.rename(columns={"u": "zz1", "v": "zz2"})
    b = b.rename(columns={c: f"k{c}" for c in b.columns if c.startswith("c")})
    rep = lineage(a, b)
    assert _c(rep, "A in B")["containment"] == 1.0


def test_helpers():
    assert norm_name("Source IP") == "srcip" and norm_name("Dst_Port") == "dstport" and norm_name("x") == "x"
    assert detect_decimals(np.array([1.25, 2.5, 3.0])) == 2 and detect_decimals(np.array([np.pi])) is None
    assert detect_decimals(np.array([np.nan])) == 0
    x = _sig_round(np.array([123456.0, 0.000123456, 0.0, np.nan]), 3)
    assert x[0] == 123000 and abs(x[1] - 0.000123) < 1e-12 and x[2] == 0 and np.isnan(x[3])
    df = pd.DataFrame({"n": [1.0, 2.0], "s": ["a", "b"], "k": [7, 7], "e": ["z", "z"], "m": ["1", "2"]})
    pr = profile_columns(df)
    assert [pr[c].kind for c in df.columns] == ["num", "str", "const", "const", "num"]
    pairs = align_columns(pr, profile_columns(df.rename(columns={"s": "S"})))
    assert ("s", "S", 0.0, "name") in pairs and ("k", "k", 0.0, "name") in pairs


def test_key_join():
    p = plant("lineage", 0.0, 15)
    cols = ColumnMap(label="label", src="src_ip", dst="dst_ip", sport="src_port", dport="dst_port",
                     proto="proto", time="ts")
    a = FlowTable(p.train.iloc[:500], cols)
    shifted = p.train.iloc[:500].copy()
    shifted["ts"] += 3600  # clock offset in the re-export
    shifted = shifted.rename(columns={"src_ip": "dst_ip", "dst_ip": "src_ip", "src_port": "dst_port",
                                      "dst_port": "src_port"})
    r = key_join_containment(a, FlowTable(shifted, cols))
    assert r["containment"] == 1.0 and r["offset_s"] == -3600
    r2 = key_join_containment(a, FlowTable(p.other, cols))
    assert r2["containment"] < 0.05


def test_renameall_mixture_recovered():
    p = plant("lineage", 0.05, 16, transform="renameall")
    rep = lineage(p.train, p.other)
    assert _c(rep, "B in A")["matched"] == p.n_leaked
    assert any(a["how"] == "values" for a in rep.results["alignment"])


def test_value_overlap_ignores_rounded_columns():
    from leakdepth.lineage import value_overlap
    r = np.random.default_rng(1)
    x = pd.DataFrame({"a": r.normal(size=3000), "b": r.normal(size=3000)})
    pr = profile_columns(x)
    f, k = value_overlap(pr["a"], pr["a"])
    assert f == 1.0 and k > 100
    assert value_overlap(pr["a"], pr["b"])[1] < 10  # below MIN_SHARED
    pr3 = profile_columns(x.round(3))
    assert pr3["a"].decimals == 3 and pr["a"].decimals is None
