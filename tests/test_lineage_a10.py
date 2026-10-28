"""Tests for the A10 minimum-information matcher (default since 0.1.1) and the frozen 0.1.0 matcher."""
import numpy as np
import pandas as pd
import pytest

from leakdepth import lineage, lineage_matches
from leakdepth.cli import main
from leakdepth.inject import plant
from leakdepth.lineage import bits_matrix, canonicalise, match_rows


def _matched(rep):
    return [r["matched"] for r in rep.results["containment"]]


def _low_info(n, seed, offset=0):
    """Flow-like table with few, low-cardinality columns and many zero counters."""
    r = np.random.default_rng(seed)
    empty = r.random(n) < 0.7
    return pd.DataFrame({
        "label": r.integers(0, 2, n),
        "dst": np.array([f"10.0.0.{i}" for i in r.integers(1, 15, n)]),
        "pkts": np.where(empty, 0, r.integers(1, 40, n)),
        "bytes": np.where(empty, 0, r.integers(1, 40, n) * 98),
        "dur_ns": r.integers(0, 1000, n) * 1_000_000 + offset,
    })


@pytest.mark.parametrize("seed,tf", [(0, "rename"), (1, "round3"), (2, "combo"), (3, "renameall"), (4, "colsubset")])
def test_disabled_bound_equals_frozen(seed, tf):
    p = plant("lineage", 0.05, seed, transform=tf)
    cols = [c for c in p.train.columns if c in p.other.columns][:6]
    if len(cols) < 4:
        pytest.skip("too few shared names for a direct match_rows call")
    kinds = ["num" if pd.api.types.is_numeric_dtype(p.train[c]) else "str" for c in cols]
    f = match_rows(p.other, p.train, cols, cols, kinds, [None] * len(cols))
    g = match_rows(p.other, p.train, cols, cols, kinds, [None] * len(cols), info_margin=-1e18)
    assert np.array_equal(f["matched"], g["matched"]) and np.array_equal(f["partner"], g["partner"])


@pytest.mark.parametrize("tf", ["rename", "round3", "combo", "renameall"])
def test_a10_keeps_planted_recall(tf):
    p = plant("lineage", 0.05, 21, transform=tf)
    a = lineage(p.train, p.other, "train", "other")
    f = lineage(p.train, p.other, "train", "other", matcher="frozen")
    assert _matched(a) == _matched(f)
    assert a.to_dict()["config"]["matcher"] == "a10" and f.to_dict()["config"]["info_margin"] is None


def test_a10_rejects_chance_agreement_on_low_information_columns():
    a, b = _low_info(20_000, 1), _low_info(20_000, 2)
    fz = lineage(a, b, "A", "B", matcher="frozen")
    am = lineage(a, b, "A", "B")
    assert sum(_matched(fz)) > 0                      # the 0.1.0 failure mode
    assert sum(_matched(am)) == 0
    assert all(r["rejected_low_info"] > 0 for r in am.results["containment"])
    assert all(f.severity == "INFO" for f in am.findings)


def test_low_information_copies_are_a_documented_limit():
    """Rows carrying fewer than log2(n_B) + margin bits cannot be told apart from chance agreement:
    A10 does not report them, while 0.1.0 reports them together with many false matches."""
    a = _low_info(20_000, 3, offset=7)
    b = pd.concat([_low_info(20_000, 4), a.iloc[:2000]], ignore_index=True)
    am = lineage(a.iloc[:2000], b, "A", "B")
    fz = lineage(a.iloc[:2000], b, "A", "B", matcher="frozen")
    assert _matched(am) == [0, 0]
    assert _matched(fz)[1] > 2000                     # B in A: far more matches than true copies


def test_a10_detects_copies_once_rows_carry_enough_information():
    r = np.random.default_rng(9)
    a = _low_info(20_000, 3).assign(ts=r.random(20_000) * 1e6, flow=r.integers(0, 10**9, 20_000))
    base = _low_info(20_000, 4).assign(ts=r.random(20_000) * 1e6, flow=r.integers(0, 10**9, 20_000))
    b = pd.concat([base, a.iloc[:2000]], ignore_index=True)
    assert _matched(lineage(a.iloc[:2000], b, "A", "B"))[0] == 2000


def test_margin_validation_and_matches_api():
    p = plant("lineage", 0.05, 22, transform="rename")
    with pytest.raises(ValueError):
        lineage(p.train, p.other, matcher="other")
    with pytest.raises(ValueError):
        lineage(p.train, p.other, info_margin=float("inf"))
    m = lineage_matches(p.other, p.train)
    assert int(m["matched"].sum()) == p.n_leaked and len(m["index"]) == len(p.other)
    small = lineage_matches(p.other, p.train, sample_n=100)
    assert len(small["index"]) == 100 and small["index"].max() < len(p.other)


def test_bits_matrix():
    H = np.array([[1, 5], [1, 6], [2, 7]], dtype=np.uint64)
    b = bits_matrix(H)
    assert b[0, 0] == pytest.approx(-np.log2(3 / 4)) and b[2, 0] == pytest.approx(1.0)
    c = canonicalise(pd.DataFrame({"x": [1.0, 2.0]}), ["x"], ["num"], [0])
    assert c.k == 1


def test_cli_matcher_flag(tmp_path):
    a, b = _low_info(5000, 5), _low_info(5000, 6)
    a.to_csv(tmp_path / "a.csv", index=False)
    b.to_csv(tmp_path / "b.csv", index=False)
    out = tmp_path / "r.json"
    assert main(["lineage", str(tmp_path / "a.csv"), str(tmp_path / "b.csv"), "--out-json", str(out), "--quiet"]) == 0
    assert main(["lineage", str(tmp_path / "a.csv"), str(tmp_path / "b.csv"), "--matcher", "frozen",
                 "--info-margin", "30", "--out-json", str(out), "--quiet"]) == 0
