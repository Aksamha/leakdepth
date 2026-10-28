import numpy as np
import pandas as pd
import pytest
from conftest import COLS

from leakdepth import ColumnMap, FlowTable
from leakdepth import groups as G


def test_roles_and_features(toy):
    assert toy.feature_names == ["a", "b", "c", "d"]
    assert toy.y.dtype == np.int8 and toy.y.sum() == (toy.cls != "BENIGN").sum()
    assert toy.has("src", "time") and not FlowTable(toy.df, ColumnMap(label="cls")).has("src")
    assert toy.X().shape == (3000, 4) and toy.X("float64").dtypes.iloc[0] == "float64"
    assert toy.subset([0, 1, 2]).df.shape[0] == 3
    assert toy.class_counts().sum() == 3000


def test_attack_column_and_time_parsing():
    df = pd.DataFrame({"c": ["x", "y"], "atk": [0, 1], "ts": ["2017-07-04 13:28", "2017-07-04 13:29:30"], "v": [1.0, 2.0]})
    t = FlowTable(df, ColumnMap(label="c", attack="atk", time="ts"))
    assert t.y.tolist() == [0, 1]
    assert t.time[1] - t.time[0] == 90
    tz = FlowTable(df.assign(ts=pd.to_datetime(df.ts, format="mixed").dt.tz_localize("UTC")), ColumnMap(label="c", time="ts"))
    assert tz.time[1] - tz.time[0] == 90


def test_missing_columns_raise():
    df = pd.DataFrame({"c": ["x"], "v": [1.0]})
    with pytest.raises(KeyError):
        FlowTable(df, ColumnMap(label="c", src="nope"))
    with pytest.raises(KeyError):
        FlowTable(df, ColumnMap(label="c", features=("zz",)))
    with pytest.raises(ValueError):
        FlowTable(df, ColumnMap(label="c")).meta("src")
    with pytest.raises(ValueError):
        _ = FlowTable(df, ColumnMap(label="c")).time


def test_dup_groups(toy):
    g = G.extract(toy, "dup")
    assert all(g[i] == g[i + 200] for i in range(200))
    assert len(np.unique(g)) == len(g) - 200
    df = toy.df.copy()
    df.loc[0, "a"] = df.loc[200, "a"] + 1e-6
    assert G.extract(FlowTable(df, COLS), "dup")[0] != G.extract(FlowTable(df, COLS), "dup")[200]
    assert G.extract(FlowTable(df, COLS), "dup:3")[0] == G.extract(FlowTable(df, COLS), "dup:3")[200]


def test_dup_respects_class(toy):
    df = toy.df.copy()
    df.loc[0, "cls"] = "A" if df.loc[200, "cls"] != "A" else "B"
    g = G.extract(FlowTable(df, COLS), "dup")
    assert g[0] != g[200]


def test_direction_insensitive(toy):
    df = toy.df.rename(columns={"src": "dst", "dst": "src", "sport": "dport", "dport": "sport"})
    t2 = FlowTable(df, COLS)
    assert (G.extract(toy, "hostpair") == G.extract(t2, "hostpair")).all()
    assert (G.extract(toy, "5tuple") == G.extract(t2, "5tuple")).all()


def test_session_gap():
    df = pd.DataFrame({"cls": ["BENIGN"] * 6, "src": ["a"] * 5 + ["c"], "dst": ["b"] * 6,
                       "t": [0, 10, 400, 405, 2000, 5], "v": [1.0] * 6})
    t = FlowTable(df, ColumnMap(label="cls", src="src", dst="dst", time="t"))
    s = G.extract(t, "session:300")
    assert s[0] == s[1] and s[2] == s[3] and len({s[0], s[2], s[4], s[5]}) == 4
    assert len(set(G.extract(t, "session:5000")[:5])) == 1


def test_session_missing_time_is_singleton():
    df = pd.DataFrame({"cls": ["x"] * 3, "src": ["a"] * 3, "dst": ["b"] * 3, "t": [0.0, np.nan, 1.0]})
    s = G.extract(FlowTable(df, ColumnMap(label="cls", src="src", dst="dst", time="t")), "session:300")
    assert s[1] != s[0] and s[1] != s[2]


def test_registry(toy):
    assert set(["row", "dup", "5tuple", "hostpair", "session", "capture"]) <= set(G.available())
    with pytest.raises(KeyError):
        G.extract(toy, "nonsense")

    @G.register("byport")
    def g_port(t, arg=None):
        return G.codes(t.meta("dport"))

    assert len(np.unique(G.extract(toy, "byport"))) == 1
    assert len(np.unique(G.extract(toy, "byport:x"))) == 1
    assert G.supported(toy, "capture") and not G.supported(FlowTable(toy.df, ColumnMap(label="cls")), "hostpair")
    assert len(np.unique(G.extract(toy, "capture"))) == 2
    assert (G.extract(toy, "row") == np.arange(3000)).all()


def test_numeric_like_text_columns_are_features():
    df = pd.DataFrame({"c": ["x", "y", "z"], "n": [" ", "1", "4"], "s": ["a", "b", "c"], "e": [None, " ", None]})
    t = FlowTable(df, ColumnMap(label="c"))
    assert t.feature_names == ["n"]
    assert np.isnan(t.X()["n"].iloc[0]) and t.X()["n"].iloc[2] == 4
