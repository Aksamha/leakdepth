
import numpy as np
import pandas as pd
import pytest

from leakdepth import FlowTable, sensitivity
from leakdepth.inject import COLUMNS, plant
from leakdepth.sensitivity import make_model, matched_sample, stratified_cap


@pytest.fixture(scope="module")
def tbl():
    p = plant("session", 0.0, 21, n_sessions=600)
    return FlowTable(pd.concat([p.train, p.test], ignore_index=True), COLUMNS, "syn")


def test_curve_and_controls(tbl, tmp_path):
    res = tmp_path / "f.jsonl"
    rep = sensitivity(tbl, ["dup", "hostpair", "session:300", "capture"], models=["hgb", "lr"], seeds=[0],
                      n_boot=50, resume=str(res))
    folds = rep.results["folds"]
    assert set(folds.unit) == {"row", "dup", "hostpair", "session:300", "capture"}
    hp = folds[(folds.unit == "hostpair") & (folds.model == "hgb")].iloc[0]
    assert hp.F_lo <= hp.F <= hp.F_hi and abs(hp.d_raw - (hp.F_L0 - hp.F)) < 1e-12
    assert not np.isnan(hp.d_full) and hp.d_full_lo <= hp.d_full <= hp.d_full_hi
    cap = folds[folds.unit == "capture"]
    assert (cap.scheme == "leave-one-group-out").all() and len(cap) >= 2
    comp = rep.results["test_composition"]
    assert np.allclose(comp.drop(columns=["seed", "unit", "fold"]).sum(axis=1), 1.0)
    curve = rep.results["curve"]
    assert {"F_mean", "d_full_mean", "n_seeds"} <= set(curve.columns)
    n_lines = len(res.read_text().splitlines())
    rep2 = sensitivity(tbl, ["dup", "hostpair", "session:300", "capture"], models=["hgb", "lr"], seeds=[0],
                       n_boot=50, resume=str(res))
    assert len(res.read_text().splitlines()) == n_lines and len(rep2.results["folds"]) == len(folds)


def test_invalid_level_reported(tbl):
    df = tbl.df.copy()
    df.loc[df.label == "scan", "day"] = "d9"
    rep = sensitivity(FlowTable(df, COLUMNS), ["capture"], seeds=[0], n_boot=20)
    folds = rep.results["folds"]
    assert "capture" in set(folds.unit)  # other day folds stay valid
    one = FlowTable(df.assign(day="d1"), COLUMNS)
    rep = sensitivity(one, ["capture"], seeds=[0], n_boot=20)
    assert rep.results["invalid_levels"] and rep.findings[0].id == "invalid-capture"


def test_custom_model_and_helpers(tbl):
    from sklearn.tree import DecisionTreeClassifier

    def tree():
        return DecisionTreeClassifier(max_depth=3, random_state=0)
    rep = sensitivity(tbl, ["hostpair"], models=[tree, "rf"], seeds=[1], n_boot=20, train_cap=2000)
    assert set(rep.results["folds"].model) == {"tree", "rf"}
    assert rep.results["folds"].n_train.max() <= 2001
    with pytest.raises(KeyError):
        make_model("svm", 0)
    r = np.random.default_rng(0)
    cls = np.array(["a"] * 90 + ["b"] * 10)
    s = stratified_cap(np.arange(100), cls, 20, r)
    assert len(s) == 20 and (cls[s] == "b").sum() == 2
    m = matched_sample(np.arange(100), cls, np.array(["a", "b"]), 20, r)
    assert (cls[m] == "b").sum() == 10
