"""0.1.3: lineage reports the other matcher and a within-corpus baseline (no change to findings);
sensitivity flags group-bootstrap intervals over fewer than 10 test groups."""
import json

import numpy as np
import pandas as pd
import pytest

from leakdepth import FlowTable, lineage, sensitivity
from leakdepth.cli import main
from leakdepth.inject import COLUMNS, plant


def _core(rep):
    return [(r["direction"], r["matched"], r["containment"]) for r in rep.results["containment"]], \
        [(f.id, f.severity) for f in rep.findings]


@pytest.mark.parametrize("seed,tf,rho", [(0, "rename", 0.05), (1, "renameall", 0.2), (2, "round3", 0.0)])
def test_extras_do_not_change_primary_result(seed, tf, rho):
    p = plant("lineage", rho, seed, transform=tf)
    full = lineage(p.train, p.other, "train", "other", seed=0)
    bare = lineage(p.train, p.other, "train", "other", seed=0, compare_matchers=False, baseline=False)
    assert _core(full) == _core(bare)
    for r in full.results["containment"]:
        assert r["other_matcher"]["matcher"] == "frozen"
        assert 0.0 <= r["other_matcher"]["containment"] <= 1.0
        assert r["baseline"] is None or 0.0 <= r["baseline"]["containment"] <= 1.0
    for r in bare.results["containment"]:
        assert "other_matcher" not in r and "baseline" not in r


def test_other_matcher_is_a10_when_frozen_is_primary():
    p = plant("lineage", 0.05, 3, transform="rename")
    rep = lineage(p.train, p.other, seed=0, matcher="frozen", baseline=False)
    assert {r["other_matcher"]["matcher"] for r in rep.results["containment"]} == {"a10"}


def _features(n, seed, dup_share):
    r = np.random.default_rng(seed)
    df = pd.DataFrame(r.normal(size=(n, 6)), columns=[f"x{i}" for i in range(6)])
    k = int(dup_share * n)
    if k:
        df.iloc[:k] = df.iloc[r.integers(k, n, k)].to_numpy()   # internal near-copies
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def test_baseline_reflects_internal_redundancy():
    a, b = _features(4000, 0, 0.4), _features(4000, 1, 0.0)
    rep = lineage(a, b, "a", "b", seed=0, compare_matchers=False)
    base = {r["direction"]: r["baseline"]["containment"] for r in rep.results["containment"]}
    assert base["a in b"] > 0.1           # a contains copies of its own rows
    assert base["b in a"] < 0.01          # b has none
    assert all("baseline" in f.message for f in rep.findings if f.id == "lineage-containment")


def test_cli_flags(tmp_path):
    p = plant("lineage", 0.05, 4, transform="rename")
    pa, pb = tmp_path / "a.csv", tmp_path / "b.csv"
    p.train.to_csv(pa, index=False)
    p.other.to_csv(pb, index=False)
    out = tmp_path / "l.json"
    main(["lineage", str(pa), str(pb), "--single-matcher", "--no-baseline", "--out-json", str(out), "--quiet"])
    d = json.load(open(out))
    assert all("other_matcher" not in r and "baseline" not in r for r in d["results"]["containment"])
    main(["lineage", str(pa), str(pb), "--out-json", str(out), "--quiet"])
    d = json.load(open(out))
    assert all("other_matcher" in r and "baseline" in r for r in d["results"]["containment"])


def test_few_group_interval_flag():
    p = plant("session", 0.0, 21, n_sessions=400)
    t = FlowTable(pd.concat([p.train, p.test], ignore_index=True), COLUMNS, "syn")
    rep = sensitivity(t, ["capture", "hostpair"], models=["lr"], seeds=[0], n_boot=20, train_cap=3000)
    folds = rep.results["folds"]
    cap = folds[folds["unit"] == "capture"]
    hp = folds[folds["unit"] == "hostpair"]
    assert len(cap) and cap["ci_few_groups"].all() and (cap["n_test_groups"] == 1).all()
    assert len(hp) and not hp["ci_few_groups"].any()
    msgs = [f for f in rep.findings if f.id == "interval-few-groups"]
    assert [f.unit for f in msgs] == ["capture"] and msgs[0].severity == "INFO"
