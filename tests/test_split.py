import numpy as np
from hypothesis import given, settings
from hypothesis import strategies as st

from leakdepth import groups as G
from leakdepth.split import check_validity, confined_classes, constrained_group_split, group_split, leave_one_group_out


def test_groups_disjoint(toy):
    rng = np.random.default_rng(1)
    for u in ["dup", "5tuple", "hostpair", "session:300", "capture"]:
        g = G.extract(toy, u)
        tr, te = group_split(g, toy.cls, 0.2, rng)
        assert not set(g[tr]) & set(g[te]) and len(tr) + len(te) == len(g)


@settings(max_examples=40, deadline=None)
@given(n=st.integers(20, 400), ng=st.integers(2, 60), frac=st.floats(0.1, 0.5), seed=st.integers(0, 10**6))
def test_group_split_properties(n, ng, frac, seed):
    r = np.random.default_rng(seed)
    g = r.integers(0, ng, n)
    cls = r.choice(["BENIGN", "X"], n)
    tr, te = group_split(g, cls, frac, np.random.default_rng(seed))
    assert len(np.intersect1d(tr, te)) == 0 and len(tr) + len(te) == n
    assert not set(g[tr]) & set(g[te])


def test_row_fraction(toy):
    tr, te = group_split(np.arange(len(toy)), toy.cls, 0.2, np.random.default_rng(0))
    assert abs(len(te) / len(toy) - 0.2) < 0.01


def test_validity_rules():
    cls = np.array(["BENIGN"] * 8 + ["A", "B"])
    y = (cls != "BENIGN").astype(np.int8)
    v = check_validity(cls, y, np.arange(9), np.array([9]), "BENIGN", 0.5)
    assert not v.valid and v.unseen_classes == ["B"] and v.warnings
    v = check_validity(cls, y, np.arange(1, 10), np.array([0]), "BENIGN")
    assert not v.valid and "attack share" in v.reasons[0]
    v = check_validity(cls, y, np.arange(10), np.array([], dtype=int), "BENIGN")
    assert not v.valid
    v = check_validity(cls, y, np.array([0, 1, 2, 8, 9]), np.array([3, 9]), "BENIGN")
    assert v.valid and v.to_dict()["valid"]


def test_constrained_redraw(toy):
    tr, te, v = constrained_group_split(G.extract(toy, "hostpair"), toy.cls, toy.y, 0.2, 0, "BENIGN")
    assert v.valid and v.tries >= 1
    g = np.where(toy.cls == "A", 0, np.arange(len(toy)) + 1)  # all of class A in one group
    tr, te, v = constrained_group_split(g, toy.cls, toy.y, 0.2, 0, "BENIGN", tries=5)
    assert v.valid or v.tries == 5
    assert confined_classes(g, toy.cls, "BENIGN") == ["A"]


def test_logo():
    folds = list(leave_one_group_out(np.array([0, 0, 1, 2])))
    assert [f[0] for f in folds] == [0, 1, 2] and folds[0][2].tolist() == [0, 1]
