import numpy as np
import pandas as pd
import pytest

from leakdepth import ColumnMap, FlowTable, audit, audit_split, audit_units, capture_checks, concat, load
from leakdepth.inject import COLUMNS, plant
from leakdepth.profiles import available, fix_cic_time


def _audit(p, **kw):
    t, tr, te = concat(FlowTable(p.train, COLUMNS), FlowTable(p.test, COLUMNS))
    return audit_split(t, tr, te, cross_capture=True, **kw)


@pytest.mark.parametrize("leak,fid", [("dup", "overlap-dup"), ("session", "overlap-session"),
                                      ("host", "overlap-hostpair"), ("capture", "overlap-capture")])
def test_planted_leaks_detected(leak, fid):
    ids = {f.id for f in _audit(plant(leak, 0.05, 3)).findings}
    assert fid in ids
    assert not _audit(plant(leak, 0.0, 3)).findings


def test_specific_types():
    ids = {f.id for f in _audit(plant("host", 0.05, 4)).findings}
    assert ids == {"overlap-hostpair"}
    ids = {f.id for f in _audit(plant("dup", 0.05, 4)).findings}
    assert ids == {"overlap-dup"}


def test_capture_severity_depends_on_protocol():
    p = plant("capture", 0.05, 1)
    t, tr, te = concat(FlowTable(p.train, COLUMNS), FlowTable(p.test, COLUMNS))
    f = [x for x in audit_split(t, tr, te).findings if x.id == "overlap-capture"]
    assert f and f[0].severity == "INFO"
    f = [x for x in audit_split(t, tr, te, thresholds={"hostpair": (0.5, "ERROR")}).findings]
    assert all(x.id != "overlap-hostpair" for x in f)


def test_index_overlap_and_concat_errors(toy):
    rep = audit_split(toy, np.arange(0, 100), np.arange(50, 150), units=["dup"])
    assert "index-overlap" in {f.id for f in rep.findings}
    with pytest.raises(ValueError):
        concat(toy, FlowTable(toy.df, ColumnMap(label="cls")))


def test_unit_validity_and_full_audit(toy):
    rep = audit_units(toy)
    rows = {r["unit"]: r for r in rep.results["unit_validity"]}
    assert rows["hostpair"]["valid"] and rows["capture"]["scheme"] == "leave-one-group-out"
    df = toy.df.copy()
    df.loc[df.cls == "A", "day"] = "d3"   # class A confined to one day
    t = FlowTable(df, toy.cols)
    rep = audit(t, units=["capture"])
    ids = {f.id for f in rep.findings}
    assert "capture-confined-class" in ids and ("invalid-capture" in ids or "partial-capture" in ids)
    one = FlowTable(df.assign(day="d1"), toy.cols)
    assert not audit_units(one, units=["capture"]).results["unit_validity"][0]["valid"]


def test_capture_encoding():
    n = 400
    df = pd.DataFrame({"cls": ["BENIGN"] * n, "cap": ["jan"] * (n // 2) + ["feb"] * (n // 2),
                       "ctr": [0.0] * (n // 2) + [np.nan] * (n // 2), "v": np.arange(n, dtype=float)})
    rep = capture_checks(FlowTable(df, ColumnMap(label="cls", capture="cap")))
    assert [f.id for f in rep.findings] == ["capture-encoding"]
    assert capture_checks(FlowTable(df, ColumnMap(label="cls"))).findings == []


def test_cic_time_fix():
    t = fix_cic_time(pd.Series(["4/7/2017 1:28", "4/7/2017 9:05", "03/07/2017 08:55:58"]))
    assert t.dt.hour.tolist() == [13, 9, 8] and t.dt.month.tolist() == [7, 7, 7]


def test_profiles():
    assert available() == ["cic-ids2017", "unsw-nb15"]
    cic = pd.DataFrame({"flow_id": ["a", "b"], "source_ip": ["1", "2"], "destination_ip": ["2", "1"],
                        "source_port": [1, 2], "destination_port": [80, 80], "protocol": [6, 6],
                        "Timestamp": ["4/7/2017 1:28", "5/7/2017 9:05"], "attack_label": ["BENIGN", "DoS"],
                        "Flow Duration": [1.0, 2.0]})
    t = load(cic, "cic-ids2017")
    assert t.meta("capture").tolist() == ["2017-07-04", "2017-07-05"] and t.feature_names == ["Flow Duration"]
    t2 = load(cic, "cic-ids2017", fix_time=False)
    assert t2.time[0] < t.time[0]
    unsw = pd.DataFrame({"srcip": ["1", "2"], "sport": [1, 2], "dstip": ["2", "1"], "dsport": [80, 80],
                         "proto": ["tcp", "udp"], "Stime": [1421927000, 1424250000], "Ltime": [1, 2],
                         "attack_cat": [None, " Backdoors "], "label": [0, 1], "ct_ftp_cmd": [0.0, np.nan],
                         "dur": [0.1, 0.2]})
    u = load(unsw, "unsw-nb15")
    assert u.cls.tolist() == ["Normal", "Backdoor"] and u.meta("capture").tolist() == ["2015-01", "2015-02"]
    assert np.isnan(u.X()["ct_ftp_cmd"].iloc[1])
    assert load(unsw, "unsw-nb15", blank_to_zero=True).X()["ct_ftp_cmd"].iloc[1] == 0
    with pytest.raises(KeyError):
        load(unsw, "nope")
