import json

import pandas as pd
import pytest

from leakdepth.cli import main
from leakdepth.inject import LEAK_TYPES, TRANSFORMS, corpus, grid, plant

ROLES = ["--label", "label", "--benign", "BENIGN", "--src", "src_ip", "--dst", "dst_ip", "--sport", "src_port",
         "--dport", "dst_port", "--proto", "proto", "--time", "ts", "--capture", "day"]


@pytest.fixture(scope="module")
def files(tmp_path_factory):
    d = tmp_path_factory.mktemp("cli")
    p = plant("host", 0.05, 31, n_sessions=400)
    c = plant("host", 0.0, 31, n_sessions=400)
    p.train.to_csv(d / "train.csv", index=False)
    p.test.to_csv(d / "test.csv", index=False)
    c.test.to_csv(d / "clean_test.csv", index=False)
    p.train.to_parquet(d / "train.parquet")
    both = pd.concat([p.train.assign(part="train"), p.test.assign(part="test")], ignore_index=True)
    both.to_csv(d / "both.csv", index=False)
    return d


def test_audit_exit_codes(files, capsys):
    d = files
    out = d / "r.json"
    rc = main(["audit", str(d / "train.csv"), "--test", str(d / "test.csv"), *ROLES, "--fail-on", "warn",
               "--out-json", str(out), "--out-md", str(d / "r.md"), "--cross-capture"])
    assert rc == 1 and "overlap-hostpair" in out.read_text()
    assert "WARN" in capsys.readouterr().out
    rc = main(["audit", str(d / "train.parquet"), "--test", str(d / "clean_test.csv"), *ROLES, "--fail-on", "WARN",
               "--units", "dup,hostpair,session:300", "--quiet"])
    assert rc == 0
    rc = main(["audit", str(d / "both.csv"), "--split-col", "part", *ROLES, "--quiet", "--fail-on", "ERROR"])
    assert rc == 0
    assert main(["gate", str(out), "--fail-on", "WARN"]) == 1
    assert main(["gate", str(out), "--quiet"]) == 0


def test_config_files(files):
    d = files
    cfg = {"columns": {"label": "label", "src": "src_ip", "dst": "dst_ip", "time": "ts", "exclude": ["day"]}}
    (d / "c.json").write_text(json.dumps(cfg))
    (d / "c.yaml").write_text("columns:\n  label: label\n  src: src_ip\n  dst: dst_ip\n")
    assert main(["audit", str(d / "train.csv"), "--test", str(d / "test.csv"), "--config", str(d / "c.json"),
                 "--fail-on", "WARN", "--quiet"]) == 1
    assert main(["audit", str(d / "train.csv"), "--config", str(d / "c.yaml"), "--quiet"]) == 0
    (d / "bad.json").write_text("[1, 2]")
    assert main(["audit", str(d / "train.csv"), "--config", str(d / "bad.json")]) == 2
    (d / "bad2.json").write_text(json.dumps({"columns": {"label": "label", "bogus": 1}}))
    assert main(["audit", str(d / "train.csv"), "--config", str(d / "bad2.json")]) == 2


def test_usage_and_input_errors(files, capsys):
    d = files
    assert main([]) == 2
    assert main(["--version"]) == 0
    assert main(["audit", str(d / "train.csv")]) == 2                      # no label
    assert main(["audit", str(d / "missing.csv"), "--label", "x"]) == 3
    assert main(["audit", str(d / "train.csv"), "--label", "nope"]) == 3
    assert main(["audit", str(d / "train.csv"), "--profile", "nope"]) == 2
    assert main(["audit", str(d / "train.csv"), "--config", str(d / "none.yaml")]) == 2
    assert main(["audit", str(d / "train.csv"), *ROLES, "--split-col", "zz"]) == 3
    assert main(["audit", str(d / "both.csv"), *ROLES, "--split-col", "label"]) == 3
    (d / "x.txt2").write_text("a")
    assert main(["audit", str(d / "x.txt2"), "--label", "a"]) == 3
    (d / "broken.parquet").write_text("not parquet")
    assert main(["audit", str(d / "broken.parquet"), "--label", "a"]) == 3
    assert main(["gate", str(d / "none.json")]) == 3
    (d / "notrep.json").write_text("{}")
    assert main(["gate", str(d / "notrep.json")]) == 3
    capsys.readouterr()


def test_lineage_and_sensitivity_cli(files, tmp_path):
    d = files
    rc = main(["lineage", str(d / "train.csv"), str(d / "both.csv"), "--exclude", "part", "--fail-on", "ERROR",
               "--out-json", str(tmp_path / "l.json")])
    assert rc == 1
    rc = main(["sensitivity", str(d / "both.csv"), *ROLES, "--levels", "hostpair", "--seeds", "0",
               "--n-boot", "20", "--out-json", str(tmp_path / "s.json"), "--quiet"])
    assert rc == 0 and json.loads((tmp_path / "s.json").read_text())["results"]["curve"]


def test_inject_ground_truth():
    tr, te, *_ = corpus(5, 400)
    assert set(tr.day) <= {"d1", "d2", "d3"} and set(te.day) == {"d4"}
    assert not set(tr.src_ip.str[:5]) & set(te.src_ip.str[:5])
    for leak in LEAK_TYPES:
        p = plant(leak, 0.05, 5, n_sessions=400)
        assert p.n_leaked == round(0.05 * len(p.test if p.other is None else p.other))
    with pytest.raises(KeyError):
        plant("bogus", 0.1, 0)
    cfgs = list(grid([0]))
    assert len(cfgs) == 4 * 4 + 4 * len(TRANSFORMS)
