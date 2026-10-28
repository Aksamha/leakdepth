import numpy as np
import pandas as pd
import pytest

from leakdepth import ColumnMap, FlowTable

COLS = ColumnMap(label="cls", benign="BENIGN", src="src", dst="dst", sport="sport", dport="dport",
                 proto="proto", time="t", capture="day")


def toy_frame(n=3000, seed=0):
    r = np.random.default_rng(seed)
    hosts = [f"10.0.0.{i}" for i in range(30)]
    cls = np.where(r.random(n) < 0.3, r.choice(["A", "B"], n), "BENIGN")
    df = pd.DataFrame(r.normal(size=(n, 4)).astype("float32"), columns=list("abcd"))
    df.iloc[:200] = df.iloc[200:400].to_numpy()
    cls[:200] = cls[200:400]
    t = np.sort(r.integers(0, 20000, n))
    df["src"], df["dst"] = r.choice(hosts, n), r.choice(hosts, n)
    df["sport"], df["dport"] = r.integers(1000, 1010, n), 80
    df["proto"], df["t"], df["day"], df["cls"] = "tcp", t, np.where(t < 10000, "d1", "d2"), cls
    return df


@pytest.fixture
def toy():
    return FlowTable(toy_frame(), COLS, "toy")
