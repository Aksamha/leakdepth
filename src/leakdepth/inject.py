"""Synthetic flow corpora with planted leakage and known ground truth.

A clean split is cross-session, cross-host-pair and cross-day: training uses days
1-3 and host pool ``10.0.*``; testing uses day 4 and host pool ``10.1.*``.
Leakage is planted by replacing a share ``rho`` of the test rows:

- ``dup``: exact feature+class copies of training rows with fresh test metadata;
- ``session``: new flows of training sessions (same host pair, time window, latent);
- ``host``: new sessions on training host pairs (half with reversed direction), test day;
- ``capture``: new sessions on test host pairs placed on a training day;
- ``lineage``: a second corpus mixing transformed training rows with fresh rows.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from .table import ColumnMap

LEAK_TYPES = ("dup", "session", "host", "capture", "lineage")
TRANSFORMS = ("rename", "reorder", "round3", "float32", "colsubset", "rowsubset", "combo", "noise")
EXTRA_TRANSFORMS = ("renameall",)  # every column renamed; reported separately
CLASSES = ("BENIGN", "scan", "dos", "brute")
DAY0 = 1_500_000_000.0
N_FEAT = 12

COLUMNS = ColumnMap(label="label", benign="BENIGN", src="src_ip", dst="dst_ip", sport="src_port",
                    dport="dst_port", proto="proto", time="ts", capture="day")


@dataclass
class Planted:
    train: pd.DataFrame
    test: pd.DataFrame
    leak: str
    rho: float
    n_leaked: int
    seed: int
    other: pd.DataFrame | None = None   # lineage: second corpus
    transform: str | None = None


class _Gen:
    def __init__(self, seed: int):
        self.r = np.random.default_rng(seed)
        r = self.r
        # heterogeneous feature definitions (scale, offset, transform)
        self.scale = r.uniform(0.5, 5.0, N_FEAT)
        self.loc = r.uniform(-3, 3, N_FEAT)
        self.kind = r.choice(["lin", "exp", "int"], N_FEAT, p=[0.5, 0.3, 0.2])
        self.cmean = {c: r.normal(0, 1.2, N_FEAT) for c in CLASSES}
        self.dshift = {d: r.normal(0, 0.3, N_FEAT) for d in range(1, 5)}
        self.dport = {"BENIGN": [80, 443, 53, 22], "scan": [21, 23, 3389, 8080], "dos": [80], "brute": [22, 21]}

    def session_latent(self, cls, day):
        return self.cmean[cls] + self.dshift[day] + self.r.normal(0, 0.6, N_FEAT)

    def flows(self, latent, n):
        z = latent + self.r.normal(0, 0.15, (n, N_FEAT))
        out = np.empty_like(z)
        for j in range(N_FEAT):
            v = self.loc[j] + self.scale[j] * z[:, j]
            if self.kind[j] == "exp":
                v = np.exp(np.clip(v / 3, -20, 20))
            elif self.kind[j] == "int":
                v = np.round(np.abs(v) * 10)
            out[:, j] = v
        return out

    def session(self, sid, src, dst, day, cls, t0=None, n=None, latent=None):
        r = self.r
        n = n or int(r.geometric(1 / 8))
        latent = self.session_latent(cls, day) if latent is None else latent
        t0 = DAY0 + (day - 1) * 86400 + r.uniform(8, 17) * 3600 if t0 is None else t0
        ts = t0 + np.cumsum(r.uniform(0.5, 40, n)) - 0.5
        f = self.flows(latent, n)
        cols = {f"f{j:02d}": f[:, j] for j in range(N_FEAT)}
        cols.update({"src_ip": [src] * n, "dst_ip": [dst] * n, "src_port": r.integers(32768, 61000, n),
                     "dst_port": r.choice(self.dport[cls], n), "proto": ["tcp"] * n, "ts": np.round(ts, 3),
                     "day": [f"d{day}"] * n, "label": [cls] * n, "_sid": np.full(n, sid)})
        return pd.DataFrame(cols), latent, t0


def _pairs(r, pool: str, n_hosts: int, n_pairs: int):
    hosts = [f"10.{pool}.{i // 250}.{i % 250 + 1}" for i in range(n_hosts)]
    seen, out = set(), []
    while len(out) < n_pairs:
        a, b = r.choice(n_hosts, 2, replace=False)
        key = tuple(sorted((a, b)))
        if key not in seen:
            seen.add(key)
            out.append((hosts[a], hosts[b]))
    return out


def corpus(seed: int, n_sessions: int = 1200, class_p=(0.7, 0.1, 0.1, 0.1)):
    """Return (train, test, generator state). Session latent vectors are kept."""
    g = _Gen(seed)
    r = g.r
    tr_pairs = _pairs(r, "0", 80, 300)
    te_pairs = _pairs(r, "1", 40, 100)
    parts, info = [], {}
    sid = 0
    for i in range(n_sessions):
        test = i % 4 == 0
        day = 4 if test else int(r.integers(1, 4))
        src, dst = (te_pairs if test else tr_pairs)[r.integers(0, 100 if test else 300)]
        cls = str(r.choice(CLASSES, p=class_p))
        df, lat, t0 = g.session(sid, src, dst, day, cls)
        parts.append(df)
        info[sid] = (src, dst, day, cls, lat, t0)
        sid += 1
    df = pd.concat(parts, ignore_index=True)
    is_test = df["day"] == "d4"
    return df[~is_test].reset_index(drop=True), df[is_test].reset_index(drop=True), g, info, sid


def _fresh_meta(g: _Gen, rows: pd.DataFrame, test: pd.DataFrame):
    rows = rows.copy()
    pick = g.r.integers(0, len(test), len(rows))
    for c in ("src_ip", "dst_ip", "day"):
        rows[c] = test[c].to_numpy()[pick]
    rows["src_port"] = g.r.integers(32768, 61000, len(rows))
    rows["ts"] = np.round(DAY0 + 3 * 86400 + g.r.uniform(8, 17, len(rows)) * 3600, 3)
    return rows


def transform_corpus(df: pd.DataFrame, how: str, seed: int) -> pd.DataFrame:
    """Schema transforms used for the lineage benchmark."""
    r = np.random.default_rng(seed)
    feats = [c for c in df.columns if c.startswith("f")]
    out = df.copy()
    if how == "renameall":
        out = out.rename(columns={c: f"col_{i}" for i, c in enumerate(r.permutation(list(out.columns)))})
    if how in ("rename", "combo"):
        out = out.rename(columns={c: f"feature_{i}" for i, c in enumerate(r.permutation(feats))})
    if how == "reorder":
        out = out[list(r.permutation(out.columns))]
    if how in ("round3", "combo"):
        num = [c for c in out.columns if c.startswith("f") and pd.api.types.is_float_dtype(out[c])]
        out[num] = out[num].round(3)
    if how == "float32":
        num = [c for c in feats if pd.api.types.is_float_dtype(out[c])]
        out[num] = out[num].astype("float32")
    if how in ("colsubset", "combo"):
        keep = [c for c in out.columns if r.random() < 0.7 or not (c.startswith("f"))]
        out = out[keep]
    if how == "noise":
        for c in feats:
            if pd.api.types.is_float_dtype(out[c]):
                out[c] = out[c] * (1 + r.normal(0, 0.01, len(out)))
    return out


def plant(leak: str, rho: float, seed: int, transform: str = "rename", n_sessions: int = 1200,
          keep_session_id: bool = False) -> Planted:
    """Build a corpus and plant ``leak`` in a share ``rho`` of the test rows. With
    ``keep_session_id`` the generator's session id is kept in column ``_sid``."""
    if leak not in LEAK_TYPES:
        raise KeyError(f"unknown leak type '{leak}'")
    train, test, g, info, next_sid = corpus(seed, n_sessions)
    r = g.r
    k = int(round(rho * len(test)))
    drop_cols = [] if keep_session_id else ["_sid"]
    if leak == "lineage":
        fresh_tr, fresh_te, *_ = corpus(seed + 7919, n_sessions)
        fresh = pd.concat([fresh_tr, fresh_te], ignore_index=True)
        kb = int(round(rho * len(test)))
        src = train.iloc[r.choice(len(train), kb, replace=False)] if kb else train.iloc[:0]
        other = pd.concat([src, fresh.iloc[r.choice(len(fresh), len(test) - kb, replace=False)]], ignore_index=True)
        other = other.drop(columns=drop_cols).sample(frac=1.0, random_state=seed).reset_index(drop=True)
        other = transform_corpus(other, transform if transform != "rowsubset" else "none", seed)
        return Planted(train.drop(columns=drop_cols), test.drop(columns=drop_cols), leak, rho, kb, seed,
                       other=other, transform=transform)
    keep = np.ones(len(test), dtype=bool)
    keep[r.choice(len(test), k, replace=False)] = False
    new = []
    n = 0
    while n < k:
        if leak == "dup":
            rows = train.iloc[r.choice(len(train), k - n, replace=False)]
            rows = _fresh_meta(g, rows, test)
        elif leak == "session":
            s = int(r.choice(train["_sid"].unique()))
            src, dst, day, cls, lat, t0 = info[s]
            rows, *_ = g.session(s, src, dst, day, cls, t0=t0 + 1.0, latent=lat)
        elif leak == "host":
            s = int(r.choice(train["_sid"].unique()))
            src, dst, day, cls, *_ = info[s]
            if r.random() < 0.5:
                src, dst = dst, src
            cls = str(r.choice(CLASSES, p=(0.7, 0.1, 0.1, 0.1)))
            rows, *_ = g.session(next_sid, src, dst, 4, cls)
            next_sid += 1
        else:  # capture
            s = int(r.choice(test["_sid"].unique()))
            src, dst, _, cls, *_ = info[s]
            rows, *_ = g.session(next_sid, src, dst, int(r.integers(1, 4)), cls,
                                 t0=DAY0 + int(r.integers(0, 3)) * 86400 + 20 * 3600 + r.uniform(0, 3000))
            next_sid += 1
        new.append(rows)
        n += len(rows)
    test2 = test[keep]
    if new:
        test2 = pd.concat([test2, pd.concat(new, ignore_index=True).iloc[:k]], ignore_index=True)
    return Planted(train.drop(columns=drop_cols), test2.drop(columns=drop_cols).reset_index(drop=True),
                   leak, rho, k, seed)


def grid(seeds, rhos=(0.0, 0.01, 0.05, 0.20), leaks=LEAK_TYPES, transforms=TRANSFORMS):
    """Configurations of the injection benchmark."""
    for s in seeds:
        for leak in leaks:
            for rho in rhos:
                for tf in (transforms if leak == "lineage" else (None,)):
                    yield {"leak": leak, "rho": rho, "seed": s, "transform": tf}
