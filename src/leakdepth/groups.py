"""Split-unit (group) extractors derived from flow metadata.

Each extractor maps a :class:`FlowTable` to an integer group code per row. Units
are given as specs: ``row``, ``dup``, ``dup:<decimals>``, ``5tuple``,
``hostpair``, ``session:<gap seconds>``, ``capture`` or any registered name.
"""
from __future__ import annotations

from collections.abc import Callable

import numpy as np
import pandas as pd

from .table import FlowTable

Extractor = Callable[..., np.ndarray]
_REGISTRY: dict[str, Extractor] = {}


def register(name: str):
    def deco(fn: Extractor) -> Extractor:
        _REGISTRY[name] = fn
        return fn
    return deco


def codes(keys) -> np.ndarray:
    """Dense integer codes for arbitrary keys (missing values form one group)."""
    s = keys if isinstance(keys, pd.Series) else pd.Series(keys)
    return pd.factorize(s, use_na_sentinel=False)[0].astype(np.int64)


def _sorted_pair(a: np.ndarray, b: np.ndarray):
    a = np.asarray(a, dtype=object)
    b = np.asarray(b, dtype=object)
    swap = a > b
    return np.where(swap, b, a), np.where(swap, a, b)


@register("row")
def g_row(t: FlowTable) -> np.ndarray:
    return np.arange(len(t), dtype=np.int64)


@register("dup")
def g_dup(t: FlowTable, decimals: int | None = None) -> np.ndarray:
    """Exact duplicate clusters on features + class (optionally after rounding)."""
    if decimals is None:  # hash the original columns: exact semantics, no copy
        h = t.feature_hash()
    else:
        h = pd.util.hash_pandas_object(t.X("float64").round(int(decimals)), index=False).to_numpy()
    hc = pd.util.hash_pandas_object(pd.Series(t.cls), index=False).to_numpy()
    return codes(pd.Series(h ^ (hc * np.uint64(0x9E3779B97F4A7C15))))


@register("5tuple")
def g_5tuple(t: FlowTable) -> np.ndarray:
    """Direction-insensitive (ip:port, ip:port, protocol)."""
    e1 = pd.Series(t.meta("src")) + ":" + pd.Series(t.meta("sport"))
    e2 = pd.Series(t.meta("dst")) + ":" + pd.Series(t.meta("dport"))
    lo, hi = _sorted_pair(e1.to_numpy(), e2.to_numpy())
    proto = pd.Series(t.meta("proto")) if t.has("proto") else pd.Series([""] * len(t))
    return codes(pd.Series(lo) + "|" + pd.Series(hi) + "|" + proto)


@register("hostpair")
def g_hostpair(t: FlowTable) -> np.ndarray:
    lo, hi = _sorted_pair(t.meta("src"), t.meta("dst"))
    return codes(pd.Series(lo) + "|" + pd.Series(hi))


@register("session")
def g_session(t: FlowTable, gap: float = 300) -> np.ndarray:
    """Sessions on a host pair: a new session starts when the gap between
    consecutive flow start times on that pair exceeds ``gap`` seconds.
    Rows without a valid time form singleton sessions."""
    hp = g_hostpair(t)
    tm = t.time.copy()
    bad = ~np.isfinite(tm)
    tm[bad] = 0.0
    order = np.lexsort((tm, hp))
    hp_s, t_s, b_s = hp[order], tm[order], bad[order]
    new = np.ones(len(t_s), dtype=bool)
    new[1:] = (hp_s[1:] != hp_s[:-1]) | ((t_s[1:] - t_s[:-1]) > gap) | b_s[1:] | b_s[:-1]
    sid_sorted = np.cumsum(new) - 1
    sid = np.empty_like(sid_sorted)
    sid[order] = sid_sorted
    return sid.astype(np.int64)


@register("capture")
def g_capture(t: FlowTable) -> np.ndarray:
    return codes(t.meta("capture"))


def requirements(spec: str) -> tuple:
    """Roles an extractor needs (used to skip units a table cannot support)."""
    name = spec.split(":", 1)[0]
    return {"row": (), "dup": (), "5tuple": ("src", "dst", "sport", "dport"),
            "hostpair": ("src", "dst"), "session": ("src", "dst", "time"),
            "capture": ("capture",)}.get(name, ())


def supported(t: FlowTable, spec: str) -> bool:
    return t.has(*requirements(spec))


def extract(t: FlowTable, spec: str) -> np.ndarray:
    """Group codes for unit ``spec`` (e.g. ``'session:300'``, ``'dup:3'``)."""
    name, _, arg = spec.partition(":")
    if name not in _REGISTRY:
        raise KeyError(f"unknown unit '{name}'; available: {sorted(_REGISTRY)}")
    fn = _REGISTRY[name]
    if not arg:
        return fn(t)
    if name == "session":
        return fn(t, gap=float(arg))
    if name == "dup":
        return fn(t, decimals=int(arg))
    return fn(t, arg)


def available() -> list:
    return sorted(_REGISTRY)
