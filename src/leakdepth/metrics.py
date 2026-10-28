"""Binary macro-F1, group bootstrap and composition weights."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .groups import codes


def _f1_from_counts(tp, fp, fn, tn):
    f1p = np.where(2 * tp + fp + fn > 0, 2 * tp / np.maximum(2 * tp + fp + fn, 1e-300), 0.0)
    f1n = np.where(2 * tn + fn + fp > 0, 2 * tn / np.maximum(2 * tn + fn + fp, 1e-300), 0.0)
    return (f1p + f1n) / 2


def macro_f1(y, p, w=None) -> float:
    """Binary macro-F1 (mean of attack and benign F1), optionally weighted."""
    y, p = np.asarray(y).astype(bool), np.asarray(p).astype(bool)
    w = np.ones(len(y)) if w is None else np.asarray(w, dtype=float)
    tp, fp = w[y & p].sum(), w[~y & p].sum()
    fn, tn = w[y & ~p].sum(), w[~y & ~p].sum()
    return float(_f1_from_counts(tp, fp, fn, tn))


def bootstrap_f1(y, p, groups=None, w=None, n_boot: int = 1000, seed: int = 0, chunk: int = 50) -> np.ndarray:
    """Bootstrap draws of binary macro-F1, resampling ``groups`` (rows if None)
    with Poisson(1) multiplicities. ``w`` are fixed per-row weights."""
    y, p = np.asarray(y).astype(bool), np.asarray(p).astype(bool)
    w = np.ones(len(y)) if w is None else np.asarray(w, dtype=float)
    g = np.arange(len(y)) if groups is None else codes(groups)
    ng = int(g.max()) + 1 if len(g) else 0
    cnt = np.zeros((ng, 4))
    for j, m in enumerate([y & p, ~y & p, y & ~p, ~y & ~p]):
        cnt[:, j] = np.bincount(g, weights=w * m, minlength=ng)
    rng = np.random.default_rng(seed)
    out = []
    for s in range(0, n_boot, chunk):
        k = min(chunk, n_boot - s)
        m = rng.poisson(1.0, size=(k, ng)).astype(np.float32)
        tp, fp, fn, tn = (m @ cnt).T
        out.append(_f1_from_counts(tp, fp, fn, tn))
    return np.concatenate(out) if out else np.array([])


def ci(draws: np.ndarray, alpha: float = 0.05) -> tuple:
    if len(draws) == 0:
        return (float("nan"), float("nan"))
    return float(np.quantile(draws, alpha / 2)), float(np.quantile(draws, 1 - alpha / 2))


def composition_weights(cls_ref: np.ndarray, cls_target: np.ndarray):
    """Per-row weights on ``cls_ref`` making its weighted class mix equal the class
    mix of ``cls_target``. Returns (weights, missing_classes)."""
    pr = pd.Series(cls_ref).value_counts(normalize=True)
    pt = pd.Series(cls_target).value_counts(normalize=True)
    missing = sorted(str(c) for c in pt.index if c not in pr.index)
    ratio = (pt / pr).fillna(0.0)
    w = pd.Series(cls_ref).map(ratio).fillna(0.0).to_numpy(dtype=float)
    return w, missing


def wilson(k: int, n: int, z: float = 1.959964) -> tuple:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    lo = 0.0 if k == 0 else float(max(0.0, c - h))   # exact bounds at the edges (floating-point
    hi = 1.0 if k == n else float(min(1.0, c + h))    # rounding gave e.g. 2e-19 instead of 0)
    return lo, hi
