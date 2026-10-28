"""Row-level lineage between two corpora whose schemas may differ.

Steps: (1) profile columns; (2) align columns by normalised name, then by value
distribution (Hungarian assignment), refined by agreement on matched rows;
(3) canonicalise aligned values (common decimal precision, significant digits);
(4) find candidate row pairs by locality-sensitive banding over column subsets and
verify each pair column by column; (5) estimate containment in both directions.

Matchers. ``matcher="a10"`` (default since 0.1.1) additionally requires that the values on
which a candidate pair agrees carry at least ``log2(n_B) + info_margin`` bits of
self-information, estimated from value frequencies in the other corpus. This rejects
chance agreement on low-information values (labels, a few host addresses, zero counters).
``matcher="frozen"`` reproduces version 0.1.0 exactly. The A10 rule was added after the
0.1.0 negative controls on real corpora failed; see CHANGELOG.md.

Since 0.1.3, :func:`lineage` also reports, per direction, (i) the containment found by the
other matcher (``other_matcher``; findings and severities come from ``matcher`` only), and
(ii) a within-corpus baseline (``baseline``): the containment of a random half of the
searched-from corpus in its other half, on the same columns. Containment far above the
baseline is more informative than containment near it; corpora built with the same flow
extractor can share many near-identical short flows without sharing provenance.
"""
from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from scipy.optimize import linear_sum_assignment

from .metrics import wilson
from .report import Finding, Report, frame_digest

SYNONYMS = {
    "sourceip": "srcip", "srcaddr": "srcip", "saddr": "srcip", "ipsrc": "srcip", "srcipaddr": "srcip",
    "destinationip": "dstip", "dstaddr": "dstip", "daddr": "dstip", "ipdst": "dstip", "dstipaddr": "dstip",
    "sourceport": "srcport", "sport": "srcport", "srcpt": "srcport",
    "destinationport": "dstport", "dport": "dstport", "dsport": "dstport", "dstpt": "dstport",
    "protocol": "proto", "ipproto": "proto",
    "flowduration": "duration", "dur": "duration",
    "label": "label", "class": "label", "attacklabel": "label", "attackcat": "label",
}
N_QUANT = 21
MIN_DISTINCT = 50       # value-overlap alignment only for high-cardinality columns
MIN_SHARED = 10
MIN_VALUE_OVERLAP = 0.005
MATCHERS = ("a10", "frozen")
DEFAULT_INFO_MARGIN = 20.0


def norm_name(c) -> str:
    s = re.sub(r"[^a-z0-9]", "", str(c).lower())
    return SYNONYMS.get(s, s)


@dataclass
class ColumnProfile:
    name: str
    kind: str  # 'num', 'str' or 'const'
    q: np.ndarray | None = None
    zero: float = 0.0
    nan: float = 0.0
    decimals: int | None = None
    top: frozenset = field(default_factory=frozenset)
    const: object = None
    values: np.ndarray | None = None  # sample of distinct finite values
    n_distinct: int = 0


def detect_decimals(v: np.ndarray, max_d: int = 8) -> int | None:
    """Smallest number of decimals that represents (almost) all values exactly."""
    v = v[np.isfinite(v)]
    if len(v) == 0:
        return 0
    v = v[:20000]
    tol = np.maximum(4 * np.spacing(np.abs(v)), 1e-12)
    for d in range(max_d + 1):
        if np.mean(np.abs(v - np.round(v, d)) <= tol) >= 0.999:
            return d
    return None


def _as_numeric(s: pd.Series):
    if pd.api.types.is_bool_dtype(s):
        return s.astype(float)
    if pd.api.types.is_numeric_dtype(s):
        return pd.to_numeric(s, errors="coerce").astype("float64")
    v = pd.to_numeric(s, errors="coerce")
    nonnull = s.notna() & (s.astype(str).str.strip() != "")
    if nonnull.sum() and v[nonnull].notna().mean() >= 0.95:
        return v.astype("float64")
    return None


def profile_columns(df: pd.DataFrame, sample_n: int = 200_000, seed: int = 0) -> dict:
    s = df.sample(n=min(sample_n, len(df)), random_state=seed) if len(df) > sample_n else df
    out = {}
    for c in s.columns:
        v = _as_numeric(s[c])
        if v is not None:
            a = v.to_numpy(dtype="float64")
            fin = a[np.isfinite(a)]
            uniq = np.unique(fin) if len(fin) else np.array([])
            nanshare = float(np.mean(~np.isfinite(a))) if len(a) else 0.0
            if len(uniq) <= 1:
                out[c] = ColumnProfile(c, "const", nan=nanshare, const=float(uniq[0]) if len(uniq) else None)
                continue
            vals = uniq if len(uniq) <= 20000 else np.random.default_rng(seed).choice(uniq, 20000, replace=False)
            out[c] = ColumnProfile(c, "num", q=np.quantile(fin, np.linspace(0, 1, N_QUANT)),
                                   zero=float(np.mean(a == 0)), nan=nanshare, decimals=detect_decimals(fin),
                                   values=vals, n_distinct=len(uniq))
        else:
            st = s[c].astype(str).str.strip().str.lower()
            vc = st.value_counts()
            if len(vc) <= 1:
                out[c] = ColumnProfile(c, "const", const=vc.index[0] if len(vc) else None)
            else:
                out[c] = ColumnProfile(c, "str", top=frozenset(vc.index[:200]))
    return out


def _num_cost(a: ColumnProfile, b: ColumnProfile) -> float:
    pool = np.concatenate([a.q, b.q])
    scale = max(float(np.quantile(pool, 0.95) - np.quantile(pool, 0.05)), float(np.ptp(pool)) / 10, 1e-12)
    return float(np.mean(np.abs(a.q - b.q)) / scale + abs(a.zero - b.zero) + abs(a.nan - b.nan))


def value_overlap(a: ColumnProfile, b: ColumnProfile, sig: int = 6) -> tuple:
    """(share of a's sampled distinct values found among b's, number shared) after
    rounding both to their common precision."""
    dd = [d for d in (a.decimals, b.decimals) if d is not None]
    if dd:
        va, vb = np.unique(np.round(a.values, min(dd))), np.unique(np.round(b.values, min(dd)))
    else:
        va, vb = np.unique(_sig_round(a.values, sig)), np.unique(_sig_round(b.values, sig))
    k = int(np.isin(va, vb).sum())
    return k / max(1, len(va)), k


def align_columns(pa: dict, pb: dict, max_cost: float = 0.1, max_str_cost: float = 0.5) -> list:
    """Return [(col_a, col_b, cost, how)]: name matches first, then assignment."""
    pairs, used_a, used_b = [], set(), set()
    nb = {}
    for c in pb:
        nb.setdefault(norm_name(c), []).append(c)
    for c, p in pa.items():
        for cb in nb.get(norm_name(c), []):
            q = pb[cb]
            if cb in used_b or p.kind != q.kind:
                continue
            if p.kind == "const" and p.const != q.const:
                continue
            pairs.append((c, cb, 0.0, "name"))
            used_a.add(c)
            used_b.add(cb)
            break
    # shared exact values among high-cardinality numeric columns: strong evidence of copying,
    # robust to mixing with unrelated rows (where value distributions differ)
    def fractional(p):  # columns of rounded or integer values share values by chance
        return p.kind == "num" and p.n_distinct >= MIN_DISTINCT and p.decimals is None

    ra = [c for c, p in pa.items() if c not in used_a and fractional(p)]
    rb = [c for c, p in pb.items() if c not in used_b and fractional(p)]
    if ra and rb:
        ov = np.zeros((len(ra), len(rb)))
        for i, a in enumerate(ra):
            for j, b in enumerate(rb):
                f1, k1 = value_overlap(pa[a], pb[b])
                f2, k2 = value_overlap(pb[b], pa[a])
                ov[i, j] = max(f1, f2) if min(k1, k2) >= MIN_SHARED else 0.0
        ii, jj = linear_sum_assignment(-ov)
        for i, j in zip(ii, jj, strict=False):
            if ov[i, j] >= MIN_VALUE_OVERLAP:
                pairs.append((ra[i], rb[j], float(1 - ov[i, j]), "values"))
                used_a.add(ra[i])
                used_b.add(rb[j])
    for kind, costf, lim in (("num", _num_cost, max_cost),
                             ("str", lambda a, b: 1 - len(a.top & b.top) / max(1, len(a.top | b.top)), max_str_cost)):
        ra = [c for c, p in pa.items() if p.kind == kind and c not in used_a]
        rb = [c for c, p in pb.items() if p.kind == kind and c not in used_b]
        if not ra or not rb:
            continue
        cost = np.array([[costf(pa[a], pb[b]) for b in rb] for a in ra])
        ii, jj = linear_sum_assignment(cost)
        for i, j in zip(ii, jj, strict=False):
            if cost[i, j] <= lim:
                pairs.append((ra[i], rb[j], float(cost[i, j]), "distribution"))
    # constant columns with equal values but different names carry no information
    return pairs


# ------------------------------------------------------------------ canonical form

def _sig_round(x: np.ndarray, sig: int) -> np.ndarray:
    out = x.copy()
    nz = np.isfinite(x) & (x != 0)
    e = np.floor(np.log10(np.abs(x[nz])))
    f = 10.0 ** (sig - 1 - e)
    out[nz] = np.round(x[nz] * f) / f
    return out


@dataclass
class Canon:
    """Canonical representation of aligned columns for one side."""
    num: np.ndarray     # float64, rounded to common decimals (verification values)
    exact: np.ndarray   # bool per numeric column: common decimals known (compare exactly)
    numh: np.ndarray    # uint64 hashes of hashing values (coarser)
    strh: np.ndarray    # uint64 hashes of string values

    @property
    def k(self) -> int:
        return self.num.shape[1] + self.strh.shape[1]

    def col_hashes(self) -> np.ndarray:
        return np.concatenate([self.numh, self.strh], axis=1)


def _hash_col(a) -> np.ndarray:
    return pd.util.hash_pandas_object(pd.Series(a), index=False).to_numpy()


def canonicalise(df: pd.DataFrame, cols: list, kinds: list, decimals: list, hash_sig: int = 5) -> Canon:
    n = len(df)
    num_cols = [(c, d) for c, k, d in zip(cols, kinds, decimals, strict=False) if k == "num"]
    str_cols = [c for c, k in zip(cols, kinds, strict=False) if k != "num"]
    num = np.empty((n, len(num_cols)))
    numh = np.empty((n, len(num_cols)), dtype=np.uint64)
    for j, (c, d) in enumerate(num_cols):
        v = _as_numeric(df[c])
        a = (v if v is not None else pd.to_numeric(df[c], errors="coerce")).to_numpy(dtype="float64")
        a = np.where(np.isfinite(a), a, np.nan)
        if d is not None:
            a = np.round(a, d)
            numh[:, j] = _hash_col(a)
        else:
            numh[:, j] = _hash_col(_sig_round(a, hash_sig))
        num[:, j] = a
    strh = np.empty((n, len(str_cols)), dtype=np.uint64)
    for j, c in enumerate(str_cols):
        strh[:, j] = _hash_col(df[c].astype(str).str.strip().str.lower().to_numpy())
    exact = np.array([d is not None for _, d in num_cols], dtype=bool)
    return Canon(num, exact, numh, strh)


def _combine(H: np.ndarray, cols: np.ndarray) -> np.ndarray:
    mult = (np.arange(1, len(cols) + 1, dtype=np.uint64) * np.uint64(0x9E3779B97F4A7C15)) | np.uint64(1)
    with np.errstate(over="ignore"):
        return (H[:, cols] * mult).sum(axis=1, dtype=np.uint64)


def band_plan(k: int, n_bands: int = 8, seed: int = 0) -> list:
    """Band 0 = all columns; then ``n_bands`` random subsets of ceil(k/2) columns."""
    rng = np.random.default_rng(seed)
    r = max(1, math.ceil(k / 2))
    bands = [np.arange(k)]
    for _ in range(n_bands):
        bands.append(np.sort(rng.choice(k, size=r, replace=False)))
    return bands


def agreement(ca: Canon, ia: np.ndarray, cb: Canon, ib: np.ndarray, rtol: float = 1e-6) -> np.ndarray:
    """Share of aligned columns on which each pair (ia[i], ib[i]) agrees. Columns with
    a known common precision must be equal after rounding; others within ``rtol``."""
    a, b = ca.num[ia], cb.num[ib]
    close = np.where(ca.exact, a == b, np.isclose(a, b, rtol=rtol, atol=0.0)) | (np.isnan(a) & np.isnan(b))
    eq = ca.strh[ia] == cb.strh[ib]
    return (close.sum(axis=1) + eq.sum(axis=1)) / max(1, ca.k)


# ------------------------------------------------------------------ matching

def _chunks(df: pd.DataFrame, size: int) -> Iterator[pd.DataFrame]:
    for s in range(0, len(df), size):
        yield df.iloc[s:s + size]


def match_rows(sample: pd.DataFrame, other, a_cols, b_cols, kinds, decimals, tau: float = 0.8,
               n_bands: int = 8, seed: int = 0, chunk: int = 200_000, info_margin: float | None = None) -> dict:
    """Verified matches of ``sample`` rows inside ``other`` (DataFrame or iterable of chunks).
    ``info_margin=None`` is the 0.1.0 matcher; a number enables the A10 information bound."""
    if info_margin is None:
        return _match_rows_frozen(sample, other, a_cols, b_cols, kinds, decimals, tau, n_bands, seed, chunk)
    return _match_rows_a10(sample, other, a_cols, b_cols, kinds, decimals, tau, n_bands, seed, chunk, info_margin)


def bits_matrix(H: np.ndarray) -> np.ndarray:
    """Self-information (bits) of each value per column, from its frequency in ``H`` (+1 smoothing)."""
    out = np.empty(H.shape, dtype=np.float64)
    n = H.shape[0]
    for j in range(H.shape[1]):
        _, inv, cnt = np.unique(H[:, j], return_inverse=True, return_counts=True)
        out[:, j] = -np.log2((cnt[inv.ravel()] + 1.0) / (n + 1.0))
    return out


def agree_mask(ca: Canon, ia: np.ndarray, cb: Canon, ib: np.ndarray, rtol: float = 1e-6) -> np.ndarray:
    """Per-column agreement (same rule and column order as :func:`agreement`)."""
    a, b = ca.num[ia], cb.num[ib]
    close = np.where(ca.exact, a == b, np.isclose(a, b, rtol=rtol, atol=0.0)) | (np.isnan(a) & np.isnan(b))
    return np.concatenate([close, ca.strh[ia] == cb.strh[ib]], axis=1)


def _match_rows_a10(sample, other, a_cols, b_cols, kinds, decimals, tau, n_bands, seed, chunk, margin) -> dict:
    ca = canonicalise(sample, a_cols, kinds, decimals)
    bands = band_plan(ca.k, n_bands, seed)
    HA = ca.col_hashes()
    BA = np.stack([_combine(HA, bd) for bd in bands], axis=1)
    n_other = len(other) if isinstance(other, pd.DataFrame) else None
    n = len(sample)
    matched = np.zeros(n, dtype=bool)
    partner = np.full(n, -1, dtype=np.int64)
    best = np.zeros(n)
    low = np.zeros(n, dtype=bool)
    offset, pairs_for_refine, need = 0, [], float("nan")
    it = _chunks(other, chunk) if isinstance(other, pd.DataFrame) else other
    for part in it:
        cb = canonicalise(part, b_cols, kinds, decimals)
        HB = cb.col_hashes()
        bits_b = bits_matrix(HB)
        need = math.log2(max(2, n_other or len(part))) + margin
        for j, bd in enumerate(bands):
            todo = ~matched
            if not todo.any():
                break
            hb = _combine(HB, bd)
            first = pd.Series(np.arange(len(hb)), index=hb)
            first = first[~first.index.duplicated()]
            cand = np.flatnonzero(todo & np.isin(BA[:, j], first.index.to_numpy()))
            if len(cand) == 0:
                continue
            ib = first.loc[BA[cand, j]].to_numpy()
            mask = agree_mask(ca, cand, cb, ib)
            ag = mask.sum(axis=1) / max(1, ca.k)
            info = (mask * bits_b[ib]).sum(axis=1)
            best[cand] = np.maximum(best[cand], ag)
            pt = ag >= tau
            ok = pt & (info >= need)
            low[cand[pt & ~ok]] = True
            matched[cand[ok]] = True
            partner[cand[ok]] = ib[ok] + offset
            strong = ok & (ag >= 0.999)
            if strong.any() and sum(len(p[0]) for p in pairs_for_refine) < 5000:
                pairs_for_refine.append((cand[strong][:2000], part.iloc[ib[strong][:2000]]))
        offset += len(part)
        if matched.all():
            break
    low &= ~matched
    return {"matched": matched, "partner": partner, "best_agreement": best, "refine_pairs": pairs_for_refine,
            "rejected_low_info": low, "info_needed": need}


def _match_rows_frozen(sample: pd.DataFrame, other, a_cols, b_cols, kinds, decimals, tau: float = 0.8,
                       n_bands: int = 8, seed: int = 0, chunk: int = 200_000) -> dict:
    """The 0.1.0 matcher, unchanged."""
    ca = canonicalise(sample, a_cols, kinds, decimals)
    bands = band_plan(ca.k, n_bands, seed)
    HA = ca.col_hashes()
    BA = np.stack([_combine(HA, bd) for bd in bands], axis=1)
    matched = np.zeros(len(sample), dtype=bool)
    partner = np.full(len(sample), -1, dtype=np.int64)
    best = np.zeros(len(sample))
    offset = 0
    pairs_for_refine = []
    it = _chunks(other, chunk) if isinstance(other, pd.DataFrame) else other
    for part in it:
        cb = canonicalise(part, b_cols, kinds, decimals)
        HB = cb.col_hashes()
        for j, bd in enumerate(bands):
            todo = ~matched
            if not todo.any():
                break
            hb = _combine(HB, bd)
            first = pd.Series(np.arange(len(hb)), index=hb)
            first = first[~first.index.duplicated()]
            cand = np.flatnonzero(todo & np.isin(BA[:, j], first.index.to_numpy()))
            if len(cand) == 0:
                continue
            ib = first.loc[BA[cand, j]].to_numpy()
            ag = agreement(ca, cand, cb, ib)
            best[cand] = np.maximum(best[cand], ag)
            ok = ag >= tau
            matched[cand[ok]] = True
            partner[cand[ok]] = ib[ok] + offset
            strong = ag >= 0.999
            if strong.any() and sum(len(p[0]) for p in pairs_for_refine) < 5000:
                pairs_for_refine.append((cand[strong][:2000], part.iloc[ib[strong][:2000]]))
        offset += len(part)
        if matched.all():
            break
    return {"matched": matched, "partner": partner, "best_agreement": best, "refine_pairs": pairs_for_refine}


def _refine(sample: pd.DataFrame, pairs, pa: dict, pb: dict, aligned: list, min_agree: float = 0.9) -> list:
    """Add alignments for numeric columns left unaligned, using value agreement on
    verified row pairs (columns may have been renamed and mixed with other data,
    which defeats distribution matching)."""
    ia = np.concatenate([p[0] for p in pairs]) if pairs else np.array([], dtype=int)
    if len(ia) < 20:
        return aligned
    rows_b = pd.concat([p[1] for p in pairs], ignore_index=True)
    rows_a = sample.iloc[ia].reset_index(drop=True)
    used_a = {x[0] for x in aligned}
    used_b = {x[1] for x in aligned}
    na = [c for c, p in pa.items() if p.kind == "num" and c not in used_a]
    nb = [c for c, p in pb.items() if p.kind == "num" and c not in used_b]
    if not na or not nb:
        return aligned
    A = np.stack([_as_numeric(rows_a[c]).to_numpy(dtype=float) for c in na], axis=1)
    B = np.stack([_as_numeric(rows_b[c]).to_numpy(dtype=float) for c in nb], axis=1)
    agree = np.zeros((len(na), len(nb)))
    for i, c in enumerate(na):
        for j, d in enumerate(nb):
            dd = [x for x in (pa[c].decimals, pb[d].decimals) if x is not None]
            a, b = A[:, i], B[:, j]
            if dd:
                a, b = np.round(a, min(dd)), np.round(b, min(dd))
                eq = a == b
            else:
                eq = np.isclose(a, b, rtol=1e-6, atol=0.0)
            agree[i, j] = np.mean(eq | (np.isnan(a) & np.isnan(b)))
    ii, jj = linear_sum_assignment(-agree)
    extra = [(na[i], nb[j], float(1 - agree[i, j]), "row-agreement")
             for i, j in zip(ii, jj, strict=False) if agree[i, j] >= min_agree]
    return aligned + extra


STRONG = ("name", "values")


def _containment(sa: pd.DataFrame, b_full, pa, pb, aligned, tau, n_bands, seed, chunk, refine=True,
                 min_aligned: int = 4, info_margin: float | None = None):
    """Match rows; when enough strongly aligned columns exist, the first pass uses
    only those, and the remaining columns are re-aligned by agreement on matched rows."""
    if refine:
        strong = [x for x in aligned if x[3] in STRONG]
        first = strong if len(strong) >= min_aligned else aligned
        res, _ = _containment(sa, b_full, pa, pb, first, tau, n_bands, seed, chunk, refine=False,
                              info_margin=info_margin)
        new = _refine(sa, res["refine_pairs"], pa, pb, first)
        if len(new) > len(first) or first is not aligned:
            final = new if len(new) > len(first) else aligned
            return _containment(sa, b_full, pa, pb, final, tau, n_bands, seed, chunk, refine=False,
                                info_margin=info_margin)
        return res, first
    a_cols = [x[0] for x in aligned]
    b_cols = [x[1] for x in aligned]
    kinds = ["num" if pa[a].kind == "num" else "str" for a in a_cols]
    decs = []
    for a, b, k in zip(a_cols, b_cols, kinds, strict=False):
        dd = [d for d in (pa[a].decimals, pb[b].decimals) if d is not None] if k == "num" else []
        decs.append(min(dd) if dd else None)
    res = match_rows(sa, b_full, a_cols, b_cols, kinds, decs, tau, n_bands, seed, chunk, info_margin=info_margin)
    return res, aligned


def _self_baseline(x: pd.DataFrame, px: dict, cols: list, sample_n: int, tau: float, n_bands: int, seed: int,
                   chunk: int, min_aligned: int, margin: float | None) -> dict | None:
    """Containment of a random half of ``x`` in its other half, on ``cols`` (identity alignment)."""
    if len(x) < 4 or len(cols) < min_aligned:
        return None
    perm = np.random.default_rng(seed).permutation(len(x))
    m = len(x) // 2
    h1 = x.iloc[perm[:m]].reset_index(drop=True)
    h2 = x.iloc[perm[m:]].reset_index(drop=True)
    s1 = h1.sample(n=sample_n, random_state=seed).reset_index(drop=True) if len(h1) > sample_n else h1
    al = [(c, c, 0.0, "identity") for c in cols]
    res, _ = _containment(s1, h2, px, px, al, tau, n_bands, seed, chunk, refine=False,
                          min_aligned=min_aligned, info_margin=margin)
    k = int(res["matched"].sum())
    lo, hi = wilson(k, len(s1))
    return {"sampled_rows": len(s1), "matched": k, "containment": k / len(s1), "ci_lo": lo, "ci_hi": hi,
            "columns": len(cols)}


def lineage(a: pd.DataFrame, b: pd.DataFrame, name_a: str = "A", name_b: str = "B", sample_n: int = 200_000,
            tau: float = 0.8, n_bands: int = 8, seed: int = 0, min_aligned: int = 4, max_cost: float = 0.1,
            warn_at: float = 0.01, error_at: float = 0.5, chunk: int = 200_000,
            exclude: tuple = (), matcher: str = "a10", info_margin: float = DEFAULT_INFO_MARGIN,
            compare_matchers: bool = True, baseline: bool = True) -> Report:
    """Estimate C(A⊂B) and C(B⊂A): the share of rows of one corpus found in the other.

    ``matcher="a10"`` (default) applies the minimum-information bound of ``info_margin`` bits;
    ``matcher="frozen"`` reproduces leakdepth 0.1.0. Findings (and so ``gate``) use ``matcher``
    only. With ``compare_matchers`` the other matcher's containment is reported alongside;
    with ``baseline`` the within-corpus containment of a random half in the other half is
    reported for each direction. Both are informational and multiply the run time."""
    margin = _margin(matcher, info_margin)
    other = "frozen" if matcher == "a10" else "a10"
    other_margin = _margin(other, info_margin)
    a = a.drop(columns=[c for c in exclude if c in a.columns])
    b = b.drop(columns=[c for c in exclude if c in b.columns])
    rep = Report("lineage", inputs=[{"name": name_a, "rows": len(a), "columns": a.shape[1], "sha256": frame_digest(a)},
                                    {"name": name_b, "rows": len(b), "columns": b.shape[1], "sha256": frame_digest(b)}],
                 config={"sample_n": sample_n, "tau": tau, "n_bands": n_bands, "seed": seed, "min_aligned": min_aligned,
                         "max_cost": max_cost, "warn_at": warn_at, "error_at": error_at,
                         "matcher": matcher, "info_margin": margin,
                         "compare_matchers": compare_matchers, "baseline": baseline})
    pa, pb = profile_columns(a, sample_n, seed), profile_columns(b, sample_n, seed)
    aligned = align_columns(pa, pb, max_cost)
    informative = [x for x in aligned if pa[x[0]].kind != "const"]
    rep.results["alignment"] = [{"a": x[0], "b": x[1], "cost": round(x[2], 5), "how": x[3]} for x in informative]
    if len(informative) < min_aligned:
        rep.add(Finding("lineage-not-comparable", "lineage", "INFO",
                        f"only {len(informative)} informative columns aligned (< {min_aligned}); containment not estimated",
                        None, {"aligned": len(informative)}))
        rep.results["containment"] = []
        return rep
    out = []
    for (x, y, nx, ny, px, py, al) in (
            (a, b, name_a, name_b, pa, pb, informative),
            (b, a, name_b, name_a, pb, pa, [(q, p, c, h) for p, q, c, h in informative])):
        sx = x.sample(n=min(sample_n, len(x)), random_state=seed) if len(x) > sample_n else x
        sx = sx.reset_index(drop=True)
        res, used = _containment(sx, y, px, py, al, tau, n_bands, seed, chunk,
                                 min_aligned=min_aligned, info_margin=margin)
        k = int(res["matched"].sum())
        lo, hi = wilson(k, len(sx))
        c = k / len(sx) if len(sx) else 0.0
        out.append({"direction": f"{nx} in {ny}", "sampled_rows": len(sx), "matched": k, "containment": c,
                    "ci_lo": lo, "ci_hi": hi, "aligned_columns": len(used),
                    "refined": any(h == "row-agreement" for *_, h in used),
                    "rejected_low_info": int(res["rejected_low_info"].sum()) if "rejected_low_info" in res else None})
        if compare_matchers:
            r2, _ = _containment(sx, y, px, py, al, tau, n_bands, seed, chunk,
                                 min_aligned=min_aligned, info_margin=other_margin)
            k2 = int(r2["matched"].sum())
            lo2, hi2 = wilson(k2, len(sx))
            out[-1]["other_matcher"] = {"matcher": other, "matched": k2, "containment": k2 / len(sx) if len(sx) else 0.0,
                                        "ci_lo": lo2, "ci_hi": hi2}
        if baseline:
            out[-1]["baseline"] = _self_baseline(x, px, [u[0] for u in used], sample_n, tau, n_bands, seed, chunk,
                                                 min_aligned, margin)
        extra = ""
        if out[-1].get("baseline"):
            extra += f"; within-{nx} baseline {out[-1]['baseline']['containment']:.2%}"
        if out[-1].get("other_matcher"):
            extra += f"; {other} matcher {out[-1]['other_matcher']['containment']:.2%}"
        sev = "ERROR" if c >= error_at else ("WARN" if c >= warn_at else "INFO")
        rep.add(Finding("lineage-containment", "lineage", sev,
                        f"{c:.2%} of {nx} rows (95% CI {lo:.2%}-{hi:.2%}) found in {ny}{extra}", None, out[-1]))
    rep.results["containment"] = out
    return rep


def _margin(matcher: str, info_margin: float | None) -> float | None:
    if matcher not in MATCHERS:
        raise ValueError(f"matcher must be one of {MATCHERS}, got {matcher!r}")
    if matcher == "frozen":
        return None
    if info_margin is None or not np.isfinite(info_margin):
        raise ValueError("info_margin must be a finite number of bits for matcher='a10'")
    return float(info_margin)


def lineage_matches(a: pd.DataFrame, b: pd.DataFrame, sample_n: int = 200_000, tau: float = 0.8, n_bands: int = 8,
                    seed: int = 0, min_aligned: int = 4, max_cost: float = 0.1, chunk: int = 200_000,
                    matcher: str = "a10", info_margin: float = DEFAULT_INFO_MARGIN) -> dict:
    """Row-level result for the direction A-in-B, with the same steps as :func:`lineage`.

    Returns ``index`` (positions of the sampled A rows in ``a``), ``matched`` (bool per sampled row),
    ``partner`` (row position in ``b`` or -1) and the alignment used; ``matched`` is None when fewer
    than ``min_aligned`` informative columns align."""
    margin = _margin(matcher, info_margin)
    pa, pb = profile_columns(a, sample_n, seed), profile_columns(b, sample_n, seed)
    informative = [x for x in align_columns(pa, pb, max_cost) if pa[x[0]].kind != "const"]
    a0 = a.reset_index(drop=True)
    sx = a0.sample(n=sample_n, random_state=seed) if len(a0) > sample_n else a0
    pos = sx.index.to_numpy()
    if len(informative) < min_aligned:
        return {"index": pos, "matched": None, "partner": None, "aligned": informative}
    sx = sx.reset_index(drop=True)
    res, used = _containment(sx, b, pa, pb, informative, tau, n_bands, seed, chunk, min_aligned=min_aligned,
                             info_margin=margin)
    return {"index": pos, "matched": res["matched"], "partner": res["partner"], "aligned": used}


def key_join_containment(ta, tb, window: float = 120.0, sample_n: int = 200_000, seed: int = 0) -> dict:
    """Share of A flows whose canonical 5-tuple occurs in B within ``window`` seconds
    after removing a global clock offset (mode of time differences, 1-s bins)."""
    from .groups import _sorted_pair

    def keys(t):
        e1 = pd.Series(t.meta("src")) + ":" + pd.Series(t.meta("sport"))
        e2 = pd.Series(t.meta("dst")) + ":" + pd.Series(t.meta("dport"))
        lo, hi = _sorted_pair(e1.to_numpy(), e2.to_numpy())
        pr = pd.Series(t.meta("proto")).str.lower() if t.has("proto") else ""
        return pd.util.hash_pandas_object(pd.Series(lo) + "|" + pd.Series(hi) + "|" + pr, index=False).to_numpy()

    rng = np.random.default_rng(seed)
    ia = np.arange(len(ta)) if len(ta) <= sample_n else np.sort(rng.choice(len(ta), sample_n, replace=False))
    A = pd.DataFrame({"k": keys(ta)[ia], "ta": ta.time[ia], "i": np.arange(len(ia))})
    B = pd.DataFrame({"k": keys(tb), "tb": tb.time})
    m = A.merge(B, on="k", how="inner")
    if m.empty:
        return {"sampled_rows": len(ia), "matched": 0, "containment": 0.0, "offset_s": None}
    dt = (m["ta"] - m["tb"]).to_numpy()
    off = float(pd.Series(np.round(dt)).mode().iloc[0])
    ok = np.abs(dt - off) <= window
    k = int(m.loc[ok, "i"].nunique())
    lo, hi = wilson(k, len(ia))
    return {"sampled_rows": len(ia), "matched": k, "containment": k / len(ia), "ci_lo": lo, "ci_hi": hi,
            "offset_s": off, "window_s": window}
