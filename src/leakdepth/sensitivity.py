"""Split-unit sensitivity curves with training- and test-composition controls."""
from __future__ import annotations

import json
import os
import time
import zlib
from collections.abc import Callable, Iterable, Sequence

import numpy as np
import pandas as pd

from . import groups as G
from .audit import FEW_GROUPS, input_record
from .metrics import bootstrap_f1, ci, composition_weights, macro_f1
from .report import Finding, Report
from .split import check_validity, constrained_group_split, leave_one_group_out
from .table import FlowTable

DEFAULT_LEVELS = ("dup", "5tuple", "hostpair", "session:60", "session:300", "session:1800", "capture")


def _signed_log1p(X):
    return np.sign(X) * np.log1p(np.abs(X))


def make_model(name: str, seed: int):
    """Built-in models: 'hgb', 'rf', 'lr' (signed log1p + scaling)."""
    from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import FunctionTransformer, StandardScaler
    if name == "hgb":
        return HistGradientBoostingClassifier(random_state=seed)
    if name == "rf":
        return make_pipeline(SimpleImputer(strategy="median"),
                             RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=seed))
    if name == "lr":
        return make_pipeline(SimpleImputer(strategy="median"), FunctionTransformer(_signed_log1p),
                             StandardScaler(), LogisticRegression(solver="saga", max_iter=100, tol=1e-3,
                                                                  random_state=seed))
    raise KeyError(f"unknown model '{name}' (use 'hgb', 'rf', 'lr' or pass a callable)")


def stratified_cap(idx: np.ndarray, cls: np.ndarray, cap: int, rng) -> np.ndarray:
    """At most ``cap`` rows of ``idx``, keeping the class mix."""
    if cap is None or len(idx) <= cap:
        return np.sort(idx)
    out = []
    c = cls[idx]
    for k in np.unique(c):
        ii = idx[c == k]
        n = max(1, int(round(cap * len(ii) / len(idx))))
        out.append(rng.choice(ii, size=min(n, len(ii)), replace=False))
    return np.sort(np.concatenate(out))


def matched_sample(pool: np.ndarray, cls: np.ndarray, target_cls: np.ndarray, n: int, rng) -> np.ndarray:
    """``n`` rows of ``pool`` with the class mix of ``target_cls`` (limited by availability)."""
    mix = pd.Series(target_cls).value_counts(normalize=True)
    pc = cls[pool]
    out = []
    for k, p in mix.items():
        ii = pool[pc == k]
        m = min(int(round(n * p)), len(ii))
        if m > 0:
            out.append(rng.choice(ii, size=m, replace=False))
    return np.sort(np.concatenate(out)) if out else np.array([], dtype=int)


def _fit_predict(model_fn, X: pd.DataFrame, y: np.ndarray, tr, te):
    if len(np.unique(y[tr])) < 2:
        return None
    m = model_fn()
    m.fit(X.iloc[tr], y[tr])
    return m.predict(X.iloc[te]).astype(np.int8)


def _splits(t: FlowTable, unit: str, test_frac: float, seed: int, tries: int):
    g = G.extract(t, unit)
    benign = str(t.cols.benign)
    ng = len(np.unique(g))
    if ng < 2:
        return g, [], "none"
    if ng < FEW_GROUPS:
        folds = []
        for gid, tr, te in leave_one_group_out(g):
            v = check_validity(t.cls, t.y, tr, te, benign)
            folds.append((str(gid), tr, te, v))
        return g, folds, "leave-one-group-out"
    tr, te, v = constrained_group_split(g, t.cls, t.y, test_frac, seed, benign, tries)
    return g, [("0", tr, te, v)], "group-split"


def _load_done(path):
    done = {}
    if path and os.path.exists(path):
        with open(path) as f:
            for line in f:
                r = json.loads(line)
                done[(r["seed"], r["unit"], r["model"], r["fold"])] = r
    return done


FEW_CI_GROUPS = 10  # group-bootstrap intervals over fewer test groups are flagged as uninformative


def sensitivity(t: FlowTable, levels: Iterable[str] = DEFAULT_LEVELS, models: Sequence = ("hgb",),
                seeds: Sequence[int] = (0,), test_frac: float = 0.2, train_cap: int | None = 300_000,
                n_boot: int = 1000, tries: int = 50, resume: str | None = None,
                log: Callable[[str], None] | None = None) -> Report:
    """For each level, seed and model: F(L) on L's split, and two controls built on
    the row-random split L0: C_train (L0 train matched to L's training size and
    class mix, scored on L0 test) and C_full (C_train scored on L0 test reweighted
    to L's test class mix). Folds/results are appended to ``resume`` (JSONL) and
    skipped when rerun."""
    levels = [u for u in levels if G.supported(t, u) and u != "row"]
    X = t.X("float32")
    y, cls = t.y, t.cls
    done = _load_done(resume)
    rows, comp, invalid = [], [], []

    def emit(r):
        rows.append(r)
        if resume:
            with open(resume, "a") as f:
                f.write(json.dumps(r) + "\n")

    for seed in seeds:
        rng = np.random.default_rng(10_000 + seed)
        tr0, te0, v0 = constrained_group_split(np.arange(len(t)), cls, y, test_frac, seed, str(t.cols.benign), tries)
        tr0c = stratified_cap(tr0, cls, train_cap, rng)
        for mi, mname in enumerate(models):
            label = mname if isinstance(mname, str) else getattr(mname, "__name__", f"model{mi}")
            mfn = (lambda s=seed, n=mname: make_model(n, s)) if isinstance(mname, str) else (lambda n=mname: n())
            key0 = (seed, "row", label, "0")
            if key0 in done:
                rows.append(done[key0])
                f0 = done[key0]["F"]
            else:
                p0 = _fit_predict(mfn, X, y, tr0c, te0)
                f0 = macro_f1(y[te0], p0)
                lo, hi = ci(bootstrap_f1(y[te0], p0, None, None, n_boot, seed))
                emit({"seed": seed, "unit": "row", "model": label, "fold": "0", "valid": True, "F": f0,
                      "F_lo": lo, "F_hi": hi, "n_train": len(tr0c), "n_test": len(te0),
                      "test_attack_share": float(y[te0].mean())})
            for unit in levels:
                g, folds, scheme = _splits(t, unit, test_frac, seed, tries)
                if not any(v.valid for *_, v in folds):
                    if mi == 0:
                        invalid.append({"seed": seed, "unit": unit, "scheme": scheme,
                                        "reasons": sorted({r for *_, v in folds for r in v.reasons}) or ["fewer than two groups"]})
                    continue
                for fid, tr, te, v in folds:
                    if not v.valid:
                        continue
                    key = (seed, unit, label, fid)
                    if key in done:
                        rows.append(done[key])
                        continue
                    t0 = time.time()
                    frng = np.random.default_rng([seed, zlib.crc32(unit.encode()), zlib.crc32(fid.encode())])
                    trc = stratified_cap(tr, cls, train_cap, frng)
                    pL = _fit_predict(mfn, X, y, trc, te)
                    if pL is None:
                        continue
                    fL = macro_f1(y[te], pL)
                    dL = bootstrap_f1(y[te], pL, g[te], None, n_boot, seed + 1)
                    ctr = matched_sample(tr0, cls, cls[trc], len(trc), frng)
                    pc = _fit_predict(mfn, X, y, ctr, te0)
                    fct = macro_f1(y[te0], pc)
                    dct = bootstrap_f1(y[te0], pc, None, None, n_boot, seed + 2)
                    w, miss = composition_weights(cls[te0], cls[te])
                    if miss:
                        fcf, dcf = float("nan"), np.array([])
                    else:
                        fcf = macro_f1(y[te0], pc, w)
                        dcf = bootstrap_f1(y[te0], pc, None, w, n_boot, seed + 2)
                    r = {"seed": seed, "unit": unit, "model": label, "fold": fid, "scheme": scheme, "valid": True,
                         "tries": v.tries, "n_train": len(trc), "n_test": len(te),
                         "test_attack_share": float(y[te].mean()), "F": fL, "F_lo": ci(dL)[0], "F_hi": ci(dL)[1],
                         "F_L0": f0, "C_train": fct, "C_full": fcf, "d_raw": f0 - fL, "d_train": fct - fL,
                         "d_train_lo": ci(dct - dL)[0], "d_train_hi": ci(dct - dL)[1],
                         "d_full": fcf - fL if not miss else float("nan"),
                         "d_full_lo": ci(dcf - dL)[0] if not miss else float("nan"),
                         "d_full_hi": ci(dcf - dL)[1] if not miss else float("nan"),
                         "classes_missing_from_L0_test": miss,
                         "n_test_groups": int(len(np.unique(g[te]))),
                         "ci_few_groups": bool(len(np.unique(g[te])) < FEW_CI_GROUPS),
                         "seconds": round(time.time() - t0, 2)}
                    emit(r)
                    if log:
                        log(f"seed {seed} {label} {unit} fold {fid}: F={fL:.4f} d_full={r['d_full']:.4f}")
                    if mi == 0:
                        cc = pd.Series(cls[te]).value_counts(normalize=True)
                        comp.append({"seed": seed, "unit": unit, "fold": fid,
                                     **{str(k): round(float(val), 6) for k, val in cc.items()}})
    rep = Report("sensitivity", inputs=[input_record(t)],
                 config={"levels": list(levels), "models": [m if isinstance(m, str) else str(m) for m in models],
                         "seeds": list(seeds), "test_frac": test_frac, "train_cap": train_cap, "n_boot": n_boot})
    curve = summarize(pd.DataFrame(rows)) if rows else pd.DataFrame()
    rep.results["curve"] = curve
    rep.results["folds"] = pd.DataFrame(rows)
    rep.results["test_composition"] = pd.DataFrame(comp).fillna(0.0) if comp else pd.DataFrame()
    rep.results["invalid_levels"] = invalid
    few = sorted({r["unit"] for r in rows if r.get("ci_few_groups")})
    for u in few:
        ng = min(r["n_test_groups"] for r in rows if r.get("unit") == u and r.get("ci_few_groups"))
        rep.add(Finding("interval-few-groups", "sensitivity", "INFO",
                        f"level {u}: group-bootstrap intervals use as few as {ng} test groups (< {FEW_CI_GROUPS}) "
                        "and are not informative; compare seeds instead", u, {"min_test_groups": ng}))
    for u in sorted({i["unit"] for i in invalid}):
        rs = sorted({r for i in invalid if i["unit"] == u for r in i["reasons"]})
        rep.add(Finding(f"invalid-{u.split(':')[0]}", "unit-validity", "WARN",
                        f"level {u} not scored (no valid split): " + "; ".join(rs), u, {"reasons": rs}))
    return rep


def summarize(folds: pd.DataFrame) -> pd.DataFrame:
    """Mean over folds, then over seeds, per (unit, model)."""
    num = [c for c in ("F", "C_train", "C_full", "d_raw", "d_train", "d_full", "test_attack_share") if c in folds]
    per_seed = folds.groupby(["unit", "model", "seed"], sort=False)[num].mean().reset_index()
    out = per_seed.groupby(["unit", "model"], sort=False)[num].agg(["mean", "std"])
    out.columns = [f"{a}_{b}" for a, b in out.columns]
    out = out.reset_index()
    out["n_seeds"] = per_seed.groupby(["unit", "model"], sort=False).size().to_numpy()
    return out
