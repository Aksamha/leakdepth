"""Audits: leakage of an existing split per unit, validity of group splits per unit,
and capture-level checks."""
from __future__ import annotations

from collections.abc import Iterable, Sequence

import numpy as np
import pandas as pd

from . import groups as G
from .report import Finding, Report, frame_digest
from .split import check_validity, confined_classes, constrained_group_split, leave_one_group_out
from .table import FlowTable

DEFAULT_UNITS = ("row", "dup", "5tuple", "hostpair", "session:300", "capture")
FEW_GROUPS = 10  # units with fewer groups are evaluated by leave-one-group-out


def default_thresholds(cross_capture: bool = False) -> dict:
    """Overlap share (of test rows) at or above which a finding is raised, and its severity."""
    return {"dup": (0.0, "ERROR"), "5tuple": (0.005, "WARN"), "hostpair": (0.005, "WARN"),
            "session": (0.005, "WARN"), "capture": (0.0, "ERROR" if cross_capture else "INFO")}


def concat(train: FlowTable, test: FlowTable) -> tuple:
    """Stack two tables with the same column map; return (table, train_idx, test_idx)."""
    if train.cols != test.cols:
        raise ValueError("train and test use different column maps")
    df = pd.concat([train.df, test.df], ignore_index=True)
    n = len(train)
    return FlowTable(df, train.cols, train.name), np.arange(n), np.arange(n, len(df))


def input_record(t: FlowTable) -> dict:
    return {"name": t.name, "rows": len(t), "columns": t.df.shape[1], "sha256": frame_digest(t.df)}


def _units(t: FlowTable, units: Iterable[str] | None) -> list:
    return [u for u in (units or DEFAULT_UNITS) if G.supported(t, u)]


def split_overlap(t: FlowTable, tr: np.ndarray, te: np.ndarray, unit: str) -> dict:
    g = G.extract(t, unit)
    gtr = np.unique(g[tr])
    shared_rows = np.isin(g[te], gtr)
    gte = np.unique(g[te])
    return {"unit": unit, "n_groups": len(np.unique(g)),
            "test_rows_overlapping": int(shared_rows.sum()),
            "overlap_share": float(shared_rows.mean()) if len(te) else 0.0,
            "test_groups_shared": float(np.isin(gte, gtr).mean()) if len(gte) else 0.0}


def audit_split(t: FlowTable, train_idx: Sequence[int], test_idx: Sequence[int],
                units: Iterable[str] | None = None, cross_capture: bool = False,
                thresholds: dict | None = None, report: Report | None = None) -> Report:
    """Measure, for every unit, how much of the test set shares a group with train."""
    tr, te = np.asarray(train_idx), np.asarray(test_idx)
    rep = report or Report("audit", inputs=[input_record(t)])
    th = default_thresholds(cross_capture) | (thresholds or {})
    rows = []
    idx_overlap = np.intersect1d(tr, te)
    if len(idx_overlap):
        rep.add(Finding("index-overlap", "split", "ERROR", f"{len(idx_overlap)} row indices are in both train and test",
                        "row", {"n": len(idx_overlap)}))
    for u in _units(t, units):
        if u == "row":
            continue
        r = split_overlap(t, tr, te, u)
        rows.append(r)
        base = u.split(":")[0]
        if base in th:
            lim, sev = th[base]
            hit = r["overlap_share"] > 0 if lim == 0 else r["overlap_share"] >= lim
            if hit:
                rep.add(Finding(f"overlap-{base}", "split-overlap", sev,
                                f"{r['overlap_share']:.2%} of test rows share a {u} group with train",
                                u, r))
    rep.results["split_overlap"] = rows
    rep.config.setdefault("audit", {}).update({"units": list(_units(t, units)), "cross_capture": cross_capture,
                                                "thresholds": {k: list(v) for k, v in th.items()}})
    return rep


def unit_validity(t: FlowTable, unit: str, test_frac: float = 0.2, seed: int = 0,
                  tries: int = 50) -> dict:
    """Validity of a fresh group split at ``unit`` (leave-one-group-out when there
    are fewer than ``FEW_GROUPS`` groups: valid if at least one fold is valid)."""
    g = G.extract(t, unit)
    ng = len(np.unique(g))
    benign = str(t.cols.benign)
    out = {"unit": unit, "n_groups": ng, "confined_classes": confined_classes(g, t.cls, benign)}
    if ng < 2:
        return out | {"scheme": "none", "valid": False, "reasons": ["fewer than two groups"], "folds_valid": 0}
    if ng < FEW_GROUPS:
        folds = []
        for _gid, tr, te in leave_one_group_out(g):
            v = check_validity(t.cls, t.y, tr, te, benign)
            folds.append(v)
        ok = [v for v in folds if v.valid]
        reasons = sorted({r for v in folds for r in v.reasons})
        return out | {"scheme": "leave-one-group-out", "valid": bool(ok), "folds": len(folds),
                      "folds_valid": len(ok), "reasons": [] if ok else reasons}
    tr, te, v = constrained_group_split(g, t.cls, t.y, test_frac, seed, benign, tries)
    return out | {"scheme": "group-split", "valid": v.valid, "tries": v.tries, "reasons": v.reasons,
                  "warnings": v.warnings, "test_fraction": v.test_fraction,
                  "test_attack_share": v.test_attack_share}


def audit_units(t: FlowTable, units: Iterable[str] | None = None, test_frac: float = 0.2, seed: int = 0,
                report: Report | None = None) -> Report:
    rep = report or Report("audit", inputs=[input_record(t)])
    rows = []
    for u in _units(t, units):
        if u == "row":
            continue
        r = unit_validity(t, u, test_frac, seed)
        rows.append(r)
        if not r["valid"]:
            rep.add(Finding(f"invalid-{u.split(':')[0]}", "unit-validity", "WARN",
                            f"no valid split at unit {u}: " + "; ".join(r["reasons"]), u, r))
        elif r["scheme"] == "leave-one-group-out" and r["folds_valid"] < r["folds"]:
            rep.add(Finding(f"partial-{u.split(':')[0]}", "unit-validity", "INFO",
                            f"{r['folds'] - r['folds_valid']} of {r['folds']} held-out {u} folds are invalid", u, r))
    rep.results["unit_validity"] = rows
    rep.config.setdefault("audit", {}).update({"test_frac": test_frac, "seed": seed})
    return rep


def capture_checks(t: FlowTable, min_diff: float = 0.5, report: Report | None = None) -> Report:
    """Capture-dependent encodings (missing share differs between capture units)
    and classes confined to one capture unit."""
    rep = report or Report("audit", inputs=[input_record(t)])
    if not t.has("capture"):
        return rep
    cap = t.meta("capture")
    miss = t.missing_by(cap)
    rows = []
    for c in miss.columns:
        lo, hi = float(miss[c].min()), float(miss[c].max())
        if hi - lo >= min_diff:
            r = {"column": c, "min_missing_share": lo, "max_missing_share": hi,
                 "by_capture": {str(k): float(v) for k, v in miss[c].items()}}
            rows.append(r)
            rep.add(Finding("capture-encoding", "capture", "WARN",
                            f"column '{c}' is missing in {hi:.1%} of rows in one capture unit and {lo:.1%} in another",
                            "capture", r))
    for c in confined_classes(G.g_capture(t), t.cls, str(t.cols.benign)):
        rep.add(Finding("capture-confined-class", "capture", "WARN",
                        f"class '{c}' occurs in one capture unit only", "capture", {"class": c}))
    rep.results["capture_encoding"] = rows
    return rep


def audit(t: FlowTable, train_idx=None, test_idx=None, units=None, cross_capture: bool = False,
          test_frac: float = 0.2, seed: int = 0, thresholds: dict | None = None) -> Report:
    """Full audit: unit validity, capture checks and, if a split is given, overlap."""
    rep = Report("audit", inputs=[input_record(t)])
    if train_idx is not None and test_idx is not None:
        audit_split(t, train_idx, test_idx, units, cross_capture, thresholds, rep)
    audit_units(t, units, test_frac, seed, rep)
    capture_checks(t, report=rep)
    return rep
