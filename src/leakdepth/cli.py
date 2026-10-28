"""Command-line interface.

Exit codes: 0 no finding at or above ``--fail-on``; 1 failing findings;
2 usage or configuration error; 3 input or data error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

from . import __version__
from .report import SEVERITIES, severity_rank

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_INPUT = 0, 1, 2, 3
ROLE_FLAGS = ("label", "benign", "attack", "src", "dst", "sport", "dport", "proto", "time", "capture")


class InputError(Exception):
    pass


class UsageError(Exception):
    pass


def read_table(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise InputError(f"file not found: {path}")
    ext = path.lower().rsplit(".", 1)[-1]
    try:
        if ext in ("parquet", "pq"):
            return pd.read_parquet(path)
        if ext in ("csv", "txt"):
            return pd.read_csv(path, low_memory=False)
        if ext in ("gz", "bz2", "zip", "xz"):
            return pd.read_csv(path, low_memory=False)
    except Exception as e:
        raise InputError(f"cannot read {path}: {e}") from e
    raise InputError(f"unsupported file type: {path} (use .csv or .parquet)")


def _load_config(path: str | None) -> dict:
    if not path:
        return {}
    if not os.path.exists(path):
        raise UsageError(f"config not found: {path}")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as e:
            raise UsageError("PyYAML is needed for YAML configs (pip install pyyaml) or use JSON") from e
        cfg = yaml.safe_load(text) or {}
    else:
        cfg = json.loads(text)
    if not isinstance(cfg, dict):
        raise UsageError("config must be a mapping")
    return cfg


def _table(df: pd.DataFrame, args, name: str):
    from .profiles import load
    from .table import ColumnMap, FlowTable
    cfg = _load_config(getattr(args, "config", None))
    if args.profile:
        opts = cfg.get("profile_options", {})
        try:
            return load(df, args.profile, name=name, **opts)
        except KeyError as e:
            raise UsageError(str(e)) from e
    cols = dict(cfg.get("columns", {}))
    for r in ROLE_FLAGS:
        v = getattr(args, r, None)
        if v is not None:
            cols[r] = v
    if "label" not in cols:
        raise UsageError("give --profile, --label (and other role flags) or a --config with 'columns'")
    for k in ("features", "exclude"):
        if k in cols and cols[k] is not None:
            cols[k] = tuple(cols[k])
    try:
        return FlowTable(df, ColumnMap(**cols), name)
    except KeyError as e:
        raise InputError(str(e)) from e
    except TypeError as e:
        raise UsageError(f"bad column configuration: {e}") from e


def _emit(rep, args) -> int:
    if args.out_json:
        rep.to_json(args.out_json)
    if args.out_md:
        rep.to_markdown(args.out_md)
    if not args.quiet:
        s = rep.to_dict()["summary"]
        print(f"leakdepth {rep.command}: ERROR {s['ERROR']} WARN {s['WARN']} INFO {s['INFO']}")
        for f in sorted(rep.findings, key=lambda f: -severity_rank(f.severity)):
            print(f"  [{f.severity}] {f.check}{' (' + f.unit + ')' if f.unit else ''}: {f.message}")
    if args.fail_on:
        return EXIT_FAIL if rep.failing(args.fail_on) else EXIT_OK
    return EXIT_OK


def cmd_audit(args) -> int:
    from .audit import audit, concat
    df = read_table(args.data)
    t = _table(df, args, os.path.basename(args.data))
    tr = te = None
    if args.test:
        t2 = _table(read_table(args.test), args, os.path.basename(args.test))
        t, tr, te = concat(t, t2)
    elif args.split_col:
        if args.split_col not in df.columns:
            raise InputError(f"split column '{args.split_col}' not found")
        s = df[args.split_col].astype(str).str.lower()
        tr, te = np.flatnonzero(s == "train"), np.flatnonzero(s == "test")
        if len(tr) == 0 or len(te) == 0:
            raise InputError("split column must contain 'train' and 'test' values")
    units = args.units.split(",") if args.units else None
    rep = audit(t, tr, te, units=units, cross_capture=args.cross_capture, test_frac=args.test_frac, seed=args.seed)
    return _emit(rep, args)


def cmd_lineage(args) -> int:
    from .lineage import lineage
    a, b = read_table(args.a), read_table(args.b)
    excl = tuple(args.exclude.split(",")) if args.exclude else ()
    rep = lineage(a, b, os.path.basename(args.a), os.path.basename(args.b), sample_n=args.sample_n,
                  tau=args.tau, seed=args.seed, exclude=excl, matcher=args.matcher, info_margin=args.info_margin,
                  compare_matchers=not args.single_matcher, baseline=not args.no_baseline)
    return _emit(rep, args)


def cmd_sensitivity(args) -> int:
    from .sensitivity import DEFAULT_LEVELS, sensitivity
    t = _table(read_table(args.data), args, os.path.basename(args.data))
    levels = args.levels.split(",") if args.levels else DEFAULT_LEVELS
    seeds = [int(s) for s in args.seeds.split(",")]
    rep = sensitivity(t, levels, args.models.split(","), seeds, args.test_frac, args.train_cap, args.n_boot,
                      resume=args.resume, log=None if args.quiet else print)
    return _emit(rep, args)


def cmd_gate(args) -> int:
    if not os.path.exists(args.report):
        raise InputError(f"report not found: {args.report}")
    try:
        with open(args.report, encoding="utf-8") as f:
            d = json.load(f)
        findings = d["findings"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise InputError(f"not a leakdepth report: {e}") from e
    k = severity_rank(args.fail_on)
    bad = [f for f in findings if severity_rank(f["severity"]) >= k]
    if not args.quiet:
        print(f"leakdepth gate: {len(bad)} finding(s) at or above {args.fail_on.upper()}")
        for f in bad:
            print(f"  [{f['severity']}] {f['check']}: {f['message']}")
    return EXIT_FAIL if bad else EXIT_OK


def _common(p, roles=True):
    p.add_argument("--out-json")
    p.add_argument("--out-md")
    p.add_argument("--fail-on", type=str.upper, choices=SEVERITIES)
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--seed", type=int, default=0)
    if roles:
        p.add_argument("--profile")
        p.add_argument("--config")
        for r in ROLE_FLAGS:
            p.add_argument(f"--{r}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="leakdepth", description="Split-unit leakage audits for security ML datasets.")
    p.add_argument("--version", action="version", version=f"leakdepth {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit", help="audit a dataset and, optionally, an existing train/test split")
    a.add_argument("data")
    a.add_argument("--test", help="separate test file (DATA is then the training file)")
    a.add_argument("--split-col", help="column with values 'train'/'test'")
    a.add_argument("--units", help="comma-separated units, e.g. dup,hostpair,session:300,capture")
    a.add_argument("--cross-capture", action="store_true", help="the protocol requires disjoint capture units")
    a.add_argument("--test-frac", type=float, default=0.2)
    _common(a)
    a.set_defaults(fn=cmd_audit)
    l_ = sub.add_parser("lineage", help="estimate row containment between two corpora")
    l_.add_argument("a")
    l_.add_argument("b")
    l_.add_argument("--exclude", help="comma-separated columns to ignore")
    l_.add_argument("--sample-n", type=int, default=200_000)
    l_.add_argument("--tau", type=float, default=0.8)
    l_.add_argument("--matcher", choices=["a10", "frozen"], default="a10",
                    help="a10 (default): minimum-information bound on matched pairs; frozen: the 0.1.0 matcher")
    l_.add_argument("--info-margin", type=float, default=20.0, help="A10 margin in bits above log2(n_B)")
    l_.add_argument("--single-matcher", action="store_true",
                    help="do not also report the other matcher's containment (findings always use --matcher)")
    l_.add_argument("--no-baseline", action="store_true",
                    help="do not report the within-corpus baseline (random half in the other half)")
    _common(l_, roles=False)
    l_.set_defaults(fn=cmd_lineage)
    s = sub.add_parser("sensitivity", help="split-unit sensitivity curve with composition controls")
    s.add_argument("data")
    s.add_argument("--levels")
    s.add_argument("--models", default="hgb")
    s.add_argument("--seeds", default="0")
    s.add_argument("--test-frac", type=float, default=0.2)
    s.add_argument("--train-cap", type=int, default=300_000)
    s.add_argument("--n-boot", type=int, default=1000)
    s.add_argument("--resume", help="JSONL file to append fold results to and resume from")
    _common(s)
    s.set_defaults(fn=cmd_sensitivity)
    g = sub.add_parser("gate", help="exit non-zero if a report has findings at or above --fail-on")
    g.add_argument("report")
    g.add_argument("--fail-on", type=str.upper, choices=SEVERITIES, default="ERROR")
    g.add_argument("--quiet", action="store_true")
    g.set_defaults(fn=cmd_gate)
    return p


def main(argv=None) -> int:
    p = build_parser()
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return EXIT_OK if e.code == 0 else EXIT_USAGE
    try:
        return args.fn(args)
    except UsageError as e:
        print(f"leakdepth: usage error: {e}", file=sys.stderr)
        return EXIT_USAGE
    except (InputError, ValueError) as e:
        print(f"leakdepth: input error: {e}", file=sys.stderr)
        return EXIT_INPUT


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
