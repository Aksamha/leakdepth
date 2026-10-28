"""Findings and reports (JSON schema v1 and Markdown)."""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import platform
from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np
import pandas as pd

from ._version import __version__

SCHEMA_VERSION = "1.0"
SEVERITIES = ("INFO", "WARN", "ERROR")


def severity_rank(s: str) -> int:
    return SEVERITIES.index(s.upper())


@dataclass
class Finding:
    id: str
    check: str
    severity: str
    message: str
    unit: str | None = None
    evidence: dict = field(default_factory=dict)

    def __post_init__(self):
        self.severity = self.severity.upper()
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")


def _jsonable(o: Any):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        f = float(o)
        return None if not np.isfinite(f) else f
    if isinstance(o, float) and not np.isfinite(o):
        return None
    if isinstance(o, np.ndarray):
        return [_jsonable(x) for x in o.tolist()]
    if isinstance(o, pd.DataFrame):
        return [{k: _jsonable(v) for k, v in r.items()} for r in o.to_dict("records")]
    if isinstance(o, pd.Series):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [_jsonable(x) for x in o]
    return o


def frame_digest(df: pd.DataFrame) -> str:
    """SHA-256 of the row hashes of a DataFrame (order-sensitive)."""
    h = pd.util.hash_pandas_object(df, index=False).to_numpy()
    m = hashlib.sha256(h.tobytes())
    m.update("|".join(map(str, df.columns)).encode())
    return m.hexdigest()


def file_digest(path: str) -> str:
    m = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            m.update(chunk)
    return m.hexdigest()


def environment() -> dict:
    import scipy
    import sklearn
    return {"python": platform.python_version(), "numpy": np.__version__, "pandas": pd.__version__,
            "scikit-learn": sklearn.__version__, "scipy": scipy.__version__, "platform": platform.platform()}


@dataclass
class Report:
    command: str
    inputs: list = field(default_factory=list)
    config: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    results: dict = field(default_factory=dict)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=severity_rank)

    def failing(self, fail_on: str = "ERROR") -> list:
        k = severity_rank(fail_on)
        return [f for f in self.findings if severity_rank(f.severity) >= k]

    def to_dict(self) -> dict:
        return _jsonable({
            "schema_version": SCHEMA_VERSION,
            "tool": "leakdepth",
            "tool_version": __version__,
            "command": self.command,
            "created_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "inputs": self.inputs,
            "config": self.config,
            "summary": {s: sum(f.severity == s for f in self.findings) for s in SEVERITIES},
            "findings": [asdict(f) for f in self.findings],
            "results": self.results,
            "environment": environment(),
        })

    def to_json(self, path: str | None = None, indent: int = 1) -> str:
        s = json.dumps(self.to_dict(), indent=indent, allow_nan=False)
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(s + "\n")
        return s

    def to_markdown(self, path: str | None = None) -> str:
        d = self.to_dict()
        lines = [f"# leakdepth {d['command']} report", "",
                 f"leakdepth {d['tool_version']} · schema {d['schema_version']} · {d['created_utc']}", ""]
        if d["inputs"]:
            lines += ["## Inputs", "", "| Name | Rows | Columns | SHA-256 |", "|---|---|---|---|"]
            for i in d["inputs"]:
                lines.append(f"| {i.get('name')} | {i.get('rows')} | {i.get('columns')} | `{str(i.get('sha256'))[:16]}` |")
            lines.append("")
        s = d["summary"]
        lines += ["## Findings", "", f"ERROR {s['ERROR']} · WARN {s['WARN']} · INFO {s['INFO']}", ""]
        if d["findings"]:
            lines += ["| Severity | Check | Unit | Message |", "|---|---|---|---|"]
            order = sorted(d["findings"], key=lambda f: -severity_rank(f["severity"]))
            for f in order:
                lines.append(f"| {f['severity']} | {f['check']} | {f['unit'] or ''} | {f['message']} |")
            lines.append("")
        for key, val in d["results"].items():
            if isinstance(val, list) and val and isinstance(val[0], dict):
                cols = list(val[0].keys())
                lines += [f"## {key}", "", "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
                for r in val:
                    lines.append("| " + " | ".join(_fmt(r.get(c)) for c in cols) + " |")
                lines.append("")
        md = "\n".join(lines)
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(md + "\n")
        return md


def _fmt(v) -> str:
    if isinstance(v, float):
        return f"{v:.4g}"
    if isinstance(v, (list, dict)):
        return json.dumps(v)[:80]
    return "" if v is None else str(v)
