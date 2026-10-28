"""Flow tables: a DataFrame plus a mapping from roles to column names."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace

import numpy as np
import pandas as pd

META_ROLES = ("label", "attack", "src", "dst", "sport", "dport", "proto", "time", "capture")


@dataclass(frozen=True)
class ColumnMap:
    """Names of the columns that play each role. Unset roles are ``None``.

    ``label`` holds the class (benign value given by ``benign``). ``attack`` is an
    optional binary column; when absent, attack = (label != benign).
    ``features`` lists model features; ``None`` means every numeric column that is
    not mapped to a role and not in ``exclude``.
    """

    label: str
    benign: str = "BENIGN"
    attack: str | None = None
    src: str | None = None
    dst: str | None = None
    sport: str | None = None
    dport: str | None = None
    proto: str | None = None
    time: str | None = None
    capture: str | None = None
    features: tuple | None = None
    exclude: tuple = field(default_factory=tuple)

    def roles(self) -> dict:
        return {r: getattr(self, r) for r in META_ROLES if getattr(self, r) is not None}

    def with_(self, **kw) -> ColumnMap:
        return replace(self, **kw)


def _to_seconds(s: pd.Series) -> np.ndarray:
    if pd.api.types.is_numeric_dtype(s):
        return pd.to_numeric(s, errors="coerce").to_numpy(dtype="float64")
    t = pd.to_datetime(s, errors="coerce", format="mixed")
    if getattr(t.dt, "tz", None) is not None:
        t = t.dt.tz_convert("UTC").dt.tz_localize(None)
    sec = (t - pd.Timestamp("1970-01-01")) / pd.Timedelta("1s")
    return sec.to_numpy(dtype="float64")


def _numeric_like(s: pd.Series, share: float = 0.95) -> bool:
    """Numeric dtype, or text whose non-blank values are (almost) all numbers
    (e.g. counters exported as strings with blanks for missing)."""
    if pd.api.types.is_bool_dtype(s) or pd.api.types.is_numeric_dtype(s):
        return True
    v = s.dropna()
    v = v[v.astype(str).str.strip() != ""]
    if len(v) == 0:
        return False
    v = v.iloc[:10000]
    return bool(pd.to_numeric(v, errors="coerce").notna().mean() >= share)


class FlowTable:
    """A flow table with role accessors. Arrays are computed once and cached."""

    def __init__(self, df: pd.DataFrame, cols: ColumnMap, name: str = "data"):
        missing = [c for c in cols.roles().values() if c not in df.columns]
        if missing:
            raise KeyError(f"columns not found: {missing}")
        if cols.features is not None:
            fm = [c for c in cols.features if c not in df.columns]
            if fm:
                raise KeyError(f"feature columns not found: {fm}")
        self.df = df
        self.cols = cols
        self.name = name
        self._cache: dict = {}

    def __len__(self) -> int:
        return len(self.df)

    # ------------------------------------------------------------ roles
    def has(self, *roles: str) -> bool:
        return all(getattr(self.cols, r) is not None for r in roles)

    def _str(self, role: str) -> np.ndarray:
        key = ("s", role)
        if key not in self._cache:
            col = getattr(self.cols, role)
            if col is None:
                raise ValueError(f"role '{role}' is not mapped to a column")
            self._cache[key] = self.df[col].astype(str).str.strip().to_numpy(dtype=object)
        return self._cache[key]

    @property
    def cls(self) -> np.ndarray:
        return self._str("label")

    @property
    def y(self) -> np.ndarray:
        if "y" not in self._cache:
            if self.cols.attack is not None:
                y = pd.to_numeric(self.df[self.cols.attack], errors="coerce").fillna(0).to_numpy() != 0
            else:
                y = self.cls != str(self.cols.benign)
            self._cache["y"] = y.astype(np.int8)
        return self._cache["y"]

    def meta(self, role: str) -> np.ndarray:
        return self._str(role)

    @property
    def time(self) -> np.ndarray:
        if "time" not in self._cache:
            if self.cols.time is None:
                raise ValueError("role 'time' is not mapped to a column")
            self._cache["time"] = _to_seconds(self.df[self.cols.time])
        return self._cache["time"]

    @property
    def feature_names(self) -> list:
        if self.cols.features is not None:
            return list(self.cols.features)
        if "fnames" not in self._cache:
            skip = set(self.cols.roles().values()) | set(self.cols.exclude)
            self._cache["fnames"] = [c for c in self.df.columns if c not in skip and _numeric_like(self.df[c])]
        return self._cache["fnames"]

    def X(self, dtype="float32") -> pd.DataFrame:
        """Feature frame (numeric, ``dtype``); non-finite values are kept as NaN."""
        key = ("X", dtype)
        if key not in self._cache:
            X = self.df[self.feature_names].apply(pd.to_numeric, errors="coerce").astype(dtype)
            X = X.replace([np.inf, -np.inf], np.nan)
            self._cache[key] = X
        return self._cache[key]

    def feature_hash(self) -> np.ndarray:
        """64-bit hash per row of the feature columns as stored (numeric, NaN-aware)."""
        if "fhash" not in self._cache:
            h = np.zeros(len(self.df), dtype=np.uint64)
            mult = np.uint64(0x100000001B3)
            for c in self.feature_names:
                v = pd.to_numeric(self.df[c], errors="coerce")
                v = v.where(np.isfinite(v)) if v.dtype.kind == "f" else v
                hc = pd.util.hash_pandas_object(v.astype("float64"), index=False).to_numpy()
                with np.errstate(over="ignore"):
                    h = (h * mult) ^ hc
            self._cache["fhash"] = h
        return self._cache["fhash"]

    def missing_by(self, by: np.ndarray) -> pd.DataFrame:
        """Share of missing (or non-finite) values per feature column, per value of ``by``."""
        out = {}
        for c in self.feature_names:
            v = pd.to_numeric(self.df[c], errors="coerce")
            miss = ~np.isfinite(v.to_numpy(dtype="float64", na_value=np.nan))
            out[c] = pd.Series(miss).groupby(by).mean()
        return pd.DataFrame(out)

    def subset(self, idx: Sequence[int]) -> FlowTable:
        return FlowTable(self.df.iloc[np.asarray(idx)].reset_index(drop=True), self.cols, self.name)

    def class_counts(self, idx: np.ndarray | None = None) -> pd.Series:
        c = self.cls if idx is None else self.cls[idx]
        return pd.Series(c).value_counts().sort_index()
