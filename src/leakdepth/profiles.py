"""Built-in column maps for public flow datasets, with documented opt-in transforms.

Profiles name columns as they appear in the commonly used CSV/Parquet releases.
Transforms are never applied silently: each one is switched by a keyword and
recorded in the report configuration.
"""
from __future__ import annotations

from collections.abc import Callable

import numpy as np
import pandas as pd

from .table import ColumnMap, FlowTable


def fix_cic_time(ts: pd.Series) -> pd.Series:
    """Parse CIC-IDS2017 timestamps (day-first dates, 12-hour clock without AM/PM).

    The capture ran in working hours (about 08:00-18:00), so clock hours 1-7 are
    afternoon hours and are shifted by +12 h.
    """
    t = pd.to_datetime(ts.astype(str).str.strip(), format="mixed", dayfirst=True)
    pm = t.dt.hour.between(1, 7)
    return t + pd.to_timedelta(np.where(pm, 12, 0), unit="h")


def _cic(df: pd.DataFrame, fix_time: bool = True) -> pd.DataFrame:
    df = df.copy(deep=False)
    t = fix_cic_time(df["Timestamp"]) if fix_time else pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True)
    df["_time"] = ((t - pd.Timestamp("1970-01-01")) / pd.Timedelta("1s")).astype("float64")
    df["_capture"] = t.dt.strftime("%Y-%m-%d")
    return df


UNSW_BLANK_COUNTERS = ("ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd")


def _unsw(df: pd.DataFrame, blank_to_zero: bool = False) -> pd.DataFrame:
    df = df.copy(deep=False)
    cat = df["attack_cat"].astype("object").where(df["attack_cat"].notna(), "Normal")
    df["attack_cat"] = cat.astype(str).str.strip().replace({"Backdoors": "Backdoor", "": "Normal"})
    if blank_to_zero:
        for c in UNSW_BLANK_COUNTERS:
            if c in df:
                df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    st = pd.to_datetime(pd.to_numeric(df["Stime"], errors="coerce"), unit="s")
    # two capture periods: 22-23 January 2015 and 18 February 2015
    df["_capture"] = np.where(st < pd.Timestamp("2015-02-01"), "2015-01", "2015-02")
    return df


PROFILES: dict[str, tuple[ColumnMap, Callable]] = {
    "cic-ids2017": (
        ColumnMap(label="attack_label", benign="BENIGN", src="source_ip", dst="destination_ip",
                  sport="source_port", dport="destination_port", proto="protocol", time="_time",
                  capture="_capture", exclude=("flow_id", "Timestamp")),
        _cic,
    ),
    "unsw-nb15": (
        ColumnMap(label="attack_cat", benign="Normal", attack="label", src="srcip", dst="dstip",
                  sport="sport", dport="dsport", proto="proto", time="Stime", capture="_capture",
                  exclude=("Ltime",)),
        _unsw,
    ),
}


def available() -> list:
    return sorted(PROFILES)


def load(df: pd.DataFrame, profile: str, name: str | None = None, **opts) -> FlowTable:
    """Apply a built-in profile (and its transforms, configured by ``opts``) to ``df``."""
    if profile not in PROFILES:
        raise KeyError(f"unknown profile '{profile}'; available: {available()}")
    cols, fn = PROFILES[profile]
    return FlowTable(fn(df, **opts), cols, name or profile)
