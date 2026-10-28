"""Group splits and split-validity checks."""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

MIN_ATTACK_SHARE = 0.01
MAX_TRIES = 50


@dataclass
class Validity:
    valid: bool
    reasons: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    unseen_classes: list = field(default_factory=list)
    test_attack_share: float = 0.0
    test_fraction: float = 0.0
    tries: int = 1

    def to_dict(self) -> dict:
        return dict(valid=self.valid, reasons=self.reasons, warnings=self.warnings,
                    unseen_classes=self.unseen_classes, test_attack_share=round(self.test_attack_share, 6),
                    test_fraction=round(self.test_fraction, 6), tries=self.tries)


def check_validity(cls: np.ndarray, y: np.ndarray, tr: np.ndarray, te: np.ndarray, benign: str,
                   target_test_frac: float | None = None, min_attack: float = MIN_ATTACK_SHARE) -> Validity:
    """Rules: INVALID if a non-benign test class is absent from train, if the test
    attack share is below ``min_attack``, or if either side is empty. WARN if the
    achieved test fraction is outside [0.5, 1.5] x target."""
    reasons, warns = [], []
    n = len(tr) + len(te)
    if len(tr) == 0 or len(te) == 0:
        reasons.append("empty train or test set")
    tr_c = set(np.unique(cls[tr])) if len(tr) else set()
    te_c = set(np.unique(cls[te])) if len(te) else set()
    unseen = sorted(str(c) for c in te_c - tr_c if str(c) != str(benign))
    if unseen:
        reasons.append(f"test classes absent from train: {unseen}")
    att = float(y[te].mean()) if len(te) else 0.0
    if len(te) and att < min_attack:
        reasons.append(f"test attack share {att:.4f} < {min_attack}")
    frac = len(te) / n if n else 0.0
    if target_test_frac and not (0.5 * target_test_frac <= frac <= 1.5 * target_test_frac):
        warns.append(f"test fraction {frac:.3f} far from target {target_test_frac}")
    return Validity(valid=not reasons, reasons=reasons, warnings=warns, unseen_classes=unseen,
                    test_attack_share=att, test_fraction=frac)


def group_split(groups: np.ndarray, cls: np.ndarray, test_frac: float, rng: np.random.Generator):
    """Stratified group split. Groups are stratified by majority class; within each
    stratum shuffled groups go to test until the stratum's test share is closest to
    ``test_frac``. A stratum with a single group stays in train."""
    groups = np.asarray(groups)
    df = pd.DataFrame({"g": groups, "c": np.asarray(cls, dtype=object)})
    gsize = df.groupby("g").size()
    gc = df.groupby(["g", "c"]).size().reset_index(name="n")
    gc = gc.sort_values(["g", "n", "c"], ascending=[True, False, True]).drop_duplicates("g")
    gmaj = pd.Series(gc["c"].to_numpy(), index=gc["g"].to_numpy())
    test_groups = []
    for c in sorted(gmaj.unique(), key=str):
        gs = gmaj.index[gmaj.to_numpy() == c].to_numpy()
        if len(gs) < 2:
            continue
        gs = gs[rng.permutation(len(gs))]
        cum = np.cumsum(gsize.loc[gs].to_numpy())
        target = test_frac * cum[-1]
        k = int(np.searchsorted(cum, target))
        cand = [max(k, 1), k + 1]
        take = min(cand, key=lambda m: abs(cum[min(m, len(gs)) - 1] - target))
        take = int(min(max(take, 1), len(gs) - 1))
        test_groups.append(gs[:take])
    tg = np.concatenate(test_groups) if test_groups else np.array([], dtype=groups.dtype)
    is_test = np.isin(groups, tg)
    return np.flatnonzero(~is_test), np.flatnonzero(is_test)


def constrained_group_split(groups, cls, y, test_frac: float, seed: int, benign: str,
                            tries: int = MAX_TRIES, min_attack: float = MIN_ATTACK_SHARE):
    """Redraw :func:`group_split` (seeded) up to ``tries`` times until valid.
    Returns (train_idx, test_idx, Validity) of the first valid draw, else the last."""
    rng = np.random.default_rng(seed)
    last = None
    for i in range(tries):
        tr, te = group_split(groups, cls, test_frac, rng)
        v = check_validity(cls, y, tr, te, benign, test_frac, min_attack)
        v.tries = i + 1
        last = (tr, te, v)
        if v.valid:
            break
    return last


def leave_one_group_out(groups: np.ndarray):
    """Folds that hold out one group each (for units with few groups, e.g. capture days)."""
    for g in np.unique(groups):
        yield g, np.flatnonzero(groups != g), np.flatnonzero(groups == g)


def confined_classes(groups: np.ndarray, cls: np.ndarray, benign: str) -> list:
    """Non-benign classes whose rows all fall in a single group."""
    df = pd.DataFrame({"g": groups, "c": np.asarray(cls, dtype=object)})
    n = df.groupby("c")["g"].nunique()
    return sorted(str(c) for c, k in n.items() if k == 1 and str(c) != str(benign))
