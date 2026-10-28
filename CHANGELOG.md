# Changelog

## 0.1.3 (unreleased)
- Lineage reports, for each direction, the containment found by the other matcher (`other_matcher`:
  `frozen` when the primary matcher is `a10`, and the reverse). Findings, severities and therefore `gate`
  still use the primary matcher only (A10 by default). CLI: `--single-matcher` turns this off.
- Lineage reports a within-corpus baseline for each direction (`baseline`): the containment of a random half
  of the searched-from corpus in its other half, on the same aligned columns and with the same matcher.
  It is printed next to the containment in the finding message. Reason: corpora built with the same flow
  extractor can share many near-identical short flows without sharing rows; containment near the baseline
  is weak evidence of reuse. CLI: `--no-baseline` turns this off. Both additions multiply the run time.
- Sensitivity fold rows record `n_test_groups` and `ci_few_groups`; levels whose group-bootstrap intervals
  rest on fewer than 10 test groups (for example leave-one-capture-out folds) get an INFO finding
  `interval-few-groups`.
- No change to matching, containment, severities or exit codes of earlier versions (tested).

## 0.1.2 (unreleased)
- Bug fix: `metrics.wilson` now returns exactly 0 as the lower bound when k = 0 and exactly 1 as the
  upper bound when k = n. Before, floating-point rounding could return a tiny positive lower bound
  (about 2e-19 for n = 1000 or 1200), so an interval did not contain a true share of 0. Containment
  values, matches, severities and exit codes are unchanged; only reported interval limits at the
  edges change.

## 0.1.1 (unreleased)
- Lineage: new default matcher `a10`. A candidate row pair is accepted only if the values on which it
  agrees carry at least log2(n_B) + `info_margin` bits (default 20) of self-information, estimated from
  value frequencies in the other corpus; seed pairs for column refinement must pass the same bound.
  Reason: on real OpenFlow corpora that share no rows, 0.1.0 reported containment of 0.014-0.448
  through chance agreement on low-information values (labels, a few host addresses, zero counters).
  This change was made after those results were seen (post hoc); 0.1.0 failed its pre-specified
  negative-control criterion.
- `matcher="frozen"` (CLI `--matcher frozen`) reproduces the 0.1.0 matcher exactly.
- Reports record `matcher`, `info_margin` and, per direction, `rejected_low_info`.
- New `lineage_matches()` returns the row-level result for one direction.

## 0.1.0 (unreleased)
- Unit extractors (row, duplicate, 5-tuple, host pair, session, capture), stratified group splits with validity checks.
- Split-overlap audit, unit-validity audit, capture checks; JSON/Markdown reports; CLI with gate exit codes.
- Sensitivity curves with training- and test-composition controls and group-bootstrap intervals.
- Cross-corpus lineage detection under schema changes; flow-key/time join.
- Synthetic injection benchmark and cross-tool comparison harness.
