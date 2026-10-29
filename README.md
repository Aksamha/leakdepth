# leakdepth

[![CI](https://github.com/Aksamha/leakdepth/actions/workflows/ci.yml/badge.svg)](https://github.com/Aksamha/leakdepth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue.svg)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23762930.svg)](https://doi.org/10.5281/zenodo.23762930)

Split-unit leakage audits for security machine-learning datasets.

Flow-based intrusion-detection benchmarks contain structure that row-random splits ignore:
duplicate records, repeated 5-tuples, host pairs, sessions, capture days, and derived corpora that
re-publish rows of another corpus under a different schema. `leakdepth` derives these split units
from flow metadata, measures how much of a test set shares a unit with training, checks whether a
split at each unit is still *valid*, measures how scores move across units with composition
controls, and gates continuous-integration jobs on the result. A lineage *screen* estimates how many
rows of one corpus reappear in another after renaming, reordering, rounding or subsetting; it is not a
provenance test (see Limitations).

## Install

```bash
pip install "git+https://github.com/Aksamha/leakdepth@v0.1.3"   # release v0.1.3 from GitHub
git clone https://github.com/Aksamha/leakdepth.git && cd leakdepth
pip install -e ".[dev]"          # from a clone, with test dependencies
```

Python ≥ 3.10; dependencies: numpy, pandas, scikit-learn, scipy (pyarrow for Parquet, PyYAML for YAML configs).

## Quick start

```python
import pandas as pd
import leakdepth as ld

train, test = pd.read_csv("train.csv"), pd.read_csv("test.csv")
cols = ld.ColumnMap(label="label", benign="BENIGN", src="src_ip", dst="dst_ip",
                    sport="src_port", dport="dst_port", proto="proto", time="ts", capture="day")
t, tr, te = ld.concat(ld.FlowTable(train, cols), ld.FlowTable(test, cols))
report = ld.audit(t, tr, te, cross_capture=True)
print(report.to_markdown())
report.to_json("audit.json")
```

Command line:

```bash
leakdepth audit train.csv --test test.csv --label label --src src_ip --dst dst_ip \
    --sport src_port --dport dst_port --time ts --capture day --cross-capture \
    --out-json audit.json --out-md audit.md --fail-on WARN
leakdepth lineage corpus_a.parquet corpus_b.csv --out-json lineage.json --fail-on ERROR
leakdepth sensitivity data.parquet --profile cic-ids2017 --models hgb,rf --seeds 0,1,2 --resume folds.jsonl
leakdepth gate audit.json --fail-on ERROR      # exit 1 if the report has ERROR findings
```

Column roles can also be given in a JSON/YAML file (`--config cols.yaml` with a `columns:` mapping).
Built-in profiles: `cic-ids2017`, `unsw-nb15` (`leakdepth audit data.parquet --profile unsw-nb15`).
Profile transforms are opt-in and recorded in the report (for example, `blank_to_zero` for the
UNSW-NB15 counters that are blank in the February capture and 0 in January).

## What it checks

| Unit | Definition |
|---|---|
| `row` | each row |
| `dup`, `dup:<d>` | identical feature vector and class (optionally after rounding to `d` decimals) |
| `5tuple` | direction-insensitive (ip:port, ip:port, protocol) |
| `hostpair` | direction-insensitive address pair |
| `session:<gap>` | flows on a host pair separated by at most `gap` seconds |
| `capture` | capture day, recording or file |

Custom units are registered with `leakdepth.groups.register`.

**Split overlap** (`audit_split`): for every unit, the share of test rows whose unit also occurs in
training. Defaults: any `dup` overlap is ERROR; `5tuple`, `hostpair`, `session` overlap ≥ 0.5 % is
WARN; `capture` overlap is ERROR when the protocol is declared cross-capture (`cross_capture=True`),
otherwise INFO. Thresholds are configurable.

**Split validity** (`audit_units`): a stratified group split at each unit, redrawn up to 50 times,
is INVALID if a non-benign test class is absent from training, the test attack share is below 1 %,
or a side is empty; units with fewer than 10 groups are evaluated leave-one-group-out. Invalid
units are reported, never silently scored.

**Capture checks**: columns whose missing share differs by ≥ 0.5 between capture units
(capture-dependent encodings) and attack classes confined to one capture unit.

**Sensitivity curve** (`sensitivity`): for each unit, a model is trained on that unit's split and
compared with two controls built on the row-random split: `C_train` (training set matched to the
unit's training size and class mix) and `C_full` (`C_train` scored on a test set reweighted to the
unit's test class mix). `d_full = C_full − F(unit)` separates the score change due to the split unit
from changes in training size and test composition. Group-bootstrap 95 % intervals, per-unit test
composition tables, and resumable fold logs are included.

**Lineage** (`lineage`): aligns columns by normalised name, shared exact values and value
distributions; canonicalises values to their common precision; finds candidate row pairs by
locality-sensitive banding over column subsets; verifies each pair column by column (≥ 80 % of
aligned columns must agree); re-aligns unmatched columns by agreement on verified pairs; and
reports containment in both directions with Wilson intervals. ≥ 1 % is WARN, ≥ 50 % is ERROR.
Since 0.1.1 the default matcher (`--matcher a10`) also requires that the values on which a pair
agrees carry at least log2(n_B) + 20 bits of self-information (`--info-margin`), which rejects chance
agreement on labels, a few host addresses and zero counters. This rule was added after version 0.1.0
reported spurious containment between real OpenFlow corpora that share no rows (see CHANGELOG.md).
`--matcher frozen` reproduces the 0.1.0 matcher exactly.
Since 0.1.3 each direction also reports the other matcher's containment and a within-corpus baseline
(a random half of the corpus searched in its other half); findings and `gate` use the primary matcher only.
Use `--single-matcher` and `--no-baseline` to skip them (each roughly doubles the run time).
`key_join_containment` matches flows by 5-tuple and time after removing a clock offset.

## Reports and exit codes

Reports are JSON (schema version 1.0: inputs with SHA-256, configuration, findings with severity
and evidence, results, environment) and Markdown. Exit codes: `0` no finding at or above
`--fail-on`; `1` failing findings; `2` usage or configuration error; `3` input or data error.

GitHub Actions example:

```yaml
- run: pip install "git+https://github.com/Aksamha/leakdepth@v0.1.3"
- run: leakdepth audit data/train.csv --test data/test.csv --config leakdepth.yaml --cross-capture --out-json audit.json
- run: leakdepth gate audit.json --fail-on ERROR
```

## Injection benchmark

`leakdepth.inject` generates synthetic flow corpora with planted duplicate, session, host-pair,
capture and lineage leakage and known ground truth; `bench/injection.py` scores leakdepth on it and
`bench/compare.py` runs other leakage tools on the same files, each in its own environment.

## Limitations

- Units come from metadata: without addresses, ports or times, only duplicate and lineage checks apply.
- Lineage does not detect rescaled units, perturbations beyond the comparison tolerance, or
  re-extraction with different feature definitions (use `key_join_containment` for the last case).
- Mixtures of copied and unrelated rows with every column renamed and no full-precision columns
  may not align.
- Sensitivity curves describe one dataset and model; they do not by themselves establish leakage.
- **Lineage is a screen, not a provenance test.** Three pre-specified lineage criteria failed
  (docs/lineage_controls.md). Between unrelated corpora built with the same flow extractor (CICFlowMeter:
  CIC-IDS2017, CSE-CIC-IDS2018, InSDN), containment reached 0.02-0.22, driven by one- and two-packet flows
  whose duration, inter-arrival and rate columns follow from a few values. For such corpora a WARN means
  "inspect the matched rows", not "rows were reused".
- With the default matcher, copied rows that carry fewer than log2(n_B) + margin bits on the aligned
  columns (few columns, many zeros) are not reported, because they cannot be told apart from chance agreement.
  In a pre-registered test on real OpenFlow corpora this included copies of empty flow entries after all
  columns were renamed, and every copy when only 4 or 6 low-entropy columns were shared
  (see docs/lineage_controls.md). Rows that are merely identical on few columns can still be reported.

## Citation and licence

If you use leakdepth, please cite it (details in `CITATION.cff`; GitHub shows them under "Cite this repository"):

> Samha, A. K. (2026). *leakdepth: split-unit leakage audits and a cross-corpus lineage screen for network
> intrusion-detection datasets* (Version 0.1.3) [Computer software]. https://github.com/Aksamha/leakdepth.
> Archived at Zenodo, https://doi.org/10.5281/zenodo.23762930.

MIT licence (`LICENSE`; identical copy in `Licence.txt`). Source: https://github.com/Aksamha/leakdepth.

## Reproducing the paper's results

See `reproduce/README.md`: benchmark scripts, the Colab notebooks (with the tested wheel embedded), saved
result summaries in `results/`, and the detail behind the paper's tables in `docs/worked_examples.md` and
`docs/lineage_controls.md`.

