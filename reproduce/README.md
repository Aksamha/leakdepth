# Reproducing the results reported for leakdepth

| Result | How | Output in this repository |
|---|---|---|
| Unit tests, coverage | `pip install -e ".[dev]" && pytest --cov` | — |
| Injection benchmark (held-out seeds 100–119) | `python bench/injection.py --seeds 100-119 --out results/stage5/injection_heldout.jsonl` | `results/stage5/injection_*` |
| Cross-tool comparison (seeds 100–109) | `python bench/compare.py` (each tool in its own virtual environment; see the script header) | `results/stage5/compare_*` |
| Lineage row recovery (ρ = 0.01 misses) | `python bench/lineage_recovery.py` | `results/stage5/lineage_recovery.*` |
| Worked examples: audits, sensitivity curves, RF diagnostic, lineage controls (0.1.0) | `nb1_worked_examples.ipynb` (Colab, High-RAM CPU) | `results/nb1_summary.json` |
| Diagnosis of 0.1.0 false matches; A10 vs 0.1.0 on controls and held-out cells | `nb2_lineage_a10.ipynb` | `docs/lineage_controls.md` |
| Pre-registered validation of A10 (fresh seeds 200–219, margin sweep, low-information reuse) | `nb3_validate_a10.ipynb` | `results/nb3_summary.json` |
| New negative controls (A12), threshold-free lineage measure, bootstrap intervals, cross-tool rerun with 0.1.1 | `nb5_further_validation.ipynb` | `results/nb5_summary.json` (copy from the run's output folder), `results/nb5_B_summary.json` |
| Read-only diagnostic of the failing negative controls (A13), interval recompute after the 0.1.2 fix | `nb6_diagnose_lineage.ipynb` | `results/nb6_summary.json` (copy from the run's output folder), `docs/lineage_controls.md` |
| Imperfect-metadata benchmark (A14), timed audits, exploratory label/overlap check (A13-D1) | `nb7_imperfect_metadata.ipynb` | `results/nb7_summary.json` (copy from the run's output folder) |
| Sensitivity with ten seeds, Holm and Bonferroni (A15) | `nb8_sensitivity_10seeds.ipynb` | `results/nb8_summary.json` (copy from the run's output folder) |
| Sensitivity figure and lineage-control intervals | `python reproduce/make_fig_sensitivity.py` | `docs/figures/`, `results/lineage_controls_wilson.json` |

The notebooks embed the exact wheel they test (SHA-256 checked) and read data from Google Drive folders whose paths
are set in their first cells (`RAW6`, `RAW11`, `OUT`, `NB1`, `NB5`); edit those paths for your own storage. The Hugging Face mirrors (CIC-IDS2017, UNSW-NB15, CSE-CIC-IDS2018, InSDN, ToN-IoT, NSL-KDD) are downloaded and checked against SHA-256 values in the notebooks. The OpenFlow
corpora (Ahuja, IoT-DH v1, Karmous, SNT, UKMDDoSFlow) are public but are not redistributed here; download them from
their publishers. Data mirrors were not validated against the original releases; results on them are preliminary.

**Embedded wheels.** The notebooks embed the leakdepth wheel they tested. For this release the wheels were re-packed
so that their metadata and licence file carry the release author (Amani K. Samha) and no e-mail address; the package files are byte-identical
to the tested wheels (checked file by file). Tested-wheel SHA-256 → released-wheel SHA-256: 0.1.0 `7da15ab8…` → `6194495b…`;
0.1.1 `5213ebdf…` → `13c0954a…`; 0.1.2 `3727dfc4…` → `dd0d06f0…`; 0.1.3 `bfd4c2a4…` → `39c75233…`.
