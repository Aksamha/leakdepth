# Worked examples: detail not shown in the paper

## Audits of public mirrors (preliminary)
| Dataset | Unit | Finding |
|---|---|---|
| CIC-IDS2017 (2,827,677 rows) | host pair | INVALID: Heartbleed and Infiltration absent from training; test attack share 0.0009 |
| | capture | INVALID in every leave-one-day-out fold; 14 attack classes confined to one day |
| UNSW-NB15 (2,280,090 rows) | capture | WARN with the profile transform off: missingness depends on capture period for ct_flw_http_mthd (92.1 % vs 0 %), is_ftp_login and ct_ftp_cmd (98.4 %) |
| | host pair, capture | valid with `blank_to_zero` |
Peak memory: 4.91 GB (CIC-IDS2017, 180 s on two cores), 3.67 GB (UNSW-NB15).

## Injection benchmark: ρ = 0.01 misses (held-out seeds 100–119, version 0.1.0)
49 of 50 non-rename misses had a planted share below 1 % after rounding; the planted rows were recovered, but
containment stayed below the WARN threshold of 0.01. The remaining misses were all-or-nothing alignment failures of
the renaming transforms (2/20 rename, 3/20 renameall). In every other non-noise configuration matched rows equalled
planted rows. On fresh seeds 200–219, detections at ρ = 0.01 were 8/20 (5/20 for rename and renameall), identical for
0.1.0 and A10.

## Random-forest duplicate-level diagnostic (CIC-IDS2017, seed 0, single run)
| Split | RF default | RF bootstrap=False | RF min_samples_leaf=5 | HGB |
|---|---|---|---|---|
| row-random | 0.9972 | 0.9970 | 0.9963 | 0.9978 |
| duplicate | 0.9640 | 0.9620 | 0.9953 | 0.9955 |
Binary macro-F1. Δfull at the duplicate level: RF 0.061 ± 0.027, HGB 0.0004 ± 0.0007, LR 0.031 ± 0.022 (three seeds).

## Cross-tool comparison (held-out seeds 100–109, ρ ∈ {0, 0.01, 0.05}; version 0.1.0)
Split leaks: dup, session, host, capture. Lineage transforms: rename (feature columns), round3, colsubset, combo, renameall
(every column). Rates are detection rates over configurations. "Oracle": the true unit column passed to tools that accept
groups. n/a: no group input (oracle) or no cross-corpus check (lineage). deepchecks "condition": its own 5 % pass/fail
condition, reported separately from the raw ratio. Median seconds per job on about 10,000 rows, two CPU cores.

| Tool | Defaults | Features only | Oracle group | Lineage (defaults) | s/job |
|---|---|---|---|---|---|
| leakdepth | all types at ρ ≥ 0.01; 0 FP | dup | – | 1.00 at ρ = 0.05 (all five); 0.60–0.80 at ρ = 0.01 | 0.08 |
| leakcheck | alerts on all configurations incl. clean; split-leakage checks: none | dup | session, host, capture | error on differing schemas; round3 detected | 2.1 |
| splitcheck | none | dup | session, host, capture | rename only | 0.57 |
| mlleak | none | dup | session, host, capture | rename, colsubset, combo | 0.02 |
| splitguard | none | dup | session, host, capture | n/a | 0.07 |
| dataleaks (no near-duplicate detector) | dup 1.00; session 0.10 | dup | n/a | rename, colsubset, combo | 0.08 |
| deepchecks | none | dup (ratio 1.00; condition 0.00/0.30) | n/a | error on differing schemas | 3.9 |

With version 0.1.1 (A10), leakdepth matched the same rows on all 720 held-out injection configurations (seeds 100–119),
which include these planted data.

## Imperfect metadata (protocol A14; NB7, version 0.1.3; seeds 300–319)
Detection = WARN/ERROR finding for the planted unit; "fp" = that finding with nothing planted (20 configurations each).

| Condition | dup | session | host pair | capture |
|---|---|---|---|---|
| none, ρ = 0.001 / 0.0025 (below the 0.005 threshold) | 20/20, 20/20 | 0/20, 0/20 | 0/20, 0/20 | 20/20, 20/20 |
| consistent address remapping | robust | robust | robust | robust |
| per-split address remapping | robust | 0 detected | 0 detected | robust |
| NAT (all hosts → 4 addresses) | robust | robust | fp 20/20 | robust |
| daily address churn (DHCP, p = 0.5) | robust | robust | 3/20 at ρ = 0.01, 7/20 at 0.05 | robust |
| timestamp jitter ±1, ±60, ±600 s | robust | robust | robust | robust |
| timestamps missing, 50 % / 100 % | robust | 9/20 at 0.01, 20/20 at 0.05 / 0 | robust | robust |
| session gap 30 s / 3000 s (generator ≤ 40 s) | robust | 19/20 at 0.01 / robust | robust | robust |
| bidirectional flow splitting | robust | robust | robust | robust |
"Robust": 20/20 at ρ = 0.01 and 0.05 and no false positive.

## Timed audits and audit detail (NB7, Colab High-RAM, 8 vCPUs)
- CIC-IDS2017 mirror: full audit 260 s (+ 10 s load and profile), peak RSS 5.07 GB. Of 61,979 host pairs, 9 carry attack rows; the largest carries 99.64 % of 556,555 attack rows, the largest five 99.95 %; every attack class except Bot (7 host pairs) is on one host pair.
- UNSW-NB15 mirror: 46.6 s / 3.17 GB without and 43.6 s / 3.13 GB with `blank_to_zero`. Without it, ct_flw_http_mthd, is_ftp_login and ct_ftp_cmd are 90.8–98.1 % zero in 2015-01 and 92.1–98.4 % missing in 2015-02; with it they are zero in 90.8 / 92.1 %, 98.1 / 98.4 % and 98.1 / 98.4 % of rows. No column's zero share differs by ≥ 0.5 between periods after the transform (three before).
