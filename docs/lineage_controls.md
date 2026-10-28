# Lineage controls on real corpora: 0.1.0 matcher vs the A10 rule

This page holds the detail behind the lineage-control table of the paper.

## Controls (pre-specified)
Positive: the Ahuja SDN dataset vs IoT-DH v1 (criterion C ≥ 0.99). Negative: Ahuja vs Karmous, SNT and
UKMDDoSFlow; CIC-IDS2017 vs UNSW-NB15 (criterion C ≤ 0.01). Corpora above 200,000 rows are sampled.

| Direction | Rows sampled | 0.1.0 matched (C) | A10 matched |
|---|---|---|---|
| Ahuja in IoT-DH v1 | 104,345 | 104,345 (1.000; Wilson 95 % lower bound 0.99996) | 104,345 |
| IoT-DH v1 in Ahuja | 200,000 | 1,356 (0.0068) | 1,356 |
| Ahuja in Karmous | 104,345 | 1,496 (0.0143) | 0 |
| Karmous in Ahuja | 200,000 | 89,507 (0.4475) | 0 |
| Ahuja in SNT | 104,345 | 2,681 (0.0257) | 0 |
| SNT in Ahuja | 200,000 | 6,993 (0.0350) | 0 |
| Ahuja in UKMDDoSFlow | 104,345 | 0 | 0 |
| UKMDDoSFlow in Ahuja | 35,865 | 0 | 0 |
| CIC-IDS2017 in UNSW-NB15 | 200,000 | 0 | 0 |
| UNSW-NB15 in CIC-IDS2017 | 200,000 | 0 | 0 |

Version 0.1.0 does not meet the negative-control criterion in four of eight directions.

## Diagnosis of the 0.1.0 false matches
- Matched pairs agreed on at least 80 % of the aligned columns, but on low-information values: the binary
  label, a few emulated host addresses, small packet and byte counts, and zero counters.
- 99.87 % of the Karmous rows matched in Ahuja were empty flow entries (zero packets), against 79.28 % of
  all sampled Karmous rows; the corresponding shares for SNT in Ahuja were 32.7 % and 50.0 %.
- The first matching pass used four aligned columns (two by name, two by value distribution). Refinement
  then aligned further columns by agreement on these pairs, for example a packet count with a flow
  duration, or packets per second with bytes per flow, which agree only because both are zero in empty
  entries (agreement 1.000).

## The A10 rule (post hoc; default from 0.1.1)
A candidate pair is accepted only if the values on which it agrees carry at least log2(n_B) + 20 bits of
self-information, −log2((count + 1)/(n + 1)) per agreeing column, with counts taken from the other corpus.
Seed pairs for refinement must pass the same bound. With the bound disabled the matcher is identical to
0.1.0 (`matcher="frozen"`). In the four corrected directions no pair passed the first matching pass, so the
refinement step that produced the spurious alignments was not reached. On the held-out injection
benchmark (seeds 100–119) every cell was identical to 0.1.0.

## Known limit
Copied rows whose aligned values carry fewer than log2(n_B) + margin bits are not reported, because they
cannot be told apart from chance agreement (tables with few columns and many zeros).

## Pre-registered validation of A10 (protocol A11, fixed before the runs)
- Equivalence: 0.1.1 `matcher="frozen"` reproduced 0.1.0 and the 0.1.1 default reproduced the A10 patch on
  development seeds and on all controls. The held-out S2 file (720 lines, SHA-256 149fc41c…60d5) matched its
  summary cell by cell.
- Fresh held-out seeds 200–219: A10 and 0.1.0 identical in every cell; 20/20 at ρ ≥ 0.05 for every non-noise
  transform; 0/20 false positives; ρ = 0.01: 8/20 (5/20 for rename and renameall); no configuration matched
  more rows than were planted.
- Margin sweep (10, 15, 20, 25, 30 bits): every margin met the positive, negative and S2 criteria.
- Planted reuse between low-information corpora (exact copies of SNT rows in a 50,000-row Karmous sample and
  vice versa; 19 shared columns or the 6/4 lowest-entropy columns; original or renamed columns; random rows or
  empty flow entries; two replicates):

| Condition (ρ = 0.05, 0.2) | 0.1.0 detected | A10 (20 bits) detected | A10 row recall |
|---|---|---|---|
| 19 columns, original names | 16/16 | 16/16 | 1.00 |
| 19 columns, renamed, random rows | 8/8 (4/4 at ρ = 0) | 7/8 | 0.21–1.00 |
| 19 columns, renamed, empty entries | 8/8 | 0/8 | 0 |
| 6 or 4 lowest-entropy columns | 32/64 (8/16 at ρ = 0) | 8/64 (2/16 at ρ = 0) | ≤ 0.03 |

  With renamed columns and nothing planted, 0.1.0 matched 50–80 % of the host rows. The A10 detections at
  ρ = 0 come from one six-column set on which 72 % of host rows are identical to donor rows; at 25 and 30 bits
  they disappear.
- Verdict under the pre-registered rule: not validated for the tested conditions, because detection fell below
  0.95 in five full-schema cells with renamed columns (empty-entry copies, and random copies in one direction).
  The 4- and 6-column conditions are documented limits.

## New negative controls (protocol A12, fixed before the run; NB5, leakdepth 0.1.1)

Nine pairs of public corpora not used to design A10 (Hugging Face mirrors pinned by revision; file hashes in
`results/`), A10 at 20 bits, criterion C <= 0.01 in both directions. **Not met.**

| Pair | A in B | B in A | 0.1.0 (frozen) |
|---|---|---|---|
| CIC-IDS2017 / CSE-CIC-IDS2018 (14-15 Feb) | 0.059 | 0.218 | same as A10 |
| InSDN / CIC-IDS2017 | 0.003 | **0.021** | same as A10 |
| InSDN / CSE-CIC-IDS2018 | 0.002 | **0.028** | same as A10 |
| ToN-IoT network / UNSW-NB15 | 0 | 0 | 0 / 0 |
| NSL-KDD / UNSW-NB15 (< 4 shared names) | 0 | 0 | 0.388 / 0.151 |
| SDN-DDoS Traffic / Ahuja, Karmous (< 4 shared names), SNT, UKMDDoSFlow | 0 | 0 | 0 / 0 |

No negative direction reached ERROR (0.5). The exact-overlap gate hashed columns shared by name, which
included timestamps where present, so it could not exclude identical feature vectors.

## Read-only diagnostic of the failing directions (protocol A13; NB6, leakdepth 0.1.2)

All six N1-N3 counts were reproduced exactly. In the four failing directions:

- 97.5-100 % of matched rows were flows of one or two packets (35-54 % in the samples); median durations
  4-58 microseconds; a median 71-74 % of the aligned values were zero (pre-registered reading H2: supported).
- The largest information contributions came from Flow Duration, Flow/Fwd IAT and packet-rate columns
  (about 6-13 bits each), which for one- or two-packet flows follow from the duration and packet count.
  Counting exactly duplicated columns once removed only 2-6 % of the bits (H3, "bound inflated by duplicated
  columns": not supported). Functional dependence between columns is a post-hoc reading.
- A10 never rejected a candidate pair (`rejected_low_info` = 0); the 5th-95th percentiles of the bits carried by matched
  pairs spanned 84-195 against 38-41 required.
- Matches were many-to-one: 185-2,584 distinct partner rows; one partner verified up to 8,465 sampled rows.
- Random halves of the same corpus: C = 0.10 (CIC-IDS2017 mirror), 0.39 (CSE-CIC-IDS2018), 0.42 (InSDN).
- H1 (matches dominated by attack traffic) could not be assessed: the pre-registered label names did not
  include the label columns of the CIC-IDS2017 mirror and InSDN (`target`).

**What this means for users.** For corpora produced by the same flow extractor, containment measures
value-level near-identity of short flows, not provenance; inspect the matched rows before concluding reuse.

**Future work.** A dependence-aware information bound (functionally related columns counted once), to be
validated on same-extractor corpora not used here, such as CIC-DDoS2019 and CICIoT2023.

## Bug fix in 0.1.2

The Wilson interval returned a lower limit of about 2e-19 instead of 0 for zero matches at some sample sizes.
Recomputed on the NB5 threshold-free results, interval coverage at rho = 0 is 1.00 (reported 0.90); 98 of
2,880 rows changed; no detection changed.

## Exploratory: labels and exact overlap of the failing matches (deviation A13-D1; NB7)
Recorded as a deviation before the run: the A13 label-name map missed `attack_label` (CIC-IDS2017 mirror) and `target`
(InSDN mirror; binary, 1 = attack). Reported as exploratory.

| Failing direction | benign among matched rows | benign among their partners | notes |
|---|---|---|---|
| CIC-IDS2017 in CSE-CIC-IDS2018 | 67.3 % | 99.9 % | 32.7 % DoS Hulk matched benign rows |
| CSE-CIC-IDS2018 in CIC-IDS2017 | 58.2 % | 99.8 % | 41.8 % FTP-BruteForce matched benign rows |
| CIC-IDS2017 in InSDN | 100 % | 100 % | |
| CSE-CIC-IDS2018 in InSDN | 97.2 % | 97.5 % | 2.5 % attack–attack (InSDN has no attack types) |

No matched pair in the CIC-IDS2017/CSE-CIC-IDS2018 directions shared an attack family. Exact overlap without timestamps,
labels and identifiers: 0 on columns shared by name in every pair; on the aligned columns 0.049 %, 0.338 %, 0.006 % and 0 %
of sampled rows (at most 1.6 % of matched rows). The matches are near-identical short flows, mostly benign, and
near-identical flows can carry different labels in different corpora.
