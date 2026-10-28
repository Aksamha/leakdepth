# S11-SecSplit — Stage 4 Design v1 (FROZEN 2026-10-27, before any injection, cross-tool or worked-example result)

Scope: SoftwareX software paper for `leakdepth` (MIT, Python ≥3.10). Requirements R1–R10 from Stage 1. No empirical hypothesis about benchmark inflation is tested. Competitor check at freeze: leakcheck HEAD b9cbae5 (2026-10-18), unchanged since Stage 2.

## D1 Package and API
Modules: `profiles` (column maps + opt-in documented transforms: `cic-ids2017` time fix A4, `unsw-nb15` blank→0 A2 and capture periods), `groups` (registry: `row`, `dup`, `5tuple`, `hostpair`, `session:<gap>`, `capture`; custom callables), `split` (stratified group split, constrained redraw, leave-one-capture-out, validity), `audit` (existing split → per-unit cross-split overlap; per-unit split validity; capture checks), `sensitivity` (levels × models × seeds with controls), `lineage`, `report` (JSON schema v1 + Markdown), `cli` (`audit`, `lineage`, `sensitivity`, `gate`), `inject` (generator + ground truth). `bench/` (cross-tool harness) is not part of the installed package.

## D2 Validity rules (per split, per unit)
INVALID if: (a) any non-benign test class absent from train; (b) test attack share < 0.01; (c) empty train or test. WARN if achieved test fraction outside [0.5, 1.5] × target, or a class's rows sit in a single group/capture unit (class confined to one unit). Constrained redraw: ≤50 seeded tries; tries recorded; INVALID levels are reported and never scored.

## D3 Audit of an existing split
For every unit u: overlap(u) = share of test rows whose u-group also occurs in train; also share of test groups shared. Finding severity (defaults, configurable): `dup` overlap > 0 → ERROR; `5tuple`/`hostpair`/`session` overlap ≥ 0.05 → WARN (they can be legitimate for random-split protocols; reported, user decides); `capture` overlap > 0 when the user declares a cross-capture protocol → ERROR, else INFO. Capture checks (when a capture column exists): column missing/constant share differing by ≥ 0.5 between capture units → WARN (capture-dependent encoding); class confined to one capture unit → WARN. Detection for the injection benchmark = any WARN/ERROR finding of the planted type.

## D4 Sensitivity curve with composition controls
Per valid level L, seed s: model M trained on the L split. Score F(L) = binary macro-F1 (attack vs benign) on L's test set. Controls from the row-random split L0:
- C_train(L): L0 train subsampled to |train_L| rows and L's training class mix (multiclass); evaluated on L0 test.
- C_full(L): C_train model evaluated on L0 test reweighted per class so the weighted class mix equals L's test class mix (w_c = p_L(c)/p_0(c)). If a class of L's test is absent from L0 test, C_full is undefined for L (reported).
Reported per level: F(L), Δraw = F(L0) − F(L), Δtrain = F(C_train) − F(L), Δfull = F(C_full) − F(L) (primary), per-level test class composition table, group-bootstrap 95% CIs (B = 1000; L test resampled by L groups, L0 test by rows; independent draws, difference per draw). Models: HistGradientBoosting, RandomForest(n=100), LR (signed log1p + scaler, A10). Training cap 300k rows (stratified). Seeds 0–2.

## D5 Lineage algorithm
1. Profile numeric columns of A and B: 21 quantiles of finite values, zero share, NaN share, distinct ratio (on ≤200k-row samples).
2. Align: normalised-name match (lower-case, strip non-alphanumerics, built-in flow synonym table) first; remaining numeric columns by Hungarian assignment on cost = Wasserstein-1 between quantile vectors / pooled IQR (plus zero/NaN-share differences); accept cost ≤ 0.1. Comparable only if ≥4 aligned columns.
3. Canonicalise aligned columns: round to 6 significant digits (tolerates float32 casts and CSV printing); NaN → sentinel.
4. Row matching: full-row hash plus LSH banding over random column subsets (b = 8 bands × r = ⌈k/2⌉ columns, seeded) so a row still matches when some columns were altered; candidates verified by per-column agreement (rel. tol 1e-5) ≥ τ = 0.8.
5. Containment C(A⊂B) = verified matches among a sample of ≤200k A rows (Wilson 95% CI); B streamed in chunks (bounded memory). Both directions reported.
6. Optional key join (canonical 5-tuple + time within window after estimating a global offset as the mode of differences) when both sides have flow keys.
Finding: C ≥ 0.01 → WARN; C ≥ 0.5 → ERROR ("A largely contained in B").
Out of scope (documented misses): unit rescaling, additive noise beyond tolerance, re-extraction with different feature definitions (key join only).

## D6 Report and gate
JSON: `schema_version`, `tool_version`, inputs (SHA-256, rows, columns), config, findings[] (`id`, `check`, `unit`, `severity`, `message`, `evidence`), results, reproducibility (Python/numpy/pandas/sklearn versions, seeds, timestamp UTC). Markdown rendering of the same. `gate` exit codes: 0 no finding ≥ fail-on (default ERROR); 1 failing findings; 2 usage/config error; 3 input/data error.

## D7 Injection benchmark (SQ2)
Generator: hosts, host pairs, sessions (bursts with near-identical features, per-session jitter), capture days (day-specific offsets), benign + 3 attack classes, metadata columns (IPs, ports, protocol, timestamp, day). A clean train/test split is cross-session, cross-host-pair and cross-day; leakage is planted by moving a fraction ρ of test rows' units into train-overlap:
- `dup`: exact copies of train rows in test; `session`: test rows drawn from train sessions; `host`: test flows on train host pairs (new sessions); `capture`: test rows from a train day (protocol declared cross-day); `lineage`: a second corpus built from train rows under transforms T ∈ {rename, reorder, round-3dp, float32, column-subset (70%), row-subset, rename+round+subset, gaussian-noise 1% (negative boundary)} mixed with fresh rows at ρ.
Grid: 5 leak types × ρ ∈ {0, 0.01, 0.05, 0.20} × seeds. Development seeds 0–4 (defaults may be fixed only on these); held-out evaluation seeds 100–119 (run once after the code freeze tag). Metrics: recall (ρ > 0) and false-positive rate (ρ = 0) per type, Wilson CIs.

## D8 Cross-tool comparison (SQ2, descriptive)
Tools pinned: leakcheck (git b9cbae5), splitguard 0.1.0, splitcheck 0.2.0, mlleak 0.1.1, dataleaks 0.1.2, deepchecks 0.19.1. Each runs in its own virtual environment as a separate process (deepchecks never imported by leakdepth). Same held-out configurations. Conditions: (i) defaults (train/test frames + target only); (ii) oracle-group (true unit column passed where the tool accepts groups). Outcome per config: detected yes/no by a documented, per-tool mapping fixed before running. No superiority claim beyond the table.

## D9 Worked examples (SQ3, PRELIMINARY: HF mirrors)
CIC-IDS2017 and UNSW-NB15 (mirrors, SHA-256 recorded): audit report; sensitivity curves (D4) at row, dup, 5tuple, hostpair, session 60/300/1800 s, capture; RF duplicate-level diagnostic (per-class errors, duplicate clusters moved to test, RF with bootstrap=False and min_samples_leaf ∈ {1, 5}). Runs in a Colab notebook (user). Lineage controls: positive IoT-DH v1 vs Ahuja (expected C(Ahuja⊂IoT-DH v1) ≈ 1, row identity reported in AlQahtani, in preparation, software DOI 10.5281/zenodo.23599584; used only as a positive control); negatives Ahuja vs Karmous/SNT/UKMDDoSFlow and CIC vs UNSW (expected ≈ 0).

## D10 Success criteria (frozen)
| ID | Criterion |
|---|---|
| S1 | All tests pass; line coverage ≥ 90 %; CI on Python 3.10–3.13 (local uv matrix until a repository exists) |
| S2 | Held-out injection: leakdepth recall ≥ 0.95 per type at ρ ≥ 0.05 and ≥ 0.80 at ρ = 0.01; FPR ≤ 0.05; lineage recall ≥ 0.95 for each non-noise transform at ρ ≥ 0.05 |
| S3 | Worked examples: CIC host-pair and capture units reported INVALID with reasons; UNSW capture-dependent encoding flagged (with profile transform off) |
| S4 | Positive control C ≥ 0.99; negative controls C ≤ 0.01 |
| S5 | Memory: CIC mirror (≈2.8 M rows) audit within 7 GB |
Any miss is reported as such; defaults are not re-tuned on held-out seeds.

## D11 Citation of S06
S06 manuscript unsubmitted (S06 log part 2, 2026-10-24: v0.2.7 needs author approval) → cite as "AlQahtani, A.A.S., What do OpenFlow DDoS benchmarks measure? …, in preparation" plus the verified software record (openflow-ddos-audit v0.3.1, doi:10.5281/zenodo.23599584).
