# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-13 · **Milestone:** M4b (honeypot backend, Alg. 3) · **Sessions completed:** 8

---

## One-line status

M4a is closed and Q10 is closed. BitcoinHeist is fetched, verified against §VII and run through
both evaluation modes with baselines beside every number. A follow-up ablation (Q10) tested
`address`-as-feature and split-grouping as leakage sources for the reproduction gap: both are
real, both are small, and **neither explains it**, alone or stacked. The honest `paper_mode`
headline is revised to **0.9442 / 0.9697** (address dropped, grouped split — M4a's original
0.9479/0.9717 used a random split and is superseded). Published row: 0.9898/0.990 — still **not
reproduced**, now stated as unexplained rather than attributed. `make test-all` runs 1112 tests
and `make lint` is clean. Next is M4b, the framework's own data path.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Docs (`CLAUDE.md`, `docs/*`) | done | DEV-06 amended in M4a and Q10; DEV-07 in M4a; M4 split into M4a/M4b |
| `configs/`, `Makefile` | done | `make data` implemented; `ml.yaml` records the sklearn `penalty` deprecation |
| `util/`, `crypto/`, `blockchain/`, `consensus/` | done | |
| `framework/` entities, pipeline, phases 1, 2, 5 | done | M3a + M3b |
| `recovery/`, `honeypot/` | done | M3a, M3b |
| `data/honeypot/` corpus | done | fixed dataset (Q9): 1467 train + 731 eval, two seeds |
| `data/raw/` BitcoinHeist | **local only** | gitignored; `make data` refetches (~56 min here); README states the wait and the sha256 |
| `detection/` dataset, models, metrics | **done** | M4a — BitcoinHeist only; `dataset.py` gained `grouped_stratified_holdout` and `encode_group_column` (Q10) |
| `detection/` profiles, detector; `phase3_detection` | not started | **M4b — start here** |
| `mitigation/`, phase 4 | not started | M5 |
| `bench/`, figures | not started | M6 |

## Current numbers

**BitcoinHeist, `paper_mode`, honest baseline** (n=46,014, address dropped, **grouped** split, run
`20260913T014022Z-c54c3974`): RF 0.9442/0.9697 · DT 0.9224/0.9569 · LR 0.9002/0.9475 ·
KNN 0.8892/0.9410 · constant-positive baseline **0.9000/0.9474**. Published row: 0.9898/0.990 —
**not reproduced**. (M4a's original figure — address dropped, *random* split, run
`20260912T172708Z-6d35b415` — was RF 0.9479/0.9717; kept for provenance, no longer "the" figure.)

**Q10 ablation** (same config hash and seed as the run above; `scripts/q10_leakage_ablation.py`
ran all four `{dropped, kept} x {grouped, random}` cells): best of all 16 model x cell
combinations is RF, address **kept** x **random** split, at 0.9540/0.9749 — still 3.58 accuracy
points under published. Neither `address`-as-feature nor split strategy, alone or stacked,
accounts for the gap. Full table in `docs/DEVIATIONS.md` DEV-06; source data checked directly:
every address carries one label end to end, but ransomware addresses repeat far more than benign
ones (mean 1.99 vs 1.10 rows/address).

**BitcoinHeist, `honest_mode`** (200K subsample, 5-fold, run `20260912T172809Z-d89aa1b6`): best
MCC is DT at 0.331, best PR-AUC is RF at 0.335, recall spans 0.00–0.36, and LR finds nothing at
all. A constant-negative classifier scores **0.9858 accuracy** — this is an illustration of
accuracy's distribution-sensitivity against the paper's 90/10-derived 0.9898, not a like-for-like
comparison (framing fixed in `docs/EXPERIMENTS.md` Target 1 and `docs/PAPER_NOTES.md`). Full-scale
(2.9M) `honest_mode` is **deferred to Ada, unrun**.

**Honeypot corpus** (M4b's data): intended Bayes-optimal ≈ **0.85**, measured baseline 0.830.
A detector scoring far above that is reading a leak.

## What M4b must not re-derive

- **The corpus is fixed (Q9).** Train on `data/honeypot/corpus_train.csv`, evaluate on
  `corpus_eval.csv`, as committed. Never regenerate per experiment; never shuffle one draw into
  both roles. Features are exactly `honeypot.features.FEATURE_NAMES` (22); `label` is the target;
  everything in `corpus.METADATA_COLUMNS` is provenance and must not enter a model.
- **Do not restore the full kill-chain feature** — `observed_stages` is truncated on purpose
  (DEV-27); the whole chain is the label in disguise.
- **Both modes, always, with baselines first** (DEV-06). `detection.metrics.baselines()` runs
  before any estimator is fitted, and no model number is reported without it.
- **`paper_mode` needs the whole dataset.** It uses every ransomware row, so a subsampled load
  runs a different, much smaller experiment; `run_detection.py` refuses it (`--full`).
- **The §VII counts are the anchor** — `load_bitcoinheist(verify=True)` raises rather than
  continuing on a file that is not the paper's. `make data` re-fetches and re-verifies.
- **Project compute before running it** (CLAUDE.md §6): `knn_projection()` decided KNN's fate at
  both scales; 1.23 GB at 200K ran, 17.94 GB at 2.9M is the Ada job.
- **`detection/` may not import `framework/` or `consensus/`**; `honeypot/` may not import
  `framework/`. Pinned by `test_module_boundaries.py`.
- **Every run writes a sidecar and a `measured` RESULTS.md line with its run_id.** A number
  without a line does not exist.
- **Test harnesses:** `pbft_harness.py`, `m3a_harness.py`, `m3b_harness.py`.

## Next task

**M4b — the honeypot backend and Alg. 3.** Add `HoneypotBackend` to `detection/dataset.py`
(reading the committed corpus, and the chain path via `SignatureRecordPayload`),
`detection/profiles.py` (`NProf`/`AProf`), `detection/detector.py` (Alg. 3's loop) and
`framework/phase3_detection.py`. Reuse `detection/metrics.py` unchanged. Exit: the framework's own
data path runs end to end and its accuracy is reported against the corpus's stated 0.85 — **a
number near 1.0 is a leak to find, not a result**. Report the honeypot and BitcoinHeist backends
side by side (FLAW-2).

## Blockers

None. Note that `data/raw/` is gitignored, so a fresh clone needs `make data` (~56 minutes at this
environment's throughput) before any BitcoinHeist run; README now states this and the sha256.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q2 | Transaction payload size — 4096 B *declared* (DEV-15), not justified | M6 result validity | **Deferred.** Needs M6's sweep; DEV-24 pins the meaning and the measured framing overhead. |
| Q4 | Do we need real feature-space evasion for M7? | M7 | defer until M6 lands |
| Q5 | One merged config object or three files at the entry points? | M6 | decide when `bench/` becomes the first multi-config consumer |
| Q8 | Does anything before M7 need pBFT state transfer (DEV-20 item 2)? | M6 | only if M6 benchmarks a lossy network |

**Q10 closed** (2026-09-13): neither `address` as a feature nor a random (vs. address-grouped)
split explains the reproduction gap — best of the 2x2's 16 model x cell combinations is 3.58
accuracy points under published. See `docs/DEVIATIONS.md` DEV-06 amendment and `RESULTS.md`.

## For the write-up

**§V-3.** pBFT's threshold is one *third*, not one half, so "PoW is 51%-vulnerable, therefore pBFT"
lowers the bar; at four nodes two colluders fork it, and a test asserts the fork. [FLAW-5].

**§V-1 / §V-5 (M3a).** §V-1 holds wherever Phases 1, 2 and 5 use session keys, but session keys
protect bytes in transit, not at the servers — hence DEV-23's attested digest (GAP-8). §V-5 is
substantiated only structurally.

**GAP-3 / FLAW-2 (M3b).** The paper defines neither the honeypot's output nor its features, then
evaluates on an unrelated Bitcoin dataset. M3b supplies the missing layer.

**FLAW-4, extended, and the non-reproduction (M4a, Q10).** The 90/10 resample is degenerate *and*
bounded at 46,014 rows — 1.58% of the cited 2.9M. Our honest reproduction (address dropped,
grouped split) reaches 0.9442/0.9697 against a published 0.9898/0.990; Q10 tested and ruled out
`address`-as-feature and split-grouping as the explanation, so the gap is reported as
**unexplained**, not attributed. At the natural rate, never predicting ransomware scores 0.9858 —
stated as an illustration of accuracy's distribution-sensitivity, not a like-for-like comparison
against the paper's 0.9898 (`docs/PAPER_NOTES.md` NOTE). The airtight within-split comparison:
constant-positive on the paper's own 90/10 split scores 0.9000/0.9474, and Sharmeen et al.'s
published F1 of 0.960 — presented in Table II as a competitive prior technique — clears that floor
by only 0.013 (FLAW-1, extended).

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D2 | `make lint` covers `src` and `tests` but not `scripts/`, and `mypy` only covers `src`. `scripts/` now has five files, including both M4a entry points and the Q10 ablation. | M6 |
| D3 | The bus never serialises, so wire-encoding cost is absent from the consensus span. | M6 |
| D4 | `ClientRequest` is unauthenticated (DEV-20 item 5). | when a claim needs it |
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8 and **removed in 1.10**; `configs/ml.yaml` still declares it (dropping it would silently accept a library default). Migrate to `l1_ratio=0` before upgrading. | before sklearn 1.10 |
| D6 | `scripts/run_detection.py`'s `paper_mode` still splits with row-random `stratified_holdout`. The honest headline (address dropped, grouped split) is currently produced only by `scripts/q10_leakage_ablation.py`, so the two entry points disagree. Fold `grouped_stratified_holdout` into the production pipeline. | before M6/figures cite `run_detection.py` as the paper_mode source |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| We wrote both the corpus generator and, in M4b, its classifier | M4b's number could measure the generator | difficulty stated up front (0.85) and enforced by the M3b leakage tests |
| Python timings diverge from the paper's Java | Targets 3 and 4 unverifiable | report ratios and shape (DEV-13) |
| Zero-delay consensus measures encryption, not consensus | Target 3 claims something different | DEV-21: delay 0 and delay > 0 in separate columns |
| The non-reproduction is read as our bug rather than a finding | the write-up's central claim collapses | baselines published beside every number; Q10 tested and ruled out address/split leakage |
| `data/raw/` is gitignored and slow to fetch | a fresh machine cannot rerun M4a quickly | `make data` verifies counts; README + `provenance.json` state the wait and the sha256 |
| The canonical encoding changes after hashes exist | stored hashes silently unreproducible | `ENCODING_VERSION` plus pinned golden vectors |
| Validation migrates out of `Chain` | two definitions of a valid block | `check_append` / `verify_block` are the only validators |

---

## Maintenance rule

This file is **replaced, not appended.** At session end:

1. Rewrite the tables above so they describe reality *now*.
2. Delete anything resolved. A closed question leaves this file entirely — its reasoning lives in
   the session log that closed it.
3. Do not paste benchmark output here. One aggregate number max; details go to `RESULTS.md`.
4. Do not paste narrative here. Narrative goes to `sessions/`.
5. If you are about to add a fifth row to a table that already has ten, something is being
   tracked at the wrong granularity — move it to `docs/ROADMAP.md`.

**Why the cap exists:** we run one session per task, so this file is read at the start of *every*
session. A 200-line file costs a few seconds of context; a 2,500-line one costs a meaningful
fraction of the window before any work begins, and gets skimmed rather than read.

## Boundaries with other docs

| File | Holds | Volatility |
|---|---|---|
| `PROJECT_STATE.md` | what is true right now | rewritten every session |
| `docs/ROADMAP.md` | the plan, M0–M7, checkboxes | ticked, rarely restructured |
| `RESULTS.md` | every benchmark ever run, one line each | append-only |
| `sessions/` | what happened in each session | append-only, one file per session |
| `docs/DEVIATIONS.md` | departures from the paper | append-only |
| `CLAUDE.md` | how to work here | near-stable |

If a fact could go in two of these, it goes in exactly one — the leftmost row that fits.
