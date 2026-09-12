# Session 2026-09-12-03 — M4a, the BitcoinHeist pipeline

**Milestone:** M4a · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/EXPERIMENTS.md` (Targets 1–2, and the output contract for sidecars),
`docs/DEVIATIONS.md` DEV-06 and DEV-07, `sessions/_TEMPLATE.md`, `configs/ml.yaml`,
`RESULTS.md`, and `scripts/bench_ecdsa_backends.py` for the established sidecar/run-id pattern.
Per the ladder, **not** `docs/ALGORITHMS.md` and **not** `docs/PAPER_NOTES.md` beyond §VII.
· **Duration:** one working session

---

## Brief *(written before any work)*

**Task:** Build the BitcoinHeist half of Phase 3 — loader, the two evaluation modes, the
baselines, and the four models — and reproduce Table II's BSFR-SH row in `paper_mode` with
`honest_mode` reported beside it.

**Exit condition:** `make test` and `make lint` exit 0; Table II's BSFR-SH row reproduced in
`paper_mode` with the resulting `n` recorded in `RESULTS.md`; `honest_mode` numbers produced for
whatever ran locally, with anything deferred to Ada named explicitly rather than skipped; the
constant and stratified-random baselines published alongside every model number; every run
carries a sidecar in `results/logs/` and a `measured` line in `RESULTS.md`.

**Out of scope:** the honeypot backend, `NProf`/`AProf`, the Alg. 3 detection loop, and every
figure. Those are M4b and M6. No BitcoinHeist number may be quoted that this session did not
measure.

**Prior context needed:** `docs/EXPERIMENTS.md` Targets 1–2 (the dataset's shape and the
reproduction target), DEV-06 (both modes, never one without the other), DEV-07 (Table II's rows
are not like-for-like), and `configs/ml.yaml`, which already declares every hyperparameter.

### Q9, closed first, as instructed

**The committed corpus is the fixed dataset.** `data/honeypot/corpus_train.csv` and
`corpus_eval.csv` are M4's data; experiments do not regenerate them. Regenerating per experiment
would make every M4 number incomparable with every other one — two runs would differ both in the
model and in the data underneath it, and no difference between them could be attributed. The
manifest keeps regeneration reproducible if the schema ever changes, but that is a deliberate,
version-bumping act, not something an experiment does on the way past. Recorded in DEV-27 and in
`honeypot/corpus.py`.

### The dataset was not on this machine

`data/raw/` held only `.gitkeep`, and `make data` had never been implemented — it exited 1
pointing at this milestone. So there was nothing to verify counts against. Since CLAUDE.md §5
specifies `make data` as "fetch/verify BitcoinHeist into `data/raw`", implementing and running it
*is* step 1 of this task rather than a detour. The rule the prompt gave stands unchanged: the
counts must match §VII's 2,916,697 rows / 2,875,284 white / 41,413 ransomware **before** any model
is fitted, and a mismatch stops the session instead of being worked around.

### Decisions taken before writing code

1. **`address` is dropped at load, not after.** It is an identifier, it leaks, and 2.9M Python
   strings as `object` dtype cost more RAM than all nine numeric features together. Dropping it in
   the `usecols` of the read is the difference between a comfortable load and an 8 GB box
   swapping.
2. **`paper_mode`'s size is arithmetic, and the arithmetic is a finding.** Only 41,413 ransomware
   rows exist, so a 90%-ransomware resample is bounded at 41,413 / 0.9 ≈ **46,014 rows**, not
   2.9M. The paper never states this. The headline 98.98% therefore came from an experiment about
   1.6% the size of the dataset it cites. The actual `n` goes in `RESULTS.md`.
3. **Baselines are computed before any model is fitted**, so no model number ever appears without
   the number that makes it interpretable: constant-positive on the 90/10 split (analytically
   accuracy 0.900, F1 0.9474 — confirmed empirically), and constant-negative plus stratified-random
   on `honest_mode`, where never predicting ransomware scores ≈98.58% accuracy.
4. **Compute is projected before `honest_mode` runs, not discovered during it** (CLAUDE.md §6).
   KNN is the hazard: no training cost, all of it at predict time, O(n_train × n_query) per fold.
   If the projection approaches the 8 GB ceiling, the run is prepared as an Ada job and named as
   deferred rather than attempted locally first.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/EXPERIMENTS.md
Targets 1-2, docs/DEVIATIONS.md DEV-06 and DEV-07. Not docs/ALGORITHMS.md,
not docs/PAPER_NOTES.md beyond §VII.

Create the session file from the template and fill the brief first.

M4 is being split. This is M4a — the BitcoinHeist pipeline, which is the
paper's reproduction target. M4b is the honeypot backend and Alg. 3 proper.
Update docs/ROADMAP.md.

Close Q9 first: the committed corpus is the fixed dataset. Regenerating per
experiment makes every M4 number incomparable to every other. Record it.

TASK — M4a. detection/dataset.py, models.py, metrics.py — BitcoinHeist only.

1. Data loading.
   2,916,697 rows, 10 attributes. Drop `address` at load — it is an
   identifier, it leaks, and 2.9M Python strings as object dtype costs more
   RAM than all nine numeric features combined. Binary target: `white` -> 0,
   any named family -> 1. Natural rate ~1.42% positive.

   Verify the row counts and class counts against §VII before proceeding. If
   the file you have does not match 2,875,284 / 41,413, say so rather than
   continuing — the reproduction is anchored to those numbers.

2. paper_mode — the reproduction target, DEV-06.
   Resample to 90% ransomware / 10% benign. Note what this implies: only
   41,413 ransomware rows exist, so the split is bounded at roughly 46,000
   rows total, not 2.9M. The paper never states this. Record the actual
   resulting n in RESULTS.md — it is a finding, and it means the headline
   98.98% came from a ~46K-row experiment.

3. honest_mode — DEV-06.
   Natural 1.42% positive, stratified k-fold. Metrics: precision, recall,
   PR-AUC, MCC, minority-class F1, confusion matrix.

4. Baselines, computed before any model is fitted.
   Constant-positive on the 90/10 split: accuracy 0.900, F1 0.947 — already
   in RESULTS.md as analytic. Confirm empirically. Also compute the
   constant-negative and stratified-random baselines on honest_mode, where
   accuracy will be ~98.6% for a classifier that never predicts ransomware.
   That contrast is the entire point of DEV-06 and it must appear in the
   output, not just the write-up.

5. Models: RF, LogReg, DecisionTree, KNN. Hyperparameters declared in
   configs/ml.yaml, not defaulted silently — the paper reports none.

   Compute: paper_mode at ~46K rows runs anywhere. honest_mode at 2.9M is
   different. Cap RF depth and set n_jobs. KNN has no training cost and all
   its cost at predict time — O(n_train x n_query) per fold — so it is the
   one that will not finish locally. Project peak memory before running
   honest_mode, per CLAUDE.md §6; if the projection is near the 8 GB ceiling,
   stop and prepare an Ada job rather than attempting it locally first.

6. Every run writes a sidecar to results/logs/ with config hash, scheme
   version, seed, host, and wall time. Every number gets a RESULTS.md line
   with mode=measured.

TESTS
Class counts match §VII. `address` absent from the feature matrix. paper_mode
n is what the resample arithmetic predicts. No row appears in both train and
test in either mode. Stratification preserves the class rate per fold.
Baselines produce their analytic values.

EXIT CONDITION
make test and make lint green. Table II's BSFR-SH row reproduced in
paper_mode with the resulting n recorded. honest_mode numbers produced for
whatever ran locally, with anything deferred to Ada named explicitly rather
than skipped silently. Baselines published alongside.

OUT OF SCOPE
No honeypot backend, no NProf/AProf, no Alg. 3 detection loop, no figures.
That is M4b and M6.

END OF SESSION
Session file with attribution and dead ends. RESULTS.md lines for every run.
Close Q9. Rewrite PROJECT_STATE.md, under 200 lines. Tick M4a and record the
split. Commit explaining why.
```

---

## What was done

**Attribution.** All new code, tests and doc text are **AI-generated (Claude, Opus 5),
human-directed**. From the prompt: the M4a/M4b split, Q9's answer, dropping `address` at load, both
evaluation modes, baselines *before* fitting, the requirement to project compute before running
`honest_mode`, the sidecar/RESULTS contract, and the instruction to stop rather than continue on a
dataset whose counts do not match §VII. Claude's: the module boundaries, `paper_mode_arithmetic()`
as a pure function so the ~46K bound is testable without data, the `LoadedDataset`/`Resample`
shapes, hand-written stratified splitters, `knn_projection()`, and the Ada job script. No file was
human-edited this session.

**Q9 closed** (see the brief): the committed corpus is the fixed dataset. Recorded in DEV-27 and
in `honeypot/corpus.py`.

**New modules**

| Module | What it does |
|---|---|
| `detection/dataset.py` | loads BitcoinHeist with `address` excluded at `usecols`, maps the label to binary, verifies §VII's counts before anything is fitted, `paper_mode_arithmetic`/`paper_mode_resample`, hand-written stratified holdout and k-fold |
| `detection/metrics.py` | `paper_metrics` (accuracy, F1), `honest_metrics` (precision, recall, PR-AUC, MCC, minority F1, confusion), `baselines()` for the three no-information classifiers, `analytic_constant_positive()` |
| `detection/models.py` | the four estimators built from `configs/ml.yaml` with the seed injected, `fit_and_score` timing fit and predict separately, `knn_projection`/`fits_in_memory` |

**Supporting**

| File | Change |
|---|---|
| `scripts/fetch_bitcoinheist.py` + `make data` | implemented the target CLAUDE.md §5 promised; fetch, extract, stream-count, verify against §VII, write `data/raw/provenance.json` |
| `scripts/run_detection.py` | sequences both modes, baselines first, sidecar to `results/logs/`, prints `RESULTS.md` lines |
| `scripts/ada_honest_mode.sbatch` | the full-scale run, prepared and **unrun** — see Findings |
| `configs/ml.yaml` | records the sklearn `penalty` deprecation rather than silently dropping the declaration |
| `pyproject.toml` | narrowly scoped mypy override for `sklearn.*` and `pandas.*`, the stanza the file anticipated |
| `tests/unit/test_module_boundaries.py` | `detection` may not import `framework` or `consensus` |
| docs | ROADMAP split into M4a/M4b; DEV-06 amended with the sample-size finding; DEV-27 amended with Q9; PAPER_NOTES §VII FLAW-4 extended |

**Tests: 993 → 1093 unit (+100), 10 integration.** New: `test_detection_dataset.py`,
`test_detection_metrics.py`, `test_detection_models.py`. One test is skipped when
`data/raw/BitcoinHeistData.csv` is absent and asserts §VII's exact counts when present, so the
anchor is checked by the suite rather than by hand.

## Findings

**The dataset was not on this machine, and `make data` had never been implemented.** `data/raw/`
held only `.gitkeep`; the Makefile target exited 1 pointing at this milestone. So the prompt's stop
condition — "if the file you have does not match 2,875,284 / 41,413, say so rather than
continuing" — applied in its strongest form: there was no file to check. Implementing the fetch was
step 1 rather than a detour, since CLAUDE.md §5 already specifies `make data` as "fetch/verify
BitcoinHeist into `data/raw`".

**The 90/10 split costs 98% of the dataset, and the paper never says so.** Only 41,413 ransomware
rows exist, so a 90%-ransomware resample holds at most 46,014 rows — **1.58% of the 2,916,697 it
cites**. The headline 98.98% is a number from a ~46K-row experiment printed directly beneath a
2.9M-row dataset description. This compounds the flaw already recorded as FLAW-4: the balance is
degenerate *and* the evidence base is a rounding error of the cited corpus, so Table II compares a
46K-row resample against four other papers' full corpora. It is pure arithmetic from published
counts, so it is asserted as a unit test and holds whether or not we ever load the file.
Recorded in DEV-06 and PAPER_NOTES §VII.

**KNN at full scale is impossible here, and the projection says so before anything runs.**
Measured by `knn_projection()`, not guessed: 5-fold over 2,916,697 rows means 2,333,358 training
rows against 583,339 queries per fold — **17.94 GB** for the distance block alone against an 8 GB
ceiling, and **1.36e12** distance computations per fold. `paper_mode` by contrast needs 0.25 GB and
4.4e8 computations, and the configured 200K subsample needs 1.23 GB. So KNN is recorded as deferred
to Ada with the projection attached, and `scripts/ada_honest_mode.sbatch` is committed **unrun**:
this environment has no Ada access, so it is a prepared job, not a result, and nothing may cite it
until it has actually run.

**scikit-learn 1.9.1 deprecates `LogisticRegression(penalty=...)`**, removed in 1.10. Dropping the
line would mean silently accepting a library default for a hyperparameter the paper never reports —
the one thing this session must not do — so the declaration stays, the replacement (`l1_ratio=0`) is
named in `configs/ml.yaml`, and the migration is carried debt. Every run under sklearn ≥ 1.8 emits
a FutureWarning for it; that is expected, not a fault.

**The runner was smoke-tested on synthetic data before the real file arrived**, which is how the
sklearn deprecation and the orchestration paths were found without burning a download. On a
synthetic 1.42%-positive frame, `paper_mode` produced exactly the arithmetic's `n` and every model
landed at or below the constant-positive baseline — the shape DEV-06 predicts, reproduced in
miniature.

**The headline does not reproduce, and three of four models cannot beat a constant.** Best here is
random forest at 0.9479 / 0.9717 against a published 0.9898 / 0.990; the paper's own best
algorithm, the decision tree, reaches 0.9262. Logistic regression scores *exactly* the
constant-positive baseline (0.9000 / 0.9474) because it predicts the majority class for every row,
and KNN lands below it. I have not tried to close the gap and have not invented a reason for it.
Three hypotheses are worth testing, in order of how much they would explain: (1) `address` left in
as a feature, which would leak the label — the paper never says it was dropped, and it is the one
change that could plausibly move accuracy from 0.95 to 0.99; (2) undeclared hyperparameters, since
the paper reports none; (3) a different resample composition or seed. **(1) is a one-run
experiment** and is recorded as open question Q10 rather than asserted here.

**Logistic regression inverts with the class balance, which is DEV-06 in one line.** On the 90/10
resample it predicts *everything* positive (0.9000 / 0.9474, identical to the constant baseline);
at the natural 1.42% it predicts *nothing* positive (precision, recall and MCC all 0.0). Same
model, same declared hyperparameters, same features — only the balance changed. Any accuracy
number quoted from the first regime describes the resample, not the model.

**At the natural rate, the paper's headline is 0.4 points above finding nothing.** A
constant-negative classifier scores 98.58% accuracy on this data against the published 98.98%.
The four models recover between 0% and 36% of the ransomware, and the best MCC is 0.331 — there is
real signal (RF's PR-AUC of 0.335 is ~24× the 0.0142 base rate), but no operating point here is
usable, which the accuracy framing completely hides.

**KNN ran locally after all, at the configured subsample.** The projection was the decision
procedure, not a guess: 1.23 GB at 200K rows (fits, ran), 17.94 GB at 2.9M (does not, deferred).
So the deferral is specific — full-scale `honest_mode` only — rather than "KNN is too slow".

## Numbers

Dataset, verified before any fit: 2,916,697 rows · 2,875,284 benign · 41,413 ransomware · 1.42%
positive · 28 families · sha256 `8ecc3744…c438`. Exactly §VII.

**`paper_mode`** — 90/10 resample, `n=46,014` (41,413 + 4,601), 70/30 stratified holdout,
run_id `20260912T172708Z-6d35b415`:

| Model | Accuracy | F1 |
|---|---|---|
| Random forest | 0.9479 | 0.9717 |
| Decision tree *(the paper's best)* | 0.9262 | 0.9590 |
| Logistic regression | 0.9000 | 0.9474 |
| KNN | 0.8861 | 0.9392 |
| **Constant-positive baseline** | **0.9000** | **0.9474** |
| *Published BSFR-SH (paper_reported)* | *0.9898* | *0.990* |

**`honest_mode`** — natural 1.42%, 200,000-row subsample, stratified 5-fold, pooled out-of-fold
predictions, run_id `20260912T172809Z-d89aa1b6`:

| Model | Precision | Recall | PR-AUC | MCC | F1 (minority) |
|---|---|---|---|---|---|
| Random forest | 0.7414 | 0.1292 | 0.3349 | 0.3062 | 0.2201 |
| Decision tree | 0.3239 | 0.3581 | 0.1253 | 0.3306 | 0.3401 |
| KNN | 0.4985 | 0.1155 | 0.1169 | 0.2352 | 0.1875 |
| Logistic regression | 0.0000 | 0.0000 | 0.0181 | 0.0000 | 0.0000 |
| Constant-negative baseline | — | 0.0000 | — | 0.0000 | 0.0000 (accuracy **0.9858**) |

Both runs have sidecars in `results/logs/`. Suite: 1093 unit + 10 integration (1103 total);
the real-dataset count check no longer skips, now that `data/raw/` is populated.
`make data` fetch: ~56 minutes at ~37 KiB/s for a 116 MB archive (235.9 MB CSV) — environment
throughput, not a property of the pipeline.

## Deviations opened or changed

- **DEV-06** amended: the 90/10 resample is bounded at 46,014 rows, 1.58% of the cited dataset.
- **DEV-27** amended: the committed corpus is the fixed dataset (Q9 closed).
- No new DEV number was needed: M4a implements DEV-06 and DEV-07 rather than departing further.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** BitcoinHeist is fetched, verified against §VII (2,916,697 / 2,875,284 / 41,413)
and run through both evaluation modes with baselines beside every number. `make data` exists and
re-verifies on any machine. The published BSFR-SH row **did not reproduce** — best here is
0.9479 / 0.9717 against 0.9898 / 0.990 — and that gap, with its baselines, is recorded in
`RESULTS.md` with run ids. Full-scale `honest_mode` is prepared for Ada and unrun. `detection/`
holds `dataset.py`, `models.py` and `metrics.py`; `profiles.py`, `detector.py` and
`phase3_detection.py` do not exist yet.

**Next task:** Build M4b — `HoneypotBackend` in `detection/dataset.py` (the committed corpus, and
the chain path via `SignatureRecordPayload`), `detection/profiles.py` (`NProf`/`AProf`),
`detection/detector.py` (Alg. 3's loop) and `framework/phase3_detection.py`, reusing
`detection/metrics.py` unchanged. Exit: the framework's own data path runs end to end and reports
against the corpus's stated Bayes-optimal 0.85 — a number near 1.0 is a leak to find, not a
result — with the honeypot and BitcoinHeist backends reported side by side (FLAW-2).

**New blockers:** none. `data/raw/` is gitignored, so a fresh clone needs `make data` first
(~56 minutes at this environment's throughput; `provenance.json` records the sha256).

**Questions opened / closed:** **Q3 closed** — the 200K stratified subsample is enough for
`honest_mode` locally (all four models in 13 s); `paper_mode` needs the full file and loads it in
~1.3 s. **Q9 closed** — the committed corpus is the fixed dataset. **Q10 opened** — why doesn't
98.98% reproduce? Leading hypothesis is `address` kept as a feature, which leaks the label; it is a
one-run experiment and belongs to M4b or a follow-up. **D5 opened** — sklearn removes
`LogisticRegression(penalty=…)` in 1.10.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended — two blocks, one line per model per mode, every row `measured` with a
      run id, plus the named Ada deferral
- [x] `docs/ROADMAP.md` boxes ticked — M4 split into M4a/M4b, M4a `[x]` with the exit condition
      stated honestly (experiment ran; published row not reproduced)
- [x] `docs/DEVIATIONS.md` updated — DEV-06 and DEV-27 amended
- [x] Committed, message explains *why*
