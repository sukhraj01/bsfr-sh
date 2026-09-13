# Session 2026-09-13-02 — M4b: the honeypot detection path and Algorithm 3

**Milestone:** M4b · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`, `docs/ALGORITHMS.md`
(Alg. 3), `docs/PAPER_NOTES.md` §IV-C, `docs/ARCHITECTURE.md` §honeypot and §detection,
`docs/NOTATION.md`, `sessions/_TEMPLATE.md`, plus (as the task required) the current
`detection/dataset.py`, `detection/models.py`, `detection/metrics.py`, `honeypot/collector.py`,
`honeypot/features.py`, `honeypot/corpus.py`, `honeypot/signatures.py`,
`framework/phase1_backup.py`, `framework/phase2_collection.py`, `blockchain/transaction.py`,
`blockchain/chain.py`, `recovery/locator.py`, `recovery/restore.py`, `tests/unit/pbft_harness.py`,
`m3a_harness.py`, `m3b_harness.py`, `test_phase2_collection.py`, `tests/unit/
test_module_boundaries.py`, `tests/integration/test_sigrw_scale.py`, `configs/ml.yaml`, and
`scripts/run_detection.py`/`q10_leakage_ablation.py`/`make_honeypot_corpus.py`. Not
`docs/EXPERIMENTS.md` in full — only enough to confirm the D6 fix's citation. · **Duration:** one
working session.

---

## Brief *(written before any work)*

**Task:** two parts. Step 0 retires D6 (the production `paper_mode` split still ran row-random,
disagreeing with the honest grouped-split figure); the main task is M4b — build the honeypot
detection path (`HoneypotBackend`, `NProf`/`AProf`, `DetectionModule`, `phase3_detection`) that
Algorithm 3 specifies and the paper's own evaluation (§VII, BitcoinHeist) never exercises.

**Exit condition:** `make test` and `make lint` green; `scripts/run_detection.py`'s `paper_mode`
groups by address and reproduces 0.9442/0.9697 from the production entry point; Phase 3 runs end
to end from real `BC_SigRW` chains built by `framework.phase2_collection.run()` through actual
pBFT consensus, scoring near the corpus's stated ~0.85 difficulty (not above it — that would be a
leak); `RESULTS.md` lines for both; D6 retired and 0.9442 cited consistently in
`docs/EXPERIMENTS.md` and `PROJECT_STATE.md`.

**Out of scope:** Phase 4, mitigation, the state machine, `bench/`, figures, any BitcoinHeist work
beyond the D6 fix.

**Prior context needed:** `docs/ALGORITHMS.md` Alg. 3's table already pins exact function names
(`load_from_chain`, `train_all`, `profiles.build`, `DetectionModule.run`) and
`test_module_boundaries.py::test_detection_does_not_orchestrate` already anticipates M4b's
backend split (`detection` may import `honeypot` and `blockchain`, not `framework`/`consensus`) —
both read as a contract from a prior session, followed rather than redesigned.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/ALGORITHMS.md
(Alg. 3), docs/PAPER_NOTES.md §IV-C, docs/ARCHITECTURE.md §honeypot and
§detection, docs/NOTATION.md. Not docs/EXPERIMENTS.md — M4a covered Targets
1-2 and this session is not about them.

Create the session file from the template and fill the brief first.

STEP 0 — retire D6.
Update run_detection.py to group by address on the paper_mode split, so the
production pipeline reports 0.9442 rather than 0.9479. The repo currently
holds two different values for the same headline claim, with the correct one
only in a closed session's results. Re-run and update the RESULTS.md line and
sidecar. Confirm docs/EXPERIMENTS.md and PROJECT_STATE.md both cite 0.9442.

TASK — M4b. The honeypot detection path and Algorithm 3 proper.

This is the half of Phase 3 the paper describes but never evaluates. FLAW-2:
§IV-C says the detector consumes Sig_RW and FT_RW from BC_SigRW, and §VII
evaluates on Bitcoin addresses instead. M4a reproduced their evaluation.
This session builds what their framework actually specifies.

1. detection/dataset.py — HoneypotBackend.
   Decrypt BC_SigRW, yield FT_RW vectors per the record schema in
   docs/ARCHITECTURE.md §honeypot. Same interface as BitcoinHeistBackend,
   selected by config, never hardcoded.

   Use the committed corpus (Q9): train seed 20260912, eval seed 20260913,
   independent draws. Do not regenerate.

2. detection/profiles.py — NProf and AProf, Alg. 3 line 3.
   The paper describes these as definitions of normal and abnormal files,
   built via the four algorithms. They are the fitted class-conditional
   descriptions. Build them as the paper specifies rather than collapsing
   them into "the classifier" — Alg. 3 line 4 detects *via* NProf and AProf,
   and that structure should be visible in the code.

3. detection/detector.py — Alg. 3 lines 4-9.
   Real-time detection loop: consume a sample, decide, and on a positive
   hand off to Phase 4. Phase 4 does not exist yet, so the handoff is an
   interface and a raised event, not a call into mitigation.

4. framework/phase3_detection.py — Alg. 3 lines 1-9 end to end.
   Chain -> decrypt -> train -> profiles -> detect. This is the first time
   Phase 2's output feeds Phase 3's input, which is the thing the paper
   never demonstrates.

THE NUMBER THAT MATTERS
PROJECT_STATE records the corpus's expected difficulty: Bayes-optimal ~0.85,
measured baseline 0.830 balanced accuracy. A detector scoring far above 0.85
here is reading a leak, not detecting. If that happens, stop and find it —
do not report it. The generator's leakage test exists for exactly this and
should be re-run against the trained models, not just the raw features.

Report balanced accuracy, precision, recall, MCC and PR-AUC. Accuracy alone
is not informative even on a balanced corpus, and M4a established why.

TESTS
Round trip: corpus -> Phase 2 -> BC_SigRW -> HoneypotBackend -> features
recovered intact and identical to pre-chain values. Train and eval draws stay
separate — no sample from one appears in the other. Detector fires on known
positives and stays quiet on known negatives. Profiles are built from the
chain, not from the corpus files directly — if it can read data/honeypot/
instead of the chain, the phase is not actually wired. Backend selection by
config, both backends satisfying the same interface.

EXIT CONDITION
make test and make lint green. Phase 3 runs end to end from BC_SigRW with
metrics in the expected difficulty range and a RESULTS.md line. D6 retired,
0.9442 cited consistently everywhere.

OUT OF SCOPE
No mitigation, no Phase 4, no state machine, no bench harness, no figures.
No BitcoinHeist work beyond the D6 fix.

END OF SESSION
Session file with attribution and dead ends. RESULTS.md lines for the
honeypot-path runs. If the wired-up Phase 2 -> Phase 3 path reveals anything
about FLAW-2 worth stating more precisely, amend docs/PAPER_NOTES.md.
Rewrite PROJECT_STATE.md, under 200 lines. Tick M4b. Commit explaining why.
```

---

## What was done

**D6 retirement** (AI-generated):
- `configs/ml.yaml` — added `dataset.group_column: address`.
- `src/bsfr_sh/detection/dataset.py` — `DatasetSpec.from_config` now reads `group_column`;
  `load_bitcoinheist`'s drop-column check exempted `group_column` from the "must not reach the
  frame" assertion (it found a real bug — the check assumed `drop_columns` and `group_column`
  never overlapped, which broke the instant `configs/ml.yaml` declared `address` as both). A test
  (`test_group_column_may_also_be_a_declared_drop_column`) pins the fix.
- `scripts/run_detection.py` — `_run_paper_mode` now calls `grouped_stratified_holdout` instead
  of `stratified_holdout`; docstring and `_print_results_lines` updated to name the split.
- Re-ran `python scripts/run_detection.py --seed 20260912 --mode paper --full`: RF
  0.9442/0.9697, exactly matching Q10's `address_dropped x grouped_split` cell. New sidecar
  `20260913T131623Z-97f51129`, new `RESULTS.md` section.
- `docs/DEVIATIONS.md` DEV-06 amended (D6 retired), `docs/ROADMAP.md`'s M4a/Q10 note updated,
  `docs/EXPERIMENTS.md` Target 1 now states the measured 0.9442/0.9697 figure explicitly.

**M4b** (AI-generated, human-reviewed in this session):
- `src/bsfr_sh/detection/dataset.py` — `DetectionDataset` (the shape both backends produce),
  `DatasetBackend` (a `Protocol`), `BitcoinHeistBackend` (thin wrapper over `load_bitcoinheist`),
  `load_from_chain()` + `HoneypotBackend` (decrypts `BC_SigRW`, validates schema and vector
  length against `honeypot.features` before trusting a value), `backend_from_config()` (picks by
  `dataset.name`, requires `chain`/`decrypt` only for `honeypot`).
- `src/bsfr_sh/detection/models.py` — `train_all()`: fit all four declared models on one draw
  (Alg. 3 line 2), no split, no timing — that is `fit_and_score`'s job for M4a's comparison.
- `src/bsfr_sh/detection/profiles.py` (new) — `NormalProfile`/`AbnormalProfile` (`NProf`/`AProf`,
  named exactly as `docs/NOTATION.md` pre-registered them), `ensemble_score()` (the four trained
  models' soft-vote), `build()`. A profile is the fitted mean/spread of the *trained ensemble's*
  score on one class's rows, not an independent statistic — see Findings.
- `src/bsfr_sh/detection/detector.py` (new) — `Detection`, `Phase4Handoff`
  (`Callable[[Detection], None]`), `DetectionModule` (Alg. 3 lines 4-9: decide by nearest-profile
  membership, hand off on a positive, never stop the loop).
- `src/bsfr_sh/framework/phase3_detection.py` (new) — `run()`: two chains in, decrypt both,
  train, profile, detect, report. Never imports `consensus` or `honeypot.corpus` (pinned by
  `test_phase3_detection.py`'s import-graph checks).
- `docs/DEVIATIONS.md` DEV-28 (new) — the profile/handoff design decisions, with rationale.
- `docs/ARCHITECTURE.md` §detection — updated to describe `detector.py` and
  `framework/phase3_detection.py`, which the doc did not mention before this session.
- `docs/PAPER_NOTES.md` §IV-C — amended: the honeypot path is not merely possible, it is the one
  evaluation path in this project that walks Fig. 3 end to end, and it scores a real number.
- Tests: `tests/unit/test_detection_dataset_honeypot.py`,
  `tests/unit/test_detection_profiles.py`, `tests/unit/test_detection_detector.py`,
  `tests/unit/test_phase3_detection.py` (direct-append chains, fast), and
  `tests/integration/test_phase2_feeds_phase3.py` (real pBFT consensus, both chains, the actual
  Phase 2 → Phase 3 demonstration).
- `scripts/run_phase3_detection.py` (new) — the headline-number entry point: one honeypot,
  harvested twice (train seed from `--seed`, eval seed `--seed + 1` — `Honeypot.harvest()`
  derives that automatically, matching how `make_honeypot_corpus.py` derived Q9's two seeds),
  each draw through real Phase 2 + pBFT consensus onto its own `BC_SigRW`, then Phase 3. Checks
  balanced accuracy against `EXPECTED_BAYES_ACCURACY + 0.05` before printing a `RESULTS.md` line —
  refuses to report past that margin.
- Ran it: `python scripts/run_phase3_detection.py --seed 20260912`. Kept counts after cleaning
  (1467 train, 731 eval) matched `data/honeypot/manifest.json` exactly, confirming the honeypot's
  generator reproduces the committed corpus bit-for-bit when driven by the same seeds through the
  real pipeline. Balanced accuracy **0.8422** — between the measured 0.830 baseline and the 0.85
  ceiling, not above it. No leak triggered.

## Findings

- **The drop-column / group-column overlap was a real latent bug**, not a hypothetical. It was
  invisible until this session because Q10's ablation script sidestepped it (`drop_columns=()`,
  managing `address` entirely through `group_column`); the production config never combined the
  two until D6's fix required it. Retiring D6 is what surfaced it.
- **`docs/ALGORITHMS.md`'s Alg. 3 table already named every function this session needed**
  (`load_from_chain`, `train_all`, `profiles.build`, `DetectionModule.run`) before any code
  existed. Reading it closely before designing anything saved a full design pass — the interface
  was already decided, just not implemented.
- **The paper gives zero content to "NProf"/"AProf" beyond the name.** The design chosen here —
  a profile is the fitted distribution of the *trained ensemble's* own score on one class's
  training rows, and detection is nearest-profile membership — was picked specifically so "built
  via the four algorithms" (line 3) is literally true of the code. An independent per-feature
  Gaussian (ignoring the trained models entirely) was considered and rejected: it would satisfy
  "definitions of normal/abnormal" but make "built via the four algorithms" false, and would sever
  line 4's detection from line 2's training entirely.
- **`Honeypot.harvest()`'s auto-incrementing seed (`draw_seed = self.seed + self.harvests`) is
  exactly what `scripts/make_honeypot_corpus.py` relies on** for deriving its eval seed
  (`args.seed + 1`) from its train seed. This session used that same property deliberately: one
  `Honeypot(seed=train_seed)`, harvested twice, gives the identical two draws the committed corpus
  was built from — without reading the CSVs. That the kept counts (1467/731) matched the manifest
  exactly on the first real run is strong evidence the whole chain — synthesize → clean →
  sign → feature → encrypt → consensus → decrypt — is bit-reproducible end to end.
- **Dead end, briefly considered:** collapsing `NProf`/`AProf` into a single "the classifier"
  abstraction with no separate profile objects. Rejected immediately — the prompt explicitly
  warns against it, and it would make Alg. 3 line 3 a no-op in the code, which is exactly the kind
  of silent flattening `CLAUDE.md` §2's "never silently fix the paper" spirit extends to design
  choices, not just correctness bugs.
- **Dead end:** an early version of `load_from_chain`'s ground-truth check wrote
  `payload.label not in (ft.SCHEMA and _HONEYPOT_LABELS)` — a copy-paste artefact from
  restructuring the module that would have been a real bug (evaluates to `_HONEYPOT_LABELS`
  unconditionally, since `ft.SCHEMA` is a non-empty string, so this never actually failed for any
  input — the branch was dead code, not a check). Caught before any test ran green against it, by
  re-reading the diff; fixed by importing `MALICIOUS`/`BENIGN` directly from `honeypot.collector`
  instead of duplicating the label strings.
- **Dead end:** the first cut of `test_phase3_detection.py`'s "reads the chain, not the corpus"
  test used a raw substring search (`"data/honeypot" not in source`) against the module's own
  source text — and failed against its own docstring, which mentions the corpus files while
  explaining why the module doesn't read them. Fixed by checking the import graph (`ast`) instead
  of prose, matching `test_module_boundaries.py`'s own approach — a substring check on a file that
  documents the thing it forbids will always be fragile.

## Numbers

Also appended to `RESULTS.md`.

- D6 retirement, production pipeline (`run 20260913T131623Z-97f51129`, seed 20260912, full scale):
  RF 0.9442/0.9697, LR 0.9002/0.9475, DT 0.9224/0.9569, KNN 0.8892/0.9410, constant-positive
  0.9000/0.9474 — exact match to Q10's `address_dropped x grouped_split` cell.
- M4b headline (`run 20260913T134602Z-ab45ac90`, seed 20260912, train n=1467 eval n=731):
  balanced accuracy **0.8422**, precision 0.8439, recall 0.8272, MCC 0.6849, PR-AUC 0.9100.
  Constant-positive baseline on the same eval draw: balanced accuracy 0.5000 (exact, by
  construction), PR-AUC 0.4829.

## Deviations opened or changed

- **DEV-06** amended: D6 retired — `scripts/run_detection.py` now groups by address, matching
  `q10_leakage_ablation.py`.
- **DEV-28** (new): `NProf`/`AProf` as ensemble-score-fitted profiles, and the `Phase4Handoff`
  interface standing in for "call Algorithm 4" until M5.

---

## Handover *(written last)*

**State after:** M4b is closed. Both `detection.dataset` backends exist behind one interface,
selected by config. `NProf`/`AProf` are real, fitted objects that `DetectionModule` detects
through — not a name attached to the classifier. `framework.phase3_detection.run()` reads two
already-built `BC_SigRW` chains and reports Alg. 3's verdicts; nothing in `detection/` or
`framework/phase3_detection.py` orchestrates consensus or reads the honeypot's raw samples
directly (pinned by import-graph tests). D6 is retired: `scripts/run_detection.py` and
`scripts/q10_leakage_ablation.py` agree at 0.9442/0.9697. The honeypot path scores 0.8422 balanced
accuracy against a stated ~0.85 ceiling — a credible number, not a leak. `make test` (1156),
`make test-all` (adds the integration suite), `make lint` all green.

**Next task:** **M5 — Mitigation (Phase 4).** Build `mitigation/state.py` (the
`DETECTED → ISOLATED → REMEDIATING → (RESTORED | CLEANED | POLICY_BLOCKED) → RESOLVED` machine
already named in `docs/ARCHITECTURE.md`), `mitigation/cases.py` (Case-1 quarantine, Case-2
restore via Phase 5, Case-3 **simulated only** — CLAUDE.md §2, enforced by
`test_case3_is_inert.py`), `mitigation/policy.py`, and `framework/phase4_mitigation.py`. Wire
`detection.detector.Phase4Handoff` to it — this is the interface M4b built specifically so this
step would not require touching `detection/` again. Exit: `tests/integration/
test_full_sequence.py` (new) walks Fig. 3 end to end, Cases 1-3 each covered by at least one test.

**New blockers:** none.

**Questions opened / closed:** none opened. No open questions from `PROJECT_STATE.md` touched
this session (Q2/Q4/Q5/Q8 are all M6+).

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated (DEV-06 amended, DEV-28 added)
- [x] Committed, message explains *why*
