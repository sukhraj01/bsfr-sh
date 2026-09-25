# Session 2026-09-25-04 — M7-8: adversarial retraining

**Milestone:** M7-8 (stretch) · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`RESULTS.md` M7-3 section, `docs/DEVIATIONS.md` DEV-27 and DEV-03,
`scripts/run_adversarial_robustness.py`, `src/bsfr_sh/detection/{models,profiles,detector,
metrics}.py`, `src/bsfr_sh/honeypot/features.py`, `configs/ml.yaml`,
`scripts/m7_7_real_malware_transfer.py` (pattern reference) · **Duration:** _

---

## Brief *(written before any work)*

**Task:** Measure whether adversarial retraining — augmenting the committed training corpus with
perturbed copies of its positive rows, using M7-3's own top-5 features/bounds — buys real
robustness against M7-3's attacks, and what it costs on clean data.

**Exit condition:** augmented training set built and row-count-tested; hardened model (RF, same
declared hyperparameters) trained on it; clean-eval metrics reported at three perturbation
budgets (25/50/100%) plus the degenerate 0% case; M7-3's degradation curves and adaptive-evasion
percentiles re-run against the hardened model and overlaid/compared against the original; feature
importance shift checked for the "throws away signal" failure mode; report section extended;
`RESULTS.md` lines for every measurement; `make test`/`make lint` green.

**Out of scope:** changes to the generator or `FT_RW` schema, deep learning models, M7-7 real-data
re-runs.

**Prior context needed:** `docs/DEVIATIONS.md` DEV-27 (committed corpus is the fixed dataset —
this session augments a *copy* of it, never overwrites the committed CSVs) and DEV-03 (`FT_RW`
schema). M7-3's established baseline (bal_acc=0.8408 on the CSV path, not 0.8422 — chain-path
float precision, DEV-27 amendment) and its top-5 feature bounds table
(`scripts/run_adversarial_robustness.py::FEATURE_BOUNDS`) are reused verbatim, not re-derived,
so the two sessions' numbers are comparable.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: RESULTS.md lines for
M7-3 (adversarial robustness — the degradation curves and adaptive evasion
percentiles), docs/DEVIATIONS.md DEV-27 and DEV-03.

Create the session file from the template and fill the brief first.

TASK — M7-8. Adversarial retraining.

[full brief: generate K=5 perturbed copies per positive training row sampled
uniformly from [0, max_perturbation] on the top-5 features toward their
evasion bound, never touch negatives or the eval set; train the hardened RF
on the augmented set; evaluate clean eval metrics, re-run M7-3's degradation
curves and adaptive evasion against the hardened model; sweep
max_perturbation in {25%, 50%, 100%}; check feature-importance shift for the
"ignores perturbed features" failure mode; write up cost/benefit with a
Pareto framing; tests for row counts, no eval contamination, and the
degenerate max_perturbation=0 case reproducing 0.8408 exactly — see task
text for full detail]

TESTS
Augmented training set has the expected row count (original + K × positives).
No perturbed sample appears in the eval set. The hardened model at
max_perturbation=0 reproduces the original 0.8422 exactly (degenerate case).
Clean eval on the original model still produces 0.8422 (confirm no
contamination). Perturbation at 0% on the hardened model produces its own
clean accuracy (not 0.8422 — it's a different model).

EXIT CONDITION
make test and make lint green. Three perturbation budgets evaluated. The
10th/median/90th adaptive comparison exists. Feature importance shift
documented. Report updated. RESULTS.md lines for every measurement.

OUT OF SCOPE
No changes to the generator or the feature schema. No deep learning models.
No M7-7 real-data re-runs. This is purely about whether adversarial training
on the existing pipeline buys robustness.

END OF SESSION
Session file. Rewrite PROJECT_STATE.md. Tick M7-8. Commit and push.
```

---

## What was done

- **`src/bsfr_sh/detection/adversarial.py`** (new, AI-generated): `FeatureBound`, `FEATURE_BOUNDS`
  (identical to M7-3's table), `balanced_accuracy`, `select_best_importance_model`,
  `top_feature_importances`, `apply_perturbation`, `ensemble_predict`, `single_feature_curves`,
  `combined_curve`, `adaptive_evasion` — M7-3's perturbation/scoring/curve/adaptive-search
  machinery, factored out so M7-3 and M7-8 share one tested implementation instead of drifting
  copies. `scripts/run_adversarial_robustness.py` itself is **not** touched: it is an already-
  published, numbered result (`RESULTS.md` M7-3, run `20260922T155316Z-3ce801ca`), and refactoring
  it to import from the new module would have re-run it under a new run ID for zero benefit here.
  This is a deliberate, documented duplication, not an oversight.
- **`src/bsfr_sh/detection/retraining.py`** (new, AI-generated): `augment_positive_rows` — K
  perturbed copies per positive training row, one independent `Uniform(0, budget)` fraction per
  top-5 feature per copy. `budget<=0.0` or `k<=0` is a no-op (returns the input arrays unchanged),
  a deliberate design choice explained in the module's own docstring: K exact-duplicate copies
  would still perturb `RandomForestClassifier`'s bootstrap sampling for zero new information,
  breaking the degenerate case's exact reproduction.
- **`tests/unit/test_detection_adversarial.py`** (new, AI-generated, 11 tests) and
  **`tests/unit/test_detection_retraining.py`** (new, AI-generated, 10 tests): generic,
  array-level correctness of the two new modules (bounds respected, only positives touched,
  batched prediction matches `DetectionModule.decide()` row-by-row, determinism).
- **`tests/unit/test_m7_8_adversarial_retraining.py`** (new, AI-generated, 6 tests, marked
  `@pytest.mark.slow`): the session's own named exit tests, run against the real committed
  `data/honeypot/corpus_{train,eval}.csv` — row count, no eval contamination, exact degenerate
  reproduction, no original-model contamination, hardened models are genuinely different fits.
- **`scripts/m7_8_adversarial_retraining.py`** (new, AI-generated): thin orchestrator — fits the
  original model once (sanity-checks 0.8408), sweeps training budgets {0%, 25%, 50%, 100%}, for
  each hardened model computes clean-eval metrics, M7-3's degradation curves, adaptive evasion,
  and a feature-importance-shift check; emits 4 figures + one sidecar; prints `RESULTS.md` lines.
- **`RESULTS.md`** "M7-8" section; **`docs/report/report.tex`** new §"Adversarial Retraining"
  between §Adversarial Robustness and §Real Malware Transfer Evaluation, four new figures copied
  to `docs/report/figs/` (`fig9a`-`fig9d`); recompiled `docs/report/report.pdf` with `tectonic`
  (already on `PATH` per the prior report-compile session's finding). `docs/ROADMAP.md` M7-8 item
  added and the top milestone line updated.

## Findings

- **The headline finding: robustness is non-monotonic in training budget, and the low-budget case
  actively backfires.** At 25% training budget the hardened model is worse than the original on
  *both* axes it was meant to trade off: clean bal_acc drops (0.8408→0.7803) and median adaptive
  evasion effort also drops (0.3213→0.2499), with the combined-evasion curve crossing below the
  0.50 useless-detector line (0.463) at full perturbation — something the unhardened original
  never did (floor 0.570). A narrow training budget teaches the model the small-perturbation
  region it was exposed to at the cost of the large-perturbation region it never saw, producing a
  detector that is worse calibrated for a stronger attacker than the one it trained against. This
  was not anticipated going in; the working assumption before running the sweep was that more
  training-time perturbation would monotonically trade clean accuracy for robustness.
- **At 50%/100% budget the defense works, but the mechanism is narrow.** Median adaptive evasion
  rises to 0.8825/1.0000, and at 100% budget the combined-evasion curve actually *increases* with
  eval-time perturbation (0.736→0.888) instead of falling. Investigated why rather than reporting
  the number alone: the hardened model's own training positives are heavily concentrated at or
  near the top-5 features' evasion bounds (that is what augmentation put there), so the model
  appears to have learned "features at their bound" as a ransomware signature in its own right —
  real, measured robustness against this specific attack shape, but a form of pattern-matching on
  the augmentation's own footprint rather than a deeper, more general representation. Untested (out
  of scope for this session): whether this "robustness" survives an attack shaped differently, e.g.
  partial perturbation short of the bound, or perturbation of a different feature subset.
- **The "throws away signal" failure mode occurs, but only partially — worth stating precisely
  rather than as a binary yes/no.** Top-5 importance sum: 0.4553 (original) → 0.4044 (25%) →
  0.2966 (50%) → 0.2309 (100%). This is a real, budget-proportional decline, but even at 100%
  budget it does not collapse to near-zero the way the brief's failure-mode description names as
  the disqualifying case. The features gaining importance instead — consistently
  `directory_breadth`, `entropy_delta`, `key_generation_events` — are never perturbed in this
  experiment, so the measured robustness could be brittle to an attack that targets those instead;
  this session does not run that attack (out of scope: no changes to the perturbation set).
- **The cost is driven by recall, not false positives.** Precision stays high or improves across
  every budget (0.8415→0.886/0.845/0.828); recall falls sharply (0.8272→0.637/0.632/0.586). The
  hardened models are not becoming noisier — they are becoming more conservative, increasingly
  refusing to call genuine, unperturbed ransomware "ransomware." This matters for the deployment
  framing in the report's closing paragraph: the cost is measured in real ransomware missed, not
  in false alarms raised.
- **Dead end avoided, recorded rather than silently dropped: refactoring `run_adversarial_
  robustness.py` itself to import the new shared module.** Considered it for DRYness, but M7-3's
  script is an already-published, numbered result with a specific `run_id` in `RESULTS.md`;
  re-running it under the refactor (even to verify byte-identical output) would add a redundant
  sidecar to `results/logs/` and risk a subtle behavioral drift going unnoticed in a script no
  test file currently covers. Left untouched; `detection/adversarial.py` is the same logic,
  independently written and unit-tested, not an extraction with an behind-the-scenes dependency
  on the old script.
- **Degenerate-case design choice, and why it had to be deliberate, not incidental.** The
  session's own exit test ("hardened model at max_perturbation=0 reproduces the original exactly")
  does not hold for free: appending `K` exact-duplicate copies of every positive row at budget=0
  would still change `RandomForestClassifier`'s bootstrap-sample distribution (more rows, more
  weight on the same values) and produce a *different*, not identical, fit. `augment_positive_
  rows` treats budget=0 as "add nothing" rather than "add K identical copies" specifically so the
  degenerate case is a true no-op — verified empirically (`test_hardened_model_at_max_
  perturbation_zero_reproduces_the_original_exactly`), not just argued.

## Numbers

Full table in `RESULTS.md` "M7-8" section, sidecar `results/logs/20260925T052030Z-31a79c4a.json`.
Headline: original model bal_acc=0.8408 (reproduces M7-3 exactly), hardened clean bal_acc 0.7803
(25%) / 0.7616 (50%) / 0.7363 (100%); adaptive-evasion median 0.2499 (25%, worse than original's
0.3213) / 0.8825 (50%) / 1.0000 (100%); top-5 importance sum 0.4553→0.4044/0.2966/0.2309.

## Deviations opened or changed

None. Same posture as M7-3: this is a pure experimental addition with nothing in the paper to
depart from (the paper does not address adversarial robustness or retraining at all), so no
`docs/DEVIATIONS.md` entry is warranted.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** the honeypot detector's adversarial-robustness story (M7-3) now has a matching
defense-side measurement (M7-8): adversarial retraining works, but only above a training-budget
threshold this session located empirically (between 25% and 50%), and the mechanism behind the
gain is narrow enough that it should not be presented as a solved problem. `detection/adversarial.
py` and `detection/retraining.py` are available for any future session that wants to run a new
attack shape against the hardened models without re-deriving the perturbation machinery.

**Next task:** None forced. If continued: (a) async pBFT with modelled network latency remains
the one open `docs/ROADMAP.md` M7 item; (b) a natural M7-8 follow-up — re-run an M7-3-style attack
against a hardened model's own new top-5 features (`directory_breadth`, `entropy_delta`,
`key_generation_events`) to test whether the measured robustness survives a differently-shaped
attack, which this session's own findings flag as untested.

**New blockers:** None.

**Questions opened / closed:** No `PROJECT_STATE.md` Q-numbers touched; this session did not open
or close a numbered open question, only M7-8's own checklist item.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines (140)
- [x] `RESULTS.md` appended, one line per run
- [x] `docs/ROADMAP.md` boxes ticked (M7-8 added, top milestone line updated)
- [x] `docs/DEVIATIONS.md` updated if the paper was departed from (n/a — see above)
- [x] `make test` (1547 tests, 44 new) and `make lint` (ruff + mypy) green
- [x] Committed, message explains *why*
