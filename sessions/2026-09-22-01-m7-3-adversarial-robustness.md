# Session 2026-09-22-01 — M7-3: adversarial robustness of the honeypot detector

**Milestone:** M7 (stretch) · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/ARCHITECTURE.md` §honeypot + §detection, `docs/DEVIATIONS.md` DEV-03 + DEV-27,
`RESULTS.md` M4b lines (bal_acc=0.8422), `sessions/_TEMPLATE.md`,
`src/bsfr_sh/honeypot/{features,collector}.py`, `src/bsfr_sh/detection/{models,profiles,detector,metrics,dataset}.py`,
`src/bsfr_sh/framework/phase3_detection.py`, `scripts/run_phase3_detection.py`, `configs/ml.yaml`,
`data/honeypot/manifest.json` · **Duration:** _

---

## Brief *(written before any work)*

**Task:** Measure how much an adversary can perturb the honeypot detector's top-5 features
(single-feature, combined, and adaptive/optimal) before its 0.8422 balanced accuracy collapses to
the 0.50 constant-positive baseline, and report the result as a new report section.

**Exit condition:** Three figures (single-feature degradation, combined-evasion degradation,
adaptive-evasion histogram) with sidecar JSON in `results/figures/`; `RESULTS.md` lines for the
degradation thresholds and adaptive percentiles; new report section after §VI; `make test` and
`make lint` green; `PROJECT_STATE.md` rewritten; `docs/ROADMAP.md` M7 item ticked; committed.

**Out of scope:** No changes to `honeypot/generator` or `detection/`. No adversarial retraining.
No slides. No live/executable perturbation — feature vectors only (CLAUDE.md §2).

**Prior context needed:** `docs/ARCHITECTURE.md` §honeypot (FT_RW schema, generator design,
DEV-27's stated difficulty) and §detection (NProf/AProf ensemble decision, not raw predict());
DEV-03 (Sig_RW/FT_RW split) and DEV-27 (22-feature schema, truncated kill chain, committed corpus
is the fixed dataset per its M4a amendment); `RESULTS.md`'s M4b entry (bal_acc=0.8422, the number
this session is stress-testing) and its provenance note (regenerated via chain at seed 20260912/
20260913, matching the committed CSV corpus counts exactly — so reading the committed CSVs
directly must reproduce the same features and the same 0.8422 under the same seed/config).

**Design decision, made before writing code:** the 0.8422 headline is the *ensemble* decision
(`DetectionModule.decide()` via `NProf`/`AProf` membership on `ensemble_score()` of all four
trained models — see `detection/detector.py`, `detection/profiles.py`), not any single model's
raw `.predict()`. The task's own exit test ("perturbation at 0% reproduces 0.8422 exactly") is
only satisfiable if the perturbation framework's balanced-accuracy computation is this same
ensemble pipeline. So: train all four `configs/ml.yaml` models + build `NProf`/`AProf` once on
`data/honeypot/corpus_train.csv` (seed 20260912, matching `run_phase3_detection.py`); use
`DetectionModule` for every balanced-accuracy measurement in steps 3-5. Feature importances
(step 1) come from a single tree-based model (RF or DT, whichever scores higher individually on
the committed eval corpus) fit the same way, since LR/KNN expose no `.feature_importances_` —
this model selects *which* features get perturbed, but the ensemble decides the outcome.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. [Full M7-3 task prompt: adversarial robustness of the honeypot detector — feature importance
   ranking, perturbation budget definition, single-feature evasion, combined evasion, adaptive
   evasion, figures/output, report write-up. Reproduced in full in the conversation transcript;
   not re-typed here to avoid duplicating ~1500 words verbatim in two places. Key acceptance
   tests stated in the prompt: (a) feature importance deterministic under the committed seed,
   (b) perturbation at 0% reproduces 0.8422 exactly, (c) perturbation at 100% on all 5 features
   should approach/reach 0.50, (d) every positive sample should find a flip by t=1.0. See
   `knowledge/ai-usage-log/` policy — this file records what happened, not a second verbatim copy
   of the prompt already in the transcript.]
```

---

## What was done

- **`scripts/run_adversarial_robustness.py`** (new, AI-generated). Self-contained analysis script,
  following `scripts/run_phase3_detection.py`'s established precedent for one-off M7-scale
  evaluations (logic in the script, not `src/bsfr_sh/`, since this touches no paper algorithm and
  has no natural home in the module dependency graph CLAUDE.md §3 fixes). Loads the committed
  corpus, fits RF/DT individually to pick the feature-importance model, fits the full 4-model
  ensemble once, perturbs, and emits three figures + a sidecar + `RESULTS.md` lines to stdout.
  Vectorized the ensemble scoring (`ensemble_predict`) rather than calling
  `DetectionModule.decide()` per row — the first implementation timed out past 120s calling
  `decide()` ~35,000+ times for the adaptive search; the batched version (verified to produce
  bit-identical predictions against `decide()` on a 40-row sample before trusting it) runs the
  full script in ~3.5s.
- **`docs/report/report.tex`** (edited, AI-generated). New `\section{Adversarial Robustness of the
  Honeypot Detector}` inserted after §VI (Honeypot Detection Evaluation), before §Conclusion:
  framing paragraph, top-5 feature/bound table, three `\includegraphics` figures, per-finding
  discussion, closing paragraph tying to FLAW-2. **Not compiled** — no `pdflatex`/`xelatex`/
  `latexmk` available in this environment (checked; none on PATH, no TeX distribution found).
  Braces/dollar-signs/environment counts verified balanced programmatically as a partial check;
  a real compile is still owed next session or by the user locally.
- **`docs/report/figs/fig7{a,b,c}_*.png`** (new, copied from `results/figures/`) — no automated
  copy step exists for this (checked: no Makefile target syncs `results/figures/` into
  `docs/report/figs/`), so this was a manual `cp`, same as the M6b figures apparently were.
- **`RESULTS.md`** (edited) — new `## M7-3` section, five result lines, findings paragraph.
- **`docs/DEVIATIONS.md`** (edited) — DEV-27 amendment (see below).
- **`docs/ROADMAP.md`** (edited) — M7's adversarial-evaluation item ticked with a one-line summary.
- **`results/figures/fig7{a,b,c}_*.png` + `.json` sidecars`** (new) and
  **`results/logs/20260922T155316Z-3ce801ca.json`** (new) — the run's own full sidecar.

## Findings

- **The exit test's own precondition was wrong, and that is itself the session's first real
  finding.** "0% perturbation reproduces 0.8422 exactly" assumed the committed CSV corpus and the
  chain-reconstructed path are bit-identical. They are not: `honeypot/corpus.py:write_corpus`
  formats every feature at 6 significant figures (`f"{value:.6g}"`); `BC_SigRW`'s
  `SignatureRecordPayload` carries full float64. Read the CSVs directly (as DEV-27's own M4a
  amendment says every M4 experiment should) and the same seed/config gives **0.8408**, not
  0.8422 — verified with zero perturbation code in the path at all, so this is not a framework
  bug. Traced, not silently absorbed: DEV-27 amended, `RESULTS.md` and the report both state
  0.8408 as this session's baseline and explain the 0.0014 gap rather than forcing a match.
- **100% combined perturbation does not reach 0.50** (floor ~0.57-0.60) — the other exit test that
  did not literally hold. Root cause identified, not just observed: the top-5 RF-important
  features carry only 45.5% of total importance mass; the ensemble's real reliance on the
  remaining 17 features holds accuracy well above "useless" even at the full evasion budget. This
  matches the task's own anticipated alternative reading almost exactly.
- **Adaptive, per-sample evasion tells a very different story than either aggregate curve**: 17.3%
  of positive eval rows are already baseline false negatives (0% perturbation), a further ~8% flip
  under 5% perturbation, so roughly a quarter of ransomware is trivially evadable by an adversary
  who can query the model — while the hardest 10% need ≥97.7% of the range. The 28 samples
  (7.9%) that never flip by t=1.0 were checked against features ranked 6th-10th (not perturbed):
  they average markedly higher `c2_beacon_count`, `entropy_delta`, `key_generation_events`,
  `shadow_copy_deletions` and `dns_entropy` than the malicious class overall — confirmed
  survivorship is explained by reliance on unperturbed features, exactly as the exit test
  anticipated as the diagnostic if any sample survived.
- **Dead end, recorded so it is not retried:** the first `adaptive_evasion` implementation called
  `DetectionModule.decide()` once per (sample, grid-point) pair — ~350 samples x 101 grid points x
  4 models' `predict_proba`, each paying sklearn's per-call/parallelism overhead on a single-row
  input. Timed out past 120s. Fix was architectural (batch every model call across all samples at
  a given `t`, not algorithmic (e.g. a smaller grid would not have fixed the per-call overhead
  problem)).
- **This project has no LaTeX toolchain installed in this environment.** `PROJECT_STATE.md`
  (pre-session) stated the report "recompiles," which was presumably true in whatever environment
  produced that claim, but is not verifiable from here. Flagged in the Handover below rather than
  silently claimed.

## Numbers

All in `results/logs/20260922T155316Z-3ce801ca.json`; headline lines also in `RESULTS.md` §M7-3:

- Feature importance: `random_forest` (individual bal_acc 0.8513, beats `decision_tree` 0.8063).
  Top-5: `observed_stages` 0.1259, `extension_change_rate` 0.1091, `rename_rate_per_s` 0.0792,
  `write_entropy_var` 0.0741, `crypto_ngram_novelty` 0.0670.
- Ensemble baseline (committed corpus, 0% perturbation): **bal_acc = 0.8408** (cf. `RESULTS.md`
  M4b's chain-path 0.8422 — see Findings).
- Single-feature @ 100%: `observed_stages` 0.784, `extension_change_rate` 0.810,
  `rename_rate_per_s` 0.814, `write_entropy_var` 0.752 (largest single drop, -0.089),
  `crypto_ngram_novelty` 0.830. None cross 0.50.
- Combined @ 100%: 0.570 (floor ~0.576 at 70%). Never crosses 0.50.
- Adaptive: n=353 positive eval rows, p10=0.0000, median=0.3213, p90=0.9771, 28 survivors (7.9%)
  at t=1.0, 61 (17.3%) already-false-negative at t=0.

## Deviations opened or changed

- **DEV-27 amended** (`docs/DEVIATIONS.md`): documents the committed-CSV-vs-chain-path float
  precision gap (6-sig-fig CSV rounding vs. full float64), discovered by this session's own exit
  test failing and traced rather than papered over. States both 0.8408 and 0.8422 are correct,
  measured, and not interchangeable for anything needing the exact figure.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** M7-3 is complete: adversarial robustness measured, three figures + sidecars
emitted, `RESULTS.md`/`docs/DEVIATIONS.md`/`docs/ROADMAP.md` updated, new report section written.
`make test` (1348 passed) and `make lint` (ruff + mypy on `src`/`tests`, unaffected by this
session's `scripts/`-only + docs changes) both green.

**Next task:** Only one M7 stretch item remains and is optional (hybrid blockchain, per the
paper's own future-work list) — not required for the deliverable. If anyone picks up
`docs/report/report.tex` next: **compile it** (no LaTeX toolchain was available in this session's
environment; the new §Adversarial Robustness section's LaTeX was checked for balanced
braces/environments/math-mode but never rendered to PDF) and proofread the new section under
compilation, since brace-balance is a necessary but not sufficient check for correct LaTeX.

**New blockers:** None functional. Documented gap: this environment has no `pdflatex`/`xelatex`/
`latexmk`, so `docs/report/report.pdf` was not regenerated this session — only `report.tex` was
edited. Whoever compiles next should treat the new section as unverified LaTeX until it renders.

**Questions opened / closed:** Q4 (`PROJECT_STATE.md`, "do we need real feature-space evasion for
M7?") is closed: yes, and it was run — answer is "nuanced" (shape (c) per the task's own taxonomy).

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run (plus a findings paragraph, matching the M4b/D3
      sections' own style of prose + fenced lines)
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated (DEV-27 amended)
- [ ] Committed, message explains *why* — pending, next step after this file is saved
