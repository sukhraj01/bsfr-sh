# Session 2026-11-12-01 — Phase 2: four gap-filling experiments

**Milestone:** Project Phase 2 (course presentation; follows M7) · **Files read at start:**
`CLAUDE.md`, `PROJECT_STATE.md`, the paper PDF (full), `README.md`, `docs/ROADMAP.md`,
`docs/PAPER_NOTES.md`, `docs/DEVIATIONS.md` (headings + DEV-26/27), `docs/THREAT_MODEL.md` (gap
analysis), `docs/EXPERIMENTS.md` (Targets 3–4), `FINAL_*.md`, `REPORT_SOURCE_MAP.md`, last session's
handover · **Duration:** one sitting

**Protocol note:** CLAUDE.md asks for one task per session. This session ran four small,
independent experiments (P2-A..D) at the user's direction, ahead of a next-day presentation. They
share no code paths except `detection.fair`'s two metric helpers, and each has its own script,
`RESULTS.md` block and DEV entry, so they can be read separately.

---

## Brief *(written before any work)*

**Task:** close the most important, explainable gaps Phase 1 left open, with a small number of
experiments the user can present and defend.

**Exit condition:** each experiment has a script, a `measured` line in `RESULTS.md` with a sidecar,
a figure, and a DEV entry; `make lint` and `make test` clean; committed on branch `phase2`.

**Out of scope:** the report PDF (not recompiled); any change to Phase 1 defaults or numbers; Ada.

**Prior context needed:** DEV-06, DEV-08, M7-6 H4, M7-12, audit items C1/C2/C8/C13/C15.

---

## Prompts *(verbatim, in order)*

```
1. Go through this project, first read the BSFR blockchain enabled security.. pdf which is out
   professrs reserch paper to see what we reimplemented from his work and then look at all
   necessary files to see how far we have gone into this project and even did many extra things
   and tested. up till now what all we did is called the phase 1 work which you need to totally
   get so that we can then move to phase 2 (which wont be as big as 1, we'll just try more things
   on this only)

2. see, i have to present phase 2 tomorrow after giving a summary of phase 1 which we have already
   presented, so what i want is that we test out more things and fill phase 1 gaps like u said
   which are important and which i can actuallu understand what happened so i can explain what we
   did and why we did it. so you can get to work, try some new things and try to fill the
   shortcomings which we have and even if some things fail it is ok we can at least report it, but
   dont keep it very extensive such that is is difficult to even prepare for. the presentation we
   create later should have the key changes we made which we can talk about and explain what made
   a difference and what did not. you can go step by step and keep reporting back to me about what
   it is that you did
```

---

## What was done *(all AI-generated under the user's direction)*

- **Housekeeping.** `docs/` had been moved (uncommitted) to `results/docs/`; verified byte-identical
  to HEAD and moved back. Fresh Linux box: `make setup`, `make data` (BitcoinHeist fetched and
  verified, csv_sha256 matches). Branch `phase2` created.
- **P2-A** `scripts/p2a_tps_fixed_cost.py` — paper-curve fit + whole-program (cold process) timer.
- **P2-B** `src/bsfr_sh/detection/fair.py` (+ `tests/unit/test_detection_fair.py`, 6 tests),
  `scripts/p2b_fair_models.py`.
- **P2-C** `scripts/p2c_year_shortcut.py` — random vs temporal split, four feature sets.
- **P2-D** `scripts/p2d_drift_threshold_sweep.py` — threshold-free AUC + 5%-false-alarm and
  two-sided variants.
- `scripts/p2_figures.py` — figures for P2-B and P2-C from their CSVs.
- `docs/PAPER_NOTES.md` FLAW-5 wording corrected (audit C15). `all-slides-content.md` (untracked
  draft) misattributed the paper to "Alharbi et al." in 3 places; corrected. The real `.pptx` was
  already correct.

## Findings

- **P2-A.** The paper's six timings are almost exactly `fixed + per_block x blocks` (R^2 0.989 /
  0.9999); fixed cost is 55–72% of case 1. TPS "rising" is amortisation with a ceiling (~383 / ~417
  tx/s). One number (fixed cost in blocks' worth, r) predicts every curve: 3(r+5)/(r+15). Per block
  the paper's ransomware chain is *faster*; its slowness is all fixed cost.
- **P2-B.** Scaling rescues KNN (balanced 0.52 -> 0.73) but not LR (0.50 -> 0.50): LR's failure is
  model capacity, not preprocessing, which Phase 1 had blamed on scale. Class weighting forces LR
  to guess but its PR-AUC stays at the base rate. Scaling *hurts* KNN at natural balance — unexplained.
- **P2-C.** The headline result is a calendar shortcut: `year` alone 92.2%; on future years the RF
  is a coin flip (55.1%, balanced 0.52) and DT 48.7%, both far below the 91.8% constant baseline.
  Dropping `year` is not a fix (balanced 0.57).
- **P2-D.** The shipped alarm could never fire (max score 0.52 vs threshold 3.0). Tuned, it flags
  lopsided batches, so it alarms on honest outbreaks as reliably as on poison. Anchor-point poison
  is detectable precisely because it is *too* average.

**Dead ends / surprises (recorded so they are not retried):**
- First draft of the `fair` test asserted a decision tree is *identical* after log-scaling. False:
  thresholds sit at midpoints and log moves midpoints, so unseen values between two training values
  can flip. Training-set predictions are identical; test agreement is ~>=90%.
- P2-D's first run used one-sided thresholds only, which made anchor-point injection look
  undetectable (AUC 0.00). The AUC of exactly 0 was the clue that it is *anomalously low*, not normal.

## Numbers

All in `RESULTS.md` under "Phase 2 / P2-A..D". Sidecars: P2-A `20261111T194706Z-d9b5df22`, P2-B
`20261111T195353Z-38152269`, P2-C `20261111T195314Z-a38f4731`, P2-D `20261111T195724Z-f65a6068`.

## Deviations opened or changed

- DEV-44 (P2-A), DEV-45 (P2-B), DEV-46 (P2-C, supersedes report l.478), DEV-47 (P2-D).

---

## Handover

**State after:** four Phase 2 results measured, figured and documented beside Phase 1's; nothing in
Phase 1 changed. The report PDF does not yet mention Phase 2 and still contains the "H4 rules out
year" sentence DEV-46 contradicts.

**Next task:** Build the Phase 2 presentation (Phase 1 recap + P2-A..D, one slide each, figures from
`results/figures/p2*.png`) in the style of `BSFR-SH_Presentation.pptx`.

**New blockers:** none.

**Questions opened / closed:** audit C1/C2/C13 (temporal/year) now reproduced in-repo; C8
(single-threshold) closed by P2-D; C15 wording fixed in PAPER_NOTES (still present in
`verification/pbft_results.md` and parts of DEVIATIONS).

## Checklist

- [x] `PROJECT_STATE.md` rewritten, under 200 lines
- [x] `RESULTS.md` appended (one line per result)
- [x] `docs/ROADMAP.md` ticked (new "Project Phase 2" section)
- [x] `docs/DEVIATIONS.md` DEV-44..47
- [x] `make lint` clean, `make test` 1816 passed
- [x] committed on branch `phase2`
