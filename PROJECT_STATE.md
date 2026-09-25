# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-25 · **Milestone:** M7 stretch — seven of eight items done; report
compiled and current · **Sessions completed:** 24

---

## One-line status

This session (M7-8) measured whether adversarial retraining — augmenting the training corpus with
perturbed copies of its positive rows, using M7-3's own top-5 features/bounds — hardens the
detector against M7-3's attack, and what it costs on clean data.

- **`detection/adversarial.py`** (new): M7-3's perturbation/scoring/curve/adaptive-search
  machinery, factored out of `scripts/run_adversarial_robustness.py` so M7-3 and M7-8 share one
  tested implementation. M7-3's own script is left untouched (already-published, numbered result;
  zero regression risk) and keeps its own equivalent inline.
- **`detection/retraining.py`** (new): `augment_positive_rows` — K=5 perturbed copies per positive
  training row, each feature independently sampled from `Uniform(0, budget)` toward its own
  evasion bound. Negatives and the eval set are never touched. `budget=0.0` is a no-op (returns
  the input unchanged) rather than K exact duplicates, so the degenerate case trains on the
  identical draw the original model saw and reproduces its fit exactly — verified, not assumed
  (`tests/unit/test_m7_8_adversarial_retraining.py`).
- **`scripts/m7_8_adversarial_retraining.py`** (new): sweeps training budgets 0/25/50/100%,
  re-runs M7-3's degradation curves + adaptive evasion against each hardened model, checks
  feature-importance shift, emits 4 figures + sidecar.
- **The finding: real but narrow, non-monotonic robustness.** At 25% training budget the hardened
  model is *worse* than no hardening on both axes (median adaptive evasion drops 0.321→0.250; the
  combined-evasion curve crosses below 0.50, which the original never did). At 50%/100% the
  opposite happens sharply (median adaptive evasion → 0.883/1.000), but the mechanism is the model
  learning "near the evasion bound" as its own ransomware signature (the 100%-budget combined
  curve *rises* with perturbation, 0.736→0.888) — pattern-matching on the augmentation's own
  footprint, not a deeper representation. Cost: clean balanced accuracy falls 6–10.5pt, driven by
  recall (0.827→0.586 at 100%), not false positives. Top-5 feature-importance sum shrinks
  0.455→0.231 at 100% (partial version of the "throws away signal" failure mode named in the
  brief — real shift, not full collapse).
- `RESULTS.md` "M7-8", report §"Adversarial Retraining" (after §Adversarial Robustness, before
  §Real Malware Transfer Evaluation), four new figures (`fig9a`-`fig9d`), `docs/ROADMAP.md` M7-8
  ticked. No `docs/DEVIATIONS.md` entry — same as M7-3, this is a pure experimental addition with
  nothing in the paper to depart from.

`make test` (1547 tests, 44 new) and `make lint` (ruff + mypy) both green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | `detection/adversarial.py`, `detection/retraining.py` added this session (M7-8) |
| `docs/report/report.pdf` | done, current | recompiled this session (`tectonic`), new §"Adversarial Retraining" |
| `verification/` | done (M7-1) | unchanged |
| `docs/STORAGE_ANALYSIS.md` | done (M7-2) | unchanged |
| `scripts/run_adversarial_robustness.py` | done (M7-3) | unchanged; its logic now also lives (factored, not moved) in `detection/adversarial.py` |
| `scripts/run_consensus_comparison.py` | done (M7-4) | unchanged |
| `scripts/run_hybrid_benchmark.py` | done (M7-5) | unchanged |
| `scripts/m7_6_gap_closure.py` | done (M7-6) | unchanged |
| `scripts/m7_7_real_malware_transfer.py` | done (M7-7) | unchanged |
| `scripts/m7_8_adversarial_retraining.py` | done (M7-8) | new this session, ~15s local run |

## Current numbers

New this session: `RESULTS.md` "M7-8" section, run `20260925T052030Z-31a79c4a`. Hardened clean
bal_acc: 0.7803 (25%), 0.7616 (50%), 0.7363 (100%), vs. original 0.8408. Adaptive-evasion median:
0.2499 (25%, worse than original's 0.3213), 0.8825 (50%), 1.0000 (100%). Everything else unchanged
since the last session.

## Next task

None forced — M7 is optional stretch work and the core deliverable was complete before M7-6/7/8.
If continued: async pBFT with modelled network latency is the one remaining `docs/ROADMAP.md`
M7 item. A natural M7-8 follow-up (not forced): re-run the M7-3-style attack against a hardened
model's own *new* top-5 features (`directory_breadth`, `entropy_delta`, `key_generation_events`
gained importance this session) to test whether the measured robustness survives a differently-
shaped attack.

## Blockers

None.

`data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length sufficient, or should it be trimmed? | report sign-off | reviewer judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 tested eight hypotheses total and narrowed (not closed) the gap to 1.51pt; report states the residual as measured-and-bounded, not unexplained without qualifier |
| Scyther binary not committed (third-party, single-platform) | a fresh clone can't re-run the verification without a manual download | exact release URL + sha256 in `verification/README.md`; the raw output is committed, so the claims don't depend on re-running it |
| The BC_SigRW/BC_DTBU timing gap is condition-dependent (35-45% off, ~25-27% on) | a reader citing "the gap" without saying which condition is wrong half the time | both figures now in `RESULTS.md`/`docs/EXPERIMENTS.md`/the report supplement, each labelled with its condition |
| Raft's message-count ratio (~60% of pBFT) is measured only at `n=4`; a reader might extrapolate the O(n)/O(n^2) asymptotic gap and expect a bigger number | over-claiming Raft's advantage at other cluster sizes | `docs/DEVIATIONS.md` DEV-32 and the report both state the ratio is small-`n`-specific, not the asymptotic one |
| M7-7's bal_acc=0.5000 could be misread as "the framework doesn't work" rather than "19/22 features have no static analogue" | undersells the synthetic-corpus result (0.8422) and the framework's actual design | DEV-34 and the report state explicitly that this is a schema dynamic-vs-static grounding finding, not a generator-calibration failure, before giving the number |
| M7-8's 25%-budget "hardening backfires" result could be misread as "adversarial retraining doesn't work" rather than "a narrow training budget generalises worse than a wide one" | undersells the real robustness gain measured at 50%/100% | report and `RESULTS.md` state the non-monotonicity explicitly and lead with it, rather than averaging budgets into one number |

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
