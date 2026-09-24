# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-25 · **Milestone:** M7 stretch — five of six items done; Q10 closed with
a tightened bound; report compiled and current · **Sessions completed:** 22

---

## One-line status

This session (M7-6) tested the three Q10 gap-closure hypotheses left untested — decision-tree
splitting criterion, resample strategy, single-split variance vs. CV — plus feature engineering
and a programmatically-stacked worst case, narrowing the reproduction gap's bound from 3.58 to
1.51 accuracy points without closing it.

- **`detection/gap_closure.py`** (new): pure logic for the new hypotheses —
  `oversample_resample`/`undersample_resample` (two more readings of "90/10" the paper's silence
  permits), `engineer_features` (year/day variants), `build_decision_tree_variant` (criterion
  ablation), `grouped_stratified_kfold` (wraps `StratifiedGroupKFold` for group-aware CV). Tested
  independently in `tests/unit/test_detection_gap_closure.py` (17 tests).
- **`scripts/m7_6_gap_closure.py`** (new): thin orchestrator, H1-H5, run `--seed 20260912`
  completes in ~5 minutes locally.
- **The finding:** oversampling (bootstrap-duplicating the 41,413 real ransomware rows to
  180,000) under a **random** split reaches 0.9690-0.9723 — under a **grouped** split the same
  resample scores 0.8746-0.9363, *worse* than the existing baseline. That 5-10 point swing is a
  materially larger leakage signature than either Q10 candidate (largest was +0.92pt), and the
  mechanism is direct: duplicated rows inherit their original's address, so a non-grouped split
  places literal train-set duplicates into the test set.
  H1 (splitting criterion) and H4 (year/day feature engineering) do not move the needle; H4
  additionally rules out `year` as a temporal leak (dropping it *costs* ~3pt). H3 (seed variance,
  5-fold group-CV) closes: the M4a/Q10 numbers are highly reproducible, not a lucky draw.
- **H5, stacked worst case, winners chosen programmatically (argmax over recorded cells, not by
  hand):** entropy criterion + oversample resample + `year x day` interaction + address kept +
  random split reaches **0.9747/0.9861 — 1.51 accuracy points short of published**, not zero.
- `docs/DEVIATIONS.md` DEV-06 amended, `RESULTS.md` "M7-6", report §"M7-6" (after the Q10
  ablation in §IV), `docs/ROADMAP.md` M7-6 note added. Q10 closed definitively: bound tightened,
  word "unexplained" now carries a measured qualifier everywhere it appears.

`make test` (1468 tests) and `make lint` (ruff + mypy) both green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | `detection/gap_closure.py` added this session (M7-6) |
| `docs/report/report.pdf` | done, current | 16 pages; recompiled this session, new §"M7-6" in §IV |
| `verification/` | done (M7-1) | unchanged |
| `docs/STORAGE_ANALYSIS.md` | done (M7-2) | unchanged |
| `scripts/run_adversarial_robustness.py` | done (M7-3) | unchanged |
| `scripts/run_consensus_comparison.py` | done (M7-4) | unchanged |
| `scripts/run_hybrid_benchmark.py` | done (M7-5) | unchanged |
| `scripts/m7_6_gap_closure.py` | done (M7-6) | new this session — H1-H5, ~5 min local run |

## Current numbers

New this session: `RESULTS.md` "M7-6 — closing the Q10 gap: three more hypotheses" section, run
ids `20260924T221930Z-3436aaad` (H1) through `20260924T222413Z-98a839c9` (H5). Best cell found
anywhere: 0.9747/0.9861 (H5 stacked), 1.51 accuracy points under published — see DEV-06's M7-6
amendment for the full breakdown. Everything else unchanged since the last session.

## Next task

None forced — M7 is optional stretch work and the core deliverable was complete before M7-6.
If continued: async pBFT with modelled network latency is the one remaining `docs/ROADMAP.md`
M7 item.

## Blockers

None.

`data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length sufficient (now 15 pages), or should it be trimmed? | report sign-off | reviewer judgement |

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
| 3 of 18 M7-5 benchmark cells show 6-12% anchor overhead against a ±1.4% baseline for the rest | a reader might read this as a real per-anchor cost | stated plainly as scheduling jitter (anchor step is sub-millisecond, runs no consensus) in both `RESULTS.md` and the report, not filtered or re-run until clean |

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
