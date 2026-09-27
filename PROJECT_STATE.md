# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-27 · **Milestone:** M7 stretch complete (M7-17 delivered) ·
**Sessions completed:** 34

---

## One-line status

M7-17 (exact minimum adversarial perturbation) is delivered: `detection/exact_adversarial.py` +
`scripts/m7_17_exact_min_perturbation.py` replace M7-3's binary-search evasion-cost approximation
with an exact/near-exact method, and re-measure M7-8's hardened models with it.

- **The session brief assumed a random-forest-only classifier; `DM_CSl` is a four-model soft-vote
  ensemble** (`random_forest`, `decision_tree`, `logistic_regression`, `k_nearest_neighbours`).
  Resolved by treating three of the four exactly (tree-path walking, closed-form LR) and bounding
  the fourth (`k_nearest_neighbours`) with a dense grid — `O(n_train^2)` exact `k_nearest_neighbours`
  enumeration judged disproportionate to this session's budget. DEV-43.
- **Original model: approximation error was small, M7-3's conclusions hold.** Exact median 0.3063
  vs. binary search's 0.3213 (-1.5pt); none of the 28 "never flips" survivors actually flip.
- **M7-8's 25%/50%-budget findings unchanged (<0.01pt shift). The 100%-budget "never flips" claim
  needed correcting, not overturning — the session's central finding.** Exact search finds 177/353
  rows flip (vs. binary search's near-zero), but verified directly against the real ensemble: 176
  of 177 revert to the correct verdict one step later, median dip width 0.38% of the perturbation
  range (vs. 39.6% for the original model's real flips). Razor-thin, unexploitable adversarial
  windows, not a stable evasion region — evidence *for* M7-8's "memorises the boundary" reading,
  not against it. The 80.95pp shift exceeded the session's 5pp retraining-revisit threshold; no
  new retraining was run since the shift is explained by measurement precision alone.
- **Two real bugs found and fixed while building the exact per-tree method**, both from treating
  sklearn tree evaluation as pure float64 arithmetic: (1) `<=`-boundary semantics mean the
  algebraic threshold crossing itself is not yet a flip; (2) sklearn casts `X` to float32 internally
  before comparing to a threshold, so a naive nudge can be swallowed by rounding for
  large-magnitude features. Both caught by the brief's own exhaustive per-tree verification test.
- **The brief's greedy majority-vote heuristic (§1c) is confirmed unsound on the real forest**
  (not just a caveat): trees split on a moving feature more than once, so "once flipped, stays
  flipped" fails in practice (measured 5-12/50 selected trees flip back before `t_star`). Kept,
  relabelled, not used for the published result.
- Report extended (`docs/report/report.tex` §"Exact Minimum Adversarial Perturbation", new figure
  `fig_m7_17_exact_vs_binary_search_histogram.png`); recompiles clean (tectonic) at **30 pages**
  (was 29 after M7-16 — see Risks, page-count gap widening again).

`make test` (1801 passed, incl. 8 new `detection.exact_adversarial` tests) and `make lint` (ruff +
mypy --strict on `src/`) green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | this session adds `detection/exact_adversarial.py` only; `detection/detector.py`/`adversarial.py` untouched |
| Honeypot poisoning: attack + three independent defenses (M7-11/12/14/15) | done | unchanged this session |
| Multi-family detection (M7-16) | done | unchanged this session |
| Adversarial robustness (M7-3/M7-8) + exact bounds (M7-17) | done | M7-8's 100%-budget hardened model's decision surface now known to have ~177 razor-thin adversarial windows, not smooth robustness — new information, model itself unchanged |
| Real-malware transfer evaluation | done, 3 datasets | unchanged this session |
| `docs/report/report.pdf` | done, 30 pages | extended this session, recompiles clean via `tectonic` |
| Everything else (M7-1 through M7-16's own deliverables) | done | unchanged |

## Next task

None forced. If a future session wants to act on this one's own findings, in order of interest:

1. **A stability-adjusted robustness metric** (M7-17's own finding): minimum perturbation that
   *stays* flipped to `t=1.0`, not just the first flip found — would likely move M7-8's
   100%-budget Pareto point further toward the robust end than either the raw binary-search or raw
   exact number suggests. Not built this session (out of scope: no new retraining/metric redesign).
2. **Exact `k_nearest_neighbours` bounds**, if ever wanted: the `O(n_train^2)` pairwise
   distance-crossing enumeration DEV-43 describes but does not implement — needs a machine that can
   afford it, not this 8GB dev box.
3. **The FT_RW/honeypot family-label gap** (M7-16's own finding, carried): the synthetic honeypot
   generator produces only `RW`/`benign`, no family — explicitly out of scope for M7-16 itself.
4. **A coordination mechanism for disagreement** (carried from M7-15): a protocol for acting on a
   federated-detection flag — the paper specifies nothing here and M7-15 built the signal, not the
   response.
5. Close the report's page-count gap (30pp vs. the original <20pp target, widened again this
   session) — ranked options in `sessions/2026-09-26-03-report-restructure-and-ember-check.md`.

## Blockers

None. `data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

**Standing limitation, not a blocker:** CICMalDroid-2020 and MalwareBazaar/Triage remain unusable
by any future session unless the user personally creates the relevant account or submits the
access request (carried, unchanged).

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length (30pp) acceptable for submission, or does it need the deeper,
substance-costing cuts `sessions/2026-09-26-03-...md` describes? Now four sessions further from
the original <20pp target than when Q11 was first opened. | report sign-off | reviewer/instructor judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 tested eight hypotheses, narrowed the gap to 1.51pt; report states the residual as measured-and-bounded |
| M7-17's raw exact-median number for M7-8's 100%-budget model (0.19) is dangerously misleading if quoted alone, without the dip-width/stability context | a reader skimming RESULTS.md could conclude the hardened model is trivially evadable at 19% perturbation, the opposite of the qualified finding | every mention (RESULTS.md, DEVIATIONS.md, report) pairs the raw number with the stable-vs-transient breakdown in the same paragraph, never states it alone |
| The report is 30 pages, not the requested under-20 (widened from 29pp last session) | a page-limited venue/rubric may reject it as-is | PROJECT_STATE.md/session files state the finding and ranked options honestly rather than silently shipping either an over-length report or one hollowed out to hit a number |
| Two Claude Code sessions ran on this repo concurrently during M7-10; nothing currently prevents this from happening again | a future concurrent session's edits could silently clobber or duplicate content | no fix implemented — flagging as a standing risk; re-read a file immediately before writing to it if a long gap occurred since it was first read |

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
session. A 200-line file costs seconds. Left to grow — the natural drift, since appending is
easier than pruning — it becomes a few thousand lines of mostly-resolved history, gets skimmed
instead of read, and stops working precisely when the project is complex enough to need it.
Pruning it is part of the task, not cleanup after the task.

## Boundaries with other docs

| File | Holds | Volatility |
|---|---|---|
| `PROJECT_STATE.md` | what is true right now | rewritten every session |
| `docs/ROADMAP.md` | the plan, M0–M7, checkboxes | ticked, rarely restructured |
| `RESULTS.md` | every benchmark ever run, one line each | append-only |
| `sessions/` | what happened in each session | append-only, one file per session |
| `docs/DEVIATIONS.md` | departures from the paper | append-only |
| `docs/THREAT_MODEL.md` | assets, adversary tiers, trust assumptions, coverage matrix, gaps | stable; amend if a future session changes a covered result |
| `CLAUDE.md` | how to work here | near-stable |

If a fact could go in two of these, it goes in exactly one — the leftmost row that fits.
