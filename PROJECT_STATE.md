# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-27 · **Milestone:** M7 stretch complete (M7-15 delivered) ·
**Sessions completed:** 32

---

## One-line status

M7-15 (federated detection via cross-replica disagreement) is delivered: `detection.federated`
(`FederatedDetector`, `majority_vote`/`vote`, `analyze_disagreement`) exploits the paper's own
`n=4` cloud-server replication instead of inspecting data (M7-12) or restricting it (M7-14) — no
new protocol message, no new trust assumption beyond M7-12's existing one. Measured against
M7-11's three strategies at 5/10/20% budgets under three scenarios (27 cells): **the result is
honestly mixed, not a clean win.**

- **(a) Poisoner trains clean, honest nodes train poisoned.** Outlier identification is always
  mechanically correct (3-vs-1). The predicted irony — the flagged outlier is the *better* model —
  holds for `label_flip`/`feature_poison` (poisoner 0.8408 vs. honest 0.7722-0.8363) but
  **inverts** for `anchor_point_injection` (honest 0.8425-0.8454 > poisoner 0.8408), reproducing
  M7-11's own finding that this strategy sometimes helps rather than hurts. Excluding the outlier
  never changes anything (majority voting had already suppressed a lone dissenter).
- **(b) Algorithm diversity (RF/DT/KNN/LR) on one shared poisoned draw.** Majority vote never
  scores below its worst individual model (9/9 cells) — but this hard-vote-of-separate-models
  architecture **underperforms** the paper's own soft-vote `DM_CSl` ensemble on 2 of 3 strategies
  at the 10% comparison point (0.786/0.819 vs. undefended 0.828/0.840), roughly even on the third.
  KNN and DT score bit-identical balanced accuracy across all three budgets for
  `anchor_point_injection` — a measured, genuine model insensitivity, not an artefact.
- **(c) Private per-node holdout** (this project's extension, not the paper's). A weak,
  inconsistent signal: only 1 of 9 cells clears its own stated detectability band
  (`anchor_point_injection` @10%), and `label_flip` — the most damaging strategy — is **not**
  reliably caught even at 20% budget. `n=4` nodes and a ~65-row holdout do not yet separate real
  degradation from sampling noise.
- Four-defense comparison table (M7-11/12/14/15 @10% budget) is the poisoning arc's capstone,
  in `RESULTS.md`, `docs/DEVIATIONS.md` DEV-41, and the report.
- Report extended (§"Federated Detection: Exploiting Replicated Redundancy", plus abstract/intro/
  conclusion updates: 14→15 extensions, "two"→"three" poisoning defenses); recompiles clean
  (tectonic) at **28 pages** (was 26 after M7-14 — see Risks, page-count gap widening).

`make test` (1758 passed, incl. 12 new `detection.federated` tests) and `make lint` (ruff + mypy
--strict on `src/`) green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | this session adds `detection/federated.py` only — no `consensus/`, `blockchain/`, or existing `detection/` module touched |
| Honeypot poisoning: attack (M7-11) + three independent defenses | done | statistical (M7-12, DEV-38, catches anchor-point-shaped batches in principle, misses label-flip) + protocol-level (M7-14, DEV-40, correctly built, measured-null effect on this corpus) + federated (M7-15, DEV-41, no new trust assumption, real but narrow/inconsistent effect) |
| Real-malware transfer evaluation | done, 3 datasets | ClaMP (3/22), EMBER (6/22), MalbehavD-V1 (12/22, DEV-39) — unchanged this session |
| `docs/report/report.pdf` | done, 28 pages | extended this session, recompiles clean via `tectonic` |
| Everything else (M7-1 through M7-14's own deliverables) | done | unchanged |

## Next task

None forced. If a future session wants to act on this one's own findings, in order of interest:

1. **A coordination mechanism for disagreement**, the limitation `docs/THREAT_MODEL.md`'s
   federated-detection subsection states plainly: M7-15 builds the signal (voting, outlier
   identification) but not what four cloud servers *do* once they disagree — the paper specifies
   nothing here and this project does not add it. A protocol for acting on a flagged node (e.g.
   feeding into `mitigation/` or a pBFT-level exclusion) is the natural next extension.
2. **Scenario (c) with a larger holdout or more nodes**: the private-holdout signal's failure to
   catch `label_flip` reliably at 20% budget is explicitly attributed to `n=4` nodes and a ~65-row
   holdout's sampling variance — untested whether more nodes or a larger holdout fraction would
   resolve it, and a candidate follow-up experiment, not a fix to this session's code.
3. Test M7-14's commit-reveal on a corpus with genuine concept drift (carried, unchanged, from the
   M7-14 session — this session did not touch commit-reveal).
4. Close the report's page-count gap (28pp vs. the original <20pp target, now two sessions wider
   than the 26pp M7-14 left it) — ranked options in
   `sessions/2026-09-26-03-report-restructure-and-ember-check.md`.

## Blockers

None. `data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

**Standing limitation, not a blocker:** CICMalDroid-2020 and MalwareBazaar/Triage remain unusable
by any future session unless the user personally creates the relevant account or submits the
access request (carried, unchanged).

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length (28pp) acceptable for submission, or does it need the deeper,
substance-costing cuts `sessions/2026-09-26-03-...md` describes? Now two sessions further from the
original <20pp target than when Q11 was first opened. | report sign-off | reviewer/instructor judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 tested eight hypotheses, narrowed the gap to 1.51pt; report states the residual as measured-and-bounded |
| M7-12's "0/15 cells prevented" could be read as "the defense doesn't work" | undersells that the mechanism works exactly where predicted | DEV-38/`RESULTS.md`/report all lead with the anchor-point-injection inversion finding before the headline 0/15 |
| M7-14's null result could be read as "commit-reveal doesn't work" | misreads a correctly-built, correctly-verified protocol as broken | DEV-40/`RESULTS.md`/report lead with "the protocol behaves exactly as specified" before the honest null result |
| M7-15's scenario (a) irony could be read as "the defense is broken" (it flags the correct model as the outlier for some cells) | misreads a stated, predicted property of disagreement-based detection as a bug | DEV-41/`RESULTS.md`/report state the irony as a designed-for finding, not a discovered defect, and show it holds for 2/3 strategies, not universally |
| The report is 28 pages, not the requested under-20 (widened from 26pp last session) | a page-limited venue/rubric may reject it as-is | PROJECT_STATE.md/session files state the finding and ranked options honestly rather than silently shipping either an over-length report or one hollowed out to hit a number |
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
