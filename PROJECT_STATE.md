# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-11-12 · **Milestone:** Project Phase 2 (four gap-filling experiments,
P2-A..D) delivered on branch `phase2` · **Sessions completed:** 36

---

## One-line status

Phase 1 (M0–M7, report, October audit) is frozen. Phase 2 added four small measured experiments
beside it, each with a script, sidecar, `RESULTS.md` block, figure (`results/figures/p2*.png`) and
DEV entry; no Phase 1 number changed.

- **P2-A (DEV-44):** the paper's rising TPS is a fixed setup cost (fit R² 0.99, 55–72% of case 1);
  our TPS rises too once the timer covers the whole program.
- **P2-B (DEV-45):** log+standardise rescues KNN (balanced acc 0.52→0.73), not LR (0.50): LR's
  failure is linearity, not scale.
- **P2-C (DEV-46):** on future years (train ≤2015, test ≥2016) the RF falls 94.2%→55.1% vs a 91.8%
  constant baseline; `year` alone scores 92.2% on the random split. Contradicts report l.478.
- **P2-D (DEV-47):** M7-12's alarm could never fire (max score 0.52 vs threshold 3.0); tuned, it
  catches lopsided batches, so it alarms on honest outbreaks too.

`make test` 1816 passed, `make lint` clean. Environment now also works on the Linux dev box
(`.venv`, `data/raw/` fetched and checksum-verified).

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation + M7 extensions | done | unchanged by Phase 2 |
| `detection/fair.py` (P2-B preprocessing) | done | new, 6 unit tests |
| Phase 2 scripts `scripts/p2{a,b,c,d}_*.py`, `p2_figures.py` | done | each writes CSV + sidecar |
| `docs/report/report.pdf` | done, 31 pages | **does not include Phase 2**; l.478 now contradicted |
| Phase 2 presentation | not started | next task |

## Next task

Build the Phase 2 presentation: one-slide Phase 1 recap, then P2-A..D one slide each (what we
tested, why, result, what it means), figures from `results/figures/p2*.png`, in the style of
`BSFR-SH_Presentation.pptx`.

Carried, lower priority: update the report with Phase 2 and fix l.478; remaining C15 wording in
`verification/pbft_results.md`/DEVIATIONS; P2-D's untested counter (noise-added anchor points);
why scaling hurts KNN at natural balance (P2-B); exact KNN bounds (M7-17); family-label gap (M7-16).

## Blockers

None. A fresh clone needs `make setup` and `make data` (took ~11 min on 2026-11-12, ~56 min earlier).

**Standing limitation, not a blocker:** CICMalDroid-2020 and MalwareBazaar/Triage remain unusable
by any future session unless the user personally creates the relevant account or submits the
access request (carried, unchanged).

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length (31pp) acceptable for submission, or does it need the deeper,
substance-costing cuts `sessions/2026-09-26-03-...md` describes? | report sign-off | reviewer/instructor judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 narrowed the gap to 1.51pt; report states the residual as measured-and-bounded |
| The report is 31 pages, not the requested under-20 (widened again this session, 30→31) | a page-limited venue/rubric may reject it as-is | stated honestly rather than silently shipping either an over-length report or a hollowed-out one |
| Two Claude Code sessions ran on this repo concurrently during M7-10; nothing currently prevents this from happening again | a future concurrent session's edits could silently clobber or duplicate content | no fix implemented — re-read a file immediately before writing to it if a long gap occurred since it was first read |
| Ada's account QOS has changed twice in one week (`low`→`medium`→back to `low` post-upgrade) and the login node/address changed (`ada`→`ada-gw1`) | a future session assuming either the old address or a specific QOS tier will have stale assumptions | `~/.ssh/config`'s `ada` host entry now points at `ada-gw1.iiit.ac.in`; re-check `myallocation`/`sacctmgr show qos` before sizing any future job rather than trusting this file's numbers |

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
