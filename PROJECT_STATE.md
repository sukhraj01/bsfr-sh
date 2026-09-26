# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-26 · **Milestone:** M7 stretch complete; write-up restructured ·
**Sessions completed:** 29

---

## One-line status

The report is restructured (17 chronological sections → 10: Introduction, Paper Summary,
Implementation, Reproduction Results, Security Analysis, Detection Analysis, Scalability
Analysis, Critique, What the Paper Gets Right, Conclusion) and recompiled; the next action on
this project is presentation prep, not more extensions.

- **`docs/report/report.tex`**: rebuilt by exact-line-range extraction and reassembly, not
  retyped — every number/table cell/finding traces to the same `RESULTS.md` line it did before.
  Redundancy given exactly one home each: Raft's quantitative table moved to Reproduction Results
  (next to pBFT's own timing), its qualitative Byzantine-leader finding to Security Analysis;
  GAP-2 (storage) moved out of Critique (it was never one of the "five defects") into Scalability
  Analysis; DEV-08/FLAW-4's Critique paragraphs shortened to interpretation + cross-reference, the
  measured evidence stays in Reproduction Results/Scalability. Scyther verification moved from
  Implementation (which keeps the design decision) to Security Analysis (Tier 1 evidence). Three
  new bibliography entries (Raft, Welford, Page-Hinkley) for name-drops that had none.
- **Seven figure pairs merged** (18 → 11 figure environments, both original labels kept per
  merged float so no `\ref` broke). **One table condensed** (hybrid-anchor frequency sweep, 18
  raw rows → 3-row summary, full data still cited to `RESULTS.md` M7-5). Two subsections
  (D3 serialization-on supplement, Neural-vs-Tree) trimmed ~30-40% without losing a number.
- **Finding: the report was already 25 pages before this session touched it** — the "16+" belief
  driving the <20-page target was stale. Compiling the untouched original standalone confirmed
  this. The naive reorganization pushed it to 27; this session's compression brought it back to
  25 — even with everything, **not under 20**, because the document is genuinely dense (verified
  page-by-page at 300 DPI: no wasted whitespace, floats already packed tight). Reaching 20 from
  here needs cutting whole findings, not padding — see Next task.
- **A real rendering defect was caught and fixed**, not shipped: tightening IEEEtran's float
  separation lengths (a standard page-budget lever) caused a genuine text/table overlap,
  reproduced across three clean rebuilds, bisected to that one preamble change, and removed
  (it bought zero net pages anyway). Every one of the report's 25 pages was visually re-verified
  clean after the fix.
- Ada/EMBER: re-verified already closed (commit `70f9e3c`, `RESULTS.md` M7-10a) — no new Ada work
  this session; this is the second session in a row to find this already done.

`make test` (1661 passed) and `make lint` (ruff + mypy --strict) unaffected and confirmed green —
this session touched only `docs/report/report.tex`.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | unchanged this session |
| `docs/report/report.pdf` | done, restructured, 25 pages | recompiled (`tectonic`); every page visually verified; not under the 20-page target — see Risks |
| Everything else (M7-1 through M7-12's own deliverables) | done | unchanged |

## Next task

None forced. If a future session is asked to close the report's page-count gap specifically, in
order of how much substance each option costs (cheapest first): (1) accept ~24-25 pages as
accurate for twelve extensions' worth of measured content, and change the target instead of the
report; (2) cut a whole confirmatory sub-experiment rather than trim more prose — the MLP-vs-RF
architecture comparison and the EMBER half of the real-data-transfer section are the most
independently-cuttable (each confirms rather than introduces a headline finding), each needing a
`docs/DEVIATIONS.md`-style note that it was cut for length, not retracted; (3) move detailed
per-cell tables (M7-6's hypothesis sweep, the 12-row pBFT-vs-Raft matrix) to a
supplementary/appendix file, keeping only summary tables in the main body — the pattern this
session already applied to the hybrid-anchoring frequency sweep.

## Blockers

None. The report compiles and renders correctly at its current length; the 20-page target is
unmet but blocks nothing else.

`data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length (25pp) acceptable for submission, or does it need the deeper, substance-costing cuts described in "Next task"? | report sign-off | reviewer/instructor judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 tested eight hypotheses, narrowed the gap to 1.51pt; report states the residual as measured-and-bounded |
| M7-12's "0/15 cells prevented" could be read as "the defense doesn't work" | undersells that the mechanism works exactly where predicted (large, novel-feature batches against mature history) | DEV-38/`RESULTS.md`/report all lead with the anchor-point-injection inversion finding before the headline 0/15 |
| The report is 25 pages, not the requested under-20 | a page-limited venue/rubric may reject it as-is | PROJECT_STATE.md/session file state the finding and the three ranked options honestly rather than silently shipping either an over-length report or one hollowed out to hit a number |
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
| `docs/THREAT_MODEL.md` | assets, adversary tiers, trust assumptions, coverage matrix, gaps | stable; amend if a future session changes a covered result |
| `CLAUDE.md` | how to work here | near-stable |

If a fact could go in two of these, it goes in exactly one — the leftmost row that fits.
