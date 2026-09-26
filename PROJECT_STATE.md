# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-26 · **Milestone:** M7 stretch complete (M7-13 delivered) ·
**Sessions completed:** 30

---

## One-line status

M7-13 (dynamic-behavioral real-malware transfer) is delivered: `MalbehavD-V1` (real Cuckoo-sandbox
execution traces) grounds 12/22 `FT_RW` features across 5/7 groups — double EMBER's 6/22,
quadruple ClaMP's 3/22, and the first dataset to reach process/network/persistence at all — yet
transfer is still exactly `bal_acc=0.5000`, now diagnosed precisely rather than just measured
again: the fitted ensemble's prediction on all 2,570 real rows is a single constant class,
provably not because real signal is absent (a within-dataset Mann-Whitney check, no synthetic data
involved, finds 9/12 mapped features separate real malware from real benign at p<1e-4) but because
`honeypot.collector`'s count features are calibrated to an unbounded ransomware episode
(thousands-scale means) while MalbehavD-V1's Cuckoo traces are capped at 175 total API calls
(single-digit real means) — a scale-calibration mismatch, not an absence of dynamic signal.

- **Dataset search dominated the session.** All four candidates the session brief named were
  checked and ruled out for distinct, verified reasons (not assumed from the brief's own
  descriptions, which were themselves wrong in one case): BODMAS's brief-given URL doesn't exist,
  and the real repo turns out to be static (same LIEF pipeline as EMBER) despite the brief calling
  it dynamic; CICMalDroid-2020 is gated behind a personal-information research-access form;
  MalwareBazaar/Triage now require account creation; a public Cuckoo instance did not respond.
  `github.com/mpasco/MalbehavD-V1` — freely downloadable, MIT-licensed, no registration — was
  found and used instead. Full account in `docs/DEVIATIONS.md` DEV-39 and this session's file.
- **Per-group permutation importance (real_drop=0.0000 for every one of the 7 groups) is what
  revealed the saturation** — without it, this session would only have re-confirmed "0.5000
  again" with no more insight than ClaMP/EMBER already gave.
- `data/external/malbehavd/` (2.3MB CSV + README) committed for full reproducibility, same posture
  as ClaMP's committed CSV.
- `docs/report/report.tex` §"Real-Data Transfer" extended with a MalbehavD-V1 subsection (coverage
  table + diagnosis + one merged figure); recompiles clean, still 25 pages (no regression).

`make test` (1693 passed, +21 new mapping tests) and `make lint` (ruff + mypy --strict) green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | unchanged this session except new `honeypot.malbehavd_mapping` module |
| Real-malware transfer evaluation | done, 3 datasets | ClaMP (3/22, DEV-34), EMBER (6/22, DEV-35), MalbehavD-V1 (12/22, 5/7 groups, DEV-39) — all `bal_acc=0.5000`, MalbehavD-V1 adds the first precise failure-mechanism diagnosis |
| `docs/report/report.pdf` | done, 25 pages | extended this session, recompiles clean |
| Everything else (M7-1 through M7-12's own deliverables) | done | unchanged |

## Next task

None forced. Two options exist if a future session is asked to act on this one's findings, neither
required:

1. **Act on M7-13's own "actionable for future work" finding**: re-calibrate
   `honeypot.collector`'s count-feature distributions (`files_touched`, `renames`, `crypto_calls`,
   and the seven Poisson-count features) to a bounded-observation-window regime instead of their
   current unbounded-episode scale, then re-run `scripts/m7_{7,10a,13}_*.py` unchanged to see
   whether any real dataset's transfer result moves off 0.5000. This is a generator change — needs
   its own `docs/DEVIATIONS.md` entry before landing, per CLAUDE.md's "never silently fix."
2. Close the report's page-count gap (25pp vs. the original <20pp target) — see prior sessions'
   ranked options in `sessions/2026-09-26-03-report-restructure-and-ember-check.md` if this
   becomes a priority; unchanged by this session, which added a bounded, single-subsection amount
   of report content, not more than the existing margin absorbed.

## Blockers

None. `data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

**Standing limitation, not a blocker, worth not re-investigating from scratch:** CICMalDroid-2020
and MalwareBazaar/Triage remain unusable by any future session unless the user personally creates
the relevant account or submits the access request — this session confirmed both are gated by
external identity verification this sandbox cannot and should not complete unilaterally.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length (25pp) acceptable for submission, or does it need the deeper, substance-costing cuts `sessions/2026-09-26-03-...md` describes? | report sign-off | reviewer/instructor judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 tested eight hypotheses, narrowed the gap to 1.51pt; report states the residual as measured-and-bounded |
| M7-12's "0/15 cells prevented" could be read as "the defense doesn't work" | undersells that the mechanism works exactly where predicted (large, novel-feature batches against mature history) | DEV-38/`RESULTS.md`/report all lead with the anchor-point-injection inversion finding before the headline 0/15 |
| M7-13's 0.5000-despite-12/22-coverage could be read as "the dynamic dataset added nothing" | undersells the actual finding (proven real signal, precisely diagnosed scale mismatch) | DEV-39/`RESULTS.md`/report all lead with the within-dataset Mann-Whitney proof before the headline 0.5000 |
| The report is 25 pages, not the requested under-20 | a page-limited venue/rubric may reject it as-is | PROJECT_STATE.md/session files state the finding and ranked options honestly rather than silently shipping either an over-length report or one hollowed out to hit a number |
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
