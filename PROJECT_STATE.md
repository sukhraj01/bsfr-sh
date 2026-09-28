# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-28 · **Milestone:** M7 stretch — M7-18 delivered (local results); two
exhaustive TLC runs pending on Ada · **Sessions completed:** 35

---

## One-line status

M7-18 (TLA+ formal verification of the reduced pBFT consensus protocol) is delivered locally:
`verification/pbft.tla` models DEV-10/DEV-20's reduced pBFT and TLC confirms, exhaustively at the
design fault bound, that Agreement/Validity/Integrity hold — the consensus-layer counterpart to
M7-1's Scyther verification of the session layer.

- **Two draft versions of the view-change safety guard were themselves shown unsound by TLC**, at
  the smallest bound, before a third verified clean — both spec bugs (a timing-free global
  snapshot; an unverified Byzantine `ViewChange` claim), kept as documented dead ends in
  `pbft.tla` rather than silently fixed. Neither was a protocol bug.
- **Measured, exhaustive**: `F=1` safety (Agreement/Validity/TypeOK) — 74,970,368 states, depth 33,
  1h08min, no violation. `F=0` liveness control (`Termination`) — 1,240,200 states, 3min, no
  violation.
- **Measured, non-exhaustive**: FLAW-5's `F=2` fork — TLC's exhaustive attempt ran 4h19min/281M
  states (stuck at BFS depth 15) before exhausting 24GB of local disk without completing;
  `-simulate` mode found the same Agreement violation in 1 second. One found counterexample already
  conclusively demonstrates the fork regardless of search strategy.
- **Not yet measured**: `F=1` liveness (`Termination`) — expected violated, per DEV-20 #2 (no state
  transfer) sharpened here to a new formal fact (at this exact `n=4/F=1` config, `QuorumSize`
  equals the honest-replica count, so *any* progress needs *every* honest replica) — but the local
  run hit a low-memory warning after 1h42min/16.4M states and was stopped rather than left running
  or risked repeating the FLAW-5 disk exhaustion.
- **Both incomplete exhaustive runs (FLAW-5 `F=2`, `Termination` `F=1`) were moved to Ada**
  (`verification/ada_flaw5.sbatch` job 2720269, `ada_liveness.sbatch` job 2720270 — both `PD`,
  queued behind the account's `cpu=10` QOS ceiling, not run in parallel). **This is an upgrade to
  already-reported findings, not a blocker** — see Next task.
- Report extended (`docs/report/report.tex` §"Formal Verification of Consensus", new table
  `tab:tlc`, coverage-matrix row 3 amended); recompiles clean (tectonic), still **30 pages**.

`make test` and `make lint` unaffected — this session touches only `verification/` (new files) and
docs; no Python source changed.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | unchanged this session |
| Formal verification: session layer (M7-1, Scyther) + consensus layer (M7-18, TLA+/TLC) | done, locally; 2 exhaustive TLC runs pending on Ada | `verification/pbft.tla`, `pbft_results.md` |
| Honeypot poisoning: attack + three independent defenses (M7-11/12/14/15) | done | unchanged |
| Multi-family detection (M7-16); adversarial robustness + exact bounds (M7-3/8/17) | done | unchanged |
| Real-malware transfer evaluation | done, 3 datasets | unchanged |
| `docs/report/report.pdf` | done, 30 pages | extended this session, recompiles clean via `tectonic` |
| Everything else (M7-2 through M7-17's own deliverables) | done | unchanged |

## Next task

**Check Ada jobs 2720269 (`ada_flaw5.sbatch`) and 2720270 (`ada_liveness.sbatch`)**:
`ssh ada squeue -u sukhraj.singh`; when each finishes, `~/m7-18-verification/ada_{flaw5,liveness}_
result_<jobid>.log` holds the result. If `ada_flaw5` completes: record total states/time and
confirm Agreement is the only invariant violated — upgrades FLAW-5 from "counterexample found" to
"full state space explored, this is the only violation." If `ada_liveness` completes: record
pass/fail — this is the one M7-18 claim not yet backed by a measured number (only an argument from
the `F=1` safety run's own certificate arithmetic). Either way, update `verification/pbft_results.md`
§"Ada runs", the report's §"Formal Verification of Consensus" (replace "pending"/"expected" wording
with the measured result), and `docs/DEVIATIONS.md` DEV-20's amendment. If Ada also exhausts disk,
note the state count reached and move on — a partial exhaustive search is still informative,
already the pattern this session used locally.

If Ada is not the next session's actual task, the M7-17 backlog is still open, in order of
interest: (1) a stability-adjusted robustness metric (M7-17); (2) exact `k_nearest_neighbours`
bounds (needs a bigger machine); (3) the `FT_RW`/honeypot family-label gap (M7-16); (4) a
coordination mechanism for federated-detection disagreement (M7-15); (5) the report's page-count
gap (Q11 below).

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
substance-costing cuts `sessions/2026-09-26-03-...md` describes? | report sign-off | reviewer/instructor judgement |
| Q12 | Do the two pending Ada TLC runs need to land before the report is considered final, or can
"pending, argued analytically" stand as submitted? | report sign-off if Ada is slow | reviewer/instructor judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 narrowed the gap to 1.51pt; report states the residual as measured-and-bounded |
| The `F=1` liveness claim (DEV-20 #2's cost) is currently an argument, not a TLC-measured fact, pending Ada job 2720270 | a reader could mistake the analytical argument for a measured result | `pbft_results.md`, `DEVIATIONS.md` and the report all state "expected violated"/"pending" explicitly, never phrase it as measured |
| The report is 30 pages, not the requested under-20 | a page-limited venue/rubric may reject it as-is | stated honestly rather than silently shipping either an over-length report or a hollowed-out one |
| Two Claude Code sessions ran on this repo concurrently during M7-10; nothing currently prevents this from happening again | a future concurrent session's edits could silently clobber or duplicate content | no fix implemented — re-read a file immediately before writing to it if a long gap occurred since it was first read |
| Ada jobs 2720269/2720270 are unattended background SLURM jobs (4-day wall-clock limit) | if never checked, they finish and are never incorporated | flagged as the explicit Next task above |

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
