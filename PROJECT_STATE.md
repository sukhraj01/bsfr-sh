# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-29 · **Milestone:** M7 stretch — M7-18 delivered; FLAW-5's `F=2` exhaustive
Ada run completed and confirms the fork; `F=1` liveness exhaustive Ada run still computing ·
**Sessions completed:** 35

---

## One-line status

M7-18 (TLA+ formal verification of the reduced pBFT consensus protocol) is delivered:
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
- **Measured, exhaustive, confirmed twice over**: FLAW-5's `F=2` fork — local `-simulate` found it
  in 1s/115,938 states; Ada's standard (non-simulate) exhaustive search independently reached the
  identical fork at 1,501,898,636 states / 15h56min (job 2720269, completed). TLC stops at the
  first violation by design (544M states were still unqueued), so "no other violation exists at
  F=2" is not established and was not pursued — not needed for FLAW-5's actual claim.
- **Still computing, not yet measured**: `F=1` liveness (`Termination`) — expected violated, per
  DEV-20 #2 (no state transfer) sharpened here to a new formal fact (at this exact `n=4/F=1`
  config, `QuorumSize` equals the honest-replica count, so *any* progress needs *every* honest
  replica). Ada job 2721161 (20 cpu/~58.6GB, resubmitted after a QOS upgrade mid-session) has fully
  built the 149,940,224-state reachable graph and is now computing the final fairness/temporal
  result — the one M7-18 claim without a measured pass/fail as of this update.
- Report extended (`docs/report/report.tex` §"Formal Verification of Consensus", new table
  `tab:tlc`, coverage-matrix row 3 amended); recompiles clean (tectonic), now **31 pages** (was 30
  — widened again, see Risks).

`make test` and `make lint` unaffected — this session touches only `verification/` (new files) and
docs; no Python source changed.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | unchanged this session |
| Formal verification: session layer (M7-1, Scyther) + consensus layer (M7-18, TLA+/TLC) | done; FLAW-5 exhaustive confirmed on Ada, 1 liveness run still computing there | `verification/pbft.tla`, `pbft_results.md` |
| Honeypot poisoning: attack + three independent defenses (M7-11/12/14/15) | done | unchanged |
| Multi-family detection (M7-16); adversarial robustness + exact bounds (M7-3/8/17) | done | unchanged |
| Real-malware transfer evaluation | done, 3 datasets | unchanged |
| `docs/report/report.pdf` | done, 31 pages | extended this session, recompiles clean via `tectonic` |
| Everything else (M7-2 through M7-17's own deliverables) | done | unchanged |

## Next task

**Check Ada job 2721161 (`ada_liveness.sbatch`) — blocked by an Ada outage, not by anything in
this project.** `ada_flaw5.sbatch` (2720269) is done: Agreement violated, 1,501,898,636 states,
15h56min, matching the local simulation's fork exactly (`verification/pbft_results.md` Run 2
already updated with this). As of 2026-09-29, the last confirmed liveness state was: reachable
graph fully built (149,940,224 states), TLC computing the final fairness/temporal result. **Ada is
now down for a scheduled major upgrade, expected back 2026-10-01** — SSH is refused outright
(`Permission denied (hostbased)`), so the job's fate (still running / paused / killed by the
upgrade) cannot be checked until then. Next session (or a later check in this one): `ssh ada
squeue -u sukhraj.singh` / `tail ~/m7-18-verification/ada_liveness_result_2721161.log`. If the job
is gone (killed by the upgrade with no result), resubmit `ada_liveness.sbatch` fresh rather than
try to recover partial state — TLC's own checkpointing is per-run, not something this project's
tooling manages across a cluster reboot. When a result lands (pass/fail): update
`verification/pbft_results.md` §"Ada runs"/§"Run 4", the report's §"Formal Verification of
Consensus" (replace "still computing"/"expected" wording with the measured result and its trace if
violated), `docs/DEVIATIONS.md` DEV-20's amendment, and this file's one-line status.

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
| Q11 | Is the report's length (31pp) acceptable for submission, or does it need the deeper,
substance-costing cuts `sessions/2026-09-26-03-...md` describes? | report sign-off | reviewer/instructor judgement |
| Q12 | Does the one still-pending Ada TLC run (`F=1` liveness, job 2721161) need to land before the
report is considered final, or can "still computing, argued analytically" stand as submitted?
FLAW-5's own Ada run already landed and confirmed the fork. | report sign-off if Ada is slow | reviewer/instructor judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 narrowed the gap to 1.51pt; report states the residual as measured-and-bounded |
| The `F=1` liveness claim (DEV-20 #2's cost) is currently an argument, not a TLC-measured fact — the only remaining unmeasured M7-18 claim, pending Ada job 2721161 | a reader could mistake the analytical argument for a measured result | `pbft_results.md`, `DEVIATIONS.md` and the report all state "expected violated"/"still computing" explicitly, never phrase it as measured |
| The report is 31 pages, not the requested under-20 (widened again this session, 30→31) | a page-limited venue/rubric may reject it as-is | stated honestly rather than silently shipping either an over-length report or a hollowed-out one |
| Two Claude Code sessions ran on this repo concurrently during M7-10; nothing currently prevents this from happening again | a future concurrent session's edits could silently clobber or duplicate content | no fix implemented — re-read a file immediately before writing to it if a long gap occurred since it was first read |
| Ada job 2721161's fate is unknown -- the cluster is down for a scheduled upgrade (back 2026-10-01) and SSH is refused | the liveness result may be lost if the job was killed rather than paused, needing a fresh resubmit | flagged as the explicit Next task above; not a project bug, an external outage |

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
