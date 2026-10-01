# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-10-01 · **Milestone:** M7 stretch complete (M7-18 delivered, fully
resolved — no pending runs) · **Sessions completed:** 35

---

## One-line status

M7-18 (TLA+ formal verification of the reduced pBFT consensus protocol) is **fully delivered,
every claim measured, nothing pending**: `verification/pbft.tla` models DEV-10/DEV-20's reduced
pBFT and TLC confirms both safety and liveness at the design fault bound — the consensus-layer
counterpart to M7-1's Scyther verification of the session layer.

- **Two draft versions of the view-change safety guard were themselves shown unsound by TLC**, at
  the smallest bound, before a third verified clean — both spec bugs (a timing-free global
  snapshot; an unverified Byzantine `ViewChange` claim), kept as documented dead ends in
  `pbft.tla` rather than silently fixed. Neither was a protocol bug.
- **Safety at `F=1`: VERIFIED, exhaustive.** Agreement/Validity/Integrity — 74,970,368 states,
  depth 33, 1h08min, no violation.
- **FLAW-5 at `F=2`: VIOLATED, confirmed twice over.** Local `-simulate` found the fork in
  1s/115,938 states; Ada's standard exhaustive BFS independently reached the identical fork at
  1,501,898,636 states/15h56min (job 2720269). TLC stops at the first violation by design (544M
  states were still unqueued), so "no other violation exists at F=2" isn't established and wasn't
  pursued — not needed for FLAW-5's actual claim.
- **Liveness at `F=0`: VERIFIED, exhaustive** (1,240,200 states, 3min). **Liveness at `F=1`:
  VERIFIED, exhaustive (149,940,224 states, 16h49min, Ada job 2721161) — and this contradicted the
  prediction going in.** DEV-20 #2's lagging-replica cost was expected to show up as a
  `Termination` violation here; it does not, *at this bound*, because `DoCommit`'s state-transfer
  guard is vacuously satisfied when `MaxSeq=1` — there is no second sequence number to fall behind
  on. The defect itself is real (a Python test constructs it on a genuine multi-height run);
  showing it formally needs `MaxSeq>=2`, which this project's observed growth rates (1.5 billion
  states at `MaxSeq=1` alone) put out of practical reach here. Reported as a bound limitation, not
  as evidence the omission is costless — see `verification/pbft_results.md` Run 4 for the full
  argument.
- Both Ada jobs finished *before* Ada's scheduled maintenance upgrade (2026-09-29→10-01, new login
  node `ada-gw1`, old `ada` address retired) — results were sitting complete on NFS home when this
  session next reached the cluster, nothing was lost or needed resubmitting.
- Report extended (`docs/report/report.tex` §"Formal Verification of Consensus", new table
  `tab:tlc`, coverage-matrix row 3 amended) with the corrected, measured results throughout;
  recompiles clean (tectonic), **31 pages** (was 30).
- **Separately, this session also fixed `README.md`**: its "Reproduction targets" table had said
  "not started" for every row since M0 scaffold time, never updated across 35 sessions of real
  work. Now shows the actual measured numbers (94.42%/0.9697 detection accuracy/F1, real mining
  times, the honest "TPS is flat, not rising" finding) plus a new "Beyond the paper" section
  covering the M7 stretch work the README previously didn't mention at all. Also fixed a broken
  `git fetch` refspec (was pinned to a stale branch name, silently breaking `git fetch`/`pull`
  while `git push` kept working) — pushes were never actually missing, just hard to verify locally.

`make test` (1801 passed) and `make lint` unaffected — this session touches only `verification/`,
`docs/`, `PROJECT_STATE.md`, `README.md`, and `.ssh/config`; no Python source changed.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | unchanged this session |
| Formal verification: session layer (M7-1, Scyther) + consensus layer (M7-18, TLA+/TLC) | **done, fully measured** | `verification/pbft.tla`, `pbft_results.md` — no pending runs |
| Honeypot poisoning: attack + three independent defenses (M7-11/12/14/15) | done | unchanged |
| Multi-family detection (M7-16); adversarial robustness + exact bounds (M7-3/8/17) | done | unchanged |
| Real-malware transfer evaluation | done, 3 datasets | unchanged |
| `docs/report/report.pdf` | done, 31 pages | recompiles clean via `tectonic` |
| `README.md` | done, now reflects real status | was stuck at M0-scaffold "not started" wording |
| Everything else (M7-2 through M7-17's own deliverables) | done | unchanged |

## Next task

None forced — M7-18 closed out clean, nothing pending. If a future session wants to act on open
findings, in order of interest: (1) a stability-adjusted robustness metric (M7-17's own finding);
(2) exact `k_nearest_neighbours` bounds (needs a bigger machine than the 8GB dev box); (3) the
`FT_RW`/honeypot family-label gap (M7-16); (4) a coordination mechanism for federated-detection
disagreement (M7-15); (5) the report's page-count gap (Q11 below); (6) *(new, low priority)* if
ever revisited, M7-18's `MaxSeq>=2` liveness check would need either a much bigger machine (Ada's
`cpu=40`/no-disk-quota headroom is the closest available) or a cheaper model-checking technique
than exhaustive BFS — not attempted this session, see `pbft_results.md` limitations.

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
