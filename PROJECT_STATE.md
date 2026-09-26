# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-27 · **Milestone:** M7 stretch complete (M7-14 delivered) ·
**Sessions completed:** 31

---

## One-line status

M7-14 (commit-then-reveal defense against honeypot poisoning) is delivered: `consensus.
commit_reveal` + `framework.commit_reveal_pipeline` implement a two-phase commit/reveal/merge
protocol, correctly built and behaviourally verified (22 unit tests, 1 real-pBFT integration
test), but its measured effect on anchor-point injection — the one M7-11 strategy M7-12's drift
detector cannot catch — is statistically indistinguishable from zero on this project's corpus (an
8-repeat robustness check: mean `damage_prevented` -0.0013 to +0.0055, zero inside one standard
deviation at every budget, at both an 85%- and a 15%-historical partition). Why, measured not
assumed: `honeypot.collector`'s profiles are stationary, low-dimensional mixtures, and even ~106
historical positive rows already estimate the population centroid almost as well as the full
corpus does, so denying the adversary the current round costs it almost nothing it could not
already infer from history.

- **The protocol itself works exactly as specified** — commitment binding/tamper-detection, round
  exclusion, canonical merge, `WithholdTracker` permanent exclusion (deterministic: exactly round
  3 of 6 for an always-withholding adversary at `max_consecutive_withholds=3`), and `f=1` crash
  tolerance through a real pBFT commit are all measured directly, not just unit-tested in
  isolation.
- **Collusion is bounded, not just deferred**: two colluding nodes at `n=4` already exceeds pBFT's
  own `f<n/3` tolerance, so commit-reveal adds no new trust assumption for that failure mode — a
  genuinely good property, stated as one rather than buried among limitations. It does add one new
  trust assumption elsewhere (no out-of-band batch leakage before reveal, Trust Assumption 8).
- **Combined with M7-12's drift detector: nothing newly caught.** Every defended anchor-point
  cell's Mahalanobis score (0.012-0.017) is still ~2 orders of magnitude below the 3.0 alarm
  threshold, consistent with the sweep's own null finding.
- `configs/chain.yaml` gained `consensus.commit_reveal.{enabled, max_consecutive_withholds}` — the
  config-flag switch between direct and commit-reveal submission.
- Report extended (§"Commit-Then-Reveal: A Protocol-Level Defense", plus abstract/intro/conclusion
  updates reflecting 14 extensions and both poisoning defenses); recompiles clean at **26 pages**
  (was 25 after M7-13 — see Risks).

`make test-all` (1746 passed) and `make lint` (ruff + mypy --strict) green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | this session adds `consensus.commit_reveal` + `framework.commit_reveal_pipeline` |
| Honeypot poisoning: attack (M7-11) + two independent defenses | done | statistical (M7-12, DEV-38, catches anchor-point-shaped batches in principle, misses label-flip) + protocol-level (M7-14, DEV-40, correctly built, measured-null effect on this corpus) |
| Real-malware transfer evaluation | done, 3 datasets | ClaMP (3/22), EMBER (6/22), MalbehavD-V1 (12/22, DEV-39) — unchanged this session |
| `docs/report/report.pdf` | done, 26 pages | extended this session, recompiles clean |
| Everything else (M7-1 through M7-13's own deliverables) | done | unchanged |

## Next task

None forced. If a future session wants to act on this one's own findings, in order of interest:

1. **Test commit-reveal on a corpus where it should actually bind**: this session's null result is
   scoped to `honeypot.collector`'s stationary, ~106+-positive-row-converges profiles. A synthetic
   corpus with genuine concept drift, higher feature dimensionality relative to sample size, or a
   much smaller absolute historical sample would be the regime to test whether the protocol's
   measured protection changes — a new experiment, not a fix to this session's code.
2. Act on M7-13's own generator-recalibration suggestion (unchanged, carried from last session).
3. Close the report's page-count gap (26pp vs. the original <20pp target) — ranked options in
   `sessions/2026-09-26-03-report-restructure-and-ember-check.md`; this session added one bounded
   subsection plus small abstract/intro/conclusion edits, consistent with prior sessions' own
   modest, content-driven growth.

## Blockers

None. `data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

**Standing limitation, not a blocker:** CICMalDroid-2020 and MalwareBazaar/Triage remain unusable
by any future session unless the user personally creates the relevant account or submits the
access request (carried from the M7-13 session, unchanged).

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length (26pp) acceptable for submission, or does it need the deeper, substance-costing cuts `sessions/2026-09-26-03-...md` describes? | report sign-off | reviewer/instructor judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 tested eight hypotheses, narrowed the gap to 1.51pt; report states the residual as measured-and-bounded |
| M7-12's "0/15 cells prevented" could be read as "the defense doesn't work" | undersells that the mechanism works exactly where predicted | DEV-38/`RESULTS.md`/report all lead with the anchor-point-injection inversion finding before the headline 0/15 |
| M7-13's 0.5000-despite-12/22-coverage could be read as "the dynamic dataset added nothing" | undersells the actual finding (proven real signal, precisely diagnosed scale mismatch) | DEV-39/`RESULTS.md`/report all lead with the within-dataset Mann-Whitney proof before the headline 0.5000 |
| M7-14's null result could be read as "commit-reveal doesn't work" or, worse, silently spun as a win | either misreads a correctly-built, correctly-verified protocol as broken, or overclaims protection the numbers don't support | DEV-40/`RESULTS.md`/report all lead with "the protocol behaves exactly as specified" (22+1 tests) before the honest "measured effect is statistically indistinguishable from zero," and state the specific corpus property (fast centroid convergence) that explains why, rather than a vague "it didn't work" |
| The report is 26 pages, not the requested under-20 | a page-limited venue/rubric may reject it as-is | PROJECT_STATE.md/session files state the finding and ranked options honestly rather than silently shipping either an over-length report or one hollowed out to hit a number |
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
