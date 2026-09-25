# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-25 · **Milestone:** M7 stretch — eight of nine items done; report
compiled and current · **Sessions completed:** 25

---

## One-line status

This session (M7-9) is documentation only: constructed the threat model the paper's §V never
states, mapping every security-relevant result this project has produced (Scyther, pBFT threshold
analysis, Raft comparison, hybrid anchoring, adversarial attack/defense) onto four adversary tiers
by capability, and replaced §V's five paragraphs of prose with a coverage matrix.

- **`docs/THREAT_MODEL.md`** (new): standalone reference — assets (with the chain + property that
  protects each), four adversary tiers (external network attacker / one compromised server f=1 /
  two compromised servers f=2 / adversarial ML evasion), five explicit trust assumptions, a
  coverage matrix (§V claim → tier → method → result → limitation), a four-item gap analysis
  (honeypot data poisoning, registration-authority insider threat, consensus DoS, backup-chain
  side channels). No solutions proposed — gaps are findings, not tickets.
- **`docs/report/report.tex`** new §"Threat Model" (before §Conclusion): shorter version, focused
  on the coverage-matrix table and the gap analysis. Recompiled with `tectonic`; fixed two LaTeX
  issues while building the table (backtick-quoted code spans instead of `\texttt{}`; one table
  cell holding an essay-length sentence in a non-wrapping `c` column caused a 144pt overfull hbox
  — both fixed, `tectonic` now clean of new warnings).
- **The finding: 3 of 5 §V claims hold at their defensible tier, 2 have measured gaps the paper
  doesn't acknowledge, and a 6th attack surface isn't a §V claim at all.** (1) session protocol —
  fully verified (Scyther, M7-1). (3) pBFT — Sybil and f=1 verified, but the "51%" framing is
  wrong (FLAW-5); f=2 demonstrably forks the chain. (5) chain isolation — verified structurally,
  unconditionally. (2) credential deletion — never implemented, nothing to check it against. (4)
  DoS-resistance — has a measured liveness gap (DEV-20: one lagging honest replica + one Byzantine
  stalls the chain at n=4). Adversarial ML (M7-3/M7-8) isn't a §V claim at all — GAP-6's clearest
  consequence.
- No code changed. `docs/ROADMAP.md` M7-9 ticked.

`make test` (1547 tests, unchanged) and `make lint` (ruff + mypy) both green — confirms nothing
broke, since this session touched no `src/`.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | unchanged this session (M7-9 is docs-only) |
| `docs/THREAT_MODEL.md` | done (M7-9) | new — standalone reference, cross-referenced from the report |
| `docs/report/report.pdf` | done, current | recompiled this session (`tectonic`), new §"Threat Model" |
| `verification/` | done (M7-1) | unchanged |
| `docs/STORAGE_ANALYSIS.md` | done (M7-2) | unchanged |
| `scripts/run_adversarial_robustness.py` | done (M7-3) | unchanged |
| `scripts/run_consensus_comparison.py` | done (M7-4) | unchanged |
| `scripts/run_hybrid_benchmark.py` | done (M7-5) | unchanged |
| `scripts/m7_6_gap_closure.py` | done (M7-6) | unchanged |
| `scripts/m7_7_real_malware_transfer.py` | done (M7-7) | unchanged |
| `scripts/m7_8_adversarial_retraining.py` | done (M7-8) | unchanged |

## Current numbers

None new — M7-9 is a synthesis of existing measurements, no new experiments. Every number in
`docs/THREAT_MODEL.md` and the report's new §"Threat Model" cites an existing `RESULTS.md` line,
test name, or `verification/` claim (M7-1/M7-3/M7-4/M7-5/M7-7/M7-8).

## Next task

None forced — M7 is optional stretch work and the core deliverable was complete before M7-6
through M7-9. If continued: async pBFT with modelled network latency is the one remaining
`docs/ROADMAP.md` M7 item. `docs/THREAT_MODEL.md`'s own gap analysis names four uncovered attack
surfaces (honeypot data poisoning, registration-authority insider threat, consensus DoS, backup-
chain side channels) as candidate future sessions — none forced, all explicitly out of scope for
the session that found them.

## Blockers

None.

`data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length sufficient, or should it be trimmed? | report sign-off | reviewer judgement |

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
| M7-7's bal_acc=0.5000 could be misread as "the framework doesn't work" rather than "19/22 features have no static analogue" | undersells the synthetic-corpus result (0.8422) and the framework's actual design | DEV-34 and the report state explicitly that this is a schema dynamic-vs-static grounding finding, not a generator-calibration failure, before giving the number |
| M7-8's 25%-budget "hardening backfires" result could be misread as "adversarial retraining doesn't work" rather than "a narrow training budget generalises worse than a wide one" | undersells the real robustness gain measured at 50%/100% | report and `RESULTS.md` state the non-monotonicity explicitly and lead with it, rather than averaging budgets into one number |
| `docs/THREAT_MODEL.md`'s anchor-chain trust assumption (Tier 3's only detection mechanism) is itself simulated, single-authority, and untested against a compromised anchor authority | a reader could mistake hybrid anchoring for a closed Tier-3 solution rather than a partial, unverified one | stated plainly in both the Tier 3 writeup and Trust Assumption 2, cross-referencing DEV-33's own "not real Ethereum or Bitcoin" caveat |

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
