# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-26 · **Milestone:** M7 stretch — M7-12 (statistical poisoning
detection) done · **Sessions completed:** 28

---

## One-line status

M7-12 built and measured the defense M7-11 only predicted the shape of: a drift-detection gate on
`BC_SigRW`'s pre-commit path, evaluated against all 15 of M7-11's (strategy, budget) cells.

- **`detection/drift.py`** (new): `DriftDetector` (Welford's online per-feature running stats,
  two scoring methods — Mahalanobis RMS-aggregated batch-centroid distance, and Page-Hinkley over
  that signal). No historical sample is ever stored, which is also why a full per-feature KS test
  (needs the raw samples, not just their moments) was scoped out rather than built.
- **`consensus/validated_commit.py`** (new): `ValidatedSigRWChain` overrides `Chain.check_append()`
  for `BC_SigRW` only, so a replica that scores a batch as anomalous raises `ChainError` and is
  rejected by pBFT's existing `2f+1` vote-counting — no new consensus message. `consensus/pbft.py`
  gained one additive `Cluster.__init__(chain_factory=...)` parameter (default `Chain`, so
  `BC_DTBU` is unaffected).
- **Finding: the defense catches the strategy predicted least catchable, and misses the one
  predicted most catchable.** Anchor-point injection's interpolated midpoint coincides with the
  corpus's *population mean* in a class-balanced corpus — it scores *below* the same-size
  clean-batch noise floor at every budget. Label flipping/feature poisoning score *above* the
  noise floor at budgets ≥5%, but from batch *composition* (all-malicious rows), not label
  content, which the detector structurally cannot see — an honest ransomware outbreak would
  trigger the identical alarm. At the shipped, pre-registered threshold: 0/15 M7-11 cells
  prevented, false-positive rate 0/30 clean batches, a "new family" probe (17x the clean p95) not
  flagged either — the detection-vs-false-positive tension measured, not assumed.
- **Two new trust assumptions** (`docs/THREAT_MODEL.md` TA-6: `BC_SigRW` replicas can now decrypt
  `Sig_RW` payloads, narrowing "miners validate blocks they cannot read"; TA-7: every honest
  replica must run the same `DriftPolicy`) and **one named architectural exception**
  (`consensus/` → `detection/`, pinned in `test_module_boundaries.py`'s `CONSENSUS_DETECTION_ALLOWED`,
  since `detection/drift.py` itself has zero internal dependencies).
- `docs/DEVIATIONS.md` DEV-38. `docs/THREAT_MODEL.md` Gap 1's "post-commit detection... not
  built" paragraph rewritten as "pre-commit detection, built and measured," plus TA-6/TA-7.
  `RESULTS.md` "M7-12". `docs/ARCHITECTURE.md` §consensus updated.

`make test` (1661 passed: 14 drift + 4 validated-commit, new this session) and `make lint` (ruff +
mypy --strict on `src`/`tests`) both green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | `detection/drift.py`, `consensus/validated_commit.py` added this session |
| `docs/report/report.pdf` | done, current | recompiled (`tectonic`), new §"Statistical Poisoning Detection" |
| `docs/THREAT_MODEL.md` | done | TA-6/TA-7 added; Gap 1 updated with M7-12's measured results |
| `scripts/m7_12_poisoning_defense.py` | done | ~5s local run; run_id `20260926T041840Z-670ec207` |
| Everything else (M7-1 through M7-11's own deliverables) | done | unchanged |

## Current numbers

`RESULTS.md` "M7-12", run `20260926T041840Z-670ec207`. 0/15 M7-11 cells prevented at Mahalanobis
threshold=3.0. Mahalanobis scores: label_flip 0.32-0.57, feature_poison 0.28-0.50,
anchor_point_injection 0.008-0.016. Matched clean-batch noise floor p95 by size (n=7/36/72/
143/358/353): 0.551/0.238/0.161/0.110/0.067/0.070. False-positive rate 0/30. New-family probe
score 1.2255, not flagged. Real pBFT: 4/4 burst-commit scenarios (label-flip and anchor-shift,
39-40 records, defended and undefended) committed against a 6-block honest history.

## Next task

None forced — M7 is complete except the items below, none required. If continued, in priority
order: (1) a size-adaptive drift threshold (informed by this session's own noise-floor-by-batch-
size table) as the direct way to close the detection-vs-false-positive tension M7-12 measured
rather than resolved; (2) a fuzz test for TA-7 (one replica running a mismatched `DriftPolicy`) —
untested, only stated; (3) async pBFT with modelled network latency, the one remaining
`docs/ROADMAP.md` M7 item from before M7-11/12.

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
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 tested eight hypotheses, narrowed the gap to 1.51pt; report states the residual as measured-and-bounded |
| M7-7's/M7-10a's bal_acc=0.5000 could be misread as "the framework doesn't work" rather than a schema-grounding finding | undersells the synthetic-corpus result and the framework's design | DEV-34/DEV-35 and the report state explicitly this is a static-vs-dynamic grounding finding, and note the PR-AUC nuance |
| M7-8's/M7-10b's hardening-backfire findings could be read as "adversarial retraining/neural nets don't work" | undersells the real robustness gain measured at other budgets | `RESULTS.md`/report state both effects explicitly, side by side with the budgets that do help |
| M7-11's "anchor-point injection improves accuracy at low budget" could be read as "poisoning is safe" | undersells label flipping's monotonic collapse and the permanence finding | `RESULTS.md`/report/DEV-37 lead with label flipping before noting anchor injection's anomaly |
| M7-12's "0/15 cells prevented" could be read as "the defense doesn't work" rather than "this specific threshold, chosen before measurement, is conservative, and loosening it has a measured false-positive cost" | undersells that the mechanism does work exactly where the array-level analysis says it should (large, novel-feature batches against mature history) | DEV-38/`RESULTS.md`/`docs/THREAT_MODEL.md` all lead with the anchor-point-injection inversion finding and the noise-floor table before the headline 0/15, and state the threshold as a measured tension, not a failure |
| Two Claude Code sessions ran on this repo concurrently during M7-10 (M7-9, M7-10); nothing currently prevents this from happening again | a future concurrent session's edits could silently clobber or duplicate content | no fix implemented — flagging as a standing risk; re-read a file immediately before writing to it if a long gap occurred since it was first read |

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
