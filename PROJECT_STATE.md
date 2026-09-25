# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-26 · **Milestone:** M7 stretch — M7-11 (honeypot data poisoning)
done · **Sessions completed:** 27

---

## One-line status

M7-11 measured M7-9's Gap 1 (honeypot poisoning) end to end: a budget sweep of three poisoning
strategies against the committed detector corpus, and one real pBFT-committed poisoned record
demonstrating that `BC_SigRW`'s immutability makes the poison permanent, not detectable.

- **`detection/poisoning.py`** (new): three pure array transforms on the training draw — label
  flipping (relabel real ransomware rows benign), feature poisoning (inject fake-ransomware rows
  with real benign features), anchor-point injection (inject boundary-midpoint rows labelled
  benign) — same no-op-at-zero-budget convention as `retraining.augment_positive_rows` (M7-8).
- **Finding: the strategies rank opposite to what "sophistication" would predict.** Label
  flipping (called simplest) is the only monotonic, most damaging strategy: 0.8408 → 0.6680 at
  50% budget → exactly 0.5000 at 100% (zero positive training rows left; no classifier fittable
  past "always benign"). Feature poisoning is mild and budget-insensitive. Anchor-point injection
  (called most sophisticated) is *least* damaging at low/medium budget and briefly *improves*
  accuracy, only turning negative at 50%.
- **Permanence, demonstrated once, for real, not simulated:** one poisoned
  `SignatureRecordPayload` (a genuine ransomware trace, `label="benign"`) committed cleanly
  through actual pBFT consensus to a real `BC_SigRW` cluster on the first attempt.
  `blockchain.chain.Chain`'s full public method list has no delete/remove/rollback/revert/
  truncate/undo method — a code-level fact, no new code written. All five of
  `Chain.check_append`'s checks are structural/cryptographic; none inspect payload semantic
  content, and the poisoned record passed every one.
- Post-commit detection (would need cross-node feature-space agreement) and hybrid-anchoring
  interaction (integrity vs. validity — anchoring can't help, poisoning is a validly-approved
  commitment) are both stated as gaps, per OUT OF SCOPE — no defense built, no chain code changed.
- `docs/DEVIATIONS.md` DEV-37. `docs/THREAT_MODEL.md` Gap 1 updated with the measured results
  (was an unmeasured claim from M7-9). `RESULTS.md` "M7-11". Report: new §"Honeypot Data
  Poisoning" after §Threat Model, cross-referenced from the Gap 1 paragraph there.

`make test` (1625 passed: 18 poisoning-primitive + 7 M7-11 end-to-end, new this session) and
`make lint` (ruff + mypy on `src`/`tests`) both green. Report recompiles clean.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | `detection/poisoning.py` added this session |
| `docs/report/report.pdf` | done, current | recompiled (`tectonic`), new §"Honeypot Data Poisoning" |
| `docs/THREAT_MODEL.md` | done | Gap 1 updated with M7-11's measured results |
| `scripts/m7_11_honeypot_poisoning.py` | done | ~6s local run (sweep) + one real pBFT commit, run_id `20260925T193933Z-3d53aee9` |
| Everything else (M7-1 through M7-10's own deliverables) | done | unchanged |

## Current numbers

`RESULTS.md` "M7-11", run `20260925T193933Z-3d53aee9`. Baseline bal_acc 0.8408. Label-flip @50%
0.6680 (Δ-0.1729), @100% 0.5000 exactly. Feature-poison range 0.8261-0.8396 (Δ-0.003 to -0.015).
Anchor-injection range 0.8284-0.8468 (Δ+0.006 to -0.013, only strategy with positive deltas).
Permanence: `committed_cleanly=True`, `chain_height_after=1`, `has_delete_or_rollback_method=False`.

## Next task

None forced — M7 is complete except the one item below, and the core deliverable was done before
M7-6. If continued: async pBFT with modelled network latency is the one remaining
`docs/ROADMAP.md` M7 item.

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
| M7-11's "anchor-point injection improves accuracy at low budget" could be read as "poisoning is safe" rather than "this specific attack is weak at this specific budget range against this specific detector" | undersells that label flipping (the simplest attack) is severely damaging, and that anchor injection does turn negative at 50% | `RESULTS.md`/report/DEV-37 lead with label flipping's monotonic collapse before noting anchor injection's low-budget anomaly, and state the permanence finding (which holds regardless of strategy effectiveness) as the headline result, not the degradation numbers alone |
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
