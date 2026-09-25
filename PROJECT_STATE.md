# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-25 · **Milestone:** M7 stretch — M7-10 (neural detector + EMBER
transfer) fully done · **Sessions completed:** 26

---

## One-line status

M7-10 answered both open questions it set out to: M7-8's memorisation failure mode is not
tree-specific (an MLP shows it earlier and more broadly than RF), and a richer static dataset
(EMBER, 6/22 features mapped vs. ClaMP's 3/22) still transfers at exactly chance on the hard
decision, though its continuous score is no longer anti-correlated with truth the way ClaMP's was.

- **`detection/mlp_model.py`**: a declared-hyperparameter MLP, returned as a single-entry `models`
  mapping so `detection/profiles`, `detector`, `adversarial`, `retraining` all consume it with
  zero code change. Unhardened, the MLP is *more* robust to M7-3's attack than RF (median adaptive
  evasion 0.4866 vs. 0.3213). Every hardened MLP (25/50/100% budget) shows M7-8's bound-
  memorisation signature — RF only showed it at 100% — and the MLP never reproduces RF's
  25%-budget backfire. Measured locally (45s, CLAUDE.md §6's local-ML allowance).
- **`honeypot/ember_mapping.py`**: EMBER's raw PE data (byte histogram, per-section entropy,
  permission flags, import table — verified against `elastic/ember`'s actual source) grounds 6/22
  `FT_RW` features vs. ClaMP's 3/22 (M7-7). Scored on all 200,000 rows of EMBER's labelled test
  split against the identical fitted ensemble: `bal_acc=0.5000` (same as ClaMP), but
  `pr_auc=0.6301` sits above the 0.50 no-skill line where ClaMP's 0.4612 sat below its 0.5225 line
  — richer mapping improves the discarded continuous score without moving the hard decision.
- **Ada infrastructure saga, resolved:** `files.pythonhosted.org` was unusable via normal `pip
  install` for most of the session; a `pip download --no-deps`-only wheelhouse cache (built once,
  reused, no further network calls) got a working venv built. That venv's scikit-learn (1.5.2, one
  minor behind the 1.9.1 reference) produces a 0.0055 sanity-check drift (0.8353 vs. 0.8408),
  accepted and documented (DEV-35) rather than chased further — doesn't change the qualitative
  finding. Full timeline: `sessions/2026-09-25-06-*.md` Findings.
- `docs/DEVIATIONS.md` DEV-35 (EMBER mapping + transfer result), DEV-36 (MLP architecture +
  permutation-importance methodology). `RESULTS.md` "M7-10" (both parts, all numbers measured).
  Report: new §"Neural vs. Tree-Based Detector", extended §"Real Malware Transfer Evaluation"
  with the EMBER table/figures/KS comparison.
- **A concurrent session** (M7-9, formal threat model, commit `8756dab`) landed mid-session;
  reconciled cleanly. Its session file is complete (contrary to what an earlier read of this
  session suggested before `8756dab` landed) — no action needed.

`make test` (1591 passed: 16 EMBER-mapping + 4 MLP-wiring + 4 M7-10b end-to-end, new this
milestone) and `make lint` (ruff + mypy on `src`/`tests`) both green. Report recompiles clean.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | `detection/mlp_model.py`, `honeypot/ember_mapping.py` added this milestone |
| `docs/report/report.pdf` | done, current | recompiled (`tectonic`), new §"Neural vs. Tree-Based Detector" + §m7-7 EMBER extension |
| `docs/THREAT_MODEL.md` | done (M7-9) | unchanged this session |
| `scripts/m7_10b_neural_detector.py` | done | ~45s local run |
| `scripts/m7_10a_ember_transfer.py` | done | ~107s on Ada, run_id `20260925T160711Z-62498d7b` |
| Everything else (M7-1 through M7-9's own deliverables) | done | unchanged |

## Current numbers

`RESULTS.md` "M7-10". Part B (run `20260925T105552Z-00a2132a`): MLP clean bal_acc 0.8237 (vs. RF
0.8408); MLP adaptive-evasion median 0.4866 unhardened, jumps to 1.0000 at every hardened budget
(no RF-style 25% backfire). Part A (run `20260925T160711Z-62498d7b`): EMBER transfer bal_acc
0.5000, precision 0.6667, recall 0.00002, mcc 0.0013, pr_auc 0.6301 (n=200,000); synthetic sanity
check 0.8353 (0.0055 below the 0.8408 reference — sklearn-version drift, DEV-35).

## Next task

None forced — M7 is complete except the one item below, and the core deliverable was done before
M7-6. If continued: async pBFT with modelled network latency is the one remaining
`docs/ROADMAP.md` M7 item.

## Blockers

None. (Ada's `wheelhouse/` cache from this session — `~/bsfr-sh/wheelhouse/` — makes any future
Ada venv rebuild instant/offline if it's still needed; worth knowing about even though nothing is
currently blocked on it.)

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
| M7-7's/M7-10a's bal_acc=0.5000 could be misread as "the framework doesn't work" rather than a schema-grounding finding | undersells the synthetic-corpus result and the framework's design | DEV-34/DEV-35 and the report state explicitly this is a static-vs-dynamic grounding finding, and note the PR-AUC nuance (EMBER's score is informative even though the hard decision isn't) |
| M7-8's 25%-budget "hardening backfires" and M7-10b's "MLP shows it at every budget" could be read as "adversarial retraining/neural nets don't work" | undersells the real robustness gain measured at 50/100% (both models) and the MLP's genuine pre-hardening robustness edge | `RESULTS.md`/report state both effects explicitly, side by side with the budgets that do help |
| Two Claude Code sessions ran on this repo concurrently during M7-10 (M7-9, M7-10); nothing currently prevents this from happening again | a future concurrent session's edits could silently clobber or duplicate content the way `docs/ROADMAP.md` briefly did mid-session | no fix implemented — flagging as a standing risk; re-read a file immediately before writing to it if a long gap (e.g. a slow remote job) occurred since it was first read |

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
