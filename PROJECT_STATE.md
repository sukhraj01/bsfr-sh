# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-25 · **Milestone:** M7 stretch — M7-10b (neural detector) done;
M7-10a (EMBER transfer) mapped and data-ready, scoring run outstanding · **Sessions completed:** 26

---

## One-line status

This session (M7-10) answered M7-8's open question (is the adversarial-retraining memorisation
failure mode tree-specific?) with a clean "no" — an MLP shows it earlier and more broadly than
RF — and mapped EMBER onto `FT_RW` at double ClaMP's coverage (6/22 vs. 3/22), but could not
finish EMBER's own scoring run: Ada's network to `files.pythonhosted.org` was unusable for most
of the session.

- **`detection/mlp_model.py`** (new): a declared-hyperparameter MLP, returned as a single-entry
  `models` mapping so `detection/profiles`, `detector`, `adversarial`, `retraining` all consume it
  with zero code change. **Finding:** unhardened, the MLP is *more* robust to M7-3's attack than
  RF (median adaptive evasion 0.4866 vs. 0.3213). But every hardened MLP (25/50/100% budget)
  shows M7-8's bound-memorisation signature (combined-degradation curve *rising* with
  perturbation) — RF only showed this at 100%. The MLP never reproduces RF's 25%-budget backfire.
  Conclusion: the failure mode is in the feature space/augmentation strategy, not tree ensembles.
- **`honeypot/ember_mapping.py`** (new): EMBER's raw PE data (byte histogram, per-section entropy,
  section permission flags, import table — verified against `elastic/ember`'s actual source, not
  assumed) grounds 6/22 `FT_RW` features vs. ClaMP's 3/22 (M7-7). EMBER downloaded and
  sha256-verified on Ada (`data/external/ember/test_features.jsonl`, 200,000 rows). **The scoring
  run itself did not complete** — see Blockers.
- Part B measured on this project's own dev machine (45s, CLAUDE.md §6's local-ML allowance), not
  Ada — see session file Findings for why.
- `docs/DEVIATIONS.md` DEV-35 (EMBER mapping), DEV-36 (MLP architecture + permutation-importance
  methodology). `RESULTS.md` "M7-10". Report: new §"Neural vs. Tree-Based Detector", extension to
  §"Real Malware Transfer Evaluation" noting EMBER's mapping/coverage without transfer numbers.
- **A concurrent session** (M7-9, formal threat model) committed to this repo mid-session
  (`8756dab`) — reconciled cleanly (one duplicate `docs/ROADMAP.md` bullet caught and removed).
  Its own session file was never completed (`sessions/2026-09-25-05-*.md` is still the empty
  template) — not this session's scope to fix, flagged here so it isn't lost.

`make test` (1591 passed, 44 new: 16 EMBER-mapping + 4 MLP-wiring + 4 M7-10b end-to-end, plus
whatever M7-9 or other concurrent sessions added) and `make lint` (ruff + mypy on `src`/`tests`,
the only paths either target checks) both green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | `detection/mlp_model.py`, `honeypot/ember_mapping.py` added this session |
| `docs/report/report.pdf` | done, current | recompiled this session (`tectonic`), new §"Neural vs. Tree-Based Detector" + §m7-7 extension |
| `docs/THREAT_MODEL.md` | done (M7-9, concurrent commit `8756dab`) | unchanged this session |
| `scripts/m7_10b_neural_detector.py` | done (M7-10b) | new this session, ~45s local run |
| `scripts/m7_10a_ember_transfer.py` | **written, untested against real data** | mapping it calls is unit-tested; the script itself needs a working Python env on Ada (or the extracted EMBER file transferred elsewhere) to actually run |
| Everything else (M7-1 through M7-9's own deliverables) | done | unchanged this session |

## Current numbers

New this session: `RESULTS.md` "M7-10", run_id `20260925T105552Z-00a2132a`. MLP clean bal_acc
0.8237 (vs. RF 0.8408); MLP adaptive-evasion median 0.4866 unhardened, jumps to 1.0000 at every
hardened budget (no RF-style 25% backfire). EMBER: 6/22 features mapped (coverage measured); no
transfer bal_acc/precision/recall/MCC/PR-AUC/KS numbers (not measured this session).

## Next task

**Finish M7-10a.** `data/external/ember/test_features.jsonl` already exists on Ada
(`~/bsfr-sh/data/external/ember/`, sha256-verified, 200,000 rows) and `scripts/
m7_10a_ember_transfer.py` is written and ready. What's missing is a working Python env: build
`~/bsfr-sh/.venv` on Ada (retry `ada_setup_venv3.sbatch`/similar, or check
`~/bsfr-sh/wheelhouse/` for a partially-downloaded set of wheels from this session's last attempt
and `pip install --no-index --find-links wheelhouse ...` from those) and run the script — under a
minute once the env exists. If Ada's network is still bad, an alternative is transferring just
`test_features.jsonl` (1.87GB) somewhere with a working `numpy`/`sklearn`/`pandas`/`scipy`/
`matplotlib` already installed (this project's own `.venv` qualifies) and running the script there
with `EMBER_TEST_JSONL` pointed at the transferred file.

Otherwise: async pBFT with modelled network latency is the one remaining optional
`docs/ROADMAP.md` M7 item. Not forced — M7 is stretch work.

## Blockers

**M7-10a's scoring run is blocked on Ada's outbound network to `files.pythonhosted.org`**, which
was severely degraded for this entire session (small files: fine, 40-480kB/s; any wheel over
~10MB: hung indefinitely across 5 attempts on 3 compute nodes). Not a code blocker — `scripts/
m7_10a_ember_transfer.py` and its mapping are both ready and tested. A `pip download`-only
workaround (no `install`, no dependency-resolution round-trips) succeeded on `numpy` after ~5
failed `install` attempts; whether that generalises to the rest of the stack was not confirmed by
session end (see `sessions/2026-09-25-06-*.md` Findings for the full timeline and
`~/bsfr-sh/wheelhouse/` on Ada for whatever it managed to fetch).

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
| M7-7's bal_acc=0.5000 / M7-10a's unmeasured transfer could both be misread as "the framework doesn't work" rather than schema-grounding findings | undersells the synthetic-corpus result and the framework's design | DEV-34/DEV-35 and the report state explicitly this is a static-vs-dynamic grounding finding, and for M7-10a specifically, that the transfer number is *unmeasured*, not zero or bad |
| M7-8's 25%-budget "hardening backfires" and M7-10b's "MLP shows it at every budget" could be read as "adversarial retraining/neural nets don't work" | undersells the real robustness gain measured at 50/100% (both models) and the MLP's genuine pre-hardening robustness edge | `RESULTS.md`/report state both effects explicitly, side by side with the budgets that do help |
| Two Claude Code sessions ran on this repo concurrently this session (M7-9, M7-10); nothing currently prevents this from happening again and landing an unreconciled conflict | a future concurrent session's edits could silently clobber or duplicate content the way this session's `docs/ROADMAP.md` draft briefly did | no fix implemented — flagging here as a standing risk; each session should re-read a file immediately before writing to it if a long gap (e.g. a slow remote job) occurred since it was first read |

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
