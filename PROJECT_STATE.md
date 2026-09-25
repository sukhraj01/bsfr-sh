# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-25 · **Milestone:** M7 stretch — six of seven items done; report
compiled and current · **Sessions completed:** 23

---

## One-line status

This session (M7-7) evaluated (never retrained) the honeypot detection ensemble on real malware
data mapped onto `FT_RW`'s schema, to test whether M4b's 0.8422 synthetic-corpus figure transfers
to behaviour the generator never anticipated.

- **Dataset decision, recorded before implementation:** EMBER (feature dataset ~2.4GB, projected
  ~17h download at this sandbox's measured ~40.6KB/s — infeasible) and CIC-MalMem-2022/
  CICMalDroid-2020 (gated behind a research-access request, not scriptable) were both checked and
  ruled out. Used **ClaMP** instead (github.com/urwithajit9/ClaMP — 5210 real PE files' static
  header features, 2722 malicious/2488 benign, openly published for ML research), fetched once and
  committed at `data/external/clamp/` (1.28MB, sha256 in its README) for full reproducibility.
  Evaluation-only, per the session's own constraint — never used to fit or tune anything.
- **`honeypot/external_mapping.py`** (new): the `FT_RW` <- ClaMP mapping table. Only the entropy
  group (3/22 features) has any real analogue — ClaMP is purely static (no execution observed), so
  the other 19 features (filesystem, crypto API, process, network, persistence, kill-chain) are
  execution-time observables with no static analogue and are marked missing (handled exactly like
  `honeypot.features.build()`'s existing unobserved-sensor convention: value 0.0, mask bit set).
- **`honeypot/distribution_compare.py`** (new): two-sample KS test wrapper, used on the 3 mapped
  features (the other 19 are a mapping constant, not a distributional claim).
- **`scripts/m7_7_real_malware_transfer.py`** (new): fits the ensemble once on the committed
  synthetic corpus, first reproduces M7-3's established CSV-path baseline exactly (0.8408) as a
  sanity check, then scores it on all 5210 mapped ClaMP rows.
- **The finding: a clean failure, not a partial degradation, and mildly worse than chance.**
  `bal_acc=0.5000` exactly — the ensemble predicts every real row as benign. `pr_auc=0.4612` is
  *below* this dataset's no-skill baseline (prevalence 0.5225): the continuous score is mildly
  anti-correlated with the true label. Mechanism: with 86% of the feature space zeroed under the
  mapping, there is essentially nothing left for the fitted profiles to discriminate on. Read as a
  finding about `FT_RW`'s dynamic-vs-static schema mismatch with the most tractable real dataset
  available, not a refutation of the synthetic generator's own 0.85 Bayes-ceiling calibration
  (DEV-27) — no static dataset could ground the other six feature groups regardless.
- `docs/DEVIATIONS.md` DEV-34 (new), `RESULTS.md` "M7-7", report §"Real Malware Transfer
  Evaluation" (after §Adversarial Robustness), two new figures (`fig8a`/`fig8b`), `docs/
  ROADMAP.md` M7-7 ticked. `pyproject.toml` gained `scipy` as a direct dependency (was already
  transitive via scikit-learn; now imported directly for `ks_2samp`).

`make test` (1503 tests) and `make lint` (ruff + mypy) both green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | `honeypot/external_mapping.py`, `honeypot/distribution_compare.py` added this session (M7-7) |
| `docs/report/report.pdf` | done, current | 17 pages; recompiled this session, new §"Real Malware Transfer Evaluation" |
| `verification/` | done (M7-1) | unchanged |
| `docs/STORAGE_ANALYSIS.md` | done (M7-2) | unchanged |
| `scripts/run_adversarial_robustness.py` | done (M7-3) | unchanged |
| `scripts/run_consensus_comparison.py` | done (M7-4) | unchanged |
| `scripts/run_hybrid_benchmark.py` | done (M7-5) | unchanged |
| `scripts/m7_6_gap_closure.py` | done (M7-6) | unchanged |
| `scripts/m7_7_real_malware_transfer.py` | done (M7-7) | new this session — evaluation-only, ~2s local run |

## Current numbers

New this session: `RESULTS.md` "M7-7 — real malware transfer evaluation" section, run
`20260925T041117Z-672f7572`. Transfer result: bal_acc=0.5000, prec=0.0000, rec=0.0000, mcc=0.0000,
pr_auc=0.4612 on 5210 real ClaMP rows (synthetic CSV-path sanity check reproduced 0.8408 exactly
first). Everything else unchanged since the last session.

## Next task

None forced — M7 is optional stretch work and the core deliverable was complete before M7-6/M7-7.
If continued: async pBFT with modelled network latency is the one remaining `docs/ROADMAP.md`
M7 item.

## Blockers

None.

`data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length sufficient (now 15 pages), or should it be trimmed? | report sign-off | reviewer judgement |

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
| 3 of 18 M7-5 benchmark cells show 6-12% anchor overhead against a ±1.4% baseline for the rest | a reader might read this as a real per-anchor cost | stated plainly as scheduling jitter (anchor step is sub-millisecond, runs no consensus) in both `RESULTS.md` and the report, not filtered or re-run until clean |
| M7-7's bal_acc=0.5000 could be misread as "the framework doesn't work" rather than "19/22 features have no static analogue" | undersells the synthetic-corpus result (0.8422) and the framework's actual design | DEV-34 and the report state explicitly that this is a schema dynamic-vs-static grounding finding, not a generator-calibration failure, before giving the number |

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
| `CLAUDE.md` | how to work here | near-stable |

If a fact could go in two of these, it goes in exactly one — the leftmost row that fits.
