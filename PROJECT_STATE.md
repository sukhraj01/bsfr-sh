# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-22 · **Milestone:** M7 stretch items (3 of 4 done) · **Sessions completed:** 17

---

## One-line status

This session (M7-3) measured the honeypot detector's adversarial robustness: how far an attacker
can perturb the top-5 Random-Forest-important features (within physically plausible, generator-
grounded bounds) before balanced accuracy collapses to the 0.50 constant-positive baseline.

- **No single top-5 feature, and no combination of exactly these five, collapses the detector.**
  Single-feature perturbation at 100% costs at most 9 points (0.841→0.752, `write_entropy_var`);
  combined perturbation of all five drops to a floor of ~0.57-0.60 and never reaches 0.50, because
  the top-5 features carry only 45.5% of Random Forest's importance mass — the ensemble's real
  reliance on the other 17 features holds it up.
- **A per-sample adaptive adversary does much better and unevenly so:** median minimum
  perturbation to flip a positive sample is 32% of the evasion range; 25.2% of malicious eval rows
  (including 17.3% already-false-negative at 0% perturbation) are evadable with ≤5%; the hardest
  10% need ≥97.7%. 28/353 (7.9%) never flip — confirmed to rely on features ranked 6th-10th
  (`c2_beacon_count`, `entropy_delta`, etc.), never perturbed.
- **Found and traced, not absorbed, a real precision discrepancy**: the committed CSV corpus
  (`data/honeypot/corpus_*.csv`, 6-significant-figure formatting) and the chain-reconstructed path
  (`RESULTS.md` M4b, full float64) give 0.8408 vs. 0.8422 balanced accuracy for the *same*
  seed/config — a 0.0014 gap from CSV rounding, not a bug. `docs/DEVIATIONS.md` DEV-27 amended;
  this session's own baseline is 0.8408 throughout, stated explicitly everywhere it's used.
- New `scripts/run_adversarial_robustness.py`, three figures (`results/figures/fig7{a,b,c}_*.png`
  + sidecars), new `docs/report/report.tex` §Adversarial Robustness (after §VI, before
  §Conclusion). **Not recompiled to PDF** — no LaTeX toolchain in this session's environment (see
  Blockers). `RESULTS.md` §M7-3; full narrative in
  `sessions/2026-09-22-01-m7-3-adversarial-robustness.md`.

`make test` (1348 passed, no `src/`/`tests/` changes this session) and `make lint` (ruff + mypy on
`src`/`tests`, out of scope for this session's `scripts/`-only code) both green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | unchanged this session |
| `docs/report/report.tex` | done, **needs recompile** | this session added §Adversarial Robustness; `report.pdf` is stale |
| `verification/` | done (M7-1) | unchanged |
| `docs/STORAGE_ANALYSIS.md` | done (M7-2) | unchanged |
| `scripts/run_adversarial_robustness.py` | done (M7-3) | self-contained, mirrors `run_phase3_detection.py`'s precedent (logic in `scripts/`, not `src/`) |

## Current numbers

New this session: `RESULTS.md` §M7-3 (feature importances, single/combined/adaptive evasion
thresholds — see One-line status above for the headline figures). Everything else unchanged since
M6b/M7-2/debt-clearance.

## Next task

**One M7 stretch item remains, and it is optional** (`docs/ROADMAP.md` M7 — not required for the
deliverable, which was already complete before M7):

1. Hybrid blockchain, which the paper lists as its own future work.

Async pBFT with realistic network latency was dropped from the M7 list in the prior session (no
longer has a debt-closure reason now that D3 is closed on its own merits).

**If nobody picks up the hybrid-blockchain item next**, the highest-value next action is simply:
**compile `docs/report/report.pdf`** from the current `report.tex` (see Blockers) and proofread
the new §Adversarial Robustness section under real compilation — its LaTeX was only checked for
balanced braces/environments programmatically, never rendered.

## Blockers

**No LaTeX toolchain (`pdflatex`/`xelatex`/`latexmk`) is available in this session's sandboxed
environment** — checked directly, none on `PATH`, no TeX distribution found under common install
locations. `docs/report/report.tex` was edited but not recompiled; `report.pdf` on disk predates
this session's new section. A prior session's `PROJECT_STATE.md` claimed the report "recompiles,"
which may have been true in a different environment (e.g. a cloud agent) but could not be
re-verified here. Whoever next has a working LaTeX install should compile and proofread the new
section before treating it as final.

`data/raw/` is gitignored; a fresh clone needs `make data` (~56 minutes here) before any
BitcoinHeist run — unchanged, not touched this session.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length sufficient, or expand toward 10-12 pages? | report sign-off | reviewer judgement |

Q4 ("do we need real feature-space evasion for M7?") is **closed** this session — yes, and it was
run; see One-line status.

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 tested and ruled out address/split leakage; report states the gap as measured-but-unexplained |
| `data/raw/` is gitignored and slow to fetch | a fresh machine cannot rerun M4a quickly | `make data` verifies counts; README + `provenance.json` state the wait and the sha256 |
| Scyther binary not committed (third-party, single-platform) | a fresh clone can't re-run the verification without a manual download | exact release URL + sha256 in `verification/README.md`; the raw output is committed, so the claims don't depend on re-running it |
| `docs/report/report.pdf` is stale relative to `report.tex` | a reader of the PDF misses §Adversarial Robustness | this file states it plainly; next session with LaTeX should recompile before anything else touches the report |

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
