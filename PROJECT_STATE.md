# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-22 · **Milestone:** results reconfirmed under D3's honest condition; report recompile still blocked · **Sessions completed:** 18

---

## One-line status

This session re-verified every timing/detection number the report presents, now that D3 (prior
session) showed consensus serialization adds real cost the original M6a numbers never paid.

- **Re-ran the full M6a bench matrix with `configs/bench.yaml`'s `serialize_messages: true`**
  (already the current default since D3 closed — no code change needed, just a run). Marginal
  per-block cost stays flat (DEV-08 survives), confirming the amortisation-shape claim holds
  regardless of serialization. **The BC_SigRW/BC_DTBU gap narrows from 35-45% (serialization off)
  to ~25-27% (serialization on)** — a real, explained finding (both chains pay a near-identical
  absolute serialization tax, which dilutes but doesn't reverse the structural ECDSA/encoding
  attribution), not noise. `RESULTS.md` new section, `docs/DEVIATIONS.md` DEV-08/DEV-30 amended,
  `docs/EXPERIMENTS.md` Targets 3-4 updated.
- **Re-ran M4a (`make repro`, `make honest`) and M4b (`run_phase3_detection.py`) at their
  published seeds — all byte-reproducible**, exactly matching existing `RESULTS.md` lines. One
  near-miss caught and fixed: `make honest` overwrote `results/tables/table2_honest_mode.csv`'s
  canonical Ada full-scale KNN row with the local-subsampled numbers; caught via `git status`
  immediately and reverted with `git checkout --` before committing anything.
- **`docs/report/report.tex` updated** (D3 footnote on both timing tables + new "Supplementary:
  timing under honest, serialization-on conditions" subsection with its own table), **but not
  recompiled** — `brew install --cask basictex` was retried (the task's suggested first move) and
  got further than last session (cask resolved, download started) but stalled at ~55/110 MB on a
  slow CTAN mirror at the ~23-minute mark and was stopped there, per the task's own 20-minute
  installation cap. `report.pdf` is now stale across **two** sessions (missing both M7-3's
  adversarial-robustness section and this session's supplementary material).

`make test` (1348 passed) and `make lint` (ruff + mypy) both green — no `src/`/`tests/` changes
this session.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | unchanged this session |
| `docs/report/report.tex` | done, **needs recompile (2 sessions stale)** | M7-3's section + this session's D3 supplement both added, neither ever rendered |
| `verification/` | done (M7-1) | unchanged |
| `docs/STORAGE_ANALYSIS.md` | done (M7-2) | unchanged |
| `scripts/run_adversarial_robustness.py` | done (M7-3) | unchanged |
| Results reconfirmation (bench + detection, honest/serialization-on condition) | done | this session — see One-line status |

## Current numbers

New this session: `RESULTS.md` "Bench reconfirmation — serialization ON" section (six
`bench/target3-time-serialized` lines, run `20260922T172916Z-22992372`) and the "M4a/M4b —
reconfirmed byte-reproducible" pointer block. Everything else unchanged since M7-3.

## Next task

**Get a working LaTeX toolchain and compile `docs/report/report.pdf`.** This is now the clear,
singular next action — nothing else is blocked on anything else. Specifics for whoever picks this
up: `brew install --cask basictex` is the right cask (small, ~100-110 MB, not full `mactex`'s
~4 GB) but the default CTAN mirror this environment resolved to
(`mirrors.in3.sahilister.net`) was too slow twice now, once here at ~23 minutes/55 MB. Try a
different network, a pinned faster mirror, or a pre-existing install. After installing:
`cd docs/report && pdflatex report.tex` twice (cross-references), then check every table/figure
renders — specifically the M7-3 figures and this session's new supplementary subsection — before
committing `report.pdf`.

**After that**, one optional M7 stretch item remains (`docs/ROADMAP.md` M7, not required for the
deliverable): hybrid blockchain, the paper's own listed future work.

## Blockers

**No LaTeX toolchain in this environment, twice confirmed.** See Next task above for the specific
retry information (cask, mirror, time-to-stall). `docker`/`pdflatex`/`xelatex`/`latexmk` all
absent from `PATH`.

`data/raw/` is present in this environment already (used this session for `make repro`/`make
honest`); a genuinely fresh clone still needs `make data` (~56 minutes) first.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length sufficient, or expand toward 10-12 pages? | report sign-off | reviewer judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 tested and ruled out address/split leakage; report states the gap as measured-but-unexplained |
| `docs/report/report.pdf` is stale relative to `report.tex` (2 sessions now) | a reader of the PDF misses §Adversarial Robustness and the D3 supplement | this file states it plainly every session until compiled; do not treat `report.pdf` as current |
| `make honest` (local) overwrites `table2_honest_mode.csv`'s canonical Ada full-scale KNN row with locally-subsampled numbers | a careless re-run silently downgrades the honest_mode table | now documented here; anyone running `make honest` locally must `git diff` that file afterward and revert if it changed, or regenerate the Ada row |
| Scyther binary not committed (third-party, single-platform) | a fresh clone can't re-run the verification without a manual download | exact release URL + sha256 in `verification/README.md`; the raw output is committed, so the claims don't depend on re-running it |
| The BC_SigRW/BC_DTBU timing gap is condition-dependent (35-45% off, ~25-27% on) | a reader citing "the gap" without saying which condition is wrong half the time | both figures now in `RESULTS.md`/`docs/EXPERIMENTS.md`/the report supplement, each labelled with its condition |

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
