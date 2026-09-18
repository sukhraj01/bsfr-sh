# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-18 · **Milestone:** Write-up (post-M6) · **Sessions completed:** 13

---

## One-line status

The course report is written and compiles: `docs/report/report.tex` -> `docs/report/report.pdf`
(IEEEtran, two-column, via `tectonic`; 9 pages, ~5.8K words of prose plus 7 tables and 5
reproduced figures). Every number in it traces to `RESULTS.md` or `docs/DEVIATIONS.md`; nothing
was regenerated. Structure follows the assigned brief exactly: abstract, intro, paper summary,
implementation (organized by six design gaps: hybrid encryption DEV-01, session protocol DEV-02,
honeypot pipeline DEV-03/26/27 with its own subsection, backup index DEV-05, Case-3 DEV-09),
reproduction results (paper-mode / honest-mode / blockchain timing, always side by side), critique
(FLAW-2, FLAW-4, FLAW-5, DEV-26, DEV-08, plus an acknowledgment paragraph), honeypot detection
evaluation, conclusion, references. `make test` (1321 passed) and `make lint` (ruff + mypy clean)
reconfirmed green this session — the report touches no source. M0–M6 remain fully closed from the
prior session; nothing about the implementation changed.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | M0–M6, unchanged this session |
| `docs/report/report.tex` + `.pdf` | done | this session; IEEEtran two-column via `tectonic`, 9 pages |
| `docs/report/figs/` | done | 6 PNGs copied from `results/figures/` (fig4/5 baseline variants, fig6a-d) |

## Current numbers

No new runs this session — the report cites existing `RESULTS.md`/`results/tables/*.csv` numbers
only, per the task's explicit "pull from results/, do not regenerate." See `RESULTS.md` for every
figure the report uses; nothing here has changed since the M6b session.

## Next task

**Review and polish the report, not new implementation or experiments.** Candidates, roughly in
order of value:

1. Visual proof-read of `docs/report/report.pdf` page-by-page (table/figure placement, no text
   overflow) — this session confirmed clean LaTeX compilation and reviewed the source, but did
   not get a rendered visual check; `pdftoppm` (poppler) was mid-install in the background when
   the session ended and may now be available (`which pdftoppm`) for `Read` on the PDF.
2. Fill in the author/course placeholder in `docs/report/report.tex`'s `\author{}` block — left
   generic ("Course Project Report") deliberately, since this project's own files carry no
   student name or course number to draw from.
3. A second read for tone against the "analytical, not adversarial" instruction, and for any
   remaining reference to internal process (file paths, `docs/*.md` names) that should not be in
   a document meant for an examiner — this session removed the ones found (a `CLAUDE.md`
   citation and a `RESULTS.md` citation in the draft), but a fresh read is cheaper than certainty.
4. Optional: tighten toward the 10-12-page target if the reviewer judges 9 pages under-filled;
   the brief treats 10-12 pages / 6000-8000 words as roughly equivalent and this report sits at
   the lower edge of both (9 pages, ~5.8K words) without any section reading as thin.

## Blockers

None. `data/raw/` is gitignored; a fresh clone needs `make data` (~56 minutes here) before any
BitcoinHeist run — unchanged, not touched this session.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is 9 pages / ~5.8K words sufficient, or does the report need expansion toward 10-12 pages? | report sign-off | reviewer judgement, next session |
| Q4 | Do we need real feature-space evasion for M7? | M7 | decide at M7 kickoff, if M7 is picked up after the report |
| Q8 | Does anything before M7 need pBFT state transfer (DEV-20 item 2)? | M7 | only if M7 benchmarks a lossy network |

## For the write-up

Resolved — this section's prior contents (the pBFT threshold note, the FLAW-2 framing, the
FLAW-4/Q10 numbers, Alg. 4's two silent gaps) are now written into `docs/report/report.tex`
directly (\S6.1–6.5, \S4) rather than staged here. Nothing queued for a future write-up remains;
the write-up happened.

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D2 | `make lint` covers `src` and `tests` but not `scripts/`, and `mypy` only covers `src`. | low priority; not cited as a report claim |
| D3 | The bus never serialises; magnitude quantified (DEV-30) but the omission itself is unfixed. | M7, if async pBFT lands |
| D4 | `ClientRequest` is unauthenticated (DEV-20 item 5). | when a claim needs it |
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10 (seen again in this session's `make test` warnings). | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Report visual layout unverified (no rendered check this session) | a table/figure could overflow a page margin despite clean LaTeX compilation | `tectonic` reported zero errors and only cosmetic hbox warnings; next session should still eyeball the PDF once poppler is available |
| The non-reproduction is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number in the report; Q10 tested and ruled out address/split leakage; report states the gap as measured-but-unexplained, not apologized for |
| `data/raw/` is gitignored and slow to fetch | a fresh machine cannot rerun M4a quickly | `make data` verifies counts; README + `provenance.json` state the wait and the sha256 |

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
