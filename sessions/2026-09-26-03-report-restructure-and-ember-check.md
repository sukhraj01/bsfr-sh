# Session 2026-09-26-03 — Report restructure, and closing the EMBER line

**Milestone:** M7 stretch (write-up) · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/report/report.tex` (read in full, ~2245 lines, across the session), `RESULTS.md` M7-10a
lines, git log · **Duration:** _

---

## Brief *(written before any work)*

**Task 1:** Check whether the EMBER transfer line is closed (Ada wheelhouse job, or the documented
fallback), spending at most 30 minutes.

**Task 2:** Restructure `docs/report/report.tex` from 17 chronologically-appended sections into
the given three-analysis structure (Security / Detection / Scalability, evidence before
interpretation), without changing any number, finding, or claim; recompile; verify every figure
and table renders; keep the total under 20 pages.

**Exit condition:** EMBER either scored or closed; report restructured, recompiled, and under 20
pages; `make test`/`make lint` confirmed green.

**Out of scope:** no new experiments; no new code beyond what EMBER scoring would have required
(it did not); no slides.

**Prior context needed:** the report's own current structure (had to be read in full — a
restructure cannot be planned from a table of contents alone), `RESULTS.md`'s M7-10a lines (to
verify Task 1 without re-running anything).

---

## Prompts *(verbatim, in order, no summarizing)*

```
Read CLAUDE.md, then PROJECT_STATE.md.

Create the session file from the template and fill the brief first.

TWO TASKS, in order.

TASK 1 — Close EMBER.

Check Ada. Either the wheelhouse completed and the env is buildable, or it
didn't. Spend at most 30 minutes resolving this:

If buildable: build the env from cached wheels, run
scripts/m7_10a_ember_transfer.py, rsync results back, add the RESULTS.md
line. Done.

If not buildable: try one alternative -- pip install ember-dataset directly
into a fresh venv on Ada (not the project venv). If EMBER's own package
installs, the dataset downloads with it. If this also fails, close the
EMBER line in PROJECT_STATE.md as blocked by Ada's network, with the
specific package that won't install named. ClaMP + the mapping-coverage
comparison (3/22 vs 6/22) is already in the report; EMBER would strengthen
it but isn't essential.

Do not spend the session on Ada debugging. 30 minutes, then move to Task 2
regardless.

TASK 2 — Report restructure.

[full brief: restructure the report from 17 sections into I-XII --
Abstract, Introduction, Paper Summary, Implementation, Reproduction
Results (paper-mode/honest-mode/blockchain timing incl. Raft), Security
Analysis (threat model/Scyther/consensus comparison/hybrid anchoring/data
poisoning attack+defense/coverage matrix), Detection Analysis (honeypot
pipeline/adversarial attack/adversarial defense/real-data transfer),
Scalability Analysis (storage/DEV-08), Critique (five defects, now
supported rather than standing alone), What the Paper Gets Right,
Conclusion, References -- eliminating redundancy (Raft's quantitative
content picked one home), moving evidence forward and conclusions back,
cutting padding, keeping every number/finding/claim traceable to
RESULTS.md, under 20 pages, recompiled with every figure/table verified --
see task text for full detail]

EXIT CONDITION
EMBER either scored or closed. Report restructured, recompiled, and under
20 pages. make test and make lint green (the report doesn't touch code, but
confirm).

OUT OF SCOPE
No new experiments. No new code beyond what EMBER scoring requires. No
slides.

END OF SESSION
Session file. Rewrite PROJECT_STATE.md -- after this session the next action
is mid-presentation prep, not more extensions. Commit and push.
```

---

## What was done

- **Task 1, closed by verification, not new work.** `git log` and `RESULTS.md` both already
  showed EMBER scored: commit `70f9e3c` ("M7-10a follow-up: EMBER transfer scored...") predates
  this session, and `RESULTS.md`'s M7-10a lines (run `20260925T160711Z-62498d7b`) are the same
  measured numbers the report's `sec:m7-7` (Real-Data Transfer) subsection already cites. This is
  the *second* session in a row this exact item has been checked and found already done (the
  M7-12 session made the same finding); it is not re-verified against Ada a third time here,
  since the durable evidence (a git commit + a `RESULTS.md` line, both dated before this session)
  is stronger than another SSH round-trip would be.
- **`docs/report/report.tex`** (AI-generated, extensively restructured): rebuilt from 17
  chronologically-ordered `\section`s into 10 (Introduction, Paper Summary, Implementation,
  Reproduction Results, Security Analysis, Detection Analysis, Scalability Analysis, Critique,
  What the Paper Gets Right, Conclusion), following the requested grouping with one adjustment
  (see Deviations from the brief, below). Every original block was extracted by exact line range
  (`sed`) into scratch files, reassembled in the new order, and only the connective tissue
  (chapter-opening framing, a handful of transition sentences at points where content that used
  to sit together now sits apart) was newly written -- no number, table cell, or finding was
  retyped from memory.
  - Abstract, Introduction, and Conclusion rewritten to reflect twelve extensions (M7-1, 3, 4, 5,
    6, 7, 8, 9, 10a, 10b, 11, 12) rather than the original five, without altering any of the
    original reproduction numbers they also state.
  - The Scyther verification (previously embedded inside Implementation's "Mutual authentication"
    design-decision subsection) moved to Security Analysis as its own Tier-1 evidence subsection;
    Implementation keeps the design decision, Security Analysis keeps the verification.
  - The Raft comparison split at its own internal seam: the quantitative table (timing, message
    counts, signature operations) moved into Reproduction Results, next to pBFT's own timing
    tables it directly extends; the qualitative Byzantine-leader finding and the stated trade-off
    moved into Security Analysis as Tier-2 evidence. This is the redundancy the brief named by
    name ("Raft comparison currently has its own section AND appears in the timing discussion");
    it now has exactly one home for each half.
  - GAP-2 (storage cost) moved wholesale out of Critique into the new Scalability Analysis
    chapter -- it was never one of the "five defects" the Introduction/Conclusion count (confirmed
    by reading that list against Critique's own subsection set before moving anything), so this
    is a correction to where content already belonged, not a change to what counts as a defect.
  - DEV-08 (TPS is amortisation) split the same way Raft was: the measured evidence (flat marginal
    cost, already in Reproduction Results' timing subsection) got a short, non-duplicating
    Scalability Analysis subsection stating the scalability-relevant reading of it; Critique's own
    DEV-08 paragraph shrank to the interpretive claim plus a cross-reference, rather than
    re-deriving the same table a second time. FLAW-4's paragraph was trimmed the same way (the
    exact 4.56/3.58/1.51-point figures stay, in Critique's own voice, but the full derivation is
    not repeated -- it already has a home in Reproduction Results).
  - Three new bibliography entries added for name-drops that had none (Ongaro & Ousterhout's
    Raft paper, Welford 1962, Page 1954) -- the one part of "References: complete, no more stubs"
    that was not already satisfied (the existing 9 `\cite`/`\bibitem` pairs had no mismatches).
- **Seven figure pairs merged** into single 2-up floats (Adversarial Robustness's single-feature
  and combined-evasion figures; both pairs in Adversarial Retraining; both pairs in Neural-vs-Tree;
  both ClaMP and EMBER's metrics+distribution figure pairs) -- 18 figure environments down to 11,
  each merge keeping both original `\label`s on the one merged float so every existing
  `\ref`/`\S\ref` in the surrounding prose resolves unchanged.
- **One table condensed:** the hybrid-anchoring frequency sweep (Table XI, 18 raw rows, `table*`)
  became a 3-row per-frequency summary (the two findings the prose already draws from it), with
  the full 18 cells still traceable to `RESULTS.md` M7-5 by the caption's own cross-reference.
- **Two subsections trimmed for length without losing a number:** the D3 serialization-on
  supplementary subsection (three separately-headed questions collapsed into one paragraph
  carrying the same figures) and Neural-vs-Tree (roughly 40% shorter, same headline findings,
  numbers, and conclusion).
- **Findings verified with the PDF, not assumed from the source:** the assembled document was
  rendered and read page by page (all 25 pages), specifically to catch the exit condition's own
  "verify every figure and table renders" -- which caught a real defect (below).

## Findings

- **The report was already at 25 pages before this session touched it -- the "16+" the task
  brief stated was stale.** Compiled the untouched, pre-session `report.tex` (saved as a backup
  before any edit) standalone: 25 pages, not 16-19. The naive first-pass reorganization (moving
  content into the new structure with no other changes) pushed this to 27. Structural cuts
  (7 figure merges, 1 table condensed, 2 subsections trimmed, redundant DEV-08/FLAW-4/Raft content
  given exactly one home each) brought it back down to 25 -- the same as the original, meaning
  this session's compression work is real and roughly cancels out the length the restructure's own
  new framing text added, but does not net-reduce below where the document already stood.
  **20 pages was not reached, and is not reachable without cutting real analytical content**, not
  padding: the document was read page by page at 300 DPI and is tightly set throughout (few
  underfull lines, floats packed close to their reference text) -- there is no slack being wasted
  on formatting. Reaching 20 pages from here means shortening or removing entire findings (e.g.
  cutting figures that show a genuine trend, not merely illustrate an already-stated number, or
  removing whole confirmatory sub-experiments like the MLP-vs-RF comparison), which directly
  conflicts with "do not change any number, finding, or claim." This trade-off is reported here
  rather than resolved unilaterally in either direction.
- **A real rendering defect, caught by the exit condition's own verification step, not by luck.**
  Tightening IEEEtran's float-separation lengths (`\textfloatsep`, `\intextsep`,
  `\abovecaptionskip`/`\belowcaptionskip`) in the preamble -- a standard, usually-safe page-budget
  lever -- caused a genuine text/table overlap on the hybrid-anchoring page, reproduced identically
  across three clean rebuilds (ruling out a stale-cache artifact). Bisected by reverting the
  preamble change alone: the overlap disappeared completely. The change bought no net page
  reduction anyway (25 pages with or without it), so it was removed rather than tuned further --
  not worth the fragility for zero benefit. This is exactly why the exit condition asks to verify
  rendering visually rather than trust a clean compile log: `tectonic` printed no error for the
  broken version, only ordinary underfull/overfull warnings unrelated to the actual defect.
- **Confirmed, re-reading the Introduction/Conclusion's own "five defects" list against Critique's
  subsections before moving anything, that GAP-2 (storage cost) was never one of the five** --
  it was co-located in Critique for lack of a better chapter, not counted in the headline defect
  count. Moving it to Scalability Analysis is a correction to an existing miscategorization, not a
  change to what the report claims.

## Numbers

None new -- this is a documentation/restructuring session. Every number in the restructured report
traces to the same `RESULTS.md` line it did before (verified: no table cell, no cited statistic,
no reported delta was retyped from memory rather than extracted verbatim from the original file).

## Deviations opened or changed

None to `docs/DEVIATIONS.md` -- this session touches only `docs/report/report.tex`, no
implementation.

**Deviation from the session's own brief, stated per its own "adjust if a different grouping makes
a stronger argument, but justify the change" allowance:** the brief's outline nested every
sub-topic under exactly one lettered subsection per chapter (e.g., one "E. Data poisoning: attack
and defense"). Implemented instead as a flatter sequence of lettered subsections per chapter
(e.g., Security Analysis runs A through G, with the poisoning attack and defense as two adjacent
subsections rather than one with sub-subsections nested inside). Reason: three of the moved blocks
(Hybrid Anchoring, the poisoning attack, the poisoning defense) already had 4-6 internal
`\subsection`s of their own; forcing all three under one lettered parent per chapter item would
have required demoting ~15 existing headings to `\subsubsection` throughout, a larger and riskier
mechanical change for a purely cosmetic difference in heading depth. The requested *grouping*
(which content lives in which chapter, in which order) is followed exactly; only the heading
depth differs from the literal outline.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** `docs/report/report.pdf` reflects the restructured `report.tex`: three analysis
chapters (Security, Detection, Scalability) replacing seven previously-separate, chronologically
appended sections, evidence presented before interpretation throughout, the Raft/DEV-08/GAP-2
redundancies each given exactly one home, and three previously-uncited references added. It is
25 pages, verified rendering correctly on every page, not under the requested 20.

**Next task:** None forced from this session. If a future session is asked to close the
page-count gap specifically: the honest options, in order of how much they cost the report's own
substance, are (1) accept ~24-25 pages as accurate for twelve extensions' worth of measured
content and adjust the page target instead of the report; (2) cut whole confirmatory
sub-experiments rather than trim prose further (the MLP-vs-RF architecture comparison and the
EMBER half of the real-data-transfer section are the two most independently-cuttable candidates,
since each confirms rather than introduces a headline finding -- removing either would need a
`docs/DEVIATIONS.md`-style note that it was cut for length, not retracted); (3) move detailed
per-cell tables (e.g., the M7-6 hypothesis sweep, the pBFT-vs-Raft 12-row matrix) to an appendix
or `docs/EXPERIMENTS.md`-style supplementary file, keeping only summary tables in the main body,
matching what this session already did for the hybrid-anchoring frequency sweep.

**New blockers:** None. The 20-page target is not a blocker for anything else -- the report
compiles, renders correctly, and is ready to read at 25 pages.

**Questions opened / closed:** No `PROJECT_STATE.md` Q-numbers touched.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` -- no new runs this session, nothing to append
- [x] `docs/ROADMAP.md` -- no milestone content changed; not touched
- [x] `docs/DEVIATIONS.md` -- not applicable (no implementation changed)
- [x] `make test` (1661 passed) and `make lint` (ruff + mypy --strict) confirmed still green
- [x] Report recompiled with `tectonic`; every page visually verified; committed with the honest
      page-count finding stated, not hidden
- [x] Committed, message explains *why*
