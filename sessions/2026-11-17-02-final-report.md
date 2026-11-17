# Session 2026-11-17-02 — End-to-end final report (ACL format)

**Milestone:** Project Phase 2 (write-up) · **Files read at start:** `PROJECT_STATE.md`,
`docs/report/report.tex` (paper summary, reproduction, critique, conclusion), `RESULTS.md` (Phase 1
extensions, P2-A..G) · **Duration:** one sitting

---

## Brief *(written before any work)*

**Task:** write an 8–9 page ACL-format report covering the paper, its claims, our mid-semester and
post-mid-semester work, the paper's limitations and our own, in plain language for the TA and
professor.

**Exit condition:** `docs/final_report/report.tex` with bibliography, ACL style files and figures,
packaged for Overleaf; `PROJECT_STATE.md` updated.

**Out of scope:** recompiling the old 31-page report; new experiments.

---

## Prompts *(verbatim, in order)*

```
1. push these changes whatever not pushed into the phase2 branch but not the speaker notes, keep
   that uncommitted pls

2. can u give me a brief idea of each experiment we did since the mid in simple words to help me
   understand simply what we tackled and how, then i will be able to understand the speaker notes
   better

3. [screenshot of the G screening notes] for this part, you say that checking for random data fails
   as we might flag even the real compressed files, or images videos etc. then how did we get past
   that? explain simply and in shiort

4. now, i want a proper report created for the whole project end to end explaining the paper, what
   was stated/claimed and what we did, mention all limitationss etc that we found out and even our
   own limitations. keep it acl format. keep the language not complex and easy to understand for
   the TA and prof, you can take the original paper as a refernce on how to write and mention the
   key terms, the results and the observations clearly. max 8-9 pages
```

---

## What was done *(all AI-generated under the user's direction)*

- `docs/final_report/report.tex` (ACL `[preprint]`), `references.bib`, official `acl.sty` and
  `acl_natbib.bst` (from acl-org/acl-style-files), `make_figs.py` and `make_arch_fig.py` (paper-sized
  figures drawn from `results/tables/*.csv`), `figs/`.
- `BSFR-SH_Final_Report_Overleaf.zip` (untracked) for compiling on Overleaf.
- Corrected the deck and speaker notes: the mid-semester TPS was ~3,000 tx/s on the Phase 1 host
  (not the ~1,130 measured later on the Linux box), and amortisation was already *suspected* at
  mid-semester (DEV-08) but not tested.

## Findings

- **Phase 1 report overstated M7-12.** Its conclusion says the drift defence "catches" a strategy;
  `RESULTS.md` M7-12 has `prevented=False` in all 15 cells. The new report says the scores
  separated but the alarm never fired, consistent with P2-D.
- The final report states DEV-46's correction of report l.478 explicitly.

**Dead ends:** no LaTeX toolchain on the dev box, so the report could not be compiled or
page-counted here; layout and length are estimated from source (~4,500 words, 6 figures, 6 tables,
about 7 pages).

## Numbers

None new; all from `RESULTS.md`.

---

## Handover

**Next task:** Compile `docs/final_report/report.tex` (pdflatex + bibtex, ACL style files included),
check it is at most 9 pages, and fix any layout problems; source-level estimate is about 7 pages.

## Checklist

- [x] `PROJECT_STATE.md` rewritten, under 200 lines
- [ ] `RESULTS.md` (nothing measured)
- [x] committed on branch `phase2` (not pushed)
