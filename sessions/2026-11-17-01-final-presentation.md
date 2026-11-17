# Session 2026-11-17-01 — Final-evaluation presentation and speaker notes

**Milestone:** Project Phase 2 (presentation) · **Files read at start:** `PROJECT_STATE.md`, last
session's handover, `results/figures/p2*.png`, `RESULTS.md` Phase 2 blocks · **Duration:** spread
over 2026-11-13 to 2026-11-17

---

## Brief *(written before any work)*

**Task:** build the final-evaluation deck (work till mid-semester, then work after it) with
speaker notes the user can present from.

**Exit condition:** a light-themed .pptx with speaker notes and a standalone HTML speaker script
exist in the repo root, untracked; `PROJECT_STATE.md` reflects them.

**Out of scope:** new experiments; the report PDF; committing the deliverables.

**Prior context needed:** RESULTS.md Phase 2, DEV-44..50.

---

## Prompts *(verbatim, in order)*

```
1. is this enough to wrap up the project now? can we make this into a striong 15 min presentation
   where we quickly recap phase 1 and then talk about phase 2? do you think project is all done
   now with all significant tests we could do

2. btw we are not keeping future work here as a slide anymore, only what weve done now

3. continue

4. continue

5. Continue from where you left off. what the fuck are u doing? o just said that we should not
   keep future work?

6. ok so lets create a ppt then for this, keep phase 1 in brief but dont name it phase one,
   instead say what was already done till mid. keep itt max 3-4 slides and then this work naming
   it after mid or something after explaining the gaps and why it was necessary etc. keep it
   informative and easy to understand for the TA. use comprehensible language and not ai slop.
   also make it light themed only. with a proper design etc but not over the top

7. i dont like repeated language like what we did, what we found etc. please make the slide sound
   less AI generated and make it seem more Security, Attacks, Blockchain, etc focused not just
   look so generic like it could be taliking about anything. you can add more diagrams for our
   system in particular or make content like that, redesign it better etc. keep the theme light
   only but make these changes such that it looks like each slide holds value.

8. ok, so now i need spearker notes on the slides that you created so i can cover each properly
   for allotted time (which is 15mins but keep the content to fit 20 mins as we tend to say lesser
   than what is written and i dont wanna eep looking at the text every time while speaking). keep
   the language simple to understand by the TA as he has many projects to grade and isnt solely
   focusing on our but remember to include the key terms as well. create a html for this

9. also did we update project state md file after my recent changes since starting phase2? do it
   if not already done.
```

---

## What was done *(all AI-generated under the user's direction)*

- A browser (claude.ai artifact) deck first; superseded when the user asked for a .pptx.
- `BSFR-SH_Final_Presentation.pptx` (15 slides, pptxgenjs, native charts, light theme), rebuilt
  once after feedback: system architecture, claims-vs-measurements, attack ladder, a gap map
  locating A–G on the system, per-experiment diagrams (setup-cost split, year split, drift-alarm
  pipeline, single key holder vs 2-of-4 shares, slow-burn backup timeline, screening pipeline).
- `BSFR-SH_Speaker_Notes.html`: per-slide cue, key terms, main script, optional extras, likely
  questions, a timer that shows which slide you should be on. The same script is written into
  the deck's speaker notes.
- Generators kept in `presentation_src/`. All four deliverables listed in `.git/info/exclude`.

## Findings

- The user's framing: "till mid-semester" / "after mid-semester", never "Phase 1/2" on slides; no
  future-work slide; light theme only; avoid repeated templated headings.

**Dead ends / surprises:**
- No LibreOffice on the dev box and downloading an AppImage was refused, so the deck could not be
  rendered for visual QA. Layout was checked by geometry and `validate.py` only; the user was
  asked to flip through it.
- The first .pptx used the same three headings on every experiment slide; the user rejected that
  as generic. The rebuild uses slide-specific diagrams instead.

## Numbers

None new. Every number on the slides and in the script comes from `RESULTS.md` (Phase 1, P2-A..G).

---

## Handover

**State after:** deck and script delivered, untracked. Nothing in `src/` or `results/` changed.

**Next task:** Update `docs/report/report.tex` with Phase 2 (P2-A..G, DEV-44..50) and correct l.478
("H4 rules out year as a temporal leak", contradicted by DEV-46), then recompile the PDF.

**New blockers:** none.

## Checklist

- [x] `PROJECT_STATE.md` rewritten, under 200 lines
- [ ] `RESULTS.md` (nothing measured)
- [ ] `docs/ROADMAP.md` (no milestone change)
- [x] committed on branch `phase2` (session file + PROJECT_STATE only)
