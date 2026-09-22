# Session 2026-09-22-02 — Results reconfirmation and report recompile

**Milestone:** post-M7-3 hygiene · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`RESULTS.md` (in full), `docs/EXPERIMENTS.md` Targets 1-4, `docs/DEVIATIONS.md` DEV-08 + DEV-30,
`sessions/_TEMPLATE.md`, `scripts/run_bench.py`, `src/bsfr_sh/bench/harness.py` (`BenchPolicy`),
`configs/bench.yaml`, `src/bsfr_sh/consensus/pbft.py` (`serialize_messages` wiring) · **Duration:** ~1h

---

## Brief *(written before any work)*

**Task:** D3's closure (prior session) found consensus serialization adds +48-68% to case-3
timing, not the ~0.2-0.3% first estimated. Before presenting or building further on the report's
timing numbers (all measured with serialization off), reconfirm everything under honest
conditions: re-run the full M6a bench matrix with serialization on, re-verify the M4a/M4b
detection numbers are still byte-reproducible, and recompile the report with a serialization
caveat + supplementary table added, including verifying the M7-3 figures actually render (the
last three sessions edited `.tex` without ever compiling it).

**Exit condition:** `make test`/`make lint` green; new, distinctly-run_id'd `RESULTS.md` lines for
the serialization-ON bench matrix (old lines untouched); M4a/M4b numbers reconfirmed
byte-identical to their existing `RESULTS.md` lines (or investigated if not); `report.pdf`
recompiled with the D3 footnote, the new supplementary table, and confirmed (by opening the PDF)
that every table/figure including M7-3's three adversarial-robustness figures renders and is
correctly placed.

**Out of scope:** No new analysis, no new features, no slides. This is verification and
publication hygiene, not research.

**Prior context needed:** `docs/DEVIATIONS.md` DEV-08 (marginal cost / TPS amortisation) and
DEV-30 (D3's magnitude, both the ~0.2-0.3% encode-only estimate and the measured +48-68%
amendment) — this session's step 1 either reconfirms DEV-08's "marginal cost stays flat" claim
under the honest condition or has to amend it. `docs/EXPERIMENTS.md` Targets 3-4 (protocol: same
seed 20260917, adaptive repeat count via `decide_repeat_count`, never assumed). `RESULTS.md`'s
existing M6a lines (run `20260917T144843Z-fb4c2410`, serialization OFF — the config option did
not exist yet at that run's time) are the baseline every delta in this session is computed
against.

**Established before writing anything:** `configs/bench.yaml` already declares
`network.serialize_messages: true` (added during D3's closure, `src/bsfr_sh/bench/harness.py`
`BenchPolicy.from_config` wires it into `PBFTPolicy.serialize_messages`, which
`consensus/pbft.py:803` turns into a real `encode_message`/`decode_message` round-trip per
`send()` call). So `scripts/run_bench.py --seed 20260917` run *today*, unmodified, already
measures the honest, serialization-on condition — no code change needed for step 1, only a run.
`--no-figures` will be used to avoid silently overwriting the existing (serialization-off)
Figs. 6(a)-(d)/component-breakdown PNGs and `target3_target4.csv`, since the task asks for a
*separate* supplementary table, not a replacement of the existing ones.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. [Full task prompt: results reconfirmation and report recompile — re-run M6a bench matrix with
   serialization on (questions a/b/c on marginal cost flatness, the BC_SigRW/BC_DTBU gap, and
   trend persistence); re-run M4a paper_mode/honest_mode and M4b honeypot detection to confirm
   byte-reproducibility; recompile report.pdf with a D3 footnote on the timing tables and a new
   supplementary serialization-ON table, verify every figure/table renders including M7-3's three
   adversarial-robustness figures; amend DEV-08/DEV-30 if the re-run changes any stated finding.
   Reproduced in full in the conversation transcript, not re-typed here.]
```

---

## What was done

- **`RESULTS.md`** (edited) — new `## Bench reconfirmation — serialization ON` section: six
  `bench/target3-time-serialized` lines (all three cases, both chains), two variance lines, the
  a/b/c findings write-up, and an `### M4a/M4b — reconfirmed byte-reproducible` subsection
  (pointers to three new run_ids, no duplicate numeric lines since nothing differed from what was
  already published).
- **`docs/DEVIATIONS.md`** (edited) — DEV-08 and DEV-30 both amended with the reconfirmation
  findings (see Deviations section below).
- **`docs/EXPERIMENTS.md`** (edited) — Target 3 and Target 4 both got a short "reconfirmed,
  serialization ON" addendum pointing at the new numbers, without disturbing the existing
  serialization-OFF measured-M6a text (which remains correct for the condition it describes).
- **`docs/report/report.tex`** (edited) — footnote added to both timing table captions
  (`tab:timing`, `tab:marginal`) per the task's exact wording; new
  `\subsection{Supplementary: timing under honest, serialization-on conditions}` inserted at the
  end of §5c (Blockchain timing), before §Critique, with its own serialization-ON table and the
  a/b/c discussion.
- **`docs/report/report.pdf`** — **not recompiled.** See Findings below for the specific attempt
  and why it was stopped within the task's own 20-minute installation budget.

## Findings

- **Confirmed: `configs/bench.yaml` already had `network.serialize_messages: true`** (set during
  D3's closure, prior session) — meant step 1 needed no code change, only a run. Worth recording
  because it was not obvious from the task prompt alone; verified by reading the config and its
  wiring through `bench/harness.py`/`consensus/pbft.py` before running anything.
- **The bench matrix's adaptive repeat count landed on the floor (n=5) this time**, not M6a's 25 —
  a different variance reading (CV ≈1.3%, quiet machine) driving the same `decide_repeat_count`
  logic to a different decision. Not a bug: this project's own `RESULTS.md` already documents one
  prior instance of exactly this (M6a's own two back-to-back runs disagreeing on CV). Reported
  as-is rather than forced to a specific repeat count.
- **Marginal cost stays flat under serialization (question a: yes, DEV-08 survives)** — both
  chains vary under 1% across cases 1-3 with serialization on, same as off, just uniformly higher.
- **The BC_SigRW/BC_DTBU gap narrows from 35-45% to ~25-27% under serialization (question b: no,
  it does not stay in that band) — a real finding, investigated rather than left as a bare
  number.** Traced to: both chains' D3 encode-only cost is nearly identical in absolute terms
  (0.000072s vs 0.000073s/block at case-3), so the real bus's serialization tax is plausibly close
  to chain-independent in absolute seconds; that near-fixed addition inflates BC_DTBU's smaller
  base by a larger percentage than it inflates the absolute gap, which is why the *percentage* gap
  shrinks even as the *absolute* gap grows slightly. The structural ECDSA/encoding attribution for
  the serialization-OFF 35-45% figure is not wrong — it was always specifically about that
  condition — but "the gap" is no longer a single number once both conditions are on record.
- **Trends hold under both conditions (question c: yes)** — monotone increase, `BC_SigRW` >
  `BC_DTBU` (narrower, never inverting), flat-not-rising TPS.
- **`make honest` clobbers `results/tables/table2_honest_mode.csv`'s canonical Ada full-scale KNN
  row with the local, KNN-subsampled numbers every time it is run locally** — discovered by
  running it for this session's M4a reconfirmation, noticed immediately via `git status`/`git
  diff` on that file, and reverted with `git checkout --` before it could propagate anywhere. This
  is a latent trap for any future session that runs `make honest` for any reason without knowing
  to check the table afterward; flagged in `PROJECT_STATE.md`'s risks table rather than only fixed
  silently this once.
- **All three detection reconfirmations (paper_mode, honest_mode locally, M4b honeypot ensemble)
  reproduced their existing `RESULTS.md` lines exactly**, to the precision both report. No
  investigation needed past that — the byte-reproducibility held on the first check.
- **LaTeX toolchain install attempted and abandoned within the task's own 20-minute budget —
  the report was not recompiled this session either.** `brew install --cask basictex` was tried
  (the task's suggested first retry, on the premise the prior session's failure was transient).
  This time the cask resolved and `curl` started fetching `mactex-basictex-20260301.pkg` (~100-
  110 MB) from a CTAN mirror (`mirrors.in3.sahilister.net`), but the download was very slow and
  effectively stalled after ~55 MB (roughly halfway) at the ~23-minute mark — killed at that point
  rather than let run indefinitely, per the task's explicit cap. `docker`, `pdflatex`, `xelatex`,
  `latexmk` all confirmed absent from `PATH` before attempting brew, same as last session.
  Overleaf-as-one-shot-compiler was not attempted: it needs an interactive browser session this
  agent does not have a reliable way to drive non-interactively within the time budget, and
  uploading the report to a third-party web service is the kind of action worth the user's own
  call rather than a default fallback. **Net result: `report.tex` carries this session's edits
  (D3 footnote on both timing tables, new supplementary serialization-ON table/subsection); the
  committed `report.pdf` is now two sessions stale** (missing both M7-3's adversarial-robustness
  section and this session's supplementary timing material). This is the single exit condition
  this session did not meet, stated plainly rather than glossed over.

## Numbers

All in `results/logs/20260922T172916Z-22992372.json` (bench matrix),
`20260922T173217Z-69eb48f0.json` (paper_mode), `20260922T173229Z-87832d2b.json` (honest_mode),
`20260922T173724Z-b99c8896.json` (M4b honeypot); headline lines in `RESULTS.md`. See that file's
new "Bench reconfirmation" and "M4a/M4b" sections for the full table — not re-duplicated here.

## Deviations opened or changed

- **DEV-08 amended**: marginal-cost flatness reconfirmed under serialization ON, full three-case
  matrix (not just case-3) — survives unchanged in shape, uniformly higher in absolute seconds.
- **DEV-30 amended**: full-matrix confirmation of the case-3-only closure's magnitude across all
  three cases, plus the new BC_SigRW/BC_DTBU gap-narrowing finding (35-45% -> ~25-27%) with its
  mechanism (near-chain-independent absolute serialization cost, diluting rather than adding to
  the percentage gap).

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** Every number the report presents or could present has now been reconfirmed under
the honest, serialization-on condition (bench matrix) or re-verified byte-reproducible (M4a/M4b) —
`RESULTS.md`, `docs/DEVIATIONS.md` (DEV-08, DEV-30), and `docs/EXPERIMENTS.md` (Targets 3-4) all
carry the new findings, none silently smoothing over the gap-narrowing result. `report.tex` has
the D3 footnote and the new supplementary table/subsection, syntactically checked (balanced
braces/dollar-signs/table-figure environment counts) but **still never compiled** — this is now
the second consecutive session to edit `report.tex` without rendering it, which is exactly the
condition this session's own step 5 was supposed to guard against and could not fully close
because the toolchain still isn't available in under 20 minutes here.

**Next task:** Get a LaTeX toolchain working — from a machine/network where `brew install --cask
basictex` (or `mactex`) can actually complete in reasonable time, or via a pre-existing install —
then run `cd docs/report && pdflatex report.tex` (twice, for cross-references) and: (1) confirm
every table and figure renders, specifically the M7-3 adversarial-robustness figures (§ after §VI)
and this session's new supplementary timing subsection (§ after §5c, before §Critique); (2) check
the D3 footnotes render correctly as footnotes on both `tab:timing` and `tab:marginal` (footnotes
inside floats occasionally need `\footnotemark`/`\footnotetext` splitting rather than a bare
`\footnote{}` depending on the document class's float handling — IEEEtran's behavior here was not
verified, since nothing compiled); (3) commit the resulting `report.pdf` alongside the already-
committed `report.tex`. If `brew`'s CTAN mirror is slow again, try `brew install --cask basictex
--force` with a different mirror pinned via `TEXLIVE_INSTALL_ENV_NOCHECK`/manual mirror override,
or `install-tl` directly from a CTAN mirror chosen for locale/speed, rather than retrying the same
default mirror.

**New blockers:** LaTeX toolchain still unavailable in this environment within a 20-minute budget
(this session's specific attempt: `brew install --cask basictex`, CTAN mirror
`mirrors.in3.sahilister.net`, stalled ~55/110 MB at ~23 minutes, killed). `docker`/`pdflatex`/
`xelatex`/`latexmk` all absent from `PATH`.

**Questions opened / closed:** None of `PROJECT_STATE.md`'s existing open questions were touched.
No new ones opened — the gap-narrowing finding is documented as a finding (DEV-30), not left as an
open question, since it was fully explained (near-chain-independent serialization cost) rather
than left unresolved.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run (bench matrix) plus the M4a/M4b reconfirmation block
- [x] `docs/ROADMAP.md` boxes ticked — N/A this session (no roadmap item closed or opened; this
      was verification of already-`[x]`'d work, not a new milestone)
- [x] `docs/DEVIATIONS.md` updated (DEV-08, DEV-30 amended)
- [ ] `report.pdf` recompiled — **not done**, see Handover
- [ ] Committed, message explains *why* — pending, next step after this file is saved
