# Session 2026-09-13-01 — Q10, address and split leakage

**Milestone:** none (Q10 follow-up, not M4b) · **Files read at start:** `CLAUDE.md`,
`PROJECT_STATE.md`, `docs/EXPERIMENTS.md` Targets 1–2, `docs/DEVIATIONS.md` DEV-06 and DEV-07,
`sessions/_TEMPLATE.md`, plus (to determine the split M4a actually used, per the prompt)
`src/bsfr_sh/detection/dataset.py`, `scripts/run_detection.py`, `configs/ml.yaml`, and the M4a
session log and its two sidecars. Per the ladder, not `docs/ALGORITHMS.md`, not
`docs/PAPER_NOTES.md` beyond what FLAW-4/FLAW-1 already cover. · **Duration:** one working session

---

## Brief *(written before any work)*

**Which split did M4a actually use?** Random, not grouped. `stratified_holdout()`
(`detection/dataset.py`) stratifies by label only — it shuffles row indices within each class and
cuts a test fraction. It never looks at `address`. So the matrix in the prompt has its comment in
the wrong place: **"address dropped x random split" is the current honest position** (it is
exactly reference run `20260912T172708Z-6d35b415`, RF 0.9479/0.9717), not "address dropped x
grouped split". Consequence, stated up front: M4a already carries candidate 2's leakage (same-
address rows on both sides of the boundary) and still only reached 0.9479. Whatever candidate 2
is worth, it is already baked into the 0.9479 we have — closing it can only move the number
*down* from here, and candidate 1's ceiling is bounded by what's left of the 0.9898 − 0.9479 gap
after that correction, not the whole gap.

Checked directly against the real file before writing any split code (2,916,697 rows): every
address carries exactly one label end to end (0 addresses with >1 distinct label). Ransomware
addresses average 1.99 rows each (20,849 addresses producing 41,413 rows — 2,549 addresses,
12.2%, appear more than once); benign addresses average 1.10 (2,610,246 addresses producing
2,875,284 rows — 94,218 addresses, 3.6%, appear more than once). So a random split's leakage is
real and asymmetric: repeated-row leakage is ~3.4x more common among ransomware addresses than
benign ones, which is exactly the class the paper resamples up to 90%.

**Task:** Run the 2x2 (address dropped/kept x random/grouped split), `paper_mode` only, all four
models, same declared hyperparameters and seed (20260912) as the reference run, to close Q10:
either identify what accounts for the 0.9479 -> 0.9898 gap, or state plainly that nothing in this
2x2 does. Also correct the honest_mode-vs-paper_mode framing in two docs before it reaches the
report, and add the `make data` timing/hash warning to the README.

**Exit condition:** four cells measured, each with its own sidecar and `RESULTS.md` line
(`mode=measured`), each cell's accuracy/F1 delta recorded against both 0.9479 and 0.9898; Q10
closed in `PROJECT_STATE.md` with a stated conclusion (including "unexplained" if that's what the
numbers show); `docs/PAPER_NOTES.md` and `docs/EXPERIMENTS.md` framing corrected so the cross-
distribution comparison (natural-rate constant-negative 0.9858 vs the paper's 90/10-derived
0.9898) is labelled illustration, with the airtight within-split comparison (constant-positive
0.9000/0.9474 on the paper's own split; Sharmeen et al.'s published F1 0.960 barely clears that
floor) stated beside it; README quick-start warns about `make data`'s ~1 hour at this
environment's throughput plus the sha256; `make test` and `make lint` green.

**Out of scope:** honeypot backend, NProf/AProf, Alg. 3, figures, Ada job, and starting M4b. Not
a milestone session — no `docs/ROADMAP.md` restructuring beyond a one-line note that Q10 closed.

**Prior context needed:** DEV-06 (both modes, the resample's arithmetic bound), DEV-07 (Table II
annotation), `configs/ml.yaml` (the declared hyperparameters and seed this session must match
exactly), and the M4a session log's numbers (0.9479/0.9717 RF, 0.9262/0.9590 DT, 0.9000/0.9474 LR,
0.8861/0.9392 KNN) as the baseline every cell is compared against.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/EXPERIMENTS.md
Targets 1-2, docs/DEVIATIONS.md DEV-06 and DEV-07. Nothing else.

Create the session file from the template and fill the brief first.

This is a short, focused session: close Q10. Not a milestone. Do not start
M4b in the same session.

CONTEXT
M4a reproduced 0.9479 against the published 0.9898 — we are 4.2 points LOW.
So the explanation must be a leakage source the paper has and we do not.
Two candidates, and Q10 currently names only the first.

  1. `address` kept as an explicit feature. We drop it at load.

  2. Splitting randomly rather than grouping by address. BitcoinHeist rows
     are (address, year, day) tuples, so one address produces many rows, and
     weight / length / count / looped / neighbors / income are all
     address-level graph features. Rows sharing an address are near
     duplicates. A random split puts them on both sides of the boundary.

TASK
First, state in the brief which splitting strategy M4a actually used. If it
already grouped by address, candidate 2 is not in play and this session
isolates candidate 1. If it split randomly, M4a already carries candidate 2's
leakage and still only reached 0.9479 — which itself bounds how much
candidate 1 can be worth.

Then run the 2x2, paper_mode only, all four models, same declared
hyperparameters and seed as run 20260912T172708Z-6d35b415 so the numbers are
comparable to it:

    address dropped  x  grouped split      <- our current honest position
    address dropped  x  random split
    address kept     x  grouped split
    address kept     x  random split

For "address kept", encode it in the way a straightforward implementation
would — label/ordinal encoding over the raw string is the likely path, and
that is the point: it is what someone gets by not thinking about it, not a
strawman. Say in the session file which encoding you used and why.

Every cell writes a sidecar and a RESULTS.md line with mode=measured. Record
the per-cell delta against 0.9479 and against the published 0.9898.

WHAT THIS IS AND IS NOT
This is not an attempt to hit 0.9898. If a cell reaches it, that identifies
what the published number requires — it does not become our result, and it
does not go in Table II's BSFR-SH row. Our reported figure stays the honest
one: address dropped, grouped split.

If no cell reaches 0.9898, say so plainly. "We could not account for the gap"
is a legitimate finding and better than a forced explanation.

ALSO IN THIS SESSION

Tighten the honest_mode framing before it reaches the report. Comparing
constant-negative at 0.9858 (natural 1.42% distribution) against the paper's
0.9898 (90/10 distribution) is rhetorically strong but not like-for-like, and
an examiner will catch it. The airtight comparison is within-split:
on the paper's own 90/10 split, constant-positive scores 0.9000 / 0.9474, and
Sharmeen et al.'s published F1 of 0.960 is barely above a do-nothing
classifier while the paper presents it as a competitive baseline. Fix the
framing in docs/PAPER_NOTES.md and docs/EXPERIMENTS.md so the cross-
distribution figure is labelled illustration, not head-to-head.

Add to README quick-start: `make data` takes roughly an hour at ~37 KiB/s and
data/raw/ is gitignored, so a fresh clone cannot run any BitcoinHeist
experiment until it completes. Include the sha256 from provenance.json. An
unexplained hour of apparent hang gets the process killed.

EXIT CONDITION
make test and make lint green. Four cells measured, logged, and interpreted.
Q10 closed with a stated conclusion - including "unexplained" if that is
what the numbers show. Framing corrected in both docs.

OUT OF SCOPE
No honeypot backend, no NProf/AProf, no Alg. 3, no figures, no Ada job. M4b
is the next session.

END OF SESSION
Session file with attribution and dead ends. RESULTS.md lines for all four
cells. Amend DEV-07 or FLAW-4 if the conclusion changes what Table II should
say. Rewrite PROJECT_STATE.md, under 200 lines. Commit explaining why.
```

---

## What was done

**Attribution.** All new code, tests and doc text are **AI-generated (Claude Sonnet 5),
human-directed**. From the prompt: the exact 2x2 to run, matching the reference run's config hash
and seed, the "not a strawman" instruction for how to encode `address`, the framing correction for
the cross-distribution comparison, and the README warning. Claude's: verifying which split M4a
actually used before writing any new code (rather than trusting the prompt's own matrix
annotation), the direct check of address/label/row-count structure against the real file before
choosing a grouping algorithm, the `grouped_stratified_holdout` design (whole groups assigned in
shuffle order until a running-count target is first met, per label), `encode_group_column`'s choice
of `sklearn.LabelEncoder`, and the decision to load the full CSV twice (once per address-encoding
variant) rather than mutate one loaded frame in place.

**Verified before writing any split code:** `stratified_holdout` (`detection/dataset.py`)
stratifies by label only and never reads `address` — M4a's `paper_mode` split was row-random, not
grouped. Confirmed by rerunning `address dropped x random split` in this session's own script and
getting M4a's exact RF numbers back (0.9479/0.9717) at an identical config hash.

**Checked directly against `data/raw/BitcoinHeistData.csv` (2,916,697 rows) before choosing a
grouping algorithm:** 0 of 2,631,095 addresses carry more than one distinct label — grouping by
address cannot mix classes within a group. Ransomware addresses average 1.99 rows each (20,849
addresses -> 41,413 rows; 2,549 addresses, 12.2%, appear more than once); benign addresses average
1.10 (2,610,246 addresses -> 2,875,284 rows; 94,218 addresses, 3.6%, repeat). So a random split's
address-duplication leakage is real and roughly 3.4x more common among ransomware rows than benign
ones — exactly the class the 90/10 resample amplifies.

**New code**

| File | What it does |
|---|---|
| `detection/dataset.py` | `GROUP_COLUMN`; `DatasetSpec.group_column` / `.encode_group_as_feature` (Q10 only — the config-driven production path never sets them); `LoadedDataset.groups` and `Resample.groups`, carried through subsampling and resampling; `encode_group_column()` (sklearn `LabelEncoder`); `grouped_stratified_holdout()` |
| `scripts/q10_leakage_ablation.py` | thin wrapper: loads the full file once per address-encoding variant, resamples and splits four ways, fits all four models per cell, writes one sidecar and prints one `RESULTS.md` line per model per cell |
| `tests/unit/test_detection_dataset.py` | 9 new tests: group-column loading stays out of the feature matrix by default, `encode_group_as_feature` appends a dense ordinal column, the encoder is refused without a group column, `Resample` carries groups through, the encoding is deterministic and sorted, grouped splits keep every group on one side and are disjoint, class rate is approximately preserved, bad `test_size`/missing `groups` are refused |

**Docs**

| File | Change |
|---|---|
| `docs/DEVIATIONS.md` | DEV-06 amended with the Q10 finding and the revised honest baseline |
| `docs/PAPER_NOTES.md` | FLAW-1 extended (Sharmeen barely clears the trivial baseline); new NOTE labelling the cross-distribution comparison as illustration; Q10 closure recorded under FLAW-4 |
| `docs/EXPERIMENTS.md` | Target 1's baseline paragraph extended with the Sharmeen point; new paragraph stating the cross-distribution pairing is illustration, not head-to-head |
| `docs/ROADMAP.md` | Q10 closure noted under M4a's exit (not a new milestone) |
| `README.md` | quick-start warns `make data` takes ~1 hour at this environment's throughput and states the sha256 from `provenance.json` |
| `PROJECT_STATE.md` | rewritten: revised honest baseline, Q10 removed from open questions, D6 added, risk mitigation updated |

**Tests: 1093 -> 1102 unit (+9), 10 integration (1112 total).** `make lint` (ruff + ruff format +
mypy --strict on `src`) and `make test-all` both clean.

## Findings

**M4a's split was random, not grouped — the prompt's own matrix had the annotation on the wrong
row.** This had to be settled by reading `detection/dataset.py` before writing anything, per the
brief's own instruction. It matters because it means candidate 2's leakage was already inside
M4a's 0.9479, not absent from it.

**Both candidate leakage sources are real, both are small, and neither explains the gap.** Full
numbers in `docs/DEVIATIONS.md` DEV-06 and `RESULTS.md`. Isolating the random split's effect
(address dropped, grouped vs. random): random forest +0.37pt, decision tree +0.38pt, logistic
regression flat, KNN -0.31pt (noise-level, KNN is not obviously helped by same-address
duplication). Isolating `address`-kept (grouped vs. random for each encoding, then comparing
encodings within a split): the effect is small everywhere except decision tree under a random
split, where it is +0.92pt over the honest baseline — a tree can split directly on a memorised
ordinal id when that id's rows appear on both sides, and this is exactly the effect that disappears
under a grouped split (kept x grouped is statistically flat against dropped x grouped for decision
tree). The best of all 16 model x cell combinations — random forest, address kept, random split —
reaches 0.9540/0.9749, still 3.58 accuracy points and 2.41 F1 points under the published
0.9898/0.990. **Q10 closes as unexplained, not resolved.**

**Dead end considered and rejected: stratifying the grouped split by exact target ratio via
fractional group splitting.** Early draft of `grouped_stratified_holdout` considered splitting a
single large group across train/test to hit `test_size` exactly. Rejected — it defeats the entire
point of grouping (a split-group address would still leak across the boundary) and the measured
drift from whole-group assignment turned out to be negligible in practice (achieved test positive
rate 0.90004 vs. a 0.90000 target, from sidecar `20260913T014022Z-c54c3974`).

**The correction this session produces is a revision, not just an ablation result.** Once random
split is shown to be the less-correct methodology, "the honest number" moves: M4a's 0.9479/0.9717
is superseded by 0.9442/0.9697 (address dropped, grouped split) as the reported `paper_mode`
figure. `scripts/run_detection.py` was deliberately **not** changed to use the grouped split in
this session (out of scope — "not a milestone"); this leaves the production entry point and the
reported figure disagreeing until D6 is retired, which is recorded rather than silently left
implicit.

## Numbers

All four cells: `paper_mode`, n=46,014, same config hash (`1f0edc64…ee858e`) and seed (20260912)
as reference run `20260912T172708Z-6d35b415`, verified identical across all four sidecars.

| Cell | RF | DT | LR | KNN | Run id |
|---|---|---|---|---|---|
| address dropped x grouped *(new honest baseline)* | 0.9442/0.9697 | 0.9224/0.9569 | 0.9002/0.9475 | 0.8892/0.9410 | `20260913T014022Z-c54c3974` |
| address dropped x random *(= M4a, exact reproduction)* | 0.9479/0.9717 | 0.9262/0.9590 | 0.9000/0.9474 | 0.8861/0.9392 | `20260913T014027Z-6b9021ae` |
| address kept x grouped | 0.9484/0.9719 | 0.9221/0.9566 | 0.9001/0.9474 | 0.8894/0.9411 | `20260913T014027Z-ca9f3d58` |
| address kept x random *(best cell)* | 0.9540/0.9749 | 0.9354/0.9642 | 0.8996/0.9471 | 0.8901/0.9414 | `20260913T014037Z-47d61ade` |

Published BSFR-SH row (`paper_reported`): 0.9898/0.990. Every cell's delta against both M4a's
0.9479 and the published 0.9898 is in the sidecar and in the `RESULTS.md` lines (16 total, one per
model per cell). Full detail: `RESULTS.md` "Q10 — address / split leakage ablation" block.

## Deviations opened or changed

- **DEV-06** amended: the Q10 2x2 result, the revised honest baseline, and the D6 pointer for the
  now-disagreeing production entry point.
- No new DEV number: this is a follow-up measurement inside DEV-06's scope, not a new departure.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** Q10 is closed as unexplained. The honest `paper_mode` reproduction figure is
revised to 0.9442/0.9697 (random forest, address dropped, grouped split); M4a's 0.9479/0.9717
(random split) is superseded but kept in `RESULTS.md` for provenance. `detection/dataset.py`
gained grouped-split and address-encoding support, used so far only by
`scripts/q10_leakage_ablation.py` — `scripts/run_detection.py`'s default `paper_mode` pipeline
still uses the random split (carried debt D6). The cross-distribution accuracy comparison
(honest_mode's natural-rate constant-negative vs. the paper's 90/10-derived headline) is now
explicitly labelled illustration in `docs/PAPER_NOTES.md` and `docs/EXPERIMENTS.md`, with the
airtight within-split comparison (Sharmeen et al.'s 0.960 barely clearing a 0.9474 trivial floor)
stated beside it. README's quick-start now warns about `make data`'s ~1 hour wait and states the
sha256.

**Next task:** M4b — build `HoneypotBackend`, `detection/profiles.py`, `detection/detector.py` and
`framework/phase3_detection.py`, per `PROJECT_STATE.md`'s "Next task" (unchanged by this session).
D6 (folding `grouped_stratified_holdout` into `scripts/run_detection.py`) should be picked up
before M6 cites `run_detection.py`'s `paper_mode` output as the reported figure, but is not itself
required to start M4b.

**New blockers:** none.

**Questions opened / closed:** **Q10 closed** — neither `address` as a feature nor the split
strategy (random vs. address-grouped), alone or together, explains the reproduction gap; best of
16 model x cell combinations is 3.58 accuracy points under published. No new questions opened.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines (190)
- [x] `RESULTS.md` appended — 16 lines (one per model per cell), all `measured` with run ids
- [x] `docs/ROADMAP.md` — no boxes to tick (not a milestone); Q10 closure noted under M4a's exit
- [x] `docs/DEVIATIONS.md` updated — DEV-06 amended
- [x] Committed, message explains *why*
