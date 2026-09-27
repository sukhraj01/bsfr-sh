# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-27 · **Milestone:** M7 stretch complete (M7-16 delivered) ·
**Sessions completed:** 33

---

## One-line status

M7-16 (multi-family ransomware detection) is delivered: `detection/multiclass.py` +
`scripts/m7_16_multiclass_detection.py` test whether BitcoinHeist's 28 named ransomware families
carry family-discriminative signal beyond binary ransomware/benign — not attempted by the paper.

- **Measured: macro F1 0.058-0.199 (decision tree best) — weak, real signal, not strong.**
  Weighted F1 (0.978-0.985) and top-3 accuracy (0.993-0.998) are both dominated by `white`'s
  98.58% share and say little alone. Every family's dominant confusion is with `white`, never
  another family — the 19x19 confusion matrix reflects the same ransomware/benign boundary the
  binary detector already measures, not inter-family blur.
- **Per-family feature signal (`year`/`income` dominate all 8 large families) is a stated
  caveat**: each family is a narrow historical campaign window, so this may be a temporal
  fingerprint rather than a behavioural one — the graph-topology features FLAW-2 already
  distrusts contribute least to family discrimination too.
- **Binary-collapse: RF/DT sit marginally *below* (not above) their published binary-only M6b
  figures** — under 1 point apart on every metric, a wash rather than a win; the brief's own
  expectation ("should match or exceed") is not quite met, reported as measured.
- **The FT_RW/honeypot gap is real, not moot**: `honeypot/features.py` has no family field;
  if graph features alone carry even weak family signal, FT_RW's richer behavioural features
  plausibly would too. Recorded as a finding; no generator change made (out of scope).
- **Found and fixed a latent performance bug** in `detection.dataset.grouped_stratified_holdout`
  (used since Q10/D6): `np.isin` on large object-dtype arrays does not take numpy's hashed fast
  path — never exercised at full 2.9M-row scale before this session (every prior caller only ran
  it on the 46K-row `paper_mode` resample). Fixed with a Python hash-set membership test (0.25s
  vs. an unbounded hang). A second fix in the same function: a class confined to a single
  address could previously land entirely in test, crashing `top_k_accuracy_score` — now reserves
  at least one group for training whenever more than one exists. Neither fix touches any
  previously-published binary number (confirmed: `test_detection_dataset.py` unchanged, still
  green).
- Report extended (`docs/report/report.tex` §"Multi-Family Ransomware Detection", new figure
  `fig_m7_16_family_confusion.png`); recompiles clean (tectonic) at **29 pages** (was 28 after
  M7-15 — see Risks, page-count gap widening again).

`make test` (1779 passed, incl. 21 new `detection.multiclass` tests) and `make lint` (ruff + mypy
--strict on `src/`) green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | this session adds `detection/multiclass.py` + one new function in `detection/dataset.py`; fixes a bug in existing `grouped_stratified_holdout` |
| Honeypot poisoning: attack + three independent defenses (M7-11/12/14/15) | done | unchanged this session |
| Multi-family detection (M7-16) | done | binary detector (`detection/detector.py`, `models.py`, `metrics.py`) untouched — new module only |
| Real-malware transfer evaluation | done, 3 datasets | unchanged this session |
| `docs/report/report.pdf` | done, 29 pages | extended this session, recompiles clean via `tectonic` |
| Everything else (M7-1 through M7-15's own deliverables) | done | unchanged |

## Next task

None forced. If a future session wants to act on this one's own findings, in order of interest:

1. **The FT_RW/honeypot family-label gap** (M7-16's own finding): the synthetic honeypot
   generator (`honeypot/collector.py`/`features.py`) produces only `RW`/`benign`, no family. A
   future session could design a family-labelled extension of the generator — explicitly out of
   scope for M7-16 itself.
2. **A coordination mechanism for disagreement** (carried from M7-15): a protocol for acting on a
   federated-detection flag (e.g. feeding into `mitigation/` or a pBFT-level exclusion) — the
   paper specifies nothing here and M7-15 built the signal, not the response.
3. Close the report's page-count gap (29pp vs. the original <20pp target, widened again this
   session) — ranked options in `sessions/2026-09-26-03-report-restructure-and-ember-check.md`.

## Blockers

None. `data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

**Standing limitation, not a blocker:** CICMalDroid-2020 and MalwareBazaar/Triage remain unusable
by any future session unless the user personally creates the relevant account or submits the
access request (carried, unchanged).

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length (29pp) acceptable for submission, or does it need the deeper,
substance-costing cuts `sessions/2026-09-26-03-...md` describes? Now three sessions further from
the original <20pp target than when Q11 was first opened. | report sign-off | reviewer/instructor judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 + M7-6 tested eight hypotheses, narrowed the gap to 1.51pt; report states the residual as measured-and-bounded |
| M7-16's binary-collapse falling slightly *below* the binary-only reference could be read as "multi-class training hurts detection" | overstates a <1pt difference as a regression | RESULTS.md/DEVIATIONS.md/report all state it as "a wash, not a regression" with the exact deltas shown, never rounded to "worse" |
| The report is 29 pages, not the requested under-20 (widened from 26pp two sessions ago) | a page-limited venue/rubric may reject it as-is | PROJECT_STATE.md/session files state the finding and ranked options honestly rather than silently shipping either an over-length report or one hollowed out to hit a number |
| Two Claude Code sessions ran on this repo concurrently during M7-10; nothing currently prevents this from happening again | a future concurrent session's edits could silently clobber or duplicate content | no fix implemented — flagging as a standing risk; re-read a file immediately before writing to it if a long gap occurred since it was first read |

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
session. A 200-line file costs seconds. Left to grow — the natural drift, since appending is
easier than pruning — it becomes a few thousand lines of mostly-resolved history, gets skimmed
instead of read, and stops working precisely when the project is complex enough to need it.
Pruning it is part of the task, not cleanup after the task.

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
