# Session 2026-09-27-03 — M7-16 multi-family ransomware detection

**Milestone:** M7-16 (stretch, post M7-15) · **Files read at start:** `CLAUDE.md`,
`PROJECT_STATE.md`, `docs/EXPERIMENTS.md` Targets 1-2, `RESULTS.md` M4a/M6b lines,
`docs/ARCHITECTURE.md` §detection, `configs/ml.yaml`, `src/bsfr_sh/detection/dataset.py`,
`models.py`, `metrics.py`, `scripts/run_detection.py`, `scripts/m7_15_federated_detection.py` ·
**Duration:** ~2h (incl. a latent full-scale performance bug found and fixed)

---

## Brief *(written before any work)*

**Task:** Test whether BitcoinHeist's 28 ransomware family labels (plus benign) are
distinguishable from the same 8 address-level graph features the binary detector uses — a
multi-class extension of the existing detection pipeline, not a new dataset or a new module
layer.

**Exit condition:** `make test`/`make lint` green; multi-class results (macro F1, weighted F1,
top-3 accuracy) for all four models measured and in `RESULTS.md`; per-family analysis (recall,
most-confused-with, feature signal) for every family with ≥100 samples; a 19×19 (after rare-family
merge) confusion matrix emitted as a figure; binary-collapse comparison against the existing
full-scale honest_mode binary result in `RESULTS.md`; report extended with a new Detection
Analysis subsection; `PROJECT_STATE.md` rewritten, `docs/ROADMAP.md` M7-16 ticked, session file
completed, committed and pushed.

**Out of scope:** No changes to `honeypot/features.py` or the synthetic generator (`FT_RW` stays
family-less — this session only documents that as a finding). No family-specific mitigation
logic in `mitigation/`. No retraining the honeypot detector on family labels.

**Prior context needed:** `docs/DEVIATIONS.md` DEV-06/D6 (grouped-split methodology this session
reuses via `detection.dataset.grouped_stratified_holdout`, which already generalises to
multi-class since it loops per label value), M6b's full-scale honest_mode RF numbers
(`prec=0.7434 rec=0.2874 mcc=0.4579 f1min=0.4145`, the binary-collapse comparison target), and
DEV-31's KNN-memory-projection precedent (`largest_feasible_n`) this session follows rather than
re-deriving.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. [Full M7-16 task brief: multi-family ransomware detection over BitcoinHeist's 28 named
   families + white, testing whether the feature space carries family-discriminative signal
   beyond binary ransomware-vs-benign — dataset prep with rare-family merge (<10 samples ->
   other_ransomware), RF/DT/KNN/LR-OvR multi-class models, macro/weighted F1, per-family
   precision/recall/confusion/top-k, binary-collapse comparison against honest-mode, per-family
   feature-importance analysis for families >=100 samples, a note on the FT_RW/honeypot gap
   (no family labels in the synthetic pipeline), report write-up, RESULTS.md/PROJECT_STATE.md/
   ROADMAP.md/session-file update, commit and push. Full text as given by the user.]
```

---

## What was done

- `src/bsfr_sh/detection/dataset.py` (AI-generated): added `FamilyDataset` + `load_bitcoinheist_families` —
  the family-preserving sibling of `load_bitcoinheist`, same read path/count verification, target
  is the raw family string instead of a binarized label. Also fixed two bugs in the existing
  `grouped_stratified_holdout` (see Findings) — the only change to previously-shipped code this
  session made.
- `src/bsfr_sh/detection/multiclass.py` (AI-generated, new module): `merge_rare_families`,
  `build_multiclass_model(s)` (RF/DT/KNN unchanged, LR wrapped in `OneVsRestClassifier`),
  `fit_and_score_multiclass`, `macro_f1`/`weighted_f1`, `per_class_report`/`confusion`/
  `most_confused_with`, `top_k_accuracy`, `binary_collapse`, `per_family_feature_signal`.
- `scripts/m7_16_multiclass_detection.py` (AI-generated, new): full pipeline mirroring
  `run_detection.py`'s conventions — KNN memory projection/fallback (DEV-31 precedent), sidecar
  JSON, RESULTS.md-ready lines, confusion-matrix figure.
- `tests/unit/test_detection_multiclass.py` (AI-generated, new): 21 tests — merge correctness,
  model wrapping, metrics (macro/weighted F1, per-class report, most-confused-with, binary
  collapse, top-k), `per_family_feature_signal`, and three real-data invariant checks (skip when
  the raw CSV is absent, matching `test_detection_dataset.py`'s convention).
- `docs/report/report.tex` (AI-generated): new `\subsection{Multi-Family Ransomware Detection}`
  under Detection Analysis, with the confusion-matrix figure and a binary-collapse table.
  Recompiles clean (tectonic), 29 pages.
- `RESULTS.md`, `docs/DEVIATIONS.md` (DEV-42), `docs/ROADMAP.md`, `PROJECT_STATE.md` updated.

## Findings

- **Class imbalance is severe and worth reporting before any model runs**: `white`=2,875,284
  (98.58%), largest family `paduaCryptoWall`=12,390, three families with exactly 1 address. 11 of
  28 families under 10 samples, merged into `other_ransomware`; 19 classes survive.
- **Macro F1 is weak (0.058-0.199), not strong** — decision tree best, narrowly over random
  forest. Weighted F1 and top-3 accuracy are both dominated by `white`'s share and are not
  informative about family discrimination on their own; this is worth stating explicitly since
  both look deceptively high (0.98+/0.99+).
- **Confusion is one-sided, not inter-family**: every family's dominant misclassification target
  is `white`, never another family. The model fails by defaulting to "benign", not by mixing up
  CryptoLocker for CryptoWall — a materially different (and more encouraging, for the "is family
  ID meaningful" question) finding than "families all look alike."
- **Per-family feature importance is dominated by `year`/`income` for every large family** — read
  as a caveat, not a clean win: each family's activity is a narrow historical campaign window, so
  this plausibly detects *when* a campaign ran more than *how* it behaves on-chain. Stated
  explicitly rather than presented as "the graph features distinguish families."
- **Binary-collapse does not quite meet the brief's own expectation** ("should match or exceed"):
  RF and DT both land marginally *below* their published binary-only M6b numbers, under 1 point on
  every metric. Reported as a wash, not forced into either a win or a regression framing —
  consistent with CLAUDE.md §2's "never claim a number we did not measure."
- **Dead end / real bug, not a design choice**: `grouped_stratified_holdout`'s `np.isin` call
  hung indefinitely (killed after 10+ minutes) the first time it was ever run against the full
  2.9M-row `white` class — every prior use (Q10/D6/M6b) only ever exercised it on the 46K-row
  `paper_mode` resample, so this was a latent bug, not something introduced this session. Root
  cause confirmed by an isolated benchmark (object-dtype `np.isin` does not take numpy's
  sorted/hashed fast path) before touching the fix, so the fix targets the actual cause rather
  than a guess. Fixed with a Python hash-set membership test.
- **Second dead end, found only after the first fix**: with the split now fast, the *first* full
  run crashed inside `top_k_accuracy_score` — `y_true contains labels not in parameter 'labels'`.
  Traced to two families (`montrealRazy`, `montrealGlobeImposter`) each confined to exactly one
  address: a single-group class cannot be split, and the existing `cut` arithmetic could put it
  entirely in test, leaving the model with zero training exposure to that class. Fixed by
  reserving at least one group for training whenever more than one exists.
- **Both `grouped_stratified_holdout` fixes are scoped to verify they cannot silently change a
  published number**: re-ran `tests/unit/test_detection_dataset.py` unchanged after each fix (all
  green), and reasoned explicitly that both edge cases require a class with very few unique
  groups — never true for the binary paper_mode/honest_mode splits (thousands of groups per class
  there).
- **A real bug in this session's own new code, found by writing the test before trusting the
  implementation**: `merge_rare_families` truncated `"other_ransomware"` to `"other"` when the
  input array was a numpy fixed-width string array (not object dtype) — a synthetic-data test
  artifact that would not have surfaced from the real pipeline (pandas hands back object dtype),
  but is a genuine robustness gap in the function as written. Fixed by working in `dtype=object`.
- **LR one-vs-rest did not need Ada**: full 2.9M-row, 19-class OvR fit in 74.07s locally — well
  under the brief's expectation that it might need the cluster. KNN did need the established
  DEV-31 fallback (projected 15.70 GB against the 8 GB ceiling; ran on a 1,248,537-row subsample
  instead, 1.19 GB peak).

## Numbers

Full run: `results/logs/20260927T071228Z-8d52159c.json` (seed 20260912, `--full`, 2,916,697 rows).
Dry-run at the configured 200K subsample: `results/logs/20260927T065605Z-ff9f662b.json` (kept for
provenance, superseded by the full run for every reported number). Both appended to `RESULTS.md`
under "Multi-family ransomware detection (M7-16)" — full model-by-model figures, the binary-collapse
comparison table, the KNN projection numbers, and the two `grouped_stratified_holdout` fixes are
documented there rather than repeated here.

## Deviations opened or changed

- DEV-42 (new): multi-family ransomware detection — weak real signal, confusion concentrated on
  the ransomware/benign boundary not inter-family, binary-collapse a wash not a win, the FT_RW gap
  named as a real (not moot) finding, and the two `grouped_stratified_holdout` bug fixes.

---

## Handover *(written last)*

**State after:** M7-16 delivered. `detection/multiclass.py` and
`scripts/m7_16_multiclass_detection.py` are new; `detection/dataset.py` has one new function
(`load_bitcoinheist_families`) plus two bug fixes to the existing `grouped_stratified_holdout`
(hash-set membership instead of `np.isin`; reserve one group for training). No existing module's
previously-published numbers changed — confirmed by re-running `test_detection_dataset.py`
unchanged. Report is 29 pages (was 28), compiles clean.

**Next task:** None forced. If a future session wants to act on this one's own finding: design a
family-labelled extension of the honeypot generator (`honeypot/collector.py`/`features.py`) — M7-16
found the gap (no family field in `FT_RW`) but explicitly left the generator untouched, per its own
out-of-scope line.

**New blockers:** None.

**Questions opened / closed:** Q11 (report length) reopened at 29pp, one session further from the
original <20pp target — not closed, same standing risk as M7-14/M7-15 left it, now slightly wider.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated if the paper was departed from
- [x] Committed, message explains *why*
