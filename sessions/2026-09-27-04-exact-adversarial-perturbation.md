# Session 2026-09-27-04 — exact minimum adversarial perturbation (M7-17)

**Milestone:** M7-17 · **Files read at start:** CLAUDE.md, PROJECT_STATE.md, RESULTS.md M7-3
section, docs/DEVIATIONS.md DEV-27, `detection/adversarial.py`, `detection/profiles.py`,
`detection/detector.py`, `configs/ml.yaml`, `scripts/run_adversarial_robustness.py`,
`tests/unit/test_detection_adversarial.py`, RESULTS.md M7-8 section · **Duration:** single session,
2026-09-27

---

## Brief *(written before any work)*

**Task:** Replace M7-3's binary-search minimum-perturbation approximation with an exact (tree
components) / near-exact (full four-model ensemble) computation, and report how much the
approximation error mattered for M7-3's and M7-8's conclusions.

**Exit condition:** `make test` and `make lint` green; exact/near-exact minimum perturbation
computed for all 353 positive eval rows; updated percentiles appended to `RESULTS.md` next to
M7-3's; a histogram-comparison figure emitted; report extended.

**Out of scope:** no neural-model (MLP) perturbation; no changes to `honeypot/collector.py` or
`detection/detector.py`; no new adversarial-retraining *budgets* (M7-8's existing 0/25/50/100%
hardened models may be re-measured with the new method, not retrained differently).

**Prior context needed:** M7-3 (`RESULTS.md`, this file's numbers), M7-8 (`RESULTS.md`, the
25%-backfire / bound-memorisation findings), `detection/adversarial.py` (the exact mechanism
being tightened), DEV-27 (why `FT_RW` looks the way it does — not directly relevant to the
method but explains the feature names in the bounds table).

**Key finding already visible before writing code:** the session brief's method (§1) is written
for a pure random-forest classifier ("100 trees... the minimum perturbation that flips the
MAJORITY vote"). `DM_CSl`'s actual decision (`detection/detector.py::DetectionModule.decide`,
confirmed via `scripts/run_adversarial_robustness.py`'s own docstring: "the ensemble, not a
single model's `.predict()`") is nearest-`NProf`/`AProf`-membership on the soft-vote average of
**four** heterogeneous models (`random_forest`, `decision_tree`, `logistic_regression`,
`k_nearest_neighbours`), not a random-forest-only majority vote. This changes what "exact" can
mean for the *published* metric M7-3/M7-8 report (see Findings / DEV-43 below).

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: RESULTS.md M7-3
lines (binary search adaptive evasion: median 32%, 10th percentile,
90th percentile), docs/DEVIATIONS.md DEV-27.

Create the session file from the template and fill the brief first.

TASK — M7-17. Exact minimum adversarial perturbation via constrained
optimization.

M7-3's adaptive evasion used binary search over the L-inf ball to find the
minimum perturbation that flips each positive sample. Binary search
approximates -- it converges to within a tolerance but doesn't guarantee
the true minimum. This session replaces the approximation with exact or
near-exact solutions.

WHY THIS MATTERS
The 10th percentile (the fraction of ransomware trivially evadable) is the
number an examiner remembers. If binary search says 5% and the exact answer
is 3%, the detector is more robust than M7-3 claimed. If it's 8%, less. The
bounds matter for whether adversarial retraining (M7-8) is worth its
clean-accuracy cost.

IMPLEMENTATION

1. Tree-ensemble-specific exact solution.
   Random forest predictions are piecewise constant -- the feature space is
   partitioned into axis-aligned hyperrectangles, each with a fixed
   prediction. Finding the minimum perturbation that changes a prediction
   is finding the nearest hyperrectangle with a different label.

   For a single decision tree, this is exact and fast: walk the tree's
   decision path for the sample, identify the closest split threshold on
   each of the top-5 features, and the minimum perturbation on that
   feature is the distance to that threshold (plus epsilon).

   For a random forest (ensemble of trees), the minimum perturbation
   that flips the MAJORITY vote is harder -- it's the minimum perturbation
   that flips enough individual trees. This is NP-hard in general, but
   for the project's small forest (100 trees, 22 features, ~1500 training
   samples) it's tractable via:

   a) Per-tree minimum perturbation (exact, fast): for each tree, find
      the minimum perturbation to flip that tree's prediction.
   b) Sort trees by their flip cost.
   c) The minimum ensemble perturbation flips the cheapest ceil(n_trees/2)
      trees. This is a greedy approximation -- not exact for the ensemble,
      but exact per tree and tighter than binary search.

   If (c) is too loose, implement:
   d) Mixed-integer programming (MIP) formulation: encode each tree's
      decision path as linear constraints, the ensemble vote as a sum,
      and minimize the L-inf perturbation subject to the vote flipping.
      Use scipy.optimize.milp or PuLP. At 100 trees x 22 features this
      is a small MIP -- solvable in seconds per sample.

2. Run on all positive eval samples.
   For each of the ~350 positive samples in the eval corpus:
   - Compute the exact (or tighter) minimum perturbation
   - Compare to M7-3's binary-search result for the same sample
   - Record both values

3. Analysis.
   Report:
   - Updated 10th / median / 90th percentile minimum perturbation
   - Per-sample delta between exact and binary-search results
   - How many samples' binary-search result was >=10% loose?
   - Updated histogram of minimum perturbations
   - Whether any sample that M7-3 classified as "never flips" (the 28/353)
     actually does flip under exact computation -- binary search can miss
     a narrow flip region

   Overlay the exact histogram on M7-3's binary-search histogram. The
   visual shows how much the approximation error matters.

4. Implications for M7-8.
   Re-examine M7-8's adversarial retraining results using the exact
   perturbation bounds:
   - Does the 25%-budget backfire still hold with exact perturbation?
   - Does the "memorizes the evasion boundary" finding change?
   - Recompute the Pareto curve (clean accuracy vs robustness) if the
     perturbation bounds shifted meaningfully

5. Write it up.
   Extend the adversarial robustness section. Structure:
   - Why exact bounds matter (one paragraph on binary search's limitation)
   - Method: per-tree exact solution, ensemble greedy or MIP
   - Updated percentiles vs M7-3's approximation
   - The histogram comparison
   - Whether any "never-flips" sample actually flips
   - Implications for M7-8's retraining conclusions
   - One paragraph: the exact bounds are tighter but do/don't change the
     qualitative finding (state which)

TESTS
Per-tree minimum perturbation is exact: applying it flips exactly that
tree's prediction (verify for every tree on every sample, not a subset).
The ensemble greedy solution flips the majority vote (verify). The exact
perturbation is <= the binary-search perturbation for every sample (it's
a tighter bound -- if any sample violates this, there's a bug). Samples
with perturbation 0 in both methods have identical predictions under both.

EXIT CONDITION
make test and make lint green. Exact perturbation computed for all positive
eval samples. Updated percentiles in RESULTS.md alongside M7-3's values.
Histogram comparison figure emitted. Report updated.

OUT OF SCOPE
No neural model perturbation (M7-10's MLP uses different decision surfaces).
No changes to the generator or detector. No new adversarial retraining runs
unless the bounds shift by >=5 percentage points.

END OF SESSION
Session file. Rewrite PROJECT_STATE.md. Tick M7-17. Commit and push.
```

---

## What was done

- `src/bsfr_sh/detection/exact_adversarial.py` (new, AI-generated). `tree_flip_t` (exact per-tree
  minimum perturbation via decision-path walking, re-deriving the path after every threshold
  crossing), `lr_flip_t` (closed-form for `logistic_regression`'s affine-in-`t` decision), 
  `per_tree_costs`/`greedy_majority_t`/`verify_greedy_majority_flip` (the brief's §1b-c greedy
  approximation, kept and labelled but not used for the published result), `exact_min_perturbation`
  (the composite: real breakpoints merged with a dense grid, bisected to `1e-6`).
- `tests/unit/test_detection_exact_adversarial.py` (new, AI-generated). Exhaustive per-tree
  exactness check (every tree, every sampled row, per the brief's TESTS section), a synthetic
  closed-form check for a single split and for the LR hyperplane, the greedy-majority invariant
  split into a controlled-monotonic-stumps test (passes) and a real-forest test (documents the
  failure honestly, see Findings), the exact-never-exceeds-binary-search invariant, and the
  zero-perturbation-matches-original-prediction case.
- `scripts/m7_17_exact_min_perturbation.py` (new, AI-generated). Reproduces M7-3's baseline,
  runs both methods on all 353 positive eval rows, checks the never-looser invariant (hard-fails
  otherwise), rechecks M7-3's 28 survivors, emits the histogram figure, re-measures M7-8's three
  hardened models with the same exact method, and adds a stability diagnostic (does a flip stay
  flipped to `t=1.0`, or revert — and if it reverts, how wide is the window).
- `RESULTS.md` (M7-17 section), `docs/DEVIATIONS.md` (DEV-43), `docs/ROADMAP.md` (ticked),
  `docs/report/report.tex` (new §"Exact Minimum Adversarial Perturbation", §\ref{sec:m7-17}, one
  new figure) — all AI-generated, human-reviewed via this transcript.

## Findings

**The brief's method assumed a pure random-forest classifier; `DM_CSl` is a four-model ensemble.**
Discovered before writing code by rereading `run_adversarial_robustness.py`'s own docstring. Had
to design around it rather than literally implement §1's MIP/greedy machinery as the published
metric — see DEV-43 for the full resolution (exact for 3 of 4 models, dense-grid-bounded for
`k_nearest_neighbours`).

**Two real bugs in the first implementation of `tree_flip_t`, both dead ends worth recording so a
future session does not re-derive them:**
1. Reporting the algebraic threshold crossing itself as the flip point is wrong — sklearn's `<=`
   routes left exactly at a threshold, so nothing has "crossed" yet. Caught immediately by the
   brief's own exhaustive-verification test requirement (applying the reported `t` and checking
   `.predict()` actually changed) on the very first run.
2. Even after nudging past the crossing, a *tiny* nudge (`1e-9` in `t`-space) can be swallowed by
   sklearn's internal float32 cast of `X` before the compiled tree traversal compares it to the
   (float64) threshold — for large-magnitude thresholds a `1e-9` step is far smaller than
   float32's ~1.2e-7 relative rounding. Fixed by reproducing the cast in `goes_left` and nudging
   in feature-value space (proportional to the threshold's magnitude) rather than `t`-space.
   Neither bug would have been caught by a coarser test that only checked a handful of samples —
   the brief's insistence on "every tree on every sample" is why they surfaced.

**The greedy majority-vote heuristic (§1c) is confirmed unsound on the real forest, not just a
theoretical caveat.** Measured directly: 5-12 of the ~50 trees selected as "cheap enough to have
flipped by `t_star`" had flipped *back* by `t_star` on 5 sampled rows — real, multi-level trees
split on a moving feature more than once along a path, so "once flipped, stays flipped" does not
hold. Kept the function (the brief asks for it), rewrote its test to measure this honestly instead
of asserting a guarantee it cannot make.

**The approximation error was small for the original model; M7-3's conclusions hold.** Exact
median 0.3063 vs. 0.3213 (-1.5pt). None of the 28 "never flips" survivors actually flip.

**The session's central finding: M7-8's 100%-budget "never flips" claim needed correcting, not
overturning — and almost reported wrong.** The first full run showed exact median 0.1905 vs.
binary search's 1.0 (an 81-point shift) with no further context, which read at first as "the
100%-budget model is dramatically less robust than M7-8 reported." Before trusting that, checked
it directly against the real ensemble (not the search machinery): 176 of 177 "flipped" rows
revert to the correct verdict one step later, median dip width 0.38% of the range. Built a
stability diagnostic (`_stability_diagnostics` in the script) and reran rather than publish the
raw number alone — the corrected finding (razor-thin, unexploitable windows, not a stable evasion
region) is evidence *for* M7-8's own "memorises the boundary" reading, not against it. This is the
kind of number CLAUDE.md §2 ("never claim a number we did not measure") is written to prevent:
the raw 0.19 *was* measured and *is* correct as literally defined, but reporting it without the
stability context would have been misleading in a way a reader could not detect from the number
alone.

**Report grew from 29 to 30 pages** — Q11 (open in `PROJECT_STATE.md`) widens again.

## Numbers

All appended to `RESULTS.md` under "M7-17" with full per-line detail; summary:

| | binary search | exact/near-exact | note |
|---|---|---|---|
| Original model | p10=0.000 median=0.321 p90=0.977 | p10=0.000 median=0.306 p90=0.975 | -1.5pt median |
| M7-8 @25% | median=0.2499 | median=0.2499 | shift 0.00pp — backfire unchanged |
| M7-8 @50% | median=0.8825 | median=0.8825 | shift 0.00pp — memorisation unchanged |
| M7-8 @100% | median=1.0000 | median=0.1905 | shift 80.95pp — 177/353 flip, 176 revert by t=1 (median dip width 0.38%) |

Original-model exactness: 65/353 (18.4%) proven-optimal; binary search >=10pp loose for 4/353
(1.1%). Wall time: exact search ~52s for 353 rows on the original model; full script (4 model
fits + all diagnostics) ~182s. Sidecar: `results/logs/20260927T171603Z-1d279ea9.json`.

## Deviations opened or changed

DEV-43 (ADD): full resolution of the ensemble-vs-random-forest mismatch, the two tree-traversal
bugs, the greedy-heuristic unsoundness, and the M7-8 100%-budget correction. `docs/DEVIATIONS.md`.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** M7-17 delivered. `detection/exact_adversarial.py` gives an exact/near-exact
minimum-perturbation method reusable by any future adversarial-robustness work on this detector.
The 100%-budget hardened model from M7-8 is now known to have a decision surface with ~177
razor-thin adversarial windows (median width 0.38% of the range) rather than being smoothly
robust — this is new information about that model, not a changed model.

**Next task:** None forced. If a future session wants to act on this one's own findings: (1) build
the stability-adjusted robustness metric this session flagged but did not build (minimum *stable*
perturbation, which would likely move the 100%-budget Pareto point further toward the robust end
than either the raw binary-search or raw exact number suggests); (2) if ever exact
`k_nearest_neighbours` bounds are wanted, the `O(n_train^2)` pairwise-crossing enumeration DEV-43
describes but does not implement is the way to get them, on a machine that can afford it (not this
8GB dev box — CLAUDE.md §6).

**New blockers:** None.

**Questions opened / closed:** Q11 (report length) not closed, widens further (29pp -> 30pp).

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated if the paper was departed from
- [x] Committed, message explains *why*
