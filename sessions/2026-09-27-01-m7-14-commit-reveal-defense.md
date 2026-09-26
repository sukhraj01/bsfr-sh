# Session 2026-09-27-01 — M7-14: commit-then-reveal defense against honeypot poisoning

**Milestone:** M7-14 · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/THREAT_MODEL.md` (Gap 1, M7-11/M7-12 sections, Trust Assumptions 6-7), `RESULTS.md` M7-11
and M7-12, `docs/ARCHITECTURE.md` §consensus, `src/bsfr_sh/detection/poisoning.py`,
`src/bsfr_sh/consensus/validated_commit.py`, `src/bsfr_sh/consensus/pbft.py` (`Cluster`),
`src/bsfr_sh/framework/_block_pipeline.py`, `src/bsfr_sh/blockchain/transaction.py`
(`SignatureRecordPayload`), `src/bsfr_sh/crypto/hashing.py`, `src/bsfr_sh/util/serialization.py`,
`scripts/m7_11_honeypot_poisoning.py` · **Duration:** long

---

## Brief *(written before any work)*

**Task:** build and measure a protocol-level commit-then-reveal defense that removes the
adversary's ability to see the honest distribution before crafting anchor-point-injection
poisoning, since M7-12's statistical drift detection provably cannot catch that strategy for
exactly that reason.

**Exit condition:** `make test`/`make lint` green; a comparison table against all 15 of M7-11's
(strategy, budget) cells under commit-reveal vs. direct submission; all three named failure modes
(repeated-round estimation, collusion bound, withholding) measured or argued; a combination
experiment with M7-12's drift detector; `RESULTS.md` lines for every cell; report updated.

**Out of scope:** changing M7-11's attack code (`detection/poisoning.py`); changing the detector
or the honeypot generator; smart contracts or a separate on-chain commitment mechanism.

**Prior context needed:** M7-11 (DEV-37, the three strategies and their budget-sweep numbers),
M7-12 (DEV-38, `detection/drift.py` + `consensus/validated_commit.py`, and specifically *why*
anchor-point injection is undetectable by batch-level statistical drift — its engineered midpoint
sits at the population mean). `docs/ARCHITECTURE.md` §consensus for how `Cluster.__init__`'s
`chain_factory` hook already exists (M7-12 added it) and is the integration point this session
reuses rather than duplicating.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/THREAT_MODEL.md
   (Gap 1, M7-11 attack results, M7-12 defense results), RESULTS.md M7-11 and
   M7-12 lines, docs/ARCHITECTURE.md §consensus.

   Create the session file from the template and fill the brief first.

   TASK — M7-14. Commit-then-reveal defense against honeypot poisoning.
   [full brief: two-phase commit/reveal/merge protocol over Sig_RW/FT_RW batches;
   consensus/commit_reveal.py implementing CommitPhase/RevealPhase/MergePhase; config-flag
   integration wrapping the existing block pipeline; evaluation against M7-11's 15 cells with the
   adversary constrained to a historical-only view; three failure modes (repeated-round
   re-estimation, collusion bound tied to pBFT's f<n/3, withholding/exclusion); a combination
   experiment with M7-12's drift detector; report write-up; DEV entry; THREAT_MODEL.md update;
   PROJECT_STATE.md rewrite; tick M7-14; commit and push. Full text as given in the task message.]
```

---

## What was done

- **`src/bsfr_sh/consensus/commit_reveal.py`** (new): `Commitment`/`Reveal`/`CommitRevealRound`
  (Phases 1-2 — commit `H(batch || blinding_factor)` over the entire batch via
  `SignatureRecordPayload.to_bytes()`, then reveal-and-verify; a node that withholds or reveals a
  mismatch is excluded, reported not raised) and `WithholdTracker` (permanent exclusion after
  `max_consecutive_withholds`, default 3). Depends only on `crypto`/`blockchain`/`util` —
  `consensus/validated_commit.py`'s dependency on `detection/` remains the one named exception to
  CLAUDE.md §3, not widened. AI-generated.
- **`src/bsfr_sh/framework/commit_reveal_pipeline.py`** (new): `submit_with_commit_reveal` — the
  Phase-3 wrapper that calls `_block_pipeline.run` unmodified on the merged, verified batch. Lives
  in `framework/`, not `consensus/`, specifically because `consensus/` may not import `framework`
  (`tests/unit/test_module_boundaries.py::test_nothing_below_framework_imports_it` — discovered by
  writing the module in `consensus/` first, running the test suite, and getting a hard failure;
  see Findings). AI-generated.
- **`configs/chain.yaml`**: added `consensus.commit_reveal.{enabled, max_consecutive_withholds}`.
  AI-generated.
- **`tests/unit/test_commit_reveal.py`** (new, 22 tests) and
  **`tests/integration/test_commit_reveal_pbft.py`** (new, 1 test): protocol-level correctness
  (commitment tamper detection, exclusion reasons, canonical merge, honest-case equivalence to
  direct submission, `WithholdTracker` streak/reset/permanent-exclusion) and one real-pBFT
  round-trip proving a withheld/crashed node's batch is excluded while the honest batch still
  commits through unmodified consensus at `n=4, f=1`. AI-generated.
- **`scripts/m7_14_commit_reveal_defense.py`** (new): the full evaluation — 15-cell defended-vs-
  undefended sweep (adversary constrained to an 85%-historical view), a 15%-historical sensitivity
  check, an 8-repeat robustness check, 10 sequential rounds, a withholding simulation, and a
  combination experiment reusing M7-12's own `DriftDetector`. AI-generated.
- **`docs/DEVIATIONS.md`** (DEV-40), **`docs/THREAT_MODEL.md`** (Gap 1 subsection + Trust
  Assumption 8), **`docs/ARCHITECTURE.md`** §consensus, **`docs/ROADMAP.md`**, **`RESULTS.md`**,
  **`docs/report/report.tex`** (new §"Commit-Then-Reveal: A Protocol-Level Defense" plus
  abstract/intro/conclusion updates) all updated. AI-generated.
- **`PROJECT_STATE.md`** rewritten (see below).

## Findings

- **Dead end, cost real time: `consensus/commit_reveal.py` cannot call `_block_pipeline.run`
  directly.** First draft put `submit_with_commit_reveal` inside `consensus/commit_reveal.py`,
  importing `framework._block_pipeline`. `make test` failed immediately on
  `test_nothing_below_framework_imports_it` — `consensus/` sits below `framework/` in this
  project's dependency direction, and `consensus/validated_commit.py`'s dependency on
  `detection/` is already the one named, deliberate exception to "consensus depends only on
  crypto/blockchain" (CLAUDE.md §3); this would have been a second, undocumented one. Fixed by
  moving the pipeline-wrapping function to a new `framework/commit_reveal_pipeline.py` — the
  protocol primitives stay in `consensus/`, the one function that touches the pipeline moves one
  layer up. Recorded so a future session does not rediscover this by the same route.
- **Dead end, a genuine test-harness mistake, not a protocol bug: the first real-pBFT integration
  test run timed out with `1 of 1 requests uncommitted after 64s`.** Debugging (replica rejection
  logs showed a cascading view-change cycle, height stuck at 0) traced to passing
  `timestamp=0.0` to `submit_with_commit_reveal`, before `pbft_harness.GENESIS_TIME` (1000.0) —
  `Chain.check_append`'s timestamp-skew tolerance silently rejected every proposal, and no replica
  ever prepared anything. Fixed by using `GENESIS_TIME` explicitly. Verified the bug was in the
  test, not the new code, by reproducing the identical failure with `_block_pipeline.run` called
  directly (bypassing commit-reveal entirely) before touching a single line of the new module.
- **The central empirical finding, and the one worth remembering longest: commit-reveal's
  measured protection against anchor-point injection is statistically indistinguishable from
  zero, on this project's specific corpus, for a reason that is itself informative.**
  `honeypot.collector`'s ransomware/benign profiles are stationary, low-dimensional (22-feature)
  parametric mixtures (DEV-27) — a historical sample of only ~106 positive rows (the 15%-historical
  sensitivity check) already estimates the population centroid almost as precisely as the full
  ~700-row corpus would. The defense's own motivating premise ("the adversary must guess the
  boundary, and a wrong guess is ineffective or detectable") is logically sound but does not bind
  in this specific numerical regime, because centroid estimation from a stationary distribution
  converges fast relative to the sample sizes this corpus actually has. An 8-repeat robustness
  check confirmed this was not one lucky/unlucky random split before it was written up as a
  finding rather than dismissed as noise.
- **A prediction made and confirmed, not just observed after the fact**: before running the
  defended sweep, the module docstring for `run_low_history_sensitivity`/`run_anchor_point_
  robustness` was written stating the expectation that `label_flip`/`feature_poison` would show
  *larger, noisier* `damage_prevented` swings than `anchor_point_injection`, purely from
  historical-pool-restriction sampling noise, since neither strategy needs to see the current
  round's honest data to operate at all (label_flip relabels the adversary's own collected
  samples; feature_poison resamples from whatever benign pool it has). The measured numbers
  confirmed this exactly (label_flip/feature_poison swung as far as -0.0325 in one run;
  anchor_point_injection never exceeded 0.006 in the canonical run). Recorded because a prediction
  that holds is worth as much as one that fails — this session's design reasoning was checkable,
  and checked.
- **`hash(strategy) % 1000` (M7-11's/M7-12's own seeding convention for a per-strategy RNG offset)
  is not reproducible across process invocations** — Python's string `hash()` is
  `PYTHONHASHSEED`-randomized per process, and `util/seeding.py`'s own docstring already states
  that setting `PYTHONHASHSEED` mid-run does not fix this. Confirmed by running this session's
  first draft twice and observing different numbers both times. Not a bug in M7-11/M7-12 worth
  reopening (their own published numbers are each tied to one cited `run_id`, the project's
  existing convention for exactly this situation) — but this session's own new script replaced the
  pattern with a fixed `_STRATEGY_SEED_OFFSET` dict, verified byte-identical across two full runs
  before any number was written into `RESULTS.md`/DEV-40.

## Numbers

All appended to `RESULTS.md` "M7-14" section; sidecar `results/logs/20260926T210819Z-1c0db7c7.json`.

- Baseline: bal_acc=0.8408 (reproduces M7-3/M7-11).
- 15-cell sweep (85% historical): `anchor_point_injection` `damage_prevented` +0.0026 to +0.0056
  (all within a hundredth of a point); `label_flip`/`feature_poison` swing -0.0272 to +0.0610
  (sampling-pool noise, predicted in advance — see Findings).
- 15%-historical sensitivity check (anchor-point only): -0.0103 to +0.0094 — same null pattern
  with an order of magnitude less historical data.
- 8-repeat robustness check (anchor-point only): mean `damage_prevented` -0.0013 to +0.0055,
  std 0.0010-0.0034 at every budget — zero inside one standard deviation throughout.
- 10 sequential rounds: bal_acc 0.8037-0.8384, no monotonic trend (confounded by corpus growth,
  stated as a limitation).
- Withholding: an always-withholding adversary permanently excluded at exactly round 3 of 6,
  matching the configured `max_consecutive_withholds=3`.
- Combination with M7-12: all 15 cells `newly_detected=False`; defended anchor-point Mahalanobis
  scores 0.0118-0.0169 vs. undefended 0.0078-0.0162, both ~2 orders of magnitude below the 3.0
  alarm threshold.

## Deviations opened or changed

- **DEV-40 (new)**: commit-then-reveal protocol (design, integration, config flag), the
  information-constraint modelling methodology, the 15-cell sweep + sensitivity + robustness +
  repeated-rounds + withholding + combination results, and the honest verdict (protocol correct,
  measured protection null on this corpus, why).

---

## Handover *(written last)*

**State after:** M7-14 delivered. Honeypot poisoning (Gap 1) now has two independent, measured
defenses on record: M7-12's statistical drift detector (catches composition-driven batches,
misses anchor-point) and M7-14's protocol-level commit-reveal (correctly built and verified,
measured-null effect on anchor-point specifically, on this corpus). `configs/chain.yaml` carries
the commit-reveal config flag; `consensus/commit_reveal.py` and
`framework/commit_reveal_pipeline.py` are real, tested, reusable modules — not a one-off script.
`make test-all` (1746 passed) and `make lint` both green. Report recompiles clean at 26 pages
(+1 from M7-13's 25, a small, content-driven increase, not a regression).

**Next task:** None forced. If a future session wants to test whether commit-reveal's protection
*can* bind on a different corpus (the natural follow-up this session's own null result points
at), the specific next step is: construct or identify a corpus with genuine concept drift, higher
feature dimensionality relative to sample size, or a much smaller absolute historical sample than
the ~106+ positive rows tested here, and re-run `scripts/m7_14_commit_reveal_defense.py`'s sweep
logic (reusable as-is) against it. This is a new experiment, not a fix — this session's own
`consensus/commit_reveal.py` needs no changes to support it.

**New blockers:** None.

**Questions opened / closed:** None of `PROJECT_STATE.md`'s prior open questions (Q11, now at
26pp) are resolved by this session; no new numbered question opened — the "test on a different
corpus" idea is recorded as a **Next task** suggestion, not a blocking question, since nothing
currently shipped depends on it.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated (DEV-40)
- [x] `docs/THREAT_MODEL.md` updated with the defense and its trust assumptions (Gap 1 subsection
      + Trust Assumption 8)
- [x] Committed (`629f3d0`) and pushed to `origin/main`, message explains *why*
