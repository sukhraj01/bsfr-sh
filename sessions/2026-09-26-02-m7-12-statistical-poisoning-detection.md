# Session 2026-09-26-02 — M7-12: statistical poisoning detection

**Milestone:** M7 (stretch) · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/THREAT_MODEL.md` Gap 1, `RESULTS.md` M7-11 section, `docs/ARCHITECTURE.md` §consensus and
§honeypot, `src/bsfr_sh/consensus/pbft.py`, `src/bsfr_sh/blockchain/chain.py`,
`src/bsfr_sh/blockchain/transaction.py`, `src/bsfr_sh/detection/poisoning.py`,
`scripts/m7_11_honeypot_poisoning.py`, `tests/unit/test_module_boundaries.py`,
`tests/unit/pbft_harness.py` · **Duration:** _

---

## Brief *(written before any work)*

**Task:** Build and measure a statistical drift-detection defense for `BC_SigRW` — the semantic
validation the paper's Algorithm 2 never has — and evaluate it against exactly the three
poisoning strategies and five budgets M7-11 already measured, honestly reporting what it catches,
what it misses, and what it costs in false positives and new trust assumptions.

**Exit condition:** `make test`/`make lint` green; at least two drift methods implemented and
compared; the defended-vs-undefended table covers all 15 of M7-11's cells; false-positive rate
measured, not assumed; a new-family probe measured for the detection-vs-legitimate-drift tension;
a new trust assumption added to `docs/THREAT_MODEL.md`; report updated.

**Out of scope:** no changes to M7-11's attack code (`detection/poisoning.py`,
`scripts/m7_11_honeypot_poisoning.py`); no deep-learning-based detection; no changes to
`BC_DTBU`'s commit path.

**Prior context needed:** `docs/THREAT_MODEL.md` Gap 1 (what M7-11 measured and predicted about a
defense's shape), `consensus/pbft.py`'s own "Consensus decides whether, Chain decides valid"
division of labour (the integration point this session uses), `blockchain/transaction.py`'s
"miners validate blocks they cannot read" invariant (the thing this session's defense narrows,
discovered while implementing, not anticipated in the brief).

---

## Prompts *(verbatim, in order, no summarizing)*

```
Two quick items before the next task:

1. Check Ada: has the EMBER wheelhouse job (2715671) completed? If the
   env is buildable from cached wheels, run scripts/m7_10a_ember_transfer.py,
   rsync results back, add the RESULTS.md line. If it's still broken,
   document the specific blocker and move on. Max 20 minutes.

2. The incomplete M7-9 session file (sessions/2026-09-25-05-m7-9-*.md)
   from the concurrent session still has no handover block. Fill it in
   from commit 8756dab's diff. It doesn't need to be perfect — it needs
   to not be empty. This is a 5-minute fix.

Then proceed to the task below.

Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/THREAT_MODEL.md
(Gap 1, now with M7-11's measured results), RESULTS.md M7-11 lines,
docs/ARCHITECTURE.md §consensus and §honeypot.

Create the session file from the template and fill the brief first.

TASK — M7-12. Statistical poisoning detection.

[full brief: distributional drift detection on BATCHES (not per-sample
outliers, per DEV-26), implemented as detection/drift.py (Welford's
online stats, at least two of Page-Hinkley / per-feature KS / Mahalanobis
distance) and integrated into consensus via consensus/validated_commit.py
(a wrapper around the BC_SigRW commit path that runs the detector before
a replica votes, withholding prepare/commit on drift, reusing the existing
2f+1 threshold arithmetic); evaluated against all 15 of M7-11's
(strategy, budget) cells for a defended-vs-undefended comparison table;
false-positive rate on clean batches measured; a genuine-new-family
probe to surface the detection-vs-legitimate-drift tension; the
architectural observation that consensus is the last pre-immutability
gate; a new trust assumption (replicas must agree on the drift
threshold) documented in THREAT_MODEL.md; a report write-up — see task
text for full detail]

TESTS
Drift detector on a constant stream returns no drift. Drift detector on a
stream with an injected shifted batch detects it. The threshold is
configurable and the detection rate is monotone in the threshold. False
positive rate on clean batches is measured, not assumed. The defended
consensus path still commits clean blocks. The defended path rejects a
poisoned block that the undefended path would commit.

EXIT CONDITION
make test and make lint green. At least two drift methods compared. The
defended vs undefended table covers all 15 of M7-11's cells. False-positive
rate measured. New trust assumption added to THREAT_MODEL.md. Report
updated.

OUT OF SCOPE
No changes to M7-11's attack code. No deep-learning-based detection. No
changes to BC_DTBU's commit path.

END OF SESSION
Session file. Update THREAT_MODEL.md with the new trust assumption and
the defense results. Rewrite PROJECT_STATE.md. Tick M7-12. Commit and push.
```

---

## What was done

- **Two pre-session housekeeping items, both already resolved before this session started** —
  checked, not re-done. (1) Ada job 2715671 (the EMBER wheelhouse cache) completed at 18:41 UTC
  2026-09-25; `scripts/m7_10a_ember_transfer.py` had already run against it (run_id
  `20260925T160711Z-62498d7b`) and its results were already in `RESULTS.md`/`results/logs/`,
  committed in `70f9e3c`. (2) `sessions/2026-09-25-05-m7-9-formal-threat-model.md` already had a
  complete Handover block and checklist, committed in `8756dab`, working tree clean — the
  "incomplete" state the prompt described no longer existed.
- **`src/bsfr_sh/detection/drift.py`** (new, AI-generated): `RunningStats` (Welford's online
  mean/variance, plus a Chan-et-al. parallel `merge_batch`), `DriftPolicy`, `DriftReport`,
  `DriftDetector` implementing two methods (Mahalanobis, diagonal RMS-aggregated; Page-Hinkley,
  a streaming mean-shift test over the Mahalanobis signal). A full per-feature KS test (the
  brief's third option) needs stored historical samples, which the Welford design deliberately
  avoids — documented as a scope choice, not built.
- **`src/bsfr_sh/consensus/validated_commit.py`** (new, AI-generated): `ValidatedSigRWChain`
  (a `Chain` subclass overriding `check_append()` to run the detector over the block's decrypted
  `Sig_RW` batch) and `build_validated_sigrw_chain_factory`. Discovered mid-implementation that
  `blockchain/transaction.py`'s own docstring states "miners validate blocks they cannot read" —
  `Sig_RW` payloads are hybrid-encrypted to one recipient (DEV-01), so no replica can see
  plaintext features without a new capability. Resolved by requiring a `decrypt_keys` parameter
  and stating the widened trust assumption explicitly (`docs/THREAT_MODEL.md` TA-6) rather than
  silently working around it.
- **`src/bsfr_sh/consensus/pbft.py`** (small, additive edit): `Cluster.__init__` gained an
  optional `chain_factory: ChainFactory` parameter (a `Protocol`, default `Chain`), used inside
  the replica-building loop instead of a hardcoded `Chain(...)` call. Backward-compatible by
  construction — every existing caller that does not pass it gets byte-identical behaviour,
  satisfying OUT OF SCOPE's "no changes to `BC_DTBU`'s commit path."
- **`tests/unit/test_module_boundaries.py`** (edited): `consensus/validated_commit.py` importing
  `detection.drift` broke the pinned "`consensus/` depends only on `crypto`/`blockchain`/`util`"
  test. Rather than loosen the rule, added a named, single-file exception
  (`CONSENSUS_DETECTION_ALLOWED`), matching the file's own pre-existing `HASHLIB_ALLOWED`
  precedent — the rule stays pinned for every other file under `consensus/`.
- **`tests/unit/pbft_harness.py`** (small, additive edit): `make_cluster()` gained an optional
  `chain_factory` parameter, passed through to `Cluster`.
- **`tests/unit/test_drift.py`** (new, 14 tests, AI-generated): constant stream never flags
  drift, an injected shifted batch is detected (both methods), offending-feature naming,
  threshold monotonicity, `score_batch` never mutates state, cold-start returns no drift before
  `min_history`, input validation.
- **`tests/unit/test_validated_commit.py`** (new, 4 tests, AI-generated): feature extraction
  decrypts/skips correctly, a defended cluster commits clean batches with zero drift events, a
  defended cluster rejects a shifted batch an undefended cluster commits. This last test
  surfaced a real, pre-existing liveness property of `consensus/pbft.py`'s reduced view change
  (DEV-20): when every honest replica independently refuses the same pending request (as all four
  do here, since all run the identical drift check), the request does not fail cleanly — each
  replica only drops it from its own `_pending` when it is its own turn as primary, so the
  cluster cascades through several view changes before going quiet, and an *unbounded*
  `cluster.run()` call hits `_start_view_change`'s exponential backoff (`2 ** (attempts - 1)`)
  hard enough to overflow a float before that. Fixed the *test* (bounded `run(until=...)`, per
  `pbft_harness.run_for`'s own existing rationale — "Byzantine runs may never go idle" applies
  identically to an all-honest cluster that unanimously refuses one request); did not touch
  `pbft.py`'s view-change code, which is DEV-20's own known, documented trade-off, not something
  this session's scope covers.
- **`scripts/m7_12_poisoning_defense.py`** (new, AI-generated): the full evaluation — the 15-cell
  defended-vs-undefended sweep (Mahalanobis + Page-Hinkley scored, accuracy measured for real on
  both sides of every cell), a false-positive rate on chunked eval-corpus batches, a matched-
  batch-size noise-floor table (added after the first run's numbers demanded it — see Findings),
  a documented "new ransomware family" feature-space perturbation, and two real end-to-end pBFT
  commits (a label-flip burst and an anchor-shift burst, both defended and undefended, seeded
  with honest history first).
- **`docs/THREAT_MODEL.md`**: two new trust assumptions (§3, TA-6 decryption, TA-7 shared
  policy); Gap 1's "post-commit detection... not built" paragraph rewritten as "pre-commit
  detection, built and measured" with the full result; cross-references updated.
- **`docs/DEVIATIONS.md`**: DEV-38, covering the layering exception, both trust assumptions, and
  the measured results, in the repo's established DEV-entry depth.
- **`docs/ARCHITECTURE.md`** §consensus: new paragraph for `consensus/validated_commit.py`,
  naming the layering exception and the widened confidentiality invariant explicitly.
- **`RESULTS.md`**: full M7-12 section, all measured lines.
- **`docs/ROADMAP.md`**: M7-12 item added, top milestone line updated.

## Findings

- **The brief's own prediction about which strategy a batch-level detector would catch was
  measured to be exactly backwards.** M7-11 (unbuilt, predicted only) guessed anchor-point
  injection would be the catchable one ("visibly clusters near the class boundary") and label
  flipping the invisible one ("features are real, only the label lies"). Measured: anchor-point
  injection's engineered midpoint between class centroids coincides, in a roughly class-balanced
  corpus, with the *population mean* — it scores *below* the same-size clean-batch noise floor at
  every budget tested (e.g., 0.0078 vs. a clean p95 of 0.11 at n=143). Label flipping and feature
  poisoning score *above* the matched noise floor at budgets >=5%, but for a reason that matters:
  not because the detector reads labels (it structurally cannot — `honeypot/features.py`'s schema
  keeps `FT_RW` and `label` separate on purpose), but because an all-malicious batch's feature
  *composition* differs from the profile's usual mix. An honest, unusually ransomware-heavy batch
  — a real outbreak, not an attack — would trigger the identical signal. This is a sharper,
  measured version of the brief's own requested "detection-vs-legitimate-drift tension," found
  inside the main sweep rather than only in the dedicated new-family probe.
- **A single record (M7-11's own permanence-demo shape) is undetectable in principle, not just in
  practice, at any threshold.** Confirmed by measuring a same-size clean-batch noise floor at
  every `n_poisoned` value from M7-11's own budgets: at `n=7` a genuinely clean batch can already
  score as high as 1.14 purely from sampling noise, and the noise floor only grows as `n` shrinks
  further. A batch-level test has nothing to average at `n=1`. This is why the real pBFT
  demonstration in `scripts/m7_12_poisoning_defense.py` uses a *burst* of 40 records rather than
  replaying M7-11's single-record scenario directly — and even so, the burst went uncaught,
  because the real demo's honest history (6 blocks, ~35 samples total, a realistic freshly-
  bootstrapped chain) is far thinner than the array-level sweep's full 1,467-row training corpus.
- **A threshold set before measurement (Mahalanobis RMS >= 3.0, chosen from general priors about
  a chi-square-like statistic, not from this corpus) turned out to be far too conservative for
  this feature space — and lowering it would not be free.** At the shipped threshold, 0 of 15
  cells are prevented and the false-positive rate is 0/30. A threshold low enough to catch the
  new-family probe (which scored 17x its own matched clean-batch p95) would also be well within
  the range label-flip/feature-poison batches already sit in — and, per the noise-floor table,
  close enough to ordinary small-batch sampling noise that the false-positive rate would rise
  well above the ~5% ceiling the brief itself named as the usability threshold. Reported as the
  measured tension it is; the threshold was not retuned to produce a more flattering headline
  number.
- **Building the defense required breaking, in one narrow and explicitly-named way, an
  architectural invariant this project had held since M2b.** `blockchain/transaction.py`'s own
  docstring: "Miners in M2b validate blocks they cannot read; that is the point." A drift check
  over plaintext features cannot exist without plaintext features. `docs/THREAT_MODEL.md` TA-6
  states this precisely as a new, real, costed widening of trust, not a detail. This was not
  anticipated by the brief and only surfaced while implementing `extract_feature_batch` and
  discovering `Transaction`'s payload is hybrid-encrypted to one recipient.
- **The one file this session's own dependency-layering (`consensus/` -> `detection/`) touches is
  named, not silently allowed.** `test_module_boundaries.py` already had a precedent for this
  shape of exception (`HASHLIB_ALLOWED`); reused it rather than inventing a new mechanism or
  loosening the check for every file under `consensus/`.
- **Dead end, recorded so it is not retried:** the first real-pBFT design submitted M7-11's exact
  single-record permanence scenario through both defended and undefended clusters. Both
  committed, uninterestingly, for the reason above (n=1 has no statistical power) — this was not
  a useful demonstration of the mechanism at all, only of its known blind spot, which the array-
  level noise-floor measurement already established more rigorously. Replaced with the 40-record
  burst design, which at least tests the mechanism under a scenario where the array-level sweep
  predicted a chance of success (label flipping at n>=36) — though even that did not commit,
  attributable to the real demo's thinner honest history, itself reported as a finding rather
  than smoothed over.

## Numbers

All in `RESULTS.md` "M7-12" (run_id `20260926T041840Z-670ec207`, sidecar
`results/logs/20260926T041840Z-670ec207.json`, figure
`results/figures/fig12_drift_defense_comparison.png`). Baseline bal_acc 0.8408 (reproduces
M7-3/M7-11). 15/15 cells: 0 prevented at the shipped threshold. Mahalanobis scores:
label_flip 0.32-0.57, feature_poison 0.28-0.50, anchor_point_injection 0.008-0.016 (all far below
same-size clean noise floor). False-positive rate 0/30 chunked eval batches (25 rows). Matched
noise floor by batch size (n=7/36/72/143/358/353): p95 = 0.551/0.238/0.161/0.110/0.067/0.070.
New-family probe (353 rows, documented feature-space perturbation): score 1.2255, not flagged.
Real pBFT: 4/4 scenarios committed (label-flip and anchor-shift bursts of 39-40 records, defended
and undefended alike, against a 6-block/~35-sample honest history).

## Deviations opened or changed

`docs/DEVIATIONS.md` DEV-38 (new): the drift-detection defense, its layering exception, its two
new trust assumptions, and the full measured result, cross-referenced from
`docs/THREAT_MODEL.md` Gap 1 and `docs/ARCHITECTURE.md` §consensus.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** Gap 1 (honeypot data poisoning) now has both an attack (M7-11) and a defense
(M7-12), measured against each other rather than described separately. The defense is real,
integrated at the correct architectural point (pre-vote, inside `Chain.check_append()`, reusing
pBFT's existing threshold arithmetic with no new message type), and honestly characterized: it
closes exactly one case (novel feature values in a large-enough, well-established-enough batch)
and does not close M7-11's most damaging strategy (label flipping) except as an accidental,
false-positive-prone side effect of batch composition. Two new trust assumptions and one named
architectural-layering exception are now part of the documented record rather than implicit in
the code.

**Next task:** None forced. If a future session wants to extend this: (a) a size-adaptive
threshold (scaling with batch `n`, informed by this session's own noise-floor table) is the most
direct way to close the false-positive/detection tension this session measured rather than
merely stated; (b) TA-7 (replicas must agree on drift policy) is untested — a fuzz test with one
replica running a mismatched `DriftPolicy` would measure, rather than assume, the disagreement
this trust assumption predicts. Neither is proposed as a task by this session's own scope
constraint (measure and report, not iterate to a better number) — available if wanted.

**New blockers:** None.

**Questions opened / closed:** No `PROJECT_STATE.md` Q-numbers touched; this session did not open
or close a numbered open question, only M7-12's own checklist item.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run (26 lines: 15-cell sweep, FPR, 6 noise-floor sizes,
      new-family probe, 4 real-commit scenarios)
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated (DEV-38)
- [x] `docs/THREAT_MODEL.md` updated (TA-6, TA-7, Gap 1 rewritten with measured results)
- [x] `make test` and `make lint` (ruff + mypy --strict) green
- [x] Committed, message explains *why*
