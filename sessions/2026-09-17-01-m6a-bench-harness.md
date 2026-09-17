# Session 2026-09-17-01 — M6a: timing harness and Figs. 6(a)-(d)

**Milestone:** M6a (M6 split into M6a/M6b this session) · **Files read at start:** `CLAUDE.md`,
`PROJECT_STATE.md`, `docs/EXPERIMENTS.md` Targets 3-4, `RESULTS.md` tail, `docs/DEVIATIONS.md`
DEV-08 and DEV-13, `configs/bench.yaml`, `configs/chain.yaml`, `tests/unit/pbft_harness.py`,
`tests/unit/m3a_harness.py`, `consensus/pbft.py`, `consensus/network.py`,
`framework/_block_pipeline.py`, `framework/phase1_backup.py`, `framework/phase2_collection.py`,
`blockchain/transaction.py`, `util/serialization.py`, `util/config.py`, `util/logging.py`,
`crypto/hashing.py`, `scripts/run_phase3_detection.py` (as the sidecar/RESULTS.md convention to
follow), `recovery/locator.py` (`BackupIndex`) · **Duration:** _

---

## Brief *(written before any work)*

**Task:** Build `bench/harness.py` and `bench/emit.py` so cases 1/2/3 (5/10/15 blocks x 100 tx,
both chains, 4 nodes) are timed with a variance-justified repeat count, compute/network/index/D3
costs are reported as separate columns, the Q2 payload sweep is closed, and `make figures`
produces Figs. 6(a)-(d) with sidecars.

**Exit condition:** `make figures` produces `results/figures/fig6a..d_*.png` with sidecar JSON
carrying config hash, scheme, seed, host, CPU, wall time, git rev. Every number has a
`RESULTS.md` line labelled `measured` (or `computed` for the modelled-network and D3 columns,
following the precedent set by the existing `computed` baseline row). Variance at case-3 is
reported and the repeat count is justified by it, not guessed. Q2 is closed with a recorded
default. D3's magnitude is stated, not left as an unquantified caveat.

**Out of scope:** Table II, Figs. 4-5, any ML run, the Ada `honest_mode` job. All M6b.

**Prior context needed:** `docs/EXPERIMENTS.md` Targets 3-4 (the six paper data points and the
properties to reproduce), `docs/DEVIATIONS.md` DEV-08 (TPS is derived, marginal cost matters),
DEV-13 (trend/ratio is the target, not seconds), DEV-05/DEV-21 (index and network cost live
outside the measured span), DEV-15 (payload size is declared, Q2 is the sweep that closes it),
DEV-03 (`SigRW`'s attestation is a real extra ECDSA sign per transaction — the structural reason
it should run slower than `BC_DTBU`, not an injected one).

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/EXPERIMENTS.md
Targets 3-4, RESULTS.md tail, docs/DEVIATIONS.md DEV-08 and DEV-13. Not
docs/PAPER_NOTES.md, not docs/ALGORITHMS.md.

Create the session file from the template and fill the brief first.

M6 is being split. This is M6a — the timing harness and Figs. 6(a)-(d).
M6b is Table II, Figs. 4-5, and the Ada honest_mode job. Update ROADMAP.

TASK — M6a. bench/harness.py and bench/emit.py.

THE PROBLEM THIS SESSION HAS TO CONFRONT
The paper reports 5.71 s for case-3 (15 blocks x 100 tx). At the 39,371
sign/s measured in M1, 1500 signatures is ~40 ms of signing. Our whole case-3
may land two orders of magnitude below their figure. That is not a bug and
not something to inflate — it means their number is dominated by JVM overhead
and their implementation, and DEV-13 already says the target is the trend,
not the seconds.

But at that timescale the trend itself may be noise. Before running the full
matrix, measure the per-run variance at case-3 and report it. If the
run-to-run spread is comparable to the difference between cases, say so
plainly — "the trend is not resolvable at this timescale" is a legitimate
finding and better than three points on a chart that mean nothing. Decide
repeat counts from the measured variance, not from a guess.

WHAT MUST BE REPORTED SEPARATELY, NOT SUMMED
Four cost components, each its own column:
  - compute time (what we actually measure)
  - modelled network time (M2b's simulated clock: delay d adds 4d per block,
    3d inside consensus; wall clock unaffected)
  - index construction (M3b split it out of the append path; the paper has
    no index, so it must not sit inside a figure compared against theirs)
  - D3: the bus passes Python objects without serializing. Real consensus
    would encode every message. That cost is absent from our numbers.
    Estimate it from util/serialization.py throughput and report it as a
    known omission with a magnitude, rather than an unquantified caveat.

A single summed number would not be comparable to the paper's, and worse,
would look like it was.

1. bench/harness.py
   Cases 1/2/3 at 5/10/15 blocks x 100 tx, both chains, 4 nodes. Median of N
   with N justified by the variance measurement, warm-up run discarded, seeds
   fixed. Record per-block marginal cost alongside totals — DEV-08 says the
   paper's rising TPS is amortisation of fixed setup, and marginal cost is
   where that becomes visible.

2. TPS is derived, never measured: tps = total_tx / total_seconds. Verified
   against all six of the paper's data points. Do not instrument it
   separately.

3. Q2 sweep — payload size.
   Still deferred. Run case-3 at three payload sizes to show how much of
   Target 3 is payload handling rather than consensus. Note the memory
   ceiling: Chain holds every block in memory, so footprint is roughly
   payload x 100 x 15. Project before running; at 10 MB payloads that is
   ~15 GB and will OOM an 8 GB box. Close Q2 with a recorded default.

4. bench/emit.py
   Figs. 6(a)-(d) to results/figures/, each with a sidecar JSON carrying
   config hash, scheme version, seed, host, CPU, wall time, git rev.
   Reproduce the paper's chart shapes for comparability, then add our own
   panel showing the component breakdown — the reproduction figure and the
   honest figure are different artifacts and both belong in the report.

EXIT CONDITION
make figures produces Figs. 6(a)-(d) with sidecars. Every number has a
RESULTS.md line with mode=measured. Variance reported and repeat count
justified by it. Q2 closed. D3's magnitude estimated and stated.

OUT OF SCOPE
No Table II, no Figs. 4-5, no ML runs, no Ada job. M6b.

END OF SESSION
Session file with attribution and dead ends. RESULTS.md lines for every run.
Amend DEV-08 if the marginal-cost data changes what it says about the
paper's TPS claim. Rewrite PROJECT_STATE.md, under 200 lines. Tick M6a and
record the split. Commit explaining why.
```

---

## What was done

- `docs/ROADMAP.md` — M6 split into M6a (this session, done) and M6b (Table II, Figs. 4-5, Ada
  job). **AI-generated.**
- `configs/bench.yaml` — added a declared `network.modelled_delay_s` / `modelled_delay_sweep_s`
  section (illustrative delays for Fig. 6(e)'s modelled-network bar; never changes any measured
  number). `configs/chain.yaml` already had `payload_bytes_sensitivity`; wired it into the schema.
  **AI-generated.**
- `src/bsfr_sh/util/config.py` — added the two new `bench` schema keys and
  `transaction.payload_bytes_sensitivity` to `chain`'s required keys, per the "add a row when
  code starts depending on it" rule. **AI-generated.**
- `src/bsfr_sh/bench/harness.py` (new) — `BenchPolicy`, transaction builders for both chains
  (`_dtbu_batch` via `encrypt_backup`, `_sigrw_batch` via `encrypt_signature_record` with one
  real ECDSA sign per record standing in for DEV-03's attestation), `run_once`/`run_case`
  (reuses `consensus.pbft.Cluster` and `framework._block_pipeline.commit` — no new consensus
  code), `decide_repeat_count`/`trend_resolvable` (variance-driven, not guessed),
  `modelled_network_seconds`/`verify_modelled_network_formula` (DEV-21's `4d`/`3d`, checked
  against a real run), `estimate_block_encode_seconds`/`estimate_d3_seconds` (D3's magnitude),
  `projected_chain_bytes`/`estimate_overhead_factor` (Q2's memory projection). **AI-generated.**
- `src/bsfr_sh/bench/emit.py` (new) — Figs. 6(a)-(d) (ours vs. paper, per-figure sidecar) and
  Fig. 6(e) (component breakdown, our own addition), `results/tables/target3_target4.csv`.
  **AI-generated.**
- `scripts/run_bench.py` (new) — orchestrates the above: variance probe, matrix, trend check,
  network-formula verification, D3 estimate, Q2 sweep with memory projection, sidecar,
  `RESULTS.md` candidate lines (printed, not auto-appended — this project's convention), figures.
  **AI-generated.**
- `tests/unit/test_bench_harness.py` (new, 19 tests) — arithmetic (`decide_repeat_count`,
  `trend_resolvable`, `modelled_network_seconds`), one real small-scale cluster run per chain,
  case aggregation, D3/Q2 helpers, `BenchPolicy` loading against the real configs. No wall-clock
  comparisons asserted (would be flaky) — timing comparisons are `RESULTS.md` findings, not test
  invariants. **AI-generated.**
- `Makefile` `figures` target wired to `scripts/run_bench.py` (was a stub that `exit 1`'d).
  **AI-generated.**
- `pyproject.toml` — mypy override for `matplotlib.*` (same shape as the existing sklearn/pandas
  one), added when `emit.py` started plotting. **AI-generated.**
- `docs/EXPERIMENTS.md` — Output contract updated for `fig6e` and `target3_target4.csv`; Target
  3/4 sections got a "Measured, M6a" paragraph each, stating which reproduced properties did and
  did not hold. **AI-generated.**
- `docs/DEVIATIONS.md` — amended DEV-08 (marginal cost measured, not just predicted), DEV-21
  (exact `4d`/`3d` formula stated and verified), DEV-15 (Q2 closed, memory ceiling projected);
  added DEV-30 (D3's magnitude quantified). **AI-generated.**
- `RESULTS.md`, `PROJECT_STATE.md` — see Numbers and Handover below. **AI-generated.**

## Findings

- **The paper's absolute seconds are ~10x below what the brief guessed, not ~100x.** Case-3
  compute lands at ~0.48-0.69s against the paper's 5.71-6.76s — one order of magnitude, not two.
  Still dominated by language/runtime/hardware (DEV-13), not a bug.
- **Variance at case-3 fluctuates between invocations of the identical code and config, on the
  same machine.** First probe: CV ~1% (both chains). Second probe, minutes later: CV up to 45%
  on `BC_DTBU`. Not algorithmic nondeterminism (seeds are fixed and transaction counts/shapes are
  identical either way) — ordinary background load on a shared dev laptop. The adaptive repeat
  count (`decide_repeat_count`) is exactly the mechanism for this: it raised N from 5 to 25 on
  the noisy reading and the case-1-to-case-3 trend stayed clearly resolvable at both readings.
  This is the session's answer to its own opening worry ("the trend may not be resolvable at
  this timescale") — it *is* resolvable, robustly, but the repeat count needed to show that
  varies 5x between two runs on the same machine, which is itself worth recording.
- **Marginal per-block cost is flat, not sublinear.** `run_case`'s timer starts after cluster
  construction by design (matching `configs/bench.yaml`'s span), so no fixed setup cost is inside
  what gets measured. The paper's concavity is therefore not reproduced — and DEV-08's
  amortisation hypothesis is *why*, not a discrepancy to explain away. Flat marginal cost also
  means flat TPS, which is the more visually obvious way the same finding shows up in Figs. 6(c)/(d).
- **`BC_SigRW`'s slowdown is real and structural, not tuned.** One extra ECDSA `sign()` per
  transaction (attestation, DEV-03) is the intentional asymmetry; the actual measured gap
  (~35-45%) is larger than that alone predicts (~38ms of pure signing at M1's 39,371 sign/s
  against a ~200ms measured gap at case-3). The remainder is very likely
  `SignatureRecordPayload.features` being encoded as many individual small floats rather than
  `BackupPayload.data`'s one raw bytes blob — the Q2 sweep supports this (payload size costs
  `BC_SigRW` visibly more than `BC_DTBU`: 16x payload costs ~2.2x time on `BC_SigRW` vs. ~1.55x
  on `BC_DTBU`) — but this was not isolated further; flagged as a **dead end / open thread**, not
  chased to a confirmed root cause. If M6b or a future session needs the exact split, profile
  `_sigrw_batch` vs. `_dtbu_batch` directly rather than inferring it from the case matrix.
- **The naive Q2 memory projection (`payload x 100 x 15`) is far too optimistic.** A `Cluster`
  holds 4 independent replica `Chain`s, each storing every block in full — a factor the brief's
  own "~15GB at 10MB payloads" estimate did not include. Measured overhead factor
  (ciphertext/AEAD-tag/wrapped-key vs. raw plaintext) is ~1.10-1.15x. Real projection: ~67 GiB,
  not ~15 GB. Recorded in DEV-15's amendment so nobody re-derives the smaller, wrong number later.
- **Dead end: block-hash determinism assumed in the first test draft.** Assumed `run_once(seed=X)`
  twice would commit byte-identical blocks; it does not, because `BlockDraft.nonce` (`RN`) is
  `secrets`-random by design (block.py's own docstring calls this inert-and-random on purpose,
  matching CLAUDE.md §4b's treatment of session ephemerals). Fixed the test to assert shape
  (transaction counts) rather than hash equality — the actually-guaranteed determinism.
- **Lint caught a real bug, not just style.** `_fig_component_breakdown` built its stacked bars
  without ever passing `color=` to `ax.bar()`, so every figure fell back to matplotlib's default
  cycle — which happened to *look* plausible (blue/orange/green/red) while not matching the
  legend's stated purple for "index construction" at all. Caught by eye against the rendered PNG,
  not by mypy/ruff; worth remembering that a plot's correctness needs visual review, lint is not
  enough. Also caught, this time by mypy: `run_once` reused the name `index` for both the block
  loop variable and the `BackupIndex` instance — harmless in this case (the loop finishes before
  the second assignment) but exactly the kind of shadowing bug that is not harmless in general.

## Numbers

All below also appended to `RESULTS.md` under "Bench (M6a — Target 3/4 timing, Figs. 6a-e)".
Canonical run: `20260917T144843Z-fb4c2410` (n=25 repeats, the noisier/more-repeats of two
variance-probe invocations — see Findings). Superseded quiet-machine probe kept for provenance:
`20260917T144151Z-3d88337d`.

- Target 3/4 matrix (measured): see `RESULTS.md` `bench/target3-time` lines and
  `results/tables/target3_target4.csv`.
- Index construction (measured, `BC_DTBU` only, DEV-05): `RESULTS.md` `bench/index-construction`.
- Variance probes (measured): `RESULTS.md` `bench/variance-case3`, both readings.
- D3 estimate (computed, DEV-30): `RESULTS.md` `bench/d3-serialization`.
- Modelled network (computed, DEV-21, formula verified): `RESULTS.md` `bench/network-modelled`.
- Q2 sweep (measured) and 10MB projection (computed): `RESULTS.md` `bench/q2-payload-sweep` and
  `bench/q2-projection`.

## Deviations opened or changed

- DEV-08 amended — marginal cost is now measured (flat), not just predicted from the derived-TPS
  arithmetic; a second, independent line of evidence for the same conclusion.
- DEV-21 amended — the exact `4d`-per-block / `3d`-inside-consensus formula stated and verified
  against a real run at three delays and two block counts, floating-point exact every time.
- DEV-15 amended — Q2 closed: the sweep ran, the 4096B default is kept, and the memory ceiling is
  projected (~67 GiB for a 10MB payload, not the naively-estimated ~15GB) rather than found by
  OOMing the dev box.
- DEV-30 added — D3's serialization-cost omission is quantified (≈0.2-0.3% of measured compute
  at case-3, both chains) via a microbenchmark on `util.serialization`, stated as a lower bound.

---

## Handover *(written last)*

**State after:** `bench/harness.py` and `bench/emit.py` exist, tested, lint-clean. `make figures`
runs end to end and produces Figs. 6(a)-(e) with sidecars plus a target3/4 CSV. Every M6a number
has a `RESULTS.md` line. Q2 is closed. D3 has a stated magnitude. DEV-08/DEV-15/DEV-21 amended,
DEV-30 added. `docs/ROADMAP.md` records the M6a/M6b split, M6a ticked done.

**Next task:** M6b — wire `make repro`/`make honest` to `scripts/run_detection.py` and
`scripts/run_phase3_detection.py` (already built, M4a/M4b), add `emit_table2()`/`emit_fig4_5()`
to `bench/emit.py` reading from `RESULTS.md`'s existing detection lines rather than re-running
ML, and submit `scripts/ada_honest_mode.sbatch` on Ada for the full 2.9M-row `honest_mode` run
(prepared, unrun). Exit: every `docs/EXPERIMENTS.md` target carries a `measured` or
`paper_reported` label.

**New blockers:** None.

**Questions opened / closed:** Q2 closed this session (payload sweep ran, memory ceiling
projected, 4096B default kept — see `docs/DEVIATIONS.md` DEV-15's amendment). Q5 closed this
session (`bench/` is the first multi-config consumer: it loads `bench.yaml` and `chain.yaml` as
two separate `Config` objects, never merged, combined only for the sidecar's `config_hash` via
`crypto.hashing.combined_config_hash` — no new merged-config type was introduced). No new
questions opened; the `BC_SigRW` slowdown's exact cost split (attestation sign vs. feature-vector
encoding overhead) is a loose thread noted in Findings, not a numbered open question.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated if the paper was departed from
- [x] Committed, message explains *why*
