# Experiments

Every number the paper reports, what we must produce, and how.

---

## Setup declared in §VII

| Parameter | Paper | Ours |
|---|---|---|
| Language / IDE | Java, Eclipse 2019-12 | Python 3.11+ |
| OS | Windows 11 64-bit | Linux (dev) / Ada HPC (full runs) |
| CPU | Intel i5 9th gen @ 2.40 GHz | recorded per run |
| RAM | 8 GB | 8 GB local, 128 GB on Ada |
| GPU | GTX 1650 4 GB | unused (no GPU work in this pipeline) |
| Miner nodes | 4 | 4 (`f = 1`, commit threshold 3) |
| Consensus | pBFT, voting-based | pBFT (Castro & Liskov) |
| Chain type | private / permissioned | same |
| Chains | 2 (backups, ransomware) | same, fully independent |
| Tx per block | 100 | 100 |
| Cases | 5 / 10 / 15 blocks | same |

Absolute seconds will not match — different language, runtime, hardware. **The target is the
trend and the ratios.** See DEV-13.

---

## Target 1 — Table II / Figs. 4 and 5 (accuracy and F1)

| Technique | Accuracy | F1 | Actual dataset used |
|---|---|---|---|
| Almashhadani et al. [11] | 97.08 | 0.971 | network traffic traces (Locky) |
| Hwang et al. [12] | 97.30 | 0.973 | dynamic analysis logs |
| Sharmeen et al. [13] | 95.96 | 0.960 | semi-supervised, own corpus |
| Bae et al. [14] | 98.65 | 0.987 | PE-file features |
| **BSFR-SH** | **98.98** | **0.990** | BitcoinHeist addresses |

Rows 1–4 are quoted from the source papers — labelled `paper_reported`, never `measured`. Only
the BSFR-SH row is reproducible by us. The `dataset` column is our addition (DEV-07).

**Our measured BSFR-SH row (address dropped, address-grouped split, random forest): 0.9442
accuracy / 0.9697 F1** — not the published 0.9898/0.990 (`docs/DEVIATIONS.md` DEV-06,
`RESULTS.md`). `scripts/run_detection.py` and `scripts/q10_leakage_ablation.py` agree on this
figure as of M4b (D6 retired); a random row-level split without address grouping measures
0.9479/0.9717 instead and is superseded, kept only for provenance.

**Baseline we must publish alongside it.** On the paper's 90/10 split, a constant "always
ransomware" classifier achieves accuracy 0.900 and F1 0.947. Any reproduction that omits this
baseline is misleading. This is the baseline every number in this table should be judged against —
including Sharmeen et al. [13]'s published F1 of 0.960, which clears it by only 0.013 while Table
II presents it as a competitive prior technique (`docs/PAPER_NOTES.md` FLAW-1, extended).

**This is a within-split baseline. Do not pair it across distributions.** `honest_mode`'s
constant-negative baseline (≈98.58% accuracy at the dataset's natural 1.42% positive rate) is
computed under a *different* class distribution than the 90/10 baseline above. Setting the two
side by side — "the published 98.98% barely beats a natural-rate do-nothing classifier at 98.58%"
— reads as a refutation but is not one: a constant classifier's accuracy is a direct function of
the positive rate it is scored against, so the pairing compares two distributions, not two
detectors. Keep it, but label it **illustration of accuracy's distribution-sensitivity**, not a
head-to-head. The head-to-head is the row above, computed on one split.

---

## Target 2 — Dataset

**BitcoinHeist Ransomware Address Dataset**, UCI ML Repository (paper ref [15], Akcora et al.,
IJCAI 2021).

- 2,916,697 rows · 10 attributes
- `address` (string), `year`, `day`, `length`, `weight`, `count`, `looped`, `neighbors`, `income`,
  `label`
- `label` ∈ {`white`} ∪ {ransomware family names: Cryptxxx, CryptoLocker, ...}
- 2,875,284 legitimate · 41,413 ransomware → **1.42% positive**

Binary target: `white` → 0, anything else → 1. `address` is dropped (identifier, not a feature) —
the paper does not say, but keeping it leaks.

**Two evaluation modes (DEV-06):**

| Mode | Split | Metrics |
|---|---|---|
| `paper_mode` | resample to 90% ransomware / 10% benign | accuracy, F1 — reproduction target |
| `honest_mode` | natural 1.42% positive, stratified k-fold | precision, recall, PR-AUC, MCC, minority F1, confusion matrix |

Both run every time. Both appear in every report.

**Models:** Random Forest, Logistic Regression, Decision Tree, KNN. Paper reports no
hyperparameters; ours are declared in `configs/ml.yaml` rather than silently defaulted. Paper's
best is **Decision Tree** for both metrics — worth flagging that a single tree beating a forest
on 2.9M rows suggests the split, not the model, is producing the score.

**Compute note:** KNN on the full dataset is the memory hazard on an 8 GB box. Default configs
subsample; `--full` runs go to Ada as a batch job.

---

## Target 3 — Fig. 6(a)/(b), computational time (seconds)

| Case | Blocks | Tx | `BC_DTBU` | `BC_SigRW` |
|---|---|---|---|---|
| 1 | 5 | 500 | 3.10 | 4.36 |
| 2 | 10 | 1000 | 4.17 | 5.54 |
| 3 | 15 | 1500 | 5.71 | 6.76 |

**Properties to reproduce (these, not the absolute seconds):**
- Time increases with block count, **sublinearly** — tripling blocks costs ~1.8× time on the
  backup chain, ~1.55× on the ransomware chain.
- The ransomware chain is consistently slower than the backup chain, by 18–41%.
- Both curves are concave, indicating fixed setup cost amortised across blocks.

Protocol: median of N ≥ 5 repeats, warm-up run discarded, seeds fixed, per-block marginal cost
recorded separately from totals. **N is decided from a measured case-3 variance probe
(`bench.harness.decide_repeat_count`), never assumed** — one M6a run measured a quiet-machine
CV of ~1%, a second measured ~45% on the same code and config (ordinary background load on a
shared dev laptop, not algorithmic nondeterminism — see the session log), and the repeat count
rose from 5 to 25 accordingly. The case-1-to-case-3 trend stayed resolvable
(`bench.harness.trend_resolvable`) at both readings.

**Measured, M6a (`RESULTS.md` `bench/target3-time`, run `20260917T144843Z-fb4c2410`).** Absolute
seconds are two to three orders of magnitude below the paper's (our case-3 `BC_DTBU`: ~0.48s
against 5.71s) — expected, not a bug (DEV-13: different language, runtime, hardware). The
properties above are **not** reproduced as stated:

* Monotone increasing — **yes**, on both chains.
* Sublinear / concave — **no**. Marginal per-block cost is flat (`bench.harness.run_case`'s
  per-block timer starts *after* cluster construction, so no fixed setup cost can amortise into
  it): tripling blocks (case-1 to case-3) costs ~2.85x time on both chains, not ~1.8x/~1.55x.
  This sharpens DEV-08 rather than contradicting it — see that entry's amendment.
* `BC_SigRW` slower than `BC_DTBU` — **yes**, consistently, by ~35-45% depending on the run
  (paper: 18-41%). Attributed structurally to one extra ECDSA sign per transaction (DEV-03's
  attestation) plus `SignatureRecordPayload`'s many-small-floats encoding costing more per byte
  than `BackupPayload`'s single bytes blob — not tuned to match, and the percentage does not
  match the paper's exactly, which is expected of a structural rather than fitted cause.

**The 35-45% figure above is the serialization-OFF condition specifically — say which condition
before citing it.** `RESULTS.md` `bench/target3-time-serialized`, run `20260922T172916Z-22992372`
(`docs/DEVIATIONS.md` DEV-30's second amendment): re-running the same three-case, both-chain
matrix with `configs/bench.yaml`'s now-current `network.serialize_messages: true` narrows the gap
to ~25-27% (case 1 +25.76%, case 2 +24.60%, case 3 +27.36%) — real serialization cost, close to
chain-independent in absolute seconds, dilutes but does not eliminate the ECDSA/encoding
attribution above. Monotone increase and `BC_SigRW` > `BC_DTBU` both still hold; only the
percentage is condition-dependent. Marginal cost stays flat under serialization too (DEV-08's
second amendment) — `BC_DTBU` 0.0541-0.0543s/block, `BC_SigRW` 0.0678-0.0688s/block, each varying
<1% across cases 1-3, same shape as serialization-OFF just uniformly ~50-65% higher.

---

## Target 4 — Fig. 6(c)/(d), transactions per second

| Case | `BC_DTBU` | `BC_SigRW` |
|---|---|---|
| 1 | 161 | 115 |
| 2 | 240 | 181 |
| 3 | 263 | 222 |

**TPS is derived, not measured.** Verified against every one of the six data points:

```
500/3.10 = 161.3    1000/4.17 = 239.8    1500/5.71 = 262.7
500/4.36 = 114.7    1000/5.54 = 180.5    1500/6.76 = 221.9
```

So we instrument wall-clock time only and compute `tps = total_tx / total_seconds`. The paper's
claim that TPS rises as the chain grows is amortisation, not throughput — we additionally report
marginal per-block cost, which should be roughly flat (DEV-08).

**Measured, M6a.** Our own TPS is flat across cases (`BC_DTBU`: ~2930-3190 tx/s; `BC_SigRW`:
~2170-2230 tx/s, case-1 through case-3), not rising like the paper's six points. This is the
direct consequence of the flat marginal cost above: with no fixed setup cost inside the timed
span, `tps = tx / (blocks * marginal_cost)` has no `blocks` term left to rise against. DEV-08's
hypothesis — the paper's rising TPS is amortisation, not a throughput property — is now backed by
a measurement showing what TPS looks like *without* that amortisation, rather than by the
arithmetic identity alone. See DEV-08's amendment.

**Reconfirmed, serialization ON (2026-09-22).** Still flat, at a uniformly lower level:
`BC_DTBU` ~1832-1848 tx/s, `BC_SigRW` ~1438-1476 tx/s (`RESULTS.md`
`bench/target3-time-serialized`). No `blocks` term reappears — serialization's cost is per-message,
not fixed-per-setup, so it lowers the flat line without un-flattening it. See DEV-08's second
amendment.

---

## Target 5 — §V security analysis

Five informal arguments, no formal model (GAP-6). Reproducing §V means writing the argument
against our concrete protocol, not running a tool. Each claim maps to a test:

| §V claim | Test |
|---|---|
| 1 · replay, MITM, impersonation, illegal session key | `test_session_replay.py`, `test_session_mitm.py` |
| 2 · privileged insider, credential guessing, stolen verifier | `test_credential_deletion.py` |
| 3 · 51%, selfish mining, Sybil | `test_pbft_byzantine.py`, `test_permissioned_membership.py` |
| 4 · DoS, data manipulation, leakage | `test_block_tamper.py`, `test_tx_confidentiality.py` |
| 5 · chain separation | `test_chains_independent.py` |

Optional extension (DEV-14): Scyther model of the session protocol.

---

## Output contract

```
results/
├── tables/
│   ├── table2_paper_mode.csv       # M6b
│   ├── table2_honest_mode.csv      # M6b
│   ├── baselines.csv               # M6b
│   └── target3_target4.csv         # M6a — measured vs. paper_reported, cases 1-3, both chains
├── figures/
│   ├── fig4_accuracy.png                    # M6b
│   ├── fig5_f1.png                          # M6b
│   ├── fig6a_time_backup.png                # M6a
│   ├── fig6b_time_ransomware.png            # M6a
│   ├── fig6c_tps_backup.png                 # M6a
│   ├── fig6d_tps_ransomware.png             # M6a
│   └── fig6e_component_breakdown.png        # M6a — our addition, not in the paper (see below)
└── logs/
    └── <run_id>.json     # config hash, seed, host, CPU, wall times, git rev
```

Every figure has a sidecar JSON. Every number is either `measured` (with a run_id) or
`paper_reported` (with a citation), with one narrow exception: a handful of `bench/`'s M6a
numbers (the modelled-network column and the D3 serialization estimate) are `computed` — pure
arithmetic or a microbenchmark, not a stopwatch around the thing itself, and precedent for a
third label already exists (`detection/constant-positive`'s baseline row in `RESULTS.md`).
`bench/harness.py`'s module docstring says which of its outputs are `measured` and which are
`computed`.

**Fig. 6(e), added in M6a, is not in the paper.** It is a component-breakdown panel — compute,
modelled network, index construction (DEV-05) and D3's serialization estimate for case-3, each
its own bar — kept structurally separate from Figs. 6(a)-(d) so that a `computed` number never
gets summed into something that looks `measured` and comparable to the paper's six data points.
See `bench/emit.py`.
