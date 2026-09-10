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

**Baseline we must publish alongside it.** On the paper's 90/10 split, a constant "always
ransomware" classifier achieves accuracy 0.900 and F1 0.947. Any reproduction that omits this
baseline is misleading.

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
recorded separately from totals.

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
│   ├── table2_paper_mode.csv
│   ├── table2_honest_mode.csv
│   └── baselines.csv
├── figures/
│   ├── fig4_accuracy.png
│   ├── fig5_f1.png
│   ├── fig6a_time_backup.png
│   ├── fig6b_time_ransomware.png
│   ├── fig6c_tps_backup.png
│   └── fig6d_tps_ransomware.png
└── logs/
    └── <run_id>.json     # config hash, seed, host, CPU, wall times, git rev
```

Every figure has a sidecar JSON. Every number is either `measured` (with a run_id) or
`paper_reported` (with a citation). No third category.
