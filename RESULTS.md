# Results Log

Append-only. **One line per benchmark run. Never edit or delete a line.** A superseded result
stays; the newer line below it is the current one.

This file exists so `PROJECT_STATE.md` never has to carry numbers. It is read *selectively* —
`tail`, or `grep` for a component — never in full.

---

## Format

```
YYYY-MM-DD | <component> | <config> | <metric>=<value> ... | <mode> | run_id | note
```

- `<mode>` is `measured` or `paper_reported`. There is no third value.
- `run_id` matches a file in `results/logs/<run_id>.json` for `measured` rows. `—` for
  `paper_reported`.
- `<note>` is at most one short clause. Reasoning belongs in the session log, not here.

**Rule:** if a number appears anywhere — a report, a figure, a chat message — it must have a line
here first. A number without a line in this file does not exist.

---

## ML detection

```
2023-02-01 | detection/bsfr-sh    | 90/10 split, DecisionTree | acc=0.9898 f1=0.990 | paper_reported | — | Table II, best of 4 algorithms
2023-02-01 | detection/almashhadani| network traces           | acc=0.9708 f1=0.971 | paper_reported | — | Table II row 1, different dataset
2023-02-01 | detection/hwang      | dynamic analysis          | acc=0.9730 f1=0.973 | paper_reported | — | Table II row 2, different dataset
2023-02-01 | detection/sharmeen   | own corpus                | acc=0.9596 f1=0.960 | paper_reported | — | Table II row 3, different dataset
2023-02-01 | detection/bae        | PE features               | acc=0.9865 f1=0.987 | paper_reported | — | Table II row 4, different dataset
```

Baseline to beat before any of the above means anything:

```
2026-09-10 | detection/constant-positive | 90/10 split | acc=0.9000 f1=0.9474 | computed | — | analytic, not a run; always-ransomware classifier on the paper's split
```

## Blockchain timing

```
2023-02-01 | chain/BC_DTBU  | case1 5blk×100tx  | time=3.10s tps=161 | paper_reported | — | Fig 6a/6c
2023-02-01 | chain/BC_DTBU  | case2 10blk×100tx | time=4.17s tps=240 | paper_reported | — | Fig 6a/6c
2023-02-01 | chain/BC_DTBU  | case3 15blk×100tx | time=5.71s tps=263 | paper_reported | — | Fig 6a/6c
2023-02-01 | chain/BC_SigRW | case1 5blk×100tx  | time=4.36s tps=115 | paper_reported | — | Fig 6b/6d
2023-02-01 | chain/BC_SigRW | case2 10blk×100tx | time=5.54s tps=181 | paper_reported | — | Fig 6b/6d
2023-02-01 | chain/BC_SigRW | case3 15blk×100tx | time=6.76s tps=222 | paper_reported | — | Fig 6b/6d
```

Note: every `tps` above equals `tx/time` exactly — derived by the authors, not measured. See
DEV-08.

## Ours

### Crypto primitives (M1)

```
2026-09-11 | crypto/ecdsa-cryptography | secp256r1 sha-256 rfc6979, 200 ops x median of 7 | sign=39371.4/s verify=23305.6/s | measured | 20260910T213021Z-f07b5fbf | Q1 backend bake-off, C/OpenSSL
2026-09-11 | crypto/ecdsa-pure-python  | secp256r1 sha-256 rfc6979, 200 ops x median of 7 | sign=2306.7/s verify=588.3/s   | measured | 20260910T213021Z-f07b5fbf | Q1 backend bake-off, `ecdsa` 0.19.2
```

Q1 closed on these: `cryptography` is 17.1x faster to sign and 39.6x faster to verify. At the
pure-Python rate, case-3's 1500 transactions would spend ~2.6 s on signature verification alone —
about 45% of the 5.71 s the paper reports for the *whole* case — so Figs. 6(a)-(d) would be
measuring the signature library rather than the framework. Both rows are logged because the
losing number is what makes the choice defensible.

### Detection — BitcoinHeist, paper_mode (M4a)

Dataset verified against §VII before any fit: 2,916,697 rows, 2,875,284 benign, 41,413 ransomware
(1.42% positive), 28 families, sha256 `8ecc3744…c438`.

```
2026-09-12 | detection/bitcoinheist-paper | random_forest, 90/10 n=46014        | acc=0.9479 f1=0.9717 | measured | 20260912T172708Z-6d35b415 | Table II target
2026-09-12 | detection/bitcoinheist-paper | logistic_regression, 90/10 n=46014  | acc=0.9000 f1=0.9474 | measured | 20260912T172708Z-6d35b415 | equals the constant baseline exactly
2026-09-12 | detection/bitcoinheist-paper | decision_tree, 90/10 n=46014        | acc=0.9262 f1=0.9590 | measured | 20260912T172708Z-6d35b415 | paper's best algorithm; ours scores 0.9262
2026-09-12 | detection/bitcoinheist-paper | k_nearest_neighbours, 90/10 n=46014 | acc=0.8861 f1=0.9392 | measured | 20260912T172708Z-6d35b415 | below the constant baseline
2026-09-12 | detection/bitcoinheist-paper | constant-positive, 90/10 n=46014    | acc=0.9000 f1=0.9474 | measured | 20260912T172708Z-6d35b415 | baseline, looks at no feature
```

The published BSFR-SH row is acc=0.9898 f1=0.990 (`paper_reported`, above). **We do not reproduce
it**: our best is random forest at 0.9479 / 0.9717, and the paper's own best algorithm (decision
tree) reaches 0.9262 here. Three of the four models sit at or below the always-ransomware baseline.
`n=46014` is the whole resample — 1.58% of the cited dataset (DEV-06 amendment).

### Detection — BitcoinHeist, honest_mode (M4a)

Natural class balance, stratified 5-fold, out-of-fold predictions pooled once. Subsampled to
200,000 rows (2,840 positive, 1.42%) per `configs/ml.yaml`; all four models ran locally.

```
2026-09-12 | detection/bitcoinheist-honest | random_forest, natural 200000 rows       | prec=0.7414 rec=0.1292 pr_auc=0.3349 mcc=0.3062 f1min=0.2201 | measured | 20260912T172809Z-d89aa1b6 | DEV-06 honest mode
2026-09-12 | detection/bitcoinheist-honest | logistic_regression, natural 200000 rows | prec=0.0000 rec=0.0000 pr_auc=0.0181 mcc=0.0000 f1min=0.0000 | measured | 20260912T172809Z-d89aa1b6 | predicts no ransomware at all
2026-09-12 | detection/bitcoinheist-honest | decision_tree, natural 200000 rows       | prec=0.3239 rec=0.3581 pr_auc=0.1253 mcc=0.3306 f1min=0.3401 | measured | 20260912T172809Z-d89aa1b6 | best MCC of the four
2026-09-12 | detection/bitcoinheist-honest | k_nearest_neighbours, natural 200000 rows | prec=0.4985 rec=0.1155 pr_auc=0.1169 mcc=0.2352 f1min=0.1875 | measured | 20260912T172809Z-d89aa1b6 | DEV-06 honest mode
2026-09-12 | detection/bitcoinheist-honest | constant-negative, natural 200000 rows   | acc=0.9858 f1=0.0000 | measured | 20260912T172809Z-d89aa1b6 | baseline; scores 98.58% by never predicting ransomware
```

Read these against the paper's 98.98% accuracy. A classifier that never predicts ransomware scores
**98.58%** here — so the published headline is 0.4 points above a classifier that finds nothing.
At the natural rate the four models recover between 0% and 36% of the ransomware, and the best MCC
of any of them is 0.331. Logistic regression is the clearest illustration of DEV-06: on the 90/10
resample it predicted *everything* positive (0.9000/0.9474, exactly the constant baseline); at the
natural rate it predicts *nothing* positive. Same model, same declared hyperparameters — only the
class balance changed.

**Deferred, not skipped:** full-scale `honest_mode` over all 2,916,697 rows has not been run. KNN
there needs ~17.94 GB for the distance block against an 8 GB ceiling, and 1.36e12 distance
computations per fold (`detection.models.knn_projection`, projected before running anything per
CLAUDE.md §6). `scripts/ada_honest_mode.sbatch` is prepared and **unrun**; no number may cite it
until it has.

### Q10 — address / split leakage ablation, `paper_mode` (2026-09-13)

`scripts/q10_leakage_ablation.py`, same declared hyperparameters and seed (20260912) as reference
run `20260912T172708Z-6d35b415`, verified identical `config_hash`
(`1f0edc64…ee858e`) across all four cells. `address_dropped x random_split` reproduces the
reference run's random-forest number exactly (0.9479/0.9717), confirming M4a's split was in fact
row-level random, not grouped by address — see the session brief in
`sessions/2026-09-13-01-q10-address-and-split-leakage.md`.

```
2026-09-13 | detection/bitcoinheist-q10 | address_dropped x grouped_split, random_forest, n=46014 | acc=0.9442 f1=0.9697 d_m4a=-0.0037 d_pub=-0.0456 | measured | 20260913T014022Z-c54c3974 | Q10 ablation, new honest baseline
2026-09-13 | detection/bitcoinheist-q10 | address_dropped x grouped_split, logistic_regression, n=46014 | acc=0.9002 f1=0.9475 d_m4a=-0.0477 d_pub=-0.0896 | measured | 20260913T014022Z-c54c3974 | Q10 ablation, new honest baseline
2026-09-13 | detection/bitcoinheist-q10 | address_dropped x grouped_split, decision_tree, n=46014 | acc=0.9224 f1=0.9569 d_m4a=-0.0255 d_pub=-0.0674 | measured | 20260913T014022Z-c54c3974 | Q10 ablation, new honest baseline
2026-09-13 | detection/bitcoinheist-q10 | address_dropped x grouped_split, k_nearest_neighbours, n=46014 | acc=0.8892 f1=0.9410 d_m4a=-0.0587 d_pub=-0.1006 | measured | 20260913T014022Z-c54c3974 | Q10 ablation, new honest baseline
2026-09-13 | detection/bitcoinheist-q10 | address_dropped x random_split, random_forest, n=46014 | acc=0.9479 f1=0.9717 d_m4a=+0.0000 d_pub=-0.0419 | measured | 20260913T014027Z-6b9021ae | Q10 ablation, exact M4a reproduction
2026-09-13 | detection/bitcoinheist-q10 | address_dropped x random_split, logistic_regression, n=46014 | acc=0.9000 f1=0.9474 d_m4a=-0.0479 d_pub=-0.0898 | measured | 20260913T014027Z-6b9021ae | Q10 ablation, exact M4a reproduction
2026-09-13 | detection/bitcoinheist-q10 | address_dropped x random_split, decision_tree, n=46014 | acc=0.9262 f1=0.9590 d_m4a=-0.0217 d_pub=-0.0636 | measured | 20260913T014027Z-6b9021ae | Q10 ablation, exact M4a reproduction
2026-09-13 | detection/bitcoinheist-q10 | address_dropped x random_split, k_nearest_neighbours, n=46014 | acc=0.8861 f1=0.9392 d_m4a=-0.0618 d_pub=-0.1037 | measured | 20260913T014027Z-6b9021ae | Q10 ablation, exact M4a reproduction
2026-09-13 | detection/bitcoinheist-q10 | address_kept x grouped_split, random_forest, n=46014 | acc=0.9484 f1=0.9719 d_m4a=+0.0005 d_pub=-0.0414 | measured | 20260913T014027Z-ca9f3d58 | Q10 ablation
2026-09-13 | detection/bitcoinheist-q10 | address_kept x grouped_split, logistic_regression, n=46014 | acc=0.9001 f1=0.9474 d_m4a=-0.0478 d_pub=-0.0897 | measured | 20260913T014027Z-ca9f3d58 | Q10 ablation
2026-09-13 | detection/bitcoinheist-q10 | address_kept x grouped_split, decision_tree, n=46014 | acc=0.9221 f1=0.9566 d_m4a=-0.0258 d_pub=-0.0677 | measured | 20260913T014027Z-ca9f3d58 | Q10 ablation
2026-09-13 | detection/bitcoinheist-q10 | address_kept x grouped_split, k_nearest_neighbours, n=46014 | acc=0.8894 f1=0.9411 d_m4a=-0.0585 d_pub=-0.1004 | measured | 20260913T014027Z-ca9f3d58 | Q10 ablation
2026-09-13 | detection/bitcoinheist-q10 | address_kept x random_split, random_forest, n=46014 | acc=0.9540 f1=0.9749 d_m4a=+0.0061 d_pub=-0.0358 | measured | 20260913T014037Z-47d61ade | Q10 ablation, largest single cell
2026-09-13 | detection/bitcoinheist-q10 | address_kept x random_split, logistic_regression, n=46014 | acc=0.8996 f1=0.9471 d_m4a=-0.0483 d_pub=-0.0902 | measured | 20260913T014037Z-47d61ade | Q10 ablation
2026-09-13 | detection/bitcoinheist-q10 | address_kept x random_split, decision_tree, n=46014 | acc=0.9354 f1=0.9642 d_m4a=-0.0125 d_pub=-0.0544 | measured | 20260913T014037Z-47d61ade | Q10 ablation, largest single leak (+0.92pt over honest DT)
2026-09-13 | detection/bitcoinheist-q10 | address_kept x random_split, k_nearest_neighbours, n=46014 | acc=0.8901 f1=0.9414 d_m4a=-0.0578 d_pub=-0.0997 | measured | 20260913T014037Z-47d61ade | Q10 ablation
```

**Conclusion: neither candidate, alone or stacked, explains the gap.** Best of all 16 model x cell
combinations is `address_kept x random_split` random forest at 0.9540/0.9749 — still 3.58 points
of accuracy and 2.41 points of F1 below the published 0.9898/0.990. The random split's leakage
(candidate 2) is real but small: isolating it (`dropped x random` minus `dropped x grouped`) moves
random forest by +0.37pt and decision tree by +0.38pt. Address kept as a naive label-encoded
feature (candidate 1) is also real and small alone, but compounds with the random split for
decision tree specifically: `kept x random` reaches +0.92pt over the honest `dropped x grouped`
baseline for that model — the largest single effect measured, and it disappears under a grouped
split (kept x grouped is statistically flat against dropped x grouped), which is exactly the
signature of an identifier being memorised across a train/test boundary that a grouped split
closes. Even that largest effect leaves decision tree at 0.9354, 5.44 points under published.
**Q10 is closed as unexplained**: the paper's 98.98%/0.990 is not accounted for by `address` as a
feature, by the split strategy, or by both together. `docs/DEVIATIONS.md` DEV-06 amended.

**Correction to the honest baseline:** M4a's headline (0.9479/0.9717, random forest) used a
random split and is revised down to `address_dropped x grouped_split`'s 0.9442/0.9697 as the
honest `paper_mode` reproduction figure going forward — grouping by address is the methodologically
correct choice once duplication is address-keyed, and random forest remains best of the four
models under it. `scripts/run_detection.py` still runs the random split by default; see
`PROJECT_STATE.md` carried debt D6.
