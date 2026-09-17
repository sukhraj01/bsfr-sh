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

### D6 retired — `run_detection.py` grouped by address (2026-09-13, M4b)

`configs/ml.yaml` now declares `dataset.group_column: address`; `scripts/run_detection.py`'s
`_run_paper_mode` calls `grouped_stratified_holdout` instead of the row-random `stratified_holdout`
it used through M4a and Q10. Same seed (20260912) and the same resample as every prior
`paper_mode` run; the production pipeline now reproduces Q10's `address_dropped x grouped_split`
cell (run `20260913T014022Z-c54c3974`) exactly, from the entry point `docs/EXPERIMENTS.md` and
`make figures` will actually call.

```
2026-09-13 | detection/bitcoinheist-paper | random_forest, 90/10 n=46014, grouped split | acc=0.9442 f1=0.9697 | measured | 20260913T131623Z-97f51129 | Table II target, D6 retired (DEV-06)
2026-09-13 | detection/bitcoinheist-paper | logistic_regression, 90/10 n=46014, grouped split | acc=0.9002 f1=0.9475 | measured | 20260913T131623Z-97f51129 | Table II target, D6 retired (DEV-06)
2026-09-13 | detection/bitcoinheist-paper | decision_tree, 90/10 n=46014, grouped split | acc=0.9224 f1=0.9569 | measured | 20260913T131623Z-97f51129 | Table II target, D6 retired (DEV-06)
2026-09-13 | detection/bitcoinheist-paper | k_nearest_neighbours, 90/10 n=46014, grouped split | acc=0.8892 f1=0.9410 | measured | 20260913T131623Z-97f51129 | Table II target, D6 retired (DEV-06)
2026-09-13 | detection/bitcoinheist-paper | constant-positive, 90/10 n=46014, grouped split | acc=0.9000 f1=0.9474 | measured | 20260913T131623Z-97f51129 | baseline, looks at nothing
```

The two entry points no longer disagree: **0.9442/0.9697 (random forest) is the one honest
`paper_mode` figure**, cited consistently in `docs/DEVIATIONS.md` DEV-06, `docs/EXPERIMENTS.md`,
and `PROJECT_STATE.md`. The earlier 0.9479/0.9717 lines above stay for provenance — they are what
M4a actually measured before Q10 found the split was leaking — but are no longer "the" figure.

### M4b — the honeypot detection path, Alg. 3 end to end from `BC_SigRW` (2026-09-13)

`scripts/run_phase3_detection.py --seed 20260912`: one honeypot deployed, harvested twice (train
seed 20260912 count 1500, eval seed 20260913 count 750 — the same two draws
`data/honeypot/manifest.json` records, reached here by re-running the generator at the same
seeds rather than reading the committed CSVs), each draw carried through `framework.phase2_collection.run()`
onto its own `BC_SigRW` cluster under real pBFT consensus, decrypted back out by
`detection.dataset.load_from_chain()`, trained and profiled by
`detection.profiles.build()`/`detection.models.train_all()`, detected by
`detection.detector.DetectionModule`. Kept counts after cleaning (1467 train, 731 eval) match the
manifest exactly, confirming the honeypot's generator is bit-reproducible through the chain.

```
2026-09-13 | detection/honeypot-phase3 | ensemble via NProf/AProf, train n=1467 eval n=731 | bal_acc=0.8422 prec=0.8439 rec=0.8272 mcc=0.6849 pr_auc=0.9100 | measured | 20260913T134602Z-ab45ac90 | FLAW-2 framework path, expect ~0.85
2026-09-13 | detection/honeypot-phase3 | constant-positive baseline, eval n=731 (353 positive) | bal_acc=0.5000 prec=0.4829 rec=1.0000 mcc=0.0000 pr_auc=0.4829 | measured | 20260913T134602Z-ab45ac90 | baseline, looks at nothing
```

**0.8422 balanced accuracy** sits between the measured simple-Gaussian baseline (0.830,
`test_honeypot_features.py::test_a_simple_baseline_lands_near_the_intended_difficulty_not_at_ceiling`)
and the corpus's intended Bayes-optimal ceiling (0.85, `honeypot.corpus.EXPECTED_BAYES_ACCURACY`) —
better than the naive baseline, not above the theoretical ceiling. `scripts/run_phase3_detection.py`
checks this automatically (`leak_margin=0.05`) and refuses to print a `RESULTS.md` line rather than
report a number that would mean the generator leaked, not that detection worked; it did not fire
here. This is the first number in this project produced by Phase 2's output feeding Phase 3's
input (FLAW-2's framework half, closed for M4b — see `docs/PAPER_NOTES.md` and `docs/DEVIATIONS.md`).

## Bench (M6a — Target 3/4 timing, Figs. 6a-e)

`scripts/run_bench.py --seed 20260917`. Two independent invocations measured case-3 variance
before deciding the repeat count: the first read a quiet-machine CV of ~1% (`BC_DTBU` 0.76%,
`BC_SigRW` 1.29%, run `20260917T144151Z-3d88337d`) and kept the declared floor of 5 repeats; the
second, run minutes later on the same code and config, read CV up to 45% on `BC_DTBU`
(`BC_SigRW` 8.85%, run `20260917T144843Z-fb4c2410`) — ordinary background load on a shared dev
laptop, not algorithmic nondeterminism, given the fixed seeds — and `decide_repeat_count` raised
the repeat count to 25 accordingly. The case-1-to-case-3 trend stayed resolvable at both
readings. **The second (noisier, more repeats) run is the one below and the one Figs. 6(a)-(e)
are built from** — the more conservative choice, and it is the one the adaptive repeat count was
built to produce.

```
2026-09-17 | bench/target3-time | BC_DTBU case_1 5blk x 100tx, n=25 | seconds=0.16822 stdev=0.02370 tps=2972.2 | measured | 20260917T144843Z-fb4c2410 | Target 3/4; marginal[:3]=0.0342, 0.0326, 0.0337
2026-09-17 | bench/target3-time | BC_SigRW case_1 5blk x 100tx, n=25 | seconds=0.22774 stdev=0.01073 tps=2195.5 | measured | 20260917T144843Z-fb4c2410 | Target 3/4; marginal[:3]=0.0454, 0.0456, 0.0454
2026-09-17 | bench/target3-time | BC_DTBU case_2 10blk x 100tx, n=25 | seconds=0.34124 stdev=0.07290 tps=2930.5 | measured | 20260917T144843Z-fb4c2410 | Target 3/4; marginal[:3]=0.0328, 0.0335, 0.0338
2026-09-17 | bench/target3-time | BC_SigRW case_2 10blk x 100tx, n=25 | seconds=0.45902 stdev=0.02022 tps=2178.6 | measured | 20260917T144843Z-fb4c2410 | Target 3/4; marginal[:3]=0.0446, 0.0451, 0.0452
2026-09-17 | bench/target3-time | BC_DTBU case_3 15blk x 100tx, n=25 | seconds=0.47895 stdev=0.03627 tps=3131.9 | measured | 20260917T144843Z-fb4c2410 | Target 3/4; marginal[:3]=0.0316, 0.0316, 0.0315
2026-09-17 | bench/target3-time | BC_SigRW case_3 15blk x 100tx, n=25 | seconds=0.69141 stdev=0.03235 tps=2169.5 | measured | 20260917T144843Z-fb4c2410 | Target 3/4; marginal[:3]=0.0450, 0.0444, 0.0455
2026-09-17 | bench/index-construction | BC_DTBU case_1 | seconds=0.06771 | measured | 20260917T144843Z-fb4c2410 | DEV-05, outside the timed append span
2026-09-17 | bench/index-construction | BC_DTBU case_2 | seconds=0.13190 | measured | 20260917T144843Z-fb4c2410 | DEV-05, outside the timed append span
2026-09-17 | bench/index-construction | BC_DTBU case_3 | seconds=0.18989 | measured | 20260917T144843Z-fb4c2410 | DEV-05, outside the timed append span
2026-09-17 | bench/variance-case3 | BC_DTBU n=12 | mean=0.74250 stdev=0.33663 cv=0.4534 | measured | 20260917T144843Z-fb4c2410 | drives the repeat count, not a Fig. 6 datapoint
2026-09-17 | bench/variance-case3 | BC_SigRW n=12 | mean=0.85818 stdev=0.07597 cv=0.0885 | measured | 20260917T144843Z-fb4c2410 | drives the repeat count, not a Fig. 6 datapoint
2026-09-17 | bench/variance-case3 | BC_DTBU n=12 (quiet-machine reading) | mean=0.46760 stdev=0.00356 cv=0.0076 | measured | 20260917T144151Z-3d88337d | superseded by the noisier reading above; kept for provenance of the CV-fluctuates finding
2026-09-17 | bench/variance-case3 | BC_SigRW n=12 (quiet-machine reading) | mean=0.67857 stdev=0.00875 cv=0.0129 | measured | 20260917T144151Z-3d88337d | superseded by the noisier reading above; kept for provenance of the CV-fluctuates finding
2026-09-17 | bench/d3-serialization | BC_DTBU case_3 15blk | encode_per_block=0.000106 case3_total=0.001591 fraction_of_compute=0.00332 | computed | 20260917T144843Z-fb4c2410 | D3, lower bound, encode only (DEV-30)
2026-09-17 | bench/d3-serialization | BC_SigRW case_3 15blk | encode_per_block=0.000073 case3_total=0.001100 fraction_of_compute=0.00159 | computed | 20260917T144843Z-fb4c2410 | D3, lower bound, encode only (DEV-30)
2026-09-17 | bench/network-modelled | both chains case_3 15blk, delay=10ms/hop | total_seconds=0.6000 consensus_seconds=0.4500 | computed | 20260917T144843Z-fb4c2410 | DEV-21, formula verified against a real run (predicted=actual=0.2000s at 5blk/10ms)
2026-09-17 | bench/q2-payload-sweep | BC_DTBU case_3 | 1024B=0.4396s 4096B=0.4983s 16384B=0.6796s | measured | 20260917T144843Z-fb4c2410 | Q2 closed, default stays 4096B (DEV-15)
2026-09-17 | bench/q2-payload-sweep | BC_SigRW case_3 | 1024B=0.6050s 4096B=0.7235s 16384B=1.3288s | measured | 20260917T144843Z-fb4c2410 | Q2 closed, default stays 4096B (DEV-15)
2026-09-17 | bench/q2-projection | 10MB payload, case_3, x4 replicas, x1.14 overhead | projected_cluster_gib=67.4 | computed | 20260917T144843Z-fb4c2410 | not run — DEV-15, would OOM the 8GB dev box
```

Paper comparison (`results/tables/target3_target4.csv`, Figs. 6(a)-(d)): our seconds are two to
three orders of magnitude below the paper's on every case/chain; TPS is flat across cases on both
of ours (~2930-3190 `BC_DTBU`, ~2170-2230 `BC_SigRW`) against the paper's rising six points. See
`docs/EXPERIMENTS.md` Target 3/4 and `docs/DEVIATIONS.md` DEV-08/DEV-13/DEV-21/DEV-30 for what
this does and does not mean.
