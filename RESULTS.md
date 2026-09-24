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

## Detection — Table II, Figs. 4-5, full-scale `honest_mode` (M6b)

`make repro` (`scripts/run_detection.py --seed 20260912 --mode paper --full`) — reproduces the D6
figure exactly, at the entry point CLAUDE.md §5 documents rather than a one-off script invocation:

```
2026-09-17 | detection/bitcoinheist-paper | random_forest, 90/10 n=46014, grouped split | acc=0.9442 f1=0.9697 | measured | 20260917T175743Z-be5c55e0 | Table II target, D6 retired (DEV-06), via make repro
2026-09-17 | detection/bitcoinheist-paper | logistic_regression, 90/10 n=46014, grouped split | acc=0.9002 f1=0.9475 | measured | 20260917T175743Z-be5c55e0 | Table II target, D6 retired (DEV-06), via make repro
2026-09-17 | detection/bitcoinheist-paper | decision_tree, 90/10 n=46014, grouped split | acc=0.9224 f1=0.9569 | measured | 20260917T175743Z-be5c55e0 | Table II target, D6 retired (DEV-06), via make repro
2026-09-17 | detection/bitcoinheist-paper | k_nearest_neighbours, 90/10 n=46014, grouped split | acc=0.8892 f1=0.9410 | measured | 20260917T175743Z-be5c55e0 | Table II target, D6 retired (DEV-06), via make repro
2026-09-17 | detection/bitcoinheist-paper | constant-positive, 90/10 n=46014, grouped split | acc=0.9000 f1=0.9474 | measured | 20260917T175743Z-be5c55e0 | baseline, via make repro
```

`results/tables/table2_paper_mode.csv` and Figs. 4-5 (+ baseline-annotated variants) emitted from
this run — `results/figures/fig4_accuracy(_baseline).png`, `fig5_f1(_baseline).png`.

`make honest` (`--mode honest --full`, 8 GB dev-box ceiling) — the **full 2,916,697-row**
`honest_mode` run, not the 200K subsample M4a used. RF/LR/DT ran on every row; KNN's full-scale
projection (17.94 GB) exceeds the 8 GB ceiling, so it ran on a 780,336-row stratified subsample
instead of being deferred outright (DEV-31):

```
2026-09-17 | detection/bitcoinheist-honest | random_forest, natural 2916697 rows | prec=0.7434 rec=0.2874 pr_auc=0.4653 mcc=0.4579 f1min=0.4145 | measured | 20260917T175754Z-f3b9e363 | DEV-06 honest mode, full scale, via make honest
2026-09-17 | detection/bitcoinheist-honest | logistic_regression, natural 2916697 rows | prec=0.0000 rec=0.0000 pr_auc=0.0177 mcc=0.0000 f1min=0.0000 | measured | 20260917T175754Z-f3b9e363 | DEV-06 honest mode, full scale, via make honest
2026-09-17 | detection/bitcoinheist-honest | decision_tree, natural 2916697 rows | prec=0.3970 rec=0.4236 pr_auc=0.1797 mcc=0.4013 f1min=0.4099 | measured | 20260917T175754Z-f3b9e363 | DEV-06 honest mode, full scale, via make honest
2026-09-17 | detection/bitcoinheist-honest | k_nearest_neighbours, natural 780336 rows | prec=0.5410 rec=0.1716 pr_auc=0.1701 mcc=0.2995 f1min=0.2605 | measured | 20260917T175754Z-f3b9e363 | DEV-06 honest mode, subsampled for memory (full n=2916697, ceiling=8.0GB, DEV-31), via make honest
```

At full scale, RF's MCC rises from 0.331 (M4a's 200K subsample, best-of-four there) to 0.458 —
more data helps, unsurprisingly, and the paper's methodology never had the chance to show this
because it never evaluated at the natural class balance at all. `results/tables/table2_honest_mode.csv`
carries the confusion matrix and balanced accuracy per model alongside these.

**Ada, full-scale KNN, `scripts/ada_honest_mode.sbatch` (DEV-31).** Adapted three times this
session, each correction found by actually trying, not guessed in advance:

1. Account's real SLURM limits (`u22` partition, `research` account, `low` QOS: 10 cpus /
   30000M max — `sacctmgr`/`scontrol`, not the M4a placeholder's `--mem=64G --cpus-per-task=16`).
2. `/share1` (the first working-directory choice — large, nearly-empty quota) turned out to be
   **login-node-only**: invisible to compute nodes, so a job that wrote there failed at
   output-file-open time with no script output at all. Corrected to a `/scratch`-per-job design,
   caught by two 5-minute test jobs before a real run repeated the mistake.
3. **Job 2700027** (first real submission) ran for 1h25m — venv built successfully — then died
   on the *dataset* download: `http.client.IncompleteRead`, ~55 KB into a ~50 MB archive, no
   retry logic in `scripts/fetch_bitcoinheist.py`'s single-shot `urlopen`. Fixed with a
   `Range`-header retry/resume loop (`_download_with_retry`, 8 attempts) so a drop late in a slow
   transfer costs seconds, not the whole file — and the sbatch now persists the built venv to
   `$HOME_CHECKOUT/.venv-ada-persist` (NFS-shared, survives the job) so a retry after a
   *later* transient failure does not repeat the ~1h pip install too.

**Resubmitted as job 2700090.** Queued `PENDING` (`QOSMaxCpuPerUserLimit`) behind a second,
unrelated job already running on this account (`2700069`, not started by this session) that was
using 4 of the 10-cpu QOS budget; started automatically once that job's quota usage dropped, ran
36m26s, and **completed cleanly** (exit 0) — all within the same session. Host: Linux x86_64,
Python 3.12.4, seed 20260912, `full_scale: true`, `deferred: {}` — nothing deferred, KNN ran on
every one of the 2,916,697 rows this time, not a subsample:

```
2026-09-18 | detection/bitcoinheist-honest | random_forest, natural 2916697 rows | prec=0.7442 rec=0.2864 pr_auc=0.4646 mcc=0.4573 f1min=0.4136 | measured | 20260917T201959Z-6e05408c | DEV-06 honest mode, full scale, Ada job 2700090
2026-09-18 | detection/bitcoinheist-honest | logistic_regression, natural 2916697 rows | prec=0.0000 rec=0.0000 pr_auc=0.0177 mcc=0.0000 f1min=0.0000 | measured | 20260917T201959Z-6e05408c | DEV-06 honest mode, full scale, Ada job 2700090
2026-09-18 | detection/bitcoinheist-honest | decision_tree, natural 2916697 rows | prec=0.3972 rec=0.4231 pr_auc=0.1797 mcc=0.4012 f1min=0.4097 | measured | 20260917T201959Z-6e05408c | DEV-06 honest mode, full scale, Ada job 2700090
2026-09-18 | detection/bitcoinheist-honest | k_nearest_neighbours, natural 2916697 rows | prec=0.6008 rec=0.2286 pr_auc=0.2242 mcc=0.3654 f1min=0.3312 | measured | 20260917T201959Z-6e05408c | DEV-06 honest mode, full scale, Ada job 2700090
```

**KNN at full scale (2.9M rows) is meaningfully better than the local 780,336-row subsample**:
MCC 0.365 vs. 0.300, precision 0.601 vs. 0.541, recall 0.229 vs. 0.172 — more data helps KNN too,
not just RF/DT. `results/tables/table2_honest_mode.csv` now holds this full-scale run (all four
models, none subsampled) in place of the local, KNN-subsampled one; the local run's KNN row stays
above for provenance (`DEV-31`'s fallback demonstrated for real, not hypothetically) but is no
longer "the" honest_mode figure. RF and DT's full-scale numbers barely moved from the local run
(RF mcc 0.4579→0.4573, DT 0.4013→0.4012) — expected, since both already saw the same full
2,916,697 rows locally; only KNN's row changed, because only KNN was subsampled locally.

This closes the item `docs/DEVIATIONS.md` DEV-31 and `scripts/ada_honest_mode.sbatch` existed to
produce, and does so **within the same session it was diagnosed as not-yet-complete in** — the
"submitted, not completed" fallback this paragraph used to describe turned out to be a snapshot
partway through a job that finished 36 minutes later, not the session's final word on it.

## D3 closed (2026-09-19) — measured, not estimated

`consensus.network.P2PCSNetwork` gained a `serialize=` hook (opaque `object -> object`, so the
bus still imports nothing internal); `consensus.pbft.Cluster` wires it to
`consensus.protocol.encode_message`/`decode_message` when `consensus.serialize_messages` is on
(`configs/chain.yaml` default off for `make test`, `configs/bench.yaml` override on for bench
runs). Case-3, both chains, n=25, same seeds, serialize on vs. off:

```
2026-09-19 | bench/d3-measured | BC_DTBU case_3 15blk x 100tx, n=25 | seconds_off=0.48785 seconds_on=0.81785 delta=+67.64% | measured | 20260919T013422Z-1cf934ad | D3 closed; supersedes DEV-30's encode-only ~0.33% estimate
2026-09-19 | bench/d3-measured | BC_SigRW case_3 15blk x 100tx, n=25 | seconds_off=0.68031 seconds_on=1.01215 delta=+48.78% | measured | 20260919T013422Z-1cf934ad | D3 closed; supersedes DEV-30's encode-only ~0.16% estimate
```

**The real magnitude is ~50-70%, not the ~0.2-0.3% DEV-30's M6a estimate reported.** The estimate
priced one `encode_block()` per committed block (the primary's `Proposal` broadcast, reused for
every recipient, decode cost excluded). The real bus pays encode+decode on *every* `send()` call —
28 messages per committed block at `n=4`
(`test_pbft.py::test_message_count_per_block_is_the_textbook_pbft_count`) — so the estimate was a
lower bound in the literal sense stated at the time, just a far looser one than "small relative to
compute" suggested. `docs/DEVIATIONS.md` DEV-30 amended accordingly; `docs/report/report.tex`
never stated the 0.2-0.3% figure (checked — it has no D3/serialization mention at all), so there
is no report number to correct here.

## Bench reconfirmation — serialization ON, honest conditions (2026-09-22)

D3's closure (above) measured +48-68% at case-3 only, one-off, n=25. Every timing number the
report presents (Table V/VI, Fig. 1's Figs. 6(a)-(d)) was measured *before* `configs/bench.yaml`
gained `network.serialize_messages: true` and is therefore serialization-OFF. This section re-runs
the **full** M6a matrix — all three cases, both chains — under the now-current, serialization-ON
config, so every published timing claim has an honest-condition counterpart on record before
anything is presented or built on further.

`scripts/run_bench.py --seed 20260917 --no-figures` (same seed, same `decide_repeat_count` logic
as the M6a run below; `--no-figures` so this run's numbers do not silently overwrite the existing
serialization-OFF Figs. 6(a)-(d)/`target3_target4.csv` — those stay as the record of what they
were measured under). The variance probe read CV ≈1.3% on both chains this time (quiet machine),
so `decide_repeat_count` kept the floor of 5 repeats rather than M6a's 25 — the same *logic*, a
different repeat count decided from a different variance reading, exactly as already happened once
between M6a's own two back-to-back runs (see that section above). `trend_resolvable` is `True` on
both chains at this repeat count.

```
2026-09-22 | bench/target3-time-serialized | BC_DTBU case_1 5blk x 100tx, n=5 | seconds=0.27057 stdev=0.00048 tps=1848.0 | measured | 20260922T172916Z-22992372 | serialize_messages=true; cf. no-serialization 0.16822s (+60.85%)
2026-09-22 | bench/target3-time-serialized | BC_SigRW case_1 5blk x 100tx, n=5 | seconds=0.34024 stdev=0.00079 tps=1469.5 | measured | 20260922T172916Z-22992372 | serialize_messages=true; cf. no-serialization 0.22774s (+49.40%)
2026-09-22 | bench/target3-time-serialized | BC_DTBU case_2 10blk x 100tx, n=5 | seconds=0.54373 stdev=0.01001 tps=1839.1 | measured | 20260922T172916Z-22992372 | serialize_messages=true; cf. no-serialization 0.34124s (+59.34%)
2026-09-22 | bench/target3-time-serialized | BC_SigRW case_2 10blk x 100tx, n=5 | seconds=0.67746 stdev=0.00482 tps=1476.1 | measured | 20260922T172916Z-22992372 | serialize_messages=true; cf. no-serialization 0.45902s (+47.59%)
2026-09-22 | bench/target3-time-serialized | BC_DTBU case_3 15blk x 100tx, n=5 | seconds=0.81886 stdev=0.02551 tps=1831.8 | measured | 20260922T172916Z-22992372 | serialize_messages=true; cf. no-serialization 0.47895s (+70.96%), cf. D3's own case-3-only n=25 reading +67.6%
2026-09-22 | bench/target3-time-serialized | BC_SigRW case_3 15blk x 100tx, n=5 | seconds=1.04285 stdev=0.03659 tps=1438.4 | measured | 20260922T172916Z-22992372 | serialize_messages=true; cf. no-serialization 0.69141s (+50.83%), cf. D3's own case-3-only n=25 reading +48.8%
2026-09-22 | bench/variance-case3-serialized | BC_DTBU n=12 | mean=0.80267 stdev=0.01071 cv=0.0133 | measured | 20260922T172916Z-22992372 | quiet-machine reading; repeats stayed at floor (5)
2026-09-22 | bench/variance-case3-serialized | BC_SigRW n=12 | mean=1.02225 stdev=0.01316 cv=0.0129 | measured | 20260922T172916Z-22992372 | quiet-machine reading; repeats stayed at floor (5)
```

**Marginal per-block cost, serialize ON** (mean seconds/block over the full case, not just the
first 3): `BC_DTBU` 0.05409 / 0.05426 / 0.05429 (case 1/2/3); `BC_SigRW` 0.06797 / 0.06777 / 0.06878.
Compare to the serialization-OFF marginal costs already in `RESULTS.md`/`docs/report/report.tex`
Table VI: `BC_DTBU` 0.0335/0.0334/0.0316; `BC_SigRW` 0.0455/0.0450/0.0450.

**a) Does marginal cost stay flat? Yes — DEV-08 survives.** Both chains' marginal cost varies by
<1% across cases 1-3 under serialization, same as without it — just uniformly ~60-65% (`BC_DTBU`)
/ ~50% (`BC_SigRW`) higher in absolute terms. Serialization adds a per-message tax, not a
per-block-count-dependent one, so it does not reintroduce the amortisation shape DEV-08 already
ruled out.

**b) Does the BC_SigRW/BC_DTBU gap stay at 35-45%? No — it narrows to ~25-27%, and this is a real
finding, not noise.** Recomputed per case from the table above: case 1 +25.76%, case 2 +24.60%,
case 3 +27.36% (marginal-cost basis: +25.66%/+24.90%/+26.69%, consistent). The *absolute*-seconds
gap between the two chains still grows slightly under serialization (case 3: 0.212s → 0.224s), but
`BC_DTBU`'s own base grew proportionally more (+71% on a smaller starting number) than the
absolute gap did, so the *percentage* gap shrinks. Reading: serialization's per-message encode/
decode cost is close to constant across the two chains in absolute terms (`BC_SigRW`'s own D3
estimate above is barely larger than `BC_DTBU`'s: 0.000073s vs 0.000072s per block, encode-only),
so it dilutes — without eliminating — ECDSA/payload-encoding's share of the gap rather than adding
to it proportionally. **The structural ECDSA/payload-encoding attribution is not wrong** (it is
still the isolated, measured cause of the serialization-OFF 35-45% gap, and that number is
unchanged and still correctly reported wherever it is quoted) **but is no longer the whole picture
once serialization is counted**, and any future claim about "the gap" must say which condition it
is under. `docs/EXPERIMENTS.md` Target 3 and `docs/DEVIATIONS.md` DEV-30 amended with this finding.

**c) Do the trends still hold? Yes, on every axis checked**: monotone increasing (both chains,
both conditions), `trend_resolvable=True` at the decided repeat count, `BC_SigRW` slower than
`BC_DTBU` (narrower gap, but never inverts or approaches parity), and TPS is flat rather than
rising (`BC_DTBU` ~1832-1848 tx/s, `BC_SigRW` ~1438-1476 tx/s across cases — lower than the
serialization-OFF ~2930-3190/~2170-2230 tx/s, and still flat).

Full sidecar: `results/logs/20260922T172916Z-22992372.json` (includes the Q2 payload-sweep and D3
encode-estimate re-measurements too, consistent with their prior values within run-to-run noise;
not reproduced in full here since neither is what this reconfirmation was checking).

### M4a/M4b — reconfirmed byte-reproducible, same seeds (2026-09-22)

Not exposed to D3 (no consensus traffic in the detection pipeline's ML path), but presented
alongside the bench numbers above, so verified rather than assumed per this session's brief.
`make repro` (`20260922T173217Z-69eb48f0`), `make honest` (`20260922T173229Z-87832d2b`) and
`scripts/run_phase3_detection.py --seed 20260912` (`20260922T173724Z-b99c8896`) were all re-run:
every number — `paper_mode`'s four models + baseline, `honest_mode`'s four models + baseline (KNN
locally subsampled to 780,336 rows, matching run `20260917T175754Z-f3b9e363`, not the Ada
full-scale run this table cites — Ada was not re-run this session, out of scope), and M4b's
ensemble `bal_acc=0.8422 prec=0.8439 rec=0.8272 mcc=0.6849 pr_auc=0.9100` — matched its existing
`RESULTS.md` line exactly, to the precision both report. No new numeric lines added here since
nothing differs from what is already published; the run_ids above are the provenance for this
session's "confirmed, not assumed" check. One incidental correction made while checking:
`make honest`'s run overwrote `results/tables/table2_honest_mode.csv` with the local
KNN-subsampled numbers, clobbering the canonical Ada full-scale row recorded in the same table
(git showed the diff immediately); restored via `git checkout -- results/tables/table2_honest_mode.csv`
before anything else touched it. `make honest` should not be re-run casually without regenerating
the Ada row afterward — noted in `PROJECT_STATE.md`.

## M7-3 — adversarial robustness of the honeypot detector (2026-09-22)

`scripts/run_adversarial_robustness.py --seed 20260912`: fits `configs/ml.yaml`'s four models plus
`NProf`/`AProf` once on the committed `data/honeypot/corpus_{train,eval}.csv` (never the chain
path, per DEV-27's "committed corpus is the fixed dataset"; never retrained after), then perturbs
the eval corpus's 353 malicious rows toward the top-5 Random-Forest-important features' physically
plausible bounds. Full method, bounds table and figures: `docs/report/report.tex`
§Adversarial Robustness (after §VI); sidecar `results/logs/20260922T155316Z-3ce801ca.json`.

**0% perturbation reproduces 0.8408, not RESULTS.md's chain-path 0.8422 — a real, explained
0.0014 gap, not a framework bug.** `honeypot/corpus.py`'s `write_corpus` formats every feature to
6 significant figures (`f"{value:.6g}"`); the M4b entry above was read back through `BC_SigRW`'s
full-precision `SignatureRecordPayload`, never through the CSV. Verified directly: loading the
committed CSVs and scoring with zero perturbation code in the path already gives 0.8408. Every
number below is relative to 0.8408.

```
2026-09-22 | detection/honeypot-adversarial | feature importances, random_forest (individual bal_acc=0.8513, beats decision_tree 0.8063) | top5: observed_stages=0.1259 extension_change_rate=0.1091 rename_rate_per_s=0.0792 write_entropy_var=0.0741 crypto_ngram_novelty=0.0670 | measured | 20260922T155316Z-3ce801ca | M7-3
2026-09-22 | detection/honeypot-adversarial | ensemble baseline, committed corpus, 0% perturbation | bal_acc=0.8408 | measured | 20260922T155316Z-3ce801ca | M7-3, cf. M4b 0.8422 (chain-path float precision, see above)
2026-09-22 | detection/honeypot-adversarial | single-feature evasion, 100% perturbation each | observed_stages=0.784 extension_change_rate=0.810 rename_rate_per_s=0.814 write_entropy_var=0.752 crypto_ngram_novelty=0.830 | measured | 20260922T155316Z-3ce801ca | none cross 0.50; largest single-feature drop write_entropy_var (-0.089)
2026-09-22 | detection/honeypot-adversarial | combined evasion, top-5 simultaneous | frac=0.0:0.841 frac=0.5:0.635 frac=0.7:0.576 frac=1.0:0.570 | measured | 20260922T155316Z-3ce801ca | floor ~0.57-0.60, never reaches 0.50 — top-5 carry only 45.5% of RF importance
2026-09-22 | detection/honeypot-adversarial | adaptive evasion, n=353 positive eval rows | p10=0.0000 median=0.3213 p90=0.9771 | measured | 20260922T155316Z-3ce801ca | 61/353 (17.3%) already miss at 0% perturbation; 28/353 (7.9%) never flip even at t=1.0
```

**Adaptive evasion is far more effective than blind perturbation, and unevenly so.** A quarter of
malicious eval rows (25.2%) are evadable with ≤5% of the physically plausible perturbation range —
17.3 points of that is baseline false negatives the detector already misses. The hardest 10% of
samples need ≥97.7% of the range. The 28 rows that never flip (7.9%) are the eval set's most
extreme on features ranked 6th-10th (`c2_beacon_count`, `entropy_delta`, `key_generation_events`,
`shadow_copy_deletions`, `dns_entropy` — all never perturbed here): survivors average
`c2_beacon_count` 10.3 vs. 7.0 for the malicious class overall, and similarly elevated on the
other four — confirming they survive because they rely on unperturbed features, exactly the check
the session's own exit test asked for.

**Finding shape: (c), the nuanced answer** (per the session brief's own taxonomy). No single top-5
feature, and no combination of exactly these five, collapses the detector to uselessness — the
ensemble's real reliance on the other 17 features holds it above 0.57 even at 100% combined
perturbation. But a median-effort *adaptive* adversary needs only ~32% of the evasion range, and a
quarter of ransomware samples are trivially evadable. Figures:
`results/figures/fig7{a,b,c}_{single_feature_degradation,combined_evasion,adaptive_evasion_histogram}.png`,
each with a sidecar JSON alongside it.

---

## M7-4 — pBFT vs Raft consensus comparison

`scripts/run_consensus_comparison.py --seed 20260924`: cases 1-3, both chains, both consensus
protocols, serialization on (same condition as `bench/target3-time-serialized`), 5 repeats/1
warmup each. Sidecar `results/logs/20260924T045952Z-2eaa456f.json`. `docs/DEVIATIONS.md` DEV-32,
`docs/report/report.tex` \S "Consensus Comparison: pBFT vs.\ Raft".

```
2026-09-24 | consensus/m7-4-comparison | pbft BC_DTBU case_1 5blk x 100tx, n=5 | seconds=0.27080 tps=1846.4 messages=140 sig_ops=140 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | raft BC_DTBU case_1 5blk x 100tx, n=5 | seconds=0.24608 tps=2031.8 messages=92 sig_ops=0 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | pbft BC_SigRW case_1 5blk x 100tx, n=5 | seconds=0.33965 tps=1472.1 messages=140 sig_ops=140 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | raft BC_SigRW case_1 5blk x 100tx, n=5 | seconds=0.31417 tps=1591.5 messages=92 sig_ops=0 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | pbft BC_DTBU case_2 10blk x 100tx, n=5 | seconds=0.54898 tps=1821.6 messages=280 sig_ops=280 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | raft BC_DTBU case_2 10blk x 100tx, n=5 | seconds=0.49230 tps=2031.3 messages=172 sig_ops=0 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | pbft BC_SigRW case_2 10blk x 100tx, n=5 | seconds=0.68066 tps=1469.2 messages=280 sig_ops=280 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | raft BC_SigRW case_2 10blk x 100tx, n=5 | seconds=0.63781 tps=1567.9 messages=172 sig_ops=0 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | pbft BC_DTBU case_3 15blk x 100tx, n=5 | seconds=0.84327 tps=1778.8 messages=420 sig_ops=420 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | raft BC_DTBU case_3 15blk x 100tx, n=5 | seconds=0.74997 tps=2000.1 messages=252 sig_ops=0 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | pbft BC_SigRW case_3 15blk x 100tx, n=5 | seconds=1.02303 tps=1466.2 messages=420 sig_ops=420 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
2026-09-24 | consensus/m7-4-comparison | raft BC_SigRW case_3 15blk x 100tx, n=5 | seconds=0.94830 tps=1581.8 messages=252 sig_ops=0 | measured | 20260924T045952Z-2eaa456f | serialization ON, DEV-32
```

**Messages are flat per block, at two different levels: pBFT 28/block in every case; Raft
converges to ~16.8/block as leader-election's one-time cost amortises** (`18.4 -> 17.2 -> 16.8`
across cases 1-3). Raft sends ~60% of pBFT's message count at this `n=4` — real, but far short of
the O(n)-vs-O(n^2) asymptotic gap a larger cluster would show. **Signature operations: pBFT
matches its own message count exactly (one ECDSA op per consensus message); Raft is exactly zero
in every cell** — no signing in the consensus path by design. **Timing gap (7-11%) is much smaller
than the message-count gap (~40%)**: consistent with DEV-08/DEV-21 — consensus messaging is a
small fraction of measured wall-clock at zero simulated network delay, so a smaller message count
buys a proportionally smaller speedup; hybrid encryption and (serialization-on) message encoding
dominate.

**Qualitative — same run, fixed small scale (3 blocks, 1-of-4 node crashed/byzantine):**
`crash_tolerance_pbft`/`crash_tolerance_raft`: both protocols commit all 3 blocks on the 3 live
replicas with 1 node silently crashed from the start (`live_heights` all `3`).
`raft_byzantine_fork`: a byzantine Raft leader sends genuinely different, honestly-signed
transaction sets to different followers at one log index; all four nodes reach height 2, but two
of three followers hold block hash `ebd2c097fd90b599...` and the third holds
`a6cf98b3bdd0447e...` — a real, undetected fork, each side individually chain-valid. Reproduced as
a standing regression test, `tests/unit/test_raft_byzantine.py`.
