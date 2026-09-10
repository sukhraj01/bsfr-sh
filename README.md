# BSFR-SH

A from-scratch Python implementation of the blockchain-enabled ransomware defense framework
described in:

> M. Wazid, A. K. Das and S. Shetty, "BSFR-SH: Blockchain-Enabled Security Framework Against
> Ransomware Attacks for Smart Healthcare," *IEEE Transactions on Consumer Electronics*,
> vol. 69, no. 1, pp. 18–28, February 2023. DOI: 10.1109/TCE.2022.3208795

Course project. Built as an extendable research base rather than a one-shot reproduction.

---

## What it does

Five phases, two independent private blockchains, pBFT consensus, ECDSA-signed blocks, and an
ML detection module.

1. **Backup creation** — healthcare data encrypted into transactions, mined into `BC_DTBU`
2. **Collection** — honeypot samples turned into ransomware signatures and behavioural features,
   mined into `BC_SigRW`
3. **Detection** — RF / LogReg / DecisionTree / KNN trained on the chain-held signature base
4. **Mitigation** — isolate, then quarantine, restore, or block by policy
5. **Recovery** — restore from `BC_DTBU` after a wipe

The idea worth keeping: the chain protects both the detector's ground truth *and* the backups, so
an attacker can neither poison detection nor destroy recovery.

---

## Three things this repo does that the paper does not

**Reproduces honestly.** The paper evaluates on BitcoinHeist resampled to 90% ransomware / 10%
benign, then reports 98.98% accuracy. On that split, a classifier that always answers
"ransomware" scores 90.0% accuracy and 0.947 F1. We reproduce the published numbers *and* rerun
on the dataset's natural 1.42% positive rate with precision, recall, PR-AUC and MCC. Both sets
appear in every report.

**Closes the gap between the framework and its evaluation.** Phases 2 and 3 describe program
signatures and behavioural features from a honeypot. The paper's experiments use Bitcoin
*address* features — a different problem entirely. We build the honeypot feature pipeline the
framework actually requires, so Phase 3 consumes Phase 2's output as designed.

**Declines to automate ransom payment.** Algorithm 4, Case-3 pays the attacker and requests a
decryption key. We implement it as a simulated policy branch that logs a decision and stops. No
network, no wallet, no transaction. See `docs/DEVIATIONS.md` DEV-09.

---

## Layout

```
docs/       reading notes, notation, algorithm mapping, deviations, experiments, roadmap
src/        crypto, blockchain, consensus, honeypot, detection, mitigation, recovery, framework, bench
configs/    YAML run configurations
tests/      unit + integration
results/    tables, figures, run logs
```

Start with `CLAUDE.md`. Then `docs/PAPER_NOTES.md` for what the paper says and where it breaks,
and `docs/ROADMAP.md` for what is built so far.

---

## Quick start

```bash
make setup      # environment + dependencies
make data       # fetch BitcoinHeist into data/raw
make test       # fast unit tests
make repro      # paper-faithful reproduction
make honest     # corrected evaluation
make figures    # emit Table II and Figs. 4, 5, 6a-6d
```

Requires Python 3.11+. Heavy ML runs (full 2.9M-row dataset, KNN in particular) belong on a
cluster, not an 8 GB laptop — see `CLAUDE.md` §6.

---

## Reproduction targets

| What | Paper | Status |
|---|---|---|
| Accuracy (Table II) | 98.98% | not started |
| F1 (Table II) | 0.990 | not started |
| Mining time, `BC_DTBU` (Fig. 6a) | 3.10 / 4.17 / 5.71 s | not started |
| Mining time, `BC_SigRW` (Fig. 6b) | 4.36 / 5.54 / 6.76 s | not started |
| TPS, `BC_DTBU` (Fig. 6c) | 161 / 240 / 263 | not started |
| TPS, `BC_SigRW` (Fig. 6d) | 115 / 181 / 222 | not started |

Timings are Java-on-Windows in the paper and Python here, so absolute seconds will not match.
The target is the trend: sublinear growth in time, a consistent gap between the two chains, and
the amortisation effect that produces the rising TPS curve. Full protocol in
`docs/EXPERIMENTS.md`.

---

## Safety

This repository contains no malicious code. The honeypot module synthesizes *feature vectors and
digests* describing ransomware behaviour; it does not generate, download, store or execute
malware. The ransom-payment branch is inert by construction and covered by a test that keeps it
that way.
