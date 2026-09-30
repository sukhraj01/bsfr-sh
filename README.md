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

**`make data` is slow, and that is expected.** It fetches a ~116 MB archive (235.9 MB CSV) from
the UCI repository and has taken **roughly an hour at ~37 KiB/s** in this environment — your
throughput will vary, but expect it to be minutes, not seconds. `data/raw/` is gitignored, so a
fresh clone cannot run `paper_mode`, `honest_mode`, or any other BitcoinHeist experiment until it
completes; do not kill it for looking stuck. It verifies the fetched file against
`docs/EXPERIMENTS.md` Target 2's row/class counts and writes `data/raw/provenance.json`, whose
`csv_sha256` should read `8ecc3744e444f35534a1bcabedc7a3b405fb5bbf41a752e51ee9a57987b8c438` —
check that file if you want to confirm a fetch finished with the right bytes without waiting on
`make test`'s dataset check.

---

## Reproduction targets

All measured, not projected — every number below traces to a run log in `results/logs/` with a
config hash and seed (`RESULTS.md`), and the honest/paper-mode distinction is never collapsed into
one figure (`docs/DEVIATIONS.md`).

| What | Paper | Status |
|---|---|---|
| Accuracy (Table II) | 98.98% | **measured 94.42%** (random forest, grouped split) — 4.56pt gap, partly narrowed to 1.51pt by an 8-hypothesis ablation; residual unexplained (DEV-06, Q10, M7-6) |
| F1 (Table II) | 0.990 | **measured 0.9697** (same run) |
| Mining time, `BC_DTBU` (Fig. 6a) | 3.10 / 4.17 / 5.71 s | **measured 0.271 / 0.544 / 0.819 s** — trend confirmed (monotone increasing) |
| Mining time, `BC_SigRW` (Fig. 6b) | 4.36 / 5.54 / 6.76 s | **measured 0.340 / 0.677 / 1.043 s** — cross-chain gap confirmed, narrower than the paper's (~26% vs ~35-45%, a real finding — DEV-30) |
| TPS, `BC_DTBU` (Fig. 6c) | 161 / 240 / 263 (rising) | **measured ~1832-1848 tx/s, flat, not rising** — a genuine deviation from the paper's own curve, not a bug (Target 3) |
| TPS, `BC_SigRW` (Fig. 6d) | 115 / 181 / 222 (rising) | **measured ~1438-1476 tx/s, flat, not rising** |

Timings are Java-on-Windows in the paper and Python here, so absolute seconds were never expected
to match (DEV-13) — the reproduction target is the trend and the ratios. Two of those trends
reproduce (sublinear-ish time growth, a persistent cross-chain gap); **TPS does not** — ours is
flat where the paper's rises, stated as a finding rather than smoothed over. Honest baselines, the
natural (non-resampled) class distribution, and full methodology: `docs/EXPERIMENTS.md`, `RESULTS.md`,
`docs/report/report.pdf`.

---

## Beyond the paper

The paper stops at five phases. This project's own stretch work (tracked as milestone M7,
`docs/ROADMAP.md`) adds what a from-scratch implementation makes possible to check:

- **Formal verification** — the session-establishment protocol under a Dolev-Yao adversary
  (Scyther), and the reduced pBFT consensus protocol by exhaustive model checking (TLA+/TLC),
  confirming both the safety bound the paper claims *and* the weaker bound (FLAW-5) it actually has.
- **Adversarial robustness** — minimum-perturbation evasion cost against the detector, exact for
  three of four models, with a hardened-model comparison and an exact-vs-approximate correction.
- **Honeypot data poisoning** — a measured attack against the signature corpus, and three
  independent defenses (statistical drift detection, a commit-reveal protocol, federated
  cross-replica disagreement), each evaluated for whether it actually helps, not just whether it
  runs.
- **pBFT vs. Raft**, external anchoring to a simulated public chain, multi-family ransomware
  detection, and a four-tier adversary threat model the paper never states.

Every one of these is measured against a stated baseline, with dead ends and negative results kept
in `sessions/` rather than edited out. `docs/report/report.pdf` is the full write-up.

---

## Safety

This repository contains no malicious code. The honeypot module synthesizes *feature vectors and
digests* describing ransomware behaviour; it does not generate, download, store or execute
malware. The ransom-payment branch is inert by construction and covered by a test that keeps it
that way.
