# Paper Notes — BSFR-SH

Wazid, Das & Shetty, *IEEE Trans. Consumer Electronics*, 69(1):18–28, Feb 2023.
DOI: 10.1109/TCE.2022.3208795

A section-by-section reading. Anything marked **[GAP]** is something we must design ourselves
because the paper does not specify it. Anything marked **[FLAW]** is a methodological problem
we must reproduce faithfully *and* correct separately.

---

## §I — Introduction

Frames ransomware against smart healthcare as a consumer-electronics problem (this is a
consumer-electronics journal, hence the framing). Core pitch: blockchain immutability protects
both (a) the ransomware signature base used for detection and (b) the data backups used for
recovery. Attacker cannot tamper with the detector's ground truth, and cannot destroy the
backups.

That two-fold use of the chain is the actual idea worth implementing. Hold onto it.

## §II — Ransomware taxonomy

Descriptive only, no implementable content. Four types (locker, crypto, double-extortion, RaaS),
eight distribution vectors, seven-stage kill chain (infection → resource identification →
encryption → notification → cleanup → payment → decryption), Fig. 1.

**Use for us:** the seven-stage kill chain is a good state machine for the honeypot simulator.
An emulated "infection event" should walk those stages so the detection module has realistic
staging to trigger on.

## §III — Related work

11 prior schemes, refs [11]–[21]. Four of them ([11] Almashhadani, [12] Hwang, [13] Sharmeen,
[14] Bae) reappear in Table II as the comparison baselines.

**[FLAW-1]** These four evaluated on entirely different data — network traffic traces, dynamic
analysis logs, PE-file features. Table II puts their accuracy next to a BitcoinHeist score.
Nothing about that comparison is valid. We reproduce the table (because reproducing the paper
means reproducing its claims) but annotate every row with the source dataset.

**[FLAW-1, extended]** — one row in Table II is weak even setting FLAW-1 aside. Sharmeen et al.
[13] report F1 0.960. On the paper's *own* 90/10 resample, a constant "always ransomware"
classifier — looking at no feature at all — scores F1 0.9474 (measured; see FLAW-4). So Sharmeen's
0.960 clears a do-nothing baseline computed under that skew by 0.013 F1, not a wide margin, while
Table II presents it as a competitive prior technique. This point does not need Sharmeen's own
data or class balance — it stands on the published Table II number and BSFR-SH's own resample
arithmetic alone, which is what makes it usable without re-running anyone else's experiment.

## §IV — The framework

Five phases, Algorithms 1–5, Fig. 2 (architecture), Fig. 3 (sequence diagram).

### §IV-A / Alg. 1 — Backup creation
Systems ship `DT_BU` to cloud servers over session key `SK_{CS_l, SYS_i}`. `CS_l` encrypts under
its own public key into `N_dTx` transactions, packs a block, broadcasts to P2PCS, leader `L`
runs pBFT, threshold of miners commits → append to `BC_DTBU`.

**[GAP-1]** Encrypting bulk backup data under a *public key* is not how anyone does this. Public
key crypto is for small payloads. Real design: symmetric AEAD for the payload, public key wraps
the data key. We do hybrid encryption and document it.

**[GAP-2]** Storing full healthcare backups on-chain is impractical at any real volume. The paper
never says how much data per transaction. We parameterise transaction payload size in config and
report the storage cost honestly. **Answered, M7-2:** `docs/STORAGE_ANALYSIS.md` — three
deployment scales, the backup-frequency lever, and an on-chain-hash/off-chain-data alternative
with its trade-off stated.

### §IV-B / Alg. 2 — Data collection, signature + feature generation
Deploy honeypot `HP_RW`, collect `DT_RW`, pre-process → `DT_RWC`, derive signatures `Sig_RW`
(ECDSA, ref [23]) and features `FT_RW`, encrypt, block, pBFT, append to `BC_SigRW`.

**[GAP-3]** The single biggest hole. The paper never says *what* the features are, *how*
signatures are computed over a program, or what the honeypot collects. `FT_RW` is completely
undefined. We must design this layer end to end. See `docs/ARCHITECTURE.md` §Honeypot.

Note also: ECDSA is a *signature* scheme, so "building signatures for malicious programs" is
conflating a digital signature (authenticity) with a malware signature (identification). We
implement both, distinctly: a content digest identifying the sample, and an ECDSA signature by
`CS_l` attesting to that digest.

### §IV-C / Alg. 3 — ML detection
Decrypt `BC_SigRW`, train on `Sig_RW`/`FT_RW`, build normal profile `NProf` and abnormal profile
`AProf`, run real-time detection. Four algorithms: Random Forest, Logistic Regression, Decision
Tree, KNN.

**[FLAW-2]** Phase 3 is described as consuming honeypot-derived program features. §VII evaluates
on BitcoinHeist Bitcoin *address* features. These are different problems: one is detecting a
running ransomware program, the other is forensically labelling a Bitcoin address that received
a ransom payment. The paper's framework half and evaluation half never connect.

Our response: build **both** pipelines. `detection/` supports two feature sources — the
BitcoinHeist address pipeline (for reproduction) and the honeypot program-feature pipeline (for
the framework to actually work as described).

**[M4b, 2026-09-13] — the honeypot pipeline is not just possible, it is reachable through the
paper's own sequence.** M4a's BitcoinHeist row never touches Phases 1, 2, 4 or 5 at all — it is a
labelled CSV loaded straight into a classifier, with no `HP_RW`, no `BC_SigRW`, no consensus
anywhere near it. Building `framework.phase3_detection.run()` against real `BC_SigRW` chains that
`framework.phase2_collection.run()` produced through actual pBFT consensus
(`tests/integration/test_phase2_feeds_phase3.py`) shows the honeypot half is not merely
plausible — it is the one evaluation path in this project that actually walks Fig. 3's sequence
end to end, and it scores a credible 0.8422 balanced accuracy against the corpus's stated 0.85
ceiling (`RESULTS.md`, DEV-28), not a degenerate number. FLAW-2 is therefore sharper than "the
paper evaluates on the wrong data": the paper's *own* framework, when actually run start to end,
produces a real, boundable detection result, and the paper substitutes an unrelated dataset for
it rather than reporting that result — a choice, not a necessity.

### §IV-D / Alg. 4 — Mitigation
Isolate infected system, raise `AMsg`, then one of three cases:
- Case-1: detection module erases the ransomware, system resumes.
- Case-2: format the system, restore from `BC_DTBU` (calls Phase 5).
- Case-3: if `RW_amt < DT-SYS_i-amt`, pay the ransom, obtain `K_d`, decrypt.

**[FLAW-3 / policy]** Case-3 automates ransom payment. This is a bad design (no guarantee of key
delivery — the paper itself admits this in §II-C — and funding attackers is sanctioned conduct
in many jurisdictions). We implement it as a **simulated policy branch only**. See `CLAUDE.md` §2.

**[GAP-4]** "Erases the ransomware" is unspecified. We model it as a quarantine + integrity-check
state transition, not as actual removal logic.

### §IV-E / Alg. 5 — Recovery
`CS_l` locates the system's backups in `BC_DTBU`, requests decryption of `E_KU(Tx_j)`, ships
plaintext back over `SK_{CS_l, SYS_i}`, system restores.

**[GAP-5]** No index structure is specified. Linear scan of a chain to find one system's backups
is O(chain length). We add a per-system transaction index and note it as an addition.

**[GAP-8]** *(found in M3a, 2026-09-12)* Nothing checks that the restored plaintext is what was
backed up. The chain certifies transactions. Reassembly, and the two servers that each hold
plaintext on the way back (Alg. 5 lines 4–5), are outside what it certifies. DEV-23 adds a payload
digest that `SYS_i` attests before shipping. Two more silences in this section: `CS'_l` is never
defined (DEV-25), and a backup larger than one transaction is never addressed (GAP-2 → DEV-24).

## §V — Security analysis

Five informal prose arguments: (1) session keys via mutual auth defeat replay/MITM/impersonation;
(2) credentials deleted post-registration defeat privileged-insider/stolen-verifier;
(3) pBFT resists 51% and selfish mining, permissioned deployment handles Sybil;
(4) blockchain immutability resists DoS/manipulation/leakage;
(5) two separate chains isolate detection from recovery.

**[FLAW-5]** *(found in M2b, 2026-09-11)* **§V-3 cites a threshold that makes pBFT look stronger than PoW; the
real threshold makes it weaker.** This is a substantive flaw in the argument, not a wording nit.

The argument, as §V-3 runs it: proof-of-work chains are vulnerable to 51% attacks; BSFR-SH uses
pBFT instead; therefore BSFR-SH resists 51% attacks. But pBFT's safety threshold is not a half —
it is a **third**. pBFT is safe only while `f < n/3` replicas are byzantine (`n >= 3f + 1`). Moving
from PoW to pBFT therefore *lowers* the fraction of the network an adversary must control, from
just over one half to one third. At the paper's own configuration of four miners, `f = 1`: two
colluding nodes — 50%, *below* the 51% the text says is being defended against — can make two
honest replicas commit different blocks at one height, and two merely silent nodes halt the chain.
Measured, not argued:
`tests/unit/test_pbft_byzantine.py::test_f2_colluding_equivocators_can_fork_honest_replicas_the_bound_is_exactly_f`.

The fair counter-point, which the write-up should concede and the paper never makes: pBFT's
threshold counts *identities*, not hash power, and in a permissioned deployment identities cannot
be minted (tested: `test_pbft.py::test_a_sybil_swarm_of_outsider_identities_cannot_form_a_certificate`).
So the defensible version of §V-3 is "an attacker must compromise two of our four cloud servers" —
a claim about operational security of a small, named set of machines, not a consensus-theoretic
guarantee, and one that gets *worse* in relative terms, not better, as a reason to prefer pBFT over
PoW. The paper substitutes a borrowed 51% figure for that argument.

What M2b does substantiate: with one byzantine node of four, the chain commits and never forks,
under all four tested behaviours; with two non-colluding faulty nodes, it stops rather than
committing wrongly. "Selfish mining" has no pBFT analogue — there is nothing to mine; the closest
thing, a leader withholding proposals, is handled by view change.

**[GAP-6]** No formal model. No ROR/BAN proof, no AVISPA or Scyther verification — unusual, since
Das's other papers almost always include one. Reproducing §V means writing the argument, not
running a tool. Optional extension: actually formalise it (Scyther is tractable) as project
value-add.

**[GAP-7]** The mutual authentication and key establishment protocol is explicitly deferred —
"any standard mechanism," cf. their BUAKA-CS [26]. We must choose and build one. Decision:
ECDH over secp256r1 with ECDSA-signed transcripts, timestamps and nonces as §V-1 requires.

## §VI — Comparative study

Table II, Figs. 4 and 5. Accuracy: 97.08 / 97.30 / 95.96 / 98.65 / **98.98**.
F1: 0.971 / 0.973 / 0.960 / 0.987 / **0.990**. See FLAW-1.

## §VII — Practical implementation

Windows 11, i5 9th gen @2.40 GHz, 8 GB RAM, GTX 1650, Eclipse 2019-12, **Java**, 4 miner nodes,
pBFT voting, private blockchain. Three cases: 5 / 10 / 15 blocks, 100 transactions each.

Dataset: BitcoinHeist (UCI, ref [15]). 2,916,697 rows, 10 attributes (address, year, day, length,
weight, count, looped, neighbors, income, label). 2,875,284 legitimate vs 41,413 ransomware
(≈1.42% positive).

**[FLAW-4] — the big one.** They resample to **90% ransomware / 10% benign**, then report
accuracy. On that split a constant "always ransomware" classifier scores 90.0% accuracy and
≈0.947 F1. Their 98.98% / 0.990 sits barely above a degenerate baseline, and the F1 is computed
on the majority class. They acknowledge it inflates FPR and defer it to future work. The reported
headline is not evidence of a good detector.

Correct evaluation, which we add: preserve the natural ≈1.4% imbalance, stratified k-fold,
report precision/recall/PR-AUC/MCC on the minority class, plus a confusion matrix.

**[FLAW-4, extended] *(found in M4a, 2026-09-12)* — the split also shrinks the experiment by 98%,
and the paper never says so.** The resample is bounded by the scarce class: only 41,413 ransomware
rows exist, so a 90%-ransomware sample holds at most `41,413 / 0.9 = 46,014` rows. The headline
98.98% is therefore a number from a **~46K-row experiment**, reported directly beneath a
2,916,697-row dataset description, with nothing in between to mark the change. Two separate
problems compound here: the balance is degenerate (the original FLAW-4), *and* the evidence base is
1.6% of the cited data. Either alone would warrant a caveat; together they mean the reported
comparison against [11]–[14] is between a 46K-row resample and four other papers' full corpora.
Arithmetic only — no data needed to check it — so it is asserted as a unit test, and the realised
`n` is recorded with every `paper_mode` run.

**[NOTE] — the cross-distribution comparison is illustration, not a head-to-head.** M4a's
`honest_mode` reports a constant-negative baseline of ≈98.58% accuracy at the dataset's natural
1.42% positive rate, and it is tempting to set that beside the paper's published 98.98% (90/10)
and say the headline barely beats finding nothing. **Don't present that pairing as commensurable
evidence** — the two numbers are computed under different class distributions, and a constant
classifier's accuracy is a direct function of the positive rate it is scored against (see
`metrics.analytic_constant_positive`). The pairing is worth keeping as an *illustration* of how
distribution-sensitive accuracy is, labelled as such, not as a within-split refutation. The
airtight, distribution-matched version is FLAW-4's own comparison, stated in Table II terms: on
the paper's own 90/10 split, constant-positive scores accuracy 0.900 / F1 0.9474 (measured,
confirming the analytic value), against which BSFR-SH's published 98.98% / 0.990 is the number
that has to be judged, and Sharmeen's 0.960 is the one that barely clears it (FLAW-1, extended).
`docs/EXPERIMENTS.md` Target 2 states the same distinction.

**[Q10, closed 2026-09-13] — address and split leakage do not explain the gap.** Two candidate
leakage sources for why our reproduction (0.9479, M4a) undershoots the published 98.98%: `address`
kept as a feature, and a random (not address-grouped) train/test split. `scripts/
q10_leakage_ablation.py` ran the resulting 2x2, `paper_mode`, all four models, at M4a's exact
config hash and seed. Both sources are real and both are small — the largest single effect is
decision tree's +0.92pt from keeping `address` under a random split, and it vanishes under a
grouped split, which is the expected signature of exactly that leak. The best of all 16 model x
cell combinations is 0.9540/0.9749 (random forest, address kept, random split) — still 3.58 points
of accuracy under the published figure. **The gap is not accounted for by either candidate, alone
or together.** Full numbers: `docs/DEVIATIONS.md` DEV-06 amendment, `RESULTS.md`. One correction
falls out of this: M4a's headline used the random split, which this ablation shows was inflating
it slightly; the honest `paper_mode` figure is revised to `address dropped x grouped split`
(0.9442/0.9697, random forest) going forward.

**[FINDING] — TPS is arithmetic, not measurement.** Verified against §VII-C and §VII-D:

| Chain | Case | Blocks | Tx | Time (s) | Reported TPS | tx/time |
|---|---|---|---|---|---|---|
| Backups | 1 | 5 | 500 | 3.10 | 161 | 161.3 |
| Backups | 2 | 10 | 1000 | 4.17 | 240 | 239.8 |
| Backups | 3 | 15 | 1500 | 5.71 | 263 | 262.7 |
| Ransomware | 1 | 5 | 500 | 4.36 | 115 | 114.7 |
| Ransomware | 2 | 10 | 1000 | 5.54 | 181 | 180.5 |
| Ransomware | 3 | 15 | 1500 | 6.76 | 222 | 221.9 |

Every reported TPS value is exactly `total_tx / total_time`. Consequence: we only instrument
wall-clock time; TPS is derived. Also, the paper's claim that "TPS rises as the blockchain grows"
is not a throughput property — it is amortisation of fixed setup cost over more blocks. Marginal
per-block cost is roughly flat. We report marginal cost alongside their averaged TPS.

**[NOTE]** §VII-C describes the x-axis as increasing "number of devices" while the setup defines
the cases by number of *blocks*. The two are conflated. We hold devices fixed and vary blocks,
matching the numeric setup rather than the prose.

**[NOTE]** §VII-B calls the F1 result "the best accuracy value ... 0.990" — copy-paste slip from
§VII-A. Best F1, via decision tree.

## §VIII — Conclusion

Future work: more features, higher accuracy without degrading security. Also flags hybrid
blockchain (§IV-A) and more balanced attacker/benign sampling (§VII) as open.

---

## Reproduction targets, consolidated

See `docs/EXPERIMENTS.md`. Best model in the paper is **Decision Tree** for both accuracy and F1
— worth noting that a decision tree beating a random forest on 2.9M rows is itself a signal that
the split is doing the work, not the model.
