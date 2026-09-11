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
report the storage cost honestly.

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
