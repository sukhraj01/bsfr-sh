# Threat Model

**Status:** M7-9, 2026-09-25. A standalone reference — self-contained, but every claim in it
either cites `docs/PAPER_NOTES.md` §V (the paper's own security prose) or a specific test,
`verification/` claim, or `RESULTS.md` line from this project's six security-relevant extensions
(Scyther verification, pBFT threshold analysis, Raft comparison, hybrid anchor chain, adversarial
evasion attack, adversarial retraining defense). Nothing here is a new measurement; this document
synthesizes existing ones into one argument.

## Why this document exists

The paper's §V states five security properties as informal prose (`docs/PAPER_NOTES.md` §V) and
never once says, for any of them, *what an adversary can do* before the property is claimed to
hold. GAP-6 names the direct consequence — no formal model, no ROR/BAN proof, no protocol
verification tool — and FLAW-5 names a deeper one: without a stated adversary model, §V-3 can
(and does) borrow a 51% proof-of-work threshold to defend a protocol whose real safety bound is a
third, because nothing in the paper's argument structure would catch that substitution. A claim
of the form "the system resists X" is only checkable once "resists X" is cashed out as "survives
an adversary who can do Y" — this document is that cashing-out, applied after the fact to five
claims the paper never stated this way, and applied prospectively to six extensions this project
built that the paper's own §V has no vocabulary to place.

This is not a new security mechanism. It changes nothing about `src/`. It is the argument that
was missing.

---

## 1. Assets

What the system protects, the chain that protects it, and the specific property that chain
provides — not "blockchain," but *which* guarantee (immutability, confidentiality, availability)
comes from *which* mechanism.

| Asset | Chain | Property | Mechanism |
|---|---|---|---|
| **Patient healthcare data** (the backups themselves) | `BC_DTBU` | Confidentiality + availability | Confidentiality: hybrid encryption, `E_KU_CSl(Tx)` payloads (DEV-01/DEV-25's key-wrapping design) — a transaction's contents are unreadable to anyone but the intended cloud server's holder. Availability: pBFT replication across 4 nodes (`n=4`, tolerates `f=1`, `tests/unit/test_pbft.py`) plus recovery via Alg. 5 (`recovery.locator.BackupIndex`, `framework/phase5_recovery.py`) — a backup survives the loss (not the *compromise*, see Tier 2/3 below) of up to one node. |
| **Ransomware signature/feature database** (`Sig_RW`/`FT_RW` records) | `BC_SigRW` | Integrity | Chain hash-linking + pBFT quorum: once a signature record commits, altering it requires forging a new block accepted by `2f+1` replicas (`tests/unit/test_pbft.py::test_a_block_that_does_not_match_the_signed_digest_is_rejected`). This is integrity of *what was recorded*, not truth of *what was observed* — see Gap 1. |
| **Detection model's ground truth** (the labelled honeypot corpus `NProf`/`AProf` are fitted from) | `BC_SigRW` (if drawn from the chain) or the committed CSV corpus (DEV-27, the fixed-dataset convention actually used by every measured M4/M7-3/M7-8 number) | Integrity of the *recorded* label, not of the *generating process* | Same mechanism as the row above — a record, once committed, cannot be silently edited. The generator that produced the record in the first place is outside this guarantee entirely (Gap 1, Tier 2). |
| **System availability** (what ransomware actually attacks — the live system, not the chain) | Neither chain directly | Availability of the *backup*, not prevention of the *attack* | The framework's own design goal (§I of the paper, "Use for us" note in `docs/PAPER_NOTES.md`) is recovery, not prevention: a system that gets encrypted is restored from `BC_DTBU`, not defended in real time. The chain's own availability (can *it* be read/written) depends on consensus liveness, which is a separate, narrower claim — see Tier 2's limitation and Gap 3. |

Two chains, two independent object graphs, by design (CLAUDE.md §4b: "Two chains are separate
objects... A bug here silently invalidates the whole benchmark") — structurally verified, not
just asserted, by `tests/unit/test_chains_independent.py` (12 tests: independent genesis blocks,
no shared storage, no shared policy object, no module-level registry, appending to one leaves the
other untouched). This independence is itself Coverage Matrix claim (5) below.

---

## 2. Adversary capabilities — four tiers

The paper's §V conflates adversaries the way FLAW-5 describes: a hash-power adversary (§V-3's
borrowed 51%) is not the same adversary as an identity-controlling one (pBFT's real `f < n/3`),
and neither is the same adversary as one who never touches a node at all (Tier 4, below, which the
paper's Algorithm 3 does not consider adversarial in the first place). Separating them is the
point of this section.

### Tier 1 — External network attacker

**Capability:** full Dolev-Yao control of the network — intercept, replay, modify, inject,
reorder any message in transit. **Cannot** compromise any node's internal state or long-term key.

**Defense:** the session establishment protocol (DEV-02), built to fill the gap the paper leaves
at §V-1/§IV-A ("any standard mutual authentication and key establishment mechanism").

**Verification:** Scyther (M7-1, symbolic/Dolev-Yao, `verification/README.md`), both bounded
(`--max-runs=5`) and unbounded search, on the shipped (post-M1) protocol:

| Claim | Result |
|---|---|
| Session-key secrecy | **VERIFIED** (`Secret_A1`, `Secret_B1`) |
| Mutual authentication, both directions | **VERIFIED** (`Niagree`/`Nisynch`, both roles) |
| Impersonation resistance | **VERIFIED** (`Weakagree`/`Alive`, both roles) |
| Distinct keys per session | **HOLDS by construction** (term-algebra argument, not a Scyther claim type) |
| Cross-identity replay (the M1 fix) | **FIXED MODEL VERIFIED**; the same tool, pointed at the pre-M1 sketch, **FOUND THE ATTACK** DEV-02 describes |

**Known limitations, stated by the verification itself, not discovered after the fact:**
within-window replay is **out of Scyther's scope** (stateless symbolic search cannot represent a
persistent seen-nonce cache) — covered instead by `tests/unit/test_session_replay.py`, a
different verification method for a claim Scyther structurally cannot make. Timestamps are
modelled as opaque values (tamper-evidence, not real elapsed-time freshness). Diffie-Hellman is
modelled via Scyther's standard oracle idiom, not a native equational theory. The model assumes
perfect cryptography for ECDSA/HKDF — a break of secp256r1 or SHA-256 is outside what any
Dolev-Yao proof can say.

### Tier 2 — Single compromised cloud server (f=1)

**Capability:** full control of one of the four `CS_l` nodes — can send arbitrary (including
equivocating) messages, withhold messages, vote dishonestly. Cannot forge another node's
signature.

**Defense:** pBFT's design threshold, `n >= 3f+1`, satisfied at the paper's own `n=4, f=1`.

**Verification:** `tests/unit/test_pbft_byzantine.py`, parametrized across byzantine behaviours
and primary/backup position —
`test_f1_the_chain_commits_and_honest_replicas_agree`, `test_f1_wrong_signature_never_counts_
toward_any_certificate`, `test_f1_stale_view_messages_are_refused_after_the_cluster_has_moved_on`:
**the chain commits and every honest replica agrees on the same block, under every tested f=1
behaviour.**

**Raft does not have this property, measured, not assumed** (DEV-32/M7-4): a byzantine Raft
leader can send genuinely different, honestly-signed transaction sets to different followers at
one log index — `tests/unit/test_raft_byzantine.py::test_a_byzantine_leader_forks_honest_
followers_with_a_single_faulty_node` — which "pBFT's matching-vote quorum would have prevented"
(that test's own comment, `test_raft_byzantine.py:60`). Raft is faster (7-11% wall-clock,
`RESULTS.md` M7-4) and cheaper (zero signature operations vs. pBFT's one-per-message), but that
speed is bought by dropping exactly the guarantee this tier needs.

**Hybrid anchoring's role at this tier is narrower than it sounds.** pBFT's own safety property
already prevents a bad block from being *committed* at f=1 — there is nothing for anchoring to
catch at the consensus layer that consensus itself did not already stop. What the anchor chain
(DEV-33/M7-5) *does* add here: a compromised server that rewrites its own already-committed local
storage (bypassing consensus entirely, corrupting its own copy of history after the fact) is
detectable by anyone holding that server's earlier anchor, via `HybridChain.verify_anchor` —
without needing to trust any of the four operators. That is a different attack surface from "win
a pBFT round," and it is the one hybrid anchoring is built for.

**Known limitation — liveness, not safety, and it is fragile at exactly this tier.** DEV-20's
reduced view change omits state transfer: a replica that falls behind is indistinguishable from a
byzantine one and "uses up" the cluster's single tolerated fault. At `n=4`, one lagging *honest*
replica plus one byzantine replica stalls the chain —
`tests/unit/test_pbft_byzantine.py::test_equivocation_with_honest_votes_strands_one_honest_replica`
demonstrates exactly this. Tier 2's safety guarantee (no wrong block commits) is solid; its
liveness guarantee (the chain keeps moving) is not, once a second, honest failure compounds it.
This is Gap 3, below.

### Tier 3 — Two compromised cloud servers (f=2)

**Capability:** the same as Tier 2, on two of the four nodes, including collusion between them.

**This exceeds pBFT's own tolerance at `n=4`.** `n >= 3f+1` requires `f <= 1`; `f=2` is `50%` of
the cluster, not the `33%` pBFT's safety proof actually needs — the exact substitution FLAW-5
identifies the paper making in the other direction (borrowing PoW's 51% figure to describe a
protocol whose real bound is a third).

**Verification — this tier is demonstrated to fail, not assumed to fail:**
`tests/unit/test_pbft_byzantine.py::test_f2_colluding_equivocators_can_fork_honest_replicas_the_
bound_is_exactly_f` — two colluding equivocators make two honest replicas commit *different*
blocks at the same height. (Non-colluding `f=2` fails safely instead — stalls rather than forks —
`test_f2_the_chain_fails_to_commit_rather_than_committing_wrongly`; collusion is the operative
word.)

**Raft offers nothing extra here — it was never a candidate at this tier.** Raft's own safety
already breaks at a single byzantine node (Tier 2), so "does Raft survive two compromised nodes"
is moot; the honest comparison stops at Tier 2, where Raft already loses to pBFT on the one
property that matters for this threat model.

**Hybrid anchoring is the only remaining detection mechanism, and it is a detection, not a
prevention.** A fork at Tier 3 produces two different `current_hash`/`merkle_root` values at the
same height; an anchor recorded before the fork lets any external holder of that anchor tell the
two apart via `verify_anchor`/`verify_anchor_chain_integrity` (DEV-33). **Stated limitation, not
hidden:** the anchor chain in this implementation is **simulated** — one signing authority,
sign-and-append, not a real public blockchain's own independent consensus (DEV-33: "In production
the anchor chain is a real public blockchain with its own separate consensus... none of that is
modelled here"). An adversary who also controls the (here, singular) anchor authority's signing
key defeats the entire hybrid design, not just this check — untested, because nothing in this
project implements a compromised anchor authority to test against.

### Tier 4 — Adversarial ML (feature-space evasion)

**Capability:** does not compromise any node. Crafts ransomware whose *observable behaviour* (not
network messages, not consensus votes) is tuned to evade the honeypot detector's `FT_RW` features.
A structurally different attack surface from Tiers 1-3 — Algorithm 3 (`§IV-C`) assumes `FT_RW` is
simply observed and never considers that the thing being observed might be adversarially shaped.

**Defense (partial, measured, not claimed to be complete):** none in the paper — this tier is
outside its threat model entirely, a direct consequence of FLAW-2 (the paper's own evaluation runs
on BitcoinHeist address features no attacker can choose the value of, so this question could never
have been asked from inside the paper's own methodology).

**Attack measured (M7-3, `RESULTS.md` M7-3):** single-feature evasion is weak (<9pt balanced-
accuracy drop at 100% perturbation of any one top-5 feature). Combined evasion of all five
compounds but plateaus around 0.57-0.60, never reaching the 0.50 useless-detector line (the top-5
features carry only 45.5% of Random Forest importance). **The adaptive, per-sample attack is the
real number:** median minimum perturbation to flip a prediction is 32.1% of the evasion range;
25.2% of malicious eval rows evade at <=5% perturbation (17.3pt of that is already-baseline false
negatives); 7.9% never flip at all (they rely on features outside the top 5).

**Defense measured (M7-8, `RESULTS.md` M7-8):** adversarial retraining on perturbed positives.
**Non-monotonic in the training budget — the finding that matters for this threat model.** At a
25% training budget, hardening is *worse* than doing nothing on both axes (median adaptive evasion
drops from 0.321 to 0.250; the combined-evasion curve crosses *below* 0.50 at full perturbation,
which the undefended model never did). At 50%/100% budget, real robustness appears (median
adaptive evasion rises to 0.883/1.000) at a cost of 6-10.5 clean-balanced-accuracy points, driven
by falling recall — and the mechanism is narrow: the hardened model learns "values near the
evasion bound" as its own ransomware signature (the 100%-budget curve *rises* with perturbation
instead of falling), which is pattern-matching on the augmentation's own footprint, not a deeper
representation.

**Known limitation:** M7-3's adaptive attack assumes white-box access — the attacker knows the
top-5 feature ranking and their exact physical bounds. This is deliberately the worst case (Trust
Assumption 5, below); the single/combined-feature results are the closer-to-black-box figure
(an attacker who knows *which kind* of feature matters from domain reasoning, without the exact
importances). M7-8's hardening is untested against an attack shaped differently from the one it
trained against — e.g. targeting the hardened model's own *new* top-5 features
(`directory_breadth`, `entropy_delta`, `key_generation_events`), which gained importance
precisely because the original top-5 lost it (M7-8's partial "throws away signal" finding).

---

## 3. Trust assumptions

The paper states none of these. Listed here because every result above is conditional on them.

1. **Fewer than `n/3` cloud servers are Byzantine** (pBFT's own assumption, `f < n/3`, `f <= 1` at
   `n=4`). Everything in Tier 2 rests on this; Tier 3 is exactly what happens when it is violated.
2. **The anchor chain is trustworthy.** In a production deployment: a real public blockchain,
   independent of the four `CS_l` operators. In this implementation: **simulated** — a single
   sign-and-append authority (DEV-33). Not tested against a compromised anchor authority; see
   Tier 3's limitation.
3. **The honeypot collects representative samples.** Unverifiable in the paper's own design (it
   specifies no honeypot at all — GAP-3/DEV-03/DEV-27). Not merely unverified in this project
   either: M7-7 (DEV-34) directly tested whether `FT_RW`'s *dynamic behavioural* schema transfers
   to real data and found it does not for the one real, tractable dataset available (ClaMP, static
   PE headers) — `bal_acc=0.5000`, at chance, because 19 of 22 features have no static analogue.
   That is evidence the representativeness assumption is fragile for at least one concrete case,
   not proof it fails for the schema's intended (dynamic/execution-trace) use.
4. **Session keys are ephemeral and the KDF is secure.** Verified at the *protocol* level by
   Scyther (Tier 1: `Secret_A1`/`Secret_B1`). Assumed, not proven, at the *primitive* level —
   Scyther's perfect-cryptography abstraction says nothing about a real cryptanalytic break of
   secp256r1, SHA-256, or HKDF (`verification/README.md`'s own stated limitation 1).
5. **Ransomware authors do not have white-box access to the detector.** M7-3's adaptive attack
   assumes the opposite — full knowledge of feature importances and physical evasion bounds —
   deliberately, as the pessimistic case a defender should plan against. If this assumption holds
   in practice (a more realistic deployment posture), the single-feature and combined-evasion
   numbers are the more representative figures, and the detector is considerably harder to evade
   than the adaptive-attack headline alone would suggest.
6. **(M7-12) `BC_SigRW` replicas can decrypt the `Sig_RW`/`FT_RW` payloads they vote on.** Added
   by the drift-detection defense (Gap 1, below), and a real widening of trust, not a detail:
   `blockchain/transaction.py`'s own docstring states the invariant this narrows — "Miners in M2b
   validate blocks they cannot read; that is the point." `Sig_RW` payloads are hybrid-encrypted to
   one recipient (DEV-01); a semantic check over plaintext features cannot run without plaintext
   features, so `consensus.validated_commit.ValidatedSigRWChain` requires a decryption key for
   every `BC_SigRW` replica that runs it. This assumption does not extend to `BC_DTBU`, whose
   replicas remain exactly as blind as before (DEV-38).
7. **(M7-12) Every honest `BC_SigRW` replica runs the same drift policy and sees batches in the
   same order.** The latter already follows from pBFT's total order within one chain; the former
   does not follow from anything — it is a new, independent assumption `detection.drift.
   DriftPolicy` introduces. A replica with a different threshold, a different decryption
   capability, or a profile that has silently diverged from its peers' disagrees with them about
   whether to vote, and an adversary who can induce that disagreement can exploit it (this is not
   measured; DEV-38 states it as a stated-but-untested limitation, matching this section's own
   convention of naming assumptions the paper — or, here, the defense — does not itself verify).

---

## 4. Coverage matrix

The table that replaces §V's five paragraphs of prose. Each row: which tier(s) the paper's claim
actually addresses (not which it *says* it addresses — see FLAW-5), how we checked it, the
result, and what is known not to hold.

| §V claim (paraphrased) | Tier(s) | Method | Result | Known limitation |
|---|---|---|---|---|
| **(1)** Session keys via mutual auth defeat replay/MITM/impersonation | 1 | Scyther (M7-1), symbolic verification | **VERIFIED** — secrecy, mutual auth both directions, impersonation resistance, all at bounded + unbounded search | Within-window replay outside Scyther's scope (covered separately by `test_session_replay.py`); perfect-crypto abstraction, no computational proof |
| **(2)** Credentials deleted post-registration defeat privileged-insider/stolen-verifier | insider (no tier — an operator-process claim, not a network- or consensus-adversary one) | **None** — no registration-authority module exists anywhere in this codebase | **UNVERIFIED / NOT IMPLEMENTED** | This project never built the registration flow §V-2 describes; the claim has nothing to check it against. Gap 2, below |
| **(3)** pBFT resists 51% attacks and selfish mining; permissioned deployment handles Sybil | 2, 3 | `tests/unit/test_pbft_byzantine.py` (f=1/f=2), `tests/unit/test_pbft.py::test_a_sybil_swarm_of_outsider_identities_cannot_form_a_certificate` | **MIXED**: Sybil resistance **VERIFIED**; f=1 Byzantine tolerance **VERIFIED**; but the "51%" framing itself is **WRONG** (FLAW-5) — the real threshold is `f < n/3` (33%), and `f=2` at `n=4` (50%, still under the paper's cited 51%) **DEMONSTRATED TO FORK THE CHAIN** | "Selfish mining" has no pBFT analogue at all — there is nothing to mine; the paper's own comparison point does not transfer |
| **(4)** Blockchain immutability resists DoS/manipulation/leakage | 1, 2, 3 (manipulation); none tested (DoS); 1 (leakage, partial) | Chain hash-linking + pBFT quorum (manipulation); DEV-20's view-change analysis (DoS); hybrid encryption (leakage) | **MIXED**: manipulation-resistance **VERIFIED/MEASURED** within Tier 1-2 (fails as designed at Tier 3, consistent with claim 3's finding); DoS-resistance has a **MEASURED GAP** — `test_equivocation_with_honest_votes_strands_one_honest_replica` shows one lagging honest replica plus one byzantine replica stalls the chain at `n=4`; leakage-resistance is **PARTIAL** — payload contents are encrypted, but see Gap 4 (metadata) | The paper's "resists DoS" is never tested by the paper itself and, per DEV-20, is fragile at exactly the fault count (2 of 4) the paper's own deployment is sized for |
| **(5)** Two separate chains isolate detection from recovery | n/a (architectural, not adversarial) | `tests/unit/test_chains_independent.py` (12 tests: independent genesis, no shared storage/policy/registry) | **VERIFIED**, structurally | None identified — this is the one §V claim that is purely architectural and holds unconditionally of adversary tier |
| *(new, not in the paper)* Feature-space evasion resistance | 4 | M7-3 (attack), M7-8 (defense) | **MEASURED, not verified**: attack is real and adaptive-case-severe (25% of samples trivially evadable); defense is real but narrow and non-monotonic in training budget (a poorly-chosen budget makes things worse) | See Tier 4 above in full; this claim does not exist in the paper at all — GAP-6's "no formal model" extends to not even having informal language for this adversary |

**Summary, stated the way the session brief asked for:** three of the paper's five §V properties
hold at (at least) their defensible tier — (1) fully, (3) partially (Sybil and f=1, not the "51%"
framing), (5) unconditionally. Two have measured limitations the paper does not acknowledge: (2)
was never implemented, so it is unverified rather than false; (4) is true for manipulation but has
a demonstrated DoS gap the paper never tests for. The sixth row — feature-space evasion — is not
a §V claim at all, which is itself GAP-6's clearest consequence: a threat model that never
mentions adversarial ML cannot be faulted for failing against it, but a deployment relying on
§V's five properties alone would have no idea this attack surface existed.

---

## 5. Gap analysis

What this threat model exposes as **not covered** by anything measured above. These are findings,
not tickets — no fix is proposed or implied.

**Gap 1 — Data poisoning of the honeypot (Tier 2, partially adjacent). Measured, M7-11.** A
Tier-2 adversary who controls the honeypot's own collection process (not necessarily one of the
four `CS_l` nodes — the honeypot is a separate role, `HP_RW`) could feed false training data into
`Sig_RW`/`FT_RW`. Once committed to `BC_SigRW`, that false data is **immutable and tamper-evident**
— which makes the poisoning *permanent and hard to retract*, not detectable. Chain integrity
certifies that a record was written as submitted; it says nothing about whether what was
submitted was true. M7-7 (DEV-34) tests a different question — whether the honeypot's *design*
generalises to real data ("is the schema representative") — not this one ("is the pipeline
poisonable"). M7-11 measures this one directly, both halves:

*Degradation.* Three strategies (label flipping, feature poisoning, anchor-point injection) x
five budgets (1-50% of ransomware training rows), against the committed corpus
(`scripts/m7_11_honeypot_poisoning.py`, `RESULTS.md` M7-11, DEV-37). Label flipping (relabel real
ransomware rows as benign) is the most damaging and the only one that is monotonic: -1.5pt
balanced accuracy at 1% budget, -17.3pt at 50%, collapsing to exactly `bal_acc=0.5000` at 100%
budget (zero positive training rows left; no classifier fittable past "always benign"). Feature
poisoning (fabricated "ransomware" rows with real benign features) is mild and roughly
budget-insensitive (-0.3 to -1.5pt). Anchor-point injection — labelled the "most sophisticated"
strategy going in — is the *least* damaging at low-to-medium budget and briefly *improves*
accuracy (+0.6pt at 1%, only turning negative at 50%, -1.3pt): a designed attack's sophistication
and its measured effectiveness are not the same axis.

*Permanence.* Demonstrated once, for real: one poisoned `SignatureRecordPayload` (a genuine
ransomware trace, `label` set to `"benign"`) committed cleanly, in one block, through actual
pBFT consensus to a real `BC_SigRW` cluster, on the first attempt. `blockchain.chain.Chain`'s
full public method list has no delete, remove, rollback, revert, truncate, or undo method — a
code-level fact about a class already in the repository (DEV-37), confirming Algorithm 2's own
gap: it appends, nothing removes.

*Pre-commit validation.* The poisoned record passed all five of `Chain.check_append`'s checks
(prev_hash linkage, Merkle root, hash uniqueness, ECDSA signature, timestamp skew) — every one
structural or cryptographic, none semantic. A correctly formatted, correctly signed poisoned
sample passes every existing validation check.

*Pre-commit detection, built and measured (M7-12).* M7-11 named this gap without building it,
predicting (before measuring) that "outlier detection... could in principle catch anchor-point-
style poisoning... but not label flipping." Measured, the prediction is exactly backwards.
`detection.drift.DriftDetector` plus `consensus.validated_commit.ValidatedSigRWChain` (DEV-38)
implement *batch*-level distributional drift detection — not the per-sample outlier check M7-11's
prediction and DEV-26 both correctly rule out — gated into `Chain.check_append()` itself, the one
place `consensus/pbft.py`'s own docstring says block validity is decided, so a replica that
detects drift withholds its prepare/commit vote through the existing `2f+1` threshold arithmetic,
with no new consensus message type. Measured against exactly M7-11's three strategies and five
budgets (`RESULTS.md` M7-12, `scripts/m7_12_poisoning_defense.py`):

* **Anchor-point injection — predicted catchable, measured invisible at every budget.** Its
  engineered midpoint between the two class centroids sits, in a roughly class-balanced corpus,
  almost exactly at the *population* mean — the batch that is supposed to look most like an
  attack looks the least anomalous of the three, scoring *below* the same-size clean-batch noise
  floor at every budget measured (e.g. 0.0078 vs. a clean p95 of 0.11 at n=143).
* **Label flipping — predicted invisible, measured statistically distinguishable from equally-
  sized clean noise at budgets >=5%, in isolation.** A batch of only the mislabelled real
  ransomware rows scores above the matched-size clean-batch noise floor (0.33 vs. a clean p95 of
  0.24 at n=36) — not because the label lied, which the detector cannot see (features and labels
  are decoupled, `honeypot/features.py`'s own schema), but because an all-malicious batch's
  feature *composition* differs from the profile's usual benign/malicious mix. The same signal
  would fire on an honest batch that happened to be unusually ransomware-heavy — an outbreak, not
  an attack — which is this defense's own version of item below's new-family tension, sharpened:
  it cannot distinguish "mislabelled" from "unusually pure," only "unusual."
* **Feature poisoning** behaves like label flipping (moderate, composition-driven scores, not a
  genuine distributional shift), consistent with M7-11's own finding that this strategy is mild
  because its injected rows are literally resampled from already-observed benign feature values.
* **The real end-to-end pBFT demonstration (small, ~35-sample honest history, the realistic
  early-chain case) did not reject either a label-flip or an anchor-shift burst of 39-40 records**
  at the conservative threshold this session shipped (Mahalanobis RMS >= 3.0, chosen before any
  of the above was measured, and left unmoved after — lowering it to match the array-level
  finding would also raise the false-positive rate on equally-small legitimate batches, which
  is exactly the tension item 4 below states, not a threshold that was simply mistuned).
* **A single record (M7-11's own permanence-demo shape) is undetectable in principle, at any
  threshold.** Batch-level testing has no averaging to lean on at `n=1`; the noise floor at `n=7`
  already needs a same-size clean-batch score as high as 1.14, and shrinks further as `n` grows —
  the defense's own design (deliberately batch-level, per DEV-26) is structurally blindest at
  exactly the smallest, least-visible submission an adversary can make.

**Honest summary: this is a real, working, measured defense against exactly one thing —**
**a poisoning batch that introduces feature values the corpus has never produced before — and**
**it is not a fix for Gap 1 in general.** It closes the anchor-point-style case M7-11 predicted it
would close and M7-9 left unbuilt; it does not close label flipping (M7-11's *most damaging*
strategy) except as an accidental side effect of batch composition that a legitimate outbreak
would trigger identically; and it adds two new trust assumptions (§3, TA-6/TA-7) the paper's own
confidentiality design ("miners validate blocks they cannot read") did not need before this
session. False-positive rate on clean batches: 0/30 chunked eval-corpus batches at the shipped
threshold; 0/1 new-family probe (a documented, disclosed feature-space perturbation, not a call
into `honeypot/collector.py`'s generator) also did not fire, despite scoring 17x the matched
clean-batch p95 — the tension item 4 of the M7-12 brief asked for, measured rather than assumed:
a threshold loose enough to catch that probe is loose enough to start firing on ordinary small
batches too. The mechanism itself (batches, not samples; cross-node feature-space agreement
avoided by gating a check every replica already runs independently before the same vote) would
need cross-node feature-space agreement, a research problem this project does not attempt to
solve beyond stating it as TA-7's own limitation.

*Hybrid anchoring (M7-5) does not help.* Anchoring verifies integrity of already-committed data
over time; poisoning is a validly signed, validly consensus-approved commitment in the first
place, not post-commit tampering. The anchor faithfully records the poisoned block exactly as
submitted — it cannot distinguish a legitimate record from a false one an authorized party chose
to submit, because that distinction is validity, not integrity (§3, Trust Assumption 2).

*Not BSFR-SH-specific.* Any system that trains a model on data from a source it does not fully
trust, and commits that data to tamper-evident append-only storage, faces the same tension: the
storage layer's integrity guarantee and the training data's trustworthiness are orthogonal, and
strengthening the first does nothing to strengthen the second. This is the same "chain integrity
is not chain validity" distinction this document needed for the row above (`Sig_RW`/`FT_RW`'s
own integrity-vs-truth caveat) — Gap 1 is that distinction's sharpest consequence, not a new one.

**Gap 2 — Insider threat at the registration authority (no tier; an operator-process claim).**
§V-2 claims credentials are deleted post-registration, defeating a privileged insider or a
stolen-verifier attack. This project implements no registration-authority module at all — there
is nothing to verify the claim against. Deletion, even if implemented, is inherently
**unverifiable from outside the deleting party** without a separate attestation mechanism (which
the paper also does not specify). This is the coverage matrix's row (2): unverified, not false,
because there is no artifact to test.

**Gap 3 — Denial of service against consensus (Tier 2, measured but not closed).** A Tier-2
adversary cannot forge a block (pBFT's safety holds at `f=1`), but can stall consensus by
withholding messages, and DEV-20's reduced view change (no state transfer) means **a lagging
honest replica is indistinguishable from a faulty one and consumes the cluster's single tolerated
fault** — `test_pbft_byzantine.py::test_equivocation_with_honest_votes_strands_one_honest_replica`
demonstrates the resulting stall directly. Liveness at `n=4` is thus more fragile than safety:
safety survives exactly one Byzantine node; liveness can be lost with one Byzantine node plus one
merely-slow honest one. No extension in this project (Scyther, Raft, hybrid) closes this — Raft
(DEV-32) is faster when honest but is *worse* under this exact adversary (loses safety, not just
liveness, to a single Byzantine leader, Tier 2's own finding above), so it is not an available
fix, only a different, worse trade-off.

**Gap 4 — Side-channel leakage from the encrypted backup chain (Tier 1, partially adjacent).**
`BC_DTBU` payload contents are encrypted (`E_KU_CSl(Tx)`, hybrid encryption), which is what
claim (4)'s "leakage" half of the coverage matrix credits. **Transaction sizes and timing are not
encrypted** — an external network observer (Tier 1, within its stated capability: it can observe
everything in transit) can see how often a system backs up and roughly how much data moves each
time, without decrypting anything. `docs/STORAGE_ANALYSIS.md` (GAP-2) analyses storage cost, not
this; no extension in this project measures or mitigates it. This is a structural property of
committing variable-sized encrypted blobs to a chain whose block headers and transaction counts
are, by design, public (`blockchain/anchor.py`'s whole premise, for `BC_DTBU`'s *hybrid* mode
specifically, is that some metadata is meant to be externally visible).

---

## Cross-references

- `docs/PAPER_NOTES.md` §V — the five claims this document replaces with a structured argument.
- `docs/DEVIATIONS.md` DEV-02 (session protocol), DEV-14 (Scyther, M7-1), DEV-20 (reduced view
  change), DEV-32 (Raft comparison, M7-4), DEV-33 (hybrid chain, M7-5), DEV-27/DEV-34 (honeypot
  representativeness, M7-7), DEV-37 (honeypot poisoning, M7-11), DEV-38 (drift-detection defense
  and its trust assumptions, M7-12).
- `RESULTS.md` M7-3 (adversarial attack), M7-4 (Raft comparison), M7-5 (hybrid anchoring), M7-7
  (real-malware transfer), M7-8 (adversarial retraining), M7-11 (honeypot poisoning), M7-12
  (drift-detection defense).
- `scripts/m7_12_poisoning_defense.py`, `src/bsfr_sh/detection/drift.py`,
  `src/bsfr_sh/consensus/validated_commit.py` — the defense measured above.
- `verification/README.md` — the full Scyther claims table and stated limitations (Tier 1).
- `docs/report/report.tex` §"Threat Model" — the shorter, matrix-and-gaps-focused version of this
  document, written for the report's own reader rather than as a standalone reference.
