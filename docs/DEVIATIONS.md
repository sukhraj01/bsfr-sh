# Deviations from the Paper

Every place our implementation departs from BSFR-SH as published. **Add the entry before the code
lands, not after.** An undocumented deviation is a bug.

Categories:
- **FILL** — the paper leaves it unspecified; we designed something.
- **FIX** — the paper specifies something broken; we do it correctly *in addition to*
  reproducing the original.
- **POLICY** — we decline to implement something on safety or legal grounds.
- **ADD** — an extension beyond the paper's scope.

Reproduction targets are never affected by FILL or ADD entries. A FIX entry always produces two
result sets: `paper_mode` and `honest_mode`.

---

### DEV-01 · FILL · Hybrid encryption for transaction payloads
**Paper:** Alg. 1 line 2 / Alg. 2 line 7 write `E_KU_CSl(Tx)` — payload encrypted directly under
the cloud server's public key.
**Problem:** EC public-key encryption cannot carry bulk payloads; healthcare backups are large.
**Ours:** AES-256-GCM over the payload, data key wrapped by ECIES under `KU_CSl`. Transaction
carries `(ciphertext, wrapped_key, nonce, tag)`. Semantics identical — only `CS_l` can decrypt.
**Impact on reproduction:** negligible timing difference; recorded in bench sidecars.

**Amendment (M1, 2026-09-11) — the wrapped key is bound to the ciphertext it protects.**
Splitting one public-key encryption into two byte strings creates a seam the original does not
have: a wrapped key and a payload that are merely *adjacent* in a `Transaction` can be separated.
An attacker who breaks neither primitive can lift the wrapped key from `Tx_1` onto `Tx_2`; because
`Sig_βj` covers whatever the block contains, every signature in the chain still verifies while
`CS_l` decrypts something the honest owner never submitted. That defeats §V-4 (data manipulation
and leakage) without forging anything.

`crypto.kem.seal_payload` therefore binds in both directions: the wrap's AEAD associated data is
the transaction metadata, and the payload's associated data is that metadata **plus the
wrapped-key bytes**. Detaching either half breaks a GCM tag. M2's `Transaction` must call
`seal_payload`/`open_payload` rather than assembling the pieces, because the binding only holds if
it is applied in one place. Tested in `tests/unit/test_kem.py`.

### DEV-02 · FILL · Session establishment protocol
**Paper:** §IV-A and §V-1 defer to "any standard mutual authentication and key establishment
mechanism," cf. BUAKA-CS [26].
**Ours:** ECDH over secp256r1 with ECDSA-signed transcripts, nonces and timestamps, per
`docs/ARCHITECTURE.md` §crypto. Chosen because it satisfies every property §V-1 asserts and
reuses the ECDSA primitive the paper already mandates.

**Amendment (M1, 2026-09-11).** Implementing the protocol found two defects in our own sketch.
Both were ours, not the paper's — the paper specifies nothing here — but both would have made
§V-1's claims false, which is worse than leaving them unspecified. `docs/ARCHITECTURE.md` §crypto
has been corrected to match; the version below is authoritative.

*(a) A's signature must name B.* The sketch signed `ID_A || N_A || TS_A || g^a`. Nothing in it
says who the message is for, so it is a valid session opening addressed to **every** cloud server.
Capture A's opening to `CS_1`, replay it verbatim to `CS_2`, and `CS_2` checks A's signature, finds
it good, and completes a session it believes A requested. That is impersonation of A requiring no
key material at all, against a property §V-1 claims explicitly. Fixed by binding `ID_B` into A's
signed message. B's reply additionally covers `N_A` and `g^a`, so message 2 cannot be detached
from the message 1 it answers.

*(b) A timestamp window is not replay protection.* It bounds how *long* a replay stays acceptable;
inside the window a captured message replays perfectly. Since §V-1 claims replay resistance
outright, `Responder` keeps a seen-nonce cache keyed by `(peer_id, nonce)` and rejects any nonce
it has already accepted. The eviction horizon is `2 x timestamp_window_s`: a message stamped `TS`
is acceptable until `TS + window` and the receiver's own clock may be `window` behind, so a
shorter horizon could evict a nonce while a replay of it is still inside the window.

Resulting protocol:

```
A -> B : ID_A, ID_B, N_A, TS_A, g^a, Sig_A(tag1 || ID_A || ID_B || N_A || TS_A || g^a)
B -> A : ID_B, ID_A, N_B, TS_B, g^b, Sig_B(tag2 || ID_B || ID_A || N_B || TS_B || g^b || N_A || g^a)
both   : SK = HKDF(g^ab, info = tag_sk || ID_A || ID_B || N_A || N_B || g^a || g^b)
```

`tag1`, `tag2` and `tag_sk` are distinct domain separators (`crypto.hashing`), so neither
signature fits the other's slot. Skew window stays configurable, default 30 s
(`configs/chain.yaml` `crypto.session.timestamp_window_s`). Tested in
`tests/unit/test_session_replay.py` and `tests/unit/test_session_mitm.py`.

### DEV-03 · FILL · Definition of `Sig_RW` and `FT_RW`
**Paper:** Alg. 2 lines 5–6 say signatures and features are "built." No definition anywhere.
**Ours:** `Sig_RW` split into `content_digest` (identification) and `attestation` (ECDSA
authenticity). `FT_RW` is a 7-group behavioural feature vector grounded in refs [11]–[14], [20].
Full schema in `docs/ARCHITECTURE.md` §honeypot.
**Why it matters:** without this, Phase 3 has nothing to consume from Phase 2 — which is exactly
why the paper had to fall back to an unrelated dataset. This is the deviation that makes the
framework coherent.

### DEV-04 · FILL · Erasure semantics in Case-1
**Paper:** Alg. 4 line 5 — "erases `RW`."
**Ours:** modelled as quarantine + integrity verification state transition. We do not implement
malware removal logic; there is nothing real to remove.

### DEV-05 · ADD · Per-system backup index
**Paper:** Alg. 5 line 1–2 implies scanning `BC_DTBU` for a system's backups.
**Ours:** `recovery.locator.BackupIndex` maintained on append. Falls back to full scan when cold,
so paper semantics are preserved exactly. Reduces recovery from O(chain) to O(1) lookup.

### DEV-06 · FIX · Class balance in ML evaluation
**Paper:** §VII resamples BitcoinHeist to 90% ransomware / 10% benign, then reports accuracy
(98.98%) and F1 (0.990). On that split a constant-positive classifier scores 90.0% accuracy and
≈0.947 F1.
**Ours:** both modes.
- `paper_mode` — exact 90/10 resample, reports accuracy and F1 as published. **Reproduction
  target.**
- `honest_mode` — natural ≈1.42% positive rate, stratified k-fold, reports precision, recall,
  PR-AUC, MCC, minority-class F1, confusion matrix.

Both appear in every report. Neither is presented without the other.

### DEV-07 · FIX · Annotate Table II with source datasets
**Paper:** Table II compares BSFR-SH's BitcoinHeist score against four schemes evaluated on
entirely different data (network traces, dynamic analysis logs, PE features).
**Ours:** reproduce the table exactly, with an added `dataset` column and a footnote stating the
comparison is not like-for-like. The bar charts (Figs. 4, 5) are reproduced as published and
reprinted with the annotation.

### DEV-08 · FIX · TPS reported as derived, plus marginal cost
**Paper:** §VII-D presents TPS as a measured throughput property that rises as the chain grows.
**Finding:** every reported TPS value equals `total_tx / total_time` exactly (verified for all six
data points — see `docs/PAPER_NOTES.md`). The rise is amortisation of fixed setup cost, not a
throughput improvement.
**Ours:** reproduce the averaged TPS as published, and additionally report marginal per-block
cost, which is approximately flat.

### DEV-09 · POLICY · Case-3 ransom payment is simulated only
**Paper:** Alg. 4 line 7 automates paying the adversary and retrieving `K_d` when
`RW_amt < DT-SYS_i-amt`.
**Ours:** the branch exists, evaluates the condition, emits a `PolicyDecision` and an audit log
record, and terminates in state `POLICY_BLOCKED`. No network access, no wallet, no transaction
construction, no key retrieval. Enforced by `tests/unit/test_case3_is_inert.py`.
**Rationale:** the paper itself notes (§II-C) there is no guarantee the key arrives or works;
automated ransom payment funds attackers and is sanctioned conduct in several jurisdictions. The
control-flow contribution is preserved; the harmful capability is not.

### DEV-10 · FILL · Explicit pBFT threshold and view change
**Paper:** "a threshold fraction of miners commit," no value given; no view change described.
**Ours:** standard `2f+1` of `n = 3f+1`; with the paper's 4 nodes that is 3 of 4, `f = 1`.
Configurable. View change on leader timeout, per Castro & Liskov [24].

**Amendment (M2b, 2026-09-11).** Built. The view change is the *reduced* form, not full
Castro–Liskov — DEV-20 names exactly what is omitted. The message format is DEV-19 and the bus's
latency model is DEV-21. Certificate sizes are the standard ones: prepared = accepted
pre-prepare + `2f` matching prepares from distinct non-primary replicas; committed = prepared +
`2f+1` matching commits from distinct replicas; new-view = `2f+1` view-changes from distinct
replicas. All counted by signed sender identity.

### DEV-11 · FILL+FIX · Merkle tree construction detail
**Paper:** `MTR` appears in the block header with no construction spec.
**Ours:** binary Merkle tree over transaction digests, odd nodes duplicate the last hash.

**Amendment (M1, 2026-09-11) — the leaf count is bound into the root.** Last-node duplication is
not injective, and this is its known consequence (the shape of CVE-2012-2459). For leaves
`[a, b, c]` the bottom level pads to `[a, b, c, c]`, so the three-transaction list and the
four-transaction list `[a, b, c, c]` build an *identical tree* and produce an *identical root*.

This is not a theoretical concern in BSFR-SH specifically: `MTR` is the only header field binding
a block to its transaction list, so a root that two different lists share is a block header that
cannot tell its own contents apart. Every §V-4 integrity claim rests on it.

The construction above is kept exactly as stated, and the count is bound into the final digest:

```
MTR = tagged_h(DOMAIN_MERKLE_ROOT, uint64_be(leaf_count), bare_root)
```

`[a, b, c]` and `[a, b, c, c]` now differ in `leaf_count` and so in `MTR`, while the tree above
them is unchanged. An inclusion proof carries `leaf_count` and is rejected if it misstates it,
which is what makes the binding load-bearing rather than decorative. Leaf and internal-node
digests also use distinct domains, closing the standard Merkle second-preimage substitution.

**Consequence:** our `MTR` values are not Bitcoin's. They were never going to be — our leaves are
domain-separated and Bitcoin's are double-SHA-256 — so no reproduction target is affected. Tested
in `tests/unit/test_merkle.py`, including a test asserting the *underlying* collision still exists,
so nobody later removes the binding on the grounds that it looks redundant.

### DEV-12 · FILL · Cases vary block count, not device count
**Paper:** §VII defines case-1/2/3 by block count (5/10/15) but §VII-C describes the x-axis as
increasing "number of devices."
**Ours:** hold device count fixed, vary blocks — matching the numeric setup, which is what
produces the published values. Noted rather than resolved, since the prose and the setup
contradict each other.

### DEV-13 · ADD · Language and runtime
**Paper:** Java, Eclipse 2019-12, Windows 11, i5-9th gen @2.40 GHz, 8 GB RAM.
**Ours:** Python 3.11+. Absolute timings will not match the paper's — different language, runtime
and hardware. **The reproduction target is the trend and the ratios, not the seconds.** Our own
hardware is recorded in every bench sidecar.

### DEV-14 · ADD *(optional)* · Formal security verification
**Paper:** §V is informal prose; no ROR/BAN proof, no AVISPA or Scyther model.
**Ours:** stretch goal — model the session-establishment protocol in Scyther and report results.
Not required for the core deliverable. Tracked in `docs/ROADMAP.md` M7.

### DEV-15 · FILL · Declared transaction payload size
**Paper:** §VII benchmarks 100 transactions per block over 5/10/15 blocks and never states how
large a transaction is. GAP-2 / open question Q2.
**Problem:** every number in Figs. 6(a)–(d) is a function of payload size. Without it, "3.10 s for
500 transactions" is not a reproducible claim — it is a claim about an unstated constant.
**Ours:** `configs/chain.yaml` declares `transaction.payload_bytes: 4096`, large enough to be a
plausible encrypted record fragment and small enough that 1500 transactions fit on the 8 GB dev
box. `payload_bytes_sensitivity: [1024, 4096, 16384]` is swept in M6 so the report can state how
much of the paper's curve is really a statement about payload size.
**Impact on reproduction:** absolute seconds shift with this value; the trend and ratio targets
(DEV-13) do not. Recorded in every bench sidecar via the config hash.

### DEV-16 · FILL · Declared ML hyperparameters and split ratio
**Paper:** §VII reports Random Forest, Logistic Regression, Decision Tree and KNN with accuracy
and F1, and no hyperparameters, no train/test ratio, no cross-validation scheme, no seed.
**Problem:** "Decision Tree scores 98.98%" is not reproducible from the paper alone, and a
difference between our number and theirs cannot be attributed without knowing what they ran.
**Ours:** every hyperparameter is declared in `configs/ml.yaml` (marked DECLARED, with the
scikit-learn defaults kept where they are sane and `max_iter: 1000` where the default does not
converge), `paper_mode.test_size: 0.30`, and `random_state` injected from `--seed` at run time.
**Impact on reproduction:** our Table II row is reproducible from our config; the paper's is not
reproducible from theirs. The report states this rather than implying our numbers are theirs.

### DEV-17 · FIX · Block timestamps are non-decreasing within a tolerance, not monotonic
**Paper:** Alg. 1 line 3 / Alg. 2 line 8 put `TS` / `TSDT_j` in the block header and the text
implies block timestamps increase along the chain. `docs/ARCHITECTURE.md` §blockchain recorded
this as "timestamp monotonicity".
**Problem:** taken strictly, that is wrong for the system the paper describes. Blocks are
produced by different cloud servers in a P2P network, each with an independent clock. Two honest
blocks committed a second apart can carry timestamps in the "wrong" order under ordinary NTP
skew, so strict monotonicity rejects honest blocks. The symptom is the unpleasant kind: an append
that fails only sometimes, only under load, on a chain that is not actually corrupt.
**Ours:** non-decreasing **within a tolerance**. A block may be up to `skew_tolerance_s` older
than the current head; beyond that it is rejected. Equal timestamps are accepted. Forward drift
is not bounded here — freshness against wall-clock belongs to `crypto.session`, and duplicating
it in the chain would mean two clock policies to keep in step.

The tolerance is the **same configured value** the session protocol uses, read through
`SessionPolicy.from_config` rather than from a second key: `configs/chain.yaml` →
`crypto.session.timestamp_window_s`, default 30 s. Two independently-tuned clock tolerances in
one system drift apart, and then "how much skew do we accept?" has a different answer depending
on which subsystem is asked.
**Impact on reproduction:** none. No benchmark varies block timestamps; case-1/2/3 append blocks
in order. This only changes which *dishonest* chains are rejected, which the paper never
measures. Tested in `tests/unit/test_chain.py`.

### DEV-18 · ADD · Config-hash construction is versioned
**Paper:** n/a — this is about our own result provenance, not BSFR-SH.
**Problem:** `results/logs/<run_id>.json` records a `config_hash` so a number can be traced to the
configuration that produced it (CLAUDE.md §2). M2a moved `config_hash()` from `util.config` into
`crypto.hashing` and routed it through `tagged_h`, which mixes in a domain tag. Every config
digest therefore changed value on 2026-09-11 **without any config file changing**. A later
comparison across that boundary would read a version difference as config drift and send someone
looking for a config that never moved.
**Ours:** `crypto.hashing.CONFIG_HASH_SCHEME` (currently 2), written into every sidecar as
`config_hash_scheme` and listed in `configs/bench.yaml` `output.sidecar_fields`. Scheme 1 is the
pre-M2a construction. The one existing sidecar has been backfilled with `config_hash_scheme: 1`
and a note; its `config_hash` is `null` — that run had no governing config — so no value is
affected, and the field records which era the file belongs to.
**Impact on reproduction:** none yet, since no `measured` row depends on a config hash. It is
recorded now because the cost of adding it later, after M6 has written figures, is much higher.

### DEV-19 · FILL · pBFT message format — digest-only signed pre-prepare, chain-bound (closes Q7)
**Paper:** Alg. 1/2 say only that the leader "broadcasts `β_j`" and the miners run pBFT. No
message format is given.
**Ours:** every pBFT message is an ECDSA signature over a canonical struct
(`util.serialization.encode_struct`) whose domain is specific to the message *type*
(`bsfr_sh.pbft.prepare.v1`, `...commit.v1`, ...), with signed fields
`(chain, view, seq, digest, replica_id)`. A pre-prepare signs only the digest; the `Block`
travels alongside it, outside the signature, and a replica rejects the pair unless
`block.current_hash == digest`. That is what real pBFT does and still matches the paper's text —
the block *is* broadcast.

Three things in the signed body are load-bearing, each pinned by a test:
- **`view`** — without it a prepare from view 0 is a valid prepare in view 1, and a replica that
  voted once can be counted in every later view.
- **`seq`** — without it a vote for height `n` is a vote for height `n+1`.
- **`chain`** — our addition. `BC_DTBU` and `BC_SigRW` run independent clusters (CLAUDE.md §4),
  but nothing stops a deployment reusing a cloud server's key on both. Without the chain name in
  the pre-image, a prepare signed for one chain verifies on the other.

Per-type domains mean a prepare's signature is never a valid commit signature for the same
`(view, seq, digest)`.
**Impact on reproduction:** none on correctness targets. On Target 3, signing a 32-byte digest
rather than the whole block keeps per-message ECDSA cost constant in block size, which is the
standard design and what makes consensus cost roughly independent of transactions per block.

### DEV-20 · FILL · Reduced view change — what is omitted from Castro–Liskov, and what it costs
**Paper:** no view change at all (DEV-10). A silent leader in the paper's design stalls its
chain forever, which undercuts §V-3's resistance claim.
**Ours:** timeout-triggered view change with prepared-certificate carry-over, in
`consensus/view_change.py`:
- a replica with an uncommitted request starts a timer (`consensus.view_change_timeout_s`);
  on expiry it moves to `view+1` and broadcasts a signed `ViewChange` carrying every prepared
  certificate it holds above its committed height, plus a commit certificate proving that height;
- a replica that sees `f+1` view-changes for higher views joins the smallest of them without
  waiting for its own timer;
- the new primary, on `2f+1` view-changes from distinct replicas, broadcasts a signed `NewView`
  that carries them and re-proposes the highest-view prepared block at the next height;
- every receiver re-verifies each carried view-change and certificate and *recomputes* the
  re-proposal set, rejecting a `NewView` whose proposals differ from what the evidence forces —
  so a byzantine new primary cannot quietly drop a prepared block;
- a view change that itself stalls escalates to `view+2` after twice the timeout.

**Omitted, precisely:**
1. **Checkpoints and stable-checkpoint garbage collection.** There are no `CHECKPOINT` messages.
   Instead each replica proves its committed height in its view-change with the `2f+1` commits
   that committed it — a one-block checkpoint. Log entries at or below the committed height are
   dropped on commit. *Cost:* none for safety; the proof is exactly what a stable checkpoint
   would give for the last block.
2. **State transfer.** A replica that falls behind — misses the commits for a height the others
   committed — has no way to fetch the missing block. It stays behind and cannot prepare later
   blocks, because it cannot validate their `prev_hash`. *Cost:* **a lagging honest replica is
   indistinguishable from a faulty one and uses up the single fault the cluster tolerates.** With
   `n=4`, one lagging honest replica plus one byzantine replica stalls the chain. It is not
   hypothetical: a byzantine primary that equivocates on blocks but votes honestly strands the
   honest replica it showed the losing block —
   `test_pbft_byzantine.py::test_equivocation_with_honest_votes_strands_one_honest_replica`
   pins it. (When the equivocator also garbles its votes, nothing commits in the old view and the
   view change's certificate carry-over rescues that replica instead — the neighbouring test.)
   A lossy network would strand replicas the same way.
3. **Pipelining / watermark window.** At most one height is in flight: a primary proposes height
   `h+1` only after committing `h`. Messages for heights up to `h + consensus.log_window` are
   buffered so reordering cannot lose them, but they are not processed early. *Cost:* throughput
   under non-zero latency — each block pays the full three-hop round trip serially. This is a
   Target 3 consideration and is recorded in `configs/bench.yaml`.
4. **Null requests.** Castro–Liskov fills gaps in the new-view sequence range with null
   requests. With one height in flight there are no gaps to fill, so the case never arises.
5. **Client replies and request authentication.** Requests (a batch of transactions to put in a
   block) are delivered to replicas unauthenticated and nothing replies to the submitter. Request
   authentication belongs to the session layer (`crypto.session`, Phase 1) and is wired in M3.
6. **Retransmission.** A dropped message is never resent; liveness under loss comes only from
   the view-change timer.
7. **Helping with already-committed heights.** A replica rejects every message for a height it
   has committed (as the M2b brief requires). If a replica commits height `n` at the same moment
   the others time out without it, it will not help re-commit `n` in the new view. Combined with
   (2), this is a liveness race, not a safety one: timeouts are seconds, message delays default
   to zero, and the tests do not reach it.

**Impact on reproduction:** none on any paper number — the paper measures no faults. Safety
(no two honest replicas commit different blocks at one height) holds for up to `f` byzantine
replicas under the reduction; liveness is weaker than full Castro–Liskov only through (2), (6)
and (7).

### DEV-21 · FILL · Message bus on a simulated clock, per-message delay declared and zero by default
**Paper:** §VII reports timings for pBFT over four miners and says nothing about the network
between them — not whether nodes were separate machines, not the link latency.
**Ours:** `consensus.network.P2PCSNetwork` is an in-process discrete-event scheduler. A message
sent at simulated time `t` is delivered at `t + consensus.message_delay_s` (+ any per-node fault
delay or jitter). View-change timers run on the same clock. Nothing sleeps. Default delay `0.0`,
DECLARED in `configs/chain.yaml`.
**Why simulated and not slept:** a view-change test on a slept clock waits seconds per case;
`sleep` jitter on the dev box is the same order as the zero-delay consensus cost; and a simulated
clock makes modelled network time exact and seed-reproducible.
**Impact on reproduction — Target 3.** With delay `0`, wall-clock around consensus is pure
compute (signing, verification, hashing, chain validation) and Fig. 6's shape is dominated by
hybrid encryption. A non-zero delay does **not** change wall-clock; it adds `≈ 3 × delay` of
simulated time per committed block (pre-prepare → prepare → commit, one height in flight per
DEV-20). M6 reports the measured compute and the modelled network time as separate columns and
labels the second as modelled — it is not `measured` in the CLAUDE.md §2 sense.

### DEV-22 · FILL · The pBFT primary assembles the block; the collecting `CS_l` submits transactions
**Paper:** Alg. 1 line 3 (and Alg. 2 line 8) has the collecting cloud server `CS_l` assemble
`β_j`, line 4 broadcasts it, and line 5 has "the leader `L`" run pBFT. Whether `CS_l` and `L` are
the same node is not said.
**Ours:** `CS_l` encrypts the transactions (Alg. 1 line 2 / Alg. 2 line 7, unchanged) and submits
them as a `ClientRequest`; the primary of the current view assembles and signs the block, so
`OID`/`OKU` name the leader that proposed it. After a view change a re-proposed block keeps its
original owner, so replicas accept any member as owner, not only the current primary.
**Why:** `β_j` carries `HP_βj-1`. Only the node ordering the chain knows which head the next block
extends; if every collecting `CS_l` assembled its own block, two of them would build on the same
head and one block would fail `Chain.append` after consensus had already been spent on it. In
pBFT the primary is that node. This is the standard client/primary split.
**Impact on reproduction:** Target 3's measured span — block construction + consensus + append —
contains the same work either way (hybrid encryption happens before submission in both); sealing
a block is one Merkle root and one ECDSA signature. No correctness target is affected.
