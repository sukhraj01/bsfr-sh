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

**Amendment (M3a, 2026-09-12): who can build the index, and what it costs.** M2a put `system_id`
inside the encrypted payload, so the chain does not reveal which systems were backed up or when.
That means an index keyed on `system_id` cannot be built from public chain data. `BackupIndex`
belongs to the key holder `CS'_l` (DEV-25) and decrypts each backup transaction once, as its block
is appended. **The index moves the decryption cost from recovery time to append time. It does not
remove that cost.** The warm index and the cold scan do the same decryptions at different moments.
Only the lookup becomes independent of chain length. The index stores pointers (height, block hash,
transaction index), never plaintext. Restore re-reads and re-verifies the block behind every
pointer. So a stale or wrong index can cost a fallback scan, but it cannot change what is restored.
If a warm index's anchor block hash no longer matches the chain, the index is discarded and rebuilt
by full scan. `tests/unit/test_backup_index.py` asserts that the index and the cold scan return
identical locations.

**Amendment (M3b, 2026-09-12): index maintenance is not part of Alg. 1's timed path.** Until now
`phase1_backup.run()` synced the index once the blocks committed, which put our index inside
anything that times Alg. 1 — and the paper has no index, so Fig. 6(a) would have compared our
indexed append against their unindexed one. `run()` no longer touches the index, and
`phase1_backup.maintain_index(index, cluster)` is an explicit step. A flag would have left the
cost one default away from the span; a separate function makes it structurally absent.
`configs/bench.yaml` (`timing.index_maintenance: separate_column`) records that M6 reports this
cost separately and never inside a Target 3 number.

### DEV-06 · FIX · Class balance in ML evaluation
**Paper:** §VII resamples BitcoinHeist to 90% ransomware / 10% benign, then reports accuracy
(98.98%) and F1 (0.990). On that split a constant-positive classifier scores 90.0% accuracy and
≈0.947 F1.

**Amendment (M4a, 2026-09-12): what the 90/10 split costs in sample size.** The paper cites a
2,916,697-row dataset and then resamples it to 90% ransomware. Only **41,413 ransomware rows
exist**, so the resample is bounded at `41,413 / 0.9 = 46,014` rows — **1.6% of the dataset it
cites**, at a class balance that occurs nowhere outside the resample. The paper never states this.
Its headline 98.98% is therefore a number from a ~46K-row experiment, not from 2.9M rows, and the
reader is given no way to notice. `paper_mode_arithmetic()` is a pure function so the bound is
asserted without touching the data
(`test_detection_dataset.py::test_the_resample_is_bounded_by_the_positives_that_exist`).
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
   **M3a (2026-09-12): wired for backups, not for requests.** A backup reaches `CS_l` only over
   its sender's `SK_{CS_l,SYS_i}`, and it must carry that sender's DEV-23 attestation. So no system
   can get a *restorable* backup onto `BC_DTBU` in another system's name. The `ClientRequest`
   from `CS_l` to the replicas is still unauthenticated. Anyone who can reach the bus can get junk
   transactions committed. That costs storage, and junk can never be restored as anyone's data.
   Closing the gap means signing requests with the submitting server's key. No M3a claim depends
   on it. The pipeline's client rule (`f+1` replicas) stands in for Castro–Liskov's replies.
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

### DEV-23 · FILL · Recovered data is checked against a digest `SYS_i` attested before shipping (GAP-8)
**Paper:** Alg. 5 decrypts `E_KU(Tx_j)`, ships the plaintext through two cloud servers and has
`SYS_i` store it. Nothing checks that what `SYS_i` stores is what it backed up.
**Problem:** the chain proves a *transaction* was not altered after commit (Merkle root, block
signature, AEAD tag). It says nothing about plaintext round-trip, which has three failure paths
the chain cannot see:
1. **Reassembly.** A backup spanning several transactions (DEV-24) is put back together off-chain.
   A wrong order, a missing chunk, or a chunk from another backup gives bytes that were never
   backed up, while every transaction verifies.
2. **The two hops.** `CS'_l` and `CS_l` each hold the plaintext between the chain and `SYS_i`
   (Alg. 5 lines 4–5). Session AEAD protects the bytes in transit. It does not protect them from
   the servers at either end.
3. **The collector.** `CS_l` encrypts in Phase 1 whatever it chooses to. The chain then certifies
   that choice faithfully.

**Ours:** before `DT_BU` leaves the device, `SYS_i` computes
`payload_digest = H(tag_payload ‖ system_id ‖ captured_at ‖ DT_BU)` and signs
`(tag_attest ‖ system_id ‖ captured_at ‖ payload_digest)` with its ECDSA identity key. Both travel
inside every chunk's encrypted payload (`BackupPayload.payload_digest`, `.attestation`). After the
last decryption, `SYS_i` recomputes the digest over the reassembled bytes, compares it, and
verifies the attestation under **its own** public key. On any mismatch it raises and stores
nothing.

**Why a signature and not only a digest:** a digest carried with the data can be recomputed by
anyone who can alter the data, and that includes both servers. It would catch path 1 and miss
paths 2 and 3. `SYS_i` cannot keep a local receipt either, because the scenario Alg. 5 exists for
is a wiped device. The attestation needs only the device's identity key, which it must hold anyway
to open the recovery session. So the check survives both the wipe and a dishonest server. It costs
one signature per backup, not per chunk.
**Consequence:** a backup record with no digest or attestation, which is what the paper's own
record amounts to (`BackupPayload`'s defaults), is **refused** at restore rather than returned
unverified. `tests/unit/test_restore.py` pins that refusal.
**Impact on reproduction:** none on any number. Phase 1 gains one ECDSA signature per backup,
on `SYS_i`, outside Target 3's span (block construction + consensus + append).

### DEV-24 · FILL · `DT_BU` is chunked across transactions, with explicit sequence numbers
**Paper:** Alg. 1 line 2 encrypts `DT_BU` into transactions `Tx_m, m = 1..N_dTx` and never says how
a backup maps onto them. GAP-2 (no payload size) makes the question unavoidable, because DEV-15's
declared 4 KiB is smaller than any real backup.
**Ours:** `blockchain.backup.split()` cuts `DT_BU` into `ceil(len / payload_bytes)` fragments of
`transaction.payload_bytes` bytes. The last fragment carries the remainder, and an empty backup is
one empty fragment, so "empty" and "absent" stay distinguishable. `CS_l` encrypts each fragment into
its own transaction. The pipeline packs them `block.transactions_per_block` to a block, so a large
backup spans several blocks. Every fragment carries `chunk_index` and `chunk_count` inside its
encrypted payload. `blockchain.backup.reassemble()` orders by `chunk_index`, **never** by block
height or position. It requires exactly the indices `0..count-1`, requires every chunk of one backup
to agree on `(system_id, captured_at, payload_digest, attestation, chunk_count)`, accepts a
byte-identical duplicate, and refuses a conflicting one.
**Why explicit indices:** block order is consensus order, and the submitter does not control it.
Batches submitted together commit in whatever order the primary proposes them, and a view change
can re-propose. Inferring fragment order from height would make restore depend on a property
consensus does not promise. Tested by committing a backup's later fragments at lower heights.
**What `payload_bytes` now means:** backup bytes per transaction, before framing and encryption.
Measured for a 4096-byte chunk with `system_id = "SYS_1"`:

* The chunk's plaintext encoding is **215 bytes** larger than its data. The paper-shaped record's
  own framing accounts for 112 of those, and M3a's indices, digest and attestation for 103.
* DEV-01's encryption adds another **161 bytes**: a 16-byte GCM tag, a 133-byte wrapped key and a
  12-byte nonce.

The exact figures vary by a byte or two with the id length and the DER signature length.
**Impact on reproduction:** none. Fig. 6 counts transactions and blocks, not backups.

### DEV-25 · FILL · `CS'_l` is the cloud server holding the key a backup was encrypted to
**Paper:** Alg. 5 line 4 has "`CS'_l`" decrypt `E_KU(Tx_j)` and hand the plaintext to `CS_l` over
`SK_{CS'_l,CS_l}`. `CS'_l` is defined nowhere.
**Ours:** Alg. 1 line 2 encrypts to `KU_CSl` of the server that *collected* the backup, so only
that server can decrypt it. The consistent reading is that `CS'_l` is Phase 1's collecting server
(the key holder) and `CS_l` is whichever server `SYS_i` recovers through (the front server).
`recovery.restore` builds both hops. When the two roles fall on one server, the first hop has no one
to go to (a server holds no session with itself), and `framework.phase5_recovery` skips it. Recovery
still succeeds, which shows the hop is there for fidelity to §IV-E, not because recovery needs it.
Tested: `test_restore.py::test_one_server_in_both_roles_skips_the_fidelity_hop`.
**Impact on reproduction:** none; Alg. 5 is not benchmarked.

### DEV-26 · FILL · What "remove the abnormalities" means (Alg. 2, line 3)
**Paper:** Alg. 2 line 3 pre-processes `DT_RW` and "removes the abnormalities". Nothing else is
said anywhere.
**Problem:** the obvious reading is catastrophic. If "abnormalities" means statistical outliers,
then this step **deletes the positive class**: ransomware behaviour *is* the outlier in a corpus of
ordinary software. A pipeline that removes anomalies before training a ransomware detector removes
exactly what the detector exists to find, and it does so silently — leaving a clean-looking dataset
and a model that has never seen an attack. Phase 3 would then report a fine-looking accuracy on
data with almost no positives left in it.
**Ours:** "abnormalities" means **sensor defects, never unusual behaviour**, implemented as five
rules in `honeypot/preprocess.py`:
1. *Structural* — no observed stage, or a non-positive duration: the record describes no episode.
   Dropped.
2. *Impossible values* — entropies outside [0, 8] bits/byte, ratios outside [0, 1], negative
   magnitudes. Out-of-range values are clamped to the bound; a negative **count** is marked
   unreadable instead, because "the sensor returned nonsense" and "the program did nothing" are
   different facts and must not become the same number.
3. *Duplicates* — two records with a byte-identical canonical trace are one observation reported
   twice. The first is kept.
4. *Missing, marked* — a counter the sensor never reported stays missing and is recorded. Nothing
   is imputed at collection time, because imputation hides the honeypot's blind spots inside the
   data where M4 cannot see them.
5. *Normalisation* — `files_touched`, `renames` and `crypto_calls` are absolute counts; divided by
   the episode duration they become the rates the feature schema declares.

No outlier filtering, no smoothing, no winsorising, no class balancing. `CleaningReport` counts
what each rule did, so survivor counts are measured rather than assumed, and
`test_honeypot_preprocess.py::test_cleaning_does_not_remove_the_positive_class` pins the property
that matters.
**Impact on reproduction:** none — the paper reports no number from this step. It changes what
Phase 3 receives, which is the point.

### DEV-27 · FILL · `FT_RW` as built: 22 features, a truncated kill chain, and a corpus with a stated difficulty
**Paper:** Alg. 2 line 6 "generates features". GAP-3: no definition of any feature anywhere, and
the paper's own evaluation then abandons this data for an unrelated Bitcoin dataset (FLAW-2).
**Ours:** the 22-feature, 7-group schema in `docs/ARCHITECTURE.md` §honeypot, named `ft_rw.v1`,
plus the record schema M4 reads. Three parts of it are decisions rather than details:

**(a) The kill-chain group is truncated.** §II-C's chain ends notification → payment →
decryption, and no benign program reaches those stages. A `stage_reached` feature over the full
chain would be *the label wearing a feature's clothes*: perfectly predictive, trivially found by
every model, and worth nothing. The two honest options were to drop the group or to keep only the
part both classes produce; we keep the observable prefix (arrival, enumeration, bulk transform,
cleanup, capped at 4), because those four are genuinely observable for benign software. The full
walk stays in `RawSample`/`CleanSample` as provenance, out of the feature vector.

**Amendment (M4a, 2026-09-12): the committed corpus is the fixed dataset — Q9 closed.** M4 trains
and evaluates on `data/honeypot/corpus_train.csv` and `corpus_eval.csv` exactly as committed;
experiments never regenerate them. Regenerating per experiment would change the data underneath
every comparison, so two M4 numbers would differ in both the model *and* the corpus, and no
difference between them could be attributed to either. Regeneration stays reproducible from the
manifest for a deliberate schema change — which bumps `GENERATOR_VERSION` and lands as its own
commit — but it is never something a run does on the way past.

**(b) The corpus is built to be hard, and says how hard.** The generator draws
`AMBIGUOUS_FRACTION = 0.25` of both classes from confusable pairs that share one identical
parameter set, so those samples carry no label information at all — a floor of 0.125 under the
Bayes error before any other overlap. Four benign profiles are deliberately ransomware-shaped
(backup agent, disk-encryption tool, installer, cleanup utility). `EXPECTED_BAYES_ACCURACY = 0.85`
is recorded in the corpus manifest and in `PROJECT_STATE.md`, because **M4 needs it to tell a
result from an artefact**: a detector scoring far above it is reading a leak. Enforced by
`test_honeypot_features.py`: every feature's class ranges overlap, no single feature (or group
mean) reaches 0.90 separability, missingness does not encode the label, and a baseline fitted on
one draw and scored on another lands near the intended figure rather than at ceiling.

**Measured on the committed corpus** (1467 train / 731 eval records, 48.9% malicious): the most
separable single feature is `extension_change_rate` at 0.816, followed by `rename_rate_per_s`
(0.803) and `observed_stages` (0.796); the baseline reaches **0.830** balanced accuracy, trained
on the train draw and scored on the eval draw. That sits just under the intended 0.85 and nowhere
near ceiling, which is the point. It took tuning: the first parameter set put
`extension_change_rate` alone at 0.885, which is exactly the single-feature giveaway the leakage
test exists to catch.

**(c) Two carriers, and two draws.** A record travels either as `SignatureRecordPayload` on
`BC_SigRW` or as a CSV row in `data/honeypot/`; both carry `schema`, `missing_mask` and `label`.
`label` is the target and never a feature; `missing_mask` marks unobserved entries rather than
imputing them (the canonical encoder has no NaN). Train and eval draws come from **different
seeds, never one draw shuffled**, because samples within one generator call can share latent
parameters.
**Impact on reproduction:** none on any published number — the paper evaluates on BitcoinHeist,
not on this. It is what lets M4 run the framework's *own* data path at all, and per FLAW-2 both
backends are reported side by side.
