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

**Amendment (M5, 2026-09-13): built as `mitigation.cases.case1_quarantine`.** It is a pure
transition on an already-isolated system (`mitigation.state.Remediating.clean()`): the quarantine
itself is Alg. 4 line 3's isolation, already done before Case-1 runs; `case1_quarantine` records
whether the post-quarantine integrity check (`integrity_verified: bool`) passed, and always
reaches `CLEANED` — a failed check is recorded, not hidden, and it is the caller's decision (Alg. 4
lines 8-10, "else re-run mitigation") whether that means trying again. No file, process, or
signature is scanned; there is no removal target in a corpus of synthesized feature vectors
(CLAUDE.md §2). Tested in `tests/unit/test_mitigation_cases.py`.

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

**Amendment (2026-09-13, Q10) — the random split was leaking too, and closing it does not close
the gap.** M4a's `paper_mode` split (`stratified_holdout`) stratifies by label only; it never
grouped by address. Checked directly against the real file before running anything: every address
carries exactly one label end to end (0 of 2,631,095 addresses have two), and ransomware addresses
repeat far more than benign ones (mean 1.99 rows/address, 12.2% appearing more than once, vs 1.10
and 3.6% for benign) — so a random split lets near-duplicate ransomware rows land on both sides of
the boundary at a rate the resample's own 90% skew amplifies. `scripts/q10_leakage_ablation.py`
ran the 2x2 this implies — {`address` dropped, kept} x {random, grouped split} — at the same
declared hyperparameters and seed as reference run `20260912T172708Z-6d35b415` (config hash
verified identical across all four cells). Findings, random forest (best of the four throughout):

| Cell | Accuracy | F1 | vs. M4a's 0.9479 | vs. published 0.9898 |
|---|---|---|---|---|
| address dropped x **grouped** split | 0.9442 | 0.9697 | −0.37pt | −4.56pt |
| address dropped x random split *(= M4a)* | 0.9479 | 0.9717 | +0.00pt | −4.19pt |
| address kept x grouped split | 0.9484 | 0.9719 | +0.05pt | −4.14pt |
| address kept x random split | 0.9540 | 0.9749 | +0.61pt | −3.58pt |

Both leakage sources are real, both are small, and stacking them does not explain the reported
98.98%. The largest single effect anywhere in the 2x2 is decision tree's `address kept x random
split`, +0.92pt over its own honest baseline — and that effect vanishes under a grouped split
(kept x grouped is flat against dropped x grouped for decision tree), which is the expected
signature of an identifier memorised across a train/test boundary that grouping closes. Even that
largest cell (decision tree, 0.9354) sits 5.44 points under the published figure. **Q10 is closed
as unexplained**, not resolved: neither `address` as a feature nor the split strategy, alone or
together, accounts for the gap between our reproduction and the paper's headline. Full numbers
and per-model deltas in `RESULTS.md`; the ablation and its 2x2 arithmetic are pure functions of
declared config plus the verified file, asserted where practical in
`test_detection_dataset.py`'s grouped-split tests.

**Consequence for the reported figure.** The honest `paper_mode` reproduction number is revised
from M4a's 0.9479/0.9717 (address dropped, random split) to **0.9442/0.9697** (address dropped,
**grouped** split) — grouping is the methodologically correct choice once duplication is
address-keyed, and this is now what Table II's BSFR-SH row should read as "ours". Random forest
stays best of the four models.

**Amendment (2026-09-13, M4b) — D6 retired.** `configs/ml.yaml` now declares
`dataset.group_column: address`, and `scripts/run_detection.py`'s `_run_paper_mode` calls
`grouped_stratified_holdout` instead of the row-random `stratified_holdout` it used through M4a
and Q10. Re-run at the same seed (20260912): random forest reproduces 0.9442/0.9697 exactly,
matching `q10_leakage_ablation.py`'s `address_dropped x grouped_split` cell (run
`20260913T014022Z-c54c3974`) from the production entry point (run `20260913T131623Z-97f51129`).
The two entry points no longer disagree. Fixing this exposed a real bug: `load_bitcoinheist`'s
drop-column check assumed `drop_columns` never reach the raw frame, which broke the instant a
column was both dropped *and* the group column (`configs/ml.yaml` declares `address` as both).
Fixed by exempting `group_column` from that check — it is loaded for grouping only and, per the
test added alongside it, never reaches the feature matrix.

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

**Amendment (M6a, 2026-09-17): measured, not just predicted.** `bench.harness.run_case()` starts
each block's timer *after* the cluster is built, so no fixed setup cost is inside the measured
span by construction — `docs/EXPERIMENTS.md` Target 3's protocol note. The result: our own
marginal per-block cost is flat (`BC_DTBU` ~0.031-0.034s/block, `BC_SigRW` ~0.044-0.046s/block,
case-1 through case-3, run `20260917T144843Z-fb4c2410`), and our own TPS is correspondingly flat
(~2930-3190 tx/s and ~2170-2230 tx/s respectively) rather than rising like the paper's six
points. This is a sharper claim than the original entry made: not just "the paper's TPS is
`tx/time`, which is arithmetic" but "when the same arithmetic is applied to a curve with the
fixed-cost term actually removed, the rise disappears" — a second, independent line of evidence
for the same conclusion, this time a measurement rather than an identity. See
`docs/EXPERIMENTS.md` Target 3/4 for the full numbers and `bench/harness.py`'s module docstring
for what is `measured` here versus `computed`.

### DEV-09 · POLICY · Case-3 ransom payment is simulated only
**Paper:** Alg. 4 line 7 automates paying the adversary and retrieving `K_d` when
`RW_amt < DT-SYS_i-amt`.
**Ours:** the branch exists, evaluates the condition, emits a `PolicyDecision` and an audit log
record, and terminates in state `POLICY_BLOCKED`. No network access, no wallet, no transaction
construction, no key retrieval. Enforced by `tests/unit/test_case3_is_inert.py`.
**Rationale:** the paper itself notes (§II-C) there is no guarantee the key arrives or works;
automated ransom payment funds attackers and is sanctioned conduct in several jurisdictions. The
control-flow contribution is preserved; the harmful capability is not.

**Amendment (M5, 2026-09-13): built as `mitigation.cases.case3_simulated_payment`, and the
inertness is a test, not a comment.** `mitigation.policy.evaluate()` computes `RW_amt <
DT-SYS_i-amt` (the boundary at equality resolves to `would_pay=False`, deliberately — see that
module's docstring) into a `PolicyDecision`; `case3_simulated_payment` writes exactly one audit
log record via `util.logging.event` and calls `mitigation.state.Remediating.block()`, which returns
`PolicyBlocked` unconditionally. There is no state in `mitigation.state` representing a completed
or attempted payment — `would_pay=True` and `would_pay=False` produce the same outcome *type*,
differing only in the recorded decision. `tests/unit/test_case3_is_inert.py` enforces this three
ways: an AST scan of every module in `mitigation/` for network/subprocess/socket imports and
calls (mirroring `test_honeypot_is_inert.py`), a handler-based check that calling the function
produces exactly one log record and nothing else, and a check that both sides of the policy
boundary produce `PolicyBlocked`.

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

**Amendment (M7-1, 2026-09-18): done. Verified our own protocol (DEV-02), not the paper's — the
paper has none to check.** Scyther v1.3.0 (native macOS arm64 binary from the tool author's own
GitHub release; full provenance and sha256 in `verification/README.md`) models both roles of
`crypto.session` under a Dolev-Yao adversary. Five claims mapped from §V-1: secrecy of `SK`,
mutual non-injective agreement (both directions), per-session key freshness, impersonation
resistance, and no reflection. **All verify clean, at both bounded (`--max-runs=5`) and unbounded
search** — `verification/results/bsfr_session.txt`. No new attack was found in the shipped
protocol; that is itself the result, not a null outcome.

The verification is discriminating, not vacuous: pointed instead at the original pre-M1 sketch
(`ID_B` missing from `A`'s signature — the flaw M1's amendment (a) describes), the identical tool
and claims find a real attack — `Niagree`/`Nisynch` fail on both roles
(`verification/results/bsfr_session_pre_m1.txt`, trace in `bsfr_session_pre_m1_attack.dot`). The
mechanism the tool found is a splice/redirect via an unbound recipient, not the literal
"replay-to-a-different-server" scenario the M1 prose describes — a related but distinct route to
the same class of failure, which is a stronger confirmation that the fix was needed than
reproducing the exact originally-imagined attack would have been.

**What this does not cover, stated rather than assumed away:** the M1 fix (b) — the nonce
cache — is a stateful, per-peer replay defense with no representation in Scyther's symbolic,
per-session model; it is exercised by `tests/unit/test_session_replay.py` instead, not by this
verification. Timestamps are modelled as opaque values (no wall-clock semantics). DH shares use
Scyther's standard `@oracle` idiom for Diffie-Hellman (Scyther has no native equational theory for
`g^(ab) = g^(ba)`, unlike Tamarin/ProVerif) — reused from, and validated against, the construction
Scyther's own author ships for the Station-to-Station protocol in this same release, not invented
here. Full methodology, the §V-1 mapping table, and all raw tool output: `verification/README.md`.
**No code change was needed** — `crypto/session.py` and `docs/ARCHITECTURE.md`'s protocol
description are unchanged by this session.

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

**Amendment (M6a, 2026-09-17): Q2 closed — the sweep ran, the default is kept, the ceiling is
projected rather than found by OOMing a box.** `scripts/run_bench.py` ran case-3 at all three
declared sizes (1024/4096/16384 B) on both chains before touching anything larger
(`bench.harness.projected_chain_bytes`, `estimate_overhead_factor`) — `RESULTS.md`
`bench/q2-payload-sweep`, run `20260917T144843Z-fb4c2410`:

```
BC_DTBU  case-3: 1024B=0.440s  4096B=0.498s  16384B=0.680s
BC_SigRW case-3: 1024B=0.605s  4096B=0.723s  16384B=1.329s
```

Payload size visibly matters more for `BC_SigRW` than `BC_DTBU` (16x payload costs ~1.55x time on
`BC_DTBU`, ~2.20x on `BC_SigRW`) — consistent with `SignatureRecordPayload` representing its
payload as many individual small floats rather than one raw bytes blob, so a bigger payload means
more canonical-encoder call overhead, not just more bytes.

**The memory ceiling is worse than a naive `payload x 100 x 15` projection suggests.** A `Cluster`
holds `consensus.miner_nodes` (4) independent `Chain` instances, each storing every block in full
(CLAUDE.md §4's per-replica independence, extended: the same "no shared state" design that keeps
`BC_DTBU` and `BC_SigRW` apart also means one cluster never shares block storage across its own
replicas). Measured ciphertext/AEAD-tag/wrapped-key overhead is ~10-15% over the raw plaintext
budget (`estimate_overhead_factor`, both chains). Projected footprint for a hypothetical 10 MB
payload at case-3 scale: `10 MiB * 100 tx * 15 blocks * 4 replicas * ~1.14 overhead ≈ 67 GiB` —
over 8x the naive single-chain estimate of ~15 GB, and decisively over an 8 GB dev box. **Not
run.** The declared default (`transaction.payload_bytes: 4096`) is kept: it sits well inside the
safe, measured range and the sweep shows the trend it produces is not an artifact of that
specific value.

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

**Amendment (M6a, 2026-09-17): the exact formula, and it is verified, not assumed.** One
committed block costs **4** message hops on the bus's simulated clock, not the ~3 the original
entry approximated: 1 for the client's `ClientRequest` broadcast reaching the replicas, plus 3
inside pBFT itself (pre-prepare, prepare, commit). `bench.harness.modelled_network_seconds()`
computes `blocks * 4 * delay_s` total, `blocks * 3 * delay_s` "inside consensus" in
`configs/bench.yaml`'s sense. `bench.harness.verify_modelled_network_formula()` runs a real small
cluster at several non-zero delays and reads `Cluster.network.now` after the last commit — the
formula matched to floating-point exactness at every delay and block count tried (1ms/10ms/50ms
x 5/15 blocks, and again at run `20260917T144843Z-fb4c2410`: predicted 0.200s, actual 0.200s at
delay=10ms, blocks=5). `bench/emit.py`'s Fig. 6(e) applies this at a declared illustrative delay
(`configs/bench.yaml` `network.modelled_delay_s`, 10ms — one same-datacenter LAN hop) and finds
the modelled network column **larger than the entire measured compute column** for case-3 on
both chains at that delay — a concrete reason the delay=0 default (chosen for test speed, not
realism) is not a free simplification for anyone reading Figs. 6(a)-(d) as a deployment estimate.

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

### DEV-28 · FILL · `NProf`/`AProf` as fitted profiles, and the Phase 4 handoff (Alg. 3, M4b)
**Paper:** Alg. 3 line 3 says `DM_CSl` builds `NProf` and `AProf`, "definitions of normal and
abnormal files... via the four algorithms," and line 4 "detects" through them. Neither term is
defined, and collapsing them into "whatever the classifier predicts" would make line 3
indistinguishable from line 2 — the profiles would exist in name only.

**Ours:** a profile (`detection.profiles.NormalProfile`/`AbnormalProfile`) is the fitted
class-conditional description of `DM_CSl`'s own soft-vote score on one class's training rows: its
mean, its spread, and that class's mean feature vector. `detection.detector.DetectionModule`
decides by nearest-profile membership — a fitted z-score against each profile's score
distribution — rather than reading a raw `estimator.predict()`. This is what makes lines 2
(train the four algorithms), 3 (build the profiles from their output) and 4 (detect through the
profiles) one connected mechanism instead of three steps where the middle one is decorative.
Alternative designs existed (e.g. two independent per-feature Gaussians fitted with no reference
to the trained models at all); this one was chosen specifically so "built via the four
algorithms" is literally true of the code, not just of the docstring.

**Phase 4 does not exist yet (M5), so line 5's "call Algorithm 4" has nothing to call.** Ours:
`detection.detector.Phase4Handoff`, a `Callable[[Detection], None]` `DetectionModule.decide()`
invokes on every positive. Phase 3 raises the event; it never imports `mitigation` and does not
need to change when that module lands. Line 4's "start detection" is a loop
(`DetectionModule.run()`), and a positive never stops it — lines 7-9 re-loop regardless of the
verdict, so a hit does not end monitoring.

**Impact on reproduction:** none — the paper reports no numbers for this half of Phase 3 at all
(FLAW-2). `RESULTS.md`'s M4b entry (balanced accuracy 0.8422, seed 20260912) is the first number
this project has produced from it.

### DEV-29 · FILL · Case selection and detection-to-system attribution in Phase 4 (M5)
**Paper:** Alg. 4 presents Case-1/2/3 as three alternatives for remediating `InfSYS_i` (lines 5-7)
and never says which one applies to a given detection, or on what basis a real deployment would
choose. Separately, Alg. 3's detection runs over honeypot signatures and features (`Sig_RW`,
`FT_RW`) — properties of a *sample* — while Alg. 4 remediates a *system*, `SYS_i`. Fig. 3's own
sequence diagram draws the arrow straight from "detect" to "mitigate" with no step in between that
names which system is affected.

**Problem:** silently picking a rule for either question — e.g. "use Case-2 whenever a backup
exists," or "the detecting honeypot's collector's most-recently-active system" — would be exactly
the kind of invented behaviour CLAUDE.md §2's "never silently fix the paper" is about, except
applied to a gap instead of a bug. Both are real operational questions a deployment would have to
answer, and the paper gives no basis for answering either.

**Ours:** `framework.phase4_mitigation.run()` takes both as explicit arguments from its caller:
`case: MitigationCase` (which of Case-1/2/3 to run) and `system_id: str` (which system the
detection concerns). Nothing in `framework/`, `mitigation/` or `detection/` infers either — a
test harness, a script, or eventually an operator supplies them, the same way `framework
.phase5_recovery.run()` already takes an explicit `system: System` rather than guessing one from
the chain. `tests/integration/test_full_sequence.py` makes this explicit at its call site: the
system a detection is attributed to is the same one Phase 1 backed up, by construction of the
test, not by anything Phase 3 or Phase 4 derives.
**Impact on reproduction:** none — Alg. 4 is not benchmarked (M6's Figs. 6a-d are Algs. 1/2/5 and
consensus timing only).

### DEV-30 · ADD · D3's magnitude — the wire-serialization cost the bus never pays, quantified (M6a)
**Paper:** §VII benchmarks a pBFT-based system without discussing message encoding at all —
absent from the paper the way the bus's own encoding is absent from this project (D3, carried
debt since M2b).

**Problem:** `consensus.network.P2PCSNetwork` passes Python objects between replicas and never
serialises them (that module's own docstring: "the bus also does not serialise"). A real
networked deployment would encode every `Proposal`/`Prepare`/`Commit` message before sending it
and decode it on arrival. That cost is entirely absent from Figs. 6(a)-(d)'s numbers. Carrying
this only as an unquantified caveat ("our numbers omit wire encoding") invites exactly the wrong
reading — that it is negligible, or that it is unknown in size. Neither was true and neither
should be assumed without measuring it.

**Ours:** `bench.harness.estimate_block_encode_seconds()` times `util.serialization.encode_block()`
on a real, already-committed block — the one place in this codebase CLAUDE.md §7 permits
canonical encoding to happen — and `estimate_d3_seconds()` multiplies by the block count,
modelling one encode per committed block (the primary's `Proposal` broadcast to `2f` backups,
encoded once and reused for every recipient; `Prepare`/`Commit` carry a 32-byte digest each and
are negligible against a multi-KB block). This is a **lower bound**, stated as such in the
function's own docstring: it excludes decode cost on the receiving side and the small vote
messages entirely.

**Measured magnitude (`RESULTS.md` `bench/d3-serialization`, run `20260917T144843Z-fb4c2410`,
case-3, 15 blocks x 100 tx x 4096 B payload):** `BC_DTBU` ≈1.6ms total (~0.33% of that case's
measured compute total), `BC_SigRW` ≈1.1ms (~0.16%). **Small relative to compute at delay=0, and
this is itself informative** — it says the omission is not what is making Figs. 6(a)-(d) diverge
from the paper by two-to-three orders of magnitude; DEV-13's language/runtime/hardware gap
dwarfs it. It stays a real, permanent omission from every number this project reports, now with a
stated size rather than an open-ended caveat, and it would matter far more at a non-zero
`message_delay_s` where decode cost on 3 recipients rather than 1 encode would start to be a
non-trivial fraction of the modelled network column (DEV-21).

**Impact on reproduction:** none on the trend/ratio target (DEV-13) — the magnitude is small
enough not to change the shape conclusion. Recorded so "the bus doesn't serialise" stops being an
asterisk with no number attached to it.

### DEV-31 · ADD · `honest_mode`'s memory ceiling is a parameter, not a constant, and KNN degrades instead of vanishing (M6b)
**Problem:** `detection.models.fits_in_memory()` (M4a) hard-coded an 8 GB ceiling — the dev box.
Called unparameterised, the same code run on a machine with more memory would still defer KNN,
because the check never knew it was somewhere else. `make honest`'s own local, full-scale run
(2,916,697 rows) confirmed this is not hypothetical: KNN's projected peak (17.94 GB) exceeds the
dev box's ceiling by design, so a caller that cannot say "this machine has more" is stuck
re-deferring on every machine, including ones the deferral does not need to apply to.

**Ours:** `--memory-ceiling-gb`/`--memory-headroom` on `scripts/run_detection.py`, threaded into
`fits_in_memory()`, default unchanged (8.0 GB / 0.6 — `make honest`'s behaviour is identical to
before). When the ceiling does not clear the projection, `detection.models.largest_feasible_n()`
(new) binary-searches `knn_projection`'s own monotone peak for the largest row count that fits,
and KNN runs on a stratified subsample of exactly that size — named as `subsampled_for_memory`
with the ceiling and the full-scale row count recorded, rather than the model disappearing from
the table. `make honest`'s own run demonstrates the fallback for real: at the 8 GB dev-box
ceiling, KNN ran on a 780,336-row stratified subsample (26.8% of the full data) instead of being
skipped — `RESULTS.md`, `results/tables/table2_honest_mode.csv`.

**Ada's real limits, discovered rather than assumed.** `scripts/ada_honest_mode.sbatch` (M4a)
carried a placeholder `--mem=64G --cpus-per-task=16` and a comment saying Ada access did not
exist from this environment. Both were wrong by the time M6b ran: `ssh ada` connects, and the
account's actual limits are `sacctmgr show qos low`'s `MaxTRESPU: cpu=10, mem=32000M` and the
`u22` partition's (the only one `AllowAccounts` permits for this account) `MaxMemPerCPU=3000` —
together capping any one job at 10 cpus / 30000M (≈29.3 GiB) regardless of what is asked for.
`--mem-per-cpu=3000 --cpus-per-task=10` requests exactly that ceiling; passed through as
`--memory-ceiling-gb 29.3 --memory-headroom 0.65`,
`largest_feasible_n(8, 5, ceiling_gb=29.3, headroom=0.65)` returns a feasible n **larger than the
full dataset** — verified in `tests/unit/test_detection_models.py` — so the Ada run was projected
to cover every row, not a further subsample, and it did: job 2700090 completed with
`deferred: {}` and all four models at 2,916,697 rows (`RESULTS.md`).

**The working directory took a second correction.** The first attempt used `/share1/<user>` (25
GB quota, nearly empty, looked like the obvious choice next to a ~3.5 GB-free home). Two small
test jobs (`envtest`/`envtest2`, this session) showed `/share1` is **login-node-only** — a compute
node's `df -h` never lists it, and a job that writes there fails at output-file-open time with no
script output produced at all. `/home2` (home) *is* NFS-mounted on compute nodes; compute nodes
also have node-local `/scratch` (1.8 TB, no per-user quota). The working sbatch therefore keeps
only a small, code-only checkout under `/home2`, and has the job itself copy that into
`/scratch/$SLURM_JOB_ID`, build the venv, and fetch the dataset there — never touching `/share1`.

**Bulk transfer is slow everywhere on this account, not just the login node — a second correction
to a first reading.** An early probe (`curl` to `pypi.org`'s index page, `envtest4`) completed in
0.1s from a compute node against a login-node request that timed out at 15s, and was read as
"compute nodes have fast internet, fetch the dataset there." That did not generalise: `pip
install`'s real package downloads on the *same* compute node, in the first real submission (job
2700027), ran at the same ~30-75 KB/s the dev-box-to-Ada rsync and the login-node `curl` both
showed — a small-page latency probe is not a bulk-bandwidth measurement. That job died 1h25m in
on the dataset download itself (`http.client.IncompleteRead`, ~55 KB into a ~50 MB archive) —
`scripts/fetch_bitcoinheist.py`'s single-shot `urlopen` had no retry, and at this sustained
transfer rate over a multi-minute download a drop is an expected event, not a rare one. Fixed
generically in the fetch script (`_download_with_retry`: `Range`-header resume, 8 attempts, so a
late drop costs seconds not the whole file) rather than only in the sbatch, so `make data` gets
the same robustness locally. The sbatch additionally persists the built venv to
`$HOME_CHECKOUT/.venv-ada-persist` (NFS-shared, survives the job) so a retry after any *later*
transient failure does not also repeat the ~1 hour `pip install`. Resubmitted as job 2700090;
fetching the dataset inside the job (rather than rsyncing it in) is still the right design, but
because a resumable in-job fetch survives a slow, drop-prone connection better than an external
transfer where a drop has no cheap resume — not because compute nodes have faster egress, which
they do not.

**Impact on reproduction:** none on Target 1/2's accuracy/F1 headline — this is entirely about
`honest_mode`, which the paper does not report at all (DEV-06). It does mean two honest_mode
results exist in `RESULTS.md`, both correctly labelled: the local, 8 GB-box run (KNN on a
780,336-row subsample, other three models at full scale, DEV-31's fallback demonstrated for
real) kept for provenance, and the Ada run (all four models at the true 2,916,697 rows, job
2700090) that `results/tables/table2_honest_mode.csv` now carries. KNN's full-scale MCC (0.365)
is meaningfully higher than its subsampled MCC (0.300) — more data helps KNN too, which the
paper's own evaluation methodology never had the chance to show either way.
