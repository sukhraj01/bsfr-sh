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

**Amendment (M7-6, 2026-09-25) — three more hypotheses tested; the bound tightens from 3.58 to
1.51 points, still not closed.** Q10 tested two leakage candidates out of at least five testable
ones and left the report calling the gap "unexplained." `scripts/m7_6_gap_closure.py` and
`src/bsfr_sh/detection/gap_closure.py` test the remaining three — decision-tree splitting
criterion (H1), resample strategy (H2), single-split variance vs. cross-validation (H3), plus
year/day feature engineering (H4) and a programmatically-assembled stacked worst case (H5). Full
table and per-cell numbers: `RESULTS.md` "M7-6 — closing the Q10 gap".

- **H1 (splitting criterion) does not explain the gap.** Entropy beats gini by ~0.4pt; explicit
  `max_depth=None` etc. is bit-identical to scikit-learn's own default (asserted, not assumed) —
  best DT cell 0.9301, 5.97pt short.
- **H2 (resample strategy) is the session's real finding.** Bootstrap-duplicating the 41,413 real
  ransomware rows to 180,000 (oversampled, ~4.35x average duplication) and undersampling benign to
  20,000, under a *random* split, reaches 0.9690-0.9723 — closer than anything Q10 found. Under a
  *grouped* split the same strategy scores 0.8746-0.9363, **worse** than the existing baseline: a
  5-10 point swing between splits, several times larger than Q10's largest leakage signature
  (+0.92pt). Mechanism: duplicated rows carry the same address, so a random (non-grouped) split
  routinely places literal duplicates of a training row into the test set; the model recognises
  them rather than generalising to them. This is oversampling-under-non-grouped-split leakage, a
  mechanism distinct from Q10's two candidates, and a materially larger effect than either.
  Undersampling (all positives, benign sized to 10% of the *positive* count rather than of the
  resample total) scores close to the existing `paper_mode` baseline in both splits — a small
  arithmetic variant of what Q10 already covered, not a new mechanism.
- **H3 is closed: neither explains the gap.** 20 seeds (20260912-20260931) on the production
  protocol give random forest an envelope of 0.9288-0.9469 (std 0.0050); on Q10's own best cell
  the envelope is even tighter (std 0.0011, max 0.9572, still 3.26pt short) — the measured numbers
  are highly reproducible, not a lucky draw. 5-fold group-stratified CV agrees with the
  single-split figure closely (RF: 0.9421 CV mean vs. 0.9442 single-split).
- **H4 rules out year-as-leakage.** Dropping `year` *costs* ~3 accuracy points — the opposite of
  what a temporal-leakage hypothesis predicts, so `year` is informative, not a leak. Cyclical
  `day` is flat against raw; a `year x day` interaction gives the best H4 cell, +0.5-2pt over raw.
- **H5 (stacked worst case), winners chosen programmatically:** entropy criterion (H1's winner,
  0.9301), oversample resample (H2's winner, 0.9723), `year x day` interaction (H4's winner,
  0.9498), address kept, random split. Reaches **0.9747/0.9861 — 1.51 accuracy points and 1.29 F1
  points short of published**, not zero. One ingredient dominates: H2's `oversample x
  decision_tree x random` cell alone (0.9723) accounts for nearly all of H5's improvement over
  Q10's 0.9540; the other four stacked choices contribute a further ~0.2-0.3pt combined. If the
  published figure is explained by methodology at all, the evidence now points specifically at an
  oversampled, non-grouped-split evaluation — not a diffuse combination of many small effects.

**Q10 is closed with a tightened, evidenced bound, not a proof.** No configuration tested across
either session — including H5's fully stacked worst case — reaches 0.9898/0.990. The gap narrows
from "3.58 points, unexplained, two hypotheses tested" to "**1.51 points, unexplained after eight
hypotheses tested, with oversample-strategy leakage under a non-grouped split identified as the
largest single contributor found**." The residual is reported with that qualifier, not as a bare
"unexplained," and not attributed to a cause beyond what was actually measured (CLAUDE.md §2).

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

**Amendment (2026-09-22): reconfirmed under the honest, serialization-ON condition — survives
unchanged.** D3's closure (DEV-30) found consensus message serialization adds +48-68% at case-3;
before presenting any M6a number again, the full three-case, both-chain matrix was re-run with
`configs/bench.yaml`'s now-current `network.serialize_messages: true`
(`RESULTS.md` `bench/target3-time-serialized`, run `20260922T172916Z-22992372`). Marginal per-block
cost stays flat under serialization too: `BC_DTBU` 0.0541-0.0543 s/block, `BC_SigRW`
0.0678-0.0688 s/block, case-1 through case-3 — each chain's own cost varies by under 1% across
cases, same as the serialization-OFF reading, just uniformly ~60-65%/~50% higher. TPS is
correspondingly flat-but-lower (`BC_DTBU` ~1832-1848 tx/s, `BC_SigRW` ~1438-1476 tx/s) rather than
rising. Serialization is a per-message cost, not a per-block-count-dependent one, so it does not
reintroduce the fixed-cost-amortisation shape this entry already ruled out — the flat-marginal-cost
finding is condition-independent, not an artefact of measuring with serialization off.

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

**Amendment (M7-18, 2026-09-28): the safety claim above is now confirmed by exhaustive model
checking, and the liveness cost of (2) is confirmed formally, though not yet by a completed TLC
run.** `verification/pbft.tla` models the reduced protocol above (view-change with prepared-
certificate carry-over, `PrevCommitted`'s guard for omission (2)) and TLC exhaustively checked
Agreement/Validity/Integrity at the design fault bound (`F=1`, one of four replicas byzantine):
**no violation over the full reachable state space at `MaxView=1, MaxSeq=1`** — 74,970,368 states,
depth 33, 1h08min (`verification/pbft_results.md`). Two draft versions of the view-change safety
guard were themselves shown unsound by TLC, at this same bound, before a third verified clean —
both were spec bugs in this session's TLA+ model, not protocol bugs; kept as documented dead ends
in `pbft.tla` rather than silently fixed.

Omission (2)'s liveness cost — "a lagging honest replica plus one byzantine replica stalls the
chain" — was expected to have a sharper formal statement than the prose above gives: at `F=1,
n=4`, the commit quorum size (`2f+1=3`) equals the honest-replica count exactly, so at this
specific configuration any progress at all requires every honest replica to commit, not merely a
quorum of them — a Byzantine equivocation combined with (2)'s missing state transfer looked like it
should be a complete-halt risk, not a minor liveness degradation, whenever it triggers. **The TLC
run built to check this — `Termination` under `F=1`, moved to the Ada cluster after not finishing
locally (1h42min, 16.4M states, low-memory warning) — completed in 16h49min, 149,940,224 states,
and found `Termination` HOLDS. The expected violation does not occur at this bound, and the reason
is itself worth recording: `DoCommit`'s state-transfer guard (`PrevCommitted`) is checking whether
seq `s-1` committed before allowing seq `s` — and at `MaxSeq=1`, the bound this project's hardware
could exhaust, there is no seq 2 for a replica to be stranded short of. The guard is vacuously
satisfied for the only sequence number that exists, so omission (2)'s cost has no path to manifest
as a liveness failure at this bound, regardless of Byzantine behaviour.** The defect is not
fictional — `test_pbft_byzantine.py::test_equivocation_with_honest_votes_strands_one_honest_replica`
constructs it concretely, on a real multi-height run — but formally reproducing it would need
`MaxSeq>=2`, and this project's own measured state-space growth (the `F=2` FLAW-5 run alone: 1.5
billion states at `MaxSeq=1`) makes that look impractical to exhaust on hardware available here.
Reported as a bound limitation on this verification, not as evidence the omission is costless. The
fault-free control (`F=0`) also verifies `Termination` exhaustively (1,240,200 states, 3min),
confirming the fault-free case was never in doubt and the `F=1` result above is a genuine finding
about the Byzantine/bound interaction, not a modelling artifact. FLAW-5
(`docs/PAPER_NOTES.md` §V-3) is confirmed twice over: first by TLC constructing the `F=2` fork via
simulation (1s), then independently by an exhaustive, standard breadth-first search on Ada reaching
the identical fork (1,501,898,636 states, 15h56min, job 2720269) — the local exhaustive attempt
that exhausted 24GB of disk at 4h19min/281M states was what was resubmitted, and this time it ran
to a found violation rather than to disk exhaustion. Full mapping
table, both configs' raw output, and stated limitations: `verification/pbft_results.md`.

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

**Amendment (M7-3, 2026-09-22): the two carriers are not bit-identical, and that is now measured,
not assumed.** `write_corpus` formats every feature at six significant figures
(`f"{value:.6g}"`); `BC_SigRW`'s `SignatureRecordPayload` carries full float64 precision. Fitting
the same seed/config on the committed CSVs and scoring through the same `DetectionModule` ensemble
gives **bal_acc=0.8408**, not `RESULTS.md`'s chain-path M4b entry of 0.8422 (delta 0.0014) —
discovered when M7-3's exit test ("0% perturbation reproduces 0.8422 exactly") failed and was
traced, not silently absorbed. Neither number is wrong; they are the same generator draw read at
two different precisions, and this session's baseline is 0.8408 throughout. Any future experiment
that must match 0.8422 bit-for-bit needs the chain path (`run_phase3_detection.py`), not the
committed CSVs; (b)'s "committed corpus is the fixed dataset" still holds for everything that does
not require matching that one specific figure.

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

**Amendment (2026-09-19, debt D3 closed) — measured, and an order of magnitude larger than the
estimate above.** `consensus.network.P2PCSNetwork` gained a `serialize=` hook: an opaque
`object -> object` callable applied in `send()` before scheduling delivery, so the bus itself
still imports nothing internal (`test_module_boundaries.py`'s
`consensus/network.py imports nothing internal` check). `consensus.pbft.Cluster` supplies
`consensus.protocol.encode_message` composed with `decode_message` as that hook when
`PBFTPolicy.serialize_messages` is set — `configs/chain.yaml`'s own default is off (`make test`
stays fast and unserialised), `configs/bench.yaml` declares it on for every bench run. Every one
of the six message shapes (`ClientRequest`, `Proposal`, `Prepare`, `Commit`, `ViewChange`,
`NewView`) round-trips through plain `util.serialization.encode`/`decode` mappings — not a
declared `Struct` domain, since nothing here is hashed or signed — and reconstructs a fresh,
independently `__post_init__`-validated object (`tests/unit/test_protocol.py`).

Case-3, both chains, n=25, identical seeds, serialize on vs. off (`RESULTS.md`
`bench/d3-measured`, run `20260919T013422Z-1cf934ad`): **BC_DTBU +67.6%, BC_SigRW +48.8%** —
nothing like the ~0.33%/~0.16% the encode-only estimate above reported. The estimate priced one
`encode_block()` per committed block; the real bus pays a full encode+decode on *every* `send()`
call, and one committed block at `n=4` is 28 such calls
(`test_pbft.py::test_message_count_per_block_is_the_textbook_pbft_count`: 4 requests + 3
pre-prepares + 3×3 prepares + 4×3 commits), not one. The estimate's own docstring called itself a
lower bound "excluding decode cost on the receiving side and the small vote messages entirely" —
true as far as it went, but "small relative to compute" was the wrong reading of what excluding
27 of 28 hops' cost would do to the total.

**Impact on reproduction:** still none on DEV-13's trend/ratio target — a 50-70% addition to
Figs. 6(a)-(d)'s already-microsecond-scale numbers does not change the shape conclusion (monotone
increase, `BC_SigRW` slower than `BC_DTBU`), and `configs/chain.yaml`'s test-path default stays
`serialize_messages: false` so no existing measured number in `RESULTS.md` is invalidated by this
— only bench runs from now on pay it, and only when they choose to. `docs/report/report.tex` was
checked and never stated the earlier 0.2-0.3% figure, so there is no report number to correct.

**Amendment (2026-09-22): full matrix confirms the magnitude, and finds a second effect the
case-3-only measurement above could not see.** The closure amendment above measured one case
(case-3, n=25). This session re-ran all three cases, both chains, at the now-current
`configs/bench.yaml` default (`RESULTS.md` `bench/target3-time-serialized`, run
`20260922T172916Z-22992372`, n=5 — a different repeat count than the case-3 closure run, decided
from a quieter variance reading; same adaptive logic, see that RESULTS.md section). **Magnitude
confirmed across all three cases**, not just case-3: `BC_DTBU` +60.85%/+59.34%/+70.96%, `BC_SigRW`
+49.40%/+47.59%/+50.83% (cases 1/2/3) — consistent with, and this run's own case-3 reading close
to, the closure's +67.6%/+48.8%.

**New finding this full matrix surfaces that the case-3-only measurement could not: the
`BC_SigRW`/`BC_DTBU` gap narrows under serialization, from the serialization-OFF 35-45%
(`docs/EXPERIMENTS.md` Target 3) to ~25-27%.** Both chains' D3 encode-only cost is nearly identical
in absolute terms (`BC_DTBU` 0.000072s/block, `BC_SigRW` 0.000073s/block at case-3 — see this
run's own `d3` sidecar section), so the real bus's fuller encode+decode-per-`send()` cost is
plausibly close to chain-independent in absolute seconds too. Because that roughly-fixed tax is
added to `BC_DTBU`'s smaller base, it inflates `BC_DTBU`'s own time by a larger *percentage*
(≈60-71%) than it inflates the *gap* between the chains, which is why the gap narrows in relative
terms even though it does not narrow (and slightly grows) in absolute seconds. This does not
overturn the structural ECDSA/payload-encoding attribution for the gap — that attribution was
always specifically about the serialization-OFF condition, and the serialization-OFF 35-45% number
is unchanged — but it means "the `BC_SigRW`/`BC_DTBU` gap" is no longer a single number once both
conditions are on record, and any future citation of it must say which condition it is under.
`docs/EXPERIMENTS.md` Target 3 amended with this finding alongside the existing 35-45% one.

**Impact on reproduction:** still none on the trend/ratio target (DEV-13) — monotone increase and
`BC_SigRW` > `BC_DTBU` both hold under either condition; only the size of the `BC_SigRW`/`BC_DTBU`
gap is condition-dependent, and that gap was never itself a claim the paper's own Target 3
properties list makes (§EXPERIMENTS.md's three reproduced/not-reproduced properties are monotone
increase, sub-linearity, and the qualitative "SigRW slower than DTBU" — not a specific percentage).

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

### DEV-32 · ADD+FILL · Raft as a comparison consensus protocol, and the `ConsensusCluster` abstraction
**Paper:** §VII names pBFT with no justification for choosing it over any alternative, and §V-3's
own defence of that choice is FLAW-5 — a borrowed 51% threshold applied to a protocol whose real
safety bound is a third. The paper never asks whether its own deployment (four cloud servers the
operator controls) actually needs Byzantine fault tolerance, or whether a crash-fault-tolerant
protocol gives the same availability more cheaply.

**Ours (M7-4):** `consensus/raft.py` implements a simplified Raft (Ongaro & Ousterhout) over the
same four-node cluster, message bus (`consensus.network.P2PCSNetwork`, unchanged) and
`ClientRequest` submitter-authentication path (`consensus.protocol.check_request_identity`,
unchanged) as pBFT — differing only in the consensus protocol, which is what makes the M7-4
comparison a controlled one rather than two unrelated benchmarks. `framework._block_pipeline` was
made consensus-agnostic via `consensus.interface.ConsensusCluster`, a `Protocol` both
`pbft.Cluster` and `raft.RaftCluster` satisfy structurally; production phases
(`phase1_backup`, `phase2_collection`) are untouched and still wired to pBFT only, since the paper
mandates it there. `docs/report/report.tex` §"Consensus Comparison: pBFT vs.\ Raft" and
`RESULTS.md` M7-4 carry the full write-up and numbers; this entry records the design decisions and
scope reductions.

**Scope reductions, and why they don't matter for this comparison** (the same discipline DEV-20
already established for pBFT's own view-change reduction):
- **No log compaction, membership changes, or snapshotting.** Cases 1-3 commit at most 15 entries;
  nothing here ever needs to discard log history or reconfigure a running cluster.
- **One log entry in flight at a time**, mirroring pBFT's own one-height-in-flight rule (DEV-20
  item 3) — the fairest basis for comparison is giving both protocols the same discipline
  everywhere except the thing being compared. This also removes most of real Raft's
  `nextIndex`-backtracking complexity: with one entry ever in flight, the previous entry is either
  already committed everywhere or not yet sent.
- **No retransmission** — the same reduction pBFT already accepted (DEV-20 item 6). A dropped
  message is never resent; a heartbeat resend or an election timeout is the only recovery.
- **No signatures in the Raft consensus path**, by design rather than omission —
  `RequestVote`/`AppendEntries` carry no ECDSA signature at all, unlike pBFT's `VOTE_FIELDS`
  (DEV-19). This is not a missing feature; it is the mechanism the whole comparison exists to
  measure (`consensus.pbft.Cluster.signature_ops` vs. `consensus.raft.RaftCluster.signature_ops`,
  always zero for the latter).

**The client-trust asymmetry is a finding, not an oversight.** `ConsensusCluster` requires a
`client_confirmation_threshold()`: pBFT's is `f+1` (at least one of that many replicas is honest —
the same reasoning as `Membership.join_quorum`), because any single pBFT replica might be lying.
Raft's is `1`: a non-byzantine Raft replica only ever reflects an entry the leader already
confirmed via a real majority (`RaftCluster.commit_index` only advances past `RaftPolicy.majority`
acks), so re-deriving that majority client-side would just repeat a check the protocol already
made. This is exactly the trust model the Byzantine-leader finding below breaks.

**Quantitative finding (measured, `RESULTS.md` M7-4, run `20260924T045952Z-2eaa456f`).** pBFT
sends a flat 28 messages/committed-block in every case (`O(n^2)` fan-out at fixed `n=4`); Raft
converges to ~16.8/block (`O(n)` fan-out plus a leader-driven commit-announcement round) — about
60% of pBFT's count at this small `n`, far short of the asymptotic gap a larger cluster would show.
Signature operations: pBFT's exactly equal its own message count (one ECDSA op per consensus
message); Raft's are exactly zero, every cell. **The wall-clock gap (7-11% faster for Raft) is far
smaller than the message-count gap (~40% fewer messages)** — consistent with DEV-08/DEV-21's
existing finding that consensus messaging is a small fraction of measured time at zero simulated
network delay: hybrid encryption and (serialization-on, DEV-30) message encoding dominate, so
cutting the message count produces a proportionally smaller speedup. The bottleneck this project's
own numbers already located is confirmed a second, independent way.

**Qualitative finding — the Byzantine leader (measured, same run;
`tests/unit/test_raft_byzantine.py` pins it as a standing regression test).** A byzantine Raft
leader sends genuinely different, honestly-signed transaction sets to different followers at one
log index, each claiming the entry already committed — standard-compliant `AppendEntries` on both
sides, no forged signature required. Every node "commits" by its own local rule: all four reach
the same height, but the two sides hold different, individually valid, individually well-linked
blocks. Neither side's own chain-integrity check (`Chain.verify_integrity`) catches this, because
both blocks are genuinely well-formed — the check that would catch it is cross-referencing what a
majority of *other* replicas independently attest to, which is exactly pBFT's `2f+1`
matching-vote quorum (DEV-10) and exactly what Raft's leader-trust model never does. Crash
tolerance is symmetric: 1-of-4 silently crashed, both protocols still commit on the remaining
three (same tolerated failure *count*, `f=1` vs. Raft's majority-of-4, different failure *model*).

**The trade-off, stated precisely, not left implicit.** Raft is faster and sends fewer messages,
but a single compromised leader corrupts the chain undetectably. Whether that trade-off is
acceptable depends on whether the deployment's threat model includes active server compromise —
exactly the question §V-3 never asks, because it substitutes a borrowed 51% figure for an actual
threat-model argument (FLAW-5). For BSFR-SH specifically, whose own §II threat model includes a
compromised or malicious cloud server, this is the paper's implicit justification for choosing
pBFT over the cheaper alternative — but it is a justification the paper never states, which is the
gap this session closes.

**Impact on reproduction:** none. No paper number is measured differently; this is a new
comparison the paper never makes, reported alongside the existing pBFT-only Target 3/4 numbers,
never merged into them.

### DEV-33 · ADD+FILL · Hybrid blockchain — a public anchor chain for external verifiability
**Paper:** §VIII: "in future, we have plan to work with hybrid blockchain," and stops there. No
design, no schema, no anchor frequency, nothing. §IV-A already states the trade-off this answers:
a private chain is fast and confidential, but its integrity rests entirely on trusting the
operators who run it — there is no way for anyone outside the four cloud servers to confirm
`BC_DTBU`/`BC_SigRW` have not been silently rewritten.

**Ours (M7-5):** `blockchain/anchor.py` defines `AnchorRecord` — one private block's height,
`current_hash` (`HC_βj`), `merkle_root` (`MTR`), a timestamp, and the anchor creator's ECDSA
signature over all of it. Never encrypted (`transaction.wrap_anchor_record`, a third, plaintext
transaction kind alongside the paper's two `E_KU_CSl(Tx)` payloads) — the whole point of a public
record is that it needs no key to read. `blockchain/hybrid.py`'s `HybridChain` schedules and
appends these onto its own anchor `Chain`, and answers three queries: `verify_anchor(chain,
height)` (does the private block at `height` still match its anchor?), `verify_range`, and
`verify_anchor_chain_integrity` (has the anchor chain's own storage been tampered with?).
`AnchorPolicy.frequency` is the cost/integrity lever: 1 anchors every private block, `N` anchors
every `N`-th (`N`x less anchor traffic, up to `N-1` blocks' unanchored tampering window) —
`RESULTS.md` M7-5 sweeps 1/5/10.

**The anchor chain's "own consensus" is sign-and-append, not a pBFT instance — a redesign, not the
first draft.** The first implementation modelled the anchor chain literally as a single-node
`consensus.pbft.Cluster` (`n=1, f=0, commit_threshold=1` — `consensus.protocol.Membership`
accepts this: `n >= 3f+1` is `1 >= 1`), reached through `framework._block_pipeline.commit` exactly
like the two private chains. It worked (`tests/unit/test_hybrid_chain.py`'s scheduling and
security tests all passed against it), but `tests/unit/test_module_boundaries.py::
test_nothing_below_framework_imports_it` correctly failed: reaching from `blockchain/hybrid.py`
into `framework._block_pipeline` pulls `blockchain` upward across the dependency direction
`docs/ARCHITECTURE.md` fixes (`util <- crypto <- blockchain <- consensus <- framework`), a
boundary every other module in this codebase holds absolutely. The fix is not a workaround around
the test — it is the correct design the test caught the absence of: a single signing authority has
no second replica to convince, so pBFT's pre-prepare/prepare/commit rounds would be pure overhead
with nothing underneath them. `HybridChain` now appends anchor blocks with one direct
`Chain.append()` call (the same primitive every chain write in this codebase already uses) and
imports nothing from `consensus` or `framework`. The quorum-agreement check a real multi-replica
private chain still needs stays where it already lived — `framework._block_pipeline.read_chain` —
and a new, thin `framework/hybrid_pipeline.py` is the only module that imports both layers,
calling the existing, unmodified pipeline first and `HybridChain.sync`/`flush` after.
`phase1_backup.py`/`phase2_collection.py` needed zero changes, which is the actual content of
"hybrid is transparent to the framework": there was nothing in either to change.

**The anchor chain is simulated, not real Ethereum or Bitcoin — stated, not hidden.** In
production the anchor chain is a real public blockchain with its own separate consensus, its own
latency, and a real gas cost per anchor; none of that is modelled here. `verify_anchor_chain_
integrity`'s own docstring states the assumption its guarantee rests on plainly: it catches
tampering of the anchor chain's *stored* blocks, exactly as `Chain.verify_integrity` does for any
chain, but it does not model an attacker who controls the anchor authority's signing key from the
start — in production, an operator who also controlled the real public chain's consensus would
defeat the entire hybrid design, not just this check. The paper's own threat model (§II) never
specifies who the external verifier actually is either (a regulator? a patient? a security
researcher auditing the deployment?) — this design makes verification possible for any of them,
without picking one, because `AnchorRecord` requires no relationship with the private chain's
operators to check.

**Impact on reproduction:** none. Hybrid mode is off by default (`configs/chain.yaml`
`hybrid.enabled: false`) and `blockchain.hybrid`/`framework.hybrid_pipeline` are additive modules
nothing else imports; every M0-M7-4 number is produced by the identical, unmodified private-chain
path. `tests/unit/test_hybrid_transparency.py` demonstrates this rather than asserting it: the
same backups recover byte-identical and the same `BC_SigRW` records commit byte-identical whether
or not a `HybridChain` observes the run afterward.

### DEV-34 · ADD · Real malware transfer evaluation: `FT_RW` mapped from ClaMP, and what does not map (M7-7)

**Paper:** n/a — the paper defines no honeypot dataset at all (GAP-3, DEV-03, DEV-27); this entry
is about testing our own `FT_RW` schema's real-world grounding, not the paper's design.

**Problem:** M4b's 0.8422 balanced accuracy (`RESULTS.md`, DEV-27) is the ensemble scored on
`honeypot.collector`'s own synthetic corpus — the same hands built the generator and the
classifier, so that number measures the generator-detector pair, not whether the detector would
recognise anything outside the distributions it was designed against.

**Dataset used, and why not the ones named in the session brief.** EMBER's actual feature dataset
is a ~2.4GB archive; this sandbox's measured throughput (1.28MB in 30.9s ≈ 40.6KB/s) projects a
~17-hour download for it, infeasible in one session. CIC-MalMem-2022/CICMalDroid-2020 are gated
behind UNB's research-access request process, not a direct scriptable download. **Used instead:
ClaMP** (github.com/urwithajit9/ClaMP, `data/external/clamp/README.md`) — 5210 real Windows PE
files' header-derived structural features, 2722 malicious / 2488 benign, openly published for ML
research, fetched once and committed (1.28MB, sha256 in the README) for full reproducibility.
Used for **evaluation only**: it never fits or tunes anything in `honeypot/` or `detection/`.

**The mapping is lopsided, and that is the finding.** `FT_RW` (`honeypot.features`) is a
*dynamic behavioural* schema — what a monitor observes a running program *do*. ClaMP is *static*
— header fields read off a file that is never executed. `honeypot.external_mapping.CLAMP_MAPPING`
maps all 22 features honestly against that mismatch:

| Group | Features | Mapped |
|---|---|---|
| entropy | `write_entropy_mean` <- `E_file` (direct-ish proxy); `write_entropy_var` <- population variance of `{E_text, E_data}`; `entropy_delta` <- `\|E_data - E_text\|` | **3/3** |
| filesystem, crypto_api, process, network, persistence, kill_chain | all 19 remaining features | **0/19** |

19 of 22 features (six of seven groups) have **no** analogue in a dataset that never ran the
sample — filesystem I/O, crypto API calls, process spawns, network beacons, persistence writes and
kill-chain progress are all execution-time observables. They are marked `MappingKind.MISSING` and
handled exactly as `honeypot.features.build()` already handles an unobserved sensor: value `0.0`,
`missing_mask` bit set — no new missing-data convention was invented for this. Considered and
rejected: using `NumberOfSections` as a proxy for `directory_breadth` (a PE section count is not a
directory count; forcing the analogy would hide the mismatch rather than report it).

**Transfer result — the ensemble does not merely degrade, it goes to chance and (slightly) past
it.** `scripts/m7_7_real_malware_transfer.py --seed 20260912` fits once on the committed synthetic
corpus (never retrains), first reproduces the established CSV-path baseline exactly
(`RESULTS.md` M7-3: 0.8408) as a sanity check that the mapping code has not corrupted anything,
then scores the same fitted ensemble on all 5210 mapped ClaMP rows:

```
bal_acc=0.5000  precision=0.0000  recall=0.0000  mcc=0.0000  pr_auc=0.4612
```

`bal_acc=0.5000` exactly is not a coincidence of rounding: the ensemble predicts **every** ClaMP
row — malicious and benign alike — as benign. With 19 of 22 input dimensions forced to `0.0`,
the resulting vector apparently sits, under the profiles fitted on the synthetic corpus, closer to
`NProf`'s mean score than `AProf`'s, for every real row tried. More strikingly, `pr_auc=0.4612` is
**below** the no-skill baseline for this dataset's class balance (2722/5210 = 0.5225): the
ensemble's continuous score is mildly *anti-correlated* with the true label on this mapped real
data, not merely uninformative. This is outcome (b) from the session brief — accuracy
significantly lower than the synthetic figure — and the mechanism is legible rather than
mysterious: with 86% of the feature space collapsed to a mapping artifact of zero, there is
essentially nothing left for the profiles to discriminate on beyond three entropy features, and
zero happens to read as "normal" under distributions fit on a corpus where the honest zero-fill
rate is much lower. **This is a finding about the schema's dynamic-vs-static mismatch with the
most tractable available real dataset, not evidence that the synthetic generator's own calibration
(DEV-27's 0.85 Bayes ceiling) is wrong** — no dataset that never executed a sample could ground
`FT_RW`'s other six feature groups, whatever the generator's distributions looked like.

**Distribution comparison, the 3 mapped features (two-sample Kolmogorov-Smirnov,
`honeypot.distribution_compare`):**

```
write_entropy_mean: D=0.1969 p=6.9e-53  (synthetic mean 5.63, real mean 6.36)
write_entropy_var:  D=0.4884 p<1e-300   (synthetic mean 0.59, real mean 3.52)
entropy_delta:      D=0.2854 p=1.7e-111 (synthetic mean 2.00, real mean 3.00)
```

All three diverge significantly. Read cautiously, not as "the generator is wrong": ClaMP's
entropy readings are whole-file and per-section entropy of arbitrary real PE files (many of them
large, compiled, resource-laden binaries with high baseline entropy regardless of malice), while
`write_entropy_mean`/`var`/`delta` are drawn to model entropy of *write operations during a
kill-chain episode*, tuned to DEV-27's 0.85 Bayes-ceiling difficulty budget for a specific
classification problem. These are different measurement modalities compared on the same numeric
scale because it is the closest real analogue available, not because they measure the same thing.
One further caveat: ~8-9% of the synthetic corpus's `write_entropy_mean` values are the
generator's own missing-value zero-fill (`missing_mask` bit set), which inflates the low end of
the synthetic histogram (visible in `fig8a_entropy_distributions.png`) and modestly affects, but
does not create, the measured KS divergence.

**Impact on reproduction:** none — this is a new evaluation, not a change to any paper target.
Figures: `results/figures/fig8a_entropy_distributions.png`,
`results/figures/fig8b_transfer_metrics.png`. Full numbers: `RESULTS.md` "M7-7", sidecar
`results/logs/20260925T041117Z-672f7572.json`. Tests: `tests/unit/test_honeypot_external_mapping.py`
(the mapping table, deterministic and total), `tests/unit/test_honeypot_distribution_compare.py`
(the KS wrapper).

### DEV-35 · ADD · EMBER mapping: a richer static dataset grounds 6/22 features vs. ClaMP's 3/22
### (M7-10a)

**Paper:** n/a — same as DEV-34, this is about testing `FT_RW`'s real-world grounding, not the
paper's design.

**Problem:** M7-7 (DEV-34) mapped ClaMP's fixed header floats onto `FT_RW` and found only the
entropy group (3/22 features) had any real correspondence — a dataset that never executes a
sample cannot ground the other six behavioural groups. The open question M7-7 could not answer
with ClaMP alone: does a *richer* static dataset close any of that gap, or is entropy-only
inherent to staticness itself, independent of how much raw data the source provides?

**Dataset.** EMBER2018 (feature version 2, `github.com/elastic/ember`,
`ember_dataset_2018_2.tar.bz2`) — raw LIEF-extracted features (not the pre-vectorized form) for
~1.1M real Windows PE files, fetched and extracted on Ada (`data/external/ember/README.md`: sha256
verified against the upstream repository's published checksum). Only `test_features.jsonl`
(200,000 fully-labelled rows) was extracted — the ~900K-row train split is never read, both
because M7-10a is evaluation-only (same posture as M7-7) and because it does not fit inside this
cluster account's storage allocation alongside the account's other projects.

**The mapping (`honeypot.ember_mapping`) grounds 6 of 22 features, double ClaMP's 3.** Verified
line-by-line against the actual `elastic/ember` `features.py` source before writing any mapping
code (not assumed from documentation) — `histogram` is confirmed a raw, un-normalised 256-bin
byte-value count; `section.sections[i]` confirmed to carry `entropy` and `props` (permission
flags) directly; `imports` confirmed `{dll_name: [function_names]}`.

| Group | Features | Mapped (proxy) | Missing |
|---|---|---|---|
| entropy | 3 | **3** | 0 |
| crypto_api | 3 | **2** | 1 |
| filesystem | 5 | **1** | 4 |
| process, network, persistence, kill_chain | 11 | 0 | 11 |
| **Total** | **22** | **6** | **16** |

Every mapped feature is a `PROXY`, never `DIRECT` — EMBER's raw data is richer than ClaMP's, but
it is still static, so nothing here claims to observe the real thing:
- `write_entropy_mean` — Shannon entropy computed directly from the whole-file 256-bin byte
  histogram (unambiguous; EMBER's alternative `byteentropy` 2D histogram was considered and
  rejected because its axis packing was not verified against source in this session, and a
  silently-transposed 256-value array would produce a wrong-but-plausible-looking number).
- `write_entropy_var` / `entropy_delta` — population variance / max-minus-min spread across
  *every* section EMBER reports (typically 4-8 per file) rather than ClaMP's fixed two-point
  `{E_text, E_data}` — a materially richer spread estimate of the same underlying quantity.
- `crypto_call_rate` / `key_generation_events` — keyword/exact-name matches against the full
  per-DLL import table; both are explicitly *counts standing in for rates/events*, since a static
  import table has no time axis and nothing guarantees an imported function is ever called.
- `read_write_ratio` — the brief's own suggestion: read-only vs. writable section counts from
  `props`. Flagged as the weakest of the six — a structural PE property, not observed I/O.
- `crypto_ngram_novelty` and `directory_breadth` remain `MISSING`: EMBER's imports carry no call
  *order* (an n-gram needs a sequence, not a set) and no section count is a directory count —
  both proxies considered and rejected for the same reason M7-7 rejected `NumberOfSections`,
  rather than silently forced.

**The coverage fraction is itself the finding, and it is informative either way (session brief).**
6/22 vs. 3/22 confirms the *direction* the brief predicted — richer static features do ground more
of `FT_RW` — but the shape of the gap is unchanged: every execution-time group (process, network,
persistence, kill-chain, 11/22 features) stays at zero regardless of how much static metadata is
available, because no PE-header/import/section field can observe a process spawn, a network
connection, a registry write, or a kill-chain stage — these are not properties a richer static
dataset can approach asymptotically; they require execution, which no static dataset by
construction ever performs.

**Transfer evaluation ran in a follow-up session, after this one's Ada infrastructure struggle
was resolved.** `scripts/m7_10a_ember_transfer.py --seed 20260912`, run_id
`20260925T160711Z-62498d7b`, against the full 200,000-row `test_features.jsonl`, sha256-verified
(`data/external/ember/README.md`). Ada's venv, built entirely from a `pip download`-only
wheelhouse cache (no further network calls once cached — the fix for the bandwidth issue this
DEV entry originally documented), pinned **scikit-learn 1.5.2**, one minor line behind the
reference environment's 1.9.1 (the same environment that established 0.8408). This session's own
synthetic-CSV sanity check reproduces to **0.8353, not 0.8408** (drift 0.0055, ~4 of 731 eval
rows) — version-dependent numerical drift in `RandomForestClassifier`/`LogisticRegression`
internals (a `ConvergenceWarning` from `lbfgs` appears only under 1.5.2), not a mapping or logic
bug. Accepted and documented rather than chased further: re-fetching an exact-matching sklearn on
Ada's still-slow network was not judged worth the wall-clock for a fit this close, and the
qualitative transfer finding below does not turn on 0.55 points of baseline drift.

**Result: still exactly chance, and the richer mapping does not move the hard decision — but the
continuous score is no longer actively anti-correlated with the label, unlike ClaMP's.**

```
bal_acc=0.5000  precision=0.6667  recall=0.00002  mcc=0.0013  pr_auc=0.6301
```

(`n`=200,000, class-balanced 50/50.) `bal_acc=0.500005` is, again, not a rounding coincidence: the
fitted profiles place all but 3 of 200,000 rows on the *NProf* (benign) side regardless of true
label — 2 of those 3 flagged rows are true positives (precision 0.6667), but that is 2 out of
100,000 actual malicious rows found (recall 0.00002). **The one place EMBER's richer mapping
visibly helps is the continuous score, not the hard call:** `pr_auc=0.6301` sits comfortably
*above* this dataset's 0.50 no-skill line, where ClaMP's `pr_auc=0.4612` sat *below* its own
0.5225 no-skill line (M7-7, DEV-34) — EMBER's ensemble score is weakly but genuinely informative,
ClaMP's was mildly anti-correlated with truth. The mechanism the hard decision fails on is
unchanged from ClaMP: 16 of 22 dimensions collapse to the structural-missing zero
(`missing_mask` constant across all 200,000 rows, confirmed in the sidecar), and the fitted
`NProf`/`AProf` profiles — built on the synthetic corpus where 16/22 features are populated —
read a mostly-zero vector as closer to benign almost universally, regardless of the 6 real
dimensions' own signal. **Doubling the coverage fraction (3/22 → 6/22) did not change the
qualitative transfer outcome; it only improved the (still discarded, by the hard-decision
boundary) continuous score.**

**Distribution comparison, the 6 mapped features (two-sample KS, synthetic corpus vs.
EMBER-mapped):**

```
read_write_ratio:      D=0.2959 p=3.4e-169  (synthetic mean 1.82, real mean 2.06)
write_entropy_mean:    D=0.1694 p=5.0e-55   (synthetic mean 5.63, real mean 6.47)
write_entropy_var:     D=0.7390 p<1e-300    (synthetic mean 0.59, real mean 4.88)
entropy_delta:         D=0.6065 p<1e-300    (synthetic mean 2.00, real mean 5.09)
crypto_call_rate:      D=0.8127 p<1e-300    (synthetic mean 25530.12, real mean 0.35)
key_generation_events: D=0.6118 p<1e-300    (synthetic mean 2.74, real mean 0.02)
```

All six diverge significantly, more sharply than ClaMP's three (DEV-34's largest statistic was
0.4884). Two features stand out for why: `crypto_call_rate`'s synthetic mean (25,530 — the
generator's own calls-per-second units) is not remotely the same scale as EMBER's raw import
*count* (mean 0.35) — the PROXY note on that feature (a rate approximated by a count) understates
just how different the two numeric ranges are; a reader comparing the raw means without that
context would wrongly conclude EMBER's PE files almost never touch crypto APIs, when the real
statement is narrower: the *units* don't match, only the *presence* of a crypto-keyword import is
comparable across the two. `read_write_ratio` is the one mapped feature whose two-sample gap is
comparatively small (D=0.30, closest to the entropy features' KS statistics under ClaMP) —
consistent with it being a structural PE-section property in both the synthetic generator's own
draws and EMBER's real files, rather than a value invented for one and absent from the other.

**Impact on reproduction:** none — new evaluation, no paper target touched, and every number above
was measured (`results/logs/20260925T160711Z-62498d7b.json`), including the 0.8353-not-0.8408
sanity-check drift, stated rather than hidden.
Figures: `results/figures/fig10a_ember_feature_distributions.png`,
`results/figures/fig10b_ember_transfer_metrics.png`.
Tests: `tests/unit/test_honeypot_ember_mapping.py` (16 tests: every feature has a decision, the
six mapped features compute what they claim, missing slots are zero-and-flagged, source-field
validation, mapping-summary totals).

### DEV-36 · ADD · MLP detector architecture, and permutation importance replacing Gini for
### the RF-vs-MLP comparison (M7-10b)

**Paper:** n/a — Table II names only the paper's four algorithms (random forest, logistic
regression, decision tree, KNN); an MLP is our own addition to test whether M7-8's adversarial-
retraining failure mode is a tree-ensemble-specific artefact.

**Problem:** M7-8 found that adversarially retraining the Random-Forest-led ensemble hardens it
against M7-3's attack at 50%/100% training budget, but by learning "values near the evasion
bound" as its own signature — the 100%-budget model's combined-evasion curve *rises* with
perturbation. Whether that is a property of tree ensembles' axis-aligned splits, or of the
22-feature space and augmentation strategy independent of architecture, was untested.

**Decision (a): the MLP is a single-model `models={"mlp": ...}` mapping into the existing
`NProf`/`AProf` machinery, not a fork of `detection/`.** `detection.profiles.ensemble_score`
already averages `predict_proba` across whatever is in the `models` mapping it is given; with one
entry, that average is just the model's own score. `detection.mlp_model.train_mlp` returns
`{"mlp": <fitted MLPClassifier>}` in the exact shape `detection.models.train_all` returns for the
four-model ensemble, so `detection/detector.py`, `detection/adversarial.py` and
`detection/retraining.py` all run against it completely unchanged — the same "reuse, don't fork"
posture M7-3/M7-7/M7-8 established. Kept as its own module (`detection/mlp_model.py`), not folded
into `detection/models.py`, because `models.MODEL_NAMES` is Table II's exact four algorithms
(CLAUDE.md §7); an MLP must never become a silent fifth entrant into that table.

**Decision (b): declared architecture (`configs/ml.yaml` `mlp_detector:`), never tuned to beat
RF.** Two hidden layers (32, 16 units), ReLU, `adam`, `alpha=0.001` L2 regularisation,
`early_stopping=True` (10% validation split, 20-epoch patience), `max_iter=500`. scikit-learn's
`MLPClassifier` implements neither dropout nor batch normalisation, so `alpha` (L2) and
`early_stopping` are the declared stand-ins the session brief's "dropout, batch norm" maps onto in
this framework — recorded here rather than silently substituted. sklearn was used rather than
PyTorch (the brief's stated fallback for "finer control over adversarial training") because the
sklearn result was informative enough on its own — see the finding below — to not require it this
session; a PyTorch follow-up remains open (`PROJECT_STATE.md`).

**Decision (c): permutation importance replaces Gini importance for the RF-vs-MLP feature-
reliance comparison.** M7-8 read `RandomForestClassifier.feature_importances_` (Gini importance,
normalised to sum to 1 across all features) to check whether the top-5's combined importance
collapsed under hardening. `MLPClassifier` has no such attribute, and Gini importance is
intrinsically tied to how a tree partitions its input space — there is no equivalent quantity for
a distributed neural representation to inherit. `scripts/m7_10b_neural_detector.py`'s
`permutation_importance_top5` instead shuffles one feature column at a time across the eval set
and measures the drop in the *actual fitted detector's* balanced accuracy
(`detection.adversarial.ensemble_predict` — the same NProf/AProf decision every other number in
this project's detection results uses, not a proxy model's raw `.predict()`). This is an absolute
scale (balanced-accuracy points lost), not Gini's sum-to-1 scale, so **M7-8's RF top-5 sums
(0.4553 → 0.2309) are not directly comparable to this session's RF permutation-importance sums
(0.1170 → 0.0177)** even though both describe the same fitted models at the same budgets — a
reader comparing the two numbers across sessions without reading this paragraph would draw a
false conclusion about the magnitude of the shift. Recomputing RF's own numbers by permutation
importance in the same run as the MLP's is what makes the two models comparable at all.

**Finding: the memorisation failure mode is not tree-specific — if anything, the MLP shows it
earlier and more completely.** Full numbers in `RESULTS.md` "M7-10" and the report's
"Neural vs. Tree-Based Detector" section. Summary: unhardened, the MLP is *more* robust than RF to
§adversarial's attack (median adaptive evasion 0.4866 vs. 0.3213) — a real architectural
difference, a smooth decision boundary needs a larger combined push to cross than RF's
axis-aligned splits. But every one of the MLP's three hardened combined-degradation curves
(25%/50%/100% budget) *rises* monotonically with perturbation — the same signature M7-8 found only
at RF's 100% budget, here present at every budget tested — and the MLP never reproduces RF's
25%-budget backfire (RF's median evasion effort *drops* below baseline at 25% before recovering;
the MLP's never dips). A higher-capacity, continuously-weighted model does not avoid the
augmentation-boundary-memorisation failure mode; it engages that shortcut faster than an ensemble
of trees does. This points at the training procedure (augmenting positives toward a bounded region
of a fixed, low-dimensional feature space) and the feature space itself as the root cause, not the
tree-ensemble architecture M7-8 tested it on.

**Impact on reproduction:** none — new evaluation, no paper target touched.
Tests: `tests/unit/test_mlp_model.py` (the MLP wiring into the shared profile/detector machinery),
`tests/unit/test_m7_10b_neural_detector.py` (end-to-end against the committed corpus — RF baseline
reproduction, MLP zero-perturbation degenerate case, MLP zero-training-budget degenerate case,
eval-set-never-perturbed).

### DEV-37 · ADD · Honeypot data poisoning: measuring M7-9's Gap 1, and blockchain immutability
### working against the defender (M7-11)

**Paper:** n/a — the paper never considers that Algorithm 2's data source could itself be
adversarial; this is the extension M7-9's threat model named as Gap 1 without measuring it.

**Problem:** a Tier-2 adversary who controls the honeypot's collection process can feed false
training data into `Sig_RW`/`FT_RW`. Once committed to `BC_SigRW` through real pBFT consensus,
the chain's own immutability guarantee — the paper's central selling point — certifies that
false data as *tamper-proof*, not as *false*. Chain integrity certifies a record was written as
submitted; it says nothing about whether what was submitted was true. This entry measures both
halves: how much three poisoning strategies degrade the detector, and (once, through real
consensus, not simulated) that the chain genuinely offers no way back.

**Three strategies (`detection.poisoning`), each a pure array transform on the training draw,
same posture as `detection.retraining.augment_positive_rows` (M7-8) — never touching the eval
set, `budget<=0.0` a true no-op so the degenerate case reproduces the unpoisoned fit exactly.
Budget is a fraction of the training set's ransomware row count throughout, so a budget is
comparable across strategies:**
- **(a) label flipping** — relabel `budget` fraction of real ransomware training rows as benign.
  Features untouched; the "benign" contribution is a real ransomware trace under the wrong label.
- **(b) feature poisoning** — inject synthetic rows labelled ransomware whose features are
  resampled (with replacement) from real benign training rows.
- **(c) anchor-point injection** — inject rows interpolated at the midpoint between the benign
  and ransomware per-feature centroids (small jitter so no two are identical), labelled benign —
  teaching the model that even the region right at the class boundary is benign, which pushes the
  effective decision boundary toward the ransomware centroid without fabricating an obviously
  wrong feature vector or flipping any real label.

**Measured on the committed corpus** (`scripts/m7_11_honeypot_poisoning.py --seed 20260912`,
`RESULTS.md` M7-11, `results/logs/20260925T193933Z-3d53aee9.json`), sanity-checked against the
CSV-path baseline **0.8408** — not the chain-path 0.8422 the session brief names. Same DEV-27
substitution every M7-x experiment against the committed corpus makes: `corpus.write_corpus`
rounds to 6 significant figures, the chain path does not, and the two are not bit-identical.

**Finding 1 — the three strategies rank in the *opposite* order the brief predicted.** Label
flipping (called "simplest, most likely to succeed") is indeed the most damaging, and
monotonically so: -1.5pt balanced accuracy at 1% budget, -17.3pt at 50%, and exactly
`bal_acc=0.5000` at 100% — at full budget the training set has zero positive rows left, so no
classifier can be fit past "always benign," which scores 0.50 on a balanced eval set by
construction, not by any model actually running. Feature poisoning (injecting fabricated
"ransomware" rows with real benign features) is mild and roughly budget-insensitive throughout
(-0.3 to -1.5pt): duplicating real benign feature vectors under the wrong label dilutes `AProf`
without teaching it anything structurally new, since the injected rows are feature-wise
indistinguishable from rows already in the benign class. **Anchor-point injection — the brief's
own "most sophisticated" strategy — is the *least* damaging at low-to-medium budget, and briefly
*improves* accuracy** (+0.6pt at 1%, still +0.1pt at 20%, only turning negative at 50%, -1.3pt):
points at the inter-class midpoint, labelled benign, act as a mild regulariser at low budget
rather than the intended boundary-shift, before enough of them accumulate to actually move it.
Sophistication of the *attack's design* and its *measured effectiveness* are not the same axis —
the crudest attack (mislabel real data) beat the most carefully engineered one across most of the
tested budget range.

**Finding 2 — the permanence argument, demonstrated once, for real, not simulated.**
`demonstrate_permanence()` builds one real malicious `CleanSample` (via the same
`honeypot.collector`/`honeypot.preprocess` path every other honeypot record in this project uses),
signs and attests it normally (`honeypot.signatures.build`), then constructs its
`SignatureRecordPayload` with `label="benign"` instead of the sample's true `"RW"` — the label-
flipping attack, applied concretely to one record — and commits it through
`framework.phase2_collection`'s own pipeline (unchanged) to a real `BC_SigRW` `Cluster` running
actual pBFT consensus (not a mock). **It committed in one block, cleanly, on the first attempt.**
Reading `blockchain.chain.Chain`'s full public method list confirms the paper's Algorithm 2 has
no counter-move: `append`, `check_append`, `create_genesis`, `adopt_genesis`, `draft_next`, and a
set of read-only accessors (`head`, `block_at`, `block_by_hash`, `contains`, `verify_block`,
`verify_integrity`, `height`) — **no delete, remove, rollback, revert, truncate, or undo method
anywhere.** This is a code-level fact about a class already in the repository, not new code
written to demonstrate the gap; `Chain` was never going to grow a fifth checked item here (OUT OF
SCOPE: no changes to the chain).

**Finding 3 — the pre-commit validation gap is exactly as wide as `Chain.check_append`'s own
five checks, and none of them are semantic.** The poisoned record passed prev_hash linkage,
Merkle root recomputation, hash uniqueness, ECDSA signature verification, and timestamp-skew
tolerance — every one of them structural or cryptographic, none of them inspecting
`SignatureRecordPayload.features` or `.label` for plausibility. A correctly formatted,
correctly signed poisoned sample passes every existing validation check because nothing in
Algorithm 1-5 was ever asked to check semantic content, and this project's implementation does
not accidentally add that check either — the session's own TESTS section named this as the
alternative, more surprising finding ("if validation catches it, that's a finding worth
reporting"); it did not.

**Finding 4 — post-commit detection is a real gap, and also a named-but-unbuilt defense.** Honest
nodes could in principle maintain their own running feature distributions and flag statistical
outliers in new contributions (something closer to the anchor-point strategy's own signature
would likely be detectable this way, since it visibly clusters near the class boundary — label
flipping, by contrast, looks like a perfectly ordinary ransomware-labelled row from the feature
side alone, since its features are real). This project does not build such a mechanism: it would
require cross-node agreement on what "normal" looks like in a 22-dimensional feature space, which
is a research problem in its own right, and building it would be a defense contribution beyond
this session's critique-only scope (OUT OF SCOPE).

**Finding 5 — hybrid anchoring (M7-5, DEV-33) does not help, because it answers a different
question.** Anchoring verifies that already-committed `BC_SigRW` data has not been tampered with
*after* commitment — it is an integrity guarantee over time. Poisoning is not post-commit
tampering; it is a *validly signed, validly consensus-approved commitment* by an authorized
node in the first place. The anchor chain faithfully, correctly records the poisoned block
exactly as submitted — anchoring cannot and does not distinguish a legitimate record from a
false one an authorized party chose to submit, because that distinction is validity, not
integrity, and the anchor's guarantee has only ever been the latter (`docs/THREAT_MODEL.md`
Trust Assumption 2, DEV-33's own "not a closed Tier-3 solution" caveat).

**This is not a BSFR-SH-specific bug.** Any system that (a) trains an ML model on data drawn
from a source it does not fully trust, and (b) commits that data to storage designed to be
tamper-evident and append-only, faces the same structural tension: the storage layer's integrity
guarantee and the training data's trustworthiness are orthogonal properties, and strengthening
the first (more replicas, stronger consensus, longer chains) does nothing to strengthen the
second. Blockchain-backed ML training pipelines inherit this tension by construction, not by
implementation mistake — it is the same "chain integrity is not chain validity" distinction this
project's own threat model (`docs/THREAT_MODEL.md`) already needed for a different claim.

**Impact on reproduction:** none — new evaluation, no paper target touched, no code in
`detection/`, `honeypot/`, or `blockchain/` changed (OUT OF SCOPE).
Figures: `results/figures/fig11a_poisoning_degradation.png`.
Tests: `tests/unit/test_detection_poisoning.py` (18 tests: no-op at zero budget, row-count and
label-distribution correctness per strategy, determinism, originals never mutated),
`tests/unit/test_m7_11_honeypot_poisoning.py` (end-to-end against the committed corpus — CSV-path
baseline reproduction, zero-budget degenerate case per strategy, expected row counts/label
distributions, eval set never perturbed, 100%-budget label-flip leaves zero positive rows).

### DEV-38 · ADD · Statistical poisoning detection: the defense DEV-37/M7-11 measured the absence
### of, and what it actually closes (M7-12)

**Paper:** n/a — Algorithm 2 has no semantic validation step at all; this is a defense M7-9's
threat model named as a possible mitigation (Gap 1) and M7-11 predicted the shape of, without
building or measuring either.

**What was built.** `detection/drift.py` (`DriftDetector`, `RunningStats`, `DriftPolicy`,
`DriftReport`): a per-replica running per-feature profile (Welford's online mean/variance, no
historical sample ever stored) scored two ways — Mahalanobis (diagonal, RMS-aggregated
standardized batch-centroid distance) and Page-Hinkley (a streaming mean-shift test over the
Mahalanobis signal itself, for slow cumulative drift). A full per-feature KS test (the brief's
third option) needs the historical sample *values*, not just their moments, so it was not
implemented — a scope choice made explicit here, not a silent omission.
`consensus/validated_commit.py` (`ValidatedSigRWChain`, `build_validated_sigrw_chain_factory`):
a `Chain` subclass that runs the detector inside `check_append()` — the one place
`consensus/pbft.py`'s own docstring says block validity is decided ("Consensus decides whether,
`Chain` decides valid") — so a replica that detects drift raises `ChainError` and is rejected by
the existing pBFT vote-counting exactly like a bad signature would be. `consensus/pbft.py` itself
gained one additive, backward-compatible change: `Cluster.__init__` takes an optional
`chain_factory` (default `Chain`, so `BC_DTBU`'s commit path — and every existing caller that
does not pass it — is byte-for-byte unchanged; OUT OF SCOPE forbade touching that path).

**Problem 1 — this is a deliberate, named exception to CLAUDE.md §3's layering rule.**
"`consensus/` depends only on `crypto/` and `blockchain/`" is a real, previously-unbroken,
test-pinned rule (`tests/unit/test_module_boundaries.py::
test_consensus_depends_only_on_crypto_blockchain_and_util`). Pre-commit drift validation for
`BC_SigRW` cannot exist without `consensus/validated_commit.py` calling
`detection.drift.DriftDetector` — there is no version of "score this block's batch before voting"
that avoids it. Rather than loosen the rule silently, the test itself now names the one file
permitted the extra edge (`CONSENSUS_DETECTION_ALLOWED`), with the reasoning inline: `detection/
drift.py` has zero internal dependencies of its own (pure numpy/stdlib), so this is one shallow,
one-directional edge, not a cycle, and every other file under `consensus/` is held to the
original rule exactly as before. `docs/ARCHITECTURE.md` §consensus states the same exception.

**Problem 2 — the defense as specified needs plaintext features, and consensus replicas are
not supposed to have them.** `blockchain/transaction.py`'s own docstring states the design
invariant this narrows: "Miners in M2b validate blocks they cannot read; that is the point."
`Sig_RW`/`FT_RW` payloads are hybrid-encrypted to one recipient (DEV-01); nothing before this
session gave a `BC_SigRW` replica a decryption key. `ValidatedSigRWChain` requires one (a new
constructor parameter, `decrypt_keys`), which is a real widening of trust, stated as
`docs/THREAT_MODEL.md` Trust Assumption 6 — not a detail to leave implicit. A transaction none of
the supplied keys open is skipped, not raised on (`extract_feature_batch`): the defense validates
what it *can* read.

**Problem 3 — a second new trust assumption, about agreement rather than access.** Every honest
replica must run the same `DriftPolicy` (threshold, method, `min_history`) to agree on whether to
vote — pBFT's total order already guarantees they see batches in the same sequence, but nothing
guarantees they run the same policy, and a replica that does not agrees with its peers about
nothing. `docs/THREAT_MODEL.md` Trust Assumption 7. Not tested against a policy-mismatched
replica; stated as a limitation, per this session's own convention of naming what is unverified
rather than leaving it implicit.

**Measured, `scripts/m7_12_poisoning_defense.py --seed 20260912`, `RESULTS.md` M7-12,
`results/logs/20260926T041840Z-670ec207.json`** — against exactly M7-11's three strategies and
five budgets, plus a false-positive rate, a "new ransomware family" probe, and two real pBFT
commits. Full discussion: `docs/THREAT_MODEL.md` Gap 1's own "pre-commit detection, built and
measured" subsection carries the numbers; summarized here for the deviation record:

* **0 of 15 M7-11 cells prevented at the shipped threshold** (Mahalanobis RMS >= 3.0, chosen
  before any measurement below and left unmoved after). Anchor-point injection scores *below* the
  matched-size clean-batch noise floor at every budget — its engineered class-boundary midpoint
  coincides, in a roughly balanced corpus, with the population mean, making the "most
  sophisticated" attack the least visible to a whole-population distributional test, exactly
  inverting M7-11's own unbuilt prediction. Label flipping and feature poisoning score
  *moderately above* the same-size clean-batch noise floor at budgets >=5% — not because the
  detector reads labels (it cannot; `honeypot/features.py`'s schema keeps them separate), but
  because an all-malicious batch's feature composition differs from the profile's usual mix. The
  same signal fires on an honest, unusually ransomware-heavy batch — an outbreak, not an attack.
* **False-positive rate: 0/30** chunked eval-corpus batches (25 rows each) at the shipped
  threshold. **New-family probe: not flagged**, despite scoring ~17x the matched clean-batch p95
  (1.2255 vs. 0.070) — the tension the brief's item 4 asked for, measured: a threshold loose
  enough to catch that probe would also raise the false-positive rate on equally small, genuinely
  clean batches, which the noise-floor table (`RESULTS.md` M7-12) makes concrete rather than
  assumed.
* **Real pBFT commits: both a 39-record label-flip burst and a 40-record anchor-shift burst
  committed under a small (~35-sample), realistic early-chain history, defended and undefended
  alike.** A single record (M7-11's own permanence-demo shape) is undetectable in principle at
  any threshold — `n=1` has no averaging to suppress sampling noise, and the noise floor only
  grows as `n` shrinks (a same-size clean batch at `n=7` can score as high as 1.14). This is the
  defense's sharpest limitation: it is blindest at exactly the smallest submission an adversary
  can make, and M7-11's own demonstration happened to be exactly that size.

**Honest verdict, stated once so it is not read as either "solved" or "useless."** This is a
real, working, measured mechanism against one specific thing: a poisoning batch that introduces
feature values the corpus profile has never produced before, submitted in a large-enough burst
against a large-enough history. It is not a general fix for Gap 1. Two new trust assumptions were
added to get even that; one deliberate architectural-layering exception was named to build it;
and the measurement that would have let this entry claim more (a lower, more sensitive threshold)
was run, and it would also have raised the false-positive rate on ordinary small clean batches —
reported as the actual tension it is, not resolved by picking a more flattering number.

**Impact on reproduction:** none — new capability, no paper target touched, `BC_DTBU`'s commit
path unchanged, M7-11's own attack code untouched (OUT OF SCOPE).
Figures: `results/figures/fig12_drift_defense_comparison.png`.
Tests: `tests/unit/test_drift.py` (14 tests: constant stream never flags drift, an injected
shifted batch is detected by both methods, offending-feature naming, threshold monotonicity,
`score_batch` never mutates state, cold-start returns no drift, input validation),
`tests/unit/test_validated_commit.py` (4 tests: feature extraction decrypts/skips correctly, a
defended cluster commits clean batches with zero drift events, a defended cluster rejects a
batch an undefended cluster commits — bounded run, see the module's own note that an all-honest
cluster unanimously refusing one request stalls via view-change escalation rather than failing
cleanly, a pre-existing property of `consensus/pbft.py`'s reduced view change, DEV-20, not
something this session introduced or fixed).

### DEV-39 · ADD · Dynamic-behavioral transfer: MalbehavD-V1 grounds 12/22 features across 5/7
groups, and the transfer still fails, but for a scale-calibration reason, not a coverage reason
(M7-13)

**Paper:** n/a — same as DEV-34/DEV-35, this is about testing `FT_RW`'s real-world grounding, not
the paper's design.

**Problem:** DEV-34 (ClaMP) and DEV-35 (EMBER) both mapped *static* PE-feature datasets — header
and structure fields read off a file that is never executed. Both grounded only the entropy group
(3/22, then 6/22), because entropy is one of the few properties measurable both statically and
dynamically; the other six groups (filesystem's dynamic half, crypto_api, process, network,
persistence, kill_chain) had no analogue in either dataset, structurally, no matter how much raw
data either one carried. The open question neither could answer: does a genuinely *dynamic*
dataset — real execution traces — change the transfer story, since it can ground groups no static
dataset can touch at all?

**Dataset search, and why the session brief's own candidate list needed correction before use.**
The brief named four candidates in order, to be checked and used at the first that works with
>=12/22 coverage:

1. **BODMAS** (brief's URL `github.com/UrbSec/BODMAS` does not exist). The real repository is
   `github.com/whyisyoung/BODMAS`. Its own README and project page state it extracts features
   "using the LIEF project (version 0.9.0), the same as the Ember dataset" — 2381-dim **static**
   structural features, not the dynamic sandbox behavioral data the brief attributed to it.
   Verified against the dataset's own documentation, not assumed from the brief's description
   (CLAUDE.md: "do not trust README descriptions — inspect the actual data" applies as much to a
   session brief's characterization of a dataset as to the dataset's own README). **Ruled out**:
   it would only reproduce EMBER's coverage under a different name.
2. **CICMalDroid-2020** — genuinely dynamic (CopperDroid VMI sandbox over 13,077 executed APKs:
   syscalls, binder calls, composite behaviors, network PCAP) but gated behind a
   `cicresearch.ca` download form requiring name/email/institution/job-title/country and manual
   review — exactly the risk the brief itself flagged. **Not obtainable this session** without
   creating an external record under the user's identity and waiting on approval.
3. **MalwareBazaar + Hatching Triage** — MalwareBazaar's API now requires an Auth-Key obtained
   through an abuse.ch account-registration portal (confirmed: an unauthenticated `get_info` POST
   now returns `{"error": "Unauthorized"}`); Triage's docs endpoint returned HTTP 403 and its
   public reports listing redirects to a login-gated SPA. **Not obtainable** without creating an
   account under the user's identity — the same class of blocker as (2).
4. **Public Cuckoo instances** (`cuckoo.cert.ee`) — did not respond at all within a 15s timeout.
   **Unreachable**, matching the brief's own "availability varies" caveat.

All four named candidates failed for distinct, verified reasons. Rather than stop on "no candidate
reachable" (the exit condition does not accept that, and CLAUDE.md's "never claim a number we did
not measure" rules out the alternative of inventing a mapping), one further, freely-downloadable,
no-registration option was checked — in the same spirit as candidate 3 (a real, published,
Cuckoo-derived API-call dataset), since none of candidates 2-4 could be obtained without the user
personally creating an external account, which this session does not do unilaterally.

**Dataset used: `github.com/mpasco/MalbehavD-V1`** (Maniriho, Mahmood & Chowdhury, "API-MalDetect:
Automated malware detection framework for Windows based on API calls and deep learning
techniques," *J. Network and Computer Applications*, 2023). 2,570 real Windows PE files (1,285
malware + 1,285 benign, perfectly balanced), each **executed** in an isolated Cuckoo-sandbox
environment and represented as its observed API call sequence (up to 175 calls, 291 distinct API
names across the corpus). MIT-licensed, committed directly to a public GitHub repo, no download
form, no account. Fetched via direct HTTPS GET, committed to this repo (`data/external/malbehavd/
README.md`: sha256 verified, row count and label balance verified by direct inspection, not taken
from the README's stated numbers alone).

**The mapping (`honeypot.malbehavd_mapping`) grounds 12 of 22 features across 5 of 7 groups** —
double EMBER's 6, quadruple ClaMP's 3 — and, more importantly, **inverts which groups ground**:
filesystem (3/5), crypto_api (3/3), process (3/3), network (2/3), persistence (1/3) are grounded;
entropy (0/3) and kill_chain (0/2) are fully `MISSING`, the exact opposite of ClaMP/EMBER, because
this dataset never captures byte content (no entropy signal) or per-call wall-clock time (no
stage-dwell signal) — only call identity and order. Every mapped feature is a real count of
observed API calls in a curated category (e.g. `child_process_spawns` <- count of
`CreateProcessInternalW`/`NtCreateUserProcess`/`ShellExecuteExW`; `key_generation_events` <- count
of `CryptGenKey`/`CryptAcquireContext*`), following the same discipline DEV-35 established:
`extension_change_rate`, `directory_breadth`, `dns_entropy`, `shadow_copy_deletions` and
`backup_path_accesses` all have a same-category API present in the vocabulary (a rename call, a
directory-traversal call, a DNS-resolution call, a generic WMI call) but are marked `MISSING`
anyway, because the dataset carries no call *arguments* (no extension string, no path, no resolved
domain name), and a count of same-category activity is a different quantity than the
argument-dependent one `FT_RW` names — the identical rejection DEV-35 applied to `NumberOfSections`
as a `directory_breadth` proxy. Every mapped feature is `PROXY`, never `DIRECT`, matching DEV-35's
own bar (a raw count standing in for a rate, since no timestamps exist — the same "count stands in
for a rate" convention `ember_mapping.crypto_call_rate` established). `crypto_ngram_novelty` is
the one feature only this dataset makes computable at all (ClaMP/EMBER have no call sequence),
computed as a self-referential distinct-bigram diversity ratio rather than novelty against a
reference population, to avoid the mapping depending on the labels of the data it evaluates —
flagged as the weakest of the twelve, and turns out to be genuinely degenerate (see below).

**The transfer result is still exactly 0.5000 — bal_acc=0.5000, prec=0.0000, rec=0.0000 — matching
both ClaMP and EMBER, but the mechanism is different and more precisely diagnosed.** Every one of
the 7 per-group permutation-importance drops on real data is exactly 0.0000, including the 5
groups that are genuinely mapped: the ensemble's prediction on all 2,570 real rows is the single
constant class `benign` (confirmed by direct score inspection — every real row's ensemble score
falls in [0.158, 0.380], entirely inside the `normal` profile's own 1-sigma band and nowhere near
`abnormal`'s 0.855 mean), so no feature — mapped or missing — can move a prediction that has
already saturated to one class. This is not ClaMP/EMBER's "16-19/22 features collapse to the
mapping's structural zero" story (here only 10/22 are that zero). **A within-dataset Mann-Whitney
U test (no synthetic data involved at all) proves real signal exists**: 9 of the 12 mapped
features separate real malware from real benign at p<1e-4, three overwhelmingly
(`child_process_spawns` p=2.25e-235, `autostart_writes` p=5.69e-98, `read_write_ratio` p=7.94e-73).
The KS means explain the actual failure mode: `honeypot.collector`'s counters simulate a full
ransomware *episode* (synthetic `crypto_calls` mean ~25,530, `renames` mean ~1,200-8,000-scale raw
counters) while MalbehavD-V1's Cuckoo traces are bounded to a short sandbox window (max 175 total
API calls per sample, so any single category's count sits in the single digits — real
`crypto_call_rate` mean 0.36, `rename_rate_per_s` mean 0.032). The fitted `NProf`/`AProf` profiles
were never shown a value in that range for *either* class, so every real row lands in the same
corner of feature space regardless of label — a **scale-calibration mismatch between an
assumed-unbounded monitor and a bounded sandbox window**, not an absence of dynamic behavioral
signal in the real world. `crypto_ngram_novelty` independently turns out to be degenerate on this
dataset (mean 1.0000 for both classes, p=1.00): traces average only 43 calls, short enough that
almost every adjacent bigram is unique, saturating the statistic — a limitation of this session's
specific proxy, not of the underlying feature concept.

**Actionable for future work, stated as a concrete, falsifiable next step rather than a vague
"improve the generator":** re-calibrating `honeypot.collector`'s count-feature distributions to a
bounded-observation-window regime (tens, not thousands, per category) is the specific, testable
change this finding points at. The shapes of the synthetic distributions may be fine; the *scale*
assumes a monitor with no time limit, which no real sandbox (or honeypot deployment with a bounded
observation window) actually has.

**Impact on reproduction:** none — new evaluation, no paper target touched. Figures:
`results/figures/fig13{a,b,c,d,e}_{coverage_progression,malbehavd_feature_distributions,
transfer_metrics,group_importance,ks_heatmap}.png`. Full numbers: `RESULTS.md` "M7-13", sidecar
`results/logs/20260926T091633Z-be5973ca.json`. Tests:
`tests/unit/test_honeypot_malbehavd_mapping.py` (21 tests: the mapping table is deterministic and
total, coverage-fraction ordering vs. ClaMP/EMBER, entropy/kill_chain fully missing, per-feature
compute correctness, malformed-row handling).

### DEV-40 · ADD · Commit-then-reveal defense against honeypot poisoning: the protocol works
exactly as specified, and measurably does not degrade anchor-point injection on this corpus (M7-14)

**Paper:** n/a — Algorithm 2's collection step has no commit phase at all (GAP-3); this is a new
protocol extension this project adds, not a paper claim being tested.

**Problem, restated precisely.** M7-12 (DEV-38) measured that `detection.drift.DriftDetector`
cannot catch anchor-point injection at any budget, and *why*: the attack's engineered midpoint
between the two class centroids sits, in this roughly class-balanced corpus, almost exactly at
the population mean — the batch designed to look most like an attack looks the least anomalous.
That midpoint is only computable because `detection.poisoning.anchor_point_injection` reads the
*current* `x_train`/`y_train` centroids directly. M7-14's brief: build a protocol-level defense
(commit before seeing the honest distribution) that removes that visibility, and measure whether
the attack degrades.

**What was built.** `consensus/commit_reveal.py` — `Commitment`/`Reveal`/`CommitRevealRound`
(Phases 1-2: commit, then reveal-and-verify, binding the *entire* batch including every feature
value via `SignatureRecordPayload.to_bytes()`, not a count or a label hash — a node that commits
to a batch and reveals a different one, or never reveals at all, is excluded from the round,
reported rather than raised, so one bad participant cannot abort the round for the rest) and
`WithholdTracker` (permanent exclusion after `max_consecutive_withholds` — default 3, chosen to
match pBFT's own `f=1`-at-`n=4` bound rather than an independently chosen number). This module
depends only on `crypto`/`blockchain`/`util` (`consensus/validated_commit.py`'s dependency on
`detection/` remains the one named exception to CLAUDE.md §3, not widened by this session); the
pipeline-wrapping step (Phase 3: hand the merged, verified batch to the existing block pipeline)
therefore lives one layer up, in `framework/commit_reveal_pipeline.py`'s
`submit_with_commit_reveal`, which calls `_block_pipeline.run` unmodified. `configs/chain.yaml`
gained `consensus.commit_reveal.{enabled, max_consecutive_withholds}` (default `enabled: false`)
— the config-flag switch the brief's item 2 asks for; it is read by callers (this session's
evaluation script; any future `phase2_collection` wiring is out of scope), since a module cannot
sensibly "be enabled" on its own.

**The information constraint is modelled explicitly, not just argued** (`scripts/
m7_14_commit_reveal_defense.py`). `detection/poisoning.py`'s three strategies are called
completely unmodified (OUT OF SCOPE line 1) — what changes is what they are *given*. The
committed corpus is split once, deterministically, into a historical partition (85%, "already on
the chain" — visible to the adversary at commit time) and this round's honest contribution (15%,
revealed only after commit); the adversary's strategy function sees only the historical
partition, its output is merged with this round's untouched honest data, and *that* merged set is
what the detector is fit on — the same total corpus content M7-11 fits on, reshuffled only by
which slice was temporarily withheld from the adversary's view.

**Measured result: the protocol behaves exactly as specified (21 unit tests + 1 real-pBFT
integration test, all passing), but its effect on anchor-point injection's measured damage is
statistically indistinguishable from zero on this corpus, at both a mature-chain (85% historical)
and an early-chain (15% historical) partition.** `damage_prevented` (undefended gap minus defended
gap, both measured against the clean baseline) at `HISTORICAL_FRACTION=0.85`: +0.0026, +0.0000,
+0.0056, -0.0000, +0.0026 across the five budgets — all within a hundredth of a point, sign
unstable. An 8-repeat robustness check (independent historical-split and injection-draw seeds per
repeat, `run_anchor_point_robustness`) confirms this is not one lucky/unlucky split: mean
`damage_prevented` ranges from -0.0013 to +0.0055 with `std` 0.0010-0.0034 — the mean sits inside
one standard deviation of zero at every budget. The `EARLY_CHAIN_HISTORICAL_FRACTION=0.15`
sensitivity check (only 106 historical positive rows, an order of magnitude less data) shows the
identical pattern: -0.0103 to +0.0094, still noise-level. **Why**: `honeypot.collector`'s four
ransomware profiles and however-many benign profiles are stationary, low-dimensional (22-feature)
Gaussian/log-normal mixtures (DEV-27) — a historical sample of even ~106 positive rows already
estimates the population centroid to within the same precision the full ~700-row corpus would,
so withholding the current round's honest data denies the adversary almost nothing it could not
already infer from history. The defense's own motivating premise — "the adversary must guess
where the boundary is, and a wrong guess is either ineffective or detectable" — is correct as
stated, but this corpus's centroids converge too fast for "wrong guess" to actually occur at any
tested history size.

**`label_flip`/`feature_poison` show larger, noisier `damage_prevented` swings (e.g. -0.0325 at
one budget in an earlier run, -0.0272 in the canonical one) — this is sampling-pool noise, not a
protocol effect, and is reported as such rather than left to look like an inconsistent result.**
Neither strategy needs to see this round's honest data to operate: `label_flip` relabels rows the
adversary already possesses (real ransomware traces it collected itself); `feature_poison`
resamples benign feature values from whatever pool it has access to. Restricting that pool to the
85%/15% historical partition changes *which* rows are available to flip or resample from, which
is exactly the kind of finite-sample variation `run_anchor_point_robustness`'s repeats quantify for
`anchor_point_injection` — not measured for the other two strategies since commit-reveal was never
expected to constrain them in the first place (stated as a prediction, not discovered post hoc:
DEV-40's own design section above explains why before any number is shown).

**Failure mode (a), repeated rounds:** 10 sequential commit-reveal rounds, `anchor_point_injection`
only, budget=0.20 of that round's *historical* positive count, the adversary's historical view
(including its own prior poison) growing each round. Measured `bal_acc` after each round: 0.8084,
0.8384, 0.8156, 0.8207, 0.8278, 0.8282, 0.8037, 0.8245, 0.8268, 0.8206 — no monotonic
strengthening; the trajectory oscillates around the 0.84 baseline without a visible trend, the
same null finding as the main sweep, for the same reason (fast centroid convergence). Confounded,
and stated as such: the accumulating corpus also grows each round (283 -> 2176 rows), which
independently affects the fit regardless of poisoning — a cleaner metric (delta against an
equivalent-size *clean* accumulator) is a natural next step this session did not build.

**Failure mode (b), collusion — argued, not measured, per the brief's own instruction.** Two
colluding nodes could share batches before committing, but at `n=4` with one adversary this
requires corrupting a second replica, which already exceeds pBFT's own `f<n/3` tolerance
(`docs/ARCHITECTURE.md` §consensus; `tests/unit/test_pbft_byzantine.py`'s existing `f=1`/`f=2`
results). **Commit-reveal therefore adds no new trust assumption beyond what consensus already
requires** — a genuinely good property, not a limitation, and stated as such rather than buried
among the failure modes it sits beside.

**Failure mode (c), withholding — deterministic, measured directly.** An always-withholding
adversary (`CS_adversary`, committing but never revealing, every round) is permanently excluded
by `WithholdTracker` at exactly round 3 of a 6-round simulation, matching
`max_consecutive_withholds=3` exactly — the mechanism behaves as specified. This is a liveness
cost, not a safety cost: every withheld batch is excluded from the merged set immediately, in the
very first round it withholds, regardless of whether permanent exclusion has triggered yet.

**Combination with M7-12 (item 5): no cell newly crosses the Mahalanobis threshold.** Every
defended anchor-point-injection cell's poisoned rows, scored by the identical `DriftDetector`/
`DriftPolicy` M7-12 used, score 0.0118-0.0169 — barely different from M7-12's own undefended
0.0078-0.0162, both roughly two orders of magnitude below the 3.0 alarm threshold. `newly_detected`
is `False` for all 15 cells (all three strategies), consistent with the sweep's own null finding:
commit-reveal did not change these batches' feature-space location enough to move a statistical
drift score, because it did not change the adversary's centroid estimate enough to matter.

**Honest verdict, stated once so it is not read as either "the defense doesn't work" or "the
paper's premise was wrong."** The protocol itself is correctly built and behaves exactly as
specified — every unit and integration test (commitment binding, tamper detection, exclusion,
withholding, `f=1` crash tolerance through real pBFT) passes, and the code is a genuine, working,
protocol-level mechanism with no new trust assumption beyond `f<n/3`. What is *not* shown is that
it meaningfully protects **this corpus's** anchor-point injection: the measured effect is
statistically indistinguishable from zero, at two different historical-partition sizes and across
8 independent repeats. This bounds where a commit-before-reveal defense of this shape is actually
useful — a stationary, low-dimensional, moderately-sampled distribution (like this project's
synthetic honeypot corpus) lets a historical-only estimate converge almost as fast as a
full-information one, so the "the adversary must guess the boundary" premise, while logically
sound, does not bind in practice here. A corpus with genuine concept drift, a much higher feature
dimensionality relative to sample size, or a much smaller absolute history (fewer than the ~100
positive rows tested here) is the regime where this defense would be expected to actually degrade
the attack — untested in this session, and a concrete direction for a future one.

**Impact on reproduction:** none — new capability, no paper target touched, `_block_pipeline.run`
and `consensus/pbft.py` byte-for-byte unchanged (the only `pbft.py` change in this project remains
M7-12's `chain_factory` parameter). Figures:
`results/figures/fig14a_commit_reveal_sweep.png`, `results/figures/fig14b_repeated_rounds.png`.
Full numbers: `RESULTS.md` "M7-14", sidecar `results/logs/20260926T210819Z-1c0db7c7.json`. Tests:
`tests/unit/test_commit_reveal.py` (22 tests: commitment determinism and tamper detection, round
exclusion for non-reveal/mismatch/no-commitment, canonical merge order, honest-case equivalence
to direct submission, `WithholdTracker` streak/reset/permanent-exclusion behaviour),
`tests/integration/test_commit_reveal_pbft.py` (1 test: a withheld/crashed node's batch is
excluded and the remaining honest batch still commits through real, unmodified pBFT consensus at
`n=4, f=1`).

### DEV-41 · ADD · Federated detection via cross-replica disagreement: a real, cost-free signal
for two of the three strategies; a weak, small-sample-limited one for the third (M7-15)

**Paper:** n/a — Algorithm 3 describes one detection module `DM_CSl` per cloud server but never
asks whether the paper's own `n=4` replication could be used *between* servers rather than only
within one. This is a new extension this project adds, exploiting redundancy the paper's own
architecture already pays for.

**Why this is the third and structurally different leg of the poisoning-defense arc.** M7-12
(DEV-38) inspects *feature distributions* and fails when the poison looks statistically normal
(anchor-point injection, invisible at every budget). M7-14 (DEV-40) restricts *information* and
fails when historical data alone already estimates what the current round would have revealed
(measured null on this corpus for the same strategy). Federated detection inspects *model
outputs* instead: four independently-trained replicas voting on the same sample. It needs no new
protocol message (`docs/ARCHITECTURE.md` §consensus's `n=4` cluster already exists) and no new
trust assumption beyond what `docs/THREAT_MODEL.md` Trust Assumption 6 (every `BC_SigRW` replica
can decrypt) already introduced for M7-12.

**The subtlety a naive framing misses, stated up front rather than discovered mid-session.** If
every node trains on the identical committed chain, disagreement has no source at all. Three
scenarios supply one, each measured separately (`scripts/m7_15_federated_detection.py`, 27 cells:
3 scenarios x 3 of M7-11's strategies x 3 budgets — 5/10/20%, narrower than M7-11/12/14's five-
budget sweep per this session's own brief):

* **(A) The poisoner trains on a different view than it commits.** Three honest nodes fit on the
  poisoned chain; the poisoner fits its own model on the pre-poison, clean view — rational for an
  attacker degrading *others'* detection, not its own. `analyze_disagreement` always correctly
  names the poisoner as the outlier (mechanical: 3-vs-1 by construction), but **the predicted
  irony — that the "outlier" is the node with the better model — holds only for two of the three
  strategies, not universally.** For `label_flip`/`feature_poison`, the poisoner's clean model
  (0.8408) genuinely outperforms the honest nodes' degraded one (0.7722-0.8363): disagreement
  flags the correct model as anomalous. For `anchor_point_injection`, the opposite holds — the
  honest nodes score *higher* (0.8425-0.8454) than the poisoner's own clean baseline, reproducing
  M7-11's own finding that this strategy sometimes *improves* accuracy — so here the flagged node
  is unremarkably the worse one, and no irony exists. `excluding_outlier_improves` is `False` in
  all 9 cells: at a 3-1 split, majority voting has already suppressed the dissenter's influence
  before any exclusion step runs, so acting on the flag changes nothing a plain vote had not
  already achieved.
* **(B) Algorithm diversity over one shared poisoned draw.** Four nodes, one of
  `configs/ml.yaml`'s four declared algorithms each (RF/DT/KNN/LR), all trained on the identical
  poisoned data. Majority voting **never scores below its own weakest individual algorithm** (all
  9 cells) — KNN alone is badly hurt on this feature space independent of poisoning
  (0.658-0.669), and voting recovers to 0.768-0.823. **This is not a like-for-like improvement
  over the M7-11/12/14 baseline**, which soft-votes across all four algorithms *inside one*
  `DetectionModule` (Alg. 3's own `DM_CSl`); scenario B hard-votes four *separately-fit*
  single-algorithm detectors, and that architecture underperforms the paper's own blended
  ensemble on `label_flip`/`feature_poison` (0.786/0.819 vs. 0.828/0.840) and is roughly even on
  `anchor_point_injection` (0.817 vs. 0.847) — the paper's own soft-vote ensemble already captures
  most of what algorithm diversity offers; this session's honest reading is "recovers the worst
  single model" rather than "beats the standard architecture." KNN and Decision Tree individually
  score **identical balanced accuracy across all three budgets** for `anchor_point_injection`
  (0.6602 and 0.8203 exactly) — a measured, genuine insensitivity: both are local/piecewise-
  constant models, and the injected anchor cluster apparently never enters any eval row's k=5
  neighbourhood or crosses an existing tree split at any tested budget, not an averaging artefact.
* **(C) A private, never-committed holdout per node** (this project's own extension — Alg. 3
  trains exclusively on `BC_SigRW`; no honeypot-collecting node in the paper reserves anything
  before committing). Four nodes each reserve 10% of their own contribution, fit on the
  (possibly-poisoned) committed 90%, and self-score against their own held-back 10% — no vote,
  no cross-node communication needed. **Measured result: a weak, inconsistent signal, not a
  reliable one.** Of 9 cells, exactly one crosses this session's own stated detectability band
  (mean drop across the 4 node-specific holdout splits is positive and exceeds its own
  cross-node standard deviation) — `anchor_point_injection` @10% (mean_drop=+0.0149,
  std_drop=0.0115) — the one strategy M7-12 and M7-14 both measured null against, briefly caught
  here but not at the adjacent 5%/20% budgets. **`label_flip`, M7-11's most damaging strategy, is
  not reliably caught even at 20% budget** (mean_drop=+0.0374, std_drop=0.0554 — zero sits inside
  the band): a ~62-70-row holdout (10% of the committed set at this corpus's size) across only
  four independent splits carries enough sampling variance that real degradation and pure noise
  are not yet distinguishable. Stated as a limitation of `n=4` nodes and this corpus's absolute
  size, the same convention M7-14 used for its own robustness check, not smoothed over.

**What was built.** `detection/federated.py`: `FederatedDetector` (a thin wrapper over N
independently-fitted `DetectionModule`s — no new training logic, reuses
`detection.adversarial.ensemble_predict`/`balanced_accuracy` unchanged), `majority_vote`/`vote`
(strict-majority decision plus per-node disagreement-fraction flagging; an exact 50/50 tie at
`n=4` resolves to benign, a stated convention, not a derived fact), and `analyze_disagreement`
(`DisagreementReport`: per-node agreement rate, the single most-divergent node — `None` on
perfect agreement or an exact tie, never an arbitrary pick — and, when ground truth is available,
individual/majority/excluding-outlier accuracy so scenario (a)'s irony is visible in the numbers
rather than assumed away by the identification step). Zero new dependencies: this module imports
only `detection.adversarial` and `detection.detector`, both already inside `detection/`'s own
boundary (`docs/ARCHITECTURE.md` §detection) — no `consensus/` change at all, unlike M7-12's named
exception. 12 unit tests (`tests/unit/test_federated_detection.py`): no-dissent reproduction,
3-vs-1 override, tie resolution, empty-input rejection, threshold-based flagging, divergent-node
identification, perfect-agreement and exact-tie null cases, the scenario-A irony property, and
the scenario-B non-negative-vs-worst-model property.

**Impact on reproduction:** none — new capability, no paper target touched, no change to
`detection/detector.py`, `detection/profiles.py`, `detection/models.py`, or any `consensus/`
module. Figure: `results/figures/fig15a_federated_scenarios.png`. Full numbers: `RESULTS.md`
"M7-15", sidecar `results/logs/20260927T053738Z-fc5e7c20.json`.

**Architectural honesty, stated once.** Unlike M7-12 (a new trust assumption, TA-6/TA-7) and
M7-14 (a new protocol module, one new trust assumption, TA-8), federated detection adds *nothing*
beyond what the paper's own `n=4` deployment and M7-12's existing decrypt-capable-replica
assumption already provide. That is a genuine structural advantage — the paper had this defense
available for free and never used it — but it is not a stronger defense on this corpus than the
other two: scenario (a) can misidentify the correct model as the outlier by design, scenario (b)
underperforms the paper's own soft-vote ensemble, and scenario (c) catches only one of nine cells.
The honest verdict is "cheapest to add, narrowly and inconsistently useful," not "solves what the
other two could not."

### DEV-42 · ADD · Multi-family ransomware detection: weak but real family signal, concentrated
entirely on the ransomware/benign boundary, not on inter-family confusion (M7-16)

**Paper:** n/a — §VII evaluates BitcoinHeist as a binary ransomware/benign problem and never asks
whether the 28 named families it already carries are themselves distinguishable. New extension.

**Why this matters for Algorithm 4, stated up front.** Case dispatch in Alg. 4 is currently
label-blind: every positive detection routes through the same isolate/remediate/case-1-2-3 state
machine regardless of which family triggered it. Different families imply different decryption
tools and kill-chain speeds, so family identification is a precondition for differentiated
response — but only if the detector can actually name the family, which this session tests rather
than assumes.

**Class imbalance is a finding, not a preamble.** 29 raw classes (28 families + `white`):
`white`=2,875,284 (98.58%), the largest family `paduaCryptoWall`=12,390, three families with
exactly 1 address each. 11 of 28 families fall under the 10-sample threshold and are merged into
`other_ransomware` per the brief; 19 classes survive. No family with >=10 samples is merged
(checked directly, not asserted).

**Measured result: macro F1 0.058-0.199 across the four models (decision tree best), weak
signal, not strong.** Weighted F1 (0.978-0.985) and top-3 accuracy (0.993-0.998) are both
dominated by `white`'s 98.58% share and say little on their own about family discrimination.
Per-family recall is highly uneven: the four largest families score 0.15-0.84 recall; the eleven
smallest score at or near zero. **The confusion is structurally one-sided** — every family's
dominant misclassification target is `white`, never another family (`most_confused_with` is
`"white"` for all 17 families with any off-diagonal mass) — so the 19x19 confusion matrix
(`results/figures/fig_m7_16_family_confusion.png`) shows the same ransomware/benign boundary the
binary detector already measures, not families blurring into each other.

**Per-family feature signal (`year`/`income` dominate every large family) is a caveat, not just a
finding.** A one-vs-rest RF per family (>=100 samples, `n_estimators=50` on a size-capped sample)
ranks `year` and `income` above every graph-topology feature (`weight`, `count`, `looped`,
`neighbors`) for all 8 large families. Since each family's activity is a narrow historical
campaign window, this may be detecting *when a campaign ran* rather than a *behavioural*
signature — the graph features FLAW-2 argues are already a poor proxy for ransomware behaviour
(§ARCHITECTURE `honeypot/`) contribute the least to family discrimination too.

**Binary-collapse: RF/DT are statistically indistinguishable from their binary-only counterparts,
not clearly better — the brief's expectation is not quite met, honestly reported rather than
rounded up.** Collapsing multi-class predictions to ransomware-vs-benign and scoring with the same
`honest_metrics` the binary detector uses: RF (prec=0.7383 rec=0.2785 mcc=0.4491 f1min=0.4044) and
DT (prec=0.3897 rec=0.4166 mcc=0.3939 f1min=0.4027) both sit marginally *below* their published
binary-only M6b figures (RF: 0.7434/0.2874/0.4579/0.4145; DT: 0.3970/0.4236/0.4013/0.4099) on
every metric — under 1 point apart, a wash rather than either a win or a real regression. LR
reproduces binary LR's exact natural-rate failure (predicts nothing) inside every one-vs-rest
sub-problem. KNN's multiclass number is nominally higher but is not a clean comparison (different
subsample sizes from different sampling procedures — see `RESULTS.md`). **Net reading: family
labels add information about *which* ransomware without detectably costing the *is-it-ransomware*
task**, for the two models (RF/DT) that do the real work in Table II.

**The FT_RW gap this surfaces.** `honeypot/features.py`'s schema (`docs/ARCHITECTURE.md`
§honeypot) has no family field — `Sig_RW`/`FT_RW` records carry `label ∈ {"RW", "benign"}` and
nothing finer. If BitcoinHeist families are even weakly distinguishable from address-level graph
features alone, a real deployment training on genuinely richer behavioural features (the
kill-chain/entropy/crypto-API groups FT_RW already has, that BitcoinHeist does not) would plausibly
do better at family identification, not worse — so this is a real, stateable gap in the synthetic
pipeline's design, not a moot one. **Out of scope for this session**: no change to
`honeypot/collector.py`, `features.py`, or the generator's label vocabulary. Recorded here as a
finding for a future session to act on, per the M7-16 brief.

**Another instance of FLAW-2's own shape.** §VII evaluates BitcoinHeist as if `label`'s only
usable content were "ransomware or not" — the family names sit unused in the same column the
paper already reads for the binary target. The paper's own chosen dataset carries more usable
structure than its own evaluation ever asks of it, one more form of the framework/evaluation
disconnect FLAW-2 names (`docs/report/report.tex` §\ref{sec:flaw2}).

**A latent performance bug this session's split exercise found and fixed, not a deviation from
the paper but load-bearing for M7-16's own numbers:** `grouped_stratified_holdout`
(`detection/dataset.py`, in place since Q10/D6) used `np.isin` for group-membership testing, which
does not take numpy's sorted/hashed fast path on object-dtype arrays. Every caller through
M4a/Q10/D6 only ever ran it on the 46K-row `paper_mode` resample, so nothing before M7-16 exercised
the majority class (`white`, 2.87M rows, ~2.6M unique addresses) at full scale; there, `np.isin`
does not complete in any practical time (confirmed killed after 10+ minutes on an isolated case of
the same size). Fixed with a Python hash-set membership test (0.25s on a comparable array; 3.81s
for a real full-scale 2.9M-row split). A second fix in the same function: two of the 19 surviving
families (`montrealRazy`, `montrealGlobeImposter`) are each confined to exactly one address, so
the whole class is one indivisible group — the split previously could put a class like this
entirely in test, leaving zero training rows and crashing `top_k_accuracy_score` downstream.
`grouped_stratified_holdout` now reserves at least one group for training whenever more than one
exists. Neither fix changes any previously-published binary number (those splits have thousands of
groups per class, nowhere near either edge case) — confirmed by re-running
`tests/unit/test_detection_dataset.py` unchanged after both fixes.

**What was built.** `detection/dataset.py`: `FamilyDataset`/`load_bitcoinheist_families` (the
family-preserving sibling of `load_bitcoinheist`, same read path, same §VII count verification).
`detection/multiclass.py`: `merge_rare_families`, `build_multiclass_model(s)` (RF/DT/KNN
unchanged, LR wrapped in `OneVsRestClassifier` per the brief), `macro_f1`/`weighted_f1`,
`per_class_report`/`confusion`/`most_confused_with`, `top_k_accuracy`, `binary_collapse`,
`per_family_feature_signal`. `scripts/m7_16_multiclass_detection.py`: full pipeline, KNN memory
projection/fallback (DEV-31's precedent), confusion-matrix figure. 21 unit tests
(`tests/unit/test_detection_multiclass.py`), including three real-data invariant checks (merge
correctness, `other_ransomware` composition, grouped-split disjointness) that skip when the raw
CSV is absent, matching `test_detection_dataset.py`'s own convention. Found and fixed a real bug
in `merge_rare_families` itself during test-writing: assigning `OTHER_RANSOMWARE` (17 characters)
into a fixed-width numpy string array silently truncates it — fixed by working in `dtype=object`.

**Impact on reproduction:** none — new capability, no paper target touched, no change to
`detection/detector.py`, `detection/profiles.py`, or any `consensus/`/`mitigation/` module.
Figure: `results/figures/fig_m7_16_family_confusion.png`. Full numbers: `RESULTS.md` "M7-16",
sidecar `results/logs/20260927T071228Z-8d52159c.json`.

### DEV-43 · ADD · Exact minimum adversarial perturbation: the brief assumed a random-forest
### classifier, `DM_CSl` is a four-model ensemble, and the 100%-budget "never flips" claim needed
### correcting, not overturning (M7-17)

**Paper:** n/a — adversarial evasion is entirely our own extension (DEV-27/M7-3). This entry is
about tightening M7-3's own measurement method, not the paper.

**The session brief's method does not fit `DM_CSl` as built, and that had to be resolved before
writing any code.** The brief (§1) is written for a pure random-forest classifier: "walk the
tree's decision path... the minimum perturbation that flips the MAJORITY vote." `DM_CSl`'s actual
decision (`detection.detector.DetectionModule.decide`, and `run_adversarial_robustness.py`'s own
docstring: *"the ensemble, not a single model's `.predict()`"*) is nearest-`NProf`/`AProf`-
membership on the soft-vote average of **four** heterogeneous `configs/ml.yaml` models —
`random_forest`, `decision_tree`, `logistic_regression`, `k_nearest_neighbours` — not a
random-forest-only hard vote. Three of the four admit an exact treatment along M7-3's fixed
top-5-simultaneous ray (`detection.exact_adversarial.tree_flip_t`/`lr_flip_t`); the fourth,
`k_nearest_neighbours`, would require enumerating pairwise crossings between the query point's
distance curve and all ~1467 training points' — `O(n_train^2)` per sample, ~1.05M pairs — judged
disproportionate to this session's time budget on an 8GB dev box (CLAUDE.md §6) and not attempted.
`exact_min_perturbation` therefore evaluates `DM_CSl`'s real decision at every
`random_forest`/`decision_tree`/`logistic_regression` breakpoint plus a dense grid (finer than
M7-3's 101 points) to bound any residual `k_nearest_neighbours`-only crossing, then bisects to
`1e-6` — exact where a tree/LR breakpoint is the true cause (65/353 rows, 18.4%, on the original
model), bounded-but-not-proven-optimal otherwise. By construction this can never report a *larger*
minimum than M7-3's own search (verified: `test_exact_min_perturbation_never_exceeds_binary_search`,
and the driver script hard-fails if any of the 353 real rows violate it).

**Two real implementation bugs surfaced and were fixed before any number could be trusted, both
from treating a decision tree's evaluation as pure float64 arithmetic when it is not.** (1) sklearn
routes tree splits with `<=`, so a sample sitting *exactly* on a threshold has not yet crossed it —
the naive "return the algebraic root" implementation reported `t=inf` ("never flips") for trees
that provably do flip by `t=1.0`, caught by the brief's own exhaustive-verification test
requirement (`test_tree_flip_t_is_exact_for_every_tree_on_every_sample`) applying `tree_flip_t`'s
own reported `t` and checking sklearn's `.predict()` actually changed. (2) sklearn's compiled tree
traversal casts `X` to **float32** before comparing to the (float64) threshold; a threshold
crossing computed in full float64 precision can land within float32's ~1.2e-7 relative rounding
of the stored threshold, so a naive comparison silently disagrees with what `.predict()` actually
does. Fixed by reproducing the cast (`goes_left`) and nudging past a crossing in feature-value
space (proportional to the threshold's own magnitude), not `t`-space, so the nudge survives
casting regardless of how large or small the crossing's `denom` is.

**The brief's own greedy majority-vote heuristic (§1c) is confirmed unsound on the real forest, not
just "an approximation" in the abstract — measured directly.** `greedy_majority_t` assumes a tree,
once flipped, stays flipped as `t` increases to 1.0; true for a depth-1 stump (nowhere to route
back through), false for `DM_CSl`'s actual multi-level trees, which split on a moving feature more
than once along a path. On 5 sampled positive rows, 5-12 of the ~50 trees selected as "cheap enough
to have flipped by `t_star`" had flipped *back* by `t_star` (verified against real per-tree
`.predict()` calls), so the true flipped count (38-59/100) sometimes falls short of the intended
majority (50). Kept in `detection.exact_adversarial.greedy_majority_t` because the brief asks for
it as a labelled approximation; `exact_min_perturbation` does not use it, and
`test_detection_exact_adversarial.py` documents the failure with a real-forest test rather than
asserting a guarantee the function cannot make.

**Finding, measured on the original (M7-3) model: the approximation error was small, and M7-3's
conclusions hold.** Exact median 0.3063 vs. binary search's 0.3213 (-1.5pt); p10/p90 move by
<0.2pt. The binary search was >=10 percentage points loose for only 4/353 rows (1.1%), all
`k_nearest_neighbours`-driven. None of M7-3's 28 "never flips" survivors actually flip under exact
search.

**Finding, measured on M7-8's hardened models: 25%/50% unchanged, 100% needed correcting.** The
25%-budget backfire and 50%-budget memorisation medians match to <0.01 percentage point. The
100%-budget model's reported median=1.0 ("never flips") is **technically wrong but practically
right**: exact search finds 177/353 rows (50.1%) DO flip, but verified directly against the real
ensemble, 176 of those 177 revert to the correct verdict one step later (median dip width 0.38% of
the perturbation range, vs. 39.6% for the real flips M7-3's own original model shows) — a decision
surface riddled with hundreds of one-sample-wide, unexploitable adversarial windows near the
augmented boundary, not a stable evasion region. This is direct, quantitative evidence *for*
M7-8's own "memorises the evasion boundary, not a deeper representation" reading (a genuinely
smooth, generalising decision function does not have that many razor-thin holes in it), not against
it. The 80.95-point median shift exceeds the session brief's 5-point retraining-revisit threshold;
no new retraining was run — the existing 100%-budget model was not retrained or altered, the shift
is fully explained by measurement precision, and the qualitative robustness conclusion is
unchanged. `results/figures/fig9d_pareto_clean_vs_robustness.png` (M7-8) is deliberately **not**
redrawn from the raw exact-median numbers alone: doing so would plot the 100%-budget point at
"robustness 0.19," which is numerically the true minimum but would misrepresent the trade-off to
any reader who does not also see the stability breakdown. A stability-adjusted robustness metric
(e.g. minimum *stable* perturbation, which would place the 100%-budget point far to the robust
end — only 1/178 of its real flips are stable) is a natural follow-up this session does not build.

**Impact on reproduction:** none — `detection/detector.py`, `honeypot/collector.py`, and every
paper-facing number are untouched; this only re-measures an existing, non-paper extension (DEV-27)
more precisely. `detection/exact_adversarial.py` (new module), `scripts/m7_17_exact_min_perturbation.py`.
Figure: `results/figures/fig_m7_17_exact_vs_binary_search_histogram.png`. Full numbers:
`RESULTS.md` "M7-17", sidecar `results/logs/20260927T171603Z-1d279ea9.json`.
