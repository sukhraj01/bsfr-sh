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

### DEV-02 · FILL · Session establishment protocol
**Paper:** §IV-A and §V-1 defer to "any standard mutual authentication and key establishment
mechanism," cf. BUAKA-CS [26].
**Ours:** ECDH over secp256r1 with ECDSA-signed transcripts, nonces and timestamps, per
`docs/ARCHITECTURE.md` §crypto. Chosen because it satisfies every property §V-1 asserts and
reuses the ECDSA primitive the paper already mandates.

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

### DEV-11 · FILL · Merkle tree construction detail
**Paper:** `MTR` appears in the block header with no construction spec.
**Ours:** binary Merkle tree over transaction digests, odd nodes duplicate the last hash.

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
