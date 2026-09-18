# Roadmap

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

**Current milestone: write-up done; M7 (stretch) not started, not required for the deliverable**

---

## M0 — Scaffold `[x]`

- [x] Directory tree
- [x] `CLAUDE.md`
- [x] `docs/PAPER_NOTES.md`, `NOTATION.md`, `ALGORITHMS.md`, `ARCHITECTURE.md`,
      `DEVIATIONS.md`, `EXPERIMENTS.md`, `ROADMAP.md`
- [x] `README.md`, `pyproject.toml`, `Makefile`, `.gitignore`
- [x] `configs/` skeleton (`chain.yaml`, `ml.yaml`, `bench.yaml`)
- [x] `util/` — config loading, logging, seeding, canonical serialization
- [x] `make setup` works, `make test` green (186 util tests, not an empty suite)

**Exit:** clone → `make setup` → `make test` passes.

---

## M1 — Crypto layer `[x]`

- [x] `crypto/hashing.py` — single SHA-256 entry point, domain-separated positions
- [x] `crypto/merkle.py` — tree, root, inclusion proofs, odd-node duplication + count binding
      (DEV-11 amended)
- [x] `crypto/ecdsa.py` — secp256r1 keygen / sign / verify, RFC 6979 deterministic nonces
- [x] `crypto/aead.py` — AES-256-GCM, nonce supplied internally so reuse is unrepresentable
- [x] `crypto/kem.py` — ECIES key wrapping bound to its ciphertext (DEV-01 amended)
- [x] `crypto/session.py` — ECDH + signed transcript, responder-identity binding, nonce cache
      (DEV-02 amended)
- [x] Tests: known-answer vectors, tamper detection, replay rejection, timestamp window
      (161 crypto tests; 347 total)
- [x] Q1 closed — `cryptography` backend, on measured throughput (RESULTS.md)

**Exit:** every §V-1 property has a passing test. **Met** — `test_session.py`,
`test_session_replay.py`, `test_session_mitm.py`.

---

## M2 — Blockchain + consensus

**Split into M2a and M2b on 2026-09-11.** The original single milestone bundled two things that
fail differently: data structures whose correctness is local and checkable in isolation, and a
distributed protocol whose correctness is about message ordering and quorums. Building them
together would have meant debugging a Merkle root through a consensus round. M2a is a hard
dependency of M2b and nothing else about the plan changed.

### M2a — Blockchain data structures `[x]`

- [x] `blockchain/transaction.py` — hybrid-encrypted `Transaction`, two payload builders
      (Alg. 1 line 2, Alg. 2 line 7)
- [x] `blockchain/block.py` — exact header field order from Alg. 1 line 3; draft/sealed split so
      a block cannot hold a digest that does not cover it; `RN` documented inert
- [x] `blockchain/chain.py` — genesis, validated append, integrity walk, iteration
- [x] Timestamps non-decreasing within the shared skew tolerance (DEV-17)
- [x] Tests: per-header-field tamper sweep, chain independence, round trip, skew bounds
      (107 blockchain tests; 465 total)
- [x] Debt D1 retired — `config_hash()` moved to `crypto.hashing`; one `hashlib` importer again
- [x] Sidecar `config_hash_scheme` added and backfilled (DEV-18)

**Exit:** `BC_DTBU` and `BC_SigRW` each build 15 blocks x 100 tx by direct single-node append,
no consensus. **Met** — `tests/unit/test_chain_scale.py`.

### M2b — Consensus `[x]`

- [x] `consensus/network.py` — in-process P2PCS bus on a simulated clock; delay configurable,
      default 0 (DEV-21); drop / delay / duplicate / reorder per node
- [x] `consensus/pbft.py` — pre-prepare / prepare / commit, `2f+1`, certificates by distinct
      signed sender; `(chain, view, seq, digest)` in every signature (DEV-19)
- [x] `consensus/view_change.py` — reduced Castro–Liskov view change (DEV-20)
- [x] `consensus/protocol.py` — shared message types, membership, certificate checks
- [x] Byzantine fixtures: silent, equivocating, wrong-signature, stale-view (+ colluding pair)
- [x] Tests: threshold enforcement, replay across views/sequences/chains, membership, view
      change, `f=1` and `f=2` (153 new; 618 total); 15 mutants of the safety rules all killed

**Exit:** `BC_DTBU` and `BC_SigRW` each build 15 blocks x 100 tx with 4 nodes, `f=1` tolerated.
**Met** — `tests/unit/test_consensus_scale.py`, one byzantine replica per cluster.

---

## M3 — Phases 1, 2, 5

**Split into M3a and M3b on 2026-09-12.** Phases 1 and 5 go together because a backup that
cannot be recovered is not a verified backup: the chunk format, the payload digest and the index
are one contract between them, and the only proof the contract holds is the round trip. Phase 2
shares nothing with them except the block pipeline, which M3a builds and M3b reuses unchanged.
Its real work (DEV-03's signatures and features) is design work of a different kind.

### M3a — Phases 1 and 5: backup and recovery `[x]`

- [x] `framework/entities.py` — `System`, `CloudServer`, session establishment
- [x] `crypto/channel.py` — messages under `SK` (session, direction, step, counter in the AAD)
- [x] `framework/_block_pipeline.py` — shared Alg. 1 lines 2–10 / Alg. 2 lines 3–10
- [x] `blockchain/backup.py` + `framework/phase1_backup.py` — Alg. 1, chunked (DEV-24)
- [x] `recovery/locator.py` + `BackupIndex` (DEV-05), index and cold scan agree
- [x] `recovery/restore.py` — Alg. 5 two-hop transfer (DEV-25), attested payload digest (DEV-23)
- [x] `framework/phase5_recovery.py` — Alg. 5
- [x] Integration test: backup → chain → recover → byte-identical restore
      (213 new unit tests, 831 total; 9 integration)

**Exit:** data survives a simulated full wipe, byte-identical, through consensus on `BC_DTBU`.
**Met** — `tests/integration/test_backup_recovery.py`, configured sizes (4096-byte chunks, 100
per block, a 201-chunk backup across three blocks), four replicas; also with a silent primary.

### M3b — Phase 2: honeypot, signatures, features `[x]`

- [x] `honeypot/collector.py` — emulated episodes, confusable profile pairs, blind sensor groups
- [x] `honeypot/preprocess.py` — Alg. 2 lines 3–4, five rules (DEV-26)
- [x] `honeypot/signatures.py` — Alg. 2 line 5, digest + attestation (DEV-03)
- [x] `honeypot/features.py` — Alg. 2 line 6, 22 features, kill chain truncated (DEV-27)
- [x] `honeypot/corpus.py` + `scripts/make_honeypot_corpus.py` — two independent draws on disk
- [x] `framework/phase2_collection.py` — Alg. 2, on M3a's `_block_pipeline` with no changes to it
- [x] Leakage and difficulty checks: overlap, no single-feature giveaway, baseline near the
      intended Bayes accuracy rather than at ceiling

**Exit:** signature records land on `BC_SigRW` through consensus and decrypt to what was built.
**Met** — `tests/integration/test_sigrw_scale.py` builds case-3 (15 × 100) from real records, and
`tests/unit/test_phase2_collection.py` asserts the full round trip.

---

## M4 — Detection (Phase 3)

**Split into M4a and M4b on 2026-09-12.** The two halves answer different questions and fail
differently. M4a reproduces the paper's *own* evaluation on BitcoinHeist, where the work is data
handling, class balance and honest baselines, and where the risk is quoting a number the split
manufactured. M4b runs the framework's own data path — the honeypot corpus and Alg. 3 — where the
risk is a leak in data we generated ourselves. Sharing `metrics.py` is the only overlap.

### M4a — the BitcoinHeist pipeline `[x]`

- [x] `make data` — fetches and verifies BitcoinHeist against §VII's counts before anything else
- [x] `detection/dataset.py` — loader, `address` dropped at read, binary label
- [x] `paper_mode` 90/10 resample · `honest_mode` natural balance, stratified k-fold (DEV-06)
- [x] `detection/models.py` — RF, LR, DT, KNN with the hyperparameters declared in `configs/ml.yaml`
- [x] `detection/metrics.py` — both metric sets, constant and stratified-random baselines
- [x] Sidecars in `results/logs/`, a `measured` line in `RESULTS.md` for every run
- [x] 100 new unit tests (1093 total); `--mode paper` refuses a subsampled load

**Exit:** the `paper_mode` experiment ran and is recorded with `n=46,014`; `honest_mode` ran
locally for all four models at the configured 200K subsample; baselines are published beside every
number. **The published BSFR-SH row did not reproduce** — best here is random forest at
0.9479 / 0.9717 against a reported 0.9898 / 0.990, and the paper's own best algorithm (decision
tree) reaches 0.9262. That gap is the M4a result, recorded in `RESULTS.md` and carried into the
write-up as an open question rather than explained away. Full-scale `honest_mode` (2.9M rows) is
deferred to Ada: prepared as `scripts/ada_honest_mode.sbatch`, **unrun**.

**Q10, closed 2026-09-13 (follow-up session, not a milestone).** Ran the `address`-kept / split-
grouping 2x2 ablation (`scripts/q10_leakage_ablation.py`); neither leakage source, alone or
stacked, explains the gap — best of 16 model x cell combinations is 3.58 accuracy points under
published. Revised the honest `paper_mode` figure to address-dropped x **grouped** split
(0.9442/0.9697, random forest); M4a's random-split number is superseded but kept for provenance.
See `docs/DEVIATIONS.md` DEV-06. **D6 retired in M4b:** `scripts/run_detection.py` now groups by
address too, so the production pipeline and the ablation script agree.

### M4b — the honeypot backend and Alg. 3 `[x]`

- [x] `detection/dataset.py` — `HoneypotBackend`/`load_from_chain`, decrypted from `BC_SigRW`;
      `BitcoinHeistBackend`, `DatasetBackend` and `backend_from_config` complete the "selected by
      config, never hardcoded" interface docs/ALGORITHMS.md Alg. 3 promised
- [x] `detection/profiles.py` — `NProf`/`AProf` (DEV-28)
- [x] `detection/detector.py` — Alg. 3 lines 4-9, `DetectionModule` and the `Phase4Handoff`
      interface (Phase 4 does not exist yet — M5)
- [x] `framework/phase3_detection.py` — Alg. 3 lines 1-9 end to end from two `BC_SigRW` chains
- [x] D6 retired: `scripts/run_detection.py`'s `paper_mode` now groups by address too, matching
      `q10_leakage_ablation.py` (DEV-06 amendment)

**Exit:** `scripts/run_phase3_detection.py --seed 20260912` runs the framework's own data path
end to end — honeypot → Phase 2 → `BC_SigRW` (real pBFT consensus, two independent draws) →
Phase 3 → detection — and scores **0.8422 balanced accuracy**, between the measured 0.830
baseline and the corpus's intended 0.85 ceiling, not above it. `RESULTS.md`, `docs/DEVIATIONS.md`
DEV-28. `tests/integration/test_phase2_feeds_phase3.py` is the first test in this project where
Phase 2's output feeds Phase 3's input.

---

## M5 — Mitigation (Phase 4) `[x]`

- [x] `mitigation/state.py` — state machine, isolation, `AMsg`
- [x] `mitigation/cases.py` — Case-1 quarantine (DEV-04), Case-2 restore, Case-3 simulated (DEV-09)
- [x] `mitigation/policy.py` — `RW_amt` vs `DT-SYS_i-amt` decision object
- [x] `tests/unit/test_case3_is_inert.py` — asserts no network imports, pure function
- [x] `framework/phase4_mitigation.py`
- [x] Integration test: full Fig. 3 sequence end to end

**Exit:** all five phases wired; `test_full_sequence.py` green. Closed 2026-09-13:
`mitigation.state`'s six frozen states make illegal transitions unrepresentable (mirroring
`BlockDraft.seal()`); Case-2 restores byte-identical through `phase5_recovery.run` in both a fast
unit test and the full pBFT integration test; Case-3's inertness is enforced by
`test_case3_is_inert.py`, not by comment (DEV-09). DEV-29 records the two gaps the paper leaves
open here: which case applies, and how a detection is attributed to a system. `make test-all`:
1293 passed.

---

## M6 — Benchmarks and figures `[x]`

**Split into M6a and M6b on 2026-09-17.** M6a is the timing harness and Figs. 6(a)-(d) — a
question about our own consensus/crypto stack, answerable entirely from code already built.
M6b is Table II, Figs. 4-5, and the Ada `honest_mode` job — ML runs, a different kind of work
with a different failure mode (leakage, class balance) than the timing side. Bundling them would
have meant debugging a matplotlib figure spec through an sklearn fit.

### M6a — timing harness and Figs. 6(a)-(d) `[x]`

- [x] `bench/harness.py` — cases 1/2/3, median of N (N justified by a measured case-3 variance
      probe, not guessed), warm-up discard, marginal per-block cost
- [x] Compute, modelled network (DEV-21's `4d`/`3d` formula), index construction (DEV-05) and
      D3's serialization estimate reported as four separate columns, never summed
- [x] Q2 payload sweep (1024/4096/16384 B) at case-3, memory-footprint projected before running
- [x] `bench/emit.py` — Figs. 6(a)-(d) + a component-breakdown panel, each with sidecar JSON
- [x] `make figures` wired for the bench half (Table II / Figs. 4-5 remain M6b)

**Exit:** `make figures` produces Figs. 6(a)-(d) with sidecars; every number has a `RESULTS.md`
line (`measured` for timings, `computed` for the modelled-network and D3 columns, matching the
existing baseline convention). Variance is reported and the repeat count follows from it.

### M6b — Table II, Figs. 4-5, Ada `honest_mode` `[x]`

- [x] Wire `make repro` / `make honest` to `detection/` (M4a/M4b already built the pipelines) —
      `make repro` reproduces D6's 0.9442/0.9697 exactly; `make honest` now runs the full
      2,916,697-row `honest_mode` locally (RF/LR/DT at full scale; KNN named-and-subsampled
      rather than deferred, DEV-31), neither touches Ada
- [x] `bench/emit.py` — Table II (`emit_table2_paper_mode`/`emit_table2_honest_mode`) + Figs. 4-5
      (`emit_fig4_5`, paper-shape and baseline-annotated versions of each)
- [x] `scripts/ada_honest_mode.sbatch` on Ada, full 2.9M-row `honest_mode` — adapted to the
      account's real, discovered SLURM limits (DEV-31), one failed attempt (dropped dataset
      download, fixed with retry/resume) and one resubmission, **completed within the session**
      (job 2700090, 36m26s, all four models at 2,916,697 rows, `deferred: {}`)

**Exit:** every target in `docs/EXPERIMENTS.md` has a `measured` or `paper_reported` label. Met.

---

## M7 — Extensions (stretch) `[ ]`

- [x] Scyther model of the session protocol (DEV-14) — `verification/`, all claims verified,
      no code change needed (2026-09-18)
- [ ] Adversarial evaluation: does the detector survive feature-space evasion?
- [ ] Storage-cost analysis for on-chain backups (GAP-2) — the practicality question the paper
      never asks
- [ ] Async pBFT with realistic network latency
- [ ] Hybrid blockchain, which the paper lists as its own future work

---

## Write-up `[x]`

- [x] Report: paper summary, our implementation, reproduction results, critique, honeypot
      detection evaluation (`docs/report/report.tex` / `.pdf`, 2026-09-18)
- [x] Reproduced-vs-honest results presented side by side throughout
- [x] The five defects that matter argued in full (FLAW-2, FLAW-4, FLAW-5, DEV-26, DEV-08);
      `docs/DEVIATIONS.md` referenced for the complete list rather than reproduced entry-by-entry,
      per the report brief
