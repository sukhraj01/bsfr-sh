# Roadmap

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

**Current milestone: M2b**

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

### M2b — Consensus `[ ]`

- [ ] `consensus/network.py` — in-process P2PCS message bus
- [ ] `consensus/pbft.py` — pre-prepare / prepare / commit, `2f+1`, view change (DEV-10)
- [ ] Byzantine fixtures: silent, equivocating, bad-signature, stale-view
- [ ] Tests: threshold enforcement, view change, `f=1` tolerated

**Exit:** `BC_DTBU` and `BC_SigRW` each build 15 blocks x 100 tx with 4 nodes, `f=1` tolerated.

---

## M3 — Phases 1, 2, 5 `[ ]`

- [ ] `framework/_block_pipeline.py` — shared Alg. 1 lines 2–10 / Alg. 2 lines 3–10
- [ ] `framework/phase1_backup.py` — Alg. 1
- [ ] `honeypot/collector.py`, `preprocess.py` — Alg. 2 lines 1–4
- [ ] `honeypot/signatures.py`, `features.py` — Alg. 2 lines 5–6 (DEV-03, the design work)
- [ ] `framework/phase2_collection.py` — Alg. 2
- [ ] `recovery/locator.py` + `BackupIndex` (DEV-05)
- [ ] `recovery/restore.py` — Alg. 5 two-hop transfer
- [ ] `framework/phase5_recovery.py` — Alg. 5
- [ ] Integration test: backup → chain → recover → byte-identical restore

**Exit:** data survives a simulated full wipe.

---

## M4 — Detection (Phase 3) `[ ]`

- [ ] `detection/dataset.py` — `BitcoinHeistBackend` + `HoneypotBackend`
- [ ] BitcoinHeist loader, `address` dropped, binary label
- [ ] `paper_mode` 90/10 resample · `honest_mode` natural balance (DEV-06)
- [ ] `detection/models.py` — RF, LR, DT, KNN with declared hyperparameters
- [ ] `detection/profiles.py` — `NProf` / `AProf`
- [ ] `detection/metrics.py` — both metric sets + constant-classifier baseline
- [ ] `detection/detector.py` — Alg. 3 real-time loop
- [ ] `framework/phase3_detection.py`

**Exit:** Table II BSFR-SH row reproduced in `paper_mode`; `honest_mode` numbers produced
alongside; baseline published.

---

## M5 — Mitigation (Phase 4) `[ ]`

- [ ] `mitigation/state.py` — state machine, isolation, `AMsg`
- [ ] `mitigation/cases.py` — Case-1 quarantine (DEV-04), Case-2 restore, Case-3 simulated (DEV-09)
- [ ] `mitigation/policy.py` — `RW_amt` vs `DT-SYS_i-amt` decision object
- [ ] `tests/unit/test_case3_is_inert.py` — asserts no network imports, pure function
- [ ] `framework/phase4_mitigation.py`
- [ ] Integration test: full Fig. 3 sequence end to end

**Exit:** all five phases wired; `test_full_sequence.py` green.

---

## M6 — Benchmarks and figures `[ ]`

- [ ] `bench/harness.py` — cases 1/2/3, median of N, warm-up discard, marginal cost
- [ ] `bench/emit.py` — tables + six figures + sidecar JSON
- [ ] `make repro`, `make honest`, `make figures`
- [ ] Reproduce Figs. 6(a)–(d) trends; verify concavity and chain-cost gap
- [ ] Ada job script for full-scale ML runs

**Exit:** every target in `docs/EXPERIMENTS.md` has a `measured` or `paper_reported` label.

---

## M7 — Extensions (stretch) `[ ]`

- [ ] Scyther model of the session protocol (DEV-14)
- [ ] Adversarial evaluation: does the detector survive feature-space evasion?
- [ ] Storage-cost analysis for on-chain backups (GAP-2) — the practicality question the paper
      never asks
- [ ] Async pBFT with realistic network latency
- [ ] Hybrid blockchain, which the paper lists as its own future work

---

## Write-up

- [ ] Report: paper summary, our implementation, reproduction results, critique, extensions
- [ ] Reproduced-vs-honest results presented side by side throughout
- [ ] Every deviation in `docs/DEVIATIONS.md` justified in the report
