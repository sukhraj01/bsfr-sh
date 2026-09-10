# Roadmap

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

**Current milestone: M1**

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

## M1 — Crypto layer `[~]`

- [ ] `crypto/hashing.py` — single SHA-256 entry point
- [ ] `crypto/merkle.py` — tree, root, inclusion proofs, odd-node duplication (DEV-11)
- [ ] `crypto/ecdsa.py` — secp256r1 keygen / sign / verify
- [ ] `crypto/aead.py` — AES-256-GCM
- [ ] `crypto/kem.py` — ECIES key wrapping (DEV-01)
- [ ] `crypto/session.py` — ECDH + signed transcript (DEV-02)
- [ ] Tests: known-answer vectors, tamper detection, replay rejection, timestamp window

**Exit:** every §V-1 property has a passing test.

---

## M2 — Blockchain + consensus `[ ]`

- [ ] `blockchain/transaction.py` — hybrid-encrypted `Transaction`
- [ ] `blockchain/block.py` — exact header field order from Alg. 1 line 3
- [ ] `blockchain/chain.py` — genesis, validated append, integrity walk
- [ ] `consensus/network.py` — in-process P2PCS message bus
- [ ] `consensus/pbft.py` — pre-prepare / prepare / commit, `2f+1`, view change (DEV-10)
- [ ] Byzantine fixtures: silent, equivocating, bad-signature, stale-view
- [ ] Tests: tampered block rejected, chain independence, threshold enforcement

**Exit:** `BC_DTBU` and `BC_SigRW` each build 15 blocks × 100 tx with 4 nodes, `f=1` tolerated.

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
