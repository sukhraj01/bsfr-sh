# Algorithms 1–5 → Code Mapping

Every module that implements a paper algorithm step carries a docstring reference of the form
`Implements Alg. N, lines a-b.` This file is the index. Keep it in sync.

---

## Algorithm 1 — Creation of Backups of Data Through Blockchain
**Output:** `BC_DTBU` · **Module:** `framework/phase1_backup.py`

| Lines | Step | Implementation |
|---|---|---|
| 1 | `CS_l` collects `DT_BU` over `SK_{CS_l,SYS_i}` | `framework.entities.establish_session()`, then `System.ship_backup()` → `CloudServer.receive_backup()` over a `crypto.channel.Channel`; `SYS_i` attests first (DEV-23) |
| 2 | Encrypt into transactions `E_KU(Tx_m)`, m = 1..`N_dTx` | `phase1_backup.backup_transactions()`: `blockchain.backup.split()` (DEV-24) + `blockchain.transaction.encrypt_backup()` (DEV-01) |
| 3 | Assemble block `β_j` with full header | `framework._block_pipeline.batch()` per `block.transactions_per_block`; the pBFT primary's `Chain.draft_next().seal()` (DEV-22) |
| 4 | Broadcast `β_j` to P2PCS | `consensus.pbft.Cluster.submit()` → `ClientRequest` to every replica over `consensus.network.P2PCSNetwork`; the primary broadcasts the block as a `Proposal` (DEV-19, DEV-22) |
| 5 | Leader `L` runs pBFT | `consensus.pbft.Replica` — pre-prepare / prepare / commit; `L` = `Membership.primary(view)` |
| 6–10 | Threshold commit → append, else re-run consensus | commit at `2f+1` → `Chain.append()`; "re-run" = view change on timeout, `consensus.view_change` (DEV-10, DEV-20) |
| 11–15 | Terminate when all blocks added | `framework._block_pipeline.commit()` returns once `f+1` replicas hold every block (the pBFT client rule); `phase1_backup.run()` |

**Watch:** line 6 of the paper reads "commit on addition of β_i" inside the β_j loop — index typo.
Treat as β_j.

---

## Algorithm 2 — Data Collection, Signature Generation, Feature Building
**Output:** `BC_SigRW` · **Module:** `framework/phase2_collection.py`

| Lines | Step | Implementation |
|---|---|---|
| 1 | Deploy `HP_RW` | `honeypot.collector.Honeypot.deploy()`, via `framework.entities.HoneypotNode.deploy()` |
| 2 | Collect `DT_RW` over `SK_{CS_l,HP_RW}` | `Honeypot.harvest()` → `HoneypotNode.ship_samples()` → `CloudServer.receive_samples()` over a `crypto.channel.Channel` |
| 3–4 | Pre-process and clean → `DT_RWC` | `honeypot.preprocess.clean()` — five rules, **design ours, DEV-26** |
| 5 | Generate `Sig_RW` | `honeypot.signatures.build()` — digest + attestation, **design ours, DEV-03** |
| 6 | Generate `FT_RW` | `honeypot.features.build()` — 22 features, kill-chain truncated, **design ours, DEV-27** |
| 7 | Encrypt into `E_KU(Tx_i)`, i = 1..`N_Tx` | `phase2_collection.build_records()` → `blockchain.transaction.encrypt_signature_record()` |
| 8–9 | Assemble and broadcast `β_i` | `framework._block_pipeline.run()` — built in M3a, shared with Alg. 1 |
| 10–15 | pBFT round, commit or retry | `framework._block_pipeline.run()` — built in M3a, shared with Alg. 1 |
| 16–20 | Terminate when all blocks added | `phase2_collection.run()` |

Lines 3–10 are structurally identical to Alg. 1 lines 2–10. **Factor once** into
`framework/_block_pipeline.py`; do not duplicate. Only the payload builder differs.

---

## Algorithm 3 — Analysis for Ransomware Detection Through ML
**Output:** detection of `RW` · **Module:** `framework/phase3_detection.py`

| Lines | Step | Implementation |
|---|---|---|
| 1 | Decrypt `BC_SigRW` → `Sig_RW`, `FT_RW` | `detection.dataset.load_from_chain()` |
| 2 | Train `DM_CSl` on RFor / LReg / DTree / KNN | `detection.models.train_all()` |
| 3 | Build `NProf` and `AProf` | `detection.profiles.build()` |
| 4 | Start detection | `detection.detector.DetectionModule.run()` |
| 5–9 | If `RW` detected → Phase 4, else re-loop | `phase3_detection.run()` |

**Dual feature source.** Per FLAW-2, `detection.dataset` supports two backends:
- `bitcoinheist` — the paper's actual evaluation data, for reproduction
- `honeypot` — chain-sourced program features, for the framework as described

Selected by config, never hardcoded.

---

## Algorithm 4 — Mitigation of Ransomware
**Output:** mitigation of detected `RW` · **Module:** `framework/phase4_mitigation.py`

| Lines | Step | Implementation |
|---|---|---|
| 1–2 | `DM_CSl` discovers `RW` in `SYS_i` | input from Phase 3 |
| 3 | Raise `AMsg`, isolate `SYS_i` | `mitigation.state.isolate()` |
| 4 | Erase `InfSYS_i` via one of three cases | `mitigation.state.MitigationMachine` |
| 5 | **Case-1** — erase `RW` | `mitigation.cases.case1_erase()` — quarantine model, GAP-4 |
| 6 | **Case-2** — format + recover via Phase 5 | `mitigation.cases.case2_restore()` |
| 7 | **Case-3** — if `RW_amt < DT-SYS_i-amt`, pay and obtain `K_d` | `mitigation.cases.case3_simulated_payment()` |
| 8–10 | Else re-run mitigation | `phase4_mitigation.run()` |

> **Case-3 is simulated only.** It returns a `PolicyDecision` dataclass and writes an audit log
> record. It has no network access, no wallet, no transaction construction. This is enforced by
> a unit test (`tests/unit/test_case3_is_inert.py`) that asserts the module imports no network
> library and that the function is pure. See `CLAUDE.md` §2.

Note the paper's own ordering bug: line 4 says "erases `InfSYS_i` using one of the following
cases," but Case-2 and Case-3 do not erase — they restore and decrypt respectively. We model
line 4 as *remediate*, not *erase*.

---

## Algorithm 5 — Data Recovery Through Blockchain
**Output:** `DT_BU` restored · **Module:** `framework/phase5_recovery.py`

| Lines | Step | Implementation |
|---|---|---|
| 1 | Identify `SYS_i` needing recovery | `System.request_recovery()` → `CloudServer.accept_recovery_request()` (a system may name only itself), then `recovery.locator.identify()` |
| 2 | Start recovery from `BC_DTBU` | `recovery.restore.begin()` — newest complete backup |
| 3 | Request decryption of `E_KU(Tx_j)` | `recovery.restore.request_decrypt()` — re-verifies each block (`Chain.verify_block`), decrypts, reassembles by `chunk_index` (DEV-24) |
| 4 | `CS'_l` decrypts, ships to `CS_l` over `SK_{CS'_l,CS_l}` | `recovery.restore.transfer()`; `CS'_l` is the key holder (DEV-25); skipped when one server holds both roles |
| 5 | `CS_l` → `SYS_i` over `SK_{CS_l,SYS_i}` | `recovery.restore.deliver()` |
| 6 | `SYS_i` stores `DT_BU` | `System.restore()` → `recovery.restore.open_delivery()`, which checks the attested digest first (DEV-23) |
| 7–11 | Terminate on success, else continue | `phase5_recovery.run()` — returns a report or raises; not a retry loop |

**Addition (DEV-05):** the paper implies a linear scan to find a system's backups. We add
`recovery.locator.BackupIndex`, a per-system transaction index maintained on append. Falls back
to full scan if the index is cold, so behaviour matches the paper's semantics exactly. Because
`system_id` is encrypted, only the key holder can build the index (DEV-05 amendment).

**Addition (DEV-23):** Alg. 5 never checks that what `SYS_i` stores is what it backed up. `SYS_i`
attests a payload digest before Phase 1 ships it and verifies it after line 5.

---

## Sequence (Fig. 3)

The paper's sequence diagram is the integration test spec:

```
SYS_i --(1) backup--> CS_l --(2) blockchain backup--> BC_DTBU
HP_RW --(3) ransomware data--> CS_l
CS_l  --(4a,4b,4c) collect / signatures / features--> BC_SigRW
CS_l  --(5) detect--> if RW: (6) mitigate --(7) notify--> SYS_i
        (8a) isolate
        (8b) Option 1 erase | Option 2 format+restore | Option 3 simulated payment
```

`tests/integration/test_full_sequence.py` walks exactly this path end to end.
