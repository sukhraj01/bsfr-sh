# Notation

Paper Table I symbols → code identifiers. Reconstructed from Algorithms 1–5 and §IV–§V, since
Table I itself is a raster figure in the PDF.

**Rule:** if you introduce a new protocol symbol, add it here before using it in code.

## Entities

| Symbol | Meaning | Code |
|---|---|---|
| `SYS_i` | i-th protected system in the smart healthcare network | `framework.entities.System` |
| `CS_l` | l-th cloud server in the P2P cloud server network | `framework.entities.CloudServer` |
| `P2PCS` | peer-to-peer cloud server network | `consensus.network.P2PCSNetwork` |
| `HP_RW` | ransomware honeypot | synthesis: `honeypot.collector.Honeypot`; its session side: `framework.entities.HoneypotNode` (`honeypot/` may not import `framework/`) |
| `DM_CSl` | detection module hosted on `CS_l` | `detection.detector.DetectionModule` |
| `L` | pBFT leader (primary) for a consensus round | `Membership.primary(view)` — round-robin, not a class |
| `A` | adversary | threat model only, no class |
| `CS'_l` | cloud server holding the key a backup was encrypted to — Phase 1's collector (DEV-25) | a `CloudServer` in the key-holder role of `recovery.restore` |

## Data

| Symbol | Meaning | Code |
|---|---|---|
| `DT_BU` | healthcare data backup payload | whole: `bytes` on `System`; one chunk per transaction: `blockchain.transaction.BackupPayload` (DEV-24) |
| — | payload digest `H(DT_BU)`, taken on `SYS_i` before shipping (DEV-23, ours) | `BackupPayload.payload_digest`, `blockchain.backup.payload_digest()` |
| — | `SYS_i`'s attestation over the digest (DEV-23, ours) | `BackupPayload.attestation`, `blockchain.backup.BackupManifest` |
| `DT_RW` | raw ransomware data from honeypot | `honeypot.collector.RawSample` |
| `DT_RWC` | cleaned/pre-processed ransomware data | `honeypot.preprocess.CleanSample` |
| `Sig_RW` | ransomware sample signature (content digest) | `honeypot.signatures.SampleSignature` |
| `FT_RW` | ransomware behavioural feature vector | `honeypot.features.FeatureVector` |
| `InfSYS_i` | infected system record | `mitigation.state.InfectedSystem` |
| `AMsg` | alert message | `mitigation.state.AlertMessage` |
| `RW_amt` | ransom amount demanded | `mitigation.policy.ransom_amount` |
| `DT-SYS_i-amt` | assessed value of data on `SYS_i` | `mitigation.policy.data_value` |
| `K_d` | decryption key held by adversary | `mitigation.policy` (simulated only) |

## Chains and blocks

| Symbol | Meaning | Code |
|---|---|---|
| `BC_DTBU` | blockchain of data backups | `Chain(name="BC_DTBU")` |
| `BC_SigRW` | blockchain of ransomware signatures | `Chain(name="BC_SigRW")` |
| `β_j` | j-th block | `blockchain.block.Block` |
| `βVer_j` | block version | `Block.version` |
| `TS`, `TSDT_j` | block timestamp | `Block.timestamp` |
| `RN`, `RNDT_j` | random nonce | `Block.nonce` |
| `MTR`, `MTRDT_j` | Merkle tree root over the block's transactions | `Block.merkle_root` |
| `OID` | owner identity | `Block.owner_id` |
| `OKU` | owner public key | `Block.owner_pubkey` |
| `Tx_i`, `Tx_m` | transaction | `blockchain.transaction.Transaction` |
| `E_KU_CSl(Tx)` | transaction encrypted for `CS_l` | `Transaction.ciphertext` |
| `N_Tx` | transactions per block, ransomware chain | `config.tx_per_block` |
| `N_dTx` | transactions per block, backup chain | `config.tx_per_block` |
| `HC_βj` | hash of current block | `Block.current_hash` |
| `HP_βj-1` | hash of previous block | `Block.prev_hash` |
| `Sig_βj` | ECDSA signature over the block by its creator | `Block.signature` |

Paper uses `HP` for both "honeypot" (`HP_RW`) and "previous block hash" (`HP_βj-1`). In code
these are `Honeypot` and `Block.prev_hash` respectively — never abbreviate either to `hp`.

## Keys

| Symbol | Meaning | Code |
|---|---|---|
| `KU_CSl` | public key of `CS_l` | `CloudServer.public_key` |
| `KU_SYSi` | public key of `SYS_i`, which session establishment already requires; it also verifies the DEV-23 attestation (that use is ours) | `System.public_key` |
| `SK_{E_A, E_B}` | session key between entities A and B | `crypto.session.SessionKey` |
| `SK_{CS_l, SYS_i}` | cloud server ↔ system session key | established in Phase 1 |
| `SK_{CS_l, HP_RW}` | cloud server ↔ honeypot session key | established in Phase 2 |
| `SK_{CS'_l, CS_l}` | cloud server ↔ cloud server session key | used in Alg. 5 line 4 |

## Consensus

Castro–Liskov symbols the paper does not define but M2b needs. Not in Table I.

| Symbol | Meaning | Code |
|---|---|---|
| `n`, `f` | replicas, and byzantine replicas tolerated; `n = 3f + 1` | `Membership.n`, `Membership.f` |
| `v` | view number; the primary of `v` is `ids[v mod n]` | `Replica.view` |
| `s` | sequence number = the chain height the block will occupy | `PrePrepare.seq` |
| `d` | block digest = `HC_βj` | `PrePrepare.digest` |
| `⟨PRE-PREPARE, v, s, d⟩` | primary's signed proposal; block travels beside it | `protocol.PrePrepare` in a `protocol.Proposal` |
| `⟨PREPARE, v, s, d, i⟩` / `⟨COMMIT, v, s, d, i⟩` | replica `i`'s signed votes | `protocol.Prepare` / `protocol.Commit` |
| `P` | prepared certificate: pre-prepare + `2f` matching prepares | `protocol.PreparedCertificate` |
| `C` | commit certificate: `2f+1` matching commits | `protocol.CommitCertificate` |
| `⟨VIEW-CHANGE, v+1, h, C, P, i⟩` | leave for view `v+1` with evidence | `protocol.ViewChange` |
| `⟨NEW-VIEW, v+1, V, O⟩` | new primary's justification and re-proposals | `protocol.NewView` |

## ML

| Symbol | Meaning | Code |
|---|---|---|
| `NProf` | normal profile (benign definition) | `detection.profiles.NormalProfile` |
| `AProf` | abnormal profile (ransomware definition) | `detection.profiles.AbnormalProfile` |
| `RFor` | random forest | `detection.models.RANDOM_FOREST` |
| `LReg` | logistic regression | `detection.models.LOGISTIC_REGRESSION` |
| `DTree` | decision tree | `detection.models.DECISION_TREE` |
| `KNN` | k-nearest neighbours | `detection.models.KNN` |
| `RW` | ransomware (detected instance) | `detection.detector.Detection` |
