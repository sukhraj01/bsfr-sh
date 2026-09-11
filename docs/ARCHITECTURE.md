# Architecture

How our modules fit together, and the designs we supply where the paper is silent.

---

## Dependency direction

```
util  <-  crypto  <-  blockchain  <-  consensus
                          ^              ^
                          |              |
   honeypot ------------->+              |
   detection ------------>+              |
   mitigation ----------->+              |
   recovery ------------->+              |
                          |              |
                     framework  <--------+
                          ^
                          |
                    bench, scripts
```

Nothing depends on `framework`, `bench`, or `scripts`. `crypto` has no internal dependencies
beyond `util`. Violations of this are architectural bugs — fix the direction, don't add a
back-import.

---

## `crypto/`

| Module | Contents |
|---|---|
| `hashing.py` | `h(bytes) -> bytes` — SHA-256, the single hashing entry point |
| `merkle.py` | Merkle tree over transaction digests, root + inclusion proofs |
| `ecdsa.py` | secp256r1 keygen, sign, verify (paper mandates ECDSA, ref [23]) |
| `aead.py` | AES-256-GCM for payloads |
| `kem.py` | ECIES-style key wrapping: EC public key wraps the AEAD data key |
| `session.py` | ECDH + ECDSA-signed transcript, timestamps, nonces (fills GAP-7) |
| `channel.py` | messages under an established `SK` (M3a): AES-256-GCM; the AAD binds session, direction, protocol step and a strictly increasing counter, so a message cannot be moved to another session, reflected, re-purposed or replayed |

**Hashing detail.** `hashing.h()` is the bare SHA-256 primitive; everything positional goes
through `tagged_h(domain, *parts)`, which length-prefixes each part via the canonical encoder. A
transaction digest, a block-header digest, a Merkle leaf and a Merkle node therefore never share a
pre-image, so a digest computed for one position cannot be replayed in another.

**Merkle detail.** Odd node counts duplicate the last hash (Bitcoin convention), *and* the leaf
count is bound into the root. Duplication alone is not injective — `[a, b, c]` and `[a, b, c, c]`
build the same tree and the same root (CVE-2012-2459), which would leave `MTR` unable to
distinguish two different transaction lists. See DEV-11.

**Session establishment (GAP-7).** The paper defers to "any standard mechanism." Ours:

```
A -> B : ID_A, ID_B, N_A, TS_A, g^a,
         Sig_A(tag1 || ID_A || ID_B || N_A || TS_A || g^a)
B -> A : ID_B, ID_A, N_B, TS_B, g^b,
         Sig_B(tag2 || ID_B || ID_A || N_B || TS_B || g^b || N_A || g^a)
both   : SK = HKDF(g^ab, info = tag_sk || ID_A || ID_B || N_A || N_B || g^a || g^b)
```

Two details are load-bearing and were both missing from the first version of this sketch — see the
M1 amendment in DEV-02 for the attacks they stop:

* **A's signature names B.** Without `ID_B` inside it, A's opening is valid for *every* cloud
  server, and a captured message replays to a different one as a genuine opening from A.
* **A nonce cache, not just a timestamp window.** The window only bounds the replay interval.
  `Responder` remembers `(peer_id, nonce)` for `2 x timestamp_window_s` and rejects repeats.

`tag1`/`tag2`/`tag_sk` are distinct domain separators, so neither signature fits the other's slot.
With those, the protocol gives what §V-1 claims: freshness from nonces and timestamps, per-session
distinct keys, mutual authentication from the signed transcript, and replay / MITM / impersonation
resistance. Timestamp window is configurable, default 30 s.

---

## `blockchain/`

`Transaction` (frozen dataclass): `tx_id`, `payload_type`, `ciphertext`, `wrapped_key`, `nonce`,
`digest`, `created_at`.

`Block` (frozen after seal): `version`, `timestamp`, `nonce`, `merkle_root`, `owner_id`,
`owner_pubkey`, `transactions`, `prev_hash`, `current_hash`, `signature`. Field order matches the
paper's Alg. 1 line 3 / Alg. 2 line 8 exactly, and canonical serialization follows that order.

`Chain`: genesis, append-with-validation, integrity walk, iteration. Two independent instances —
`BC_DTBU` and `BC_SigRW` — never sharing node sets or state.

Validation on append checks, in order: prev_hash linkage, Merkle root recomputation, current_hash
recomputation, ECDSA signature under `owner_pubkey`, timestamp. `Chain.verify_block(height)` (M3a)
re-runs the per-block part on stored state for a reader that is about to trust one block.

`backup.py` (M3a) is the `DT_BU` contract between Phase 1 and Phase 5, kept in one module because
each half is only correct relative to the other: `split`/`reassemble` (DEV-24: explicit chunk
indices, never block order) and `attest`/`verify_restored` (DEV-23: `SYS_i`'s signed payload
digest). `BackupPayload` in `transaction.py` carries one chunk.

**Two block types, not one.** `current_hash` and `signature` are header fields computed over the
other header fields, so a single dataclass holding all ten can hold a digest that does not match
what it digests. `BlockDraft` has no `current_hash` and no `signature` fields at all; `Block` is
produced only by `BlockDraft.seal()` and **stores neither derived digest** — `merkle_root` and
`current_hash` are computed from the stored fields on access. There is no assignment through
which they could disagree. The signature is the one derived field that must be stored, and it is
verified in `Block.__post_init__`, so a `Block` with an invalid signature cannot exist either.

`Sig_βj` covers `BlockPart.SIGN` — every header field except `signature` itself. See the
`blockchain/block.py` docstring for why the full set rather than `current_hash` alone.

**`RN` is inert.** The paper's header carries a random nonce. Under proof-of-work that is the
mining counter; BSFR-SH uses pBFT, where blocks are committed by a `2f+1` quorum and there is
nothing to mine. The field is kept for header fidelity and has no consensus role, no difficulty
target and no validation rule. Nothing should ever loop over it looking for leading zeros.

**Timestamps** are non-decreasing within a tolerance, not strictly monotonic, and the tolerance is
the same configured value `crypto.session` uses — see DEV-17.

---

## `consensus/`

pBFT per Castro & Liskov (paper ref [24]). Four miner nodes as in §VII, so `n = 4`, `f = 1`,
commit threshold `2f + 1 = 3` (DEV-10). One `Cluster` per chain — `BC_DTBU` and `BC_SigRW` each
get their own bus, replicas and `Chain` instances.

| Module | Contents | Depends on |
|---|---|---|
| `network.py` | `P2PCSNetwork` — discrete-event bus on a **simulated clock**; per-message delay (config, default 0), per-sender `LinkFaults` (drop, delay, duplicate, jitter/reorder), timers | nothing internal |
| `protocol.py` | signed messages (`PrePrepare`/`Prepare`/`Commit`, `ViewChange`, `NewView`), `Proposal` (pre-prepare + block), `Membership` and quorum sizes, certificate verification | `crypto`, `blockchain`, `util` |
| `view_change.py` | build/verify view-changes and new-views, the deterministic re-proposal rule | `protocol` |
| `pbft.py` | `Replica` state machine, `PBFTPolicy`, the `Behaviour` hook, `Cluster` builder | all of the above |

`protocol.py` exists so that `pbft` and `view_change` can share message types without importing
each other. `network.py` carries opaque payloads and must never learn what a pBFT message is —
pinned by `test_module_boundaries.py`, and what keeps it swappable for M7's async bus.

**Signed bodies (DEV-19).** Every normal-case signature covers `(chain, view, seq, digest,
replica_id)` under a per-message-type domain. A pre-prepare signs the digest only; the block
travels beside it in a `Proposal` and is accepted only if `block.current_hash == digest` (Q7).

**Consensus decides whether, `Chain` decides valid.** A replica prepares a block only if its own
`Chain.check_append()` accepts it — the same code `append()` runs — and commits by calling
`append()`. There is no second definition of block validity in the protocol layer.

**Who builds the block (DEV-22).** The collecting `CS_l` encrypts transactions and submits them
as a `ClientRequest`; the view's primary assembles and signs `β_j`. `seq` is the chain height, and
one height is in flight at a time.

**View change (DEV-20, reduced).** Timeout → `ViewChange` carrying prepared certificates and a
commit certificate proving the sender's height → `NewView` from the next primary on `2f+1` →
receivers recompute the forced re-proposal and reject a mismatch. Omitted from Castro–Liskov:
checkpoint messages, state transfer, pipelining, null requests, retransmission — with costs in
DEV-20.

**Latency (DEV-21).** The bus never sleeps. Delay moves the simulated clock (`network.now`), not
wall-clock, so M6 reads measured compute and modelled network time separately.

**Byzantine behaviours** are test fixtures (`tests/unit/pbft_harness.py`): silent, equivocating,
wrong-signature, stale-view, plus a colluding pair used to pin the `f` bound. Each is a
`Behaviour` set on a running `Replica`; the protocol code has no knowledge of them.

---

## `honeypot/` — the layer the paper omits (GAP-3)

The paper says "signatures and features are built" and stops. Our design:

**Sample model.** A synthesized ransomware sample is a record of an emulated infection walking
the seven kill-chain stages from §II-C. It is a *data structure*, never executable code.

**`Sig_RW` — two distinct things, deliberately separated:**
- `content_digest`: SHA-256 over the sample's canonical behavioural trace — the malware-signature
  sense, used for identification.
- `attestation`: ECDSA signature by `CS_l` over `content_digest || timestamp || collector_id` —
  the digital-signature sense, used for authenticity on-chain.

The paper conflates these under one symbol. Keeping them apart is the only way the phase makes
sense.

**`FT_RW` — behavioural feature vector.** Grounded in what the surveyed detectors ([11]–[14],
[20]) actually measure:

| Group | Features |
|---|---|
| Filesystem | files touched/s, read:write ratio, rename rate, extension-change rate, directory traversal breadth |
| Entropy | mean/variance of written-block entropy, entropy delta pre/post write |
| Crypto API | crypto call count, key-generation events, API call sequence n-grams |
| Process | child process spawns, injection attempts, privilege escalation attempts |
| Network | C2 beacon count, DNS entropy, outbound connection burst rate |
| Persistence | registry/autostart writes, shadow-copy deletion attempts, backup-path access |
| Kill-chain | stage reached, dwell time per stage |

Benign samples are generated from the same schema with distributions drawn from normal
application behaviour, so `NProf` and `AProf` are learned rather than asserted.

**This is our design, not the paper's.** Documented as DEV-03. It is what makes Phase 3 actually
consume Phase 2's output, which the paper never achieves.

---

## `detection/`

`dataset.py` exposes one interface with two backends:
- `BitcoinHeistBackend` — loads the UCI CSV, applies the paper's 90/10 resample **or** the natural
  distribution, depending on config
- `HoneypotBackend` — decrypts `BC_SigRW` and yields `FT_RW` vectors

`models.py` wraps the four required estimators with fixed hyperparameters recorded in config.
The paper reports none, so ours are declared, not inferred.

`profiles.py` builds `NProf` / `AProf` as the fitted class-conditional descriptions the paper
describes at Alg. 3 line 3.

`metrics.py` computes both metric sets: `paper_mode` (accuracy, F1 as reported) and
`honest_mode` (precision, recall, PR-AUC, MCC, confusion matrix, minority-class F1).

---

## `mitigation/` and `recovery/`

`mitigation/state.py` is an explicit state machine:
`DETECTED → ISOLATED → REMEDIATING → (RESTORED | CLEANED | POLICY_BLOCKED) → RESOLVED`.

`POLICY_BLOCKED` is where Case-3 terminates. It is a terminal simulated state.

`recovery/locator.py` finds a system's backup chunks. `scan()` is the paper's walk. `BackupIndex`
(DEV-05) is the per-system pointer index that the key holder maintains on append. `identify()`
returns the identical tuple either way. `system_id` is encrypted, so only the key holder can build
the index, and building it costs the same decryptions as a scan, paid at append time.

`recovery/restore.py` implements Alg. 5 lines 1–6 as functions over a `Chain`, a `Decryptor` and
`Channel` endpoints:

* `begin` chooses the newest complete backup.
* `request_decrypt` re-verifies each block, decrypts, and reassembles.
* `transfer` is the `CS'_l` → `CS_l` hop. It is there for fidelity (DEV-25): the paper routes
  through a second server, and we keep that even though one would do.
* `deliver` is the `CS_l` → `SYS_i` hop.
* `open_delivery` is `SYS_i`'s DEV-23 check.

Every failure raises, and none returns data.

---

## `framework/` (M3a)

Participants and phase orchestration. Depends on everything below it; nothing depends on it
(`test_module_boundaries.py::test_nothing_below_framework_imports_it`).

| Module | Contents |
|---|---|
| `entities.py` | `System` (`SYS_i`), `CloudServer` (`CS_l`), `establish_session`: an identity, a keypair, and one `crypto.channel.Channel` per established session. Thin: each entity performs its own steps and never sequences them |
| `_block_pipeline.py` | Alg. 1 lines 2–10 = Alg. 2 lines 3–10, parametrised on a payload builder and the target chain's `Cluster`. It submits transactions, never blocks (DEV-22), and waits until `f+1` replicas hold each block (the pBFT client rule) |
| `phase1_backup.py` | Alg. 1: collect over `SK`, attest (DEV-23), chunk (DEV-24), encrypt, pipeline |
| `phase5_recovery.py` | Alg. 5: request, identify, begin, decrypt at `CS'_l`, two hops, `SYS_i` verifies |

**Where a boundary bit.** `recovery/` implements Alg. 5's hops between entities that live in
`framework/`, and may not import it. So `recovery` takes a decryption callable (`Decryptor`) and
`Channel` endpoints instead of `CloudServer` objects, and `crypto.channel` sits below both.

---

## `bench/`

`harness.py` runs cases 1/2/3 (5/10/15 blocks × 100 tx) against both chains, median of N repeats,
recording per-block marginal cost as well as totals.

`emit.py` writes `results/tables/table2.csv` and the four figure files, each accompanied by a
sidecar JSON with config hash, seed, host, and timestamp.

TPS is computed as `total_tx / total_seconds` — matching the paper's own derivation, see the
FINDING in `docs/PAPER_NOTES.md`.
