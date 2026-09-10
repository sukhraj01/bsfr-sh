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
recomputation, ECDSA signature under `owner_pubkey`, timestamp monotonicity.

---

## `consensus/`

pBFT per Castro & Liskov (paper ref [24]). Four miner nodes as in §VII, so `n = 4`, `f = 1`,
commit threshold `2f + 1 = 3`.

Three phases: pre-prepare (leader proposes) → prepare (replicas broadcast) → commit (threshold
reached). View change on leader timeout. The paper says "a threshold fraction of miners commit";
we make the threshold explicit and configurable, defaulting to the standard `2f+1`.

Byzantine node behaviours for testing: silent, equivocating, wrong-signature, stale-view. Each is
a fixture in `tests/unit/test_pbft_byzantine.py`.

Nodes run in-process with a simulated message bus by default. A `--async` mode using asyncio is
planned for realistic latency modelling but is not required for the reproduction targets.

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

`recovery/locator.py` holds `BackupIndex` (DEV-05). `recovery/restore.py` implements the
two-hop transfer of Alg. 5 lines 3–5 — the paper routes through a second cloud server `CS'_l`,
which we preserve even though a single server would do, because it is what §IV-E specifies.

---

## `bench/`

`harness.py` runs cases 1/2/3 (5/10/15 blocks × 100 tx) against both chains, median of N repeats,
recording per-block marginal cost as well as totals.

`emit.py` writes `results/tables/table2.csv` and the four figure files, each accompanied by a
sidecar JSON with config hash, seed, host, and timestamp.

TPS is computed as `total_tx / total_seconds` — matching the paper's own derivation, see the
FINDING in `docs/PAPER_NOTES.md`.
