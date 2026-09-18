# Storage-cost analysis (M7-2 / GAP-2)

The paper (`docs/PAPER_NOTES.md` GAP-2) proposes storing encrypted healthcare backups on a
four-node pBFT chain and never asks how much that costs or at what scale it stops being
feasible. This is pure arithmetic over values already measured or declared elsewhere in this
project — no new code, no new benchmark runs. Every number below either cites a `RESULTS.md`
line / `docs/DEVIATIONS.md` entry, or is flagged **ASSUMPTION** with its value stated inline.

---

## 1. Inputs

| Quantity | Value | Source |
|---|---|---|
| Transaction payload size | 4096 B | `configs/chain.yaml` `transaction.payload_bytes` — DECLARED default, Q2 closed (DEV-15) |
| Transactions per block | 100 | `configs/chain.yaml` `block.transactions_per_block` — PAPER §VII value |
| Per-chunk framing overhead | 215 B | DEV-24, measured: 112 B paper-shaped record framing + 103 B indices/digest/attestation |
| Per-chunk encryption overhead (DEV-01) | 161 B | DEV-24, measured: 16 B GCM tag + 133 B wrapped key + 12 B nonce |
| Full-block overhead factor | ×1.14 | `RESULTS.md` `bench/q2-projection` (`estimate_overhead_factor`, BC\_DTBU, case-3, 4096B payload, 100 tx/block) — measured ratio of the full encoded block (header + Merkle root + struct/list encoding + framing + encryption) to the raw plaintext payload budget |
| Replication factor | ×4 | `configs/chain.yaml` `consensus.miner_nodes` — PAPER §VII, 4 miner nodes, each an independent full-chain replica (CLAUDE.md §4b) |
| Marginal compute cost / block (BC\_DTBU, case-3) | 0.0316 s | `RESULTS.md` `bench/target3-time` case\_3 BC\_DTBU `marginal[:3]` ≈ (0.0316+0.0316+0.0315)/3, dev-laptop hardware (DEV-13: not comparable to production or to the paper's hardware) |
| Measured throughput, BC\_DTBU | ~2,930–3,190 tx/s | `RESULTS.md` `bench/target3-time`, cases 1–3 |
| **ASSUMPTION** — "1 MB backup" | 1 MiB = 1,048,576 B | chosen so 1 MB / 4096 B divides exactly (256 chunks, no remainder); the paper and the task brief do not specify decimal vs. binary megabytes |
| **ASSUMPTION** — off-chain pointer size (hash-only scheme) | 128 B | sized for a UUID-based object-storage key or short URI; nothing in this codebase measures one because the hash-only scheme does not exist here |

### Why the block-level overhead is one measured ratio, not separately-derived header/Merkle figures

The task brief asks for block header size and Merkle tree overhead as separate inputs. They are
not separately measured anywhere in this codebase, and cannot be produced without writing new
code: the header's fixed-format fields (version, timestamp, nonce, two 32-byte hashes, a 65-byte
X9.62 pubkey — `crypto/ecdsa.py`) are cheap to size by inspection, but the DER-encoded ECDSA
signature is variable-length and its exact byte count is logged nowhere in this project, and the
canonical `struct` encoding (`util/serialization.py`) adds a UTF-8 field name per header field —
also never separately measured. Guessing either would be exactly the kind of unmeasured number
CLAUDE.md §2 rules out ("never claim a number we did not measure").

`bench.harness.estimate_overhead_factor` already measures the thing that matters for this
analysis — the ratio of one real, fully-encoded block (header + Merkle root + all struct/list
encoding + every transaction's framing and encryption) to the raw plaintext payload budget it
carries — at exactly the declared 4096B/100-tx configuration this analysis uses. Cross-checking
it against DEV-24's transaction-level figure shows it is consistent, not merely convenient:

```
transaction-level overhead ratio = (4096 + 215 + 161) / 4096 = 4472 / 4096 = 1.0918
full-block overhead ratio (measured)                                       = 1.14
                                                          block-level residual = 1.14 / 1.0918 ≈ 1.044
                                                    i.e. ≈ 4.8 percentage points of the measured
                                                    14% total is header/Merkle/struct-tag overhead,
                                                    amortised over the block's 100 transactions —
                                                    not chunk-level framing or encryption.
```

This analysis uses the measured ×1.14 for all "on-chain-data" totals below. It is the same figure
DEV-15's amendment already cites for the 10 MB memory-ceiling projection, reused here rather than
re-derived.

---

## 2. Per-backup on-chain cost

One patient's daily 1 MiB backup:

```
chunks per backup   = 1,048,576 B / 4,096 B/chunk        = 256 chunks (exact)
on-chain bytes/node = 1,048,576 B × 1.14 (overhead factor) = 1,195,376.64 B ≈ 1.140 MiB
on-chain bytes/cluster (×4 replicas)                       ≈ 4.560 MiB
```

This scales linearly in the number of patients and in backup frequency — the two levers the
three scenarios and the frequency sweep vary.

---

## 3. Three scenarios (daily backups, 1 MiB/patient/day)

Per-node bytes/day = patients × 1.14 MiB. Cluster = ×4. "Time to 1 TiB/node" = 1,048,576 MiB ÷
per-node MiB/day.

| Scenario | Patients | Per-node/day | Per-node/month (30d) | Per-node/year (365d) | Cluster/day (×4) | Cluster/month | Cluster/year | Time to 1 TiB/node |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Small clinic | 50 | 57.0 MiB | 1.670 GiB | 20.32 GiB | 228.0 MiB | 6.680 GiB | 81.27 GiB | ≈50.4 years |
| Medium hospital | 5,000 | 5,700 MiB (5.566 GiB) | 167.0 GiB | 1.984 TiB | 22,800 MiB (22.27 GiB) | 667.97 GiB | 7.937 TiB | ≈6.05 months |
| Large network | 50,000 | 57,000 MiB (55.66 GiB) | 1.631 TiB | 19.84 TiB | 228,000 MiB (222.7 GiB) | 6.523 TiB | 79.36 TiB | ≈18.4 days |

**Full arithmetic (per node, MiB, before ×4 replication):**

```
Small  (50 patients):     50 × 1.14 =    57.0 MiB/day
  ×30  =  1,710 MiB/month = 1,710/1024   =  1.6699  GiB/month
  ×365 = 20,805 MiB/year  = 20,805/1024  = 20.3174  GiB/year
  1,048,576 / 57     = 18,396.07 days  = 18,396.07/365 = 50.40 years

Medium (5,000 patients): 5,000 × 1.14 = 5,700 MiB/day
  ×30  =   171,000 MiB/month = 171,000/1024  = 166.992 GiB/month
  ×365 = 2,080,500 MiB/year  = 2,080,500/1024 = 2,031.74 GiB = 2,031.74/1024 = 1.9841 TiB/year
  1,048,576 / 5,700  = 183.96 days = 183.96/30.44 ≈ 6.05 months

Large  (50,000 patients): 50,000 × 1.14 = 57,000 MiB/day
  ×30  = 1,710,000 MiB/month = 1,710,000/1024 = 1,669.92 GiB = 1,669.92/1024 = 1.6308 TiB/month
  ×365 = 20,805,000 MiB/year = 20,805,000/1024 = 20,317.4 GiB = 20,317.4/1024 = 19.841 TiB/year
  1,048,576 / 57,000 = 18.396 days ≈ 2.6 weeks
```

Cluster columns are every per-node figure above ×4 (four independent full-chain replicas, no
shared storage — CLAUDE.md §4b).

---

## 4. The lever: backup frequency (medium hospital, 5,000 patients)

Holding scenario size fixed and varying how often the *whole* hospital's patients are backed up.
Per-cycle on-chain cost (per node) is the same 5,700 MiB regardless of cycle length — what
changes is how many cycles happen per year.

| Frequency | Cycles/year | Per-node/year | Time to 1 TiB/node |
|---|---:|---:|---:|
| Daily | 365 | 2,080,500 MiB = 1.984 TiB | ≈6.05 months |
| Weekly | 52 | 296,400 MiB = 289.45 GiB (0.2827 TiB) | ≈3.53 years |
| Monthly | 12 | 68,400 MiB = 66.80 GiB | ≈15.34 years |

```
Daily:   365 × 5,700 = 2,080,500 MiB/year  (as in §3)
Weekly:   52 × 5,700 =   296,400 MiB/year  = 296,400/1024 = 289.45 GiB = 289.45/1024 = 0.2827 TiB
Monthly:  12 × 5,700 =    68,400 MiB/year  =  68,400/1024 =  66.80 GiB

Ratio daily:weekly:monthly = 365:52:12 ≈ 30.4 : 4.33 : 1
  → daily backups cost ~7.0x weekly, ~30.4x monthly, in chain growth, for identical clinical
    content per event.

Time to 1 TiB/node:
  Weekly:  1,048,576 MiB / (5,700 MiB/week)  = 183.96 weeks × 7  = 1,287.7 days  ≈ 3.53 years
  Monthly: 1,048,576 MiB / (5,700 MiB/month) = 183.96 months / 12                ≈ 15.33 years
```

Backup frequency is the single largest lever available to a real deployment — larger than any
plausible payload-size tuning (DEV-15's sweep found payload size costs 1.55–2.2x across a 16x
range) — because it scales the *number* of on-chain events directly, not their size.

---

## 5. On-chain-data vs. on-chain-hash-off-chain-data

**On-chain-data** (what the paper builds): the full encrypted payload, chunked, lives on every
replica's chain forever. Per-backup on-chain footprint (per node) = payload × 1.14 (§2) —
1,195,376.64 B for a 1 MiB backup.

**On-chain-hash-off-chain-data**: only a content digest and a pointer to externally-stored
ciphertext go on-chain. The chain still lets `SYS_i` (or an auditor) detect tampering with the
off-chain blob — recomputing the digest and comparing it to the immutable on-chain record is
exactly as tamper-evident as the paper's own design, because the paper's own immutability
guarantee already rests on the block's Merkle root and signature chain, not on the payload's raw
bytes being large. What it does **not** preserve is on-chain *availability*: if the off-chain
store is lost, the digest alone cannot reconstruct the backup, whereas the paper's on-chain-data
design can always restore from the chain itself. That is the trade-off; this analysis states it
rather than picking a side, per CLAUDE.md's rule against silently "fixing" the paper.

Per-backup on-chain footprint under hash-only, reusing DEV-24's measured 215+161 = 376 B total
directly (same framing + attestation + encryption a hash-only record still needs, per DEV-23),
plus the stated 128 B pointer assumption:

```
hash-only on-chain bytes/backup/node = 376 B (measured, DEV-24) + 128 B (assumption, pointer) = 504 B

storage ratio (1 MiB backup) = 1,195,376.64 / 504 ≈ 2,371×
```

This ratio is not fixed: on-chain-data is O(payload size) and on-chain-hash is O(1) per backup
regardless of payload size. At a hypothetical 50 MiB backup (e.g. an imaging study), on-chain-data
would be 50× larger while on-chain-hash's 504 B is unchanged, widening the ratio to ≈118,500×. The
paper's design gets proportionally worse as backups get larger, not just larger in absolute terms
— the opposite of what "just put it on-chain" implicitly assumes scales.

---

## 6. Compute-cost implication (large-network scenario)

```
chunks/day = 50,000 patients × 256 chunks/patient (1,048,576 / 4,096, exact) = 12,800,000 chunks/day
blocks/day = 12,800,000 / 100 tx-per-block                                    = 128,000 blocks/day

consensus seconds/day = 128,000 blocks × 0.0316 s/block (measured marginal cost, BC_DTBU, case-3)
                       = 4,044.8 s/day  ≈ 67.4 minutes/day  ≈ 4.68% of a 24h day
```

That is comfortably inside one core's daily budget on the same 8 GB dev laptop the measurement
came from (DEV-13: not comparable to the paper's hardware, and not comparable to a real production
cluster either — no network, disk I/O, or production-hardware factor is measured here). The
sustained rate this requires — 128,000 / 86,400 ≈ 1.48 blocks/s on average, or ≈17.8 blocks/s if
compressed into a 2-hour nightly backup window — sits inside the measured achievable throughput
(BC\_DTBU: ~2,930–3,190 tx/s ≈ 29–32 blocks/s at 100 tx/block, `RESULTS.md` `bench/target3-time`).
Compute is feasible on this measured hardware; the bottleneck this analysis exists to surface is
the storage-growth numbers in §3, not consensus throughput.

---

## 7. Summary of assumptions (for reproducibility)

1. 1 "MB" backup = 1 MiB = 1,048,576 bytes.
2. Off-chain pointer for the hash-only scheme = 128 bytes (nothing measures this; no such scheme
   exists in this codebase).
3. Full-block overhead factor (1.14) measured at the declared 4096B/100-tx configuration is
   applied uniformly to aggregate daily/monthly/yearly totals, rather than recomputing a
   partially-full-block overhead for every possible chunk/block boundary — a second-order effect
   given how well 100 tx already amortises the fixed header cost (§1).
4. Marginal per-block compute cost (0.0316 s) is BC\_DTBU's case-3 dev-laptop figure (DEV-13
   applies); it is not a production or paper-hardware number.
5. Backup content and compressibility are out of scope; "1 MiB" is treated as already the
   ciphertext-bound size fed to `blockchain.backup.split()` (DEV-24), not a pre-encryption
   estimate.
