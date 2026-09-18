# Session 2026-09-19-01 — M7-2: storage-cost analysis

**Milestone:** M7-2 · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/DEVIATIONS.md` DEV-01/DEV-15/DEV-24, `docs/EXPERIMENTS.md` Targets 3-4, `RESULTS.md` tail
(M6a bench lines), `configs/chain.yaml`, `configs/bench.yaml`, `docs/PAPER_NOTES.md` GAP-2,
`docs/ROADMAP.md` M7, `src/bsfr_sh/bench/harness.py` (`estimate_overhead_factor`,
`projected_chain_bytes`), `src/bsfr_sh/crypto/ecdsa.py` (pubkey/signature encoding, to check
whether header-field byte sizes are separately measured anywhere — they are not),
`docs/report/report.tex` §Critique (structure/style to match) · **Duration:** _

---

## Brief *(written before any work)*

**Task:** Compute the on-chain storage cost of BSFR-SH's backup design from already-measured
values (no new benchmarks, no new code), across three deployment scales and three backup
frequencies, compare it against a hash-only off-chain alternative, and note the compute-cost
implication at the largest scale — writing the arithmetic to `docs/STORAGE_ANALYSIS.md` and a
short summary subsection into the report.

**Exit condition:** `docs/STORAGE_ANALYSIS.md` committed with full arithmetic; report gains a new
subsection (three-scenario table, hash-only paragraph, one sentence on compute cost); `make test`
and `make lint` still green; every number in the table traces to a measured value or a stated
assumption.

**Out of scope:** No code changes, no new benchmark runs, no adversarial evasion work, no slides.

**Prior context needed:** DEV-01 (hybrid encryption framing), DEV-15 (Q2 closed — declared
4096B payload, measured overhead factor ~1.14 for a full 100-tx block), DEV-24 (per-chunk framing
215B + encryption overhead 161B, measured), `configs/chain.yaml` (100 tx/block, PAPER value),
`RESULTS.md` M6a lines (`bench/target3-time` marginal costs, `bench/q2-projection` overhead
factor).

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/DEVIATIONS.md
DEV-01 (hybrid encryption) and the Q2 closure in PROJECT_STATE.md.
docs/EXPERIMENTS.md Targets 3-4 for the measured block sizes. RESULTS.md
tail for the M6a timing numbers.

Create the session file from the template and fill the brief first.

TASK — M7-2. Storage-cost analysis. The practicality question the paper
never asks.

[full task text as given by the user — establish per-backup cost from
measured values (payload size, DEV-01/DEV-24 overhead, block header size,
Merkle overhead, 4x replication); model three scenarios (small/medium/large,
daily backups, 1MB/patient) with daily/monthly/yearly growth, cluster
totals, time to 1TB/node; vary backup frequency (daily/weekly/monthly) for
the medium scenario; compare on-chain-data vs. on-chain-hash-off-chain-data
and compute the storage ratio, stating the trade-off rather than advocating;
note the compute-cost implication at the large-network scenario's daily
block count against M6a's measured marginal per-block cost; write one new
report subsection (table + hash-only paragraph + one sentence on compute
cost) and a standalone docs/STORAGE_ANALYSIS.md with the full arithmetic.
No new code — use the calculator.

EXIT CONDITION: docs/STORAGE_ANALYSIS.md committed with full arithmetic.
Report updated with the new subsection. make test and make lint still
green. Three-scenario table exists, every number traces to a measured value
or a stated assumption.

OUT OF SCOPE: No code changes. No adversarial evasion. No slides.

END OF SESSION: Session file. Rewrite PROJECT_STATE.md. Tick M7-2 in
ROADMAP. Commit and push.]
```

---

## What was done

- `docs/STORAGE_ANALYSIS.md` (new) — full arithmetic: per-backup on-chain cost derivation from
  DEV-01/DEV-15/DEV-24's measured framing/encryption/overhead-factor figures, the three-scenario
  table (small/medium/large clinic, daily/monthly/yearly, ×4 replication, time to 1 TiB/node), the
  medium-hospital frequency sensitivity (daily/weekly/monthly), the on-chain-data vs.
  on-chain-hash-off-chain-data comparison and storage ratio, and the compute-cost cross-check
  against M6a's measured marginal per-block cost and measured TPS. **AI-generated.**
- `docs/report/report.tex` — new `\subsection{GAP-2 -- storage-cost analysis}` inserted into
  §Critique, immediately before "What the paper gets right" (matching the section's existing
  FLAW-N/DEV-NN subsection convention): the three-scenario table, one paragraph on the hash-only
  alternative and its trade-off, one sentence on the frequency lever, one sentence on compute
  cost. Recompiled via `tectonic` — clean, no new overfull/underfull warnings. **AI-generated.**
- `docs/PAPER_NOTES.md` — GAP-2's entry gets a one-line pointer to `docs/STORAGE_ANALYSIS.md` now
  that it is answered rather than open. **AI-generated.**
- `docs/ROADMAP.md`, `PROJECT_STATE.md` — see Handover. **AI-generated.**

## Findings

- **The codebase has no separately measured block-header-only or Merkle-only byte count**, and
  none can be produced without writing new code: header field sizes are fixed-format (version,
  timestamp, nonce, two 32-byte hashes, a 65-byte pubkey) but the DER-encoded ECDSA signature is
  variable-length and its exact byte count is never logged anywhere in the codebase or its docs
  (checked `crypto/ecdsa.py`, `RESULTS.md`, all of `docs/DEVIATIONS.md` for "byte" near
  "signature" — nothing). Reconstructing it field-by-field from the canonical-encoding tag format
  in `util/serialization.py` would mean guessing the DER signature's exact length and the
  struct-encoding's per-field-name overhead — i.e. estimating, which CLAUDE.md's "never claim a
  number we did not measure" rules out. **Decision:** use `estimate_overhead_factor`'s measured
  ratio (~1.14, `RESULTS.md` `bench/q2-projection`) as the single figure for "header + Merkle root
  + struct/list encoding overhead, amortised over a 100-tx block" — this is a real measured
  artifact of the same run DEV-15's amendment already cites, not a new estimate. DEV-24's 215+161
  byte figures are used directly for the per-chunk (transaction-level) share of that same
  overhead, and are consistent with it: 4472/4096 = 1.092 at the transaction level, vs. 1.14 for
  the full block, so ~4.8 percentage points of the measured 14% is block-level (header/Merkle/
  struct-tag) overhead, not chunk-level. This decomposition is stated in
  `docs/STORAGE_ANALYSIS.md` rather than assumed away.
- **1 MB is treated as 1 MiB (1,048,576 bytes)** so that "1 MB / 4096B chunk" divides exactly
  (256 chunks, no remainder) rather than needing a ceiling correction — stated explicitly as an
  assumption, since the paper and the task brief do not specify decimal vs. binary megabytes.
- **The hash-only alternative reuses DEV-24's 215+161 = 376-byte total directly**, rather than
  re-deriving digest/attestation/pointer sizes from scratch: a hash-only record needs the same
  framing and the same per-backup attestation signature DEV-23 already requires, just with the
  chunked payload replaced by a fixed-size off-chain pointer (128 bytes, stated assumption — sized
  for a UUID-based object-storage key or short URI). This keeps every non-assumption byte in the
  comparison traceable to the same measured constant already used on the other side of the ratio.
- **The storage ratio is not fixed — it widens with backup size.** On-chain-hash is O(1) per
  backup regardless of payload size; on-chain-data is O(payload). At 1 MB the ratio is ~2,371×; at
  a hypothetical 50 MB payload (e.g. an imaging study) it would be ~50× larger again, ~118,000×,
  with no change to the hash-only side's cost. Worth stating because it means the paper's
  architecture gets *worse*, not proportionally worse, as backup size grows — the opposite of
  what "just store everything on-chain" implicitly assumes scales.
- **Compute cost at the large-network scenario is comfortably feasible on the measured dev-laptop
  hardware** (~4,045 s/day, ~4.7% of a day, cross-checked against M6a's measured ~2,930-3,190 tx/s
  BC_DTBU throughput — even a compressed 2-hour nightly window's required rate sits inside that
  measured ceiling) — but this is compute only, on hardware nothing like a production cluster's,
  and says nothing about network, disk I/O, or the storage-growth numbers above, which are the
  actual bottleneck this analysis exists to surface. Stated as a scoped, not a general, feasibility
  claim.

## Numbers

No new benchmark runs this session — this is arithmetic over M6a's and M1/M3a's already-recorded
`RESULTS.md` values (`bench/target3-time`, `bench/q2-payload-sweep`, `bench/q2-projection`) and
`docs/DEVIATIONS.md` DEV-01/DEV-15/DEV-24's measured byte counts. Nothing appended to
`RESULTS.md` — correctly, per the M7-1 precedent (formal/derived work, not a new measurement).
Full derivation: `docs/STORAGE_ANALYSIS.md`.

## Deviations opened or changed

None. This session does not depart from the paper or from any prior deviation; it answers
`docs/PAPER_NOTES.md` GAP-2 (storage impracticality, flagged at M0) using values already declared
under DEV-15/DEV-24. No DEV-NN entry opened — there is no new implementation choice to record,
only an analysis of existing ones.

---

## Handover *(written last)*

**State after:** `docs/STORAGE_ANALYSIS.md` exists with the full three-scenario table, the
frequency-sensitivity table, the on-chain-data vs. hash-only comparison and ratio, and the
compute-cost cross-check. The report's §Critique gained the matching subsection. GAP-2
(`docs/PAPER_NOTES.md`) is answered, not just flagged. `make test` and `make lint` reconfirmed
green (no source touched).

**Next task:** M7 has three remaining stretch items, none required for the deliverable
(`docs/ROADMAP.md` M7): (1) adversarial feature-space evasion for the honeypot detector (Q4,
open), (2) async pBFT with realistic network latency (DEV-20 item 2, DEV-21), (3) hybrid
blockchain (paper's own stated future work). None follows naturally from M7-2; pick one or stop —
the core deliverable has been complete since before M7-1.

**New blockers:** None.

**Questions opened / closed:** No PROJECT_STATE Q-numbers touched. GAP-2 (`docs/PAPER_NOTES.md`,
not a numbered Q) is now answered with a citation to `docs/STORAGE_ANALYSIS.md`.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run — N/A, no new runs this session
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated if the paper was departed from — N/A, no departure
- [x] Committed, message explains *why*
