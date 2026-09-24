# Session 2026-09-24-01 — M7-4: consensus comparison, pBFT vs Raft

**Milestone:** M7-4 (stretch) · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/ARCHITECTURE.md` §consensus, `docs/PAPER_NOTES.md` §V-3 (FLAW-5), `docs/DEVIATIONS.md`
DEV-10 and DEV-20, `consensus/{network,protocol,pbft,view_change}.py`, `blockchain/chain.py`,
`framework/_block_pipeline.py`, `bench/harness.py`, `configs/{chain,bench}.yaml`,
`tests/unit/pbft_harness.py`, `docs/EXPERIMENTS.md` Targets 3-4 · **Duration:** _

---

## Brief *(written before any work)*

**Task:** implement a simplified Raft consensus protocol alongside pBFT, benchmark both across
the same case matrix, and demonstrate — quantitatively (message count, timing, TPS) and
qualitatively (a Byzantine-leader test) — the trade-off FLAW-5 raises but never answers: is pBFT's
Byzantine tolerance worth its cost for this deployment, or does a crash-fault-tolerant protocol
buy the same availability more cheaply at the price of trusting the leader.

**Exit condition:** `consensus/raft.py` exists and passes leader-election, log-replication,
failover, crashed-follower, and Byzantine-leader tests; `framework._block_pipeline` runs against
either protocol through a common `ConsensusCluster` protocol; the bench matrix (cases 1-3, both
chains, both consensus protocols, serialization on) is measured and in `RESULTS.md`; the
Byzantine-leader test demonstrates Raft accepting divergent leader data (expected failure, not a
bug); a report section states the trade-off; `make test`/`make lint` green.

**Out of scope:** Raft log compaction, cluster membership changes, snapshotting; HotStuff/
Tendermint; touching `framework/phase1_backup.py` or `phase2_collection.py` (production phases
stay pBFT-only per the paper); recompiling `docs/report/report.pdf` (pre-existing blocker,
unrelated to this task — LaTeX toolchain unavailable in this environment).

**Prior context needed:** DEV-10 (pBFT threshold), DEV-19 (message format/signing), DEV-20
(view-change reduction and its costs — Raft's own scope reductions follow the same precedent),
DEV-21 (simulated-clock bus, latency model), FLAW-5 (§V-3's broken 51%-vs-pBFT argument, the
motivating question for this session).

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. [Full M7-4 task brief: pBFT vs Raft consensus comparison — implement consensus/raft.py,
   make the block pipeline consensus-agnostic, benchmark both protocols across the case matrix
   with message-count and signature-op instrumentation, add fault-tolerance tests (crashed
   follower, Byzantine leader), write up the trade-off, update RESULTS.md/DEVIATIONS.md/
   PROJECT_STATE.md, commit and push. Full text as given by the user.]
```

---

## What was done

All AI-generated (this session), reviewed and tested against the existing suite:

- `src/bsfr_sh/consensus/raft.py` (new) — simplified Raft: leader election (randomized,
  per-cluster-seeded timeouts), log replication (`AppendEntries`), majority commit, failover.
  No ECDSA signing in the consensus path, by design. Reuses `consensus.network.P2PCSNetwork`
  unchanged and `consensus.protocol.ClientRequest`/`check_request_identity` unchanged.
- `src/bsfr_sh/consensus/interface.py` (new) — `ConsensusCluster` `Protocol`, the boundary that
  lets `framework._block_pipeline` drive either `pbft.Cluster` or `raft.RaftCluster`.
- `src/bsfr_sh/consensus/protocol.py` — renamed `_wire_block`/`_unwire_block`/`_wire_transaction`/
  `_unwire_transaction` to public names (`wire_block`, etc.) and exported them, since `raft.py`
  now needs the same block-wire encoding pBFT's `Proposal` already used. No behaviour change.
- `src/bsfr_sh/consensus/pbft.py` — added `Replica.signature_ops` (counts consensus-message
  ECDSA sign/verify calls) and `Cluster.signature_ops`/`client_confirmation_threshold()`/
  `tick_seconds()` (the last two satisfy `ConsensusCluster`).
- `src/bsfr_sh/framework/_block_pipeline.py` — `cluster` parameters retyped from
  `consensus.pbft.Cluster` to `consensus.interface.ConsensusCluster`; `_committed`/`read_chain`
  use `cluster.client_confirmation_threshold()` instead of a hardcoded `f+1`.
- `src/bsfr_sh/bench/harness.py` — `_cluster`/`run_once`/`run_case` accept either
  `pbft_policy` or `raft_policy` (both optional, mutually exclusive; every existing M6a call site
  unchanged); `RunMeasurement`/`CaseResult` gained `message_count`/`signature_ops` fields, read
  from `cluster.network.stats.sent`/`cluster.signature_ops` — no new instrumentation needed, the
  bus already counted messages.
- `configs/chain.yaml` — new `consensus.raft.*` DECLARED block (election/heartbeat timeouts).
- `scripts/run_consensus_comparison.py` (new) — the M7-4 matrix (cases 1-3, both chains, both
  protocols, serialization on, 5 repeats) plus the qualitative fault checks, mirroring
  `run_bench.py`'s sidecar/RESULTS.md-candidate-lines convention as a separate script so M6a's
  own numbers are never at risk of changing by a bit.
- `tests/unit/raft_harness.py`, `tests/unit/test_raft.py`, `tests/unit/test_raft_byzantine.py`
  (new) — election, replication, majority-required, crash tolerance (1-of-4 and 2-of-4), failover,
  pBFT/Raft content parity, `ConsensusCluster` conformance, and the byzantine-leader fork.
- `docs/ARCHITECTURE.md` §consensus, `docs/DEVIATIONS.md` DEV-32, `docs/ROADMAP.md` M7,
  `docs/report/report.tex` new §"Consensus Comparison: pBFT vs.\ Raft" (source only, not
  recompiled — pre-existing blocker), `RESULTS.md`, `PROJECT_STATE.md`.

## Findings

- **Raft's message-count advantage at `n=4` is real but modest (~60% of pBFT's count), not the
  O(n)-vs-O(n^2) asymptotic gap.** pBFT: flat 28 msgs/block every case. Raft: converges to
  ~16.8/block as one-time leader-election cost amortises (18.4 -> 17.2 -> 16.8 across cases 1-3).
  `n=4` is too small for the quadratic term to dominate — worth stating explicitly so nobody
  extrapolates the ratio to a larger deployment from this number alone.
- **The timing gap (7-11%) is much smaller than the message-count gap (~40%) — and that is the
  finding the task brief predicted might happen.** Consistent with DEV-08/DEV-21: at zero
  simulated network delay, consensus messaging is a small slice of measured wall-clock; hybrid
  encryption and (serialization-on) message encoding dominate. Cutting messages by 40% does not
  cut total time by 40% when messaging was never the bottleneck.
- **Signature-operation counting had to be scoped carefully.** Counting every `crypto.ecdsa.sign`/
  `verify` call during a block's construction+consensus+append would include block-sealing and
  `ClientRequest` signing — paid identically by both protocols — and make "Raft: zero" false. The
  counter lives on `Replica`/instrumented at the vote-creation and vote-screening call sites
  specifically, so it counts only pBFT's pre-prepare/prepare/commit signing and verification.
- **The Byzantine-leader fork needed no forged signatures or hacky internal state — standard,
  spec-compliant Raft on both ends produces it.** First attempt used a nonce-varied sibling of the
  *same* transactions (mirroring pbft_harness's `Equivocating` fixture) and the fork was real but
  underwhelming (identical `merkle_root`, only the block nonce differed). Switched to genuinely
  different transaction sets per side, which is both a stronger demonstration and a more literal
  read of "commits wrong data."
- **`LinkFaults(drop_rate=1.0)` models a silent/one-way-crashed node, not a fully-partitioned
  one** — it drops what a node *sends*, not what it receives, so a "crashed" node's own local
  chain state still catches up passively from what it receives. This is the same fault model the
  existing pBFT byzantine fixtures already use (`Silent.outgoing` returns nothing), so it is
  consistent with precedent, but worth recording: it demonstrates "the other three keep
  committing," not "the crashed node is unreachable in both directions."
- **mypy needed `ConsensusCluster`'s shared members declared as `@property`, not plain
  attributes.** A plain-attribute `Mapping[str, ReplicaLike]` protocol member requires invariant
  (read+write) compatibility, which no concrete `dict[str, Replica]` satisfies even when `Replica`
  structurally conforms to `ReplicaLike`. Read-only properties fixed it by requiring only
  covariant (read) compatibility.

## Numbers

Full matrix, qualitative checks, and interpretation: `RESULTS.md` "M7-4 — pBFT vs Raft consensus
comparison", run `20260924T045952Z-2eaa456f`, sidecar `results/logs/20260924T045952Z-2eaa456f.json`.

## Deviations opened or changed

- **DEV-32** (new) — Raft as a comparison consensus protocol, the `ConsensusCluster` abstraction,
  every scope reduction and why it doesn't matter for this comparison, the client-trust asymmetry
  (`client_confirmation_threshold`), and the full quantitative + qualitative findings.

---

## Handover *(written last)*

**State after:** `consensus/raft.py` and `consensus/interface.py` exist, tested, and lint-clean.
`framework._block_pipeline` is consensus-agnostic; production phases are still pBFT-only by
choice. The M7-4 comparison is measured and written up in `RESULTS.md`, `docs/DEVIATIONS.md`
DEV-32, and `docs/report/report.tex` (source only). `docs/ROADMAP.md` M7's only remaining item is
the optional hybrid-blockchain stretch goal.

**Next task:** Get a working LaTeX toolchain and compile `docs/report/report.pdf` — unchanged
from the last two sessions, now carrying three sessions' worth of un-rendered sections (M7-3,
the D3 supplement, and this session's M7-4 section). See `PROJECT_STATE.md` Next task for the
specific mirror/cask guidance already tried twice.

**New blockers:** none new. The LaTeX blocker is unchanged (third confirmation).

**Questions opened / closed:** none opened or closed this session (Q11 carries over unchanged).

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated if the paper was departed from
- [x] Committed, message explains *why*

## Checklist

- [ ] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [ ] `RESULTS.md` appended, one line per run
- [ ] `docs/ROADMAP.md` boxes ticked
- [ ] `docs/DEVIATIONS.md` updated if the paper was departed from
- [ ] Committed, message explains *why*
