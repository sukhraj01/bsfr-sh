"""M6a — the timing harness behind Figs. 6(a)-(d) (`docs/EXPERIMENTS.md` Targets 3-4).

What this module measures, and what it does not
-------------------------------------------------
Per `configs/bench.yaml`, the timed span is **block construction + consensus + append**, run
case-by-case (5/10/15 blocks x `block.transactions_per_block`, both chains, 4 nodes) by reusing
the same cluster machinery the consensus and M3a/M3b test suites already build
(`consensus.pbft.Cluster`, `framework._block_pipeline.commit`) — nothing here reimplements pBFT
or the pipeline.

Four costs are kept apart because none of them is comparable to the paper's number on its own:

* **compute seconds** — wall-clock, `time.perf_counter()`, around one block's construction,
  consensus round and append. This is the only thing `run_case()` measures directly.
* **modelled network seconds** — `modelled_network_seconds()`. Pure arithmetic on the bus's
  simulated-clock model (DEV-21), not a stopwatch reading. `verify_modelled_network_formula()`
  checks the arithmetic against one real run with a non-zero `message_delay_s` before it is
  trusted.
* **index construction seconds** — `BC_DTBU` only (DEV-05). Timed as its own step, after the
  blocks are committed, because `framework.phase1_backup.run()` deliberately never touches the
  index (see that module and DEV-05's M3b amendment) and nothing here should put it back.
* **D3's serialization estimate** — `estimate_d3_seconds()`. The bus passes Python objects and
  never serialises (`consensus/network.py`); this is not a gap in the harness, it is a gap in
  what the whole project's consensus numbers cover. Estimated from `util.serialization`'s own
  throughput on a real committed block, not measured from a run that actually pays the cost.

Only the first of these is `measured` in the `RESULTS.md` sense. The other three are `computed`
— arithmetic or a microbenchmark, not a stopwatch around the thing itself — and every caller that
emits a number derived from them must carry that label, per the precedent already set by the
`detection/constant-positive` baseline row in `RESULTS.md`.

Why `BC_SigRW` should run slower than `BC_DTBU`, structurally
----------------------------------------------------------------
`_sigrw_batch()` performs one extra ECDSA sign per transaction — standing in for DEV-03's
attestation, which real Phase 2 (`honeypot.signatures.build`) also pays and Phase 1 never does.
This is not injected to reproduce the paper's shape; it is the one real asymmetry between what
the two phases do per transaction, and Fig. 6(a)/(b)'s "ransomware chain is slower" property
(`docs/EXPERIMENTS.md` Target 3) is expected to fall out of it rather than being tuned to match.

Determinism
-----------
Every function here takes an explicit seed. `run_once()` derives one keypair per replica from
`seed`, and the per-block payload bytes from `seed` and the block index, so two calls with the
same arguments build byte-identical clusters and transactions (CLAUDE.md §4b) — the only
non-determinism is wall-clock timing itself, which is what is being measured.
"""

from __future__ import annotations

import functools
import math
import random
import statistics
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace

from bsfr_sh.blockchain.block import Block
from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW, build_genesis
from bsfr_sh.blockchain.transaction import (
    BackupPayload,
    SignatureRecordPayload,
    Transaction,
    decrypt,
    encrypt_backup,
    encrypt_signature_record,
)
from bsfr_sh.consensus.pbft import Cluster, PBFTPolicy
from bsfr_sh.consensus.raft import RaftCluster, RaftPolicy
from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey, keypair_from_secret, sign
from bsfr_sh.crypto.hashing import h
from bsfr_sh.framework import _block_pipeline as pipeline
from bsfr_sh.recovery.locator import BackupIndex
from bsfr_sh.util.config import Config
from bsfr_sh.util.serialization import BlockPart, Value, encode_block

__all__ = [
    "BenchPolicy",
    "CaseResult",
    "ModelledNetwork",
    "RunMeasurement",
    "VarianceReport",
    "decide_repeat_count",
    "estimate_block_encode_seconds",
    "estimate_d3_seconds",
    "modelled_network_seconds",
    "projected_chain_bytes",
    "run_case",
    "run_once",
    "trend_resolvable",
    "verify_modelled_network_formula",
]

#: Approximate on-wire bytes per float feature in `_sigrw_batch`'s padding — tag(1) + 8-byte
#: binary64 body = 9. Only used to size a payload to a target byte count; not load-bearing for
#: correctness, since `SignatureRecordPayload.features` accepts any length.
_BYTES_PER_FEATURE = 9

#: `_wait_s` is generous multiples of the view-change timeout, matching
#: `framework._block_pipeline.PipelinePolicy.from_config`'s own formula, so a bench run never
#: races a slow machine into a spurious `PipelineError`.
_WAIT_TIMEOUTS = 32


# --------------------------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class BenchPolicy:
    """What to run, from `configs/bench.yaml` (`run.*`, `timing.*`) plus `configs/chain.yaml`."""

    cases: tuple[str, ...]
    case_blocks: Mapping[str, int]
    chains: tuple[str, ...]
    transactions_per_block: int
    repeats: int
    warmup_runs: int
    payload_bytes: int
    payload_bytes_sensitivity: tuple[int, ...]
    modelled_delay_s: float
    modelled_delay_sweep_s: tuple[float, ...]
    pbft: PBFTPolicy
    #: M7-4 — the comparison protocol. Not read by anything before that session; every M6a call
    #: site keeps passing `pbft_policy=` explicitly and ignores this field.
    raft: RaftPolicy

    @classmethod
    def from_config(cls, bench_config: Config, chain_config: Config) -> BenchPolicy:
        cases = tuple(str(c) for c in bench_config.require("run.cases", list))
        case_map = chain_config.require("cases", dict)
        return cls(
            cases=cases,
            case_blocks={name: int(case_map[name]) for name in cases},
            chains=tuple(str(c) for c in bench_config.require("run.chains", list)),
            transactions_per_block=chain_config.require("block.transactions_per_block", int),
            repeats=bench_config.require("timing.repeats", int),
            warmup_runs=bench_config.require("timing.warmup_runs", int),
            payload_bytes=chain_config.require("transaction.payload_bytes", int),
            payload_bytes_sensitivity=tuple(
                int(v) for v in chain_config.require("transaction.payload_bytes_sensitivity", list)
            ),
            modelled_delay_s=float(bench_config.get("network.modelled_delay_s")),
            modelled_delay_sweep_s=tuple(
                float(v) for v in bench_config.require("network.modelled_delay_sweep_s", list)
            ),
            # `chain.yaml`'s own default is off (test speed); `bench.yaml`'s declared
            # `network.serialize_messages` turns it on for every bench run (D3, closed).
            pbft=replace(
                PBFTPolicy.from_config(chain_config),
                serialize_messages=bool(bench_config.get("network.serialize_messages", True)),
            ),
            raft=replace(
                RaftPolicy.from_config(chain_config),
                serialize_messages=bool(bench_config.get("network.serialize_messages", True)),
            ),
        )


# --------------------------------------------------------------------------------------------
# Transaction builders
# --------------------------------------------------------------------------------------------
def _dtbu_batch(
    count: int, payload_bytes: int, recipient: PublicKey, *, seed: int, tag: str
) -> tuple[Transaction, ...]:
    """Alg. 1 line 2's shape: one `BackupPayload` chunk per transaction, `payload_bytes` each."""
    rng = random.Random(seed)
    return tuple(
        encrypt_backup(
            recipient=recipient,
            tx_id=f"{tag}-{i:04d}",
            payload=BackupPayload(
                system_id=f"SYS_{i % 8}", data=rng.randbytes(payload_bytes), captured_at=i
            ),
            created_at=i,
        )
        for i in range(count)
    )


def _sigrw_batch(
    count: int,
    payload_bytes: int,
    recipient: PublicKey,
    collector_key: PrivateKey,
    *,
    seed: int,
    tag: str,
) -> tuple[Transaction, ...]:
    """Alg. 2 line 7's shape, with a real attestation sign per record — see the module docstring.

    Not `honeypot.signatures`' exact preimage (this module must not depend on `honeypot`'s
    internal format — see docs/ARCHITECTURE.md's dependency direction). What matters for a
    timing harness is that a real `crypto.ecdsa.sign` call happens once per transaction, which is
    the one structural cost Phase 2 pays that Phase 1 does not.
    """
    rng = random.Random(seed)
    n_features = max(8, payload_bytes // _BYTES_PER_FEATURE)
    out = []
    for i in range(count):
        content_digest = h(rng.randbytes(64))
        attestation = sign(collector_key, content_digest)
        features = tuple(rng.random() for _ in range(n_features))
        payload = SignatureRecordPayload(
            sample_id=f"{tag}-{i:04d}",
            content_digest=content_digest,
            attestation=attestation,
            features=features,
            collected_at=i,
            schema="bench.synthetic.v1",
        )
        out.append(
            encrypt_signature_record(
                recipient=recipient, tx_id=f"{tag}-{i:04d}", payload=payload, created_at=i
            )
        )
    return tuple(out)


def _batch(
    chain_name: str,
    count: int,
    payload_bytes: int,
    recipient: PublicKey,
    collector_key: PrivateKey,
    *,
    seed: int,
    tag: str,
) -> tuple[Transaction, ...]:
    if chain_name == BC_DTBU:
        return _dtbu_batch(count, payload_bytes, recipient, seed=seed, tag=tag)
    if chain_name == BC_SigRW:
        return _sigrw_batch(count, payload_bytes, recipient, collector_key, seed=seed, tag=tag)
    raise ValueError(f"unknown chain {chain_name!r}; expected {BC_DTBU!r} or {BC_SigRW!r}")


# --------------------------------------------------------------------------------------------
# Cluster
# --------------------------------------------------------------------------------------------
def _cluster(
    *,
    chain_name: str,
    id_prefix: str,
    pbft_policy: PBFTPolicy | None = None,
    raft_policy: RaftPolicy | None = None,
    seed: int,
    submitters: Mapping[str, PublicKey],
) -> Cluster | RaftCluster:
    """A fresh cluster of `policy.replicas` nodes, keyed from `seed` (CLAUDE.md §4b).

    Exactly one of `pbft_policy`/`raft_policy` is given (M7-4) — the same key-derivation and
    genesis-construction code either way, so a timing difference between the two clusters this
    builds can never be attributed to how they were set up.
    """
    if pbft_policy is not None and raft_policy is None:
        ids = tuple(f"{id_prefix}_{index}" for index in range(pbft_policy.replicas))
        keys = {rid: keypair_from_secret(seed + i + 1).private for i, rid in enumerate(ids)}
        genesis = build_genesis(owner_id=ids[0], private_key=keys[ids[0]], timestamp=0.0)
        return Cluster(
            chain_name=chain_name,
            keys=keys,
            genesis=genesis,
            policy=pbft_policy,
            seed=seed,
            submitters=submitters,
        )
    if raft_policy is not None and pbft_policy is None:
        ids = tuple(f"{id_prefix}_{index}" for index in range(raft_policy.replicas))
        keys = {rid: keypair_from_secret(seed + i + 1).private for i, rid in enumerate(ids)}
        genesis = build_genesis(owner_id=ids[0], private_key=keys[ids[0]], timestamp=0.0)
        return RaftCluster(
            chain_name=chain_name,
            keys=keys,
            genesis=genesis,
            policy=raft_policy,
            seed=seed,
            submitters=submitters,
        )
    raise ValueError("exactly one of pbft_policy/raft_policy must be given")


# --------------------------------------------------------------------------------------------
# One run
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class RunMeasurement:
    """One full pass through `blocks` blocks on one chain. Compute time only."""

    chain_name: str
    blocks: int
    transactions_per_block: int
    payload_bytes: int
    seed: int
    block_seconds: tuple[float, ...]
    index_seconds: float | None
    last_block: Block
    #: M7-4. Total bus messages / consensus-message ECDSA ops across the whole run — `0` for a
    #: field never populated by a caller that doesn't pass it (every M6a call site).
    message_count: int = 0
    signature_ops: int = 0

    @property
    def total_compute_seconds(self) -> float:
        return sum(self.block_seconds)

    @property
    def transaction_count(self) -> int:
        return self.blocks * self.transactions_per_block


def run_once(
    *,
    chain_name: str,
    blocks: int,
    transactions_per_block: int,
    payload_bytes: int,
    pbft_policy: PBFTPolicy | None = None,
    raft_policy: RaftPolicy | None = None,
    seed: int,
    tag: str,
) -> RunMeasurement:
    """Build a fresh cluster and commit `blocks` blocks, one `ClientRequest` at a time.

    Each block's timer starts before its transactions are built and stops once the pipeline
    reports it committed (`_block_pipeline._committed`'s rule — `f+1` replicas for pBFT, `1` for
    Raft, `consensus.interface.ConsensusCluster.client_confirmation_threshold`), so the measured
    span is exactly `configs/bench.yaml`'s block_construction + consensus + append. Nothing here
    calls `BackupIndex` inside that loop (DEV-05) — see below.

    Exactly one of `pbft_policy`/`raft_policy` is given (M7-4, DEV-32) — everything else about
    this function (transaction construction, timing span, index cost) is identical either way,
    which is what makes the two protocols' numbers comparable rather than measuring two different
    experiments.
    """
    id_prefix = "CS" if chain_name == BC_DTBU else "HP"
    collector = keypair_from_secret(seed + 90_001)
    submitter_id = f"{tag}-collector"
    cluster = _cluster(
        chain_name=chain_name,
        id_prefix=id_prefix,
        pbft_policy=pbft_policy,
        raft_policy=raft_policy,
        seed=seed,
        submitters={submitter_id: collector.public},
    )
    if pbft_policy is not None:
        wait_s = pbft_policy.view_change_timeout_s * _WAIT_TIMEOUTS
    else:
        assert raft_policy is not None
        wait_s = raft_policy.election_timeout_max_s * _WAIT_TIMEOUTS

    block_seconds: list[float] = []
    for block_index in range(blocks):
        started = time.perf_counter()
        batch = _batch(
            chain_name,
            transactions_per_block,
            payload_bytes,
            collector.public,
            collector.private,
            seed=seed * 100_003 + block_index,
            tag=f"{tag}-b{block_index}",
        )
        pipeline.commit(
            cluster,
            [batch],
            timestamp=float(block_index + 1),
            wait_s=wait_s,
            submitter_id=submitter_id,
            key=collector.private,
        )
        block_seconds.append(time.perf_counter() - started)

    chain = pipeline.read_chain(cluster)
    index_seconds: float | None = None
    if chain_name == BC_DTBU:
        backup_index = BackupIndex(functools.partial(decrypt, collector.private))
        index_started = time.perf_counter()
        backup_index.sync(chain)
        index_seconds = time.perf_counter() - index_started

    return RunMeasurement(
        chain_name=chain_name,
        blocks=blocks,
        transactions_per_block=transactions_per_block,
        payload_bytes=payload_bytes,
        seed=seed,
        block_seconds=tuple(block_seconds),
        index_seconds=index_seconds,
        last_block=chain.head(),
        message_count=cluster.network.stats.sent,
        signature_ops=cluster.signature_ops,
    )


# --------------------------------------------------------------------------------------------
# Variance and repeat-count decision
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class VarianceReport:
    """Spread of `total_compute_seconds` across independent runs of one case."""

    chain_name: str
    case: str
    samples: tuple[float, ...]

    @property
    def mean_seconds(self) -> float:
        return statistics.mean(self.samples)

    @property
    def stdev_seconds(self) -> float:
        return statistics.pstdev(self.samples) if len(self.samples) > 1 else 0.0

    @property
    def coefficient_of_variation(self) -> float:
        mean = self.mean_seconds
        return self.stdev_seconds / mean if mean > 0 else math.inf


def decide_repeat_count(
    cv: float, *, floor: int = 5, ceiling: int = 25, target_relative_stderr: float = 0.05
) -> int:
    """How many repeats bring the median's standard error under `target_relative_stderr`.

    `stderr(mean) ~= stdev/sqrt(n)`, so `n >= (cv / target)^2`. The harness reports the *median*
    (bench.yaml `timing.aggregate: median`, chosen so one slow run cannot move the number), whose
    standard error is a constant factor above the mean's for a roughly symmetric distribution —
    close enough for choosing a repeat count, not for a confidence interval. Clamped to
    `[floor, ceiling]` and forced odd, so the median is always a real sample, never an average of
    two adjacent ones. `docs/EXPERIMENTS.md`'s protocol floor is 5; this raises it when the
    measured spread demands it and never lowers it.
    """
    n = floor if not math.isfinite(cv) or cv <= 0 else math.ceil((cv / target_relative_stderr) ** 2)
    n = max(floor, min(ceiling, n))
    if n % 2 == 0:
        n += 1
    return n


def trend_resolvable(
    variance: VarianceReport, *, other_case_median_seconds: float, repeats: int
) -> bool:
    """Whether the gap to another case's median is bigger than this case's own noise floor.

    Uses the standard error of a median of `repeats` samples from this case
    (`1.2533 * stdev / sqrt(n)`, the large-sample constant for the median of a roughly normal
    variable) against `|this case's mean - other_case_median_seconds|`. If the gap is smaller
    than twice that standard error, a trend line through the two points is not distinguishable
    from noise at this repeat count, and the honest finding is "not resolvable", not a chart.
    """
    if repeats <= 1:
        return False
    stderr_of_median = 1.2533 * variance.stdev_seconds / math.sqrt(repeats)
    gap = abs(variance.mean_seconds - other_case_median_seconds)
    return gap > 2 * stderr_of_median


# --------------------------------------------------------------------------------------------
# Aggregated case result
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class CaseResult:
    """Median-of-N compute timing for one (case, chain), plus the index cost if applicable."""

    case: str
    chain_name: str
    blocks: int
    transactions_per_block: int
    payload_bytes: int
    repeats: int
    warmup_runs: int
    totals_seconds: tuple[float, ...]
    marginal_seconds: tuple[float, ...]
    index_seconds: float | None
    #: M7-4. Empty tuples for every M6a call site that doesn't pass a protocol at all — see
    #: `median_message_count`/`median_signature_ops`.
    message_counts: tuple[int, ...] = ()
    signature_ops_counts: tuple[int, ...] = ()

    @property
    def median_total_seconds(self) -> float:
        return statistics.median(self.totals_seconds)

    @property
    def stdev_seconds(self) -> float:
        return statistics.pstdev(self.totals_seconds) if len(self.totals_seconds) > 1 else 0.0

    @property
    def transaction_count(self) -> int:
        return self.blocks * self.transactions_per_block

    @property
    def tps(self) -> float:
        """DEV-08: derived, never separately measured. `tps = total_tx / total_seconds`."""
        return self.transaction_count / self.median_total_seconds

    @property
    def median_message_count(self) -> float:
        return statistics.median(self.message_counts) if self.message_counts else 0.0

    @property
    def median_signature_ops(self) -> float:
        return statistics.median(self.signature_ops_counts) if self.signature_ops_counts else 0.0


def run_case(
    *,
    case: str,
    chain_name: str,
    blocks: int,
    transactions_per_block: int,
    payload_bytes: int,
    pbft_policy: PBFTPolicy | None = None,
    raft_policy: RaftPolicy | None = None,
    base_seed: int,
    repeats: int,
    warmup_runs: int,
) -> CaseResult:
    """Warm-up runs discarded, then `repeats` independent runs, aggregated to a median.

    Each run gets its own seed (`base_seed + k`) and therefore its own cluster and transactions
    — repeats measure run-to-run wall-clock spread, not the same computation replayed. Exactly one
    of `pbft_policy`/`raft_policy` is given, same rule as `run_once` (M7-4, DEV-32).
    """
    kept: list[RunMeasurement] = []
    for k in range(warmup_runs + repeats):
        measurement = run_once(
            chain_name=chain_name,
            blocks=blocks,
            transactions_per_block=transactions_per_block,
            payload_bytes=payload_bytes,
            pbft_policy=pbft_policy,
            raft_policy=raft_policy,
            seed=base_seed + k,
            tag=f"{case}-{chain_name}-{k}",
        )
        if k >= warmup_runs:
            kept.append(measurement)

    totals = tuple(m.total_compute_seconds for m in kept)
    marginal = tuple(statistics.median(m.block_seconds[i] for m in kept) for i in range(blocks))
    index_seconds: float | None = None
    if chain_name == BC_DTBU:
        index_seconds = statistics.median(
            m.index_seconds for m in kept if m.index_seconds is not None
        )

    return CaseResult(
        case=case,
        chain_name=chain_name,
        blocks=blocks,
        transactions_per_block=transactions_per_block,
        payload_bytes=payload_bytes,
        repeats=repeats,
        warmup_runs=warmup_runs,
        totals_seconds=totals,
        marginal_seconds=marginal,
        index_seconds=index_seconds,
        message_counts=tuple(m.message_count for m in kept),
        signature_ops_counts=tuple(m.signature_ops for m in kept),
    )


# --------------------------------------------------------------------------------------------
# Modelled network cost (DEV-21) — arithmetic, not a stopwatch
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ModelledNetwork:
    """`computed`, never `measured` — see the module docstring."""

    blocks: int
    delay_s: float
    consensus_seconds: float
    total_seconds: float


def modelled_network_seconds(*, blocks: int, delay_s: float) -> ModelledNetwork:
    """One committed block costs 4 message hops on the bus's simulated clock, serially:

    1 (client `ClientRequest` broadcast reaches the replicas) + 3 inside pBFT itself
    (pre-prepare, prepare, commit — `consensus/pbft.py`'s module docstring, normal case steps
    2-5). At most one height is in flight (DEV-20 item 3), so the cost is `blocks * 4 * delay_s`
    total, of which `blocks * 3 * delay_s` is "inside consensus" in `configs/bench.yaml`'s sense.
    `verify_modelled_network_formula()` checks this against a real run before it is trusted.
    """
    return ModelledNetwork(
        blocks=blocks,
        delay_s=delay_s,
        consensus_seconds=blocks * 3 * delay_s,
        total_seconds=blocks * 4 * delay_s,
    )


def verify_modelled_network_formula(
    *,
    chain_name: str,
    blocks: int,
    transactions_per_block: int,
    pbft_policy: PBFTPolicy,
    delay_s: float,
    seed: int,
) -> tuple[float, float]:
    """Run `blocks` blocks with `message_delay_s = delay_s` and return `(predicted, actual)`.

    `actual` is the bus's simulated clock (`Cluster.network.now`) after the last block commits —
    never wall-clock, which `consensus/network.py`'s module docstring is explicit does not move
    with delay. Small payload, since only the clock reading is being checked here.
    """
    policy = replace(pbft_policy, message_delay_s=delay_s)
    id_prefix = "CS" if chain_name == BC_DTBU else "HP"
    collector = keypair_from_secret(seed + 90_001)
    submitter_id = "verify-collector"
    cluster = _cluster(
        chain_name=chain_name,
        id_prefix=id_prefix,
        pbft_policy=policy,
        seed=seed,
        submitters={submitter_id: collector.public},
    )
    wait_s = policy.view_change_timeout_s * _WAIT_TIMEOUTS
    for index in range(blocks):
        batch = _batch(
            chain_name,
            transactions_per_block,
            64,
            collector.public,
            collector.private,
            seed=seed * 100_003 + index,
            tag=f"verify-b{index}",
        )
        pipeline.commit(
            cluster,
            [batch],
            timestamp=float(index + 1),
            wait_s=wait_s,
            submitter_id=submitter_id,
            key=collector.private,
        )
    predicted = modelled_network_seconds(blocks=blocks, delay_s=delay_s).total_seconds
    return predicted, cluster.network.now


# --------------------------------------------------------------------------------------------
# D3 — serialization cost estimate (`computed`)
# --------------------------------------------------------------------------------------------
def _encodable_fields(block: Block) -> dict[str, Value]:
    return {
        "version": block.version,
        "timestamp": block.timestamp,
        "nonce": block.nonce,
        "merkle_root": block.merkle_root,
        "owner_id": block.owner_id,
        "owner_pubkey": block.owner_pubkey,
        "transactions": [tx.encoded() for tx in block.transactions],
        "prev_hash": block.prev_hash,
        "current_hash": block.current_hash,
        "signature": block.signature,
    }


def estimate_block_encode_seconds(block: Block, *, repeats: int = 50) -> float:
    """Median seconds to `encode_block()` one real, already-committed block.

    A microbenchmark on `util.serialization`, the module CLAUDE.md §7 names as the one place
    canonical encoding happens — not a stopwatch around anything the bus actually does, since the
    bus does not serialise (D3, `consensus/network.py`).
    """
    fields = _encodable_fields(block)
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        encode_block(fields, BlockPart.FULL)
        samples.append(time.perf_counter() - started)
    return statistics.median(samples)


def estimate_d3_seconds(per_block_encode_seconds: float, blocks: int) -> float:
    """Lower-bound estimate of the wire-encoding cost a real network layer would pay.

    Models one `encode_block()` per committed block — the primary encoding its `Proposal` once
    for broadcast to `2f` backups (the dominant payload; `Prepare`/`Commit` carry only a 32-byte
    digest each and are negligible by comparison). It does **not** count decode cost on the
    receiving side, or the small vote messages, so it undercounts D3's true magnitude rather than
    overstating it — stated explicitly here so the number is read as a floor, not a total.
    """
    return per_block_encode_seconds * blocks


# --------------------------------------------------------------------------------------------
# Q2 — payload-size memory projection
# --------------------------------------------------------------------------------------------
def projected_chain_bytes(
    *, payload_bytes: int, transactions_per_block: int, blocks: int, overhead_factor: float
) -> int:
    """Rough in-memory footprint of one `Chain` holding this many blocks.

    `overhead_factor` is measured, not assumed — `estimate_overhead_factor()` below fits it from
    a real small run before this function is used to project a size nobody should actually run
    (CLAUDE.md §6, "project compute before running it").
    """
    return int(payload_bytes * transactions_per_block * blocks * overhead_factor)


def estimate_overhead_factor(
    payload_bytes: int, measured_run: RunMeasurement, *, transactions_per_block: int
) -> float:
    """Ciphertext/AEAD-tag/wrapped-key/Python-object overhead per plaintext payload byte.

    Compares one already-committed block's actual serialized size (`encode_block`, the same
    canonical form `estimate_block_encode_seconds` times) against the raw plaintext byte budget
    the case declared, and reports the ratio. `>= 1.0` always, since ciphertext plus a wrapped
    key plus a nonce plus a Merkle leaf never encodes smaller than the plaintext it replaces.
    """
    plaintext_bytes = payload_bytes * transactions_per_block
    encoded = encode_block(_encodable_fields(measured_run.last_block), BlockPart.FULL)
    return len(encoded) / plaintext_bytes if plaintext_bytes else 1.0
