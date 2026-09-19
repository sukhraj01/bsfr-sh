"""The block pipeline shared by Alg. 1 lines 2-10 and Alg. 2 lines 3-10.

docs/ALGORITHMS.md says Alg. 2 lines 3-10 are "structurally identical to Alg. 1 lines 2-10.
Factor once." This module is that factoring, built before Phase 2 exists so that M3b adds a payload
builder and nothing else. A phase supplies two things: a **payload builder** that turns one of its
items into encrypted transactions, and the **`Cluster` of the chain** those transactions go to. The
pipeline does the rest:

| Step | Alg. 1 | Alg. 2 | Here |
|---|---|---|---|
| encrypt | 2 | 7 | `builder(item)`, items in order, transactions in builder order |
| assemble | 3 | 8 | batch per `block.transactions_per_block`; primary seals `β_j` (DEV-22) |
| broadcast | 4 | 9 | `Cluster.submit`: transactions, never blocks |
| pBFT, commit or re-run | 5-10 | 10-15 | inside the cluster; "re-run" is the view change (DEV-20) |
| terminate | 11-15 | 16-20 | return once every request is committed, or raise `PipelineError` |

When is a request committed?
----------------------------
The pipeline stands where a pBFT client stands, so it uses the client's rule (Castro-Liskov §4.1):
a result counts once `f+1` replicas report it, because at least one of them is honest. Here,
"report" means holding a block whose `MTR` equals the request id. `ClientRequest.request_id` is
defined as exactly that root. An honest replica appends only on a commit certificate, so one
honest holder is proof of commit.

Waiting on simulated time
-------------------------
The bus runs on a simulated clock (DEV-21). The pipeline first drains everything due *now*, then
advances by one tick: the message delay, or the view-change timeout when there is no delay. It
stops as soon as every request is committed, so the clock never runs more than one tick past the
last commit. It raises if the cluster goes idle with requests outstanding, or when
`consensus.client_wait_timeouts` view-change timeouts have passed.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import TypeVar

from bsfr_sh.blockchain.chain import Chain
from bsfr_sh.blockchain.transaction import Transaction
from bsfr_sh.consensus.pbft import Cluster
from bsfr_sh.crypto.ecdsa import PrivateKey
from bsfr_sh.util.config import Config
from bsfr_sh.util.logging import event, get_logger

__all__ = [
    "CommittedRequest",
    "PipelineError",
    "PipelinePolicy",
    "PipelineResult",
    "batch",
    "commit",
    "read_chain",
    "run",
]

_LOG = get_logger("framework.pipeline")

T = TypeVar("T")

#: Default `consensus.client_wait_timeouts`, for configs written before M3a declared it.
_DEFAULT_WAIT_TIMEOUTS = 32


class PipelineError(RuntimeError):
    """Raised when a batch cannot be submitted, or does not commit within the wait."""


@dataclass(frozen=True)
class PipelinePolicy:
    """`block.transactions_per_block` and the commit wait, from `configs/chain.yaml`."""

    transactions_per_block: int
    wait_s: float

    def __post_init__(self) -> None:
        if self.transactions_per_block <= 0:
            raise PipelineError("transactions_per_block must be positive")
        if self.wait_s <= 0:
            raise PipelineError("wait_s must be positive")

    @classmethod
    def from_config(cls, config: Config) -> PipelinePolicy:
        timeouts = int(config.get("consensus.client_wait_timeouts", _DEFAULT_WAIT_TIMEOUTS))
        return cls(
            transactions_per_block=config.require("block.transactions_per_block", int),
            wait_s=timeouts * float(config.get("consensus.view_change_timeout_s")),
        )


@dataclass(frozen=True)
class CommittedRequest:
    """One submitted batch, and the block it became."""

    request_id: bytes
    height: int
    block_hash: bytes
    transaction_count: int


@dataclass(frozen=True)
class PipelineResult:
    """What one pipeline run committed, in submission order."""

    chain_name: str
    committed: tuple[CommittedRequest, ...]

    @property
    def block_count(self) -> int:
        return len(self.committed)

    @property
    def transaction_count(self) -> int:
        return sum(request.transaction_count for request in self.committed)


def batch(transactions: Sequence[Transaction], size: int) -> tuple[tuple[Transaction, ...], ...]:
    """Implements Alg. 1, line 3 / Alg. 2, line 8, submitter side: one block per request."""
    if size <= 0:
        raise PipelineError("batch size must be positive")
    return tuple(tuple(transactions[i : i + size]) for i in range(0, len(transactions), size))


def run(
    cluster: Cluster,
    items: Iterable[T],
    builder: Callable[[T], Sequence[Transaction]],
    *,
    chain: str,
    policy: PipelinePolicy,
    timestamp: float,
    submitter_id: str,
    key: PrivateKey,
) -> PipelineResult:
    """Implements Alg. 1, lines 2-15 / Alg. 2, lines 7-20, for any payload builder.

    `chain` names the chain the items belong on. It must be `cluster`'s chain, so that a phase
    cannot write its payloads to the other chain by being handed the wrong cluster (CLAUDE.md §4).
    `submitter_id`/`key` identify and sign as the submitting `CS_l` (DEV-20 item 5 / debt D4) —
    must be one of `cluster.submitters`, or every replica rejects the request.
    """
    if cluster.chain_name != chain:
        raise PipelineError(f"refusing to write {chain} payloads to {cluster.chain_name}")
    transactions = [tx for item in items for tx in builder(item)]
    batches = batch(transactions, policy.transactions_per_block)
    return commit(
        cluster,
        batches,
        timestamp=timestamp,
        wait_s=policy.wait_s,
        submitter_id=submitter_id,
        key=key,
    )


def commit(
    cluster: Cluster,
    batches: Sequence[tuple[Transaction, ...]],
    *,
    timestamp: float,
    wait_s: float,
    submitter_id: str,
    key: PrivateKey,
) -> PipelineResult:
    """Submit each batch as one signed `ClientRequest` and wait until every one is committed.

    Implements Alg. 1, lines 4-15. The batches are submitted together. Which height each one
    lands at is consensus's decision, and the result reports it.
    """
    to_submit = [b for b in batches if b]
    # Checked before anything is sent: pBFT deduplicates identical requests, so the second would
    # never commit and the wait below would run to its deadline for nothing.
    if len({tuple(tx.digest for tx in b) for b in to_submit}) != len(to_submit):
        raise PipelineError("two batches hold identical transactions; pBFT would commit one")
    request_ids = [
        cluster.submit(b, timestamp=timestamp, submitter_id=submitter_id, key=key)
        for b in to_submit
    ]
    network = cluster.network
    deadline = network.now + wait_s
    tick = cluster.policy.message_delay_s or cluster.policy.view_change_timeout_s
    while True:
        cluster.run(until=network.now)
        done = _committed(cluster, request_ids)
        if len(done) == len(request_ids):
            break
        if network.pending == 0:
            raise PipelineError(
                f"{cluster.chain_name} went idle with {len(request_ids) - len(done)} of "
                f"{len(request_ids)} requests uncommitted"
            )
        if network.now >= deadline:
            raise PipelineError(
                f"{cluster.chain_name}: {len(request_ids) - len(done)} of {len(request_ids)} "
                f"requests uncommitted after {wait_s:.0f}s of simulated time"
            )
        cluster.run(until=min(network.now + tick, deadline))
    result = PipelineResult(cluster.chain_name, tuple(done[rid] for rid in request_ids))
    event(
        _LOG,
        "pipeline_committed",
        chain=cluster.chain_name,
        blocks=result.block_count,
        transactions=result.transaction_count,
        sim_time=network.now,
    )
    return result


def _committed(cluster: Cluster, request_ids: Sequence[bytes]) -> dict[bytes, CommittedRequest]:
    """Requests that `f+1` replicas hold, at one height, in one block. See the module docstring."""
    wanted = set(request_ids)
    holders: dict[tuple[bytes, int, bytes], int] = {}
    sizes: dict[tuple[bytes, int, bytes], int] = {}
    for replica in cluster.replicas.values():
        chain = replica.chain
        for height in range(1, chain.height + 1):
            block = chain.block_at(height)
            if block.merkle_root in wanted:
                key = (block.merkle_root, height, block.current_hash)
                holders[key] = holders.get(key, 0) + 1
                sizes[key] = block.transaction_count
    needed = cluster.policy.f + 1
    return {
        key[0]: CommittedRequest(key[0], key[1], key[2], sizes[key])
        for key, count in holders.items()
        if count >= needed
    }


def read_chain(cluster: Cluster) -> Chain:
    """The longest chain whose head `f+1` replicas agree on: a committed chain to read from.

    Uses the client rule again, so that a reader never takes one replica's word for what the chain
    holds.
    """
    needed = cluster.policy.f + 1
    chains = sorted((r.chain for r in cluster.replicas.values()), key=len, reverse=True)
    for candidate in chains:
        height = candidate.height
        head = candidate.head_hash()
        agreeing = sum(
            1 for c in chains if c.height >= height and c.block_at(height).current_hash == head
        )
        if agreeing >= needed:
            return candidate
    raise PipelineError(f"no {needed} replicas of {cluster.chain_name} agree on any head")
