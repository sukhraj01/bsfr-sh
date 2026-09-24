"""Wires `blockchain.hybrid.HybridChain` into the existing Alg. 1/2 pipeline. M7-5, DEV-33.

`blockchain.hybrid.HybridChain` holds no `consensus` or `framework` dependency — see that
module's docstring for why. This is the module on the other side of that boundary: it is where
`framework._block_pipeline.read_chain`'s quorum-agreement check (the trust rule every other
consumer of a committed chain already uses) meets `HybridChain.sync`/`flush`.

`append()` below is the whole of "hybrid is transparent to the framework": it calls
`framework._block_pipeline.run` exactly as `phase1_backup.run`/`phase2_collection.run` already do
— same cluster, same batching, same commit-or-raise semantics, completely unmodified — and only
*after* that call returns does it read the now-trusted chain and hand it to `hybrid`. Nothing
about what gets committed to the private chain depends on whether hybrid mode is on; `hybrid` only
observes the result afterward. `phase1_backup.py`/`phase2_collection.py` themselves are untouched
by M7-5 for exactly this reason — there was nothing to change in them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import TypeVar

from bsfr_sh.blockchain.hybrid import HybridChain
from bsfr_sh.blockchain.transaction import Transaction
from bsfr_sh.consensus.interface import ConsensusCluster
from bsfr_sh.crypto.ecdsa import PrivateKey
from bsfr_sh.framework import _block_pipeline as pipeline

__all__ = ["append"]

T = TypeVar("T")


def append(
    cluster: ConsensusCluster,
    hybrid: HybridChain,
    items: Iterable[T],
    builder: Callable[[T], Sequence[Transaction]],
    *,
    policy: pipeline.PipelinePolicy,
    timestamp: float,
    submitter_id: str,
    key: PrivateKey,
) -> pipeline.PipelineResult:
    """Commit to `cluster`'s private chain, then anchor whatever became due.

    `cluster` is typed against `consensus.interface.ConsensusCluster` (DEV-32's boundary), not the
    concrete `pbft.Cluster` — this module runs the identical pipeline against Raft too, the same
    way `bench.harness` already does for M7-4's comparison, with no code path here caring which
    protocol committed the block.
    """
    result = pipeline.run(
        cluster,
        items,
        builder,
        chain=cluster.chain_name,
        policy=policy,
        timestamp=timestamp,
        submitter_id=submitter_id,
        key=key,
    )
    trusted = pipeline.read_chain(cluster)
    hybrid.sync(trusted, timestamp=timestamp)
    hybrid.flush(trusted, timestamp=timestamp)
    return result
