"""`ConsensusCluster` — the common shape `framework._block_pipeline` needs from a cluster.

M7-4 introduces a second consensus protocol (`consensus.raft`) alongside pBFT
(`consensus.pbft`). The pipeline (Alg. 1 lines 2-15 / Alg. 2 lines 7-20, factored once per
`docs/ALGORITHMS.md`) does not care *how* a batch of transactions gets committed — only that it
can submit a batch, run the bus, and read back which replicas hold what. This module names that
boundary as a `Protocol` so `pbft.Cluster` and `raft.RaftCluster` can both satisfy it without
either importing the other, and without `_block_pipeline` importing a specific protocol module
at all (DEV-32).

Two methods exist only because the two protocols disagree about what "the client can trust one
replica's word" means:

* `client_confirmation_threshold()` — how many distinct replicas must independently hold a
  request before the client counts it committed. pBFT's is `f+1` (`Membership.join_quorum`'s
  reasoning: at least one of them is honest). Raft's is `1`: a non-Byzantine replica only ever
  reflects an entry the leader already confirmed via a real majority (`RaftCluster.commit_index`
  advances only past `RaftPolicy.majority` acks), so a client re-deriving that majority itself
  would just be repeating a check the protocol already made. This asymmetry is not an oversight —
  it is the qualitative point of DEV-32: pBFT's client-side quorum exists *because* any single
  replica might be lying; Raft's doesn't need one because a single Raft replica cannot lie about
  what the leader told it (it can only be wrong about who to trust, which is a different failure
  covered by the Byzantine-leader test, not by asking more replicas).
* `tick_seconds()` — how far to advance the simulated clock between polls while a request is
  in flight (`_block_pipeline.commit`'s wait loop). pBFT's is the message delay, or the
  view-change timeout when delay is zero; Raft's is the message delay, or the heartbeat interval.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from bsfr_sh.blockchain.chain import Chain
from bsfr_sh.blockchain.transaction import Transaction
from bsfr_sh.consensus.network import P2PCSNetwork
from bsfr_sh.crypto.ecdsa import PrivateKey

__all__ = ["ConsensusCluster", "ReplicaLike"]


class ReplicaLike(Protocol):
    """What `_block_pipeline` reads off one member of a cluster: its own chain."""

    @property
    def chain(self) -> Chain: ...


@runtime_checkable
class ConsensusCluster(Protocol):
    """What `_block_pipeline.run`/`commit`/`read_chain` need from a cluster, either protocol.

    The three members below are declared as read-only `@property` getters rather than plain
    attributes so mypy checks them *covariantly* (read compatibility only): `pbft.Cluster.replicas`
    is a concrete `dict[str, Replica]`, and a plain-attribute protocol member would demand
    invariant (read+write) compatibility with `Mapping[str, ReplicaLike]`, which no concrete `dict`
    of a narrower value type ever satisfies. Neither implementation needs to declare these as
    properties themselves — a plain attribute of a compatible type satisfies a read-only protocol
    property just as well.
    """

    @property
    def chain_name(self) -> str: ...

    @property
    def network(self) -> P2PCSNetwork: ...

    @property
    def replicas(self) -> Mapping[str, ReplicaLike]: ...

    def submit(
        self,
        transactions: tuple[Transaction, ...],
        *,
        timestamp: float,
        submitter_id: str,
        key: PrivateKey,
    ) -> bytes: ...

    def run(self, *, until: float | None = None) -> int: ...

    def client_confirmation_threshold(self) -> int: ...

    def tick_seconds(self) -> float: ...
