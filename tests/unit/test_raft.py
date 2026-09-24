"""M7-4 — `consensus/raft.py`: leader election, log replication, failover, crash tolerance.

Mirrors `test_pbft.py`'s shape and coverage, over the analogous Raft properties, so the two
suites read as a comparison rather than two unrelated test files. The Byzantine-leader test lives
separately in `test_raft_byzantine.py` — it is the one test in this pair that is *expected* to
show a failure, and keeping it apart makes that distinction visible in the test tree.
"""

from __future__ import annotations

import raft_harness as h

from bsfr_sh.blockchain.chain import BC_DTBU
from bsfr_sh.consensus.network import LinkFaults
from bsfr_sh.consensus.raft import Role
from bsfr_sh.framework import _block_pipeline as pipeline


# --------------------------------------------------------------------------------------------
# Leader election
# --------------------------------------------------------------------------------------------
def test_exactly_one_leader_is_elected_from_a_fresh_cluster() -> None:
    cluster = h.make_cluster(seed=1)
    h.run_for(cluster, 5 * h.POLICY.election_timeout_max_s)
    leaders = [n for n in cluster.nodes.values() if n.is_leader]
    assert len(leaders) == 1


def test_every_node_agrees_on_the_elected_leaders_term() -> None:
    cluster = h.make_cluster(seed=2)
    h.run_for(cluster, 5 * h.POLICY.election_timeout_max_s)
    leader = h.leader_of(cluster)
    for node in cluster.nodes.values():
        assert node.current_term == leader.current_term


def test_a_lone_candidate_cannot_win_without_a_majority() -> None:
    """A candidate with only its own vote (no peer grants) never becomes leader."""
    cluster = h.make_cluster(seed=3)
    candidate = cluster.nodes["CS_1"]
    candidate.role = Role.CANDIDATE
    candidate.current_term += 1
    candidate._votes_received = {candidate.node_id}
    assert not candidate.is_leader


# --------------------------------------------------------------------------------------------
# Log replication / commit
# --------------------------------------------------------------------------------------------
def test_a_submitted_batch_commits_on_every_node() -> None:
    cluster = h.make_cluster(seed=4)
    h.submit_block(cluster, 0)
    h.run_for(cluster)
    heights = cluster.heights()
    assert all(height == 1 for height in heights.values())
    for node in cluster.nodes.values():
        assert node.chain.block_at(1).transaction_count == 2


def test_several_blocks_commit_in_submission_order_one_at_a_time() -> None:
    cluster = h.make_cluster(seed=5)
    for i in range(4):
        h.submit_block(cluster, i)
        h.run_for(cluster)
    assert all(height == 4 for height in cluster.heights().values())
    h.assert_no_fork(list(cluster.nodes.values()))


def test_commit_requires_a_real_majority_not_just_the_leader() -> None:
    """Drop every follower's ability to talk back to the leader: nothing should commit."""
    cluster = h.make_cluster(seed=6)
    h.run_for(cluster, 5 * h.POLICY.election_timeout_max_s)
    leader = h.leader_of(cluster)
    others = h.honest(cluster, byzantine=(leader.node_id,))
    for node in others:
        cluster.network.set_faults(node.node_id, LinkFaults(drop_rate=1.0))
    h.submit_block(cluster, 0)
    h.run_for(cluster)
    assert leader.height == 0
    assert leader.commit_index == 0


# --------------------------------------------------------------------------------------------
# Fault tolerance — the M7-4 comparison points
# --------------------------------------------------------------------------------------------
def test_one_crashed_node_does_not_block_commits() -> None:
    """`n=4`, majority=3: with one node silent, the other three still commit — same tolerated
    fault *count* as pBFT's `f=1` (`test_pbft.py`), different failure model (crash, not lie)."""
    cluster = h.make_cluster(seed=7)
    crashed = "CS_3"
    cluster.network.set_faults(crashed, LinkFaults(drop_rate=1.0))
    for i in range(3):
        h.submit_block(cluster, i)
        h.run_for(cluster)
    live = h.honest(cluster, byzantine=(crashed,))
    assert all(node.height == 3 for node in live)
    h.assert_no_fork(live)


def test_two_crashed_nodes_stall_the_cluster() -> None:
    """Below a majority, Raft cannot commit — same structural limit pBFT has at `f+1` failed."""
    cluster = h.make_cluster(seed=8)
    for crashed in ("CS_2", "CS_3"):
        cluster.network.set_faults(crashed, LinkFaults(drop_rate=1.0))
    h.submit_block(cluster, 0)
    h.run_for(cluster, 10 * h.POLICY.election_timeout_max_s)
    assert all(node.height == 0 for node in cluster.nodes.values())


def test_leader_failover_on_timeout_new_leader_elected_chain_continues() -> None:
    """Kill the leader outright; a new one is elected and commits continue."""
    cluster = h.make_cluster(seed=9)
    h.submit_block(cluster, 0)
    h.run_for(cluster)
    old_leader = h.leader_of(cluster).node_id

    cluster.network.set_faults(old_leader, LinkFaults(drop_rate=1.0))
    h.submit_block(cluster, 1)
    h.run_for(cluster, 10 * h.POLICY.election_timeout_max_s)

    live = h.honest(cluster, byzantine=(old_leader,))
    new_leader = h.leader_of(cluster)
    assert new_leader.node_id != old_leader
    assert all(node.height == 2 for node in live)
    h.assert_no_fork(live)


# --------------------------------------------------------------------------------------------
# Parity with pBFT in the non-faulty case — same data, not same hashes (block `RN` is drawn from
# `secrets`, never seeded; `test_bench_harness.py`'s
# `test_run_once_is_deterministic_in_content_not_wall_clock` documents the identical property
# for pBFT). The fair, protocol-agnostic claim is that both commit the same transactions in the
# same order, which `blockchain.chain.Chain` — the thing both protocols hand blocks to — cannot
# tell apart by construction.
# --------------------------------------------------------------------------------------------
def test_raft_and_pbft_commit_the_same_transactions_from_the_same_input() -> None:
    import pbft_harness as p

    from bsfr_sh.consensus.pbft import Cluster as PBFTCluster

    raft_cluster = h.make_cluster(seed=11)
    pbft_cluster = p.make_cluster(seed=11)
    assert isinstance(pbft_cluster, PBFTCluster)

    txs = h.make_transactions("parity", count=3)
    pipeline.commit(
        raft_cluster,
        [txs],
        timestamp=2000.0,
        wait_s=h.HORIZON_S,
        submitter_id=h.SUBMITTER_ID,
        key=h.SUBMITTER.private,
    )
    pipeline.commit(
        pbft_cluster,
        [txs],
        timestamp=2000.0,
        wait_s=p.HORIZON_S,
        submitter_id=p.SUBMITTER_ID,
        key=p.SUBMITTER.private,
    )

    raft_chain = pipeline.read_chain(raft_cluster)
    pbft_chain = pipeline.read_chain(pbft_cluster)
    assert raft_chain.height == pbft_chain.height == 1
    raft_digests = tuple(tx.digest for tx in raft_chain.block_at(1).transactions)
    pbft_digests = tuple(tx.digest for tx in pbft_chain.block_at(1).transactions)
    assert raft_digests == pbft_digests == tuple(tx.digest for tx in txs)


def test_raft_cluster_satisfies_the_consensus_cluster_protocol() -> None:
    from bsfr_sh.consensus.interface import ConsensusCluster

    cluster = h.make_cluster(seed=12)
    assert isinstance(cluster, ConsensusCluster)
    assert cluster.chain_name == BC_DTBU
    assert cluster.client_confirmation_threshold() == 1
    assert cluster.signature_ops == 0
