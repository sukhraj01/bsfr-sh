"""M7-4 — the qualitative half of the pBFT/Raft comparison.

Every other Raft test asserts the protocol *works*. This one asserts it does not protect against
a lying leader — and that is the point, not a bug. `consensus/raft.py`'s module docstring names
the mechanism: a follower's `AppendEntries` handler checks the leader's term and the previous
entry's consistency, never cross-checks its own accepted entry against any other follower's copy.
A byzantine leader can therefore hand two different, individually well-formed (validly signed,
correctly linked) blocks to two different followers at one height, and both sides "commit" by
their own local rules.

Contrast `test_pbft_byzantine.py`'s
`test_f2_colluding_equivocators_can_fork_honest_replicas_the_bound_is_exactly_f` — pBFT forks
too, but only once faulty replicas exceed `f` (here, two of four colluding). This test forks Raft
with a *single* faulty node, because Raft's fault model was never Byzantine to begin with
(DEV-32): the leader does not need to collude with anyone to lie, it just has to talk.
"""

from __future__ import annotations

import raft_harness as h


def test_a_byzantine_leader_forks_honest_followers_with_a_single_faulty_node() -> None:
    cluster = h.make_cluster(seed=20)

    # Warm up so a leader is elected under honest behaviour first.
    h.submit_block(cluster, 0)
    h.run_for(cluster)
    leader = h.leader_of(cluster)
    followers = [rid for rid in cluster.nodes if rid != leader.node_id]
    side_b = frozenset(followers[:1])
    side_a = frozenset(followers[1:])

    real_transactions = h.make_transactions("real", count=2)
    fake_transactions = h.make_transactions("fabricated-by-the-leader", count=2)
    leader.behaviour = h.EquivocatingLeader(side_b=side_b, variant_transactions=fake_transactions)

    cluster.submit(
        real_transactions,
        timestamp=h.GENESIS_TIME + 100,
        submitter_id=h.SUBMITTER_ID,
        key=h.SUBMITTER.private,
    )
    h.run_for(cluster)

    # Every node "commits" by its own local rule — that is the failure. No exception, no
    # rejection, no stall: each side thinks consensus succeeded.
    assert all(node.height == 2 for node in cluster.nodes.values())
    assert leader.commit_index == 2

    side_a_nodes = [cluster.nodes[rid] for rid in side_a]
    side_b_nodes = [cluster.nodes[rid] for rid in side_b]

    a_digests = {tuple(tx.digest for tx in n.chain.block_at(2).transactions) for n in side_a_nodes}
    b_digests = {tuple(tx.digest for tx in n.chain.block_at(2).transactions) for n in side_b_nodes}
    assert len(a_digests) == 1
    assert len(b_digests) == 1, "each side should at least agree with itself"
    assert a_digests != b_digests, (
        "side_a and side_b committed different transaction sets at the same height — the fork "
        "pBFT's matching-vote quorum would have prevented (test_pbft_byzantine.py)"
    )

    a_hash = side_a_nodes[0].chain.block_at(2).current_hash
    b_hash = side_b_nodes[0].chain.block_at(2).current_hash
    assert a_hash != b_hash, "the two sides hold different, individually-valid blocks at height 2"

    # Each side's own chain is still internally *valid* — no signature, hash, or link check
    # catches this. The chain only ever asked "is this block well-formed and correctly linked?",
    # never "does every other honest node agree this is what happened?" — that second question is
    # exactly what pBFT's `2f+1` matching-commit rule answers and Raft's leader-trust model does
    # not ask.
    side_a_nodes[0].chain.verify_integrity()
    side_b_nodes[0].chain.verify_integrity()
