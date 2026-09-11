"""`framework._block_pipeline`: Alg. 1 lines 2-15 / Alg. 2 lines 7-20, for any payload builder."""

from __future__ import annotations

import pytest
from pbft_harness import CONFIG, POLICY, SIGRW_IDS, Silent, make_cluster, make_transactions

from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW
from bsfr_sh.framework._block_pipeline import (
    PipelineError,
    PipelinePolicy,
    batch,
    commit,
    read_chain,
    run,
)

SMALL = PipelinePolicy(transactions_per_block=4, wait_s=15 * POLICY.view_change_timeout_s)


def _two(tag: str):
    return lambda _item: make_transactions(tag, 2)


def test_policy_comes_from_config() -> None:
    policy = PipelinePolicy.from_config(CONFIG)
    assert policy.transactions_per_block == CONFIG.require("block.transactions_per_block", int)
    timeouts = CONFIG.get("consensus.client_wait_timeouts")
    assert policy.wait_s == timeouts * POLICY.view_change_timeout_s


def test_batch_sizes_with_a_remainder() -> None:
    txs = make_transactions("b", 10)
    assert [len(b) for b in batch(txs, 4)] == [4, 4, 2]
    assert batch((), 4) == ()
    with pytest.raises(PipelineError):
        batch(txs, 0)


def test_items_become_blocks_through_consensus_in_order() -> None:
    cluster = make_cluster()
    seen: list[int] = []

    def build(item: int):
        seen.append(item)
        return make_transactions(f"item{item}", 3)

    result = run(cluster, range(5), build, chain=BC_DTBU, policy=SMALL, timestamp=1001.0)
    assert seen == [0, 1, 2, 3, 4]
    assert result.transaction_count == 15
    assert [c.transaction_count for c in result.committed] == [4, 4, 4, 3]
    assert [c.height for c in result.committed] == [1, 2, 3, 4]
    assert set(cluster.heights().values()) == {4}
    chain = read_chain(cluster)
    committed_ids = [tx.tx_id for h in range(1, 5) for tx in chain.block_at(h).transactions]
    assert committed_ids == [f"item{i}-{j:03d}" for i in range(5) for j in range(3)]


def test_a_zero_delay_run_leaves_no_phantom_simulated_time() -> None:
    """DEV-21: M6 reads `network.now` as modelled latency. Waiting must not add to it."""
    cluster = make_cluster()
    run(cluster, [0], _two("t"), chain=BC_DTBU, policy=SMALL, timestamp=1001.0)
    assert cluster.network.now == 0.0


def test_payloads_are_refused_by_the_other_chains_cluster() -> None:
    cluster = make_cluster(BC_SigRW, SIGRW_IDS)
    with pytest.raises(PipelineError, match="refusing"):
        run(cluster, [0], _two("t"), chain=BC_DTBU, policy=SMALL, timestamp=1001.0)
    assert set(cluster.heights().values()) == {0}
    assert cluster.network.stats.sent == 0


def test_nothing_to_commit_submits_nothing() -> None:
    cluster = make_cluster()
    result = run(cluster, [], _two("t"), chain=BC_DTBU, policy=SMALL, timestamp=1001.0)
    assert result.block_count == 0
    assert cluster.network.stats.sent == 0


def test_identical_batches_are_refused_before_submission() -> None:
    cluster = make_cluster()
    txs = make_transactions("d", 2)
    with pytest.raises(PipelineError, match="identical"):
        commit(cluster, [txs, txs], timestamp=1001.0, wait_s=SMALL.wait_s)
    assert cluster.network.stats.sent == 0


@pytest.mark.parametrize("faulty", ["CS_0", "CS_2"], ids=["silent-primary", "silent-backup"])
def test_one_silent_replica_is_tolerated(faulty) -> None:
    cluster = make_cluster()
    cluster.replicas[faulty].behaviour = Silent()
    result = run(
        cluster,
        range(3),
        lambda i: make_transactions(f"s{i}", 4),
        chain=BC_DTBU,
        policy=SMALL,
        timestamp=1001.0,
    )
    assert result.block_count == 3
    assert read_chain(cluster).height == 3


def test_two_silent_replicas_are_reported_not_waited_on_forever() -> None:
    cluster = make_cluster()
    for rid in ("CS_1", "CS_2"):
        cluster.replicas[rid].behaviour = Silent()
    with pytest.raises(PipelineError, match="uncommitted"):
        run(cluster, [0], _two("t"), chain=BC_DTBU, policy=SMALL, timestamp=1001.0)
    assert set(cluster.heights().values()) == {0}
