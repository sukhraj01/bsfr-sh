"""`framework.phase1_backup`: Alg. 1 through pBFT on a four-replica `BC_DTBU` cluster."""

from __future__ import annotations

from m3a_harness import make_server, make_system
from pbft_harness import CONFIG, POLICY, make_cluster

from bsfr_sh.blockchain.backup import reassemble
from bsfr_sh.blockchain.transaction import BackupPayload
from bsfr_sh.framework import phase1_backup as phase1
from bsfr_sh.framework._block_pipeline import PipelinePolicy, read_chain
from bsfr_sh.recovery.locator import BackupIndex, identify

SMALL = phase1.BackupPolicy(
    chunk_bytes=64,
    pipeline=PipelinePolicy(transactions_per_block=4, wait_s=15 * POLICY.view_change_timeout_s),
)


def _run(systems, collector, **kwargs):
    cluster = make_cluster()
    report = phase1.run(
        systems=systems,
        collector=collector,
        cluster=cluster,
        policy=SMALL,
        captured_at=100,
        timestamp=1001.0,
        **kwargs,
    )
    return cluster, report


def test_policy_comes_from_config() -> None:
    policy = phase1.BackupPolicy.from_config(CONFIG)
    assert policy.chunk_bytes == CONFIG.require("transaction.payload_bytes", int)
    assert policy.pipeline.transactions_per_block == CONFIG.require(
        "block.transactions_per_block", int
    )


def test_backups_reach_bc_dtbu_through_consensus_and_decrypt_to_what_was_shipped() -> None:
    collector = make_server(10)
    systems = [make_system(1, 64 * 4 + 1), make_system(2, 64), make_system(3, 0)]
    cluster, report = _run(systems, collector)
    assert [r.chunk_count for r in report.receipts] == [5, 1, 1]
    assert (report.pipeline.transaction_count, report.pipeline.block_count) == (7, 2)
    assert set(cluster.heights().values()) == {2}
    chain = read_chain(cluster)
    for system in systems:
        chunks = [
            BackupPayload.from_bytes(
                collector.decrypt(chain.block_at(loc.height).transactions[loc.tx_index])
            )
            for loc in identify(chain, system.identity, decrypt=collector.decrypt)
        ]
        assert reassemble(chunks)[1] == system.data


def test_a_backup_larger_than_a_block_spans_blocks() -> None:
    collector = make_server(10)
    cluster, _ = _run([make_system(1, 64 * 9 + 10)], collector)  # 10 chunks, 4 per block
    found = identify(read_chain(cluster), "SYS_1", decrypt=collector.decrypt)
    assert {loc.height for loc in found} == {1, 2, 3}


def test_the_key_holders_index_is_brought_level_on_append() -> None:
    collector = make_server(10)
    index = BackupIndex(collector.decrypt)
    cluster, _ = _run([make_system(1, 300), make_system(2, 10)], collector, index=index)
    chain = read_chain(cluster)
    assert not index.cold
    assert index.height == chain.height
    assert index.lookup("SYS_1") == identify(chain, "SYS_1", decrypt=collector.decrypt)


def test_the_chain_does_not_name_the_systems_it_holds_backups_for() -> None:
    collector = make_server(10)
    system = make_system(1, 200)
    cluster, _ = _run([system], collector)
    for block in read_chain(cluster):
        for tx in block.transactions:
            assert "SYS" not in tx.tx_id
            assert system.data[:32] not in tx.ciphertext
