"""M3a exit: data survives a full wipe and returns byte-identical, through pBFT on `BC_DTBU`.

This test uses the configured values throughout (`transaction.payload_bytes` chunks,
`block.transactions_per_block` per block, four replicas, `f = 1`), so it runs the deployment shape
rather than a scaled-down one. Fig. 3 steps (1)-(2), then Alg. 5.
"""

from __future__ import annotations

import pytest
from m3a_harness import make_server, make_system
from pbft_harness import CONFIG, Silent, make_cluster

from bsfr_sh.framework import phase1_backup as phase1
from bsfr_sh.framework import phase5_recovery as phase5
from bsfr_sh.framework._block_pipeline import batch, commit, read_chain
from bsfr_sh.recovery.locator import BackupIndex, identify

pytestmark = pytest.mark.integration

POLICY = phase1.BackupPolicy.from_config(CONFIG)
CHUNK = POLICY.chunk_bytes
PER_BLOCK = POLICY.pipeline.transactions_per_block
#: One chunk, a few chunks, exactly one chunk, and one backup that crosses two block boundaries
#: and ends in a remainder.
SIZES = {1: 500, 2: 10 * 1024, 3: CHUNK, 4: CHUNK * PER_BLOCK * 2 + 1234}


def _deploy(sizes=SIZES, *, silent=None):
    cluster = make_cluster()
    if silent is not None:
        cluster.replicas[silent].behaviour = Silent()
    key_holder, front = make_server(10), make_server(11)
    systems = {i: make_system(i, size) for i, size in sizes.items()}
    index = BackupIndex(key_holder.decrypt)
    report = phase1.run(
        systems=list(systems.values()),
        collector=key_holder,
        cluster=cluster,
        policy=POLICY,
        captured_at=100,
        timestamp=1001.0,
    )
    # Separate step on purpose: the paper has no index, so it stays out of Alg. 1's timed path
    # (DEV-05, M3b amendment).
    phase1.maintain_index(index, cluster)
    return cluster, key_holder, front, systems, index, report


def test_a_wiped_system_returns_byte_identical_through_consensus() -> None:
    cluster, key_holder, front, systems, index, report = _deploy()
    assert report.pipeline.block_count == 3  # 1 + 3 + 1 + 201 chunks = 206 = 100 + 100 + 6
    originals = {i: s.data for i, s in systems.items()}
    victim = systems[4]
    victim.wipe()
    result = phase5.run(
        system=victim, front=front, key_holder=key_holder, chain=read_chain(cluster), index=index
    )
    assert victim.data == originals[4]
    assert (result.located_by, result.hops, result.chunk_count) == ("index", 2, 201)
    assert all(systems[i].data == originals[i] for i in (1, 2, 3))


@pytest.mark.parametrize("system_id", [*(f"SYS_{i}" for i in SIZES), "SYS_9"])
def test_index_and_cold_scan_agree_on_the_committed_chain(system_id) -> None:
    cluster, key_holder, _, _, index, _ = _deploy()
    chain = read_chain(cluster)
    warm = identify(chain, system_id, decrypt=key_holder.decrypt, index=index)
    assert warm == identify(chain, system_id, decrypt=key_holder.decrypt)


def test_every_replica_holds_a_chain_the_system_can_be_restored_from() -> None:
    cluster, key_holder, front, systems, _, _ = _deploy({2: 10 * 1024})
    original = systems[2].data
    for replica in cluster.replicas.values():
        systems[2].wipe()
        phase5.run(system=systems[2], front=front, key_holder=key_holder, chain=replica.chain)
        assert systems[2].data == original


def test_restore_when_consensus_commits_the_chunks_out_of_order() -> None:
    cluster = make_cluster()
    key_holder, front = make_server(10), make_server(11)
    system = make_system(5, CHUNK * PER_BLOCK * 2 + 7)  # 201 chunks, three batches
    ((manifest, data),) = phase1.collect([system], key_holder, captured_at=100)
    txs = phase1.backup_transactions(
        manifest, data, recipient=key_holder.public_key, chunk_bytes=CHUNK, created_at=100
    )
    commit(cluster, batch(txs, PER_BLOCK)[::-1], timestamp=1001.0, wait_s=POLICY.pipeline.wait_s)
    chain = read_chain(cluster)
    height_of = {
        loc.chunk_index: loc.height for loc in identify(chain, "SYS_5", decrypt=key_holder.decrypt)
    }
    assert height_of[0] == 3 and height_of[200] == 1  # the first chunk committed last
    original = system.data
    system.wipe()
    phase5.run(system=system, front=front, key_holder=key_holder, chain=chain)
    assert system.data == original


def test_the_round_trip_survives_a_silent_primary() -> None:
    cluster, key_holder, front, systems, index, _ = _deploy({1: 500, 2: 3 * CHUNK}, silent="CS_0")
    original = systems[2].data
    systems[2].wipe()
    phase5.run(
        system=systems[2],
        front=front,
        key_holder=key_holder,
        chain=read_chain(cluster),
        index=index,
    )
    assert systems[2].data == original
