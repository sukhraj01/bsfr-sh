"""`recovery.locator`: Alg. 5 line 1, and DEV-05's claim that the index changes nothing but cost.

The central assertion is that `identify()` returns the *identical* tuple with and without a warm
index, for every system, including one with no backups. The fallback scan is the paper's semantics,
and the index is allowed only because it agrees with it.
"""

from __future__ import annotations

import pytest
from m3a_harness import (
    CHUNK,
    append_in_blocks,
    back_up_directly,
    collect_transactions,
    dtbu_chain,
    make_server,
    make_system,
    tamper_ciphertext,
)

from bsfr_sh.blockchain.chain import BC_SigRW, Chain
from bsfr_sh.recovery.locator import BackupIndex, RecoveryError, identify, scan

#: 3 chunks, one empty chunk, 7 chunks over 3 blocks, and exactly one full chunk.
SIZES = {1: 40, 2: 0, 3: 100, 4: CHUNK}
EVERY = [f"SYS_{i}" for i in (*SIZES, 9)]  # SYS_9 has no backups


@pytest.fixture
def world():
    chain = dtbu_chain()
    collector = make_server(10)
    systems = [make_system(i, size) for i, size in SIZES.items()]
    back_up_directly(chain, systems, collector)
    return chain, collector, systems


@pytest.mark.parametrize("system_id", EVERY)
def test_index_and_cold_scan_return_identical_locations(world, system_id) -> None:
    chain, collector, _ = world
    cold = identify(chain, system_id, decrypt=collector.decrypt)
    index = BackupIndex(collector.decrypt)
    index.sync(chain)
    assert identify(chain, system_id, decrypt=collector.decrypt, index=index) == cold
    assert cold == tuple(
        loc for loc in scan(chain, collector.decrypt) if loc.system_id == system_id
    )


def test_the_locations_cover_every_chunk_and_nothing_else(world) -> None:
    chain, collector, _ = world
    for i, size in SIZES.items():
        found = identify(chain, f"SYS_{i}", decrypt=collector.decrypt)
        assert sorted(loc.chunk_index for loc in found) == list(range(max(1, -(-size // CHUNK))))
        assert {loc.system_id for loc in found} == {f"SYS_{i}"}
    assert identify(chain, "SYS_9", decrypt=collector.decrypt) == ()


def test_the_fixture_exercises_a_multi_block_backup(world) -> None:
    chain, collector, _ = world
    assert len({loc.height for loc in identify(chain, "SYS_3", decrypt=collector.decrypt)}) > 1


def test_the_index_is_maintained_as_blocks_are_appended(world) -> None:
    chain, collector, systems = world
    index = BackupIndex(collector.decrypt)
    assert index.sync(chain) == chain.height + 1
    before = chain.height
    systems[0].data = b"a second, later capture" * 3
    back_up_directly(chain, systems[:1], collector, captured_at=200)
    assert index.sync(chain) == chain.height - before  # only what was appended since
    warm = identify(chain, "SYS_1", decrypt=collector.decrypt, index=index)
    assert warm == identify(chain, "SYS_1", decrypt=collector.decrypt)
    assert len({loc.backup_id for loc in warm}) == 2


def test_on_append_block_by_block_matches_the_scan(world) -> None:
    chain, collector, _ = world
    index = BackupIndex(collector.decrypt)
    for height, block in enumerate(chain):
        index.on_append(block, height)
    for system_id in EVERY:
        assert index.lookup(system_id) == identify(chain, system_id, decrypt=collector.decrypt)


def test_a_cold_index_falls_back_to_the_scan_and_stays_cold(world) -> None:
    chain, collector, _ = world
    index = BackupIndex(collector.decrypt)
    via_cold = identify(chain, "SYS_1", decrypt=collector.decrypt, index=index)
    assert via_cold == identify(chain, "SYS_1", decrypt=collector.decrypt)
    assert index.cold
    with pytest.raises(RecoveryError, match="cold"):
        index.lookup("SYS_1")


def test_an_index_built_on_another_chain_is_rebuilt_not_trusted(world) -> None:
    chain, collector, systems = world
    index = BackupIndex(collector.decrypt)
    index.sync(chain)
    other = dtbu_chain()
    back_up_directly(other, systems[2:3], collector, captured_at=300)
    assert identify(other, "SYS_1", decrypt=collector.decrypt, index=index) == ()
    assert index.rebuilds == 1
    via_index = identify(other, "SYS_3", decrypt=collector.decrypt, index=index)
    assert via_index == identify(other, "SYS_3", decrypt=collector.decrypt)


def test_blocks_must_reach_the_index_in_chain_order(world) -> None:
    chain, collector, _ = world
    with pytest.raises(RecoveryError, match="cannot index"):
        BackupIndex(collector.decrypt).on_append(chain.block_at(1), 1)


def test_another_collectors_backups_are_skipped_not_fatal(world) -> None:
    chain, collector, _ = world
    other_collector = make_server(11)
    append_in_blocks(chain, collect_transactions([make_system(7, 30)], other_collector))
    assert identify(chain, "SYS_7", decrypt=collector.decrypt) == ()
    assert len(identify(chain, "SYS_7", decrypt=other_collector.decrypt)) == 2


def test_backups_are_only_looked_for_on_bc_dtbu(world) -> None:
    _, collector, _ = world
    with pytest.raises(RecoveryError, match="§V-5"):
        identify(Chain(BC_SigRW), "SYS_1", decrypt=collector.decrypt)


@pytest.mark.parametrize("recompute_digest", [False, True], ids=["stale-digest", "fixed-digest"])
def test_a_tampered_block_stops_the_scan(world, recompute_digest) -> None:
    chain, collector, _ = world
    tamper_ciphertext(chain, 2, recompute_digest=recompute_digest)
    with pytest.raises(RecoveryError, match="failed verification"):
        identify(chain, "SYS_1", decrypt=collector.decrypt)
