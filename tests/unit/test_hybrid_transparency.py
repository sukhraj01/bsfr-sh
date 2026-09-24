"""Hybrid mode is transparent to the framework. M7-5.

The task brief's own exit condition: "hybrid mode produces identical application-level results
(same backups recovered, same detections fired) as private-only mode." `framework.hybrid_pipeline.
append` never changes what gets committed to a private chain (`blockchain.hybrid`'s module
docstring) — it calls the existing pipeline first, unmodified, and only reads afterward. These
tests demonstrate that claim end to end rather than asserting it structurally: same collector
key, same cluster construction, same seed, with the only difference being whether a `HybridChain`
observes the run afterward.

The detection leg stops at "the committed, decrypted chain content is identical" rather than
re-running `phase3_detection`'s full four-model fit twice (that path is already covered, without
hybrid, by `tests/integration/test_phase2_feeds_phase3.py`) — since `phase3_detection.run` is a
pure function of chain content, identical chain content is what "same detections fired" reduces
to, and keeping this in `tests/unit` (not `tests/integration`) means it runs in `make test`, not
only `make test-all`.
"""

from __future__ import annotations

from m3a_harness import make_server, make_system
from m3b_harness import SMALL, make_node
from pbft_harness import CONFIG, SIGRW_IDS, make_cluster

from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW
from bsfr_sh.blockchain.hybrid import AnchorPolicy, HybridChain
from bsfr_sh.blockchain.transaction import encrypt_signature_record
from bsfr_sh.crypto.ecdsa import keypair_from_secret
from bsfr_sh.framework import hybrid_pipeline
from bsfr_sh.framework import phase1_backup as phase1
from bsfr_sh.framework import phase2_collection as phase2
from bsfr_sh.framework import phase5_recovery as phase5
from bsfr_sh.framework._block_pipeline import read_chain
from bsfr_sh.recovery.locator import BackupIndex

POLICY = phase1.BackupPolicy.from_config(CONFIG)

_ANCHOR_KEY = keypair_from_secret(
    0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B
).private


def make_hybrid(chain_name: str, *, frequency: int = 1) -> HybridChain:
    return HybridChain(
        private_chain_name=chain_name,
        anchor_chain_name=f"{chain_name}_anchor",
        anchor_key=_ANCHOR_KEY,
        policy=AnchorPolicy(frequency=frequency),
    )


# --------------------------------------------------------------------------------------------
# "same backups recovered"
# --------------------------------------------------------------------------------------------
def _run_backup(*, hybrid: HybridChain | None):
    key_holder = make_server(10)
    cluster = make_cluster(submitters={key_holder.identity: key_holder.public_key})
    systems = [make_system(1, 500), make_system(2, 10 * 1024), make_system(3, 128)]
    index = BackupIndex(key_holder.decrypt)

    if hybrid is None:
        pipeline_result = phase1.run(
            systems=systems,
            collector=key_holder,
            cluster=cluster,
            policy=POLICY,
            captured_at=100,
            timestamp=1001.0,
        ).pipeline
    else:
        received = list(phase1.collect(systems, key_holder, captured_at=100))

        def build(item):
            manifest, data = item
            return phase1.backup_transactions(
                manifest,
                data,
                recipient=key_holder.public_key,
                chunk_bytes=POLICY.chunk_bytes,
                created_at=100,
            )

        pipeline_result = hybrid_pipeline.append(
            cluster,
            hybrid,
            received,
            build,
            policy=POLICY.pipeline,
            timestamp=1001.0,
            submitter_id=key_holder.identity,
            key=key_holder.keypair.private,
        )

    phase1.maintain_index(index, cluster)
    return cluster, key_holder, systems, index, pipeline_result


def test_hybrid_mode_recovers_the_same_backups_as_private_only() -> None:
    baseline_cluster, baseline_holder, baseline_systems, baseline_index, baseline_pipeline = (
        _run_backup(hybrid=None)
    )
    hybrid = make_hybrid(BC_DTBU, frequency=1)
    hy_cluster, hy_holder, hy_systems, hy_index, hy_pipeline = _run_backup(hybrid=hybrid)

    # Same private-chain outcome, block for block. `Block.nonce` (`RN`) is random per block by
    # design (block.py's module docstring) -- even two identical, non-hybrid runs would produce
    # different block hashes, so equality here is at the content level, not the hash level.
    assert baseline_pipeline.block_count == hy_pipeline.block_count
    assert baseline_pipeline.transaction_count == hy_pipeline.transaction_count
    baseline_chain = read_chain(baseline_cluster)
    hy_chain = read_chain(hy_cluster)
    assert baseline_chain.height == hy_chain.height
    for height in range(1, baseline_chain.height + 1):
        b1, b2 = baseline_chain.block_at(height), hy_chain.block_at(height)
        assert b1.transaction_count == b2.transaction_count
        for tx1, tx2 in zip(b1.transactions, b2.transactions, strict=True):
            assert baseline_holder.decrypt(tx1) == hy_holder.decrypt(tx2)

    # Same recovered bytes for every system, in both deployments.
    for i in range(1, 4):
        original = bytes(baseline_systems[i - 1].data)
        baseline_systems[i - 1].wipe()
        phase5.run(
            system=baseline_systems[i - 1],
            front=baseline_holder,
            key_holder=baseline_holder,
            chain=baseline_chain,
            index=baseline_index,
        )
        assert baseline_systems[i - 1].data == original

        hy_systems[i - 1].wipe()
        phase5.run(
            system=hy_systems[i - 1],
            front=hy_holder,
            key_holder=hy_holder,
            chain=hy_chain,
            index=hy_index,
        )
        assert hy_systems[i - 1].data == original

    # And hybrid mode anchored something, so the wrapper genuinely ran, not a no-op.
    assert len(hybrid.anchored_heights) == hy_pipeline.block_count


# --------------------------------------------------------------------------------------------
# "same detections fired" -- reduces to identical committed chain content; see module docstring.
# --------------------------------------------------------------------------------------------
def test_hybrid_mode_commits_the_same_sigrw_records_as_private_only() -> None:
    node = make_node(seed=777)
    collector = make_server(60)
    submitters = {collector.identity: collector.public_key}

    baseline_cluster = make_cluster(BC_SigRW, SIGRW_IDS, seed=21, submitters=submitters)
    phase2.run(
        node=node,
        collector=collector,
        cluster=baseline_cluster,
        policy=SMALL,
        count=20,
        timestamp=2001.0,
    )
    baseline_chain = read_chain(baseline_cluster)

    node2 = make_node(seed=777)  # fresh honeypot, identical seed -> identical synthetic draw
    hy_cluster = make_cluster(BC_SigRW, SIGRW_IDS, seed=21, submitters=submitters)
    hybrid = make_hybrid(BC_SigRW, frequency=1)

    raw = phase2.collect(node2, collector, count=20, malicious_fraction=0.5)
    cleaned, _ = phase2.clean(raw)
    records = phase2.build_records(cleaned, collector)

    def build(record):
        return (
            encrypt_signature_record(
                recipient=collector.public_key,
                tx_id=record.sample_id,
                payload=record,
                created_at=1,
            ),
        )

    hybrid_pipeline.append(
        hy_cluster,
        hybrid,
        records,
        build,
        policy=SMALL,
        timestamp=2001.0,
        submitter_id=collector.identity,
        key=collector.keypair.private,
    )
    hy_chain = read_chain(hy_cluster)

    # Content equality, not hash equality -- see the backup test's comment on `RN`.
    assert baseline_chain.height == hy_chain.height
    for height in range(1, baseline_chain.height + 1):
        b1, b2 = baseline_chain.block_at(height), hy_chain.block_at(height)
        assert b1.transaction_count == b2.transaction_count
        for tx1, tx2 in zip(b1.transactions, b2.transactions, strict=True):
            assert collector.decrypt(tx1) == collector.decrypt(tx2)

    assert len(hybrid.anchored_heights) == hy_chain.height
