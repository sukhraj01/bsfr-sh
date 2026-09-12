"""M3b exit: `BC_SigRW` builds 15 blocks x 100 real signature records through consensus.

The counterpart of M2a's `test_chain_scale.py` and M2b's `test_consensus_scale.py`, except that
every transaction here carries a real `Sig_RW` and `FT_RW` built by Phase 2 rather than filler.
"""

from __future__ import annotations

import pytest
from m3b_harness import make_node, make_server
from pbft_harness import CONFIG, SIGRW_IDS, make_cluster

from bsfr_sh.blockchain.chain import BC_SigRW
from bsfr_sh.blockchain.transaction import SignatureRecordPayload
from bsfr_sh.framework import phase2_collection as phase2
from bsfr_sh.framework._block_pipeline import PipelinePolicy, read_chain
from bsfr_sh.honeypot.features import FEATURE_NAMES, SCHEMA
from bsfr_sh.honeypot.signatures import SampleSignature

pytestmark = pytest.mark.integration

POLICY = PipelinePolicy.from_config(CONFIG)
BLOCKS = CONFIG.require("cases", dict)["case_3"]  # 15
PER_BLOCK = POLICY.transactions_per_block  # 100


def test_bc_sigrw_builds_case_three_from_real_records() -> None:
    cluster = make_cluster(BC_SigRW, SIGRW_IDS)
    node, collector = make_node(), make_server(10)
    # A few samples are dropped by cleaning, so harvest enough to fill the blocks and commit the
    # first BLOCKS * PER_BLOCK records exactly.
    report = phase2.run(
        node=node,
        collector=collector,
        cluster=cluster,
        policy=POLICY,
        count=BLOCKS * PER_BLOCK,
        timestamp=1001.0,
    )
    assert report.harvested == BLOCKS * PER_BLOCK
    assert report.pipeline.block_count >= BLOCKS - 1
    assert set(cluster.heights().values()) == {report.pipeline.block_count}

    chain = read_chain(cluster)
    assert chain.transaction_count == report.committed
    # Every committed record decrypts, carries the schema, and is attested by the collector.
    for height in range(1, chain.height + 1):
        for tx in chain.block_at(height).transactions:
            payload = SignatureRecordPayload.from_bytes(collector.decrypt(tx))
            assert payload.schema == SCHEMA
            assert len(payload.features) == len(FEATURE_NAMES)
            assert SampleSignature(
                content_digest=payload.content_digest,
                attestation=payload.attestation,
                collector_id=collector.identity,
                collected_at=payload.collected_at,
            ).verify(collector.public_key)
