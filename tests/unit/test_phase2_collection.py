"""`framework.phase2_collection`: Alg. 2 onto `BC_SigRW`, on M3a's pipeline unchanged."""

from __future__ import annotations

import pytest
from m3b_harness import SMALL, make_node, make_server
from pbft_harness import DTBU_IDS, SIGRW_IDS, make_cluster

from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW
from bsfr_sh.blockchain.transaction import SignatureRecordPayload
from bsfr_sh.framework import phase2_collection as phase2
from bsfr_sh.framework._block_pipeline import PipelineError, read_chain
from bsfr_sh.framework.entities import EntityError, establish_session
from bsfr_sh.honeypot.features import FEATURE_NAMES, SCHEMA
from bsfr_sh.honeypot.signatures import SampleSignature


def _run(count: int = 9):
    cluster = make_cluster(BC_SigRW, SIGRW_IDS)
    node, collector = make_node(), make_server(10)
    report = phase2.run(
        node=node,
        collector=collector,
        cluster=cluster,
        policy=SMALL,
        count=count,
        timestamp=1001.0,
    )
    return cluster, collector, report


def test_records_reach_bc_sigrw_through_consensus() -> None:
    cluster, _, report = _run(9)
    assert report.harvested == 9
    assert report.committed == len(report.records)
    assert report.pipeline.chain_name == BC_SigRW
    assert report.pipeline.block_count == -(-len(report.records) // SMALL.transactions_per_block)
    assert set(cluster.heights().values()) == {report.pipeline.block_count}


def test_the_round_trip_returns_the_features_intact() -> None:
    """harvest -> preprocess -> sign -> encrypt -> chain -> decrypt -> features recovered."""
    cluster, collector, report = _run(9)
    chain = read_chain(cluster)
    on_chain = {
        payload.sample_id: payload
        for height in range(1, chain.height + 1)
        for payload in (
            SignatureRecordPayload.from_bytes(collector.decrypt(tx))
            for tx in chain.block_at(height).transactions
        )
    }
    assert set(on_chain) == {r.sample_id for r in report.records}
    for built in report.records:
        assert on_chain[built.sample_id] == built
        assert on_chain[built.sample_id].features == built.features
        assert on_chain[built.sample_id].schema == SCHEMA
        assert len(built.features) == len(FEATURE_NAMES)


def test_the_attestation_on_chain_verifies_under_the_collectors_key() -> None:
    cluster, collector, _ = _run(5)
    chain = read_chain(cluster)
    for height in range(1, chain.height + 1):
        for tx in chain.block_at(height).transactions:
            payload = SignatureRecordPayload.from_bytes(collector.decrypt(tx))
            signature = SampleSignature(
                content_digest=payload.content_digest,
                attestation=payload.attestation,
                collector_id=collector.identity,
                collected_at=payload.collected_at,
            )
            assert signature.verify(collector.public_key)


def test_the_label_rides_as_metadata_and_the_vector_stays_clean() -> None:
    _, _, report = _run(6)
    assert {r.label for r in report.records} <= {"RW", "benign"}
    assert all(len(r.features) == len(FEATURE_NAMES) for r in report.records)
    assert all(r.missing_mask < 1 << len(FEATURE_NAMES) for r in report.records)


def test_records_are_refused_by_the_other_chains_cluster() -> None:
    cluster = make_cluster(BC_DTBU, DTBU_IDS)
    node, collector = make_node(), make_server(10)
    with pytest.raises(PipelineError, match="refusing"):
        phase2.run(
            node=node,
            collector=collector,
            cluster=cluster,
            policy=SMALL,
            count=4,
            timestamp=1001.0,
        )
    assert set(cluster.heights().values()) == {0}


def test_the_collector_refuses_a_harvest_from_a_peer_it_has_no_session_with() -> None:
    node, collector, stranger = make_node(), make_server(10), make_server(11)
    establish_session(node, collector)
    envelope = node.ship_samples(collector.identity, count=3)
    with pytest.raises(EntityError, match="no session"):
        stranger.receive_samples(envelope)


def test_phase_two_adds_no_pipeline_of_its_own() -> None:
    """If Phase 2 needed its own batching or submission, M3a's factoring would have been wrong."""
    source = phase2.__file__
    with open(source, encoding="utf-8") as handle:  # noqa: PTH123 - reading our own module
        text = handle.read()
    assert "Cluster.submit" not in text
    assert "def batch" not in text
    assert "pipeline.run(" in text
