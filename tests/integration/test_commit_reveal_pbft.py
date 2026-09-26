"""Commit-reveal + real pBFT: a withheld (crashed) node's batch is excluded, and the round still
commits through actual consensus on the remaining honest batch. M7-14, DEV-40.

The TESTS section's own requirement: "Commit-reveal + pBFT together still tolerate f=1 crash
fault (a crashed node that never reveals is equivalent to a withholder)." This is the one
commit-reveal test that needs a real `Cluster`/`_block_pipeline` round trip rather than the pure
protocol-object tests in `tests/unit/test_commit_reveal.py` — everything up to `finalize()` is
unit-tested there; this file is what proves the merged, verified batch actually reaches
`BC_SigRW` through the unmodified pBFT machinery.
"""

from __future__ import annotations

import pytest
from pbft_harness import GENESIS_TIME, REPO_ROOT, SIGRW_IDS, make_cluster

from bsfr_sh.blockchain.chain import BC_SigRW
from bsfr_sh.blockchain.transaction import (
    SignatureRecordPayload,
    Transaction,
    encrypt_signature_record,
)
from bsfr_sh.crypto.ecdsa import keypair_from_secret
from bsfr_sh.framework._block_pipeline import PipelinePolicy
from bsfr_sh.framework.commit_reveal_pipeline import submit_with_commit_reveal
from bsfr_sh.util.config import load_config

pytestmark = pytest.mark.integration

CHAIN_CONFIG = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
POLICY = PipelinePolicy.from_config(CHAIN_CONFIG)

_RECIPIENT = keypair_from_secret(0x5EED5EED)
_SUBMITTER_ID = "CS_coordinator"
_SUBMITTER = keypair_from_secret(0x5AB4171E)


def _payload(sample_id: str, value: float) -> SignatureRecordPayload:
    return SignatureRecordPayload(
        sample_id=sample_id,
        content_digest=b"\x00" * 32,
        attestation=b"\x01" * 64,
        features=(value, value * 2.0),
        collected_at=0,
        schema="ft_rw.v1",
        missing_mask=0,
        label="benign",
    )


def _builder(record: SignatureRecordPayload) -> tuple[Transaction, ...]:
    return (
        encrypt_signature_record(
            recipient=_RECIPIENT.public,
            tx_id=record.sample_id,
            payload=record,
            created_at=record.collected_at,
        ),
    )


def test_a_withheld_batch_is_excluded_and_the_honest_batch_still_commits() -> None:
    submitters = {_SUBMITTER_ID: _SUBMITTER.public}
    cluster = make_cluster(BC_SigRW, SIGRW_IDS, seed=20260927, submitters=submitters)

    node_batches = {
        "CS_honest": (_payload("s-honest-0", 1.0), _payload("s-honest-1", 2.0)),
        "CS_crashed": (_payload("s-crashed-0", 999.0),),
    }
    pipeline_result, round_result = submit_with_commit_reveal(
        cluster,
        node_batches,
        _builder,
        chain=BC_SigRW,
        policy=POLICY,
        timestamp=GENESIS_TIME,
        submitter_id=_SUBMITTER_ID,
        key=_SUBMITTER.private,
        reveal_node_ids=("CS_honest",),  # CS_crashed never reveals -- modelling a crash
    )

    assert round_result.included_node_ids == ("CS_honest",)
    assert round_result.excluded_node_ids == ("CS_crashed",)
    assert round_result.exclusion_reasons["CS_crashed"] == "withheld reveal"
    assert {p.sample_id for p in round_result.merged} == {"s-honest-0", "s-honest-1"}

    # The real pipeline committed exactly the honest batch's two transactions, through actual
    # pBFT consensus at the cluster's ordinary n=4, f=1, threshold=3 -- nothing about the
    # crashed node's non-participation changed the vote-counting.
    assert pipeline_result.transaction_count == 2
    assert pipeline_result.block_count >= 1

    chain = next(iter(cluster.replicas.values())).chain
    committed_ids = set()
    for height in range(1, chain.height + 1):
        for tx in chain.block_at(height).transactions:
            committed_ids.add(tx.tx_id)
    assert committed_ids == {"s-honest-0", "s-honest-1"}
    assert "s-crashed-0" not in committed_ids
