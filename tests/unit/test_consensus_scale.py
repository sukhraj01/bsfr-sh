"""M2b exit condition — both chains, case 3 (15 blocks x 100 tx), through full pBFT consensus.

Each chain runs its own 4-replica cluster on its own bus (CLAUDE.md §4) with one byzantine
replica, so `f=1` is exercised at full size rather than asserted:

* `BC_DTBU` — the view-0 primary is **silent**: the first block forces a view change and the
  remaining fourteen commit under the view-1 primary.
* `BC_SigRW` — a backup signs everything with the **wrong key**: every one of its votes is
  refused and the three honest replicas carry the chain alone.

`test_chain_scale.py` builds the same sizes by direct append; this file is the same workload with
consensus deciding every append. It is a correctness test, not a timing run — consensus timing
is M6 (see `configs/bench.yaml` on what the zero-delay default means for Target 3).
"""

from __future__ import annotations

import pytest
from pbft_harness import (
    CONFIG,
    DTBU_IDS,
    GENESIS_TIME,
    RECIPIENT,
    SIGRW_IDS,
    Silent,
    WrongSignature,
    assert_no_fork,
    honest,
    make_cluster,
    run_for,
)

from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW
from bsfr_sh.blockchain.transaction import (
    BackupPayload,
    SignatureRecordPayload,
    Transaction,
    encrypt_backup,
    encrypt_signature_record,
)
from bsfr_sh.consensus.pbft import Cluster

#: PAPER §VII — read from config, never re-literalled.
BLOCKS = CONFIG.require("cases", dict)["case_3"]
TX_PER_BLOCK = CONFIG.require("block.transactions_per_block", int)
PAYLOAD_BYTES = CONFIG.require("transaction.payload_bytes", int)


def _backup_txs(block: int) -> tuple[Transaction, ...]:
    return tuple(
        encrypt_backup(
            recipient=RECIPIENT.public,
            tx_id=f"dtbu-{block:02d}-{i:03d}",
            payload=BackupPayload(
                system_id=f"SYS_{i % 8}",
                data=bytes([block, i % 256]) * (PAYLOAD_BYTES // 2),
                captured_at=1000 + block,
            ),
            created_at=1000 + block,
        )
        for i in range(TX_PER_BLOCK)
    )


def _signature_txs(block: int) -> tuple[Transaction, ...]:
    return tuple(
        encrypt_signature_record(
            recipient=RECIPIENT.public,
            tx_id=f"sigrw-{block:02d}-{i:03d}",
            payload=SignatureRecordPayload(
                sample_id=f"RW-{block:02d}-{i:03d}",
                content_digest=bytes([block, i % 256]) * 16,
                attestation=bytes(70),
                features=tuple(float(v) for v in range(24)),
                collected_at=1000 + block,
            ),
            created_at=1000 + block,
        )
        for i in range(TX_PER_BLOCK)
    )


def _build(cluster: Cluster, make_txs) -> None:  # type: ignore[no-untyped-def]
    for block in range(BLOCKS):
        cluster.submit(make_txs(block), timestamp=GENESIS_TIME + 1 + block)
        run_for(cluster)


@pytest.mark.slow
def test_both_chains_build_case_3_through_consensus_with_one_byzantine_replica_each() -> None:
    dtbu = make_cluster(BC_DTBU, DTBU_IDS, seed=1)
    dtbu.replicas["CS_0"].behaviour = Silent()
    sigrw = make_cluster(BC_SigRW, SIGRW_IDS, seed=2)
    sigrw.replicas["CS_7"].behaviour = WrongSignature()

    _build(dtbu, _backup_txs)
    _build(sigrw, _signature_txs)

    for cluster, bad in ((dtbu, "CS_0"), (sigrw, "CS_7")):
        rest = honest(cluster, {bad})
        assert len(rest) == 3
        for replica in rest:
            assert replica.height == BLOCKS
            assert replica.chain.transaction_count == BLOCKS * TX_PER_BLOCK
            replica.chain.verify_integrity()
        assert_no_fork(rest)

    # f=1 was genuinely exercised, not just configured.
    assert {r.view for r in honest(dtbu, {"CS_0"})} == {1}
    assert all(any(x.sender == "CS_7" for x in r.rejections) for r in honest(sigrw, {"CS_7"}))

    # Still two independent chains at full size.
    assert dtbu.network is not sigrw.network
    head_dtbu = dtbu.replicas["CS_1"].chain
    head_sigrw = sigrw.replicas["CS_4"].chain
    assert not {b.current_hash for b in head_dtbu} & {b.current_hash for b in head_sigrw}
