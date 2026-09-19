"""Phase 2: Alg. 2, data collection, signature and feature generation. Output: `BC_SigRW`.

* **line 1**, deploy `HP_RW`: `honeypot.collector.Honeypot.deploy`.
* **line 2**, collect `DT_RW` over `SK_{CS_l,HP_RW}`: `collect`, which is
  `HoneypotNode.ship_samples` then `CloudServer.receive_samples`.
* **lines 3-4**, pre-process to `DT_RWC`: `honeypot.preprocess.clean` (DEV-26).
* **line 5**, `Sig_RW`: `honeypot.signatures.build` — digest plus `CS_l`'s attestation (DEV-03).
* **line 6**, `FT_RW`: `honeypot.features.build` (DEV-27).
* **line 7**, encrypt into `E_KU_CSl(Tx_i)`: `blockchain.transaction.encrypt_signature_record`.
* **lines 8-20**, assemble, broadcast, pBFT, terminate: `framework._block_pipeline.run`, exactly
  as Phase 1 uses it.

This module is the test of M3a's factoring: Phase 2 supplies a payload builder and a cluster, and
adds nothing else. If anything here had to reach into the pipeline, the factoring would have been
wrong — it did not.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from bsfr_sh.blockchain.chain import BC_SigRW
from bsfr_sh.blockchain.transaction import (
    SignatureRecordPayload,
    Transaction,
    encrypt_signature_record,
)
from bsfr_sh.consensus.pbft import Cluster
from bsfr_sh.framework import _block_pipeline as pipeline
from bsfr_sh.framework.entities import CloudServer, HoneypotNode, establish_session
from bsfr_sh.honeypot import features as ft
from bsfr_sh.honeypot import signatures
from bsfr_sh.honeypot.collector import RawSample
from bsfr_sh.honeypot.preprocess import CleaningReport, CleanSample, clean

__all__ = [
    "CollectionReport",
    "build_records",
    "collect",
    "run",
]


@dataclass(frozen=True)
class CollectionReport:
    """What one Phase 2 run harvested, cleaned and committed."""

    harvested: int
    cleaning: CleaningReport
    records: tuple[SignatureRecordPayload, ...]
    pipeline: pipeline.PipelineResult

    @property
    def committed(self) -> int:
        return self.pipeline.transaction_count


def collect(
    node: HoneypotNode, collector: CloudServer, *, count: int, malicious_fraction: float = 0.5
) -> tuple[RawSample, ...]:
    """Implements Alg. 2, lines 1-2: deploy `HP_RW`, harvest, ship over `SK_{CS_l,HP_RW}`."""
    if not node.has_session(collector.identity):
        establish_session(node, collector)
    envelope = node.ship_samples(
        collector.identity, count=count, malicious_fraction=malicious_fraction
    )
    return collector.receive_samples(envelope)


def build_records(
    samples: Sequence[CleanSample], collector: CloudServer
) -> tuple[SignatureRecordPayload, ...]:
    """Implements Alg. 2, lines 5-6: `Sig_RW` and `FT_RW` for each cleaned sample.

    `label` rides along as metadata because M4 needs ground truth to learn `NProf` and `AProf` at
    all; it is never part of `FT_RW` (DEV-27).
    """
    records: list[SignatureRecordPayload] = []
    for sample in samples:
        signature = signatures.build(
            sample, collector_key=collector.keypair.private, collector_id=collector.identity
        )
        vector = ft.build(sample)
        records.append(
            SignatureRecordPayload(
                sample_id=sample.sample_id,
                content_digest=signature.content_digest,
                attestation=signature.attestation,
                features=vector.values,
                collected_at=sample.collected_at,
                schema=vector.schema,
                missing_mask=vector.missing_mask,
                label=sample.label,
            )
        )
    return tuple(records)


def run(
    *,
    node: HoneypotNode,
    collector: CloudServer,
    cluster: Cluster,
    policy: pipeline.PipelinePolicy,
    count: int,
    timestamp: float,
    malicious_fraction: float = 0.5,
) -> CollectionReport:
    """Implements Alg. 2, lines 1-20: honeypot to `BC_SigRW`, through consensus."""
    raw = collect(node, collector, count=count, malicious_fraction=malicious_fraction)
    cleaned, report = clean(raw)
    records = build_records(cleaned, collector)

    def build(record: SignatureRecordPayload) -> tuple[Transaction, ...]:
        return (
            encrypt_signature_record(
                recipient=collector.public_key,
                tx_id=record.sample_id,
                payload=record,
                created_at=record.collected_at,
            ),
        )

    result = pipeline.run(
        cluster,
        records,
        build,
        chain=BC_SigRW,
        policy=policy,
        timestamp=timestamp,
        submitter_id=collector.identity,
        key=collector.keypair.private,
    )
    return CollectionReport(harvested=len(raw), cleaning=report, records=records, pipeline=result)
