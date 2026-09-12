"""Phase 1: Alg. 1, creation of backups of data through blockchain. Output: `BC_DTBU`.

* **line 1**, `CS_l` collects `DT_BU` over `SK_{CS_l,SYS_i}`: `collect`, which is
  `System.ship_backup` then `CloudServer.receive_backup`.
* **line 2**, encrypt into `E_KU_CSl(Tx_m)`, `m = 1..N_dTx`: `backup_transactions`, which is
  `blockchain.backup.split` (DEV-24) then `encrypt_backup`.
* **lines 3-10**, assemble `β_j`, broadcast, pBFT, commit or re-run: `framework._block_pipeline.run`
  (DEV-22: the primary assembles).
* **lines 11-15**, terminate when all blocks are added: `run` returns once every request commits.

The submitter is authenticated twice. At the session layer, a backup only opens under the
`SK_{CS_l,SYS_i}` of the system that sent it. At the payload layer, it must be attested by that same
system (DEV-23). A system therefore cannot put a backup on the chain in another system's name,
which is the part of DEV-20 item 5 that concerns backups.

There is no ransomware concept here: Phase 1 runs before any infection exists.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from bsfr_sh.blockchain.backup import BackupManifest, chunk_tx_id, split
from bsfr_sh.blockchain.chain import BC_DTBU
from bsfr_sh.blockchain.transaction import Transaction, encrypt_backup
from bsfr_sh.consensus.pbft import Cluster
from bsfr_sh.crypto.ecdsa import PublicKey
from bsfr_sh.framework import _block_pipeline as pipeline
from bsfr_sh.framework.entities import CloudServer, System, establish_session
from bsfr_sh.recovery.locator import BackupIndex
from bsfr_sh.util.config import Config

__all__ = [
    "BackupPolicy",
    "BackupReceipt",
    "BackupReport",
    "backup_transactions",
    "collect",
    "maintain_index",
    "run",
]


@dataclass(frozen=True)
class BackupPolicy:
    """`transaction.payload_bytes` per transaction (DEV-24), plus the pipeline policy."""

    chunk_bytes: int
    pipeline: pipeline.PipelinePolicy

    @classmethod
    def from_config(cls, config: Config) -> BackupPolicy:
        return cls(
            chunk_bytes=config.require("transaction.payload_bytes", int),
            pipeline=pipeline.PipelinePolicy.from_config(config),
        )


@dataclass(frozen=True)
class BackupReceipt:
    """What one system's backup became."""

    system_id: str
    backup_id: str
    size: int
    chunk_count: int


@dataclass(frozen=True)
class BackupReport:
    receipts: tuple[BackupReceipt, ...]
    pipeline: pipeline.PipelineResult


def collect(
    systems: Sequence[System], collector: CloudServer, *, captured_at: int
) -> Iterator[tuple[BackupManifest, bytes]]:
    """Implements Alg. 1, line 1: each `SYS_i` ships `DT_BU` to `CS_l` over `SK_{CS_l,SYS_i}`."""
    for system in systems:
        if not system.has_session(collector.identity):
            establish_session(system, collector)
        yield collector.receive_backup(
            system.ship_backup(collector.identity, captured_at=captured_at)
        )


def backup_transactions(
    manifest: BackupManifest,
    data: bytes,
    *,
    recipient: PublicKey,
    chunk_bytes: int,
    created_at: int,
) -> tuple[Transaction, ...]:
    """Implements Alg. 1, line 2: `DT_BU` into `E_KU_CSl(Tx_m)`, `m = 1..N_dTx` (DEV-24 chunks)."""
    return tuple(
        encrypt_backup(
            recipient=recipient, tx_id=chunk_tx_id(chunk), payload=chunk, created_at=created_at
        )
        for chunk in split(manifest, data, chunk_bytes=chunk_bytes)
    )


def maintain_index(index: BackupIndex, cluster: Cluster) -> int:
    """Bring the key holder's `BackupIndex` level with the committed chain. Returns blocks indexed.

    DEV-05's "maintained on append", as a step of its own rather than a tail of `run()`. The
    paper's design has no index, so anything that times Alg. 1 must be able to exclude ours or
    report it separately: with this split, index maintenance cannot end up inside a measured
    append span by default (`configs/bench.yaml`, Target 3).
    """
    return index.sync(pipeline.read_chain(cluster))


def run(
    *,
    systems: Sequence[System],
    collector: CloudServer,
    cluster: Cluster,
    policy: BackupPolicy,
    captured_at: int,
    timestamp: float,
) -> BackupReport:
    """Implements Alg. 1, lines 1-15: back up every system in `systems` onto `BC_DTBU`.

    `collector` is `CS_l`; the backups are encrypted to its public key, so it is also the key
    holder `CS'_l` for recovering them (DEV-25). This function does **not** touch the
    `BackupIndex`: call `maintain_index()` for that, so index maintenance stays outside the span
    M6 times.
    """
    received = list(collect(systems, collector, captured_at=captured_at))

    def build(item: tuple[BackupManifest, bytes]) -> tuple[Transaction, ...]:
        manifest, data = item
        return backup_transactions(
            manifest,
            data,
            recipient=collector.public_key,
            chunk_bytes=policy.chunk_bytes,
            created_at=captured_at,
        )

    result = pipeline.run(
        cluster, received, build, chain=BC_DTBU, policy=policy.pipeline, timestamp=timestamp
    )
    receipts = tuple(
        BackupReceipt(
            system_id=manifest.system_id,
            backup_id=manifest.backup_id,
            size=len(data),
            chunk_count=max(1, -(-len(data) // policy.chunk_bytes)),
        )
        for manifest, data in received
    )
    return BackupReport(receipts=receipts, pipeline=result)
