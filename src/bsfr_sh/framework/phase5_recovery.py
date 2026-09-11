"""Phase 5: Alg. 5, data recovery through blockchain. Output: `DT_BU` restored on `SYS_i`.

| Alg. 5 | Step | Here |
|---|---|---|
| 1 | identify `SYS_i` | `System.request_recovery` → `accept_recovery_request`; `identify` |
| 2 | start recovery from `BC_DTBU` | `recovery.restore.begin` |
| 3 | request decryption of `E_KU(Tx_j)` | `restore.request_decrypt`, with the key holder's key |
| 4 | `CS'_l` decrypts, ships to `CS_l` over `SK_{CS'_l,CS_l}` | `recovery.restore.transfer` |
| 5 | `CS_l` → `SYS_i` over `SK_{CS_l,SYS_i}` | `recovery.restore.deliver` |
| 6 | `SYS_i` stores `DT_BU` | `System.restore` (DEV-23's check first) |
| 7-11 | terminate on success, else continue | `run` returns a report, or raises `RecoveryError` |

`key_holder` is `CS'_l`, the server the backup was encrypted to in Phase 1 (DEV-25), and `front`
is `CS_l`. The first hop is fidelity to §IV-E, not necessity. When both roles fall on one server
the hop has nowhere to go (a server holds no session with itself), so it is skipped.

"Else continue" (lines 7-11) is not a retry loop. Every failure here is a verification failure,
and repeating it gives the same answer. A failure raises and the caller decides what comes next,
which in M5 is Phase 4's Case-2.
"""

from __future__ import annotations

from dataclasses import dataclass

from bsfr_sh.blockchain.backup import pack
from bsfr_sh.blockchain.chain import Chain
from bsfr_sh.framework.entities import CloudServer, System, establish_session
from bsfr_sh.recovery import restore as alg5
from bsfr_sh.recovery.locator import BackupIndex, identify
from bsfr_sh.util.logging import event, get_logger

__all__ = ["RecoveryReport", "run"]

_LOG = get_logger("framework.phase5")


@dataclass(frozen=True)
class RecoveryReport:
    system_id: str
    backup_id: str
    captured_at: int
    size: int
    chunk_count: int
    located_by: str  # "index" or "scan"
    hops: int
    skipped: tuple[str, ...]


def run(
    *,
    system: System,
    front: CloudServer,
    key_holder: CloudServer,
    chain: Chain,
    index: BackupIndex | None = None,
) -> RecoveryReport:
    """Implements Alg. 5, lines 1-11: restore `system`'s newest complete backup from `chain`."""
    if not system.has_session(front.identity):
        establish_session(system, front)
    two_hops = front is not key_holder
    if two_hops and not front.has_session(key_holder.identity):
        establish_session(front, key_holder)

    system_id = front.accept_recovery_request(system.request_recovery(front.identity))
    located_by = "scan" if index is None or index.cold else "index"
    locations = identify(chain, system_id, decrypt=key_holder.decrypt, index=index)
    plan = alg5.begin(system_id, locations)
    manifest, data = alg5.request_decrypt(chain, plan, key_holder.decrypt)

    if two_hops:
        handed_over = alg5.transfer(manifest, data, key_holder.channel(front.identity))
        delivery = alg5.deliver(
            handed_over,
            inbound=front.channel(key_holder.identity),
            outbound=front.channel(system.identity),
        )
    else:
        delivery = front.channel(system.identity).seal(alg5.PURPOSE_DELIVERY, pack(manifest, data))
    restored = system.restore(delivery)

    report = RecoveryReport(
        system_id=system_id,
        backup_id=restored.backup_id,
        captured_at=restored.captured_at,
        size=len(data),
        chunk_count=len(plan.locations),
        located_by=located_by,
        hops=2 if two_hops else 1,
        skipped=plan.skipped,
    )
    event(
        _LOG,
        "phase5_restored",
        system=system_id,
        backup=restored.backup_id[:12],
        size=report.size,
        located_by=located_by,
        hops=report.hops,
    )
    return report
