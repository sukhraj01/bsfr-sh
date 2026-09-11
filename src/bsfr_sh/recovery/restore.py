"""Alg. 5 — data recovery through blockchain. Output: `DT_BU` restored.

| Alg. 5 | Step | Here |
|---|---|---|
| 1 | identify `SYS_i`'s backups | `recovery.locator.identify` (and `request` / `accept_request`) |
| 2 | start recovery from `BC_DTBU` | `begin` — choose the backup to restore |
| 3 | request decryption of `E_KU(Tx_j)` | `request_decrypt`: re-verify, decrypt, reassemble |
| 4 | `CS'_l` → `CS_l` over `SK_{CS'_l,CS_l}` | `transfer` |
| 5 | `CS_l` → `SYS_i` over `SK_{CS_l,SYS_i}` | `deliver` |
| 6 | `SYS_i` stores `DT_BU` | `open_delivery`, called by `framework.entities.System.restore` |

Two hops, and why both are built (DEV-25)
-----------------------------------------
Only the server a backup was encrypted to, `CS'_l`, can decrypt it. `CS_l` is the server `SYS_i`
recovers through. Recovery needs just one server that can decrypt and has a session with `SYS_i`.
The first hop exists because §IV-E specifies it: **it is fidelity to the paper, not necessity.**
When the two roles fall on the same server, `framework.phase5_recovery` skips it.

Who may recover what
--------------------
A recovery request names the system to recover and travels over the requester's own session.
`accept_request` refuses any target other than the authenticated peer. `deliver` refuses to seal
a backup to anyone but the system it belongs to. An intercepted delivery cannot be opened without
`SK_{CS_l,SYS_i}`. §V-1's session keys are what make "`SYS_j` recovers `SYS_i`'s data" impossible,
rather than merely unimplemented.

What is trusted
---------------
Nothing the locator returns is trusted. Every pointer is re-read from the chain, and every block it
names is re-verified (`Chain.verify_block`). `SYS_i` then checks the plaintext against the digest
it attested before backing up (DEV-23). Every failure raises, and none of them returns data.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from bsfr_sh.blockchain.backup import (
    BackupError,
    BackupManifest,
    pack,
    reassemble,
    unpack,
    verify_restored,
)
from bsfr_sh.blockchain.chain import BC_DTBU, Chain, ChainError
from bsfr_sh.blockchain.transaction import BackupPayload, TransactionError
from bsfr_sh.crypto.channel import Channel, Envelope
from bsfr_sh.crypto.ecdsa import PublicKey
from bsfr_sh.recovery.locator import BackupLocation, Decryptor, RecoveryError
from bsfr_sh.util.serialization import CanonicalEncodingError, decode, encode

__all__ = [
    "PURPOSE_DELIVERY",
    "PURPOSE_REQUEST",
    "PURPOSE_TRANSFER",
    "RecoveryError",
    "RecoveryPlan",
    "accept_request",
    "begin",
    "deliver",
    "open_delivery",
    "request",
    "request_decrypt",
    "transfer",
]

PURPOSE_REQUEST: Final = "alg5.request"
PURPOSE_TRANSFER: Final = "alg5.transfer"
PURPOSE_DELIVERY: Final = "alg5.delivery"


@dataclass(frozen=True)
class RecoveryPlan:
    """The backup `begin` chose, where its chunks are, and any newer backups it had to pass over."""

    system_id: str
    backup_id: str
    captured_at: int
    locations: tuple[BackupLocation, ...]
    skipped: tuple[str, ...]


# --------------------------------------------------------------------------------------------
# Line 1 — who is asking, for whom
# --------------------------------------------------------------------------------------------
def request(channel: Channel, system_id: str) -> Envelope:
    """`SYS_i` asks its front server `CS_l` to recover `system_id` over `SK_{CS_l,SYS_i}`."""
    return channel.seal(PURPOSE_REQUEST, encode(system_id))


def accept_request(envelope: Envelope, channel: Channel) -> str:
    """`CS_l`'s side of the request. Returns the system to recover, which is always the requester.

    The target is carried explicitly so that a request for someone else is *refused* rather than
    quietly reinterpreted. This is the check that makes one system unable to recover another's data.
    """
    raw = channel.open(envelope, PURPOSE_REQUEST)
    try:
        target = decode(raw)
    except CanonicalEncodingError as exc:
        raise RecoveryError(f"malformed recovery request: {exc}") from exc
    if target != channel.peer_id:
        raise RecoveryError(
            f"{channel.peer_id!r} asked to recover {target!r}; a system may recover only its own "
            f"backups"
        )
    return channel.peer_id


# --------------------------------------------------------------------------------------------
# Lines 2-3 — choose, re-verify, decrypt, reassemble
# --------------------------------------------------------------------------------------------
def begin(system_id: str, locations: Sequence[BackupLocation]) -> RecoveryPlan:
    """Implements Alg. 5, line 2: pick the newest *complete* backup of `SYS_i`.

    "Complete" here is judged from the locator's metadata; `request_decrypt` re-checks it from the
    decrypted chunks. A newer backup with chunks missing, for example one whose Phase 1 run did not
    finish committing, is passed over and named in `skipped` rather than failing the recovery.
    """
    groups: dict[str, list[BackupLocation]] = {}
    for location in locations:
        if location.system_id != system_id:
            raise RecoveryError(
                f"location for {location.system_id!r} passed to recover {system_id!r}"
            )
        groups.setdefault(location.backup_id, []).append(location)
    newest_first = sorted(
        groups.items(), key=lambda item: (item[1][0].captured_at, item[0]), reverse=True
    )
    skipped: list[str] = []
    for backup_id, group in newest_first:
        counts = {location.chunk_count for location in group}
        indices = {location.chunk_index for location in group}
        if len(counts) == 1 and indices == set(range(counts.pop())):
            return RecoveryPlan(
                system_id=system_id,
                backup_id=backup_id,
                captured_at=group[0].captured_at,
                locations=tuple(sorted(group)),
                skipped=tuple(skipped),
            )
        skipped.append(backup_id)
    raise RecoveryError(
        f"no complete backup of {system_id!r} on {BC_DTBU}"
        + (f" ({len(skipped)} incomplete)" if skipped else "")
    )


def request_decrypt(
    chain: Chain, plan: RecoveryPlan, decrypt: Decryptor
) -> tuple[BackupManifest, bytes]:
    """Implements Alg. 5, line 3 and `CS'_l`'s decryption in line 4.

    Reads each chunk from the chain rather than from the plan. The block it sits in is re-verified
    and the pointer is checked against it, then the chunk is decrypted, and finally the chunks are
    reassembled in `chunk_index` order (DEV-24).
    """
    if chain.name != BC_DTBU:
        raise RecoveryError(f"backups live on {BC_DTBU}, not {chain.name} (§V-5)")
    chunks: list[BackupPayload] = []
    for location in plan.locations:
        try:
            block = chain.verify_block(location.height)
        except ChainError as exc:
            raise RecoveryError(
                f"backup {plan.backup_id[:12]} is on a block that fails verification: {exc}"
            ) from exc
        if block.current_hash != location.block_hash or location.tx_index >= len(
            block.transactions
        ):
            raise RecoveryError(f"no transaction at height {location.height} matches the locator")
        tx = block.transactions[location.tx_index]
        if tx.tx_id != location.tx_id:
            raise RecoveryError(
                f"transaction at height {location.height} is not {location.tx_id!r}"
            )
        try:
            chunk = BackupPayload.from_bytes(decrypt(tx))
        except TransactionError as exc:
            raise RecoveryError(f"cannot decrypt {tx.tx_id!r}: {exc}") from exc
        if chunk.system_id != plan.system_id:
            raise RecoveryError(
                f"{tx.tx_id!r} belongs to {chunk.system_id!r}, not {plan.system_id!r}"
            )
        chunks.append(chunk)
    try:
        manifest, data = reassemble(chunks)
    except BackupError as exc:
        raise RecoveryError(f"backup {plan.backup_id[:12]} does not reassemble: {exc}") from exc
    if manifest.backup_id != plan.backup_id:
        raise RecoveryError("reassembled backup is not the one the plan chose")
    return manifest, data


# --------------------------------------------------------------------------------------------
# Lines 4-6 — the two hops, and SYS_i's check
# --------------------------------------------------------------------------------------------
def transfer(manifest: BackupManifest, data: bytes, channel: Channel) -> Envelope:
    """Implements Alg. 5, line 4: `CS'_l` hands `DT_BU` to `CS_l` over `SK_{CS'_l,CS_l}`.

    This hop is fidelity to §IV-E, not necessity (DEV-25).
    """
    return channel.seal(PURPOSE_TRANSFER, pack(manifest, data))


def deliver(envelope: Envelope, *, inbound: Channel, outbound: Channel) -> Envelope:
    """Implements Alg. 5, line 5: `CS_l` opens the transfer and seals it to `SYS_i`.

    `inbound` is `CS_l`'s side of `SK_{CS'_l,CS_l}` and `outbound` its side of `SK_{CS_l,SYS_i}`.
    Refuses to deliver a backup to any system but the one it belongs to.
    """
    raw = inbound.open(envelope, PURPOSE_TRANSFER)
    try:
        manifest, _ = unpack(raw)
    except BackupError as exc:
        raise RecoveryError(f"transfer from {inbound.peer_id!r} is malformed: {exc}") from exc
    if manifest.system_id != outbound.peer_id:
        raise RecoveryError(
            f"refusing to deliver {manifest.system_id!r}'s backup to {outbound.peer_id!r}"
        )
    return outbound.seal(PURPOSE_DELIVERY, raw)


def open_delivery(
    envelope: Envelope, channel: Channel, *, system_public: PublicKey
) -> tuple[BackupManifest, bytes]:
    """`SYS_i`'s side of line 5 plus DEV-23's end-to-end check. Only returns data that passes it."""
    raw = channel.open(envelope, PURPOSE_DELIVERY)
    try:
        manifest, data = unpack(raw)
        verify_restored(manifest, data, system_id=channel.local_id, system_public=system_public)
    except BackupError as exc:
        raise RecoveryError(f"restored backup rejected: {exc}") from exc
    return manifest, data
