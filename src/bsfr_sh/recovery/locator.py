"""Finding a system's backups on `BC_DTBU`: Alg. 5 line 1, with DEV-05's index.

The paper's semantics are a scan. Walk the chain, and for every backup transaction ask whether it
belongs to `SYS_i`. `scan()` does exactly that. `BackupIndex` gives the same answer without
walking the chain at lookup time. Its test, and the reason it is allowed to exist, is that
`identify()` returns the identical tuple through either path.

Who can build the index (DEV-05 amendment)
------------------------------------------
M2a put `system_id` *inside* the encrypted payload, so which systems backed up when is not public.
An index keyed on `system_id` can therefore only be built by the holder of the key the backups were
encrypted to, `CS'_l` (DEV-25). It decrypts each backup transaction once, when the block is
appended. The index moves that decryption from recovery time to append time. It does not remove
it. What becomes independent of chain length is the lookup.

What the index stores, and why it is not trusted
------------------------------------------------
The index stores pointers (height, block hash, position, tx id) plus the chunk metadata it read,
and no plaintext. `recovery.restore` re-reads and re-verifies the block behind every pointer, so a
stale or corrupted index can cost a fallback scan but cannot change what is restored. An index
whose anchor (the hash of the last block it indexed) no longer matches the chain is discarded and
rebuilt by a full scan.

Which transactions are skipped
------------------------------
Every block is re-verified first (`Chain.verify_block`: Merkle root, each transaction's digest
against its contents, signature). A backup transaction in a verified block that still fails to
decrypt was not encrypted to this key holder. Another collector's backups share `BC_DTBU`, so it
is skipped. Tampering never reaches that branch: it fails verification, which raises.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Final

from bsfr_sh.blockchain.backup import manifest_of
from bsfr_sh.blockchain.block import Block
from bsfr_sh.blockchain.chain import BC_DTBU, Chain, ChainError
from bsfr_sh.blockchain.transaction import (
    PAYLOAD_TYPE_BACKUP,
    BackupPayload,
    Transaction,
    TransactionError,
)

__all__ = [
    "BackupIndex",
    "BackupLocation",
    "Decryptor",
    "RecoveryError",
    "identify",
    "scan",
]

#: A key holder's decryption of one transaction — `CloudServer.decrypt` in `framework.entities`.
#: A callable rather than the server, because `recovery` may not import `framework`.
Decryptor = Callable[[Transaction], bytes]

_COLD: Final = -1


class RecoveryError(ValueError):
    """Raised when recovery cannot locate, verify, decrypt, reassemble, or deliver a backup."""


@dataclass(frozen=True, order=True)
class BackupLocation:
    """Where one chunk of one backup sits on `BC_DTBU`. Ordered by chain position."""

    height: int
    tx_index: int
    block_hash: bytes
    tx_id: str
    system_id: str
    backup_id: str
    captured_at: int
    chunk_index: int
    chunk_count: int


def _locations_in(block: Block, height: int, decrypt: Decryptor) -> Iterator[BackupLocation]:
    for position, tx in enumerate(block.transactions):
        if tx.payload_type != PAYLOAD_TYPE_BACKUP:
            continue
        try:
            chunk = BackupPayload.from_bytes(decrypt(tx))
        except TransactionError:
            continue  # encrypted to another key holder; see the module docstring
        yield BackupLocation(
            height=height,
            tx_index=position,
            block_hash=block.current_hash,
            tx_id=tx.tx_id,
            system_id=chunk.system_id,
            backup_id=manifest_of(chunk).backup_id,
            captured_at=chunk.captured_at,
            chunk_index=chunk.chunk_index,
            chunk_count=chunk.chunk_count,
        )


def _verified(chain: Chain, height: int) -> Block:
    try:
        return chain.verify_block(height)
    except ChainError as exc:
        raise RecoveryError(
            f"{chain.name} failed verification while locating backups: {exc}"
        ) from exc


def scan(chain: Chain, decrypt: Decryptor, *, from_height: int = 0) -> tuple[BackupLocation, ...]:
    """Every backup chunk on `chain` this key holder can open, in chain order. The paper's scan."""
    return tuple(
        location
        for height in range(from_height, chain.height + 1)
        for location in _locations_in(_verified(chain, height), height, decrypt)
    )


class BackupIndex:
    """DEV-05: per-system pointers into `BC_DTBU`, maintained as blocks are appended.

    Owned by the key holder `CS'_l`. Cold until the first block is indexed. `on_append` is the
    append-time hook, and `sync` catches up with a chain by feeding it every block above the
    indexed height.
    """

    __slots__ = ("_anchor", "_by_system", "_decrypt", "_height", "rebuilds")

    def __init__(self, decrypt: Decryptor) -> None:
        self._decrypt = decrypt
        self._by_system: dict[str, list[BackupLocation]] = {}
        self._height = _COLD
        self._anchor: bytes | None = None
        #: How many times a stale index was discarded and rebuilt from a full scan.
        self.rebuilds = 0

    @property
    def cold(self) -> bool:
        return self._height == _COLD

    @property
    def height(self) -> int:
        """The highest height indexed, or -1 when cold."""
        return self._height

    def on_append(self, block: Block, height: int) -> None:
        """Index the block just appended at `height`. Heights must arrive in chain order."""
        if height != self._height + 1:
            raise RecoveryError(f"index is at height {self._height}; cannot index {height} next")
        if self._anchor is not None and block.prev_hash != self._anchor:
            raise RecoveryError(f"block at height {height} does not extend the indexed chain")
        for location in _locations_in(block, height, self._decrypt):
            self._by_system.setdefault(location.system_id, []).append(location)
        self._height = height
        self._anchor = block.current_hash

    def sync(self, chain: Chain) -> int:
        """Bring the index level with `chain`. Returns how many blocks were indexed.

        If the block the index last saw is no longer at that height (a different chain, or a
        shorter one), the index is stale. It is reset and rebuilt from genesis rather than patched.
        """
        if chain.name != BC_DTBU:
            raise RecoveryError(f"backups live on {BC_DTBU}, not {chain.name} (§V-5)")
        if not self.cold and (
            self._height > chain.height or chain.block_at(self._height).current_hash != self._anchor
        ):
            self.reset()
            self.rebuilds += 1
        start = self._height + 1
        for height in range(start, chain.height + 1):
            self.on_append(_verified(chain, height), height)
        return chain.height + 1 - start

    def lookup(self, system_id: str) -> tuple[BackupLocation, ...]:
        if self.cold:
            raise RecoveryError("index is cold; use identify(), which falls back to a scan")
        return tuple(sorted(self._by_system.get(system_id, ())))

    def reset(self) -> None:
        self._by_system.clear()
        self._height = _COLD
        self._anchor = None


def identify(
    chain: Chain, system_id: str, *, decrypt: Decryptor, index: BackupIndex | None = None
) -> tuple[BackupLocation, ...]:
    """Implements Alg. 5, line 1: every chunk of every backup of `SYS_i` on `BC_DTBU`. DEV-05.

    With no index, or a cold one, this is the paper's full scan. With a warm index, it brings the
    index level with the chain (indexing only blocks appended since) and looks up. Both paths
    return the same tuple, sorted by position.
    """
    if chain.name != BC_DTBU:
        raise RecoveryError(f"backups live on {BC_DTBU}, not {chain.name} (§V-5)")
    if index is None or index.cold:
        return tuple(loc for loc in scan(chain, decrypt) if loc.system_id == system_id)
    index.sync(chain)
    return index.lookup(system_id)
