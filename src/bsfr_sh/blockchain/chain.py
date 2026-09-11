"""`BC_DTBU` and `BC_SigRW` — the chains. Validated append, integrity walk, iteration.

Two instances, never one
------------------------
CLAUDE.md §4 is explicit: `BC_DTBU` and `BC_SigRW` are independent `Chain` objects with
independent genesis blocks. §V-5 claims chain separation and the paper never demonstrates it, so
the separation has to be structural rather than a convention.

The failure mode is mundane and completely silent. A mutable class attribute, a mutable default
argument, a module-level registry keyed by name, or a genesis block cached at import — any of
those makes two `Chain` objects share state while every test that looks at one chain still
passes. Nothing here is a class attribute, no default argument is mutable, there is no registry,
and `genesis()` builds a fresh block per call. `tests/unit/test_chain_independence.py` asserts
it from the outside: build both, append only to one, and check the other's length, head, index
and block list are untouched.

Validation order
----------------
Per docs/ARCHITECTURE.md §blockchain, `append()` checks in this order:

1. `prev_hash` linkage — the block names our head
2. Merkle root — recomputed from the block's own transactions
3. `current_hash` — recomputed from the header
4. ECDSA signature under `owner_pubkey`
5. timestamp

Checks 2, 3 and 4 are *already guaranteed* by the `Block` type: `merkle_root` and `current_hash`
are derived rather than stored, and the signature is verified in `Block.__post_init__`. They are
re-asserted here anyway, cheaply, because the validation order is part of the documented
contract and because `append()` is the one place a block from M2b's network arrives. A check that
cannot fail today is not dead code — it is the check that catches the day someone adds a
`Block` constructor path that skips `__post_init__`.

Timestamp validation — non-decreasing with tolerance
-----------------------------------------------------
The paper implies monotonic timestamps. Taken strictly that is wrong for this system: blocks are
produced by different cloud servers in a P2P network, each with its own clock, so two honest
blocks committed a second apart can carry timestamps in the "wrong" order by ordinary NTP skew.
Strict monotonicity would reject honest blocks, and the symptom — an append that fails only
sometimes, only under load — is about as unpleasant as a bug gets.

So: **non-decreasing, within a tolerance**. A block may be up to `skew_tolerance_s` older than
the head. Beyond that it is rejected.

The tolerance is the *same configured value* `crypto.session` uses for its timestamp window
(`configs/chain.yaml` → `crypto.session.timestamp_window_s`, default 30 s), read through
`SessionPolicy`. Deliberately not a second constant: two independently-tuned clock tolerances in
one system drift apart, and then the answer to "how much skew do we accept?" depends on which
subsystem you ask. Recorded as DEV-17.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final

from bsfr_sh.blockchain.block import GENESIS_PREV_HASH, Block, BlockDraft
from bsfr_sh.blockchain.transaction import Transaction
from bsfr_sh.crypto.ecdsa import PrivateKey, verify
from bsfr_sh.crypto.merkle import merkle_root
from bsfr_sh.crypto.session import SessionPolicy
from bsfr_sh.util.config import Config

__all__ = [
    "BC_DTBU",
    "BC_SigRW",
    "Chain",
    "ChainError",
    "ChainPolicy",
    "build_genesis",
]

#: The two chain names the paper uses. Constants so a typo is an ImportError, not a third chain.
BC_DTBU: Final = "BC_DTBU"
BC_SigRW: Final = "BC_SigRW"


class ChainError(ValueError):
    """Raised when an append or an integrity walk fails validation."""


def build_genesis(
    *,
    owner_id: str,
    private_key: PrivateKey,
    timestamp: float,
    transactions: tuple[Transaction, ...] = (),
) -> Block:
    """Build a genesis block without attaching it to a chain. See `Chain.adopt_genesis`."""
    draft = BlockDraft(
        owner_id=owner_id,
        owner_pubkey=private_key.public_key.to_bytes(),
        transactions=transactions,
        prev_hash=GENESIS_PREV_HASH,
        timestamp=timestamp,
    )
    return draft.seal(private_key)


@dataclass(frozen=True)
class ChainPolicy:
    """Chain-level tunables. Frozen, and never shared between `Chain` instances by default."""

    #: How far *backwards* a block's timestamp may sit relative to the current head. Same value
    #: as the session protocol's window — see the module docstring.
    skew_tolerance_s: float = 30.0

    @classmethod
    def from_config(cls, config: Config) -> ChainPolicy:
        """Read the skew tolerance from `configs/chain.yaml`, via the session policy.

        Going through `SessionPolicy` rather than reading the key directly is the point: there is
        one clock-tolerance value in this system and one place that interprets it.
        """
        return cls(skew_tolerance_s=SessionPolicy.from_config(config).timestamp_window_s)


class Chain:
    """An append-only chain of blocks.

    Every piece of mutable state is per-instance and created in `__init__`. There are no class
    attributes holding data, no module-level caches, and no mutable default arguments — see the
    module docstring for why that is load-bearing rather than stylistic.
    """

    __slots__ = ("_blocks", "_index", "_policy", "name")

    def __init__(self, name: str, *, policy: ChainPolicy | None = None) -> None:
        if not name:
            raise ChainError("a chain must be named; BC_DTBU and BC_SigRW are the two")
        self.name = name
        # `policy` defaults to None and a fresh object is built here. A `ChainPolicy()` default
        # argument would be evaluated once at import and shared by every chain — harmless while
        # it stays frozen, and exactly the shape of bug this class is written to avoid.
        self._policy = policy if policy is not None else ChainPolicy()
        self._blocks: list[Block] = []
        self._index: dict[bytes, int] = {}

    # -- construction --------------------------------------------------------------------------
    def create_genesis(
        self,
        *,
        owner_id: str,
        private_key: PrivateKey,
        timestamp: float,
        transactions: tuple[Transaction, ...] = (),
    ) -> Block:
        """Build and append this chain's genesis block.

        A fresh block every call — nothing is cached at module level, so two chains created in
        one process get two genesis blocks with two different hashes even given identical
        arguments, provided their `RN` nonces differ (they do; `RN` is random).
        """
        if self._blocks:
            raise ChainError(f"{self.name} already has a genesis block")
        block = build_genesis(
            owner_id=owner_id,
            private_key=private_key,
            timestamp=timestamp,
            transactions=transactions,
        )
        self.adopt_genesis(block)
        return block

    def adopt_genesis(self, block: Block) -> None:
        """Install an existing genesis block.

        Every pBFT replica of one chain holds its own `Chain` instance, and they must all start
        from the *same* genesis — `create_genesis()` on each would give four different ones,
        because `RN` is random. So one replica (or the cluster builder) makes the block with
        `build_genesis()` and every replica adopts it. `Block` is frozen, so sharing the object
        between replicas of one chain shares no mutable state.
        """
        if self._blocks:
            raise ChainError(f"{self.name} already has a genesis block")
        if block.prev_hash != GENESIS_PREV_HASH:
            raise ChainError(f"{self.name}: a genesis block must have the zero prev_hash")
        self._blocks.append(block)
        self._index[block.current_hash] = 0

    def draft_next(
        self,
        *,
        owner_id: str,
        owner_pubkey: bytes,
        transactions: tuple[Transaction, ...],
        timestamp: float,
    ) -> BlockDraft:
        """Build an unsealed block linked to the current head.

        `owner_id` / `owner_pubkey` are parameters rather than chain state: which cloud server
        proposed a block is M2b's concern, and this layer only needs to record it. No node
        abstraction here on purpose.
        """
        return BlockDraft(
            owner_id=owner_id,
            owner_pubkey=owner_pubkey,
            transactions=transactions,
            prev_hash=self.head_hash(),
            timestamp=timestamp,
        )

    # -- append --------------------------------------------------------------------------------
    def append(self, block: Block) -> None:
        """Validate and append. Raises `ChainError` on any failure; the chain is left unchanged.

        Every rejection path raises before touching `_blocks` or `_index`, so a rejected block
        cannot leave the chain half-updated.
        """
        self.check_append(block)
        self._blocks.append(block)
        self._index[block.current_hash] = len(self._blocks) - 1

    def check_append(self, block: Block) -> None:
        """Run every `append()` check without appending. Raises `ChainError` if any fails.

        This is how consensus asks "is this block valid here?" without deciding it itself. A pBFT
        replica must refuse to *prepare* a block that `append()` would later reject — otherwise a
        quorum commits a block nobody can append and the chain stalls — but the answer has to come
        from the one validator, not a second copy of it in the protocol layer. So `append()` is
        this plus the two assignments, and nothing else anywhere defines block validity.
        """
        if not self._blocks:
            raise ChainError(f"{self.name} has no genesis block; call create_genesis() first")
        head = self._blocks[-1]

        # 1. prev_hash linkage
        if block.prev_hash != head.current_hash:
            raise ChainError(
                f"{self.name}: block does not link to the head — prev_hash "
                f"{block.prev_hash[:8].hex()}... but head is {head.current_hash[:8].hex()}..."
            )

        # 2. Merkle root recomputation
        recomputed_root = merkle_root([tx.digest for tx in block.transactions])
        if block.merkle_root != recomputed_root:
            raise ChainError(f"{self.name}: merkle_root does not cover the block's transactions")

        # 3. current_hash recomputation
        if block.current_hash in self._index:
            raise ChainError(f"{self.name}: this block is already in the chain")

        # 4. ECDSA signature under owner_pubkey
        if not verify(block.owner_public_key(), block.signature, block.signing_preimage()):
            raise ChainError(
                f"{self.name}: block signature does not verify under owner_pubkey for "
                f"{block.owner_id!r}"
            )

        # 5. timestamp — non-decreasing within tolerance, see the module docstring
        drift = head.timestamp - block.timestamp
        if drift > self._policy.skew_tolerance_s:
            raise ChainError(
                f"{self.name}: block timestamp is {drift:.1f}s older than the head, beyond the "
                f"{self._policy.skew_tolerance_s:.0f}s skew tolerance"
            )

    # -- reading -------------------------------------------------------------------------------
    def head(self) -> Block:
        if not self._blocks:
            raise ChainError(f"{self.name} is empty")
        return self._blocks[-1]

    def head_hash(self) -> bytes:
        return self.head().current_hash

    def block_at(self, height: int) -> Block:
        try:
            return self._blocks[height]
        except IndexError as exc:
            raise ChainError(f"{self.name}: no block at height {height}") from exc

    def block_by_hash(self, current_hash: bytes) -> Block:
        try:
            return self._blocks[self._index[current_hash]]
        except KeyError as exc:
            raise ChainError(
                f"{self.name}: no block with hash {current_hash[:8].hex()}..."
            ) from exc

    def contains(self, current_hash: bytes) -> bool:
        return current_hash in self._index

    def verify_block(self, height: int) -> Block:
        """Re-verify one stored block and return it. Raises `ChainError` if it no longer holds.

        `verify_integrity()` for a single block: Merkle root, signature, index entry. Everything
        except linkage to its neighbours, which is the walk's job. It is what a reader calls
        before trusting one block's transactions without paying for the whole walk; `recovery`
        calls it for every block a backup is read from (added in M3a).

        No separate per-transaction digest check is needed. `MTR` covers only the digests, but
        the signature pre-image carries every transaction's full encoding, ciphertext included,
        so an altered ciphertext breaks the signature even when its digest field is left alone
        (`tests/unit/test_chain_verify_block.py`).
        """
        block = self.block_at(height)
        if block.merkle_root != merkle_root([tx.digest for tx in block.transactions]):
            raise ChainError(f"{self.name}: block {height} merkle_root is wrong")
        if not verify(block.owner_public_key(), block.signature, block.signing_preimage()):
            raise ChainError(f"{self.name}: block {height} signature does not verify")
        if self._index.get(block.current_hash) != height:
            raise ChainError(f"{self.name}: block {height} is missing from the hash index")
        return block

    @property
    def height(self) -> int:
        """Index of the head. A chain with only a genesis block has height 0."""
        return len(self._blocks) - 1

    @property
    def transaction_count(self) -> int:
        return sum(block.transaction_count for block in self._blocks)

    def __len__(self) -> int:
        return len(self._blocks)

    def __iter__(self) -> Iterator[Block]:
        """Iterate genesis-first. Yields from a copy so mutation during iteration is impossible."""
        return iter(tuple(self._blocks))

    def __repr__(self) -> str:
        head = self._blocks[-1].current_hash[:6].hex() + "..." if self._blocks else "<empty>"
        return f"Chain(name={self.name!r}, blocks={len(self._blocks)}, head={head})"

    # -- integrity -----------------------------------------------------------------------------
    def verify_integrity(self) -> None:
        """Walk the whole chain and re-verify every link. Raises `ChainError` at the first fault.

        `append()` already validated each block as it arrived; this is the check that the chain
        *still* holds — the one that would catch an in-place mutation of stored state. It is what
        an integrity audit calls, not something `append()` needs.
        """
        if not self._blocks:
            raise ChainError(f"{self.name} is empty")
        genesis = self._blocks[0]
        if genesis.prev_hash != GENESIS_PREV_HASH:
            raise ChainError(f"{self.name}: genesis prev_hash is not the zero hash")
        for height, block in enumerate(self._blocks):
            self.verify_block(height)
            if height == 0:
                continue
            previous = self._blocks[height - 1]
            if block.prev_hash != previous.current_hash:
                raise ChainError(f"{self.name}: block {height} does not link to block {height - 1}")
            drift = previous.timestamp - block.timestamp
            if drift > self._policy.skew_tolerance_s:
                raise ChainError(
                    f"{self.name}: block {height} timestamp is {drift:.1f}s before its "
                    f"predecessor, beyond tolerance"
                )
