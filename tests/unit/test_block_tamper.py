"""§V-4 data manipulation — every header field, tampered individually.

The paper claims a block cannot be altered without detection. That claim is only as strong as its
weakest field, so this parametrizes over *every* header field rather than checking one and
assuming the rest. A field that could be changed without invalidating something would be a hole
the paper's §V-4 argument does not cover.

The structure of the block type means there are two distinct kinds of tamper, and both are here:

* **Stored fields** (`version`, `timestamp`, `nonce`, `owner_id`, `owner_pubkey`,
  `transactions`, `prev_hash`, `signature`) — altering one either fails `Block.__post_init__`,
  because the signature no longer covers the header, or fails at `Chain.append`.
* **Derived fields** (`merkle_root`, `current_hash`) — these are not stored, so there is nothing
  to tamper with in memory. On the wire they are claimed values, and `Block.from_fields`
  recomputes and compares. Both routes are tested.

Named to match the test file docs/EXPERIMENTS.md Target 5 maps §V-4 to.
"""

from __future__ import annotations

import pytest

from bsfr_sh.blockchain.block import GENESIS_PREV_HASH, Block, BlockDraft, BlockError
from bsfr_sh.blockchain.chain import BC_DTBU, Chain, ChainError
from bsfr_sh.blockchain.transaction import BackupPayload, Transaction, encrypt_backup
from bsfr_sh.crypto.ecdsa import KeyPair
from bsfr_sh.util.serialization import BLOCK_FIELD_ORDER

DERIVED = ("merkle_root", "current_hash")
STORED = tuple(name for name in BLOCK_FIELD_ORDER if name not in DERIVED)


def txs(keys: KeyPair, count: int) -> tuple[Transaction, ...]:
    return tuple(
        encrypt_backup(
            recipient=keys.public,
            tx_id=f"tx-{i:04d}",
            payload=BackupPayload("SYS_1", bytes([i % 256]) * 32, i),
            created_at=i,
        )
        for i in range(count)
    )


def sealed(keys: KeyPair, count: int = 4) -> Block:
    return BlockDraft(
        owner_id="CS_1",
        owner_pubkey=keys.public.to_bytes(),
        transactions=txs(keys, count),
        prev_hash=GENESIS_PREV_HASH,
        timestamp=1_757_548_800.0,
    ).seal(keys.private)


def altered_value(block: Block, field: str, other: KeyPair) -> object:
    """A different, well-formed value for one header field."""
    return {
        "version": block.version + 1,
        "timestamp": block.timestamp + 1.0,
        "nonce": bytes(16) if block.nonce != bytes(16) else b"\x01" * 16,
        "owner_id": "CS_EVIL",
        "owner_pubkey": other.public.to_bytes(),
        "transactions": block.transactions[:-1],
        "prev_hash": b"\x09" * 32,
        "signature": block.signature[:-1] + bytes([block.signature[-1] ^ 0x01]),
        "merkle_root": bytes(32),
        "current_hash": bytes(32),
    }[field]


# --------------------------------------------------------------------------------------------
# Stored fields — in memory
# --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("field", STORED)
def test_tampering_with_any_stored_header_field_is_rejected(
    field: str, cs1_keys: KeyPair, cs2_keys: KeyPair
) -> None:
    """Rebuilding a `Block` with one field changed must fail its own signature check."""
    block = sealed(cs1_keys)
    stored = {name: getattr(block, name) for name in Block.__dataclass_fields__}
    with pytest.raises(BlockError, match=r"signature does not verify|not a valid secp256r1"):
        Block(**{**stored, field: altered_value(block, field, cs2_keys)})


# --------------------------------------------------------------------------------------------
# Every field — on the wire
# --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("field", BLOCK_FIELD_ORDER)
def test_tampering_with_any_header_field_on_the_wire_is_rejected(
    field: str, cs1_keys: KeyPair, cs2_keys: KeyPair
) -> None:
    """The route a block actually arrives by: claimed fields, recomputed and compared.

    Covers the derived fields too, which have no in-memory representation to tamper with.
    """
    block = sealed(cs1_keys)
    fields = block.to_fields()
    if field == "transactions":
        fields["transactions"] = [tx.encoded() for tx in block.transactions[:-1]]
    else:
        fields[field] = altered_value(block, field, cs2_keys)  # type: ignore[assignment]
    with pytest.raises(BlockError):
        Block.from_fields(fields)


# --------------------------------------------------------------------------------------------
# Transactions
# --------------------------------------------------------------------------------------------
def test_reordering_transactions_changes_the_merkle_root(cs1_keys: KeyPair) -> None:
    """`MTR` is order-sensitive, so a reordered block is a different block."""
    original = sealed(cs1_keys, 6)
    reordered = BlockDraft(
        owner_id=original.owner_id,
        owner_pubkey=original.owner_pubkey,
        transactions=tuple(reversed(original.transactions)),
        prev_hash=original.prev_hash,
        timestamp=original.timestamp,
        nonce=original.nonce,
    )
    assert reordered.merkle_root != original.merkle_root
    assert reordered.current_hash != original.current_hash


def test_reordered_transactions_invalidate_the_signature(cs1_keys: KeyPair) -> None:
    block = sealed(cs1_keys, 6)
    stored = {name: getattr(block, name) for name in Block.__dataclass_fields__}
    with pytest.raises(BlockError, match="signature does not verify"):
        Block(**{**stored, "transactions": tuple(reversed(block.transactions))})


def test_substituting_a_transaction_is_rejected(cs1_keys: KeyPair) -> None:
    block = sealed(cs1_keys, 4)
    intruder = encrypt_backup(
        recipient=cs1_keys.public,
        tx_id="tx-intruder",
        payload=BackupPayload("SYS_9", b"injected", 1),
        created_at=1,
    )
    stored = {name: getattr(block, name) for name in Block.__dataclass_fields__}
    swapped = (*block.transactions[:-1], intruder)
    with pytest.raises(BlockError, match="signature does not verify"):
        Block(**{**stored, "transactions": swapped})


def test_tampering_with_a_transaction_inside_a_block_changes_mtr(cs1_keys: KeyPair) -> None:
    """Alter a transaction's ciphertext and the block no longer covers it."""
    block = sealed(cs1_keys, 4)
    target = block.transactions[1]
    flipped = bytearray(target.ciphertext)
    flipped[0] ^= 0x01
    mangled = Transaction(**{**target.to_fields(), "ciphertext": bytes(flipped)})
    repaired = Transaction(**{**mangled.to_fields(), "digest": mangled.compute_digest()})
    stored = {name: getattr(block, name) for name in Block.__dataclass_fields__}
    with pytest.raises(BlockError, match="signature does not verify"):
        Block(
            **{
                **stored,
                "transactions": (block.transactions[0], repaired, *block.transactions[2:]),
            }
        )


# --------------------------------------------------------------------------------------------
# In a chain
# --------------------------------------------------------------------------------------------
def test_a_block_signed_by_the_wrong_owner_is_rejected_on_append(
    cs1_keys: KeyPair, cs2_keys: KeyPair
) -> None:
    """`owner_pubkey` names who must have signed; a block signed by anyone else does not append.

    Built by hand rather than through `seal()`, because `seal()` refuses this case up front —
    this is the block an adversary would put on the wire.
    """
    chain = Chain(BC_DTBU)
    chain.create_genesis(owner_id="CS_0", private_key=cs1_keys.private, timestamp=1000.0)
    honest = BlockDraft(
        owner_id="CS_1",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=txs(cs1_keys, 2),
        prev_hash=chain.head_hash(),
        timestamp=1001.0,
    )
    from bsfr_sh.crypto.ecdsa import sign

    forged_signature = sign(cs2_keys.private, honest.signing_preimage())
    stored = {
        "owner_id": honest.owner_id,
        "owner_pubkey": honest.owner_pubkey,
        "transactions": honest.transactions,
        "prev_hash": honest.prev_hash,
        "timestamp": honest.timestamp,
        "version": honest.version,
        "nonce": honest.nonce,
        "signature": forged_signature,
    }
    with pytest.raises(BlockError, match="signature does not verify"):
        Block(**stored)
    assert len(chain) == 1


def test_broken_prev_hash_linkage_is_rejected(cs1_keys: KeyPair) -> None:
    chain = Chain(BC_DTBU)
    chain.create_genesis(owner_id="CS_0", private_key=cs1_keys.private, timestamp=1000.0)
    orphan = BlockDraft(
        owner_id="CS_1",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=txs(cs1_keys, 2),
        prev_hash=b"\x09" * 32,
        timestamp=1001.0,
    ).seal(cs1_keys.private)
    with pytest.raises(ChainError, match="does not link to the head"):
        chain.append(orphan)
    assert len(chain) == 1
