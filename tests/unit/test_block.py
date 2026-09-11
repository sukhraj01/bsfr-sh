"""`blockchain.block` — header structure, the two-type seal, and what `Sig_βj` covers.

Tampering is `test_block_tamper.py` (§V-4). This file covers construction.
"""

from __future__ import annotations

import pytest

from bsfr_sh.blockchain.block import (
    BLOCK_VERSION,
    GENESIS_PREV_HASH,
    Block,
    BlockDraft,
    BlockError,
)
from bsfr_sh.blockchain.transaction import BackupPayload, Transaction, encrypt_backup
from bsfr_sh.crypto.ecdsa import KeyPair
from bsfr_sh.crypto.merkle import merkle_root, verify_proof
from bsfr_sh.util.serialization import BLOCK_FIELD_ORDER


def txs(keys: KeyPair, count: int) -> tuple[Transaction, ...]:
    return tuple(
        encrypt_backup(
            recipient=keys.public,
            tx_id=f"tx-{i:04d}",
            payload=BackupPayload(system_id="SYS_1", data=bytes([i % 256]) * 64, captured_at=i),
            created_at=i,
        )
        for i in range(count)
    )


def draft(keys: KeyPair, count: int = 4, **overrides: object) -> BlockDraft:
    base: dict[str, object] = {
        "owner_id": "CS_1",
        "owner_pubkey": keys.public.to_bytes(),
        "transactions": txs(keys, count),
        "prev_hash": GENESIS_PREV_HASH,
        "timestamp": 1_757_548_800.0,
    }
    return BlockDraft(**{**base, **overrides})  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------------
# Header structure
# --------------------------------------------------------------------------------------------
def test_sealed_block_exposes_exactly_the_paper_header(cs1_keys: KeyPair) -> None:
    """Alg. 1 line 3 / Alg. 2 line 8, via `util.serialization.BLOCK_FIELD_ORDER`."""
    block = draft(cs1_keys).seal(cs1_keys.private)
    assert tuple(block.to_fields()) == BLOCK_FIELD_ORDER


def test_draft_has_no_hash_or_signature_fields(cs1_keys: KeyPair) -> None:
    """The point of the two-type split: an unsealed block cannot carry a wrong hash.

    `merkle_root` and `current_hash` are derived properties, not dataclass fields, so there is no
    constructor argument through which a bogus value could be supplied.
    """
    fields = set(BlockDraft.__dataclass_fields__)
    assert "current_hash" not in fields
    assert "signature" not in fields
    assert "merkle_root" not in fields


def test_sealed_block_stores_no_derived_digest(cs1_keys: KeyPair) -> None:
    """`Block` stores neither `merkle_root` nor `current_hash` — they are computed on access."""
    fields = set(Block.__dataclass_fields__)
    assert "current_hash" not in fields
    assert "merkle_root" not in fields
    assert "signature" in fields  # not derivable without the private key


def test_version_and_nonce_defaults(cs1_keys: KeyPair) -> None:
    block = draft(cs1_keys).seal(cs1_keys.private)
    assert block.version == BLOCK_VERSION
    assert len(block.nonce) == 16


def test_nonces_differ_between_blocks(cs1_keys: KeyPair) -> None:
    """`RN` is random per block. It is inert — no mining, no difficulty — but still fresh."""
    assert draft(cs1_keys).nonce != draft(cs1_keys).nonce


def test_merkle_root_matches_the_transaction_digests(cs1_keys: KeyPair) -> None:
    block = draft(cs1_keys, 7).seal(cs1_keys.private)
    assert block.merkle_root == merkle_root([tx.digest for tx in block.transactions])


def test_empty_block_is_valid(cs1_keys: KeyPair) -> None:
    """Genesis blocks typically carry no transactions."""
    block = draft(cs1_keys, 0).seal(cs1_keys.private)
    assert block.transaction_count == 0
    assert len(block.merkle_root) == 32


# --------------------------------------------------------------------------------------------
# Sealing
# --------------------------------------------------------------------------------------------
def test_seal_produces_a_verifying_signature(cs1_keys: KeyPair) -> None:
    from bsfr_sh.crypto.ecdsa import verify

    block = draft(cs1_keys).seal(cs1_keys.private)
    assert verify(cs1_keys.public, block.signature, block.signing_preimage())


def test_signature_covers_every_header_field_except_itself(cs1_keys: KeyPair) -> None:
    """What `Sig_βj` covers, asserted rather than only documented.

    The pre-image is `BlockPart.SIGN` — every header field but `signature`. If a later change
    narrowed it, this test is what notices.
    """
    from bsfr_sh.util.serialization import BLOCK_SIGNED_FIELDS, decode

    block = draft(cs1_keys).seal(cs1_keys.private)
    decoded = decode(block.signing_preimage())
    assert tuple(decoded.fields) == BLOCK_SIGNED_FIELDS  # type: ignore[union-attr]
    assert set(BLOCK_FIELD_ORDER) - set(BLOCK_SIGNED_FIELDS) == {"signature"}


def test_sealing_with_a_key_that_is_not_the_owner_is_rejected(
    cs1_keys: KeyPair, cs2_keys: KeyPair
) -> None:
    with pytest.raises(BlockError, match="does not match owner_pubkey"):
        draft(cs1_keys).seal(cs2_keys.private)


def test_deterministic_signing_makes_a_seal_reproducible(cs1_keys: KeyPair) -> None:
    """RFC 6979: identical drafts seal to identical bytes, which is what makes runs comparable."""
    fixed = txs(cs1_keys, 2)
    common: dict[str, object] = {
        "owner_id": "CS_1",
        "owner_pubkey": cs1_keys.public.to_bytes(),
        "transactions": fixed,
        "prev_hash": GENESIS_PREV_HASH,
        "timestamp": 1000.0,
        "nonce": b"\x07" * 16,
    }
    first = BlockDraft(**common).seal(cs1_keys.private)  # type: ignore[arg-type]
    second = BlockDraft(**common).seal(cs1_keys.private)  # type: ignore[arg-type]
    assert first.current_hash == second.current_hash
    assert first.signature == second.signature


# --------------------------------------------------------------------------------------------
# Validation at construction
# --------------------------------------------------------------------------------------------
def test_empty_owner_id_is_rejected(cs1_keys: KeyPair) -> None:
    with pytest.raises(BlockError, match="owner_id must be non-empty"):
        draft(cs1_keys, owner_id="")


def test_short_prev_hash_is_rejected(cs1_keys: KeyPair) -> None:
    with pytest.raises(BlockError, match="prev_hash must be 32 bytes"):
        draft(cs1_keys, prev_hash=b"\x00" * 16)


def test_invalid_owner_pubkey_is_rejected(cs1_keys: KeyPair) -> None:
    with pytest.raises(BlockError, match="not a valid secp256r1 point"):
        draft(cs1_keys, owner_pubkey=b"\x04" + b"\x01" * 64)


def test_a_list_of_transactions_is_rejected(cs1_keys: KeyPair) -> None:
    """`MTR` is not mutable, so neither is the list it covers."""
    with pytest.raises(BlockError, match="must be a tuple"):
        draft(cs1_keys, transactions=list(txs(cs1_keys, 2)))


def test_a_block_cannot_exist_with_an_invalid_signature(cs1_keys: KeyPair) -> None:
    """Verified in `__post_init__`, so there is no such object to hold."""
    block = draft(cs1_keys).seal(cs1_keys.private)
    stored = {name: getattr(block, name) for name in Block.__dataclass_fields__}
    with pytest.raises(BlockError, match="signature does not verify"):
        Block(**{**stored, "signature": bytes(70)})


# --------------------------------------------------------------------------------------------
# Wire round trip
# --------------------------------------------------------------------------------------------
def test_block_round_trips_through_fields(cs1_keys: KeyPair) -> None:
    block = draft(cs1_keys, 5).seal(cs1_keys.private)
    rebuilt = Block.from_fields(block.to_fields())
    assert rebuilt == block
    assert rebuilt.current_hash == block.current_hash
    assert rebuilt.merkle_root == block.merkle_root


def test_a_lying_merkle_root_is_caught_at_the_boundary(cs1_keys: KeyPair) -> None:
    block = draft(cs1_keys, 5).seal(cs1_keys.private)
    with pytest.raises(BlockError, match="claimed merkle_root"):
        Block.from_fields({**block.to_fields(), "merkle_root": bytes(32)})


def test_a_lying_current_hash_is_caught_at_the_boundary(cs1_keys: KeyPair) -> None:
    block = draft(cs1_keys, 5).seal(cs1_keys.private)
    with pytest.raises(BlockError, match="claimed current_hash"):
        Block.from_fields({**block.to_fields(), "current_hash": bytes(32)})


def test_missing_fields_are_rejected(cs1_keys: KeyPair) -> None:
    block = draft(cs1_keys).seal(cs1_keys.private)
    fields = block.to_fields()
    del fields["nonce"]
    with pytest.raises(BlockError, match="missing"):
        Block.from_fields(fields)


# --------------------------------------------------------------------------------------------
# Inclusion proofs
# --------------------------------------------------------------------------------------------
def test_every_transaction_has_an_inclusion_proof(cs1_keys: KeyPair) -> None:
    block = draft(cs1_keys, 9).seal(cs1_keys.private)
    for index, tx in enumerate(block.transactions):
        assert verify_proof(block.merkle_root, tx.digest, block.prove_transaction(index))


def test_a_transaction_not_in_the_block_has_no_proof(cs1_keys: KeyPair) -> None:
    block = draft(cs1_keys, 4).seal(cs1_keys.private)
    outsider = encrypt_backup(
        recipient=cs1_keys.public,
        tx_id="tx-outside",
        payload=BackupPayload("SYS_9", b"not in this block", 1),
        created_at=1,
    )
    assert not verify_proof(block.merkle_root, outsider.digest, block.prove_transaction(0))
