"""`blockchain.anchor` — `AnchorRecord` construction, signature verification, wire round-trip.

M7-5. The security properties `HybridChain` relies on (`test_hybrid_chain.py`) are only as strong
as this module's: a signature that verified on a tampered record, or a wire encoding that lost a
field silently, would make every downstream verification meaningless.
"""

from __future__ import annotations

import pytest

from bsfr_sh.blockchain.anchor import AnchorRecord, AnchorRecordError, create_anchor_record
from bsfr_sh.blockchain.block import BlockDraft
from bsfr_sh.blockchain.chain import GENESIS_PREV_HASH
from bsfr_sh.blockchain.transaction import BackupPayload, encrypt_backup
from bsfr_sh.crypto.ecdsa import KeyPair


def sealed_block(keys: KeyPair, count: int = 2):
    txs = tuple(
        encrypt_backup(
            recipient=keys.public,
            tx_id=f"tx-{i:03d}",
            payload=BackupPayload("SYS_1", bytes([i % 256]) * 16, i),
            created_at=i,
        )
        for i in range(count)
    )
    return BlockDraft(
        owner_id="CS_1",
        owner_pubkey=keys.public.to_bytes(),
        transactions=txs,
        prev_hash=GENESIS_PREV_HASH,
        timestamp=1_000.0,
    ).seal(keys.private)


def test_create_anchor_record_verifies(cs1_keys: KeyPair) -> None:
    block = sealed_block(cs1_keys)
    record = create_anchor_record(
        anchored_chain="BC_DTBU",
        block_height=3,
        block=block,
        timestamp=42.0,
        creator_id="anchor_authority",
        private_key=cs1_keys.private,
    )
    assert record.anchored_chain == "BC_DTBU"
    assert record.block_height == 3
    assert record.block_hash == block.current_hash
    assert record.merkle_root == block.merkle_root
    assert record.matches(block, height=3)


def test_matches_rejects_wrong_height(cs1_keys: KeyPair) -> None:
    block = sealed_block(cs1_keys)
    record = create_anchor_record(
        anchored_chain="BC_DTBU",
        block_height=3,
        block=block,
        timestamp=0.0,
        creator_id="anchor_authority",
        private_key=cs1_keys.private,
    )
    assert not record.matches(block, height=4)


def test_matches_rejects_a_different_block_at_the_same_height(cs1_keys: KeyPair) -> None:
    block = sealed_block(cs1_keys)
    other = sealed_block(cs1_keys, count=3)  # different transaction count -> different hash
    record = create_anchor_record(
        anchored_chain="BC_DTBU",
        block_height=3,
        block=block,
        timestamp=0.0,
        creator_id="anchor_authority",
        private_key=cs1_keys.private,
    )
    assert not record.matches(other, height=3)


@pytest.mark.parametrize(
    "field",
    ["anchored_chain", "block_height", "block_hash", "merkle_root", "timestamp", "creator_id"],
)
def test_tampering_any_field_breaks_the_signature(field: str, cs1_keys: KeyPair) -> None:
    """Rebuilding a record with one field changed must fail `__post_init__`'s signature check."""
    block = sealed_block(cs1_keys)
    record = create_anchor_record(
        anchored_chain="BC_DTBU",
        block_height=3,
        block=block,
        timestamp=42.0,
        creator_id="anchor_authority",
        private_key=cs1_keys.private,
    )
    altered = {
        "anchored_chain": "BC_SigRW",
        "block_height": 4,
        "block_hash": bytes(32),
        "merkle_root": bytes(32),
        "timestamp": 43.0,
        "creator_id": "someone_else",
    }[field]
    fields = record._fields()
    fields[field] = altered
    with pytest.raises(AnchorRecordError, match="signature"):
        AnchorRecord(**fields, signature=record.signature)


def test_tampering_the_signature_itself_is_rejected(cs1_keys: KeyPair) -> None:
    block = sealed_block(cs1_keys)
    record = create_anchor_record(
        anchored_chain="BC_DTBU",
        block_height=3,
        block=block,
        timestamp=42.0,
        creator_id="anchor_authority",
        private_key=cs1_keys.private,
    )
    bad_sig = record.signature[:-1] + bytes([record.signature[-1] ^ 0x01])
    with pytest.raises(AnchorRecordError, match="signature"):
        AnchorRecord(**record._fields(), signature=bad_sig)


def test_signed_by_the_wrong_key_is_rejected(cs1_keys: KeyPair, cs2_keys: KeyPair) -> None:
    """A record claiming `cs1`'s pubkey but signed by `cs2` must not verify."""
    block = sealed_block(cs1_keys)
    genuine = create_anchor_record(
        anchored_chain="BC_DTBU",
        block_height=3,
        block=block,
        timestamp=42.0,
        creator_id="anchor_authority",
        private_key=cs2_keys.private,
    )
    fields = genuine._fields()
    fields["creator_pubkey"] = cs1_keys.public.to_bytes()
    with pytest.raises(AnchorRecordError, match="signature"):
        AnchorRecord(**fields, signature=genuine.signature)


def test_wire_round_trip(cs1_keys: KeyPair) -> None:
    block = sealed_block(cs1_keys)
    record = create_anchor_record(
        anchored_chain="BC_SigRW",
        block_height=7,
        block=block,
        timestamp=123.5,
        creator_id="anchor_authority",
        private_key=cs1_keys.private,
    )
    restored = AnchorRecord.from_bytes(record.to_bytes())
    assert restored == record


def test_from_bytes_rejects_garbage() -> None:
    with pytest.raises(AnchorRecordError):
        AnchorRecord.from_bytes(b"not a canonical encoding")


def test_block_height_must_be_non_negative(cs1_keys: KeyPair) -> None:
    block = sealed_block(cs1_keys)
    with pytest.raises(AnchorRecordError, match="block_height"):
        create_anchor_record(
            anchored_chain="BC_DTBU",
            block_height=-1,
            block=block,
            timestamp=0.0,
            creator_id="anchor_authority",
            private_key=cs1_keys.private,
        )
