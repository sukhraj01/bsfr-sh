"""`Chain.verify_block` (M3a): re-verify one stored block, as recovery does before trusting it.

Recorded because M3a nearly logged a false finding. `MTR` covers transaction *digests* only, so
it looked as if a ciphertext altered while its digest was left alone would go unnoticed. It does
not: `HC_βj` and `Sig_βj` both cover every transaction's full canonical encoding, ciphertext
included (`blockchain.block`), so the block signature breaks either way.
"""

from __future__ import annotations

import dataclasses

import pytest
from m3a_harness import tamper_ciphertext

from bsfr_sh.blockchain.block import BlockError
from bsfr_sh.blockchain.chain import BC_DTBU, Chain, ChainError, build_genesis
from bsfr_sh.blockchain.transaction import BackupPayload, encrypt_backup


def _chain_with_one_block(keys):
    chain = Chain(BC_DTBU)
    chain.adopt_genesis(build_genesis(owner_id="CS_1", private_key=keys.private, timestamp=1000.0))
    transactions = tuple(
        encrypt_backup(
            recipient=keys.public,
            tx_id=f"t{i}",
            payload=BackupPayload("SYS_1", bytes([i]) * 32, 1),
            created_at=1,
        )
        for i in range(3)
    )
    block = chain.draft_next(
        owner_id="CS_1",
        owner_pubkey=keys.public.to_bytes(),
        transactions=transactions,
        timestamp=1001.0,
    ).seal(keys.private)
    chain.append(block)
    return chain, block


def test_an_honest_block_verifies_and_is_returned(cs1_keys) -> None:
    chain, block = _chain_with_one_block(cs1_keys)
    assert chain.verify_block(1) is block
    assert chain.verify_block(0) is chain.block_at(0)


def test_a_block_cannot_be_rebuilt_around_an_altered_ciphertext(cs1_keys) -> None:
    """The signature covers each transaction's full encoding, not just the digest `MTR` uses."""
    _, block = _chain_with_one_block(cs1_keys)
    tx = block.transactions[0]
    altered = dataclasses.replace(tx, ciphertext=bytes([tx.ciphertext[0] ^ 1]) + tx.ciphertext[1:])
    with pytest.raises(BlockError, match="signature does not verify"):
        dataclasses.replace(block, transactions=(altered, *block.transactions[1:]))


@pytest.mark.parametrize("recompute_digest", [False, True], ids=["stale-digest", "fixed-digest"])
def test_an_altered_ciphertext_in_storage_is_caught(cs1_keys, recompute_digest) -> None:
    chain, _ = _chain_with_one_block(cs1_keys)
    tamper_ciphertext(chain, 1, recompute_digest=recompute_digest)
    with pytest.raises(ChainError, match="block 1"):
        chain.verify_block(1)
    with pytest.raises(ChainError, match="block 1"):
        chain.verify_integrity()


def test_a_height_that_does_not_exist_is_an_error(cs1_keys) -> None:
    chain, _ = _chain_with_one_block(cs1_keys)
    with pytest.raises(ChainError, match="no block at height 2"):
        chain.verify_block(2)
