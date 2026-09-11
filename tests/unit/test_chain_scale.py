"""Both chains at the paper's case-3 size — 15 blocks x 100 transactions, no consensus.

This is M2a's exit condition, and it is a real test rather than a demo: it is the first thing
that exercises the whole layer end to end at the size Fig. 6 reports, and it is where a mistake
that only shows up in bulk (a quadratic Merkle rebuild, a shared index, a payload size that is
silently a literal) would surface.

Appends go straight in, single-node. There is no pBFT here — that is M2b. When consensus lands,
this file is the "what the chain does without it" baseline.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW, Chain
from bsfr_sh.blockchain.transaction import (
    BackupPayload,
    SignatureRecordPayload,
    Transaction,
    decrypt,
    encrypt_backup,
    encrypt_signature_record,
)
from bsfr_sh.crypto.ecdsa import KeyPair
from bsfr_sh.util.config import load_config

REPO_ROOT = Path(__file__).resolve().parents[2]
CHAIN_CONFIG = REPO_ROOT / "configs" / "chain.yaml"

CONFIG = load_config(CHAIN_CONFIG, expected_kind="chain")
#: PAPER §VII — read, never re-literalled (CLAUDE.md §4b, configs/chain.yaml convention).
BLOCKS = CONFIG.require("cases", dict)["case_3"]
TX_PER_BLOCK = CONFIG.require("block.transactions_per_block", int)
#: DECLARED — DEV-15 / Q2. The size is a config value precisely so it is never a literal here.
PAYLOAD_BYTES = CONFIG.require("transaction.payload_bytes", int)


def build_backup_chain(keys: KeyPair) -> Chain:
    chain = Chain(BC_DTBU)
    chain.create_genesis(owner_id="CS_0", private_key=keys.private, timestamp=1000.0)
    for block_index in range(BLOCKS):
        transactions: tuple[Transaction, ...] = tuple(
            encrypt_backup(
                recipient=keys.public,
                tx_id=f"dtbu-{block_index:02d}-{i:03d}",
                payload=BackupPayload(
                    system_id=f"SYS_{i % 8}",
                    data=os.urandom(PAYLOAD_BYTES),
                    captured_at=1000 + block_index,
                ),
                created_at=1000 + block_index,
            )
            for i in range(TX_PER_BLOCK)
        )
        draft = chain.draft_next(
            owner_id=f"CS_{block_index % 4}",
            owner_pubkey=keys.public.to_bytes(),
            transactions=transactions,
            timestamp=1001.0 + block_index,
        )
        chain.append(draft.seal(keys.private))
    return chain


def build_signature_chain(keys: KeyPair) -> Chain:
    chain = Chain(BC_SigRW)
    chain.create_genesis(owner_id="CS_0", private_key=keys.private, timestamp=1000.0)
    for block_index in range(BLOCKS):
        transactions: tuple[Transaction, ...] = tuple(
            encrypt_signature_record(
                recipient=keys.public,
                tx_id=f"sigrw-{block_index:02d}-{i:03d}",
                payload=SignatureRecordPayload(
                    sample_id=f"RW-{block_index:02d}-{i:03d}",
                    content_digest=os.urandom(32),
                    attestation=os.urandom(70),
                    features=tuple(float(v) for v in range(24)),
                    collected_at=1000 + block_index,
                ),
                created_at=1000 + block_index,
            )
            for i in range(TX_PER_BLOCK)
        )
        draft = chain.draft_next(
            owner_id=f"CS_{block_index % 4}",
            owner_pubkey=keys.public.to_bytes(),
            transactions=transactions,
            timestamp=1001.0 + block_index,
        )
        chain.append(draft.seal(keys.private))
    return chain


@pytest.mark.slow
def test_both_chains_build_case_3_and_stay_independent(cs1_keys: KeyPair) -> None:
    """15 blocks x 100 transactions on each chain, by direct append."""
    dtbu = build_backup_chain(cs1_keys)
    sigrw = build_signature_chain(cs1_keys)

    for chain in (dtbu, sigrw):
        assert len(chain) == BLOCKS + 1  # genesis plus the case's blocks
        assert chain.height == BLOCKS
        assert chain.transaction_count == BLOCKS * TX_PER_BLOCK
        chain.verify_integrity()

    # Still separate at scale — no shared index, no colliding hashes.
    assert dtbu.head_hash() != sigrw.head_hash()
    for block in dtbu:
        assert not sigrw.contains(block.current_hash)


@pytest.mark.slow
def test_a_transaction_survives_the_round_trip_at_scale(cs1_keys: KeyPair) -> None:
    """Encrypt → append → read back, from a full-size chain rather than a one-block fixture."""
    chain = build_backup_chain(cs1_keys)
    block = chain.block_at(BLOCKS)  # the last one
    tx = block.transactions[42]
    recovered = BackupPayload.from_bytes(decrypt(cs1_keys.private, tx))
    assert len(recovered.data) == PAYLOAD_BYTES
    assert recovered.system_id == f"SYS_{42 % 8}"


@pytest.mark.slow
def test_payload_size_comes_from_config_not_from_a_literal(cs1_keys: KeyPair) -> None:
    """Q2's practical guard: the declared size is what actually lands on the chain.

    Q2 stays open — 4096 B is declared (DEV-15), not justified, and justifying it needs M6's
    sensitivity sweep. What is closed here is the weaker but necessary property: the value is
    read from `configs/chain.yaml`, so the sweep will actually move it and no module has quietly
    baked in a different number.
    """
    chain = build_backup_chain(cs1_keys)
    sizes = {
        len(BackupPayload.from_bytes(decrypt(cs1_keys.private, tx)).data)
        for tx in chain.block_at(1).transactions
    }
    assert sizes == {PAYLOAD_BYTES}
    assert CONFIG.require("transaction.payload_bytes", int) == PAYLOAD_BYTES
