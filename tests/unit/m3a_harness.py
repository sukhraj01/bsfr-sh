"""M3a test harness: fixture-keyed entities, a direct-append `BC_DTBU`, deterministic data.

Not a test module (no `test_` prefix). Keys derive from fixed scalars (CLAUDE.md §4b). Session
ephemerals and ECIES data keys are random, as M1 established. That changes ciphertexts between
runs and never plaintexts or outcomes.

`dtbu_chain` + `append_in_blocks` build a chain by direct append, with no consensus, so the
locator and restore tests stay local and fast. The consensus path is covered by
`test_phase1_backup.py` and `tests/integration/test_backup_recovery.py`.
"""

from __future__ import annotations

import copy
import dataclasses
import random
from collections.abc import Sequence

from pbft_harness import GENESIS_TIME

from bsfr_sh.blockchain.chain import BC_DTBU, Chain, build_genesis
from bsfr_sh.blockchain.transaction import Transaction
from bsfr_sh.crypto.ecdsa import KeyPair, keypair_from_secret
from bsfr_sh.framework import phase1_backup as phase1
from bsfr_sh.framework.entities import CloudServer, System

#: Owner of the directly-appended unit chains. Not a replica; there is no consensus here.
OWNER: KeyPair = keypair_from_secret(0x0A11CE)
#: Small enough that a 100-byte backup is 7 chunks over 3 blocks.
CHUNK = 16
PER_BLOCK = 3
CAPTURED_AT = 100


def blob(seed: int, size: int) -> bytes:
    return random.Random(seed).randbytes(size)


def make_system(index: int, size: int | None = None) -> System:
    """`SYS_<index>`, holding `size` deterministic bytes (or nothing)."""
    return System(
        identity=f"SYS_{index}",
        keypair=keypair_from_secret(0x5E5E_0000 + index),
        data=None if size is None else blob(index, size),
    )


def make_server(index: int) -> CloudServer:
    """`CS_<index>`. Use 10+ so the name never suggests one of the harness's replicas."""
    return CloudServer(identity=f"CS_{index}", keypair=keypair_from_secret(0xC5C5_0000 + index))


def dtbu_chain() -> Chain:
    chain = Chain(BC_DTBU)
    chain.adopt_genesis(
        build_genesis(owner_id="CS_0", private_key=OWNER.private, timestamp=GENESIS_TIME)
    )
    return chain


def append_in_blocks(
    chain: Chain, transactions: Sequence[Transaction], per_block: int = PER_BLOCK
) -> None:
    for start in range(0, len(transactions), per_block):
        block = chain.draft_next(
            owner_id="CS_0",
            owner_pubkey=OWNER.public.to_bytes(),
            transactions=tuple(transactions[start : start + per_block]),
            timestamp=GENESIS_TIME + 1,
        ).seal(OWNER.private)
        chain.append(block)


def collect_transactions(
    systems: Sequence[System],
    collector: CloudServer,
    *,
    captured_at: int = CAPTURED_AT,
    chunk_bytes: int = CHUNK,
) -> list[Transaction]:
    """Alg. 1 lines 1-2 exactly as Phase 1 runs them, stopping before submission."""
    return [
        tx
        for manifest, data in phase1.collect(systems, collector, captured_at=captured_at)
        for tx in phase1.backup_transactions(
            manifest,
            data,
            recipient=collector.public_key,
            chunk_bytes=chunk_bytes,
            created_at=captured_at,
        )
    ]


def back_up_directly(
    chain: Chain,
    systems: Sequence[System],
    collector: CloudServer,
    *,
    captured_at: int = CAPTURED_AT,
) -> None:
    append_in_blocks(chain, collect_transactions(systems, collector, captured_at=captured_at))


def tamper_ciphertext(
    chain: Chain, height: int, position: int = 0, *, recompute_digest: bool = False
) -> None:
    """Corrupt one stored transaction in place, on this chain only.

    The block is *replaced* in this chain's list rather than mutated. Replicas share `Block`
    objects (the bus passes references and never serialises; debt D3), so mutating one would
    corrupt every replica's copy at once, which is not the storage fault being modelled.
    `recompute_digest=True` models an attacker who also fixes up the transaction's digest.
    """
    block = chain.block_at(height)
    tx = block.transactions[position]
    bad = dataclasses.replace(tx, ciphertext=bytes([tx.ciphertext[0] ^ 1]) + tx.ciphertext[1:])
    if recompute_digest:
        bad = dataclasses.replace(bad, digest=bad.compute_digest())
    transactions = list(block.transactions)
    transactions[position] = bad
    corrupt = copy.copy(block)
    object.__setattr__(corrupt, "transactions", tuple(transactions))
    chain._blocks[height] = corrupt
