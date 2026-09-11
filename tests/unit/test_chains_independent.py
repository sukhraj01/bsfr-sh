"""§V-5 chain separation — `BC_DTBU` and `BC_SigRW` share no state whatsoever.

CLAUDE.md §4: *"Two chains are separate objects... Do not share state between them. A bug here
silently invalidates the whole benchmark."* The paper claims chain separation and never
demonstrates it; this file is the demonstration.

The failure mode being guarded against is mundane, not exotic: a mutable class attribute, a
mutable default argument, a module-level registry keyed by chain name, or a genesis block cached
at import. Any of those makes two `Chain` objects share storage while every test that examines
*one* chain continues to pass. So these tests build both, touch one, and assert the other is
untouched — length, head, hash index, and block list, not just length.

Named to match the test file docs/EXPERIMENTS.md Target 5 maps §V-5 to.
"""

from __future__ import annotations

import pytest

from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW, Chain, ChainError, ChainPolicy
from bsfr_sh.blockchain.transaction import (
    BackupPayload,
    SignatureRecordPayload,
    Transaction,
    encrypt_backup,
    encrypt_signature_record,
)
from bsfr_sh.crypto.ecdsa import KeyPair


def backup_txs(keys: KeyPair, count: int) -> tuple[Transaction, ...]:
    return tuple(
        encrypt_backup(
            recipient=keys.public,
            tx_id=f"dtbu-{i:04d}",
            payload=BackupPayload("SYS_1", bytes([i % 256]) * 32, i),
            created_at=i,
        )
        for i in range(count)
    )


def signature_txs(keys: KeyPair, count: int) -> tuple[Transaction, ...]:
    return tuple(
        encrypt_signature_record(
            recipient=keys.public,
            tx_id=f"sigrw-{i:04d}",
            payload=SignatureRecordPayload(
                sample_id=f"RW-{i:04d}",
                content_digest=bytes([i % 256]) * 32,
                attestation=b"\x22" * 70,
                features=(float(i), 0.5),
                collected_at=i,
            ),
            created_at=i,
        )
        for i in range(count)
    )


def both_chains(keys: KeyPair) -> tuple[Chain, Chain]:
    dtbu = Chain(BC_DTBU)
    sigrw = Chain(BC_SigRW)
    dtbu.create_genesis(owner_id="CS_0", private_key=keys.private, timestamp=1000.0)
    sigrw.create_genesis(owner_id="CS_0", private_key=keys.private, timestamp=1000.0)
    return dtbu, sigrw


def snapshot(chain: Chain) -> tuple[object, ...]:
    """Everything observable about a chain, including its private index."""
    return (
        len(chain),
        chain.height,
        chain.head_hash(),
        chain.transaction_count,
        tuple(block.current_hash for block in chain),
        tuple(sorted(chain._index.items())),
    )


# --------------------------------------------------------------------------------------------
# The core claim
# --------------------------------------------------------------------------------------------
def test_appending_to_one_chain_leaves_the_other_untouched(cs1_keys: KeyPair) -> None:
    """§V-5, stated as an experiment: touch one chain, check every observable of the other."""
    dtbu, sigrw = both_chains(cs1_keys)
    before = snapshot(sigrw)

    for i in range(5):
        draft = dtbu.draft_next(
            owner_id="CS_1",
            owner_pubkey=cs1_keys.public.to_bytes(),
            transactions=backup_txs(cs1_keys, 3),
            timestamp=1001.0 + i,
        )
        dtbu.append(draft.seal(cs1_keys.private))

    assert len(dtbu) == 6
    assert snapshot(sigrw) == before
    assert len(sigrw) == 1
    assert sigrw.transaction_count == 0
    sigrw.verify_integrity()
    dtbu.verify_integrity()


def test_the_two_genesis_blocks_are_different(cs1_keys: KeyPair) -> None:
    """Independent genesis blocks (CLAUDE.md §4), even from identical arguments.

    If a genesis block were cached at module level, these would be equal and both chains would
    share a head hash — after which a block from one chain would append to the other.
    """
    dtbu, sigrw = both_chains(cs1_keys)
    assert dtbu.head_hash() != sigrw.head_hash()
    assert dtbu.block_at(0) != sigrw.block_at(0)


def test_a_block_from_one_chain_does_not_append_to_the_other(cs1_keys: KeyPair) -> None:
    """The practical consequence of separate genesis blocks: no cross-chain linkage."""
    dtbu, sigrw = both_chains(cs1_keys)
    draft = dtbu.draft_next(
        owner_id="CS_1",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=backup_txs(cs1_keys, 2),
        timestamp=1001.0,
    )
    block = draft.seal(cs1_keys.private)
    dtbu.append(block)
    with pytest.raises(ChainError, match="does not link to the head"):
        sigrw.append(block)
    assert len(sigrw) == 1


def test_neither_chain_sees_the_other_s_hashes(cs1_keys: KeyPair) -> None:
    dtbu, sigrw = both_chains(cs1_keys)
    for i in range(3):
        draft = dtbu.draft_next(
            owner_id="CS_1",
            owner_pubkey=cs1_keys.public.to_bytes(),
            transactions=backup_txs(cs1_keys, 2),
            timestamp=1001.0 + i,
        )
        dtbu.append(draft.seal(cs1_keys.private))
    for block in dtbu:
        assert not sigrw.contains(block.current_hash)
        with pytest.raises(ChainError, match="no block with hash"):
            sigrw.block_by_hash(block.current_hash)


def test_both_chains_grow_independently(cs1_keys: KeyPair) -> None:
    """Interleaved appends to both, each carrying its own payload type."""
    dtbu, sigrw = both_chains(cs1_keys)
    for i in range(4):
        dtbu.append(
            dtbu.draft_next(
                owner_id="CS_1",
                owner_pubkey=cs1_keys.public.to_bytes(),
                transactions=backup_txs(cs1_keys, 2),
                timestamp=1001.0 + i,
            ).seal(cs1_keys.private)
        )
        sigrw.append(
            sigrw.draft_next(
                owner_id="CS_2",
                owner_pubkey=cs1_keys.public.to_bytes(),
                transactions=signature_txs(cs1_keys, 3),
                timestamp=1001.0 + i,
            ).seal(cs1_keys.private)
        )
    assert len(dtbu) == len(sigrw) == 5
    assert dtbu.transaction_count == 8
    assert sigrw.transaction_count == 12
    assert {tx.payload_type for b in dtbu for tx in b.transactions} == {"DT_BU"}
    assert {tx.payload_type for b in sigrw for tx in b.transactions} == {"SIG_RW"}


# --------------------------------------------------------------------------------------------
# The specific sharing mechanisms, each ruled out directly
# --------------------------------------------------------------------------------------------
def test_chain_has_no_class_level_mutable_state() -> None:
    """A mutable class attribute is the quietest way two instances end up sharing storage."""
    import inspect

    for name, value in inspect.getmembers(Chain):
        if name.startswith("__"):
            continue
        assert not isinstance(value, list | dict | set | bytearray), (
            f"Chain.{name} is a mutable class attribute; two chains would share it"
        )


def test_chain_uses_slots_so_state_cannot_be_bolted_on() -> None:
    assert hasattr(Chain, "__slots__")
    assert set(Chain.__slots__) == {"_blocks", "_index", "_policy", "name"}


def test_two_chains_have_distinct_storage_objects(cs1_keys: KeyPair) -> None:
    dtbu, sigrw = both_chains(cs1_keys)
    assert dtbu._blocks is not sigrw._blocks
    assert dtbu._index is not sigrw._index


def test_two_chains_built_with_no_policy_do_not_share_a_policy_object() -> None:
    """A `ChainPolicy()` default argument would be evaluated once at import and shared."""
    first = Chain(BC_DTBU)
    second = Chain(BC_SigRW)
    assert first._policy is not second._policy
    assert first._policy == second._policy


def test_a_shared_policy_is_still_allowed_explicitly() -> None:
    """Sharing an immutable policy on purpose is fine; it is the *implicit* sharing that is not."""
    policy = ChainPolicy(skew_tolerance_s=5.0)
    first = Chain(BC_DTBU, policy=policy)
    second = Chain(BC_SigRW, policy=policy)
    assert first._policy is second._policy
    assert len(first) == len(second) == 0


def test_no_module_level_chain_registry() -> None:
    """A registry keyed by chain name would hand two `Chain(BC_DTBU)` objects one store."""
    from bsfr_sh.blockchain import chain as chain_module

    shared = {
        name: value
        for name, value in vars(chain_module).items()
        if not name.startswith("__") and isinstance(value, list | dict | set)
    }
    assert not shared, f"module-level mutable state in blockchain.chain: {sorted(shared)}"


def test_two_chains_of_the_same_name_still_do_not_share(cs1_keys: KeyPair) -> None:
    """Even the pathological case: same name, same process, same arguments."""
    first = Chain(BC_DTBU)
    second = Chain(BC_DTBU)
    first.create_genesis(owner_id="CS_0", private_key=cs1_keys.private, timestamp=1000.0)
    assert len(second) == 0
    with pytest.raises(ChainError, match="is empty"):
        second.head()
