"""`blockchain.chain` — genesis, validated append, integrity walk, timestamps.

Chain separation is `test_chains_independent.py` (§V-5); tampering is `test_block_tamper.py`
(§V-4). This file covers the chain's own behaviour, including the skew tolerance that replaces
the paper's implied strict monotonicity (DEV-17).
"""

from __future__ import annotations

from itertools import pairwise
from pathlib import Path

import pytest

from bsfr_sh.blockchain.block import GENESIS_PREV_HASH, BlockDraft
from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW, Chain, ChainError, ChainPolicy
from bsfr_sh.blockchain.transaction import BackupPayload, Transaction, encrypt_backup
from bsfr_sh.crypto.ecdsa import KeyPair
from bsfr_sh.util.config import load_config

REPO_ROOT = Path(__file__).resolve().parents[2]
CHAIN_CONFIG = REPO_ROOT / "configs" / "chain.yaml"


def txs(keys: KeyPair, count: int, tag: str = "a") -> tuple[Transaction, ...]:
    return tuple(
        encrypt_backup(
            recipient=keys.public,
            tx_id=f"tx-{tag}-{i:04d}",
            payload=BackupPayload("SYS_1", bytes([i % 256]) * 32, i),
            created_at=i,
        )
        for i in range(count)
    )


def started_chain(keys: KeyPair, name: str = BC_DTBU, **kwargs: object) -> Chain:
    chain = Chain(name, **kwargs)  # type: ignore[arg-type]
    chain.create_genesis(owner_id="CS_0", private_key=keys.private, timestamp=1000.0)
    return chain


def extend(
    chain: Chain, keys: KeyPair, *, timestamp: float, count: int = 2, tag: str = "a"
) -> None:
    draft = chain.draft_next(
        owner_id="CS_1",
        owner_pubkey=keys.public.to_bytes(),
        transactions=txs(keys, count, tag),
        timestamp=timestamp,
    )
    chain.append(draft.seal(keys.private))


# --------------------------------------------------------------------------------------------
# Genesis
# --------------------------------------------------------------------------------------------
def test_genesis_has_the_zero_prev_hash(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    assert chain.block_at(0).prev_hash == GENESIS_PREV_HASH
    assert chain.height == 0
    assert len(chain) == 1


def test_a_second_genesis_is_refused(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    with pytest.raises(ChainError, match="already has a genesis"):
        chain.create_genesis(owner_id="CS_0", private_key=cs1_keys.private, timestamp=1000.0)


def test_appending_before_genesis_is_refused(cs1_keys: KeyPair) -> None:
    chain = Chain(BC_DTBU)
    block = BlockDraft(
        owner_id="CS_1",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=(),
        prev_hash=GENESIS_PREV_HASH,
        timestamp=1000.0,
    ).seal(cs1_keys.private)
    with pytest.raises(ChainError, match="no genesis block"):
        chain.append(block)


def test_an_unnamed_chain_is_refused() -> None:
    with pytest.raises(ChainError, match="must be named"):
        Chain("")


def test_empty_chain_has_no_head(cs1_keys: KeyPair) -> None:
    with pytest.raises(ChainError, match="is empty"):
        Chain(BC_DTBU).head()


# --------------------------------------------------------------------------------------------
# Append and read
# --------------------------------------------------------------------------------------------
def test_append_links_and_indexes(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    genesis_hash = chain.head_hash()
    extend(chain, cs1_keys, timestamp=1001.0)
    assert len(chain) == 2
    assert chain.height == 1
    assert chain.head().prev_hash == genesis_hash
    assert chain.contains(chain.head_hash())
    assert chain.block_by_hash(chain.head_hash()) == chain.head()


def test_iteration_is_genesis_first(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    for i in range(3):
        extend(chain, cs1_keys, timestamp=1001.0 + i, tag=f"t{i}")
    blocks = list(chain)
    assert len(blocks) == 4
    assert blocks[0].prev_hash == GENESIS_PREV_HASH
    for previous, current in pairwise(blocks):
        assert current.prev_hash == previous.current_hash


def test_iteration_yields_a_snapshot(cs1_keys: KeyPair) -> None:
    """Appending during iteration must not change what the iterator yields."""
    chain = started_chain(cs1_keys)
    iterator = iter(chain)
    extend(chain, cs1_keys, timestamp=1001.0)
    assert len(list(iterator)) == 1


def test_transaction_count_sums_the_chain(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    extend(chain, cs1_keys, timestamp=1001.0, count=3, tag="x")
    extend(chain, cs1_keys, timestamp=1002.0, count=5, tag="y")
    assert chain.transaction_count == 8


def test_the_same_block_cannot_be_appended_twice(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    draft = chain.draft_next(
        owner_id="CS_1",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=txs(cs1_keys, 2),
        timestamp=1001.0,
    )
    block = draft.seal(cs1_keys.private)
    chain.append(block)
    with pytest.raises(ChainError, match=r"does not link to the head|already in the chain"):
        chain.append(block)


def test_a_rejected_append_leaves_the_chain_unchanged(cs1_keys: KeyPair) -> None:
    """Every rejection path raises before mutating, so a failure cannot half-update the chain."""
    chain = started_chain(cs1_keys)
    extend(chain, cs1_keys, timestamp=1001.0)
    before_len, before_head = len(chain), chain.head_hash()
    orphan = BlockDraft(
        owner_id="CS_1",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=txs(cs1_keys, 2, "orphan"),
        prev_hash=b"\x09" * 32,
        timestamp=1002.0,
    ).seal(cs1_keys.private)
    with pytest.raises(ChainError):
        chain.append(orphan)
    assert len(chain) == before_len
    assert chain.head_hash() == before_head
    assert not chain.contains(orphan.current_hash)
    chain.verify_integrity()


def test_unknown_height_and_hash_raise(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    with pytest.raises(ChainError, match="no block at height"):
        chain.block_at(5)
    with pytest.raises(ChainError, match="no block with hash"):
        chain.block_by_hash(bytes(32))


# --------------------------------------------------------------------------------------------
# Timestamps — DEV-17
# --------------------------------------------------------------------------------------------
def test_increasing_timestamps_are_accepted(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    extend(chain, cs1_keys, timestamp=1001.0)
    extend(chain, cs1_keys, timestamp=1002.0, tag="b")
    assert len(chain) == 3


def test_an_equal_timestamp_is_accepted(cs1_keys: KeyPair) -> None:
    """Non-decreasing, not strictly increasing: two blocks can share a second."""
    chain = started_chain(cs1_keys)
    extend(chain, cs1_keys, timestamp=1000.0)
    assert len(chain) == 2


def test_skew_inside_the_tolerance_is_accepted(cs1_keys: KeyPair) -> None:
    """An honest block from a cloud server whose clock runs slow. Strict monotonicity would
    reject this, which is why DEV-17 replaces it."""
    chain = started_chain(cs1_keys, policy=ChainPolicy(skew_tolerance_s=30.0))
    extend(chain, cs1_keys, timestamp=1000.0 - 29.0)
    assert len(chain) == 2


def test_skew_beyond_the_tolerance_is_rejected(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys, policy=ChainPolicy(skew_tolerance_s=30.0))
    draft = chain.draft_next(
        owner_id="CS_1",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=txs(cs1_keys, 1),
        timestamp=1000.0 - 31.0,
    )
    with pytest.raises(ChainError, match="skew tolerance"):
        chain.append(draft.seal(cs1_keys.private))
    assert len(chain) == 1


def test_a_far_future_timestamp_is_accepted_by_the_chain(cs1_keys: KeyPair) -> None:
    """The chain bounds backwards drift only — freshness against wall-clock is the session
    layer's job, and duplicating it here would mean two clock policies to keep in step."""
    chain = started_chain(cs1_keys)
    extend(chain, cs1_keys, timestamp=1000.0 + 86_400.0)
    assert len(chain) == 2


def test_the_tolerance_comes_from_the_shipped_config() -> None:
    """DEV-17: one configured clock tolerance, shared with `crypto.session`, not two constants."""
    from bsfr_sh.crypto.session import SessionPolicy

    config = load_config(CHAIN_CONFIG, expected_kind="chain")
    chain_policy = ChainPolicy.from_config(config)
    session_policy = SessionPolicy.from_config(config)
    assert chain_policy.skew_tolerance_s == session_policy.timestamp_window_s == 30.0


# --------------------------------------------------------------------------------------------
# Integrity walk
# --------------------------------------------------------------------------------------------
def test_integrity_walk_passes_on_an_honest_chain(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    for i in range(5):
        extend(chain, cs1_keys, timestamp=1001.0 + i, tag=f"w{i}")
    chain.verify_integrity()


def test_integrity_walk_detects_a_duplicated_block(cs1_keys: KeyPair) -> None:
    """The check `append` cannot do: that the chain *still* holds after storage was touched."""
    chain = started_chain(cs1_keys)
    extend(chain, cs1_keys, timestamp=1001.0)
    extend(chain, cs1_keys, timestamp=1002.0, tag="b")
    # Reach into private storage on purpose — this is the scenario the walk exists for.
    chain._blocks[1] = chain._blocks[2]
    with pytest.raises(ChainError, match="missing from the hash index"):
        chain.verify_integrity()


def test_integrity_walk_detects_broken_linkage(cs1_keys: KeyPair) -> None:
    """Linkage specifically, with the hash index kept consistent so it is not what fires."""
    chain = started_chain(cs1_keys)
    extend(chain, cs1_keys, timestamp=1001.0)
    extend(chain, cs1_keys, timestamp=1002.0, tag="b")
    orphan = BlockDraft(
        owner_id="CS_1",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=txs(cs1_keys, 1, "orphan"),
        prev_hash=b"\x09" * 32,
        timestamp=1001.5,
    ).seal(cs1_keys.private)
    del chain._index[chain._blocks[1].current_hash]
    chain._blocks[1] = orphan
    chain._index[orphan.current_hash] = 1
    with pytest.raises(ChainError, match="does not link to block 0"):
        chain.verify_integrity()


def test_integrity_walk_detects_a_genesis_with_a_real_prev_hash(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    impostor = BlockDraft(
        owner_id="CS_0",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=(),
        prev_hash=b"\x09" * 32,
        timestamp=1000.0,
    ).seal(cs1_keys.private)
    del chain._index[chain._blocks[0].current_hash]
    chain._blocks[0] = impostor
    chain._index[impostor.current_hash] = 0
    with pytest.raises(ChainError, match="genesis prev_hash is not the zero hash"):
        chain.verify_integrity()


def test_integrity_walk_rejects_an_empty_chain() -> None:
    with pytest.raises(ChainError, match="is empty"):
        Chain(BC_SigRW).verify_integrity()


# --------------------------------------------------------------------------------------------
# check_append / adopt_genesis — the two entry points M2b's consensus uses
# --------------------------------------------------------------------------------------------
def test_check_append_accepts_what_append_accepts_and_changes_nothing(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    block = chain.draft_next(
        owner_id="CS_1",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=txs(cs1_keys, 2),
        timestamp=1001.0,
    ).seal(cs1_keys.private)
    chain.check_append(block)
    assert len(chain) == 1, "check_append must not append"
    chain.append(block)
    assert chain.head() == block


def test_check_append_refuses_what_append_refuses(cs1_keys: KeyPair) -> None:
    """One validator: the consensus layer's pre-check and append() can never disagree."""
    chain = started_chain(cs1_keys)
    orphan = BlockDraft(
        owner_id="CS_1",
        owner_pubkey=cs1_keys.public.to_bytes(),
        transactions=txs(cs1_keys, 2),
        prev_hash=bytes(range(32)),
        timestamp=1001.0,
    ).seal(cs1_keys.private)
    with pytest.raises(ChainError, match="does not link"):
        chain.check_append(orphan)
    with pytest.raises(ChainError, match="does not link"):
        chain.append(orphan)


def test_replicas_adopt_one_shared_genesis(cs1_keys: KeyPair) -> None:
    from bsfr_sh.blockchain.chain import build_genesis

    genesis = build_genesis(owner_id="CS_0", private_key=cs1_keys.private, timestamp=1000.0)
    a, b = Chain(BC_DTBU), Chain(BC_DTBU)
    a.adopt_genesis(genesis)
    b.adopt_genesis(genesis)
    assert a.head_hash() == b.head_hash()
    extend(a, cs1_keys, timestamp=1001.0)
    assert len(b) == 1, "sharing the frozen genesis block shares no chain state"


def test_adopt_genesis_refuses_a_non_genesis_block_and_a_second_genesis(cs1_keys: KeyPair) -> None:
    chain = started_chain(cs1_keys)
    extend(chain, cs1_keys, timestamp=1001.0)
    with pytest.raises(ChainError, match="already has a genesis"):
        chain.adopt_genesis(chain.block_at(0))
    with pytest.raises(ChainError, match="zero prev_hash"):
        Chain(BC_DTBU).adopt_genesis(chain.block_at(1))
