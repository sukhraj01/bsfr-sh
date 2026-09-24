"""`blockchain.hybrid.HybridChain` — anchor scheduling and the three security properties. M7-5.

Uses `pbft_harness.make_cluster` for a real 4-node private cluster (the same fixture
`tests/unit/test_pbft.py` builds), so "quorum-agreed" is not simulated — `framework.
_block_pipeline.read_chain` genuinely walks replica agreement before `HybridChain` ever sees a
`Chain`.
"""

from __future__ import annotations

import math

import pytest
from pbft_harness import make_cluster, run_for, submit_block

from bsfr_sh.blockchain.block import BlockDraft
from bsfr_sh.blockchain.chain import BC_DTBU, ChainError
from bsfr_sh.blockchain.hybrid import AnchorPolicy, HybridChain, HybridChainError
from bsfr_sh.blockchain.transaction import BackupPayload, encrypt_backup
from bsfr_sh.crypto.ecdsa import KeyPair, keypair_from_secret
from bsfr_sh.framework._block_pipeline import read_chain

ANCHOR_KEYS: KeyPair = keypair_from_secret(
    0x0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A
)


def make_hybrid(frequency: int = 1) -> HybridChain:
    return HybridChain(
        private_chain_name=BC_DTBU,
        anchor_chain_name=f"{BC_DTBU}_anchor",
        anchor_key=ANCHOR_KEYS.private,
        policy=AnchorPolicy(frequency=frequency),
    )


def commit_blocks(cluster, count: int) -> None:
    for i in range(count):
        submit_block(cluster, i)
        run_for(cluster)


# --------------------------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------------------------
def test_anchor_chain_name_must_differ_from_private_chain_name() -> None:
    with pytest.raises(HybridChainError, match="must differ"):
        HybridChain(
            private_chain_name=BC_DTBU,
            anchor_chain_name=BC_DTBU,
            anchor_key=ANCHOR_KEYS.private,
        )


def test_anchor_frequency_must_be_at_least_one() -> None:
    with pytest.raises(HybridChainError, match="frequency"):
        AnchorPolicy(frequency=0)


def test_hybrid_chain_starts_with_an_anchor_genesis_and_no_anchors() -> None:
    hybrid = make_hybrid()
    assert hybrid.anchor_chain.height == 0
    assert hybrid.anchored_heights == ()


# --------------------------------------------------------------------------------------------
# Scheduling — the ceil(blocks/N) property the task brief pins down explicitly
# --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("frequency,blocks", [(1, 1), (1, 7), (5, 15), (5, 12), (10, 27), (3, 9)])
def test_sync_then_flush_anchors_exactly_ceil_blocks_over_frequency(frequency, blocks) -> None:
    cluster = make_cluster()
    commit_blocks(cluster, blocks)
    hybrid = make_hybrid(frequency=frequency)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)
    hybrid.flush(chain, timestamp=0.0)
    assert len(hybrid.anchored_heights) == math.ceil(blocks / frequency)
    assert hybrid.anchored_heights[-1] == blocks  # flush always closes out the head
    assert all(h % frequency == 0 for h in hybrid.anchored_heights[:-1])


def test_frequency_one_anchors_every_single_block() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 4)
    hybrid = make_hybrid(frequency=1)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)
    assert hybrid.anchored_heights == (1, 2, 3, 4)
    hybrid.flush(chain, timestamp=0.0)  # a no-op: nothing left to close out
    assert hybrid.anchored_heights == (1, 2, 3, 4)


def test_sync_without_flush_leaves_a_trailing_gap_when_not_a_multiple() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 7)
    hybrid = make_hybrid(frequency=5)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)
    assert hybrid.anchored_heights == (5,)  # height 7 not yet closed out
    hybrid.flush(chain, timestamp=0.0)
    assert hybrid.anchored_heights == (5, 7)


def test_sync_is_idempotent_once_caught_up() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 3)
    hybrid = make_hybrid(frequency=1)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)
    first = hybrid.anchored_heights
    hybrid.sync(chain, timestamp=1.0)
    assert hybrid.anchored_heights == first


def test_wrong_chain_name_is_rejected() -> None:
    from bsfr_sh.blockchain.chain import BC_SigRW

    cluster = make_cluster(BC_SigRW, ("CS_4", "CS_5", "CS_6", "CS_7"))
    commit_blocks(cluster, 1)
    hybrid = make_hybrid()  # built for BC_DTBU
    with pytest.raises(HybridChainError, match="expected"):
        hybrid.sync(read_chain(cluster), timestamp=0.0)


# --------------------------------------------------------------------------------------------
# Security test (a) — tamper an anchored block; verify_anchor catches it
# --------------------------------------------------------------------------------------------
def test_verify_anchor_confirms_an_untampered_anchored_block() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 3)
    hybrid = make_hybrid(frequency=1)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)
    result = hybrid.verify_anchor(chain, 2)
    assert result.anchored and result.verified


def _tamper_private_block(cluster, height: int) -> None:
    """Replace the block at `height`, on every replica, with a different but validly-signed one.

    Mirrors `tests/unit/test_block_tamper.py`'s pattern of rebuilding rather than mutating a
    `Block` in place (it is frozen); reaching into `Chain._blocks` simulates a storage-level
    compromise the application layer's own API cannot express, which is exactly the threat
    `blockchain.hybrid`'s module docstring says the anchor exists to catch.
    """
    owner = cluster.membership.ids[0]
    key = next(iter(cluster.replicas.values()))._private_key
    for replica in cluster.replicas.values():
        original = replica.chain.block_at(height)
        evil_tx = encrypt_backup(
            recipient=key.public_key,
            tx_id="evil",
            payload=BackupPayload("SYS_EVIL", b"tampered" * 4, 999),
            created_at=999,
        )
        tampered = BlockDraft(
            owner_id=owner,
            owner_pubkey=key.public_key.to_bytes(),
            transactions=(evil_tx,),
            prev_hash=replica.chain.block_at(height - 1).current_hash,
            timestamp=original.timestamp,
        ).seal(key)
        replica.chain._blocks[height] = tampered
        replica.chain._index[tampered.current_hash] = height


def test_security_a_tamper_after_anchoring_is_caught() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 3)
    hybrid = make_hybrid(frequency=1)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)
    assert hybrid.verify_anchor(chain, 2).verified

    _tamper_private_block(cluster, 2)
    tampered_chain = read_chain(cluster)
    result = hybrid.verify_anchor(tampered_chain, 2)
    assert result.anchored
    assert not result.verified


# --------------------------------------------------------------------------------------------
# Security test (b) — tamper an unanchored block; verify_anchor cannot see it (the honest gap)
# --------------------------------------------------------------------------------------------
def test_security_b_tamper_of_an_unanchored_block_is_not_detected() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 7)
    hybrid = make_hybrid(frequency=5)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)  # anchors height 5 only; 6 and 7 are the honest gap
    assert hybrid.anchored_heights == (5,)

    _tamper_private_block(cluster, 6)
    tampered_chain = read_chain(cluster)
    result = hybrid.verify_anchor(tampered_chain, 6)
    assert not result.anchored  # nothing to check against — cost of infrequent anchoring, stated
    assert not result.verified

    # And the anchored height is, correctly, still unaffected by that tamper.
    assert hybrid.verify_anchor(tampered_chain, 5).verified


# --------------------------------------------------------------------------------------------
# Security test (c) — tamper the anchor chain itself; its own integrity check catches it
# --------------------------------------------------------------------------------------------
def test_security_c_tamper_of_the_anchor_chain_is_caught() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 3)
    hybrid = make_hybrid(frequency=1)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)
    hybrid.verify_anchor_chain_integrity()  # clean before tampering

    original = hybrid.anchor_chain.block_at(2)
    evil_tx = encrypt_backup(
        recipient=ANCHOR_KEYS.public,
        tx_id="evil-anchor",
        payload=BackupPayload("SYS_EVIL", b"x" * 8, 1),
        created_at=1,
    )
    bad = BlockDraft(
        owner_id=original.owner_id,
        owner_pubkey=original.owner_pubkey,
        transactions=(evil_tx,),
        prev_hash=hybrid.anchor_chain.block_at(1).current_hash,
        timestamp=original.timestamp,
    ).seal(ANCHOR_KEYS.private)
    hybrid.anchor_chain._blocks[2] = bad
    hybrid.anchor_chain._index[bad.current_hash] = 2

    with pytest.raises(ChainError):
        hybrid.verify_anchor_chain_integrity()


# --------------------------------------------------------------------------------------------
# verify_range and read_anchor_record_from_chain
# --------------------------------------------------------------------------------------------
def test_verify_range_covers_anchored_and_unanchored_heights() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 6)
    hybrid = make_hybrid(frequency=3)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)
    results = hybrid.verify_range(chain, 1, 6)
    assert [r.block_height for r in results] == [1, 2, 3, 4, 5, 6]
    assert [r.anchored for r in results] == [False, False, True, False, False, True]
    assert all(r.verified for r in results if r.anchored)


def test_verify_range_rejects_bad_bounds() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 2)
    hybrid = make_hybrid()
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)
    with pytest.raises(HybridChainError, match="start"):
        hybrid.verify_range(chain, 2, 1)
    with pytest.raises(HybridChainError, match="genesis"):
        hybrid.verify_range(chain, 0, 1)


def test_read_anchor_record_from_chain_round_trips() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 2)
    hybrid = make_hybrid(frequency=1)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=5.0)
    from_chain = hybrid.read_anchor_record_from_chain(1)
    assert from_chain is not None
    assert from_chain == hybrid.verify_anchor(chain, 1).record


def test_read_anchor_record_from_chain_returns_none_for_an_unanchored_height() -> None:
    cluster = make_cluster()
    commit_blocks(cluster, 7)
    hybrid = make_hybrid(frequency=5)
    chain = read_chain(cluster)
    hybrid.sync(chain, timestamp=0.0)
    assert hybrid.read_anchor_record_from_chain(6) is None
