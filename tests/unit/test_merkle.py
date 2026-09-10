"""`crypto.merkle` — root construction, inclusion proofs, and the DEV-11 collision fix.

§V mapping: §V-4 (data manipulation). `MTR` is the only header field binding a block to its
transaction list, so every claim that a block's contents cannot be altered rests on these tests.
The duplicate-list case is the one the paper's design gets wrong; see docs/DEVIATIONS.md DEV-11.
"""

from __future__ import annotations

import pytest

from bsfr_sh.crypto.hashing import DOMAIN_MERKLE_LEAF, DOMAIN_MERKLE_NODE, tagged_h
from bsfr_sh.crypto.merkle import (
    EMPTY_ROOT,
    MerkleError,
    MerkleProof,
    MerkleTree,
    leaf_digest,
    merkle_root,
    node_digest,
    verify_proof,
)


def tx(index: int) -> bytes:
    """A stand-in transaction digest. Raw bytes, not a `Transaction` — M2 owns that type."""
    return bytes([index % 256]) * 32


def txs(count: int) -> list[bytes]:
    return [tx(i) for i in range(count)]


# --------------------------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------------------------
def test_single_leaf_root_is_the_count_bound_leaf() -> None:
    tree = MerkleTree([tx(0)])
    assert tree.depth == 0
    assert tree.root != leaf_digest(tx(0))  # the count binding is applied even at depth 0


def test_two_leaves_build_one_node() -> None:
    tree = MerkleTree(txs(2))
    assert tree.depth == 1


def test_odd_level_duplicates_the_last_node_per_dev_11() -> None:
    """DEV-11's stated construction, checked by hand against three leaves."""
    leaves = txs(3)
    a, b, c = (leaf_digest(item) for item in leaves)
    expected_bare = node_digest(node_digest(a, b), node_digest(c, c))
    from bsfr_sh.crypto.merkle import DOMAIN_MERKLE_ROOT, _count_prefix

    assert MerkleTree(leaves).root == tagged_h(DOMAIN_MERKLE_ROOT, _count_prefix(3), expected_bare)


def test_leaf_and_node_domains_differ() -> None:
    """An internal node must not be presentable as a leaf (Merkle second-preimage)."""
    assert tagged_h(DOMAIN_MERKLE_LEAF, b"x") != tagged_h(DOMAIN_MERKLE_NODE, b"x")


def test_empty_tree_has_a_defined_root_distinct_from_every_other() -> None:
    assert MerkleTree([]).root == EMPTY_ROOT
    assert merkle_root([tx(0)]) != EMPTY_ROOT


def test_root_is_order_sensitive() -> None:
    assert merkle_root([tx(0), tx(1)]) != merkle_root([tx(1), tx(0)])


def test_root_is_deterministic() -> None:
    assert merkle_root(txs(7)) == merkle_root(txs(7))


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 8, 9, 15, 16, 100])
def test_root_is_stable_for_many_sizes(count: int) -> None:
    assert len(merkle_root(txs(count))) == 32


# --------------------------------------------------------------------------------------------
# The DEV-11 amendment: CVE-2012-2459
# --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("count", [1, 3, 5, 7, 9, 15, 99])
def test_duplicate_last_transaction_does_not_collide(count: int) -> None:
    """A list of N and that list with its last element repeated must not share a root.

    Under plain Bitcoin-style duplication they do — odd-count padding makes the two lists build
    an identical tree. `MTR` is what binds a block to its contents, so a collision here means two
    different transaction lists that a block header cannot distinguish. The count binding added by
    the DEV-11 amendment separates them.
    """
    original = txs(count)
    padded = [*original, original[-1]]
    assert merkle_root(original) != merkle_root(padded)


def test_the_underlying_tree_really_does_collide_without_the_count_binding() -> None:
    """The vulnerability is real, not hypothetical — this is the collision we are fixing.

    Recorded as a test so nobody later "simplifies" the count binding away on the grounds that it
    looks redundant.
    """
    original = txs(3)
    padded = [*original, original[-1]]
    bare_original = MerkleTree(original)._levels[-1][0]
    bare_padded = MerkleTree(padded)._levels[-1][0]
    assert bare_original == bare_padded  # the trees are identical...
    assert original != padded  # ...over different transaction lists
    assert MerkleTree(original).root != MerkleTree(padded).root  # ...and the roots are not


# --------------------------------------------------------------------------------------------
# Inclusion proofs
# --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 8, 11, 16, 100])
def test_every_leaf_has_a_verifying_inclusion_proof(count: int) -> None:
    items = txs(count)
    tree = MerkleTree(items)
    for index, item in enumerate(items):
        assert verify_proof(tree.root, item, tree.prove(index))


def test_forged_proof_for_an_absent_transaction_does_not_verify() -> None:
    items = txs(8)
    tree = MerkleTree(items)
    forged = tx(200)
    assert forged not in items
    assert not verify_proof(tree.root, forged, tree.prove(3))


def test_proof_with_a_tampered_sibling_does_not_verify() -> None:
    items = txs(8)
    tree = MerkleTree(items)
    proof = tree.prove(2)
    is_right, sibling = proof.path[0]
    tampered = MerkleProof(
        leaf_index=proof.leaf_index,
        leaf_count=proof.leaf_count,
        path=((is_right, bytes(32)), *proof.path[1:]),
    )
    assert sibling != bytes(32)
    assert not verify_proof(tree.root, items[2], tampered)


def test_proof_with_a_flipped_sibling_side_does_not_verify() -> None:
    """Swapping left for right forges a different tree shape over the same digests."""
    items = txs(8)
    tree = MerkleTree(items)
    proof = tree.prove(2)
    flipped = MerkleProof(
        leaf_index=proof.leaf_index,
        leaf_count=proof.leaf_count,
        path=tuple((not is_right, sibling) for is_right, sibling in proof.path),
    )
    assert not verify_proof(tree.root, items[2], flipped)


def test_proof_that_misstates_the_leaf_count_does_not_verify() -> None:
    """This is what makes the count binding load-bearing rather than decorative."""
    items = txs(4)
    tree = MerkleTree(items)
    proof = tree.prove(1)
    lying = MerkleProof(leaf_index=1, leaf_count=3, path=proof.path)
    assert not verify_proof(tree.root, items[1], lying)


def test_proof_against_the_wrong_root_does_not_verify() -> None:
    items = txs(8)
    tree = MerkleTree(items)
    other = MerkleTree(txs(9))
    assert not verify_proof(other.root, items[0], tree.prove(0))


def test_malformed_proofs_are_rejected_rather_than_evaluated() -> None:
    items = txs(4)
    tree = MerkleTree(items)
    proof = tree.prove(0)
    assert not verify_proof(tree.root, items[0], MerkleProof(0, 0, proof.path))
    assert not verify_proof(tree.root, items[0], MerkleProof(-1, 4, proof.path))
    assert not verify_proof(tree.root, items[0], MerkleProof(9, 4, proof.path))
    assert not verify_proof(tree.root, items[0], MerkleProof(0, 4, proof.path[:1]))


def test_out_of_range_leaf_index_raises() -> None:
    tree = MerkleTree(txs(4))
    with pytest.raises(MerkleError, match="out of range"):
        tree.prove(4)
