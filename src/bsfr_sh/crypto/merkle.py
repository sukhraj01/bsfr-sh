"""Merkle tree over transaction digests — `MTR` in docs/NOTATION.md.

Implements the construction declared in docs/DEVIATIONS.md DEV-11: a binary tree, Bitcoin's
convention of duplicating the last node when a level has an odd count, plus the count binding
added by the DEV-11 amendment.

Why the count binding exists
----------------------------
Last-node duplication is not injective. Take the four leaves ``[a, b, c]``: the bottom level is
padded to ``[a, b, c, c]``. The three-leaf list and the four-leaf list ``[a, b, c, c]`` therefore
build *the same tree* and produce *the same root*. This is the shape of CVE-2012-2459, and it is
not theoretical here: `MTR` is the only thing in a block header that binds the header to its
transaction list, so two different transaction lists that a block header cannot tell apart is an
integrity hole in the paper's design.

The fix keeps DEV-11's construction exactly as stated and binds the leaf count into the final
digest:

    MTR = tagged_h(DOMAIN_MERKLE_ROOT, uint64_be(leaf_count), bare_root)

``[a, b, c]`` and ``[a, b, c, c]`` now differ in `leaf_count`, so they produce different roots
while the tree above them is unchanged. The cost is that our `MTR` values are not Bitcoin's —
which they were never going to be anyway, since our leaves are domain-separated (see
`crypto.hashing`) and Bitcoin's are double-SHA-256.

Positions are separated too: a leaf digest and an internal-node digest use different domains, so
an internal node cannot be replayed as a leaf to claim inclusion of data the tree never held.
"""

from __future__ import annotations

import hmac
import struct
from dataclasses import dataclass
from typing import Final

from bsfr_sh.crypto.hashing import (
    DOMAIN_MERKLE_LEAF,
    DOMAIN_MERKLE_NODE,
    DOMAIN_MERKLE_ROOT,
    tagged_h,
)

__all__ = [
    "EMPTY_ROOT",
    "MerkleError",
    "MerkleProof",
    "MerkleTree",
    "leaf_digest",
    "merkle_root",
    "node_digest",
    "verify_proof",
]

#: Bitcoin's rule, restated from DEV-11: an odd level duplicates its last node.
ODD_NODE_POLICY: Final = "duplicate_last"


class MerkleError(ValueError):
    """Raised when a tree, a root, or an inclusion proof is malformed or does not verify."""


def _count_prefix(leaf_count: int) -> bytes:
    """Fixed-width big-endian leaf count — the DEV-11 amendment's binding."""
    return struct.pack(">Q", leaf_count)


def leaf_digest(item: bytes) -> bytes:
    """Digest of a leaf. `item` is a transaction digest (docs/ARCHITECTURE.md §crypto)."""
    return tagged_h(DOMAIN_MERKLE_LEAF, item)


def node_digest(left: bytes, right: bytes) -> bytes:
    """Digest of an internal node over its two children, in order."""
    return tagged_h(DOMAIN_MERKLE_NODE, left, right)


#: Root of a tree with no leaves. Defined rather than an error so that a block with an empty
#: transaction list still has a well-formed header; the count binding keeps it distinct from
#: every non-empty root.
EMPTY_ROOT: Final = tagged_h(DOMAIN_MERKLE_ROOT, _count_prefix(0), b"")


@dataclass(frozen=True)
class MerkleProof:
    """An inclusion proof for one leaf.

    `path` runs bottom-up. Each step is `(sibling_is_right, sibling_digest)`: `True` means the
    sibling sits on the right and the running digest is the left child. `leaf_count` is carried
    because the root binds it — a proof that does not state the count cannot reconstruct the
    root, which is precisely what makes the count binding effective rather than decorative.
    """

    leaf_index: int
    leaf_count: int
    path: tuple[tuple[bool, bytes], ...]


class MerkleTree:
    """A built Merkle tree, retaining its levels so proofs are O(log n) lookups.

    Levels are stored bottom-up: `levels[0]` is the leaf digests as built (before any padding),
    `levels[-1]` is the single bare root.
    """

    __slots__ = ("_leaf_count", "_levels", "_root")

    def __init__(self, items: list[bytes]) -> None:
        leaves = [leaf_digest(item) for item in items]
        self._leaf_count = len(leaves)
        if not leaves:
            self._levels: list[list[bytes]] = [[]]
            self._root = EMPTY_ROOT
            return
        levels: list[list[bytes]] = [leaves]
        current = leaves
        while len(current) > 1:
            # DEV-11: odd level duplicates its last node. The duplicate is materialised into the
            # stored level so that proof generation and root computation walk identical data.
            if len(current) % 2 == 1:
                current = [*current, current[-1]]
                levels[-1] = current
            current = [node_digest(current[i], current[i + 1]) for i in range(0, len(current), 2)]
            levels.append(current)
        self._levels = levels
        self._root = tagged_h(DOMAIN_MERKLE_ROOT, _count_prefix(self._leaf_count), levels[-1][0])

    @property
    def root(self) -> bytes:
        """`MTR` — the count-bound root that goes into the block header."""
        return self._root

    @property
    def leaf_count(self) -> int:
        return self._leaf_count

    @property
    def depth(self) -> int:
        """Number of internal levels above the leaves."""
        return len(self._levels) - 1

    def prove(self, leaf_index: int) -> MerkleProof:
        """Build an inclusion proof for the leaf at `leaf_index`."""
        if not 0 <= leaf_index < self._leaf_count:
            raise MerkleError(
                f"leaf_index {leaf_index} out of range for a tree of {self._leaf_count} leaves"
            )
        path: list[tuple[bool, bytes]] = []
        index = leaf_index
        for level in self._levels[:-1]:
            sibling_is_right = index % 2 == 0
            sibling_index = index + 1 if sibling_is_right else index - 1
            path.append((sibling_is_right, level[sibling_index]))
            index //= 2
        return MerkleProof(leaf_index=leaf_index, leaf_count=self._leaf_count, path=tuple(path))


def merkle_root(items: list[bytes]) -> bytes:
    """`MTR` over a transaction-digest list. The one function M2's `Block` calls."""
    return MerkleTree(items).root


def verify_proof(root: bytes, item: bytes, proof: MerkleProof) -> bool:
    """Return whether `item` is the leaf at `proof.leaf_index` of the tree with root `root`.

    Recomputes the root from the proof and compares. Because the root binds `leaf_count`, a proof
    that misstates the count fails here even when every digest on its path is genuine — which is
    what closes the duplicate-last-leaf collision described in the module docstring.
    """
    if proof.leaf_count <= 0 or not 0 <= proof.leaf_index < proof.leaf_count:
        return False
    # The path length is determined by the leaf count; a proof of any other length is malformed
    # and must be rejected rather than evaluated.
    expected_depth = 0
    width = proof.leaf_count
    while width > 1:
        width = (width + 1) // 2
        expected_depth += 1
    if len(proof.path) != expected_depth:
        return False

    running = leaf_digest(item)
    for sibling_is_right, sibling in proof.path:
        running = (
            node_digest(running, sibling) if sibling_is_right else node_digest(sibling, running)
        )
    recomputed = tagged_h(DOMAIN_MERKLE_ROOT, _count_prefix(proof.leaf_count), running)
    # Digest comparison is not secret-dependent here, but comparing digests in constant time is
    # cheap and keeps the habit uniform across the crypto package.
    return hmac.compare_digest(recomputed, root)
