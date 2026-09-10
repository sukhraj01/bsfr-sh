"""SHA-256 — the single hashing entry point for the whole project.

CLAUDE.md §7: *"Hashing is always SHA-256 via `crypto.hashing.h()`. Never call `hashlib`
directly outside that module."* `tests/unit/test_module_boundaries.py` enforces that with an AST
check, so the rule is checked on every `make test` rather than in review.

Domain separation
-----------------
`h()` alone is not enough. A bare SHA-256 over a byte string says nothing about what the string
*was*, so a digest computed in one position can be replayed in another: a Merkle leaf presented
as an internal node (the classic second-preimage attack on Merkle trees), a transaction encoding
accepted as a block-header pre-image, a KEM transcript reused as a session transcript.

`tagged_h()` fixes the position into the digest. The pre-image is

    encode(domain) || encode(part_0) || encode(part_1) || ...

using the canonical encoder from `util.serialization`, which tag- *and* length-prefixes every
value. Two consequences matter:

* **Prefix-free.** ``tagged_h(D, b"ab", b"c")`` and ``tagged_h(D, b"a", b"bc")`` differ, because
  each part carries its own length. Plain concatenation would collide, and a Merkle root built on
  a colliding concatenation is a forgeable root.
* **Cross-domain distinct.** Two domains never share a pre-image, so a digest is only ever valid
  in the position it was computed for.

`util.serialization` deliberately does not hash and this module deliberately does not encode
protocol structures; the dependency runs `util <- crypto` and never back
(docs/ARCHITECTURE.md §Dependency direction).
"""

from __future__ import annotations

import hashlib
from typing import Final

from bsfr_sh.util.serialization import encode

__all__ = [
    "DIGEST_SIZE",
    "DOMAIN_BLOCK_HEADER",
    "DOMAIN_KEM_TRANSCRIPT",
    "DOMAIN_MERKLE_LEAF",
    "DOMAIN_MERKLE_NODE",
    "DOMAIN_MERKLE_ROOT",
    "DOMAIN_SESSION_TRANSCRIPT",
    "DOMAIN_TRANSACTION",
    "HASH_NAME",
    "h",
    "hex_digest",
    "tagged_h",
]

#: SHA-256, per `configs/chain.yaml` ``crypto.hash`` and the paper throughout.
HASH_NAME: Final = "sha-256"
DIGEST_SIZE: Final = 32

# --------------------------------------------------------------------------------------------
# Domains
# --------------------------------------------------------------------------------------------
# One constant per *position a digest can occupy*. Versioned, because changing what goes into a
# pre-image while keeping the tag would silently invalidate every stored digest.
#
# These are distinct from `util.serialization`'s DOMAIN_* constants, which separate *encodings*.
# A value can be encoded once and then hashed into several positions; the two layers separate
# different things and are deliberately not shared.

#: A transaction's content digest — `Transaction.digest` in M2.
DOMAIN_TRANSACTION: Final = "bsfr_sh.hash.transaction.v1"

#: A block header's `HC_βj` (docs/NOTATION.md).
DOMAIN_BLOCK_HEADER: Final = "bsfr_sh.hash.block_header.v1"

#: Merkle positions. Leaf and node must differ or an attacker can present an internal node as a
#: leaf and claim inclusion of data that was never in the tree.
DOMAIN_MERKLE_LEAF: Final = "bsfr_sh.hash.merkle.leaf.v1"
DOMAIN_MERKLE_NODE: Final = "bsfr_sh.hash.merkle.node.v1"

#: The count-bound root — see `crypto.merkle` and docs/DEVIATIONS.md DEV-11.
DOMAIN_MERKLE_ROOT: Final = "bsfr_sh.hash.merkle.root.v1"

#: ECIES wrap transcript (DEV-01) and session-establishment transcript (DEV-02).
DOMAIN_KEM_TRANSCRIPT: Final = "bsfr_sh.hash.kem.transcript.v1"
DOMAIN_SESSION_TRANSCRIPT: Final = "bsfr_sh.hash.session.transcript.v1"


def h(data: bytes) -> bytes:
    """Return the raw SHA-256 digest of `data`.

    The unadorned primitive: use it only where the input is already unambiguous — an existing
    digest, or bytes that carry their own framing. For anything positional, use `tagged_h`.
    """
    return hashlib.sha256(data).digest()


def tagged_h(domain: str, *parts: bytes) -> bytes:
    """Return the domain-separated SHA-256 digest of `parts`.

    Each part is length-prefixed by the canonical encoder, so the pre-image is unambiguous and
    no two distinct argument lists collide.
    """
    if not domain:
        raise ValueError("domain must be a non-empty string; an empty tag separates nothing")
    hasher = hashlib.sha256()
    hasher.update(encode(domain))
    for part in parts:
        hasher.update(encode(part))
    return hasher.digest()


def hex_digest(digest: bytes) -> str:
    """Hex-encode a digest for logs and result sidecars."""
    return digest.hex()
