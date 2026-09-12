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
from collections.abc import Mapping
from typing import Any, Final

from bsfr_sh.util.serialization import (
    DOMAIN_CONFIG,
    CanonicalEncodingError,
    encode,
    encode_struct,
)

__all__ = [
    "CONFIG_HASH_SCHEME",
    "DIGEST_SIZE",
    "DOMAIN_BACKUP_ATTESTATION",
    "DOMAIN_BACKUP_ID",
    "DOMAIN_BACKUP_PAYLOAD",
    "DOMAIN_BACKUP_TX_ID",
    "DOMAIN_BLOCK_HEADER",
    "DOMAIN_CONFIG",
    "DOMAIN_KEM_TRANSCRIPT",
    "DOMAIN_MERKLE_LEAF",
    "DOMAIN_MERKLE_NODE",
    "DOMAIN_MERKLE_ROOT",
    "DOMAIN_SAMPLE_ATTESTATION",
    "DOMAIN_SAMPLE_TRACE",
    "DOMAIN_SESSION_TRANSCRIPT",
    "DOMAIN_TRANSACTION",
    "HASH_NAME",
    "combined_config_hash",
    "config_hash",
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

#: `DT_BU` positions (DEV-23, DEV-24): the digest `SYS_i` takes before shipping, the pre-image it
#: signs over that digest, the backup id derived from both, and each chunk's public `tx_id`. Four
#: positions, four tags — a payload digest must never verify as an attestation pre-image.
DOMAIN_BACKUP_PAYLOAD: Final = "bsfr_sh.hash.backup.payload.v1"
DOMAIN_BACKUP_ATTESTATION: Final = "bsfr_sh.hash.backup.attestation.v1"
DOMAIN_BACKUP_ID: Final = "bsfr_sh.hash.backup.id.v1"
DOMAIN_BACKUP_TX_ID: Final = "bsfr_sh.hash.backup.tx_id.v1"

#: `Sig_RW`'s two senses (DEV-03), which must never share a pre-image: the content digest over a
#: sample's canonical behavioural trace, and the pre-image `CS_l` signs to attest to that digest.
DOMAIN_SAMPLE_TRACE: Final = "bsfr_sh.hash.sample.trace.v1"
DOMAIN_SAMPLE_ATTESTATION: Final = "bsfr_sh.hash.sample.attestation.v1"


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


# --------------------------------------------------------------------------------------------
# Config hashing
# --------------------------------------------------------------------------------------------
# This lives here, not in `util.config`, because `util` may not import upward
# (docs/ARCHITECTURE.md fixes the direction as `util <- crypto`) and CLAUDE.md §7 requires this
# module to be the only `hashlib` importer. Those two rules together mean a config digest cannot
# be computed inside `util.config` at load time; the consumer that needs one — `bench`, or a
# script writing a sidecar — composes `util.config` with this function instead. That is why
# `Config` no longer carries a `config_hash` field. Retires debt D1.

#: Bumped when the *construction* of a config hash changes, independently of the config content.
#:
#: Scheme 1 (M0-M1) hashed `encode_struct(DOMAIN_CONFIG, ...)` through a bare `hashlib.sha256`
#: call inside `util.config`. Scheme 2 routes the same pre-image through `tagged_h`, which mixes
#: in a domain tag, so every config hash changed value on 2026-09-11 *without any config file
#: changing*. Sidecars record the scheme so that a later comparison reads a version difference as
#: a version difference rather than as config drift — see `CONFIG_HASH_SCHEME` in the sidecar
#: contract, and the backfilled `results/logs/20260910T213021Z-f07b5fbf.json`.
CONFIG_HASH_SCHEME: Final = 2

#: The position a config digest occupies. Distinct from `util.serialization.DOMAIN_CONFIG`, which
#: separates the *encoding*; this separates the *hash*.
DOMAIN_CONFIG_HASH: Final = "bsfr_sh.hash.config.v2"


def config_hash(kind: str, data: Mapping[str, Any]) -> str:
    """Return the stable SHA-256 hex digest of a config's content.

    Order-independent (mappings are sorted by canonical encoded key), comment-independent, and
    identical across runs, processes, machines and Python versions — the property every
    `results/logs/<run_id>.json` depends on to tie a number back to the configuration that
    produced it (CLAUDE.md §2).
    """
    try:
        payload = encode_struct(DOMAIN_CONFIG, ("kind", "data"), {"kind": kind, "data": data})
    except CanonicalEncodingError as exc:
        raise ValueError(f"config for {kind!r} contains a non-encodable value: {exc}") from exc
    return tagged_h(DOMAIN_CONFIG_HASH, payload).hex()


def combined_config_hash(hashes_by_kind: Mapping[str, str]) -> str:
    """Hash of several configs, for a run that reads more than one file.

    Takes `{kind: config_hash}` rather than `Config` objects, so that `crypto` does not need to
    know what a `Config` is. Independent of the order the configs were loaded in.
    """
    return config_hash("combined", dict(hashes_by_kind))
