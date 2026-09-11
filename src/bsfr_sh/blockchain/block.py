"""`β_j` — the block. Implements Alg. 1 line 3 and Alg. 2 line 8.

Header field order is `util.serialization.BLOCK_FIELD_ORDER`, which mirrors the paper's Alg. 1
line 3 exactly and is asserted against this module's types at import so the two cannot drift.

Why there are two types
-----------------------
`current_hash` (`HC_βj`) and `signature` (`Sig_βj`) are header fields computed *over* the other
header fields. A single dataclass holding all ten is a structure that can hold a digest which
does not match the thing it digests — and once such an object exists, every guarantee downstream
is a matter of remembering to re-check it. Two mechanisms remove that:

1. **`BlockDraft` has no `current_hash` and no `signature` fields at all.** An unsealed block
   cannot carry a wrong hash because it carries no hash. It is what an assembler builds and what
   M2b's consensus will pass around before commitment.

2. **`Block` never stores its derived fields.** `merkle_root` and `current_hash` are computed
   from the stored fields on access (and cached). There is no assignment through which they
   could disagree with the contents — not "checked and found consistent", but *not separately
   representable*. A block arriving from outside carries claimed values; `Block.from_fields`
   recomputes and compares, so the comparison happens once, at the boundary, rather than being
   re-derivable anywhere later.

`signature` is the one derived field that must be stored, because a signature is not
recomputable without the private key. It is verified in `__post_init__` against the block's own
`owner_pubkey`, so a `Block` instance with an invalid signature cannot exist either.

What `Sig_βj` covers
--------------------
The signature is over `BlockPart.SIGN` — `util.serialization.BLOCK_SIGNED_FIELDS`, which is every
header field except `signature` itself:

    version, timestamp, nonce, merkle_root, owner_id, owner_pubkey, transactions,
    prev_hash, current_hash

This is deliberately the *whole* header and not just `current_hash`. Signing `current_hash` alone
would also be sound here, because `current_hash` is taken over `BlockPart.HASH` — every header
field except `current_hash` and `signature` — and so transitively covers all of them. Signing the
full set costs nothing and removes the need for that argument to stay true: if a later change
ever narrowed what `current_hash` covers, a signature over `current_hash` alone would silently
narrow with it, while this one would not. §V-4's tamper-resistance claim rests on this being
written down, so it is.

`transactions` enters both pre-images as the ordered list of canonical transaction encodings, so
reordering transactions changes `MTR`, `current_hash` and the signature.

`RN` — the random nonce — is inert
-----------------------------------
The paper's header carries `RN` / `RNDT_j`, a random nonce. Under proof-of-work that is the
mining counter: you vary it until the block hash meets a difficulty target. BSFR-SH does not use
proof-of-work — §VII specifies voting-based pBFT consensus (Castro & Liskov, ref [24]), where
blocks are committed by a `2f+1` quorum and there is nothing to mine.

The field is kept for header fidelity: it is in the paper's header, it is in `MTR`'s sibling
fields, and dropping it would change every block hash away from the paper's structure. But it has
**no consensus role, no difficulty target, and no validation rule**. Nothing anywhere in this
codebase should loop over nonce values looking for a hash with leading zeros. If M2b grows a
mining loop around this field, that is a bug and not a feature — pBFT has no such step, and a
proof-of-work loop would make Fig. 6's timings a measurement of an artificial difficulty setting.
It is set once, at random, per block, and never examined again.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from functools import cached_property
from typing import Final

from bsfr_sh.blockchain.transaction import Transaction
from bsfr_sh.crypto.ecdsa import (
    PrivateKey,
    PublicKey,
    SignatureError,
    load_public_key,
    sign,
    verify,
)
from bsfr_sh.crypto.hashing import DOMAIN_BLOCK_HEADER, tagged_h
from bsfr_sh.crypto.merkle import MerkleProof, MerkleTree
from bsfr_sh.util.serialization import (
    BLOCK_FIELD_ORDER,
    BlockPart,
    Value,
    encode_block,
)

__all__ = [
    "BLOCK_VERSION",
    "GENESIS_PREV_HASH",
    "NONCE_BYTES",
    "Block",
    "BlockDraft",
    "BlockError",
]

#: `βVer_j`. The paper gives no version scheme; 1 is ours, declared in `configs/chain.yaml`.
BLOCK_VERSION: Final = 1

#: `RN` width. Inert — see the module docstring.
NONCE_BYTES: Final = 16

#: `HP_βj-1` for the genesis block, which has no predecessor.
GENESIS_PREV_HASH: Final = bytes(32)


class BlockError(ValueError):
    """Raised when a block is malformed, inconsistent, or badly signed."""


# --------------------------------------------------------------------------------------------
# Draft
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class BlockDraft:
    """An unsealed block. Implements Alg. 1 line 3 / Alg. 2 line 8, up to the signature.

    Carries no `current_hash` and no `signature` — those come into existence only in `seal()`,
    which is why a draft cannot be internally inconsistent. `merkle_root` is derived, not stored,
    for the same reason.
    """

    owner_id: str
    owner_pubkey: bytes
    transactions: tuple[Transaction, ...]
    prev_hash: bytes
    timestamp: float
    version: int = BLOCK_VERSION
    nonce: bytes = field(default_factory=lambda: secrets.token_bytes(NONCE_BYTES))

    def __post_init__(self) -> None:
        if not self.owner_id:
            raise BlockError("owner_id must be non-empty")
        if len(self.prev_hash) != 32:
            raise BlockError(f"prev_hash must be 32 bytes, got {len(self.prev_hash)}")
        try:
            load_public_key(self.owner_pubkey)
        except SignatureError as exc:
            raise BlockError(f"owner_pubkey is not a valid secp256r1 point: {exc}") from exc
        if not isinstance(self.transactions, tuple):
            raise BlockError("transactions must be a tuple; a list is mutable and MTR is not")

    @cached_property
    def _tree(self) -> MerkleTree:
        return MerkleTree([tx.digest for tx in self.transactions])

    @cached_property
    def merkle_root(self) -> bytes:
        """`MTR` — over the transaction digests, count-bound (DEV-11)."""
        return self._tree.root

    @cached_property
    def current_hash(self) -> bytes:
        """`HC_βj` — over `BlockPart.HASH`, every header field but the hash and the signature."""
        return _header_hash(self._hashed_fields())

    def _hashed_fields(self) -> dict[str, Value]:
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "merkle_root": self.merkle_root,
            "owner_id": self.owner_id,
            "owner_pubkey": self.owner_pubkey,
            "transactions": [tx.encoded() for tx in self.transactions],
            "prev_hash": self.prev_hash,
        }

    def signing_preimage(self) -> bytes:
        """The bytes `Sig_βj` is taken over — `BlockPart.SIGN`. See the module docstring."""
        return encode_block(
            {**self._hashed_fields(), "current_hash": self.current_hash}, BlockPart.SIGN
        )

    def seal(self, private_key: PrivateKey) -> Block:
        """Sign the draft and produce the immutable `Block`. The only way a `Block` is made.

        The signing key must match `owner_pubkey`: signing a block that claims a different owner
        would produce a block that fails its own `__post_init__`, so it is caught here with a
        message that says what went wrong rather than there with one that does not.
        """
        if private_key.public_key.to_bytes() != self.owner_pubkey:
            raise BlockError(
                "signing key does not match owner_pubkey; a block must be signed by the owner "
                "it names (OID/OKU, docs/NOTATION.md)"
            )
        return Block(
            owner_id=self.owner_id,
            owner_pubkey=self.owner_pubkey,
            transactions=self.transactions,
            prev_hash=self.prev_hash,
            timestamp=self.timestamp,
            version=self.version,
            nonce=self.nonce,
            signature=sign(private_key, self.signing_preimage()),
        )


# --------------------------------------------------------------------------------------------
# Sealed block
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Block:
    """`β_j` — a sealed, signed block.

    Stores only what cannot be derived. `merkle_root` and `current_hash` are computed on access,
    so no `Block` can carry a digest that disagrees with its contents. The signature is verified
    at construction, so no `Block` can carry one that does not verify under its own
    `owner_pubkey`.

    Produced by `BlockDraft.seal()` or `Block.from_fields()`. Constructing one directly is
    possible in Python but pointless: the same checks run either way.
    """

    owner_id: str
    owner_pubkey: bytes
    transactions: tuple[Transaction, ...]
    prev_hash: bytes
    timestamp: float
    version: int
    nonce: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if len(self.prev_hash) != 32:
            raise BlockError(f"prev_hash must be 32 bytes, got {len(self.prev_hash)}")
        if not isinstance(self.transactions, tuple):
            raise BlockError("transactions must be a tuple")
        try:
            public = load_public_key(self.owner_pubkey)
        except SignatureError as exc:
            raise BlockError(f"owner_pubkey is not a valid secp256r1 point: {exc}") from exc
        if not verify(public, self.signature, self.signing_preimage()):
            raise BlockError(
                f"block signature does not verify under owner_pubkey for owner "
                f"{self.owner_id!r}; the block was altered, or signed by someone else"
            )

    # -- derived, never stored ---------------------------------------------------------------
    @cached_property
    def _tree(self) -> MerkleTree:
        return MerkleTree([tx.digest for tx in self.transactions])

    @cached_property
    def merkle_root(self) -> bytes:
        """`MTR`. Recomputed from the transactions, so it cannot disagree with them."""
        return self._tree.root

    @cached_property
    def current_hash(self) -> bytes:
        """`HC_βj`. Recomputed from the header, so it cannot disagree with it."""
        return _header_hash(self._hashed_fields())

    def _hashed_fields(self) -> dict[str, Value]:
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "merkle_root": self.merkle_root,
            "owner_id": self.owner_id,
            "owner_pubkey": self.owner_pubkey,
            "transactions": [tx.encoded() for tx in self.transactions],
            "prev_hash": self.prev_hash,
        }

    def signing_preimage(self) -> bytes:
        """The bytes `Sig_βj` covers — `BlockPart.SIGN`."""
        return encode_block(
            {**self._hashed_fields(), "current_hash": self.current_hash}, BlockPart.SIGN
        )

    def to_fields(self) -> dict[str, Value]:
        """All ten header fields, in `BLOCK_FIELD_ORDER`. The wire form."""
        return {
            **self._hashed_fields(),
            "current_hash": self.current_hash,
            "signature": self.signature,
        }

    def encoded(self) -> bytes:
        """Canonical encoding of the full block."""
        return encode_block(self.to_fields(), BlockPart.FULL)

    # -- inclusion ----------------------------------------------------------------------------
    def prove_transaction(self, index: int) -> MerkleProof:
        """Inclusion proof for the transaction at `index`, against this block's `MTR`."""
        return self._tree.prove(index)

    def owner_public_key(self) -> PublicKey:
        return load_public_key(self.owner_pubkey)

    @property
    def transaction_count(self) -> int:
        return len(self.transactions)

    @classmethod
    def from_fields(cls, fields: dict[str, Value]) -> Block:
        """Rebuild a block from wire fields, checking the claimed digests against recomputed ones.

        This is the boundary where a claimed `merkle_root` and `current_hash` are compared. Once
        past it, the values are derived and there is nothing left to disagree.
        """
        missing = [name for name in BLOCK_FIELD_ORDER if name not in fields]
        if missing:
            raise BlockError(f"block fields missing {missing}")
        raw_txs = fields["transactions"]
        if not isinstance(raw_txs, list):
            raise BlockError("transactions must be a list of encoded transactions")
        block = cls(
            owner_id=_as_str(fields["owner_id"], "owner_id"),
            owner_pubkey=_as_bytes(fields["owner_pubkey"], "owner_pubkey"),
            transactions=tuple(_decode_transaction(item) for item in raw_txs),
            prev_hash=_as_bytes(fields["prev_hash"], "prev_hash"),
            timestamp=_as_float(fields["timestamp"], "timestamp"),
            version=_as_int(fields["version"], "version"),
            nonce=_as_bytes(fields["nonce"], "nonce"),
            signature=_as_bytes(fields["signature"], "signature"),
        )
        claimed_root = _as_bytes(fields["merkle_root"], "merkle_root")
        if claimed_root != block.merkle_root:
            raise BlockError("claimed merkle_root does not match the block's transactions")
        claimed_hash = _as_bytes(fields["current_hash"], "current_hash")
        if claimed_hash != block.current_hash:
            raise BlockError("claimed current_hash does not match the block's header")
        return block

    def __repr__(self) -> str:
        return (
            f"Block(owner={self.owner_id!r}, txs={len(self.transactions)}, "
            f"hash={self.current_hash[:6].hex()}..., prev={self.prev_hash[:6].hex()}...)"
        )


def _header_hash(hashed_fields: dict[str, Value]) -> bytes:
    return tagged_h(DOMAIN_BLOCK_HEADER, encode_block(hashed_fields, BlockPart.HASH))


def new_nonce() -> bytes:
    """A fresh `RN`. Random, inert, never examined — see the module docstring."""
    return os.urandom(NONCE_BYTES)


# The header the paper declares, the encoding M0 pinned, and these two types must agree forever.
# Checked at import, because a mismatch would not fail loudly — it would produce blocks whose
# hashes are simply different from every other run's.
_DERIVED_FIELDS: Final = ("merkle_root", "current_hash")
assert set(BLOCK_FIELD_ORDER) == set(Block.__dataclass_fields__) | set(_DERIVED_FIELDS), (
    "Block stored+derived fields have drifted from util.serialization.BLOCK_FIELD_ORDER"
)
assert set(BlockDraft.__dataclass_fields__) | set(_DERIVED_FIELDS) == (
    set(BLOCK_FIELD_ORDER) - {"signature"}
), "BlockDraft fields have drifted from BLOCK_FIELD_ORDER minus the signature"


# --------------------------------------------------------------------------------------------
# Field decoding
# --------------------------------------------------------------------------------------------
def _decode_transaction(item: Value) -> Transaction:
    from bsfr_sh.util.serialization import CanonicalEncodingError, Struct, decode

    if not isinstance(item, bytes):
        raise BlockError("each transaction must be a canonical encoding")
    try:
        decoded = decode(item)
    except CanonicalEncodingError as exc:
        raise BlockError(f"transaction is not a canonical encoding: {exc}") from exc
    if not isinstance(decoded, Struct):
        raise BlockError("transaction encoding is not a struct")
    fields = decoded.fields
    return Transaction(
        tx_id=_as_str(fields["tx_id"], "tx_id"),
        payload_type=_as_str(fields["payload_type"], "payload_type"),
        ciphertext=_as_bytes(fields["ciphertext"], "ciphertext"),
        wrapped_key=_as_bytes(fields["wrapped_key"], "wrapped_key"),
        nonce=_as_bytes(fields["nonce"], "nonce"),
        digest=_as_bytes(fields["digest"], "digest"),
        created_at=_as_int(fields["created_at"], "created_at"),
    )


def _as_str(value: Value, name: str) -> str:
    if not isinstance(value, str):
        raise BlockError(f"block field {name!r} is not a string")
    return value


def _as_bytes(value: Value, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise BlockError(f"block field {name!r} is not bytes")
    return value


def _as_int(value: Value, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BlockError(f"block field {name!r} is not an integer")
    return value


def _as_float(value: Value, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise BlockError(f"block field {name!r} is not a number")
    return float(value)
