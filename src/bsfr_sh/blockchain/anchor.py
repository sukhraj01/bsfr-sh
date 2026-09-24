"""`AnchorRecord` — the public-chain tamper-evidence primitive. M7-5, DEV-33.

The paper's own §VIII: "in future, we have plan to work with hybrid blockchain," and stops there.
§IV-A already states the trade-off a hybrid design answers: a private chain is fast and
confidential, but its integrity rests entirely on trusting the operators who run it; a public
chain is externally verifiable, but exposes whatever it carries to everyone. A hybrid chain keeps
the paper's own private chains exactly as they are — same speed, same confidentiality — and adds
one more thing external to them: a small, public commitment that lets someone holding no key for
either private chain confirm it has not been silently rewritten.

This module defines that commitment. `blockchain.hybrid.HybridChain` is what schedules and
commits it; this module only defines what one entry *is* and how it is signed and verified.

Why an `AnchorRecord` is never encrypted
-----------------------------------------
Every other payload in this codebase is `E_KU_CSl(Tx)` (Alg. 1 line 2 / Alg. 2 line 7) — sealed so
only one cloud server can read it. An anchor record inverts that: its only job is to be readable
by anyone, so an external verifier never needs a private-chain key to check one. `block_hash` and
`merkle_root` are copied verbatim from the private block's own header (`docs/NOTATION.md`
`HC_βj`/`MTR`) — never derived from, or requiring decryption of, that block's transactions. See
`blockchain.transaction.wrap_anchor_record` for how this record travels as a transaction without
being sealed to a recipient.

What verification does and does not prove
-------------------------------------------
Given an `AnchorRecord` and a candidate block claiming to be the one it anchors, anyone can check
`block.current_hash == record.block_hash` and `block.merkle_root == record.merkle_root` without
decrypting a single transaction inside that block. That is the whole guarantee: the *shape* of the
private chain at that height is fixed the moment the anchor commits, even to an operator who
controls every private-chain replica. It is not a claim about the private chain's *contents* being
correct — only that they cannot be changed after the fact without the change being visible to
anyone holding the anchor. `HybridChain`'s security tests (`tests/unit/test_hybrid_chain.py`) draw
this line precisely: an anchored block's tamper is caught, an unanchored one's is not, and the
anchor chain's own integrity is a separate, stated assumption (see that module's docstring).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from bsfr_sh.blockchain.block import Block
from bsfr_sh.crypto.ecdsa import (
    PrivateKey,
    PublicKey,
    SignatureError,
    load_public_key,
    sign,
    verify,
)
from bsfr_sh.crypto.hashing import DOMAIN_ANCHOR_RECORD
from bsfr_sh.util.serialization import (
    CanonicalEncodingError,
    Struct,
    Value,
    decode,
    encode_struct,
)

__all__ = [
    "ANCHOR_FIELD_ORDER",
    "AnchorRecord",
    "AnchorRecordError",
    "create_anchor_record",
]

#: Every field but the signature itself — the pre-image the creator signs over (mirrors
#: `blockchain.block`'s `BLOCK_HASHED_FIELDS`/`BLOCK_SIGNED_FIELDS` split, minus the derived-hash
#: half: an `AnchorRecord` has no field computed from its own other fields, so there is only one
#: split here, not two).
ANCHOR_FIELD_ORDER: Final[tuple[str, ...]] = (
    "anchored_chain",
    "block_height",
    "block_hash",
    "merkle_root",
    "timestamp",
    "creator_id",
    "creator_pubkey",
)

#: The wire form (this domain, not `DOMAIN_ANCHOR_RECORD`) includes the signature. Kept distinct so
#: a wire encoding can never be replayed as something that verifies as a signing pre-image.
_WIRE_DOMAIN: Final = "bsfr_sh.anchor.record.v1.wire"
_WIRE_FIELD_ORDER: Final[tuple[str, ...]] = (*ANCHOR_FIELD_ORDER, "signature")


class AnchorRecordError(ValueError):
    """Raised when an anchor record is malformed or badly signed."""


def _preimage(fields: Mapping[str, Value]) -> bytes:
    return encode_struct(DOMAIN_ANCHOR_RECORD, ANCHOR_FIELD_ORDER, fields)


@dataclass(frozen=True)
class AnchorRecord:
    """One committed entry on the anchor chain: one private block, attested by its own creator.

    Frozen and signature-verified at construction — the same shape `blockchain.block.Block` uses
    and for the same reason (module docstring there): an `AnchorRecord` that failed its own
    signature check should not be constructible at all, not merely "checked and found invalid"
    somewhere downstream.
    """

    #: Which private chain this anchors — `blockchain.chain.BC_DTBU` or `BC_SigRW`.
    anchored_chain: str
    #: The private chain's height this record covers.
    block_height: int
    #: `HC_βj` — the private block's own header hash, copied verbatim.
    block_hash: bytes
    #: `MTR` — the private block's own Merkle root, copied verbatim.
    merkle_root: bytes
    #: When this anchor was created, on the anchor chain's own simulated clock.
    timestamp: float
    #: The anchor creator's id (an operator-controlled cloud server, same trust model as `CS_l`).
    creator_id: str
    creator_pubkey: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if not self.anchored_chain:
            raise AnchorRecordError("anchored_chain must be non-empty")
        if self.block_height < 0:
            raise AnchorRecordError(f"block_height must be non-negative, got {self.block_height}")
        if len(self.block_hash) != 32:
            raise AnchorRecordError(f"block_hash must be 32 bytes, got {len(self.block_hash)}")
        if len(self.merkle_root) != 32:
            raise AnchorRecordError(f"merkle_root must be 32 bytes, got {len(self.merkle_root)}")
        if not self.creator_id:
            raise AnchorRecordError("creator_id must be non-empty")
        try:
            public = load_public_key(self.creator_pubkey)
        except SignatureError as exc:
            raise AnchorRecordError(
                f"creator_pubkey is not a valid secp256r1 point: {exc}"
            ) from exc
        if not verify(public, self.signature, self.signing_preimage()):
            raise AnchorRecordError(
                f"anchor record signature does not verify under creator_pubkey for creator "
                f"{self.creator_id!r}; the record was altered, or signed by someone else"
            )

    def _fields(self) -> dict[str, Value]:
        return {
            "anchored_chain": self.anchored_chain,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "creator_id": self.creator_id,
            "creator_pubkey": self.creator_pubkey,
        }

    def signing_preimage(self) -> bytes:
        """The bytes `signature` covers — every field except the signature itself."""
        return _preimage(self._fields())

    def matches(self, block: Block, *, height: int) -> bool:
        """Whether `block`, claimed to sit at `height`, is the one this record anchors.

        No decryption anywhere in this check — `current_hash`/`merkle_root` are the private
        block's own header fields, exactly what an external verifier is given.
        """
        return (
            height == self.block_height
            and block.current_hash == self.block_hash
            and block.merkle_root == self.merkle_root
        )

    def creator_public_key(self) -> PublicKey:
        return load_public_key(self.creator_pubkey)

    def to_bytes(self) -> bytes:
        """Canonical wire encoding, signature included.

        This is what `blockchain.hybrid.HybridChain` hands to
        `blockchain.transaction.wrap_anchor_record` as the anchor-chain transaction's plaintext.
        """
        return encode_struct(
            _WIRE_DOMAIN, _WIRE_FIELD_ORDER, {**self._fields(), "signature": self.signature}
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> AnchorRecord:
        """Rebuild a record from wire bytes, re-verifying its signature (`__post_init__`)."""
        try:
            decoded = decode(raw)
        except CanonicalEncodingError as exc:
            raise AnchorRecordError(f"anchor record is not a canonical encoding: {exc}") from exc
        if not isinstance(decoded, Struct) or decoded.domain != _WIRE_DOMAIN:
            raise AnchorRecordError("anchor record encoding is not a wire-form anchor struct")
        fields = decoded.fields
        missing = [name for name in _WIRE_FIELD_ORDER if name not in fields]
        if missing:
            raise AnchorRecordError(f"anchor record fields missing {missing}")
        return cls(
            anchored_chain=_as_str(fields["anchored_chain"], "anchored_chain"),
            block_height=_as_int(fields["block_height"], "block_height"),
            block_hash=_as_bytes(fields["block_hash"], "block_hash"),
            merkle_root=_as_bytes(fields["merkle_root"], "merkle_root"),
            timestamp=_as_float(fields["timestamp"], "timestamp"),
            creator_id=_as_str(fields["creator_id"], "creator_id"),
            creator_pubkey=_as_bytes(fields["creator_pubkey"], "creator_pubkey"),
            signature=_as_bytes(fields["signature"], "signature"),
        )

    def __repr__(self) -> str:
        return (
            f"AnchorRecord(chain={self.anchored_chain!r}, height={self.block_height}, "
            f"hash={self.block_hash[:6].hex()}...)"
        )


def create_anchor_record(
    *,
    anchored_chain: str,
    block_height: int,
    block: Block,
    timestamp: float,
    creator_id: str,
    private_key: PrivateKey,
) -> AnchorRecord:
    """Build and sign an `AnchorRecord` over one private-chain block at `block_height`.

    `block_height` is a parameter rather than read off `block` because a `Block` does not know
    its own chain position — only the `Chain` it was read from does (`blockchain.chain.Chain`
    stores height as list position, not as a header field). The caller (`blockchain.hybrid`) reads
    both from the same `Chain.block_at(height)` call, so they cannot disagree in practice.
    """
    fields: dict[str, Value] = {
        "anchored_chain": anchored_chain,
        "block_height": block_height,
        "block_hash": block.current_hash,
        "merkle_root": block.merkle_root,
        "timestamp": timestamp,
        "creator_id": creator_id,
        "creator_pubkey": private_key.public_key.to_bytes(),
    }
    signature = sign(private_key, _preimage(fields))
    return AnchorRecord(
        anchored_chain=anchored_chain,
        block_height=block_height,
        block_hash=block.current_hash,
        merkle_root=block.merkle_root,
        timestamp=timestamp,
        creator_id=creator_id,
        creator_pubkey=private_key.public_key.to_bytes(),
        signature=signature,
    )


def _as_str(value: Value, name: str) -> str:
    if not isinstance(value, str):
        raise AnchorRecordError(f"anchor record field {name!r} is not a string")
    return value


def _as_bytes(value: Value, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise AnchorRecordError(f"anchor record field {name!r} is not bytes")
    return value


def _as_int(value: Value, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AnchorRecordError(f"anchor record field {name!r} is not an integer")
    return value


def _as_float(value: Value, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise AnchorRecordError(f"anchor record field {name!r} is not a number")
    return float(value)
