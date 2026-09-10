"""Canonical deterministic byte encoding.

This module defines *the* byte encoding used everywhere a structure has to be hashed, signed, or
compared. It is deliberately the first thing built in this repo: if two modules encode the same
block differently, their hashes diverge, pBFT stops committing, and the symptom looks like a
consensus bug rather than an encoding bug.

Guarantees
----------
1. **Deterministic across runs, processes and Python versions.** No `hash()`, no `repr()`, no
   `pickle`, no dict iteration order, no locale- or platform-dependent formatting.
2. **Unambiguous.** Every value is tag-prefixed and every variable-length value is
   length-prefixed, so no two distinct values share an encoding and no field boundary has to be
   inferred. `decode()` is an exact inverse and rejects any non-canonical input.
3. **Order-independent for mappings, order-*fixed* for structures.** Mapping entries are sorted
   by encoded key, so two dicts built in different insertion orders encode identically. Protocol
   structures use a declared field order instead (see `BLOCK_FIELD_ORDER`), because the paper
   fixes that order and it is part of the block definition.

Wire format
-----------
Every value is ``tag || body``. Lengths and counts are minimal LEB128 unsigned varints.

===== ============ ==========================================================================
Tag   Type         Body
===== ============ ==========================================================================
0x00  null         empty
0x01  false        empty
0x02  true         empty
0x03  int          uvarint(len) || canonical decimal ASCII, arbitrary precision, "-" for sign
0x04  float        8 bytes, IEEE-754 binary64, big-endian; NaN/Inf rejected, -0.0 normalised
0x05  bytes        uvarint(len) || raw bytes
0x06  str          uvarint(len) || UTF-8 of the NFC-normalised string
0x07  list         uvarint(count) || encoded items in order
0x08  map          uvarint(count) || (encoded key || encoded value)*, sorted by encoded key
0x09  struct       encoded domain str || uvarint(count) || (encoded name || encoded value)*
===== ============ ==========================================================================

Integers are decimal ASCII rather than fixed-width so that arbitrary precision is representable
and no width has to be agreed in advance; the canonical form has no leading zeros and no "-0".

Scope
-----
This module encodes. It does not hash and does not sign — those are `crypto.hashing` (M1) and
`crypto.ecdsa` (M1), which consume the bytes produced here. Keeping the dependency in that
direction is what lets `crypto` depend on `util` and never the reverse.
"""

from __future__ import annotations

import math
import struct
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, TypeAlias

__all__ = [
    "BLOCK_FIELD_ORDER",
    "BLOCK_HASHED_FIELDS",
    "BLOCK_SIGNED_FIELDS",
    "DOMAIN_CONFIG",
    "DOMAIN_TRANSACTION",
    "TRANSACTION_FIELD_ORDER",
    "BlockPart",
    "CanonicalEncodingError",
    "Struct",
    "Value",
    "decode",
    "encode",
    "encode_block",
    "encode_struct",
    "encode_transaction",
]


class CanonicalEncodingError(ValueError):
    """Raised when a value cannot be encoded canonically, or a decode input is not canonical."""


@dataclass(frozen=True)
class Struct:
    """A domain-separated, order-fixed record.

    `domain` is mixed into the encoding so that a block encoding can never collide with a
    transaction encoding that happens to carry the same field values.
    """

    domain: str
    fields: Mapping[str, Value]


Value: TypeAlias = (
    "bool | int | float | str | bytes | bytearray "
    "| Sequence[Value] | Mapping[Any, Value] | Struct | None"
)

# --------------------------------------------------------------------------------------------
# Tags
# --------------------------------------------------------------------------------------------
_TAG_NULL: Final = 0x00
_TAG_FALSE: Final = 0x01
_TAG_TRUE: Final = 0x02
_TAG_INT: Final = 0x03
_TAG_FLOAT: Final = 0x04
_TAG_BYTES: Final = 0x05
_TAG_STR: Final = 0x06
_TAG_LIST: Final = 0x07
_TAG_MAP: Final = 0x08
_TAG_STRUCT: Final = 0x09

#: Bumped only if the wire format changes. A bump invalidates every stored hash, which is the
#: point: a silent format change that leaves old hashes looking valid is the failure mode.
ENCODING_VERSION: Final = 1

# --------------------------------------------------------------------------------------------
# Protocol field orders
# --------------------------------------------------------------------------------------------
# Block header order is fixed by the paper (Alg. 1 line 3 / Alg. 2 line 8) and mirrored in
# docs/ARCHITECTURE.md §blockchain. It is declared here, not in `blockchain.block`, so that the
# encoder and the Block dataclass cannot drift apart: M2's Block asserts against these names.
BLOCK_FIELD_ORDER: Final[tuple[str, ...]] = (
    "version",
    "timestamp",
    "nonce",
    "merkle_root",
    "owner_id",
    "owner_pubkey",
    "transactions",
    "prev_hash",
    "current_hash",
    "signature",
)

#: Pre-image of `current_hash`: every header field except the hash itself and the signature.
BLOCK_HASHED_FIELDS: Final[tuple[str, ...]] = BLOCK_FIELD_ORDER[:-2]

#: Pre-image of `signature`: the hashed fields plus the `current_hash` they produce.
BLOCK_SIGNED_FIELDS: Final[tuple[str, ...]] = BLOCK_FIELD_ORDER[:-1]

#: Transaction field order, per docs/ARCHITECTURE.md §blockchain.
TRANSACTION_FIELD_ORDER: Final[tuple[str, ...]] = (
    "tx_id",
    "payload_type",
    "ciphertext",
    "wrapped_key",
    "nonce",
    "digest",
    "created_at",
)

DOMAIN_TRANSACTION: Final = "bsfr_sh.transaction.v1"
DOMAIN_CONFIG: Final = "bsfr_sh.config.v1"


class BlockPart(Enum):
    """Which slice of a block is being encoded, and under which domain.

    Using the wrong slice is the classic self-referential-hash bug (hashing a block including the
    hash field you are about to write). Naming the three legitimate slices makes that bug hard to
    write and obvious to review.
    """

    FULL = ("bsfr_sh.block.v1.full", BLOCK_FIELD_ORDER)
    HASH = ("bsfr_sh.block.v1.hash", BLOCK_HASHED_FIELDS)
    SIGN = ("bsfr_sh.block.v1.sign", BLOCK_SIGNED_FIELDS)

    def __init__(self, domain: str, field_order: tuple[str, ...]) -> None:
        self.domain = domain
        self.field_order = field_order


# --------------------------------------------------------------------------------------------
# Varints
# --------------------------------------------------------------------------------------------
def _uvarint(n: int) -> bytes:
    """Minimal LEB128 encoding of a non-negative integer."""
    if n < 0:
        raise CanonicalEncodingError(f"length/count must be non-negative, got {n}")
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _read_uvarint(data: bytes, pos: int) -> tuple[int, int]:
    """Read a minimal LEB128 varint at `pos`; return (value, new_pos)."""
    result = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(data):
            raise CanonicalEncodingError("truncated varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
        if shift > 63:
            raise CanonicalEncodingError("varint too long")
    # Reject non-minimal encodings: a canonical encoder never emits a redundant continuation.
    if _uvarint(result) != data[start:pos]:
        raise CanonicalEncodingError("non-minimal varint encoding")
    return result, pos


# --------------------------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------------------------
def encode(value: Value) -> bytes:
    """Encode `value` to its canonical byte string.

    Rejects anything whose encoding could vary between runs: sets and frozensets (iteration
    order), NaN and infinities (no canonical bit pattern / no meaningful comparison), and any
    type not in the table above (datetimes, Decimals, numpy scalars — convert explicitly at the
    call site so the conversion is visible in review).
    """
    out = bytearray()
    _encode_into(value, out)
    return bytes(out)


def _encode_into(value: Value, out: bytearray) -> None:
    # bool before int: bool is a subclass of int and must not encode as one.
    if value is None:
        out.append(_TAG_NULL)
    elif value is True:
        out.append(_TAG_TRUE)
    elif value is False:
        out.append(_TAG_FALSE)
    elif isinstance(value, int):
        body = _int_body(value)
        out.append(_TAG_INT)
        out += _uvarint(len(body))
        out += body
    elif isinstance(value, float):
        out.append(_TAG_FLOAT)
        out += _float_body(value)
    elif isinstance(value, str):
        body = unicodedata.normalize("NFC", value).encode("utf-8")
        out.append(_TAG_STR)
        out += _uvarint(len(body))
        out += body
    elif isinstance(value, bytes | bytearray):
        out.append(_TAG_BYTES)
        out += _uvarint(len(value))
        out += bytes(value)
    elif isinstance(value, Struct):
        _encode_struct_into(value.domain, tuple(value.fields.keys()), value.fields, out)
    elif isinstance(value, Mapping):
        _encode_mapping_into(value, out)
    elif isinstance(value, set | frozenset):
        raise CanonicalEncodingError(
            "sets have no defined iteration order; encode a sorted list instead"
        )
    elif isinstance(value, Sequence | Iterable):
        items = list(value)
        out.append(_TAG_LIST)
        out += _uvarint(len(items))
        for item in items:
            _encode_into(item, out)
    else:
        raise CanonicalEncodingError(
            f"no canonical encoding for {type(value).__name__}; convert explicitly at the call site"
        )


def _int_body(value: int) -> bytes:
    # Decimal ASCII: arbitrary precision, no width negotiation, and Python's str(int) is
    # specified (no leading zeros, "-" only for negatives, no "-0"), so it is canonical.
    return str(value).encode("ascii")


def _float_body(value: float) -> bytes:
    if math.isnan(value) or math.isinf(value):
        raise CanonicalEncodingError(
            f"{value!r} has no canonical encoding; NaN and infinities are rejected"
        )
    if value == 0.0:
        value = 0.0  # normalise -0.0, which is == 0.0 but has a different bit pattern
    return struct.pack(">d", value)


def _encode_mapping_into(mapping: Mapping[Any, Value], out: bytearray) -> None:
    # Sort by *encoded key bytes*, not by the keys themselves: that is well defined for mixed
    # key types and is independent of insertion order, locale, and any __lt__ implementation.
    encoded: list[tuple[bytes, bytes]] = []
    for key, val in mapping.items():
        encoded.append((encode(key), encode(val)))
    encoded.sort(key=lambda pair: pair[0])
    for i in range(1, len(encoded)):
        if encoded[i][0] == encoded[i - 1][0]:
            raise CanonicalEncodingError("duplicate key in mapping after canonical encoding")
    out.append(_TAG_MAP)
    out += _uvarint(len(encoded))
    for key_bytes, val_bytes in encoded:
        out += key_bytes
        out += val_bytes


def _encode_struct_into(
    domain: str,
    field_order: Sequence[str],
    fields: Mapping[str, Value],
    out: bytearray,
) -> None:
    missing = [name for name in field_order if name not in fields]
    extra = [name for name in fields if name not in field_order]
    if missing or extra:
        raise CanonicalEncodingError(
            f"struct {domain!r} field mismatch: missing={missing}, unexpected={extra}"
        )
    out.append(_TAG_STRUCT)
    _encode_into(domain, out)
    out += _uvarint(len(field_order))
    for name in field_order:
        _encode_into(name, out)
        _encode_into(fields[name], out)


def encode_struct(domain: str, field_order: Sequence[str], fields: Mapping[str, Value]) -> bytes:
    """Encode a record in a *declared* field order under a domain separator.

    Unlike a mapping, the field order here is not sorted — it is the protocol's own order. The
    key set must match `field_order` exactly; a missing or unexpected field is an error rather
    than a silently shorter pre-image.
    """
    out = bytearray()
    _encode_struct_into(domain, field_order, fields, out)
    return bytes(out)


def encode_block(fields: Mapping[str, Value], part: BlockPart = BlockPart.FULL) -> bytes:
    """Encode a block, or the pre-image of its hash or signature.

    `fields` is a plain mapping, not a `Block` — this module must not depend on `blockchain`
    (see the dependency direction in docs/ARCHITECTURE.md). Only the names in
    `part.field_order` may be supplied.
    """
    return encode_struct(part.domain, part.field_order, fields)


def encode_transaction(fields: Mapping[str, Value]) -> bytes:
    """Encode a transaction in the field order declared by docs/ARCHITECTURE.md."""
    return encode_struct(DOMAIN_TRANSACTION, TRANSACTION_FIELD_ORDER, fields)


# --------------------------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------------------------
def decode(data: bytes) -> Value:
    """Decode a canonical encoding, rejecting anything an encoder here would not have produced.

    Round-trip caveats, both deliberate: a tuple decodes to a list, and a `bytearray` decodes to
    `bytes`. Everything else round-trips to an equal value.
    """
    value, pos = _decode_at(data, 0)
    if pos != len(data):
        raise CanonicalEncodingError(f"{len(data) - pos} trailing byte(s) after value")
    return value


def _decode_at(data: bytes, pos: int) -> tuple[Value, int]:
    if pos >= len(data):
        raise CanonicalEncodingError("truncated input: expected a tag")
    tag = data[pos]
    pos += 1
    if tag == _TAG_NULL:
        return None, pos
    if tag == _TAG_TRUE:
        return True, pos
    if tag == _TAG_FALSE:
        return False, pos
    if tag == _TAG_INT:
        length, pos = _read_uvarint(data, pos)
        body = _take(data, pos, length)
        text = body.decode("ascii")
        value = int(text)
        if str(value) != text:
            raise CanonicalEncodingError(f"non-canonical integer literal {text!r}")
        return value, pos + length
    if tag == _TAG_FLOAT:
        body = _take(data, pos, 8)
        (number,) = struct.unpack(">d", body)
        if math.isnan(number) or math.isinf(number):
            raise CanonicalEncodingError("NaN/Inf is not a canonical float encoding")
        if body == struct.pack(">d", -0.0):
            raise CanonicalEncodingError("negative zero is not a canonical float encoding")
        return number, pos + 8
    if tag == _TAG_BYTES:
        length, pos = _read_uvarint(data, pos)
        return _take(data, pos, length), pos + length
    if tag == _TAG_STR:
        length, pos = _read_uvarint(data, pos)
        body = _take(data, pos, length)
        text = body.decode("utf-8")
        if unicodedata.normalize("NFC", text) != text:
            raise CanonicalEncodingError("string is not NFC-normalised")
        return text, pos + length
    if tag == _TAG_LIST:
        count, pos = _read_uvarint(data, pos)
        items: list[Value] = []
        for _ in range(count):
            item, pos = _decode_at(data, pos)
            items.append(item)
        return items, pos
    if tag == _TAG_MAP:
        count, pos = _read_uvarint(data, pos)
        mapping: dict[Any, Value] = {}
        previous: bytes | None = None
        for _ in range(count):
            key_start = pos
            key, pos = _decode_at(data, pos)
            key_bytes = data[key_start:pos]
            if previous is not None and key_bytes <= previous:
                raise CanonicalEncodingError("map keys are not in canonical sorted order")
            previous = key_bytes
            mapping[key], pos = _decode_at(data, pos)
        return mapping, pos
    if tag == _TAG_STRUCT:
        domain, pos = _decode_at(data, pos)
        if not isinstance(domain, str):
            raise CanonicalEncodingError("struct domain must be a string")
        count, pos = _read_uvarint(data, pos)
        fields: dict[str, Value] = {}
        for _ in range(count):
            name, pos = _decode_at(data, pos)
            if not isinstance(name, str):
                raise CanonicalEncodingError("struct field name must be a string")
            if name in fields:
                raise CanonicalEncodingError(f"duplicate struct field {name!r}")
            fields[name], pos = _decode_at(data, pos)
        return Struct(domain=domain, fields=fields), pos
    raise CanonicalEncodingError(f"unknown tag 0x{tag:02x} at offset {pos - 1}")


def _take(data: bytes, pos: int, length: int) -> bytes:
    end = pos + length
    if end > len(data):
        raise CanonicalEncodingError(f"truncated input: wanted {length} byte(s) at {pos}")
    return data[pos:end]
