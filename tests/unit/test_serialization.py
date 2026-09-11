"""Canonical encoding: round-trip, determinism, and rejection of non-canonical input.

These tests are written now rather than in M1 on purpose. Every block hash, Merkle leaf and
signature pre-image in this project is a function of `util.serialization`, so an encoding that
drifts does not fail here — it fails as a pBFT node that will not commit, three milestones later.
"""

from __future__ import annotations

import datetime as dt
import subprocess
import sys

import pytest

from bsfr_sh.util.serialization import (
    BLOCK_FIELD_ORDER,
    BLOCK_HASHED_FIELDS,
    BLOCK_SIGNED_FIELDS,
    DOMAIN_TRANSACTION,
    TRANSACTION_FIELD_ORDER,
    BlockPart,
    CanonicalEncodingError,
    Struct,
    decode,
    encode,
    encode_block,
    encode_struct,
    encode_transaction,
)

# A block whose fields are the right *shapes* for M2 without being a real block: bytes for
# digests and keys, int for counters, str for identifiers.
BLOCK = {
    "version": 1,
    "timestamp": 1757462400,
    "nonce": 42,
    "merkle_root": b"\x11" * 32,
    "owner_id": "CS_1",
    "owner_pubkey": b"\x02" + b"\xab" * 32,
    "transactions": [b"\xaa" * 32, b"\xbb" * 32],
    "prev_hash": b"\x00" * 32,
    "current_hash": b"\xcc" * 32,
    "signature": b"\xdd" * 64,
}

#: Pinned pre-image of the block above, hashed-fields slice. See the golden-vector test below.
GOLDEN_BLOCK_HASH_PREIMAGE = (
    "090615627366725f73682e626c6f636b2e76312e6861736808060776657273696f6e030131060974696d"
    "657374616d70030a3137353734363234303006056e6f6e636503023432060b6d65726b6c655f726f6f74"
    "0520111111111111111111111111111111111111111111111111111111111111111106086f776e65725f"
    "6964060443535f31060c6f776e65725f7075626b6579052102ababababababababababababababababab"
    "ababababababababababababababab060c7472616e73616374696f6e7307020520aaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0520bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0609707265765f6861736805200000000000000000000000000000"
    "000000000000000000000000000000000000"
)


# ---------------------------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        1,
        -1,
        2**64,
        -(2**128),
        0.0,
        1.5,
        -2.25,
        1e308,
        5e-324,
        "",
        "CS_1",
        "smart-healthcare / é中文",
        b"",
        b"\x00\xff",
        b"\x00" * 300,
        [],
        [1, "two", b"three", None, True, [4, [5]]],
        {},
        {"b": 1, "a": 2},
        {"nested": {"deep": [{"x": 1}]}},
        {1: "int key", "1": "str key"},
        {True: "bool key", "True": "str key"},
        [{"a": [1, 2]}, {"b": {"c": None}}],
    ],
)
def test_round_trip(value: object) -> None:
    assert decode(encode(value)) == value


def test_round_trip_of_a_block_sized_structure() -> None:
    block = dict(BLOCK)
    block["transactions"] = [bytes([i % 256]) * 32 for i in range(100)]
    decoded = decode(encode_block(block))
    assert isinstance(decoded, Struct)
    assert decoded.domain == BlockPart.FULL.domain
    assert dict(decoded.fields) == block
    assert list(decoded.fields) == list(BLOCK_FIELD_ORDER)


def test_tuple_decodes_to_list_and_bytearray_to_bytes() -> None:
    # Documented, deliberate asymmetry: the encoding has one sequence type and one byte type.
    assert decode(encode((1, 2, 3))) == [1, 2, 3]
    assert decode(encode(bytearray(b"ab"))) == b"ab"
    assert encode((1, 2, 3)) == encode([1, 2, 3])
    assert encode(bytearray(b"ab")) == encode(b"ab")


def test_struct_round_trips() -> None:
    struct = Struct(domain="test.v1", fields={"a": 1, "b": [2, 3]})
    decoded = decode(encode(struct))
    assert decoded == struct


# ---------------------------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------------------------
def test_mapping_encoding_is_independent_of_insertion_order() -> None:
    forwards = {"alpha": 1, "beta": 2, "gamma": 3}
    backwards = {"gamma": 3, "beta": 2, "alpha": 1}
    assert list(forwards) != list(backwards)  # the dicts really do differ in order
    assert encode(forwards) == encode(backwards)


def test_nested_mapping_order_does_not_leak_into_the_encoding() -> None:
    a = {"outer": {"z": [{"q": 1, "p": 2}], "a": 3}}
    b = {"outer": {"a": 3, "z": [{"p": 2, "q": 1}]}}
    assert encode(a) == encode(b)


def test_encoding_is_stable_across_processes_with_different_hash_seeds() -> None:
    """The strongest available check that no `hash()` randomisation leaks into the bytes.

    `PYTHONHASHSEED` is fixed at interpreter start-up, so this has to be a subprocess: an
    in-process test cannot vary it (see `util.seeding`).
    """
    script = (
        "from bsfr_sh.util.serialization import encode;"
        "print(encode({'b':1,'a':[{'z':0,'y':{'k':'v'}}],'c':(1,2)}).hex())"
    )
    digests = set()
    for hash_seed in ("0", "1", "12345"):
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
            env={"PYTHONHASHSEED": hash_seed, "PATH": "/usr/bin:/bin"},
        )
        digests.add(proc.stdout.strip())
    assert len(digests) == 1, f"encoding varied with PYTHONHASHSEED: {digests}"


def test_pinned_golden_vector() -> None:
    """Pins the wire format itself.

    If this fails and the change was intentional, bump `ENCODING_VERSION` and understand that
    every previously computed hash is now unreproducible — which is exactly the conversation this
    test exists to force.
    """
    value = {"a": 1, "b": [True, None, b"\x01", "x"], "c": -3}
    assert encode(value).hex() == "08030601610301310601620704020005010106017806016303022d33"


def test_pinned_golden_block_hash_preimage() -> None:
    preimage = {name: BLOCK[name] for name in BLOCK_HASHED_FIELDS}
    assert encode_block(preimage, BlockPart.HASH).hex() == GOLDEN_BLOCK_HASH_PREIMAGE


# ---------------------------------------------------------------------------------------------
# Ambiguity: distinct values never share an encoding
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("left", "right"),
    [
        (1, True),
        (0, False),
        (1, 1.0),
        (1, "1"),
        ("1", b"1"),
        (None, False),
        ([1, 2], [[1], 2]),
        ({"a": 1}, [["a", 1]]),
        (b"ab", ["a", "b"]),
        # Length prefixing: concatenation ambiguity would make these collide.
        (["ab", "c"], ["a", "bc"]),
        ([b"", b"x"], [b"x", b""]),
    ],
)
def test_distinct_values_have_distinct_encodings(left: object, right: object) -> None:
    assert encode(left) != encode(right)


def test_negative_zero_is_normalised() -> None:
    assert encode(-0.0) == encode(0.0)
    assert decode(encode(-0.0)) == 0.0


# ---------------------------------------------------------------------------------------------
# Rejection of values with no canonical form
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    [
        {1, 2, 3},
        frozenset({1}),
        float("nan"),
        float("inf"),
        float("-inf"),
        dt.datetime(2026, 9, 10, tzinfo=dt.UTC),
        dt.date(2026, 9, 10),
        complex(1, 2),
        object(),
    ],
)
def test_unencodable_values_are_rejected(value: object) -> None:
    with pytest.raises(CanonicalEncodingError):
        encode(value)


def test_set_rejection_says_what_to_do_instead() -> None:
    with pytest.raises(CanonicalEncodingError, match="sorted list"):
        encode({1, 2})


# ---------------------------------------------------------------------------------------------
# Decoding rejects anything this encoder would not have produced
# ---------------------------------------------------------------------------------------------
def test_trailing_bytes_are_rejected() -> None:
    with pytest.raises(CanonicalEncodingError, match="trailing"):
        decode(encode(1) + b"\x00")


def test_truncated_input_is_rejected() -> None:
    blob = encode("hello")
    with pytest.raises(CanonicalEncodingError):
        decode(blob[:-1])
    with pytest.raises(CanonicalEncodingError):
        decode(b"")


def test_unknown_tag_is_rejected() -> None:
    with pytest.raises(CanonicalEncodingError, match="unknown tag"):
        decode(b"\x7f")


def test_non_minimal_varint_is_rejected() -> None:
    # b"" encoded canonically is tag 0x05 || uvarint(0); 0x80 0x00 is a redundant two-byte zero.
    assert encode(b"") == b"\x05\x00"
    with pytest.raises(CanonicalEncodingError, match="non-minimal"):
        decode(b"\x05\x80\x00")


def test_non_canonical_integer_literal_is_rejected() -> None:
    for literal in (b"007", b"-0", b"+1", b" 1"):
        blob = b"\x03" + bytes([len(literal)]) + literal
        with pytest.raises(CanonicalEncodingError):
            decode(blob)


def test_unsorted_map_is_rejected() -> None:
    good = encode({"a": 1, "b": 2})
    a_pair = encode("a") + encode(1)
    b_pair = encode("b") + encode(2)
    header = good[: len(good) - len(a_pair) - len(b_pair)]
    with pytest.raises(CanonicalEncodingError, match="sorted order"):
        decode(header + b_pair + a_pair)


def test_duplicate_map_keys_are_rejected() -> None:
    pair = encode("a") + encode(1)
    with pytest.raises(CanonicalEncodingError):
        decode(b"\x08\x02" + pair + pair)


def test_non_nfc_string_is_rejected() -> None:
    decomposed = "é"  # "e" + combining acute; NFC form is "é"
    body = decomposed.encode("utf-8")
    blob = b"\x06" + bytes([len(body)]) + body
    with pytest.raises(CanonicalEncodingError, match="NFC"):
        decode(blob)
    # ... and the encoder normalises rather than emitting it.
    assert encode(decomposed) == encode("é")


def test_nan_and_negative_zero_are_rejected_on_decode() -> None:
    import struct as _struct

    with pytest.raises(CanonicalEncodingError):
        decode(b"\x04" + _struct.pack(">d", float("nan")))
    with pytest.raises(CanonicalEncodingError, match="negative zero"):
        decode(b"\x04" + _struct.pack(">d", -0.0))


# ---------------------------------------------------------------------------------------------
# Protocol structures
# ---------------------------------------------------------------------------------------------
def test_block_field_order_matches_the_architecture_document() -> None:
    # docs/ARCHITECTURE.md §blockchain, mirroring Alg. 1 line 3 / Alg. 2 line 8. If the paper
    # reading changes, this tuple changes here first and M2 follows.
    assert BLOCK_FIELD_ORDER == (
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
    assert TRANSACTION_FIELD_ORDER == (
        "tx_id",
        "payload_type",
        "ciphertext",
        "wrapped_key",
        "nonce",
        "digest",
        "created_at",
    )


def test_hash_preimage_excludes_the_hash_and_signature() -> None:
    # A block hash computed over a field containing that same hash is unsatisfiable; a signature
    # computed over itself likewise. These two tuples are what stops M2 writing that bug.
    assert "current_hash" not in BLOCK_HASHED_FIELDS
    assert "signature" not in BLOCK_HASHED_FIELDS
    assert "signature" not in BLOCK_SIGNED_FIELDS
    assert "current_hash" in BLOCK_SIGNED_FIELDS
    assert BLOCK_FIELD_ORDER[:8] == BLOCK_HASHED_FIELDS
    assert BLOCK_FIELD_ORDER[:9] == BLOCK_SIGNED_FIELDS


def test_block_parts_encode_differently() -> None:
    full = encode_block(BLOCK, BlockPart.FULL)
    signed = encode_block({k: BLOCK[k] for k in BLOCK_SIGNED_FIELDS}, BlockPart.SIGN)
    hashed = encode_block({k: BLOCK[k] for k in BLOCK_HASHED_FIELDS}, BlockPart.HASH)
    assert len({full, signed, hashed}) == 3


def test_block_encoding_ignores_dict_order_but_keeps_declared_field_order() -> None:
    shuffled = {key: BLOCK[key] for key in reversed(BLOCK_FIELD_ORDER)}
    assert list(shuffled) != list(BLOCK_FIELD_ORDER)
    assert encode_block(shuffled) == encode_block(BLOCK)


@pytest.mark.parametrize("field", BLOCK_FIELD_ORDER)
def test_every_block_field_affects_the_encoding(field: str) -> None:
    tampered = dict(BLOCK)
    original = tampered[field]
    tampered[field] = original + 1 if isinstance(original, int) else _perturb(original)
    assert encode_block(tampered) != encode_block(BLOCK)


def _perturb(value: object) -> object:
    if isinstance(value, bytes):
        return value + b"\x01"
    if isinstance(value, str):
        return value + "x"
    if isinstance(value, list):
        return [*value, b"\xee" * 32]
    raise AssertionError(f"unhandled field type {type(value).__name__}")


def test_missing_or_unexpected_struct_fields_are_errors() -> None:
    missing = {k: v for k, v in BLOCK.items() if k != "nonce"}
    with pytest.raises(CanonicalEncodingError, match=r"missing=\['nonce'\]"):
        encode_block(missing)
    extra = {**BLOCK, "surprise": 1}
    with pytest.raises(CanonicalEncodingError, match=r"unexpected=\['surprise'\]"):
        encode_block(extra)


def test_domain_separation_between_structures() -> None:
    fields = dict.fromkeys(("a", "b"), b"")
    assert encode_struct("one.v1", ("a", "b"), fields) != encode_struct(
        "two.v1", ("a", "b"), fields
    )


def test_transaction_encoding_uses_its_own_domain() -> None:
    tx = {
        "tx_id": b"\x01" * 32,
        "payload_type": "DT_BU",
        "ciphertext": b"\x02" * 64,
        "wrapped_key": b"\x03" * 48,
        "nonce": b"\x04" * 12,
        "digest": b"\x05" * 32,
        "created_at": 1757462400,
    }
    blob = encode_transaction(tx)
    decoded = decode(blob)
    assert isinstance(decoded, Struct)
    assert decoded.domain == DOMAIN_TRANSACTION
    assert list(decoded.fields) == list(TRANSACTION_FIELD_ORDER)
    # A transaction and a block that happened to carry identical field values must not collide.
    assert blob != encode_struct(BlockPart.FULL.domain, tuple(tx), tx)
