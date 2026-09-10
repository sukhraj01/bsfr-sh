"""`crypto.hashing` — published SHA-256 vectors and domain separation.

Known-answer vectors are taken from FIPS 180-2 Appendix B / the NIST SHA test-vector set. Using
published vectors rather than self-generated ones is the point: a self-generated vector only
proves the implementation agrees with itself, which it would also do if it were hashing the wrong
thing entirely.

§V mapping: underpins every claim — §V-3 (chain integrity), §V-4 (data manipulation) and §V-5
(chain separation) all reduce to "this digest is over the bytes we think it is".
"""

from __future__ import annotations

import pytest

from bsfr_sh.crypto.hashing import (
    DIGEST_SIZE,
    DOMAIN_BLOCK_HEADER,
    DOMAIN_MERKLE_LEAF,
    DOMAIN_MERKLE_NODE,
    DOMAIN_TRANSACTION,
    h,
    hex_digest,
    tagged_h,
)

# FIPS 180-2 Appendix B.1/B.2 and the NIST empty-string vector.
SHA256_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
]


@pytest.mark.parametrize(("message", "expected"), SHA256_VECTORS)
def test_sha256_known_answer_vectors(message: bytes, expected: str) -> None:
    assert hex_digest(h(message)) == expected


@pytest.mark.slow
def test_sha256_million_a_vector() -> None:
    """FIPS 180-2 B.3 — one million 'a'. Slow, so excluded from the fast loop."""
    assert (
        hex_digest(h(b"a" * 1_000_000))
        == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    )


def test_digest_size_is_32_bytes() -> None:
    assert len(h(b"anything")) == DIGEST_SIZE


def test_domains_produce_different_digests_for_the_same_input() -> None:
    """A value valid in one position must never be reinterpretable in another.

    Without this, a Merkle leaf digest and a transaction digest over identical bytes would be the
    same 32 bytes, and either could be presented where the other was expected.
    """
    payload = b"the same bytes in every position"
    digests = {
        tagged_h(domain, payload)
        for domain in (
            DOMAIN_TRANSACTION,
            DOMAIN_BLOCK_HEADER,
            DOMAIN_MERKLE_LEAF,
            DOMAIN_MERKLE_NODE,
        )
    }
    assert len(digests) == 4


def test_tagged_digest_differs_from_the_bare_digest() -> None:
    payload = b"payload"
    assert tagged_h(DOMAIN_TRANSACTION, payload) != h(payload)


def test_parts_are_length_prefixed_so_concatenations_do_not_collide() -> None:
    """``(b"ab", b"c")`` and ``(b"a", b"bc")`` must differ.

    Plain concatenation collides here, and a Merkle node built on a colliding concatenation lets
    an attacker move the boundary between two children.
    """
    assert tagged_h(DOMAIN_MERKLE_NODE, b"ab", b"c") != tagged_h(DOMAIN_MERKLE_NODE, b"a", b"bc")


def test_part_count_changes_the_digest() -> None:
    assert tagged_h(DOMAIN_MERKLE_NODE, b"a") != tagged_h(DOMAIN_MERKLE_NODE, b"a", b"")


def test_empty_domain_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        tagged_h("", b"x")


def test_hashing_is_deterministic_across_calls() -> None:
    assert tagged_h(DOMAIN_TRANSACTION, b"x", b"y") == tagged_h(DOMAIN_TRANSACTION, b"x", b"y")
