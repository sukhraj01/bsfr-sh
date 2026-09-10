"""`crypto.ecdsa` — published vectors, tamper rejection, wrong-key rejection.

Known-answer vectors are RFC 6979 Appendix A.2.5 (ECDSA, NIST P-256, SHA-256). They serve two
purposes at once: they check that we verify signatures produced by an independent implementation,
and — because RFC 6979 fixes `k` — that our *deterministic signing* reproduces the published
`(r, s)` byte for byte. A self-generated vector could do neither.

§V mapping: §V-1 (impersonation resistance — a signature is what authenticates an entity) and
§V-4 (data manipulation — `Sig_βj` is what makes a tampered block detectable in M2).
"""

from __future__ import annotations

import pytest

from bsfr_sh.crypto.ecdsa import (
    CURVE_NAME,
    DETERMINISTIC_SIGNING,
    PUBLIC_KEY_BYTES,
    KeyPair,
    SignatureError,
    generate_keypair,
    keypair_from_secret,
    load_private_key,
    load_public_key,
    sign,
    signature_from_raw,
    signature_to_raw,
    verify,
)

# RFC 6979 A.2.5 — key.
RFC6979_X = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
RFC6979_UX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
RFC6979_UY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"

# RFC 6979 A.2.5 — signatures with SHA-256.
RFC6979_VECTORS = [
    (
        b"sample",
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    ),
    (
        b"test",
        "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
        "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
    ),
]


@pytest.fixture(scope="module")
def rfc6979_keys() -> KeyPair:
    return keypair_from_secret(RFC6979_X)


def test_public_point_matches_the_rfc_6979_vector(rfc6979_keys: KeyPair) -> None:
    """Derivation is checked before anything is signed with it."""
    encoded = rfc6979_keys.public.to_bytes()
    assert len(encoded) == PUBLIC_KEY_BYTES
    assert encoded[0] == 0x04
    assert encoded[1:33].hex().upper() == RFC6979_UX
    assert encoded[33:].hex().upper() == RFC6979_UY


@pytest.mark.parametrize(("message", "r", "s"), RFC6979_VECTORS)
def test_published_signature_verifies(
    rfc6979_keys: KeyPair, message: bytes, r: str, s: str
) -> None:
    """Verify a signature this code did not produce — the half that holds on any backend."""
    signature = signature_from_raw(bytes.fromhex(r + s))
    assert verify(rfc6979_keys.public, signature, message)


@pytest.mark.parametrize(("message", "r", "s"), RFC6979_VECTORS)
def test_deterministic_signing_reproduces_the_published_signature(
    rfc6979_keys: KeyPair, message: bytes, r: str, s: str
) -> None:
    """RFC 6979 fixes `k`, so our `(r, s)` must equal the published one exactly.

    This is what makes signature bytes reproducible across machines, which CLAUDE.md §4b requires
    of test runs — and it is the evidence that nonce generation is not a source of key leakage.
    """
    if not DETERMINISTIC_SIGNING:  # pragma: no cover - backend-dependent
        pytest.skip("backend does not support RFC 6979 deterministic ECDSA")
    produced = signature_to_raw(sign(rfc6979_keys.private, message))
    assert produced.hex().upper() == r + s


def test_signing_is_repeatable(rfc6979_keys: KeyPair) -> None:
    if not DETERMINISTIC_SIGNING:  # pragma: no cover - backend-dependent
        pytest.skip("backend does not support RFC 6979 deterministic ECDSA")
    assert sign(rfc6979_keys.private, b"m") == sign(rfc6979_keys.private, b"m")


# --------------------------------------------------------------------------------------------
# Rejection paths
# --------------------------------------------------------------------------------------------
def test_tampered_signature_is_rejected(sys_keys: KeyPair) -> None:
    signature = bytearray(sign(sys_keys.private, b"block header bytes"))
    signature[-1] ^= 0x01
    assert not verify(sys_keys.public, bytes(signature), b"block header bytes")


def test_tampered_message_is_rejected(sys_keys: KeyPair) -> None:
    signature = sign(sys_keys.private, b"block header bytes")
    assert not verify(sys_keys.public, signature, b"block header bytez")


def test_wrong_key_is_rejected(sys_keys: KeyPair, attacker_keys: KeyPair) -> None:
    """§V-1 impersonation: a valid signature under the adversary's key is still not `SYS_i`."""
    signature = sign(attacker_keys.private, b"I am SYS_1")
    assert not verify(sys_keys.public, signature, b"I am SYS_1")


def test_malformed_signature_is_false_not_an_exception(sys_keys: KeyPair) -> None:
    """A caller deciding whether to accept a message needs one answer, not two failure modes."""
    assert not verify(sys_keys.public, b"not der at all", b"m")
    assert not verify(sys_keys.public, b"", b"m")


# --------------------------------------------------------------------------------------------
# Key handling
# --------------------------------------------------------------------------------------------
def test_public_key_round_trips_through_bytes(sys_keys: KeyPair) -> None:
    assert load_public_key(sys_keys.public.to_bytes()) == sys_keys.public


def test_private_key_round_trips_through_der(sys_keys: KeyPair) -> None:
    reloaded = load_private_key(sys_keys.private.to_der())
    assert reloaded.public_key == sys_keys.public


def test_point_not_on_the_curve_is_rejected() -> None:
    """An invalid-curve point handed to ECDH leaks a static private key; reject at the boundary."""
    bogus = bytes([0x04]) + b"\x01" * 64
    with pytest.raises(SignatureError, match="not on"):
        load_public_key(bogus)


def test_compressed_and_short_points_are_rejected(sys_keys: KeyPair) -> None:
    with pytest.raises(SignatureError, match="uncompressed"):
        load_public_key(sys_keys.public.to_bytes()[:64])
    with pytest.raises(SignatureError, match="uncompressed"):
        load_public_key(b"\x02" + sys_keys.public.to_bytes()[1:33])


def test_out_of_range_secret_is_rejected() -> None:
    with pytest.raises(SignatureError, match="out of range"):
        keypair_from_secret(0)


def test_generated_keys_are_distinct() -> None:
    assert generate_keypair().public != generate_keypair().public


def test_private_key_repr_does_not_leak_material(sys_keys: KeyPair) -> None:
    assert repr(sys_keys.private) == "PrivateKey(<secp256r1>)"


def test_curve_is_the_one_the_config_pins() -> None:
    assert CURVE_NAME == "secp256r1"
