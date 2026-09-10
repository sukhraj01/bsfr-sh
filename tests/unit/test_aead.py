"""`crypto.aead` — published AES-256-GCM vectors, tamper rejection, nonce discipline.

Known-answer vectors are the AES-256 cases from the GCM specification's test-vector set
(McGrew & Viega, *The Galois/Counter Mode of Operation*, Test Cases 13, 14 and 16), the same
values NIST's `gcmEncryptExtIV256.rsp` carries.

A fixed nonce is required to check a KAT and the public API deliberately refuses to accept one,
so these tests reach for the private `_seal_with_nonce`. That is the only sanctioned use of it —
see the module docstring in `crypto/aead.py`.

§V mapping: §V-4 (data manipulation and leakage) — the AEAD tag is what makes an altered payload
detectable rather than silently decrypted.
"""

from __future__ import annotations

import pytest

from bsfr_sh.crypto.aead import (
    KEY_BYTES,
    MAX_SEALS_PER_KEY,
    NONCE_BYTES,
    TAG_BYTES,
    AeadError,
    AeadKey,
    Sealed,
    _seal_with_nonce,
    open_sealed,
)

# (key, nonce, plaintext, aad, ciphertext, tag) — GCM spec Test Cases 13, 14, 16 (AES-256).
GCM_VECTORS = [
    (
        "00" * 32,
        "00" * 12,
        "",
        "",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b",
    ),
    (
        "00" * 32,
        "00" * 12,
        "00" * 16,
        "",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919",
    ),
    (
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b",
    ),
]


@pytest.mark.parametrize(("key", "nonce", "pt", "aad", "ct", "tag"), GCM_VECTORS)
def test_aes_256_gcm_known_answer_vectors(
    key: str, nonce: str, pt: str, aad: str, ct: str, tag: str
) -> None:
    sealed = _seal_with_nonce(
        AeadKey(bytes.fromhex(key)),
        bytes.fromhex(nonce),
        bytes.fromhex(pt),
        bytes.fromhex(aad),
    )
    assert sealed.ciphertext.hex() == ct + tag


@pytest.mark.parametrize(("key", "nonce", "pt", "aad", "ct", "tag"), GCM_VECTORS)
def test_aes_256_gcm_vectors_decrypt(
    key: str, nonce: str, pt: str, aad: str, ct: str, tag: str
) -> None:
    sealed = Sealed(nonce=bytes.fromhex(nonce), ciphertext=bytes.fromhex(ct + tag))
    assert AeadKey(bytes.fromhex(key)).unseal(sealed, bytes.fromhex(aad)) == bytes.fromhex(pt)


# --------------------------------------------------------------------------------------------
# Round trip and rejection
# --------------------------------------------------------------------------------------------
def test_round_trip() -> None:
    key = AeadKey.generate()
    sealed = key.seal(b"DT_BU payload", b"tx-0001")
    assert open_sealed(key, sealed, b"tx-0001") == b"DT_BU payload"


def test_tampered_ciphertext_is_rejected() -> None:
    key = AeadKey.generate()
    sealed = key.seal(b"DT_BU payload", b"tx-0001")
    flipped = bytearray(sealed.ciphertext)
    flipped[0] ^= 0x01
    with pytest.raises(AeadError, match="authentication failed"):
        key.unseal(Sealed(nonce=sealed.nonce, ciphertext=bytes(flipped)), b"tx-0001")


def test_tampered_tag_is_rejected() -> None:
    key = AeadKey.generate()
    sealed = key.seal(b"DT_BU payload", b"tx-0001")
    flipped = bytearray(sealed.ciphertext)
    flipped[-1] ^= 0x80
    with pytest.raises(AeadError, match="authentication failed"):
        key.unseal(Sealed(nonce=sealed.nonce, ciphertext=bytes(flipped)), b"tx-0001")


def test_tampered_associated_data_is_rejected() -> None:
    """The binding that `crypto.kem` relies on: change the context, lose the plaintext."""
    key = AeadKey.generate()
    sealed = key.seal(b"DT_BU payload", b"tx-0001")
    with pytest.raises(AeadError, match="authentication failed"):
        key.unseal(sealed, b"tx-0002")


def test_wrong_key_is_rejected() -> None:
    sealed = AeadKey.generate().seal(b"DT_BU payload", b"tx-0001")
    with pytest.raises(AeadError, match="authentication failed"):
        AeadKey.generate().unseal(sealed, b"tx-0001")


def test_wrong_nonce_is_rejected() -> None:
    key = AeadKey.generate()
    sealed = key.seal(b"DT_BU payload", b"tx-0001")
    with pytest.raises(AeadError, match="authentication failed"):
        key.unseal(Sealed(nonce=bytes(NONCE_BYTES), ciphertext=sealed.ciphertext), b"tx-0001")


# --------------------------------------------------------------------------------------------
# Nonce discipline
# --------------------------------------------------------------------------------------------
def test_seal_takes_no_nonce_parameter() -> None:
    """Nonce reuse is prevented structurally, not by documentation.

    If a nonce parameter ever appears on the public API, this test is the tripwire: a caller that
    can supply a nonce is a caller that can repeat one, and a repeated (key, nonce) under GCM
    reveals both plaintexts and the authentication key.
    """
    import inspect

    parameters = set(inspect.signature(AeadKey.seal).parameters)
    assert parameters == {"self", "plaintext", "associated_data"}


def test_nonces_do_not_repeat_across_seals() -> None:
    key = AeadKey.generate()
    nonces = {key.seal(b"x", b"").nonce for _ in range(256)}
    assert len(nonces) == 256
    assert key.seals_issued == 256


def test_same_plaintext_seals_to_different_ciphertexts() -> None:
    key = AeadKey.generate()
    assert key.seal(b"same", b"").ciphertext != key.seal(b"same", b"").ciphertext


def test_key_refuses_to_exceed_the_sp_800_38d_invocation_limit() -> None:
    key = AeadKey.generate()
    key._seals = MAX_SEALS_PER_KEY
    with pytest.raises(AeadError, match="exhausted"):
        key.seal(b"x", b"")


def test_key_length_is_enforced() -> None:
    with pytest.raises(AeadError, match="AES-256"):
        AeadKey(b"\x00" * 16)
    assert AeadKey(b"\x00" * KEY_BYTES).seals_issued == 0


def test_sealed_rejects_a_wrong_length_nonce_or_a_truncated_ciphertext() -> None:
    with pytest.raises(AeadError, match="nonce must be"):
        Sealed(nonce=b"\x00" * 8, ciphertext=b"\x00" * TAG_BYTES)
    with pytest.raises(AeadError, match="shorter than the GCM tag"):
        Sealed(nonce=b"\x00" * NONCE_BYTES, ciphertext=b"\x00")


def test_key_repr_does_not_leak_material() -> None:
    assert "aes-256" in repr(AeadKey.generate())
    assert AeadKey(b"\xab" * KEY_BYTES).key_bytes.hex() not in repr(AeadKey(b"\xab" * KEY_BYTES))
