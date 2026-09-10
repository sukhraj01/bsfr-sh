"""`crypto.kem` — DEV-01 hybrid encryption and the wrapped-key/ciphertext binding.

§V mapping: §V-4 (data manipulation and leakage). The paper's `E_KU_CSl(Tx)` promises that only
`CS_l` can read a transaction; DEV-01 keeps that promise with a hybrid construction. The
key-swap tests are the ones that matter — they cover an attack that leaves every ECDSA signature
in the chain verifying, so signatures alone do not substantiate §V-4.

`tests/integration/` will exercise this against real `Transaction` objects in M2; here the
metadata is a plain mapping, because `crypto` must not know M2's types.
"""

from __future__ import annotations

import pytest

from bsfr_sh.crypto.aead import KEY_BYTES
from bsfr_sh.crypto.ecdsa import KeyPair
from bsfr_sh.crypto.kem import (
    HybridCiphertext,
    KemError,
    WrappedKey,
    open_payload,
    seal_payload,
    unwrap_key,
    wrap_key,
)

PAYLOAD = b"encrypted healthcare record fragment" * 100  # DT_BU, roughly 4 KiB per DEV-15

TX_1 = {"tx_id": "tx-0001", "payload_type": "DT_BU", "created_at": 1757548800}
TX_2 = {"tx_id": "tx-0002", "payload_type": "DT_BU", "created_at": 1757548801}


# --------------------------------------------------------------------------------------------
# Round trip
# --------------------------------------------------------------------------------------------
def test_round_trip(cs1_keys: KeyPair) -> None:
    hybrid = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    assert open_payload(cs1_keys.private, hybrid, TX_1) == PAYLOAD


def test_ciphertext_does_not_contain_the_plaintext(cs1_keys: KeyPair) -> None:
    hybrid = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    assert PAYLOAD not in hybrid.ciphertext
    assert PAYLOAD[:32] not in hybrid.ciphertext


def test_sealing_twice_produces_different_ciphertexts(cs1_keys: KeyPair) -> None:
    """Fresh ephemeral key and fresh data key per payload, so no two seals are comparable."""
    first = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    second = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    assert first.ciphertext != second.ciphertext
    assert first.wrapped_key != second.wrapped_key


def test_metadata_key_order_does_not_change_decryptability(cs1_keys: KeyPair) -> None:
    """The AAD is canonically encoded, so a differently-built metadata dict still opens."""
    hybrid = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    reordered = dict(reversed(list(TX_1.items())))
    assert open_payload(cs1_keys.private, hybrid, reordered) == PAYLOAD


# --------------------------------------------------------------------------------------------
# Rejection paths
# --------------------------------------------------------------------------------------------
def test_wrong_recipient_cannot_open(cs1_keys: KeyPair, cs2_keys: KeyPair) -> None:
    """Only `CS_l` can decrypt — the property the paper's `E_KU_CSl(Tx)` asserts."""
    hybrid = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    with pytest.raises(KemError, match="cannot unwrap"):
        open_payload(cs2_keys.private, hybrid, TX_1)


def test_tampered_ciphertext_is_rejected(cs1_keys: KeyPair) -> None:
    hybrid = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    flipped = bytearray(hybrid.ciphertext)
    flipped[0] ^= 0x01
    with pytest.raises(KemError, match="cannot open payload"):
        open_payload(
            cs1_keys.private,
            HybridCiphertext(hybrid.wrapped_key, hybrid.nonce, bytes(flipped)),
            TX_1,
        )


def test_tampered_wrapped_key_is_rejected(cs1_keys: KeyPair) -> None:
    hybrid = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    wrapped = WrappedKey.from_bytes(hybrid.wrapped_key)
    flipped = bytearray(wrapped.ciphertext)
    flipped[0] ^= 0x01
    mangled = WrappedKey(wrapped.ephemeral_public, wrapped.nonce, bytes(flipped)).to_bytes()
    with pytest.raises(KemError, match="cannot unwrap"):
        open_payload(
            cs1_keys.private,
            HybridCiphertext(mangled, hybrid.nonce, hybrid.ciphertext),
            TX_1,
        )


def test_mismatched_metadata_is_rejected(cs1_keys: KeyPair) -> None:
    hybrid = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    with pytest.raises(KemError, match="cannot unwrap"):
        open_payload(cs1_keys.private, hybrid, TX_2)


def test_invalid_ephemeral_point_is_rejected(cs1_keys: KeyPair) -> None:
    """An off-curve ephemeral point fed to a static private key leaks that key."""
    hybrid = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    wrapped = WrappedKey.from_bytes(hybrid.wrapped_key)
    bogus = WrappedKey(b"\x04" + b"\x01" * 64, wrapped.nonce, wrapped.ciphertext).to_bytes()
    with pytest.raises(KemError, match="invalid ephemeral point"):
        open_payload(
            cs1_keys.private,
            HybridCiphertext(bogus, hybrid.nonce, hybrid.ciphertext),
            TX_1,
        )


def test_malformed_wrapped_key_encoding_is_rejected(cs1_keys: KeyPair) -> None:
    hybrid = seal_payload(cs1_keys.public, PAYLOAD, TX_1)
    with pytest.raises(KemError, match="canonical encoding"):
        open_payload(
            cs1_keys.private,
            HybridCiphertext(b"not an encoding", hybrid.nonce, hybrid.ciphertext),
            TX_1,
        )


# --------------------------------------------------------------------------------------------
# The binding this construction exists for
# --------------------------------------------------------------------------------------------
def test_wrapped_key_cannot_be_swapped_onto_another_transaction(cs1_keys: KeyPair) -> None:
    """§V-4: the attack that survives every signature check.

    Two transactions to the same cloud server. Lift `Tx_1`'s wrapped key onto `Tx_2`'s payload.
    Nothing is forged and no key is broken — the block signature covers whatever the block holds,
    so the chain still validates. Without the binding, `CS_l` would attempt a decryption the
    honest owner never authorised.
    """
    first = seal_payload(cs1_keys.public, b"record for Tx_1", TX_1)
    second = seal_payload(cs1_keys.public, b"record for Tx_2", TX_2)
    swapped = HybridCiphertext(
        wrapped_key=first.wrapped_key, nonce=second.nonce, ciphertext=second.ciphertext
    )
    with pytest.raises(KemError, match="cannot unwrap"):
        open_payload(cs1_keys.private, swapped, TX_2)
    # ...and it does not open as Tx_1 either: the payload AAD names Tx_1's wrapped key but
    # Tx_2's data key was never wrapped for Tx_1.
    with pytest.raises(KemError):
        open_payload(cs1_keys.private, swapped, TX_1)


def test_ciphertext_cannot_be_swapped_under_a_wrapped_key(cs1_keys: KeyPair) -> None:
    """The mirror image: keep the wrapped key, substitute someone else's payload."""
    first = seal_payload(cs1_keys.public, b"record for Tx_1", TX_1)
    second = seal_payload(cs1_keys.public, b"record for Tx_2", TX_2)
    swapped = HybridCiphertext(
        wrapped_key=first.wrapped_key, nonce=first.nonce, ciphertext=second.ciphertext
    )
    with pytest.raises(KemError, match="cannot open payload"):
        open_payload(cs1_keys.private, swapped, TX_1)


def test_wrapped_key_is_bound_to_its_metadata_at_the_kem_layer(cs1_keys: KeyPair) -> None:
    """Same check one level down, so a future caller assembling the pieces by hand still fails."""
    data_key = b"\x07" * KEY_BYTES
    wrapped = wrap_key(cs1_keys.public, data_key, b"context-one")
    assert unwrap_key(cs1_keys.private, wrapped, b"context-one") == data_key
    with pytest.raises(KemError, match="cannot unwrap"):
        unwrap_key(cs1_keys.private, wrapped, b"context-two")


def test_wrap_rejects_a_wrong_length_data_key(cs1_keys: KeyPair) -> None:
    with pytest.raises(KemError, match="data key must be"):
        wrap_key(cs1_keys.public, b"\x00" * 16, b"context")


def test_wrapped_key_round_trips_through_bytes(cs1_keys: KeyPair) -> None:
    wrapped = wrap_key(cs1_keys.public, b"\x07" * KEY_BYTES, b"ctx")
    assert WrappedKey.from_bytes(wrapped.to_bytes()) == wrapped
