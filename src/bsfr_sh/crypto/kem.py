"""ECIES-style key wrapping — DEV-01, our hybrid replacement for the paper's `E_KU_CSl(Tx)`.

The paper writes transactions as encrypted directly under the cloud server's public key. Elliptic
-curve public keys cannot carry bulk payloads at all, and healthcare backups are bulk, so DEV-01
substitutes the standard hybrid construction: a fresh AES-256-GCM data key per payload, wrapped
to `KU_CSl` by ephemeral ECDH. The semantics the paper relies on are preserved exactly — only
`CS_l`, holding the matching private key, can recover the payload.

Wrapping
--------
1. Generate an ephemeral secp256r1 keypair `(e, g^e)`.
2. ECDH against the recipient's static key: `Z = ECDH(e, KU_CSl)`.
3. HKDF-SHA256 over `Z`, with the full transcript as `info` — both public keys and the payload
   metadata. Binding the transcript into the KDF is what stops a wrapped key derived for one
   recipient or one transaction from deriving the same KEK anywhere else.
4. AES-256-GCM the data key under that KEK, with the transcript digest as associated data.

Why the ciphertext binding exists
---------------------------------
A wrapped key and the payload it protects are two separate byte strings in a `Transaction`. If
they are only *adjacent*, an attacker who cannot break either can still detach one from the other:
lift the wrapped key from transaction `Tx_1` onto transaction `Tx_2`, and — because the block
signature covers whatever the block contains — every ECDSA check in the chain still verifies while
`CS_l` decrypts something other than what the honest owner submitted. That defeats the
data-manipulation and leakage claims in §V-4 without forging a single signature.

`seal_payload` therefore binds in both directions:

* the wrap's associated data is the transaction metadata, so a wrapped key is valid only for the
  transaction it was created for;
* the payload's associated data is the metadata **plus the wrapped-key bytes**, so a payload can
  only be opened next to the exact wrapped key it shipped with.

Swapping either half breaks a GCM tag. The construction is `seal_payload` / `open_payload`, and
M2's `Transaction` is expected to call those rather than assembling the pieces itself — the
binding is only reliable if there is one place where it is applied.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from bsfr_sh.crypto.aead import KEY_BYTES, AeadError, AeadKey, Sealed
from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey, load_public_key
from bsfr_sh.crypto.hashing import DOMAIN_KEM_TRANSCRIPT, tagged_h
from bsfr_sh.util.serialization import CanonicalEncodingError, Value, decode, encode

__all__ = [
    "KEM_ALGORITHM",
    "HybridCiphertext",
    "KemError",
    "WrappedKey",
    "open_payload",
    "seal_payload",
    "unwrap_key",
    "wrap_key",
]

KEM_ALGORITHM: Final = "ecies"
_KDF_INFO_LABEL: Final = b"bsfr-sh/kem/hkdf-sha256/v1"


class KemError(ValueError):
    """Raised when wrapping or unwrapping fails — wrong recipient, or a broken binding."""


@dataclass(frozen=True)
class WrappedKey:
    """A data key wrapped to one recipient, for one transaction.

    `to_bytes` is the canonical form that goes into `Transaction.wrapped_key` and, critically,
    into the payload's associated data.
    """

    ephemeral_public: bytes
    nonce: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        """Canonical encoding — unambiguous, so it can be used as associated data directly."""
        return encode([self.ephemeral_public, self.nonce, self.ciphertext])

    @classmethod
    def from_bytes(cls, data: bytes) -> WrappedKey:
        try:
            parts = decode(data)
        except CanonicalEncodingError as exc:
            raise KemError(f"wrapped key is not a canonical encoding: {exc}") from exc
        if not isinstance(parts, list) or len(parts) != 3:
            raise KemError("wrapped key must encode exactly three byte strings")
        if not all(isinstance(part, bytes) for part in parts):
            raise KemError("wrapped key fields must be byte strings")
        ephemeral, nonce, ciphertext = parts
        assert isinstance(ephemeral, bytes)
        assert isinstance(nonce, bytes)
        assert isinstance(ciphertext, bytes)
        return cls(ephemeral_public=ephemeral, nonce=nonce, ciphertext=ciphertext)


@dataclass(frozen=True)
class HybridCiphertext:
    """DEV-01's replacement for `E_KU_CSl(Tx)`: wrapped key plus AEAD payload.

    Field names match `Transaction`'s (docs/ARCHITECTURE.md §blockchain) so M2 can carry them
    straight through without a translation step that could drop the binding.
    """

    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes


def _metadata_bytes(metadata: Mapping[str, Value]) -> bytes:
    """Canonically encode transaction metadata.

    A mapping, not a struct: `crypto` must not know M2's transaction field order
    (docs/ARCHITECTURE.md dependency direction). The encoder sorts mapping keys by encoded bytes,
    so the result is insertion-order independent — verified across processes in the M1 STEP 0
    check.
    """
    try:
        return encode(dict(metadata))
    except CanonicalEncodingError as exc:
        raise KemError(f"transaction metadata is not canonically encodable: {exc}") from exc


def _transcript(recipient: bytes, ephemeral: bytes, associated_data: bytes) -> bytes:
    """Digest binding both public keys and the caller's associated data into one value."""
    return tagged_h(DOMAIN_KEM_TRANSCRIPT, recipient, ephemeral, associated_data)


def _derive_kek(shared_secret: bytes, transcript: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=None,
        info=_KDF_INFO_LABEL + transcript,
    ).derive(shared_secret)


def wrap_key(recipient: PublicKey, data_key: bytes, associated_data: bytes) -> WrappedKey:
    """Wrap `data_key` to `recipient`, bound to `associated_data`.

    Implements DEV-01's key-transport step. `associated_data` is mandatory: it is the transaction
    metadata, and a wrapped key that is not bound to one is a wrapped key that can be moved.
    """
    if len(data_key) != KEY_BYTES:
        raise KemError(f"data key must be {KEY_BYTES} bytes, got {len(data_key)}")
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = PublicKey(ephemeral.public_key()).to_bytes()
    recipient_bytes = recipient.to_bytes()
    shared = ephemeral.exchange(ec.ECDH(), recipient._key)
    transcript = _transcript(recipient_bytes, ephemeral_public, associated_data)
    kek = AeadKey(_derive_kek(shared, transcript))
    sealed = kek.seal(data_key, transcript)
    return WrappedKey(
        ephemeral_public=ephemeral_public, nonce=sealed.nonce, ciphertext=sealed.ciphertext
    )


def unwrap_key(recipient: PrivateKey, wrapped: WrappedKey, associated_data: bytes) -> bytes:
    """Recover a wrapped data key. Raises `KemError` if it was not wrapped for this exact context.

    The ephemeral point is validated by `load_public_key` before it reaches ECDH: an attacker-
    supplied point off the curve, fed to a static private key, leaks that key one small-subgroup
    residue at a time.
    """
    try:
        ephemeral = load_public_key(wrapped.ephemeral_public)
    except ValueError as exc:
        raise KemError(f"wrapped key carries an invalid ephemeral point: {exc}") from exc
    shared = recipient._key.exchange(ec.ECDH(), ephemeral._key)
    transcript = _transcript(
        recipient.public_key.to_bytes(), wrapped.ephemeral_public, associated_data
    )
    kek = AeadKey(_derive_kek(shared, transcript))
    try:
        return kek.unseal(Sealed(nonce=wrapped.nonce, ciphertext=wrapped.ciphertext), transcript)
    except AeadError as exc:
        raise KemError(
            "cannot unwrap: wrong recipient key, altered wrapped key, or metadata that does not "
            "match the transaction this key was wrapped for"
        ) from exc


def seal_payload(
    recipient: PublicKey, plaintext: bytes, metadata: Mapping[str, Value]
) -> HybridCiphertext:
    """Encrypt a transaction payload to `CS_l`. The DEV-01 entry point M2 should call.

    `metadata` is whatever identifies the transaction the payload belongs to — `tx_id`,
    `payload_type`, `created_at`. It is bound into both halves, so the returned triple can only
    be opened as a whole and only for this transaction.
    """
    aad_metadata = _metadata_bytes(metadata)
    data_key = AeadKey.generate()
    wrapped = wrap_key(recipient, data_key.key_bytes, aad_metadata)
    wrapped_bytes = wrapped.to_bytes()
    # The payload's AAD covers the wrapped key, so the two cannot be separated. Order matters:
    # the wrap has no dependency on the payload, so there is no cycle.
    payload_aad = encode([aad_metadata, wrapped_bytes])
    sealed = data_key.seal(plaintext, payload_aad)
    return HybridCiphertext(
        wrapped_key=wrapped_bytes, nonce=sealed.nonce, ciphertext=sealed.ciphertext
    )


def open_payload(
    recipient: PrivateKey, hybrid: HybridCiphertext, metadata: Mapping[str, Value]
) -> bytes:
    """Recover a transaction payload. Raises `KemError` on any broken binding.

    Rejects: the wrong recipient key, an altered ciphertext, an altered wrapped key, metadata
    that does not match, and — the case this construction exists for — a wrapped key lifted from
    a different transaction.
    """
    aad_metadata = _metadata_bytes(metadata)
    wrapped = WrappedKey.from_bytes(hybrid.wrapped_key)
    data_key = AeadKey(unwrap_key(recipient, wrapped, aad_metadata))
    payload_aad = encode([aad_metadata, hybrid.wrapped_key])
    try:
        return data_key.unseal(
            Sealed(nonce=hybrid.nonce, ciphertext=hybrid.ciphertext), payload_aad
        )
    except AeadError as exc:
        raise KemError(
            "cannot open payload: ciphertext, nonce, wrapped key or metadata was altered"
        ) from exc
