"""AES-256-GCM — the payload cipher for DEV-01's hybrid encryption.

`configs/chain.yaml` pins ``crypto.aead``: AES-256-GCM, 256-bit keys, 96-bit nonces.

Nonce reuse is structurally impossible, not merely forbidden
------------------------------------------------------------
Repeating a (key, nonce) pair under GCM is catastrophic rather than merely weakening: the
keystream repeats, so XORing the two ciphertexts reveals the plaintexts, and the authentication
key `H` can be recovered from the resulting forgery polynomial, which lets an attacker forge
arbitrary messages under that key. It is the single most common way GCM deployments fail.

A comment saying "callers must not reuse the nonce" is not a defence, because it relocates the
obligation to every call site including the ones not written yet. So `seal()` takes **no nonce
parameter at all**. The nonce is drawn from the system CSPRNG inside this module and returned
alongside the ciphertext, and there is no public API through which a caller can supply one. This
is NIST SP 800-38D §8.2.2's RBG-based construction: with 96-bit random nonces the birthday bound
puts collision probability below 2^-32 only while a single key is used fewer than 2^32 times, so
`AeadKey` counts its own seals and refuses to continue past that limit rather than silently
crossing the bound.

In DEV-01's actual usage each data key wraps one transaction and is used exactly once, so the
counter never approaches its limit — it is there for the case where a later milestone reuses a
key without noticing.

Known-answer tests need a fixed nonce, which is exactly what this API refuses to provide.
`_seal_with_nonce` exists for that and is private, untyped into `__all__`, and used only by
`tests/unit/test_aead.py`. Production code calling it is a bug.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "AEAD_ALGORITHM",
    "KEY_BYTES",
    "MAX_SEALS_PER_KEY",
    "NONCE_BYTES",
    "TAG_BYTES",
    "AeadError",
    "AeadKey",
    "Sealed",
    "open_sealed",
]

AEAD_ALGORITHM: Final = "aes-256-gcm"
KEY_BYTES: Final = 32
NONCE_BYTES: Final = 12
TAG_BYTES: Final = 16

#: NIST SP 800-38D §8.3 — the RBG-based nonce construction holds only below 2^32 invocations
#: per key. Past that the key must be retired, so we refuse rather than continue.
MAX_SEALS_PER_KEY: Final = 2**32


class AeadError(ValueError):
    """Raised on malformed key material, an exhausted key, or a failed decryption."""


@dataclass(frozen=True)
class Sealed:
    """An AES-256-GCM ciphertext with the nonce that produced it.

    `ciphertext` includes the 16-byte GCM tag appended, as `cryptography` returns it. The fields
    map onto M2's `Transaction.nonce` and `Transaction.ciphertext`.
    """

    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if len(self.nonce) != NONCE_BYTES:
            raise AeadError(f"nonce must be {NONCE_BYTES} bytes, got {len(self.nonce)}")
        if len(self.ciphertext) < TAG_BYTES:
            raise AeadError("ciphertext is shorter than the GCM tag")


class AeadKey:
    """A 256-bit AES-GCM key that owns its nonce sequence.

    Not a dataclass and not frozen: it carries mutable seal-count state, and its `__repr__` must
    never render key material.
    """

    __slots__ = ("_aesgcm", "_key", "_seals")

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_BYTES:
            raise AeadError(f"key must be {KEY_BYTES} bytes for AES-256, got {len(key)}")
        self._key = bytes(key)
        self._aesgcm = AESGCM(self._key)
        self._seals = 0

    @classmethod
    def generate(cls) -> AeadKey:
        """Draw a fresh data key from the system CSPRNG. `crypto.kem` calls this per payload."""
        return cls(os.urandom(KEY_BYTES))

    @property
    def key_bytes(self) -> bytes:
        """The raw key, for wrapping by `crypto.kem`. The only legitimate reason to read it."""
        return self._key

    @property
    def seals_issued(self) -> int:
        return self._seals

    def seal(self, plaintext: bytes, associated_data: bytes) -> Sealed:
        """Encrypt and authenticate `plaintext`, authenticating `associated_data` alongside it.

        `associated_data` is mandatory rather than optional: in this project it is what binds a
        ciphertext to the transaction and the wrapped key it belongs to (see `crypto.kem`), and
        an optional parameter with a `b""` default is one forgotten argument away from losing
        that binding. Pass `b""` explicitly where there is genuinely nothing to bind.
        """
        if self._seals >= MAX_SEALS_PER_KEY:
            raise AeadError(
                f"key exhausted: {MAX_SEALS_PER_KEY} seals is the SP 800-38D limit for "
                f"random {NONCE_BYTES * 8}-bit nonces; derive a new key"
            )
        self._seals += 1
        return _seal_with_nonce(self, os.urandom(NONCE_BYTES), plaintext, associated_data)

    def unseal(self, sealed: Sealed, associated_data: bytes) -> bytes:
        """Decrypt and verify. Raises `AeadError` if the tag, the AAD or the nonce is wrong."""
        try:
            return self._aesgcm.decrypt(sealed.nonce, sealed.ciphertext, associated_data)
        except InvalidTag as exc:
            raise AeadError(
                "AEAD authentication failed: ciphertext, nonce or associated data was altered"
            ) from exc

    def __repr__(self) -> str:
        return f"AeadKey(<aes-256>, seals={self._seals})"


def open_sealed(key: AeadKey, sealed: Sealed, associated_data: bytes) -> bytes:
    """Function form of `AeadKey.unseal`, for call sites that read better that way."""
    return key.unseal(sealed, associated_data)


def _seal_with_nonce(
    key: AeadKey, nonce: bytes, plaintext: bytes, associated_data: bytes
) -> Sealed:
    """Encrypt under a caller-supplied nonce. **Test-only** — see the module docstring.

    Deliberately private and deliberately not re-exported: this is the door that `seal()` closes,
    reopened only wide enough to run published NIST GCM vectors, which cannot be checked against
    a randomly-nonced API.
    """
    if len(nonce) != NONCE_BYTES:
        raise AeadError(f"nonce must be {NONCE_BYTES} bytes, got {len(nonce)}")
    ciphertext = key._aesgcm.encrypt(nonce, plaintext, associated_data)
    return Sealed(nonce=nonce, ciphertext=ciphertext)
