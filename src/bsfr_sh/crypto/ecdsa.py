"""ECDSA over secp256r1 (NIST P-256) — `Sig_βj` and the session transcript signatures.

The paper mandates ECDSA (ref [23]); CLAUDE.md §7 forbids substituting Ed25519 even though it
would be the better primitive. `configs/chain.yaml` pins ``crypto.signature.curve: secp256r1``.

Deterministic nonces (RFC 6979)
-------------------------------
ECDSA leaks the private key outright if the per-signature nonce `k` repeats or is even slightly
biased — the standard failure, from the Sony PS3 key recovery onwards. RFC 6979 derives `k`
deterministically from the private key and the message, so there is no nonce generator to get
wrong, and it makes our signatures byte-reproducible, which is what lets fixture-loaded test keys
produce byte-identical test runs (CLAUDE.md §4b, *Determinism*).

`cryptography` supports it from 42.0 when linked against OpenSSL 3.2+. Where it is unavailable we
fall back to randomised nonces — still correct ECDSA, just not reproducible — and
`DETERMINISTIC_SIGNING` records which of the two is in force so a bench sidecar can say so.

Backend
-------
`cryptography` (C/OpenSSL), chosen in M1 on measured throughput against the pure-Python `ecdsa`
package — see `RESULTS.md` and the Q1 entry in the M1 session log. The benchmark lives in
`scripts/bench_ecdsa_backends.py`, not here.

Key encoding
------------
Public keys travel as X9.62 uncompressed points (65 bytes, ``0x04 || X || Y``), which is what
`Block.owner_pubkey` (`OKU`) carries in M2 and what the session protocol puts in its transcript.
Private keys serialise as PKCS#8 DER, unencrypted — these are test fixtures and simulated cloud
servers, never real secrets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

__all__ = [
    "CURVE_NAME",
    "DETERMINISTIC_SIGNING",
    "PUBLIC_KEY_BYTES",
    "SIGNATURE_ALGORITHM",
    "KeyPair",
    "PrivateKey",
    "PublicKey",
    "SignatureError",
    "generate_keypair",
    "keypair_from_secret",
    "load_private_key",
    "load_public_key",
    "sign",
    "signature_from_raw",
    "signature_to_raw",
    "verify",
]

SIGNATURE_ALGORITHM: Final = "ecdsa"
CURVE_NAME: Final = "secp256r1"
#: X9.62 uncompressed point: 0x04 || X(32) || Y(32).
PUBLIC_KEY_BYTES: Final = 65

_CURVE: Final = ec.SECP256R1()
#: Order of the base point of secp256r1 (FIPS 186-4 D.1.2.3), needed to range-check raw secrets.
_ORDER: Final = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class SignatureError(ValueError):
    """Raised when a key or a signature is malformed. A *failed* verification is not an error."""


def _deterministic_supported() -> bool:
    try:
        key = ec.derive_private_key(1, _CURVE)
        key.sign(b"probe", ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    except (UnsupportedAlgorithm, TypeError):  # pragma: no cover - backend-dependent
        return False
    return True


#: Whether RFC 6979 deterministic nonces are in force. Recorded in bench sidecars: a run with
#: randomised nonces is not byte-reproducible and should not be presented as if it were.
DETERMINISTIC_SIGNING: Final = _deterministic_supported()


def _algorithm() -> ec.ECDSA:
    if DETERMINISTIC_SIGNING:
        return ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    return ec.ECDSA(hashes.SHA256())  # pragma: no cover - backend-dependent


@dataclass(frozen=True)
class PublicKey:
    """A secp256r1 public key. `KU_CSl` / `OKU` in docs/NOTATION.md."""

    _key: ec.EllipticCurvePublicKey

    def to_bytes(self) -> bytes:
        """X9.62 uncompressed point — the on-chain and on-the-wire form."""
        return self._key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

    def to_pem(self) -> bytes:
        return self._key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PublicKey) and self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash(self.to_bytes())

    def __repr__(self) -> str:
        return f"PublicKey({self.to_bytes()[1:9].hex()}...)"


@dataclass(frozen=True)
class PrivateKey:
    """A secp256r1 private key. Simulated entity keys and test fixtures only."""

    _key: ec.EllipticCurvePrivateKey

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self._key.public_key())

    def to_der(self) -> bytes:
        """Unencrypted PKCS#8 DER — for loading fixtures, never for real secrets."""
        return self._key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def __repr__(self) -> str:
        # Never render key material, not even truncated.
        return "PrivateKey(<secp256r1>)"


@dataclass(frozen=True)
class KeyPair:
    """A private key and its public key, carried together for readability at call sites."""

    private: PrivateKey
    public: PublicKey


def generate_keypair() -> KeyPair:
    """Generate a fresh keypair from the system CSPRNG.

    CLAUDE.md §4b: tests load fixtures instead of calling this, so that a test run is
    byte-reproducible. Use `keypair_from_secret` to build a fixture.
    """
    private = PrivateKey(ec.generate_private_key(_CURVE))
    return KeyPair(private=private, public=private.public_key)


def keypair_from_secret(secret: int) -> KeyPair:
    """Derive a keypair from a raw scalar — the fixture constructor.

    Deterministic, so a test suite gets the same keys on every machine and every run.
    """
    if not 0 < secret < _ORDER:
        raise SignatureError(f"secret out of range for {CURVE_NAME}")
    private = PrivateKey(ec.derive_private_key(secret, _CURVE))
    return KeyPair(private=private, public=private.public_key)


def load_private_key(data: bytes) -> PrivateKey:
    """Load a PKCS#8 DER private key."""
    try:
        key = serialization.load_der_private_key(data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise SignatureError(f"not a loadable DER private key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != CURVE_NAME:
        raise SignatureError(f"private key is not {CURVE_NAME}")
    return PrivateKey(key)


def load_public_key(data: bytes) -> PublicKey:
    """Load an X9.62 uncompressed point.

    Rejects anything that is not a point on secp256r1 — an invalid-curve point handed to ECDH is
    the standard way to recover a static private key one bit at a time, and `crypto.kem` accepts
    peer keys through exactly this function.
    """
    if len(data) != PUBLIC_KEY_BYTES or data[0] != 0x04:
        raise SignatureError(
            f"public key must be a {PUBLIC_KEY_BYTES}-byte uncompressed X9.62 point"
        )
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, data)
    except ValueError as exc:
        raise SignatureError(f"point is not on {CURVE_NAME}: {exc}") from exc
    return PublicKey(key)


def sign(private: PrivateKey, message: bytes) -> bytes:
    """Sign `message` with ECDSA/SHA-256, returning a DER-encoded signature.

    `message` is signed directly, not pre-hashed by the caller: the backend hashes it. Callers
    that need domain separation must build the pre-image with `crypto.hashing.tagged_h` and pass
    that — see `crypto.session`.
    """
    return private._key.sign(message, _algorithm())


def verify(public: PublicKey, signature: bytes, message: bytes) -> bool:
    """Return whether `signature` is a valid ECDSA/SHA-256 signature by `public` over `message`.

    Returns `False` rather than raising, because a failed verification is an expected protocol
    outcome (a forged block, a replayed session opening) and not an exceptional condition. A
    malformed DER blob is also just `False`; there is no security difference between "invalid"
    and "unparseable" to a caller deciding whether to accept a message.
    """
    try:
        public._key.verify(signature, message, _algorithm())
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def signature_to_raw(signature: bytes) -> bytes:
    """Convert DER to the fixed 64-byte ``r || s`` form used by published test vectors."""
    r, s = decode_dss_signature(signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def signature_from_raw(raw: bytes) -> bytes:
    """Convert a fixed 64-byte ``r || s`` signature to DER."""
    if len(raw) != 64:
        raise SignatureError("raw signature must be 64 bytes (r || s)")
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
