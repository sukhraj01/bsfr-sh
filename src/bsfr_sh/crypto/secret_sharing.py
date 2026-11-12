"""Shamir secret sharing over GF(2^8) — Phase 2 / P2-F (DEV-48), not part of the paper.

Why this exists
---------------
Every backup on `BC_DTBU` is encrypted to exactly one cloud server's key (DEV-01, DEV-25): the
chain keeps four copies of the *ciphertext*, but the key that opens it exists once. Lose that one
server to ransomware and every backup it collected is unreadable; compromise it and every backup
it collected is readable from any replica's copy of the chain. Splitting each backup's data key
into `n` shares, any `t` of which rebuild it, removes that single point of failure.

The construction
----------------
Standard Shamir, one independent polynomial per byte of the secret, over GF(2^8) with the AES
reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11B). Byte-wise sharing keeps every share exactly
as long as the secret, so a share of a 32-byte AES key is itself 32 bytes and can be wrapped by
`crypto.kem.wrap_key` unchanged. Share `i` is the polynomial evaluated at `x = i` (1..255); the
secret is the value at `x = 0`, recovered by Lagrange interpolation.

Properties relied on, and their limits
--------------------------------------
* Any `t` distinct shares rebuild the secret exactly.
* Fewer than `t` shares are consistent with *every* possible secret, so they reveal nothing about
  it (information-theoretic, provided the coefficients are uniformly random).
* `combine` cannot tell whether it was given enough shares: fewer than `t` simply produce a wrong
  value. Callers detect that downstream; `crypto.threshold_kem` does so with the AEAD tag.
* No verifiability: a malicious share holder can hand over a wrong share. That is detected (the
  AEAD tag fails) but not attributed. Verifiable secret sharing is out of scope.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

__all__ = ["MAX_SHARES", "SecretSharingError", "Share", "combine", "split"]

MAX_SHARES: Final = 255
_REDUCTION: Final = 0x11B


def _tables() -> tuple[tuple[int, ...], tuple[int, ...]]:
    exp = [0] * 510
    log = [0] * 256
    value = 1
    for power in range(255):
        exp[power] = value
        log[value] = power
        # multiply by the generator 3 (= x + 1)
        value ^= value << 1
        if value & 0x100:
            value ^= _REDUCTION
    for power in range(255, 510):
        exp[power] = exp[power - 255]
    return tuple(exp), tuple(log)


_EXP, _LOG = _tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(2^8)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


class SecretSharingError(ValueError):
    """Bad parameters or malformed shares."""


@dataclass(frozen=True)
class Share:
    """One share: the evaluation point `index` (1..255) and one byte per secret byte."""

    index: int
    value: bytes

    def __post_init__(self) -> None:
        if not 1 <= self.index <= MAX_SHARES:
            raise SecretSharingError(f"share index must be in 1..{MAX_SHARES}, got {self.index}")


def split(
    secret: bytes,
    *,
    shares: int,
    threshold: int,
    randbytes: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[Share, ...]:
    """Split `secret` into `shares` shares, any `threshold` of which rebuild it.

    `randbytes` supplies the polynomial coefficients. The default is the OS CSPRNG; tests inject
    a seeded source so runs are reproducible (CLAUDE.md §4b). A non-uniform source voids the
    "fewer than t shares reveal nothing" property.
    """
    if not secret:
        raise SecretSharingError("cannot share an empty secret")
    if not 1 <= threshold <= shares <= MAX_SHARES:
        raise SecretSharingError(
            f"need 1 <= threshold <= shares <= {MAX_SHARES}, got threshold={threshold}, "
            f"shares={shares}"
        )
    # coefficients[d][j] = coefficient of x^d for secret byte j; degree 0 is the secret itself
    coefficients = [secret] + [randbytes(len(secret)) for _ in range(threshold - 1)]
    if any(len(c) != len(secret) for c in coefficients):
        raise SecretSharingError("randbytes returned the wrong number of bytes")
    out = []
    for x in range(1, shares + 1):
        value = bytearray(len(secret))
        for j in range(len(secret)):
            acc = 0
            for degree in range(threshold - 1, -1, -1):  # Horner
                acc = _mul(acc, x) ^ coefficients[degree][j]
            value[j] = acc
        out.append(Share(index=x, value=bytes(value)))
    return tuple(out)


def combine(shares: Sequence[Share]) -> bytes:
    """Rebuild the secret from shares by Lagrange interpolation at x = 0.

    Given at least the threshold number of distinct shares, returns the secret. Given fewer,
    returns some unrelated value — this function cannot know the threshold.
    """
    if not shares:
        raise SecretSharingError("no shares given")
    indices = [s.index for s in shares]
    if len(set(indices)) != len(indices):
        raise SecretSharingError(f"duplicate share indices: {sorted(indices)}")
    length = len(shares[0].value)
    if any(len(s.value) != length for s in shares):
        raise SecretSharingError("shares have different lengths")
    # Lagrange basis at 0: prod_{m != j} x_m / (x_m - x_j); subtraction is XOR in GF(2^8)
    weights = []
    for j, xj in enumerate(indices):
        num, den = 1, 1
        for m, xm in enumerate(indices):
            if m != j:
                num = _mul(num, xm)
                den = _mul(den, xm ^ xj)
        weights.append(_div(num, den))
    secret = bytearray(length)
    for share, weight in zip(shares, weights, strict=True):
        for k in range(length):
            secret[k] ^= _mul(share.value[k], weight)
    return bytes(secret)
