"""Q1 — ECDSA sign/verify throughput, `cryptography` vs. pure-Python `ecdsa`.

A one-off decision benchmark, not part of the M6 timing harness (`bench.harness`/`bench.emit`):
`PROJECT_STATE.md` Q1 asked which backend `crypto.ecdsa` should use, and said to decide on speed —
every Fig. 6 timing is downstream of the choice, so a slow signature primitive contaminates
Targets 3 and 4. This module produces the numbers that closed it. It stays a small sibling of
`harness.py`/`emit.py` rather than growing into either: those carry Fig. 6's case/sidecar
machinery, and this is a single library comparison with no case structure of its own.

`scripts/bench_ecdsa_backends.py` is the thin CLI wrapper (CLAUDE.md §3): it parses arguments,
seeds, calls `compare_backends()`, and writes the sidecar. The measurement logic lives here so
`make lint`'s `mypy --strict` over `src/` actually covers it (debt D2, closed).

Protocol follows CLAUDE.md §4b: warm-up discarded, median of N repeats, never a single sample.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any, Final

__all__ = [
    "MESSAGE",
    "Measurement",
    "bench_cryptography",
    "bench_pure_python",
    "compare_backends",
    "measurements_as_dicts",
]

MESSAGE: Final = b"BSFR-SH block header pre-image, 32 bytes:" + b"\x00" * 24

#: The fixed scalar every backend signs with (CLAUDE.md §4b — fixture-loaded, never fresh).
_SECRET: Final = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721


@dataclass(frozen=True)
class Measurement:
    """Median throughput for one backend and one operation."""

    backend: str
    operation: str
    operations: int
    median_seconds: float
    ops_per_second: float
    all_seconds: list[float]


def _time_operation(
    backend: str,
    operation: str,
    fn: Callable[[], None],
    operations: int,
    repeats: int,
    warmup: int,
) -> Measurement:
    for _ in range(warmup):
        for _ in range(operations):
            fn()
    runs: list[float] = []
    for _ in range(repeats):
        started = time.perf_counter()
        for _ in range(operations):
            fn()
        runs.append(time.perf_counter() - started)
    median = statistics.median(runs)
    return Measurement(
        backend=backend,
        operation=operation,
        operations=operations,
        median_seconds=median,
        ops_per_second=operations / median,
        all_seconds=runs,
    )


def bench_cryptography(operations: int, repeats: int, warmup: int) -> list[Measurement]:
    """Throughput of `crypto.ecdsa`'s actual backend (`cryptography`, secp256r1/SHA-256)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.derive_private_key(_SECRET, ec.SECP256R1())
    public = key.public_key()
    algorithm = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    signature = key.sign(MESSAGE, algorithm)

    def do_sign() -> None:
        key.sign(MESSAGE, algorithm)

    def do_verify() -> None:
        public.verify(signature, MESSAGE, algorithm)

    return [
        _time_operation("cryptography", "sign", do_sign, operations, repeats, warmup),
        _time_operation("cryptography", "verify", do_verify, operations, repeats, warmup),
    ]


def bench_pure_python(operations: int, repeats: int, warmup: int) -> list[Measurement]:
    """Throughput of the pure-Python `ecdsa` package, the alternative Q1 ruled out."""
    import hashlib

    import ecdsa
    from ecdsa.util import sigdecode_der, sigencode_der

    key = ecdsa.SigningKey.from_secret_exponent(
        _SECRET, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256
    )
    public = key.get_verifying_key()
    signature = key.sign_deterministic(MESSAGE, sigencode=sigencode_der)

    def do_sign() -> None:
        key.sign_deterministic(MESSAGE, sigencode=sigencode_der)

    def do_verify() -> None:
        public.verify(signature, MESSAGE, sigdecode=sigdecode_der)

    return [
        _time_operation("ecdsa (pure python)", "sign", do_sign, operations, repeats, warmup),
        _time_operation("ecdsa (pure python)", "verify", do_verify, operations, repeats, warmup),
    ]


def compare_backends(
    *, operations: int, repeats: int, warmup: int
) -> tuple[list[Measurement], bool]:
    """Both backends' measurements, plus whether the pure-Python one was available at all.

    `ecdsa` is a dev-only extra (`pyproject.toml`); a `make test`-only environment need not have
    it, so its absence is reported rather than raised — same behaviour the script always had.
    """
    measurements = list(bench_cryptography(operations, repeats, warmup))
    try:
        measurements.extend(bench_pure_python(operations, repeats, warmup))
        available = True
    except ImportError:
        available = False
    return measurements, available


def measurements_as_dicts(measurements: list[Measurement]) -> list[dict[str, Any]]:
    """`asdict()` over every measurement, for the sidecar JSON."""
    return [asdict(m) for m in measurements]
