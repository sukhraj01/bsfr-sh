"""`bench.ecdsa_backends` — Q1's decision benchmark, moved out of `scripts/` closing debt D2.

No timing assertions (see `test_bench_harness.py`'s docstring on why): these check shape and
plumbing — both backends produce sign/verify measurements, a missing pure-Python `ecdsa` is
reported rather than raised, and the sidecar dict shape round-trips through `asdict`.
"""

from __future__ import annotations

from bsfr_sh.bench.ecdsa_backends import (
    Measurement,
    bench_cryptography,
    compare_backends,
    measurements_as_dicts,
)


def test_bench_cryptography_measures_sign_and_verify() -> None:
    measurements = bench_cryptography(operations=5, repeats=2, warmup=1)
    ops = {(m.backend, m.operation) for m in measurements}
    assert ops == {("cryptography", "sign"), ("cryptography", "verify")}
    for m in measurements:
        assert m.operations == 5
        assert len(m.all_seconds) == 2
        assert m.median_seconds >= 0.0
        assert m.ops_per_second > 0.0


def test_compare_backends_always_includes_cryptography() -> None:
    measurements, available = compare_backends(operations=5, repeats=2, warmup=1)
    backends = {m.backend for m in measurements}
    assert "cryptography" in backends
    # The pure-Python `ecdsa` package is a dev extra (pyproject.toml); when present its four
    # measurements (sign/verify x this backend) are included and `available` says so.
    if available:
        assert "ecdsa (pure python)" in backends
        assert len(measurements) == 4
    else:
        assert len(measurements) == 2


def test_measurements_as_dicts_round_trips_every_field() -> None:
    sample = [
        Measurement(
            backend="cryptography",
            operation="sign",
            operations=5,
            median_seconds=0.001,
            ops_per_second=5000.0,
            all_seconds=[0.001, 0.0011],
        )
    ]
    (encoded,) = measurements_as_dicts(sample)
    assert encoded == {
        "backend": "cryptography",
        "operation": "sign",
        "operations": 5,
        "median_seconds": 0.001,
        "ops_per_second": 5000.0,
        "all_seconds": [0.001, 0.0011],
    }
