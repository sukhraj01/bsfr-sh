"""Q1 — measure ECDSA sign/verify throughput, `cryptography` vs pure-Python `ecdsa`.

A one-off decision benchmark, not part of the reproduction suite. `PROJECT_STATE.md` Q1 asks
which backend `crypto.ecdsa` should use, and says to decide on speed: every Fig. 6 timing is
downstream of the choice, so a slow signature primitive contaminates Targets 3 and 4. This
script produces the numbers that close it.

It lives in `scripts/` rather than `src/bsfr_sh/bench/` deliberately: `bench/` is the M6 timing
harness for the paper's own targets, and starting it here to answer a library question would put
a milestone's worth of structure in place for a one-afternoon measurement. It is re-runnable, so
the decision stays checkable.

Protocol follows CLAUDE.md §4b: warm-up discarded, median of N repeats, never a single sample.
A sidecar lands in `results/logs/<run_id>.json`, so the RESULTS.md line is traceable.

Usage::

    python scripts/bench_ecdsa_backends.py --seed 20260911 --repeats 7 --operations 200
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

MESSAGE = b"BSFR-SH block header pre-image, 32 bytes:" + b"\x00" * 24


@dataclass(frozen=True)
class Measurement:
    """Median throughput for one backend and one operation."""

    backend: str
    operation: str
    operations: int
    median_seconds: float
    ops_per_second: float
    all_seconds: list[float]


def _median_of(runs: list[float]) -> float:
    return statistics.median(runs)


def bench_cryptography(operations: int, repeats: int, warmup: int) -> list[Measurement]:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.derive_private_key(
        0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721, ec.SECP256R1()
    )
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
    import ecdsa
    from ecdsa.util import sigencode_der, sigdecode_der

    key = ecdsa.SigningKey.from_secret_exponent(
        0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
        curve=ecdsa.NIST256p,
        hashfunc=__import__("hashlib").sha256,
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


def _time_operation(
    backend: str,
    operation: str,
    fn: Any,
    operations: int,
    repeats: int,
    warmup: int,
) -> Measurement:
    for _ in range(warmup):
        for _ in range(operations):
            fn()
    runs: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        for _ in range(operations):
            fn()
        runs.append(time.perf_counter() - start)
    median = _median_of(runs)
    return Measurement(
        backend=backend,
        operation=operation,
        operations=operations,
        median_seconds=median,
        ops_per_second=operations / median,
        all_seconds=runs,
    )


def _git_rev() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=REPO_ROOT,
        )
    except (OSError, subprocess.CalledProcessError):
        return "<unknown>"
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260911)
    parser.add_argument("--repeats", type=int, default=7, help="median of N (CLAUDE.md §4b)")
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--operations", type=int, default=200)
    args = parser.parse_args()

    seed_all(args.seed)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    measurements: list[Measurement] = []
    measurements.extend(bench_cryptography(args.operations, args.repeats, args.warmup))
    try:
        measurements.extend(bench_pure_python(args.operations, args.repeats, args.warmup))
    except ImportError:
        log.event(
            logger,
            "backend_unavailable",
            backend="ecdsa",
            hint="pip install -e '.[dev]' — the comparison is part of the dev extras",
        )

    for measurement in measurements:
        log.event(
            logger,
            "ecdsa_backend_measured",
            backend=measurement.backend,
            operation=measurement.operation,
            ops_per_second=round(measurement.ops_per_second, 1),
            median_seconds=round(measurement.median_seconds, 6),
        )

    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "Q1 — ECDSA backend selection",
        "seed": args.seed,
        "config_hash": None,
        "note": "no config file governs this run; parameters are the CLI arguments below",
        "parameters": {
            "operations": args.operations,
            "repeats": args.repeats,
            "warmup": args.warmup,
            "curve": "secp256r1",
            "hash": "sha-256",
            "deterministic_nonces": True,
        },
        "git_rev": _git_rev(),
        "host": {
            "machine": platform.machine(),
            "processor": platform.processor() or platform.machine(),
            "system": f"{platform.system()} {platform.release()}",
            **log.env_snapshot(),
        },
        "measurements": [asdict(m) for m in measurements],
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{run_id}.json"
    out_path.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log.event(logger, "sidecar_written", path=str(out_path.relative_to(REPO_ROOT)))
    sys.stdout.write(f"{run_id}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
