"""Q1 — measure ECDSA sign/verify throughput, `cryptography` vs pure-Python `ecdsa`.

Thin CLI wrapper (CLAUDE.md §3): the comparison itself lives in
`bsfr_sh.bench.ecdsa_backends.compare_backends`, which `make lint`'s `mypy --strict` over `src/`
now covers (debt D2, closed — this script used to hold that logic, uncovered).

A sidecar lands in `results/logs/<run_id>.json`, so the RESULTS.md line is traceable.

Usage::

    python scripts/bench_ecdsa_backends.py --seed 20260911 --repeats 7 --operations 200
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bsfr_sh.bench.ecdsa_backends import compare_backends, measurements_as_dicts  # noqa: E402
from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402


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

    measurements, pure_python_available = compare_backends(
        operations=args.operations, repeats=args.repeats, warmup=args.warmup
    )
    if not pure_python_available:
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
        # A config hash is only comparable against another hash built the same way. The
        # construction changed in M2a (scheme 1 -> 2: the pre-image now goes through `tagged_h`,
        # so every config digest changed value without any config file changing), so the scheme
        # is recorded alongside the digest. Without it, M6 comparing a new hash to an old one
        # would read a version difference as config drift and go looking for a config that
        # never moved.
        "config_hash_scheme": CONFIG_HASH_SCHEME,
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
        "measurements": measurements_as_dicts(measurements),
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
