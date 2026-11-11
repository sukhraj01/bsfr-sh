"""Phase 2 / P2-A: where does the paper's *rising* TPS curve come from?

Phase 1 (M6a, DEV-08) measured flat TPS where the paper's Fig. 6(c)/(d) rises, and argued the
paper's rise is fixed setup cost amortised over more blocks. That was an argument from arithmetic.
This script tests it three ways:

1. **Fit the paper's own six points** to ``time = fixed + per_block * blocks``. If the fit is good
   and ``fixed`` is large, the paper's curve *is* a fixed cost plus a flat per-block cost. The fit
   also predicts a TPS ceiling, ``tx_per_block / per_block``, that the paper's "TPS rises with
   chain size" can never exceed.
2. **Inner timer** (what Phase 1 measured): stopwatch around each block only, cluster already built.
3. **Whole-program timer**: a fresh Python process per run, stopwatch from *outside* the process,
   so interpreter start-up, library imports, key derivation and cluster construction all fall
   inside the timer, the way a naive "time the whole program" measurement would. No cost is
   injected; whatever fixed cost appears is real.

Usage::

    python scripts/p2a_tps_fixed_cost.py --seed 20261112
    python scripts/p2a_tps_fixed_cost.py --child BC_DTBU 5 20261112   # internal, one cold run
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

_T_PROCESS = time.perf_counter()  # first line that runs in a child, before any heavy import

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

#: Fig. 6(a)-(d), `docs/EXPERIMENTS.md` Targets 3-4 (paper_reported).
PAPER_SECONDS = {
    "BC_DTBU": {5: 3.10, 10: 4.17, 15: 5.71},
    "BC_SigRW": {5: 4.36, 10: 5.54, 15: 6.76},
}
PAPER_TPS = {"BC_DTBU": {5: 161, 10: 240, 15: 263}, "BC_SigRW": {5: 115, 10: 181, 15: 222}}
TX_PER_BLOCK = 100
BLOCKS = (5, 10, 15)
REPEATS = 5


def linear_fit(xs: list[float], ys: list[float]) -> dict[str, float]:
    """Least-squares ``y = fixed + slope * x`` with R^2. Pure arithmetic, no numpy needed."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True))
    slope = sxy / sxx
    fixed = my - slope * mx
    ss_res = sum((y - (fixed + slope * x)) ** 2 for x, y in zip(xs, ys, strict=True))
    ss_tot = sum((y - my) ** 2 for y in ys)
    return {"fixed_s": fixed, "per_block_s": slope, "r2": 1.0 - ss_res / ss_tot}


def _child(chain: str, blocks: int, seed: int) -> None:
    """One cold run. Prints a JSON line with the in-process breakdown."""
    from bsfr_sh.bench import harness
    from bsfr_sh.util.config import load_config

    t_imported = time.perf_counter()
    bench_config = load_config(REPO_ROOT / "configs" / "bench.yaml", expected_kind="bench")
    chain_config = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
    policy = harness.BenchPolicy.from_config(bench_config, chain_config)
    t_run0 = time.perf_counter()
    m = harness.run_once(
        chain_name=chain,
        blocks=blocks,
        transactions_per_block=policy.transactions_per_block,
        payload_bytes=policy.payload_bytes,
        pbft_policy=policy.pbft,
        seed=seed,
        tag=f"p2a-{chain}-{blocks}",
    )
    t_end = time.perf_counter()
    blocks_s = m.total_compute_seconds
    index_s = m.index_seconds or 0.0
    print(
        json.dumps(
            {
                "import_s": t_imported - _T_PROCESS,
                "config_s": t_run0 - t_imported,
                "setup_s": (t_end - t_run0) - blocks_s - index_s,  # keys + genesis + cluster
                "blocks_s": blocks_s,
                "index_s": index_s,
            }
        )
    )


def _cold_run(chain: str, blocks: int, seed: int) -> dict[str, float]:
    started = time.perf_counter()
    out = subprocess.run(
        [sys.executable, __file__, "--child", chain, str(blocks), str(seed)],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    )
    wall = time.perf_counter() - started
    breakdown = json.loads(out.stdout.strip().splitlines()[-1])
    return {"wall_s": wall, **breakdown}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261112)
    parser.add_argument("--child", nargs=3, metavar=("CHAIN", "BLOCKS", "SEED"))
    args = parser.parse_args()
    if args.child:
        _child(args.child[0], int(args.child[1]), int(args.child[2]))
        return 0

    from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, combined_config_hash, config_hash
    from bsfr_sh.util import logging as log
    from bsfr_sh.util.config import load_config
    from bsfr_sh.util.seeding import seed_all

    seed_all(args.seed)
    run_id = log.configure()
    bench_config = load_config(REPO_ROOT / "configs" / "bench.yaml", expected_kind="bench")
    chain_config = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")

    # 1. the paper's own numbers -------------------------------------------------------------
    paper_fit = {
        c: linear_fit([float(b) for b in BLOCKS], [PAPER_SECONDS[c][b] for b in BLOCKS])
        for c in PAPER_SECONDS
    }

    # 2 + 3. our runs: one warm-up cold run per chain, then REPEATS per cell -------------------
    rows: list[dict[str, Any]] = []
    for chain in ("BC_DTBU", "BC_SigRW"):
        _cold_run(chain, BLOCKS[0], args.seed)  # warm-up (disk cache, .pyc), discarded
        for blocks in BLOCKS:
            runs = [_cold_run(chain, blocks, args.seed + k) for k in range(REPEATS)]
            med = {k: statistics.median(r[k] for r in runs) for k in runs[0]}
            tx = blocks * TX_PER_BLOCK
            rows.append(
                {
                    "chain": chain,
                    "blocks": blocks,
                    "transactions": tx,
                    **{f"median_{k}": v for k, v in med.items()},
                    "tps_inner": tx / med["blocks_s"],
                    "tps_whole_program": tx / med["wall_s"],
                    "paper_seconds": PAPER_SECONDS[chain][blocks],
                    "paper_tps": PAPER_TPS[chain][blocks],
                    "wall_samples": [r["wall_s"] for r in runs],
                }
            )
            sys.stderr.write(f"{chain} {blocks:>2} blocks: {med}\n")

    our_fit: dict[str, dict[str, dict[str, float]]] = {}
    for chain in ("BC_DTBU", "BC_SigRW"):
        sub = [r for r in rows if r["chain"] == chain]
        xs = [float(r["blocks"]) for r in sub]
        our_fit[chain] = {
            "inner": linear_fit(xs, [r["median_blocks_s"] for r in sub]),
            "whole_program": linear_fit(xs, [r["median_wall_s"] for r in sub]),
        }

    # outputs ------------------------------------------------------------------------------
    tables = REPO_ROOT / "results" / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    cols = [
        "chain", "blocks", "transactions", "paper_seconds", "paper_tps", "median_blocks_s",
        "tps_inner", "median_wall_s", "tps_whole_program", "median_import_s", "median_setup_s",
    ]  # fmt: skip
    lines = [",".join(cols)]
    for r in rows:
        lines.append(",".join(f"{r[c]:.4f}" if isinstance(r[c], float) else str(r[c]) for c in cols))
    (tables / "p2a_tps_fixed_cost.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")

    sidecar = {
        "run_id": run_id,
        "purpose": "P2-A: fixed setup cost as the source of the paper's rising TPS",
        "seed": args.seed,
        "repeats": REPEATS,
        "config_hash": combined_config_hash(
            {
                "bench": config_hash(bench_config.kind, bench_config.data),
                "chain": config_hash(chain_config.kind, chain_config.data),
            }
        ),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=REPO_ROOT
        ).stdout.strip(),
        "host": log.env_snapshot(),
        "paper_fit": paper_fit,
        "our_fit": our_fit,
        "rows": rows,
    }
    logs = REPO_ROOT / "results" / "logs"
    (logs / f"{run_id}.json").write_text(json.dumps(sidecar, indent=2, default=float) + "\n")

    _figure(rows, paper_fit, REPO_ROOT / "results" / "figures" / "p2a_tps_fixed_cost.png")
    print(json.dumps({"run_id": run_id, "paper_fit": paper_fit, "our_fit": our_fit}, indent=2))
    return 0


def _figure(rows: list[dict[str, Any]], paper_fit: dict[str, dict[str, float]], out: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for ax, chain in zip(axes, ("BC_DTBU", "BC_SigRW"), strict=True):
        sub = [r for r in rows if r["chain"] == chain]
        xs = [r["blocks"] for r in sub]

        def rel(vals: list[float]) -> list[float]:
            return [v / vals[0] for v in vals]

        ax.plot(xs, rel([r["paper_tps"] for r in sub]), "o-", color="#b22222", label="Paper")
        ax.plot(xs, rel([r["tps_whole_program"] for r in sub]), "s-", color="#1f4e9c",
                label="Ours: whole-program timer")  # fmt: skip
        ax.plot(xs, rel([r["tps_inner"] for r in sub]), "^--", color="#888888",
                label="Ours: per-block timer (Phase 1)")  # fmt: skip
        ax.set_title(f"{chain}: TPS relative to case 1")
        ax.set_xlabel("blocks mined (case 1 / 2 / 3)")
        ax.set_xticks(xs)
        ax.set_ylabel("TPS / TPS at 5 blocks")
        ax.axhline(1.0, color="#cccccc", lw=0.8)
        ax.grid(alpha=0.3)
        f = paper_fit[chain]
        ax.text(0.02, 0.97, f"paper fit: {f['fixed_s']:.2f}s fixed + {f['per_block_s']:.3f}s/block"
                f"\nR²={f['r2']:.3f}, TPS ceiling ≈ {TX_PER_BLOCK / f['per_block_s']:.0f} tx/s",
                transform=ax.transAxes, va="top", fontsize=8)  # fmt: skip
    axes[0].legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out, dpi=150)


if __name__ == "__main__":
    raise SystemExit(main())
