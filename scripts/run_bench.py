"""M6a: run the timing harness end to end and emit Figs. 6(a)-(d).

Order of operations, each a plain function call into `bsfr_sh.bench.harness` /
`bsfr_sh.bench.emit` — this script wires them together and does no measurement itself:

1. Variance probe at case-3, both chains — decides the repeat count (`decide_repeat_count`)
   instead of trusting `configs/bench.yaml`'s declared floor blindly.
2. The full case x chain matrix at that repeat count (`run_case`).
3. A check of whether the case-1-to-case-3 trend is resolvable above the measured noise
   (`trend_resolvable`) — reported either way, not only when it comes out favourably.
4. The modelled-network formula (DEV-21) verified against one real non-zero-delay run, then
   applied at the declared illustrative delays (`configs/bench.yaml` `network.*`).
5. D3's serialization-cost estimate, from one representative committed block per chain.
6. The Q2 payload-size sweep at case-3, with the in-memory footprint projected before every size
   actually runs, closing the open question at `configs/chain.yaml`'s declared default.
7. Sidecars in `results/logs/`, `RESULTS.md` candidate lines printed to stdout (this project's
   convention — see `scripts/run_phase3_detection.py` — is that a human reviews and appends
   them, so a bad run can never self-report), and Figs. 6(a)-(d) plus the component-breakdown
   panel via `bsfr_sh.bench.emit`.

Usage::

    python scripts/run_bench.py --seed 20260917
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bsfr_sh.bench import emit  # noqa: E402
from bsfr_sh.bench import harness  # noqa: E402
from bsfr_sh.blockchain.chain import BC_DTBU  # noqa: E402
from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, combined_config_hash, config_hash  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

#: Independent runs at case-3 used only to measure spread, before deciding how many of the
#: *reported* repeats to run. Fixed rather than config-driven: this is a property of the
#: measurement process, not of what is being measured.
_VARIANCE_PROBES = 12

#: Small scale for `verify_modelled_network_formula` — only the bus's simulated clock is being
#: checked, so there is no reason to pay case-3's real cost for it.
_VERIFY_BLOCKS = 5
_VERIFY_TX = 20


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


def _host() -> dict[str, Any]:
    return {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260917)
    parser.add_argument(
        "--no-figures", action="store_true", help="skip bsfr_sh.bench.emit (measurement only)"
    )
    args = parser.parse_args()

    bench_config = load_config(REPO_ROOT / "configs" / "bench.yaml", expected_kind="bench")
    chain_config = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
    policy = harness.BenchPolicy.from_config(bench_config, chain_config)

    seed_all(args.seed)
    run_id = log.configure()
    logger = log.get_logger(__name__)
    started_at = time.time()

    # -- 1. variance probe at case-3 ------------------------------------------------------------
    case3_blocks = policy.case_blocks["case_3"]
    variance: dict[str, harness.VarianceReport] = {}
    for chain in policy.chains:
        samples = tuple(
            harness.run_once(
                chain_name=chain,
                blocks=case3_blocks,
                transactions_per_block=policy.transactions_per_block,
                payload_bytes=policy.payload_bytes,
                pbft_policy=policy.pbft,
                seed=args.seed + 500_000 + k,
                tag=f"variance-{chain}-{k}",
            ).total_compute_seconds
            for k in range(_VARIANCE_PROBES)
        )
        variance[chain] = harness.VarianceReport(chain_name=chain, case="case_3", samples=samples)
        log.event(
            logger,
            "variance_probe",
            chain=chain,
            probes=_VARIANCE_PROBES,
            mean_seconds=round(variance[chain].mean_seconds, 5),
            stdev_seconds=round(variance[chain].stdev_seconds, 5),
            cv=round(variance[chain].coefficient_of_variation, 4),
        )

    worst_cv = max(v.coefficient_of_variation for v in variance.values())
    repeats = harness.decide_repeat_count(worst_cv, floor=policy.repeats)
    log.event(logger, "repeat_count_decided", worst_cv=round(worst_cv, 4), repeats=repeats)

    # -- 2. the case x chain matrix ------------------------------------------------------------
    matrix: dict[tuple[str, str], harness.CaseResult] = {}
    for case in policy.cases:
        blocks = policy.case_blocks[case]
        for chain in policy.chains:
            result = harness.run_case(
                case=case,
                chain_name=chain,
                blocks=blocks,
                transactions_per_block=policy.transactions_per_block,
                payload_bytes=policy.payload_bytes,
                pbft_policy=policy.pbft,
                base_seed=args.seed + 10_000 * (hash((case, chain)) % 97),
                repeats=repeats,
                warmup_runs=policy.warmup_runs,
            )
            matrix[(case, chain)] = result
            log.event(
                logger,
                "case_measured",
                case=case,
                chain=chain,
                blocks=blocks,
                median_seconds=round(result.median_total_seconds, 5),
                stdev_seconds=round(result.stdev_seconds, 5),
                tps=round(result.tps, 1),
                index_seconds=(
                    round(result.index_seconds, 5) if result.index_seconds is not None else None
                ),
            )

    # -- 3. is the trend resolvable above the noise? -------------------------------------------
    trend: dict[str, bool] = {}
    for chain in policy.chains:
        trend[chain] = harness.trend_resolvable(
            variance[chain],
            other_case_median_seconds=matrix[("case_1", chain)].median_total_seconds,
            repeats=repeats,
        )
        log.event(logger, "trend_resolvable", chain=chain, resolvable=trend[chain])

    # -- 4. modelled network: verify the formula, then apply it at declared delays -------------
    verify_predicted, verify_actual = harness.verify_modelled_network_formula(
        chain_name=BC_DTBU,
        blocks=_VERIFY_BLOCKS,
        transactions_per_block=_VERIFY_TX,
        pbft_policy=policy.pbft,
        delay_s=0.01,
        seed=args.seed + 999,
    )
    formula_verified = abs(verify_predicted - verify_actual) < 1e-9
    log.event(
        logger,
        "network_formula_verified",
        predicted=verify_predicted,
        actual=verify_actual,
        verified=formula_verified,
    )
    modelled_network = {
        case: {
            delay: harness.modelled_network_seconds(
                blocks=policy.case_blocks[case], delay_s=delay
            )
            for delay in policy.modelled_delay_sweep_s
        }
        for case in policy.cases
    }

    # -- 5. D3 — serialization estimate, one representative block per chain --------------------
    d3: dict[str, dict[str, float]] = {}
    for chain in policy.chains:
        support = harness.run_once(
            chain_name=chain,
            blocks=case3_blocks,
            transactions_per_block=policy.transactions_per_block,
            payload_bytes=policy.payload_bytes,
            pbft_policy=policy.pbft,
            seed=args.seed + 700_001,
            tag=f"d3-support-{chain}",
        )
        per_block = harness.estimate_block_encode_seconds(support.last_block)
        total = harness.estimate_d3_seconds(per_block, case3_blocks)
        overhead_factor = harness.estimate_overhead_factor(
            policy.payload_bytes, support, transactions_per_block=policy.transactions_per_block
        )
        d3[chain] = {
            "per_block_encode_seconds": per_block,
            "case3_total_seconds": total,
            "case3_compute_seconds": matrix[("case_3", chain)].median_total_seconds,
            "overhead_factor": overhead_factor,
        }
        log.event(
            logger,
            "d3_estimated",
            chain=chain,
            per_block_encode_seconds=round(per_block, 6),
            case3_total_seconds=round(total, 6),
            fraction_of_measured_compute=round(total / d3[chain]["case3_compute_seconds"], 5),
        )

    # -- 6. Q2 payload sweep, memory projected before running ----------------------------------
    q2: dict[str, dict[int, harness.CaseResult]] = {chain: {} for chain in policy.chains}
    q2_repeats = max(3, min(repeats, 5))
    for payload_bytes in policy.payload_bytes_sensitivity:
        projected = (
            harness.projected_chain_bytes(
                payload_bytes=payload_bytes,
                transactions_per_block=policy.transactions_per_block,
                blocks=case3_blocks,
                overhead_factor=max(d3[c]["overhead_factor"] for c in policy.chains),
            )
            * policy.pbft.replicas
        )
        log.event(
            logger,
            "q2_projected",
            payload_bytes=payload_bytes,
            projected_cluster_bytes=projected,
            projected_cluster_mib=round(projected / 2**20, 1),
        )
        for chain in policy.chains:
            q2[chain][payload_bytes] = harness.run_case(
                case="case_3",
                chain_name=chain,
                blocks=case3_blocks,
                transactions_per_block=policy.transactions_per_block,
                payload_bytes=payload_bytes,
                pbft_policy=policy.pbft,
                base_seed=args.seed + 800_000 + payload_bytes,
                repeats=q2_repeats,
                warmup_runs=1,
            )

    ten_mb_projection = (
        harness.projected_chain_bytes(
            payload_bytes=10 * 2**20,
            transactions_per_block=policy.transactions_per_block,
            blocks=case3_blocks,
            overhead_factor=max(d3[c]["overhead_factor"] for c in policy.chains),
        )
        * policy.pbft.replicas
    )
    log.event(
        logger,
        "q2_closed",
        declared_default_bytes=policy.payload_bytes,
        ten_mb_payload_projected_cluster_gib=round(ten_mb_projection / 2**30, 1),
    )

    # -- 7. sidecars, RESULTS.md lines, figures -------------------------------------------------
    combined_hash = combined_config_hash(
        {
            "bench": config_hash(bench_config.kind, bench_config.data),
            "chain": config_hash(chain_config.kind, chain_config.data),
        }
    )
    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M6a — timing harness, Figs. 6(a)-(d), docs/EXPERIMENTS.md Targets 3-4",
        "seed": args.seed,
        "config_hash": combined_hash,
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": _host(),
        "started_at": started_at,
        "wall_seconds": time.time() - started_at,
        "repeats": repeats,
        "warmup_runs": policy.warmup_runs,
        "variance": {
            chain: {
                "probes": _VARIANCE_PROBES,
                "mean_seconds": v.mean_seconds,
                "stdev_seconds": v.stdev_seconds,
                "cv": v.coefficient_of_variation,
            }
            for chain, v in variance.items()
        },
        "trend_resolvable": trend,
        "matrix": {
            f"{case}/{chain}": {
                "blocks": r.blocks,
                "median_total_seconds": r.median_total_seconds,
                "stdev_seconds": r.stdev_seconds,
                "marginal_seconds": list(r.marginal_seconds),
                "tps": r.tps,
                "index_seconds": r.index_seconds,
                "totals_seconds": list(r.totals_seconds),
            }
            for (case, chain), r in matrix.items()
        },
        "network_formula": {
            "verified": formula_verified,
            "predicted_seconds": verify_predicted,
            "actual_seconds": verify_actual,
            "blocks": _VERIFY_BLOCKS,
            "delay_s": 0.01,
        },
        "modelled_network": {
            case: {str(delay): vars(mn) for delay, mn in by_delay.items()}
            for case, by_delay in modelled_network.items()
        },
        "d3": d3,
        "q2": {
            chain: {
                str(payload): {
                    "median_total_seconds": r.median_total_seconds,
                    "repeats": r.repeats,
                }
                for payload, r in by_payload.items()
            }
            for chain, by_payload in q2.items()
        },
        "q2_ten_mb_projected_cluster_gib": round(ten_mb_projection / 2**30, 2),
        "q2_declared_default_bytes": policy.payload_bytes,
    }

    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(matrix, variance, d3, q2, run_id)

    if not args.no_figures:
        report = emit.emit_all(
            matrix=matrix,
            policy=policy,
            sidecar_meta=sidecar,
            figures_dir=REPO_ROOT / bench_config.require("output.figures_dir", str),
            tables_dir=REPO_ROOT / bench_config.require("output.tables_dir", str),
        )
        log.event(
            logger,
            "figures_emitted",
            figures=[str(p.relative_to(REPO_ROOT)) for p in report.figures],
            tables=[str(p.relative_to(REPO_ROOT)) for p in report.tables],
        )

    return 0


def _print_results_lines(
    matrix: dict[tuple[str, str], harness.CaseResult],
    variance: dict[str, harness.VarianceReport],
    d3: dict[str, dict[str, float]],
    q2: dict[str, dict[int, harness.CaseResult]],
    run_id: str,
) -> None:
    date = time.strftime("%Y-%m-%d")
    lines: list[str] = []
    for (case, chain), r in matrix.items():
        marginal = ", ".join(f"{s:.4f}" for s in r.marginal_seconds[:3]) + (
            ", ..." if r.blocks > 3 else ""
        )
        note = "Target 3/4; marginal[:3]=" + marginal
        lines.append(
            f"{date} | bench/target3-time | {chain} {case} {r.blocks}blk x "
            f"{r.transactions_per_block}tx, n={r.repeats} | "
            f"seconds={r.median_total_seconds:.5f} stdev={r.stdev_seconds:.5f} "
            f"tps={r.tps:.1f} | measured | {run_id} | {note}"
        )
        if r.index_seconds is not None:
            lines.append(
                f"{date} | bench/index-construction | {chain} {case} | "
                f"seconds={r.index_seconds:.5f} | measured | {run_id} | DEV-05, outside the "
                f"timed append span"
            )
    for chain, v in variance.items():
        lines.append(
            f"{date} | bench/variance-case3 | {chain} n={len(v.samples)} | "
            f"mean={v.mean_seconds:.5f} stdev={v.stdev_seconds:.5f} cv={v.coefficient_of_variation:.4f} | "
            f"measured | {run_id} | drives the repeat count, not a Fig. 6 datapoint"
        )
    for chain, values in d3.items():
        lines.append(
            f"{date} | bench/d3-serialization | {chain} case_3 15blk | "
            f"encode_per_block={values['per_block_encode_seconds']:.6f} "
            f"case3_total={values['case3_total_seconds']:.6f} "
            f"fraction_of_compute={values['case3_total_seconds'] / values['case3_compute_seconds']:.5f} | "
            f"computed | {run_id} | D3, lower bound, encode only"
        )
    for chain, by_payload in q2.items():
        parts = " ".join(
            f"{p}B={r.median_total_seconds:.4f}s" for p, r in sorted(by_payload.items())
        )
        lines.append(
            f"{date} | bench/q2-payload-sweep | {chain} case_3 | {parts} | measured | {run_id} | "
            f"Q2 closed, default stays 4096B (DEV-15)"
        )
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    for line in lines:
        sys.stdout.write(line + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
