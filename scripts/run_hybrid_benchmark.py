"""M7-5: hybrid vs private-only — the case matrix, both chains, anchor frequency sweep.

Mirrors `scripts/run_consensus_comparison.py`'s shape (sidecar JSON, `RESULTS.md` candidate lines
printed for a human to review and append) and reuses `bench.harness`'s cluster/transaction-builder
machinery without touching M6a's own call sites, same discipline that script follows.

What this measures
-------------------
For cases 1-3, both chains, serialization ON (M6a's condition after DEV-30), at anchor frequency
1/5/10:

1. **Private-only total time** — `bench.harness.run_once`'s own span (block construction +
   consensus + append), completely unmodified. This is the M6a/M7-4 baseline number, not a new
   measurement.
2. **Hybrid total time** — the identical private-chain commit, immediately followed by one
   `HybridChain.sync()` + `flush()` pair (exactly `framework.hybrid_pipeline.append`'s own
   sequence), timed together. The private-chain span is therefore byte-for-byte the same work as
   (1); what's added is only the anchor step.
3. **Anchor overhead** — `(hybrid - private_only) / private_only`, as a percentage.
4. **Anchor chain storage cost** — total encoded bytes of every committed anchor block (never the
   private chain's own bytes), plus bytes/anchor. Expected to be tiny: an anchor transaction
   carries one `AnchorRecord` (two 32-byte hashes, a height, a timestamp, an id, a pubkey, a
   signature — a few hundred bytes), not a payload.

Usage::

    python scripts/run_hybrid_benchmark.py --seed 20260925
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

from bsfr_sh.bench import harness  # noqa: E402
from bsfr_sh.blockchain.chain import BC_DTBU  # noqa: E402
from bsfr_sh.blockchain.hybrid import AnchorPolicy, HybridChain  # noqa: E402
from bsfr_sh.consensus.pbft import PBFTPolicy  # noqa: E402
from bsfr_sh.crypto.ecdsa import keypair_from_secret  # noqa: E402
from bsfr_sh.crypto.hashing import (  # noqa: E402
    CONFIG_HASH_SCHEME,
    combined_config_hash,
    config_hash,
)
from bsfr_sh.framework import _block_pipeline as pipeline  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

#: Modest, independent of `configs/bench.yaml`'s M6a variance-driven floor — same reasoning
#: `run_consensus_comparison.py` gives: the overhead/storage figures here do not need M6a's
#: repeat inflation to be visible cell to cell.
_REPEATS = 5
_WARMUP = 1
_FREQUENCIES = (1, 5, 10)
_ANCHOR_KEY_OFFSET = 777_001


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


def _anchor_chain_bytes(hybrid: HybridChain) -> int:
    """Total encoded bytes of every anchor block, genesis excluded (it carries no anchors)."""
    return sum(
        len(hybrid.anchor_chain.block_at(h).encoded())
        for h in range(1, hybrid.anchor_chain.height + 1)
    )


def _run_hybrid_once(
    *,
    chain_name: str,
    blocks: int,
    transactions_per_block: int,
    payload_bytes: int,
    pbft_policy: PBFTPolicy,
    frequency: int,
    seed: int,
    tag: str,
) -> tuple[float, float, int, int]:
    """One pass: `blocks` private blocks, then one `sync()`+`flush()`.

    Returns `(private_seconds, anchor_seconds, anchor_count, anchor_chain_bytes)`. The private
    span is measured exactly as `harness.run_once` measures it (same builder, same
    `pipeline.commit` call) so it is directly comparable to a private-only run at the same seed.
    """
    id_prefix = "CS" if chain_name == BC_DTBU else "HP"
    collector = keypair_from_secret(seed + 90_001)
    submitter_id = f"{tag}-collector"
    cluster = harness._cluster(
        chain_name=chain_name,
        id_prefix=id_prefix,
        pbft_policy=pbft_policy,
        seed=seed,
        submitters={submitter_id: collector.public},
    )
    wait_s = pbft_policy.view_change_timeout_s * 32

    private_seconds = 0.0
    for block_index in range(blocks):
        started = time.perf_counter()
        batch = harness._batch(
            chain_name,
            transactions_per_block,
            payload_bytes,
            collector.public,
            collector.private,
            seed=seed * 100_003 + block_index,
            tag=f"{tag}-b{block_index}",
        )
        pipeline.commit(
            cluster,
            [batch],
            timestamp=float(block_index + 1),
            wait_s=wait_s,
            submitter_id=submitter_id,
            key=collector.private,
        )
        private_seconds += time.perf_counter() - started

    anchor_key = keypair_from_secret(seed + _ANCHOR_KEY_OFFSET)
    hybrid = HybridChain(
        private_chain_name=chain_name,
        anchor_chain_name=f"{chain_name}_anchor",
        anchor_key=anchor_key.private,
        policy=AnchorPolicy(frequency=frequency),
    )
    trusted = pipeline.read_chain(cluster)
    anchor_started = time.perf_counter()
    hybrid.sync(trusted, timestamp=float(blocks + 1))
    hybrid.flush(trusted, timestamp=float(blocks + 1))
    anchor_seconds = time.perf_counter() - anchor_started

    return (
        private_seconds,
        anchor_seconds,
        len(hybrid.anchored_heights),
        _anchor_chain_bytes(hybrid),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260925)
    args = parser.parse_args()

    bench_config = load_config(REPO_ROOT / "configs" / "bench.yaml", expected_kind="bench")
    chain_config = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
    policy = harness.BenchPolicy.from_config(bench_config, chain_config)

    seed_all(args.seed)
    run_id = log.configure()
    logger = log.get_logger(__name__)
    started_at = time.time()

    rows: dict[tuple[str, str, int], dict[str, Any]] = {}
    for case in policy.cases:
        blocks = policy.case_blocks[case]
        for chain in policy.chains:
            base_seed = args.seed + 10_000 * (hash((case, chain)) % 97)
            private_only = [
                harness.run_once(
                    chain_name=chain,
                    blocks=blocks,
                    transactions_per_block=policy.transactions_per_block,
                    payload_bytes=policy.payload_bytes,
                    pbft_policy=policy.pbft,
                    seed=base_seed + repeat,
                    tag=f"{case}-{chain}-priv-{repeat}",
                ).total_compute_seconds
                for repeat in range(_WARMUP + _REPEATS)
            ][_WARMUP:]
            private_median = sorted(private_only)[len(private_only) // 2]

            for frequency in _FREQUENCIES:
                samples = [
                    _run_hybrid_once(
                        chain_name=chain,
                        blocks=blocks,
                        transactions_per_block=policy.transactions_per_block,
                        payload_bytes=policy.payload_bytes,
                        pbft_policy=policy.pbft,
                        frequency=frequency,
                        seed=base_seed + repeat,
                        tag=f"{case}-{chain}-f{frequency}-{repeat}",
                    )
                    for repeat in range(_WARMUP + _REPEATS)
                ][_WARMUP:]
                priv_secs = sorted(s[0] for s in samples)[len(samples) // 2]
                anchor_secs = sorted(s[1] for s in samples)[len(samples) // 2]
                total_secs = priv_secs + anchor_secs
                anchor_count = samples[len(samples) // 2][2]
                anchor_bytes = samples[len(samples) // 2][3]
                overhead_pct = 100.0 * (total_secs - private_median) / private_median

                key = (case, chain, frequency)
                rows[key] = {
                    "blocks": blocks,
                    "private_only_seconds": private_median,
                    "hybrid_total_seconds": total_secs,
                    "anchor_seconds": anchor_secs,
                    "overhead_pct": overhead_pct,
                    "anchor_count": anchor_count,
                    "anchor_chain_bytes": anchor_bytes,
                    "anchor_bytes_per_anchor": anchor_bytes / anchor_count if anchor_count else 0,
                }
                log.event(
                    logger,
                    "hybrid_benchmark_case_measured",
                    case=case,
                    chain=chain,
                    frequency=frequency,
                    blocks=blocks,
                    private_only_seconds=round(private_median, 5),
                    hybrid_total_seconds=round(total_secs, 5),
                    overhead_pct=round(overhead_pct, 2),
                    anchor_count=anchor_count,
                    anchor_chain_bytes=anchor_bytes,
                )

    combined_hash = combined_config_hash(
        {
            "bench": config_hash(bench_config.kind, bench_config.data),
            "chain": config_hash(chain_config.kind, chain_config.data),
        }
    )
    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-5 — hybrid vs private-only blockchain, anchor frequency sweep",
        "seed": args.seed,
        "config_hash": combined_hash,
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": _host(),
        "started_at": started_at,
        "wall_seconds": time.time() - started_at,
        "repeats": _REPEATS,
        "warmup_runs": _WARMUP,
        "frequencies": _FREQUENCIES,
        "matrix": {f"{case}/{chain}/f{freq}": row for (case, chain, freq), row in rows.items()},
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(rows, run_id)
    return 0


def _print_results_lines(rows: dict[tuple[str, str, int], dict[str, Any]], run_id: str) -> None:
    date = time.strftime("%Y-%m-%d")
    lines = [
        f"{date} | hybrid/m7-5-benchmark | {chain} {case} freq={freq} {r['blocks']}blk, "
        f"n={_REPEATS} | private={r['private_only_seconds']:.5f}s "
        f"hybrid={r['hybrid_total_seconds']:.5f}s overhead={r['overhead_pct']:.2f}% "
        f"anchors={r['anchor_count']} anchor_bytes={r['anchor_chain_bytes']} | "
        f"measured | {run_id} | serialization ON, DEV-33"
        for (case, chain, freq), r in rows.items()
    ]
    sys.stdout.write("\n---- RESULTS.md candidate lines (review, then append) ----\n")
    for line in lines:
        sys.stdout.write(line + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
