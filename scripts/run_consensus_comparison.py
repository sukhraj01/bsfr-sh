"""M7-4: pBFT vs Raft — the same case matrix, both protocols, plus the qualitative fault tests.

Mirrors `scripts/run_bench.py`'s shape (sidecar JSON, `RESULTS.md` candidate lines printed for a
human to review and append — never self-appended, same convention as
`scripts/run_phase3_detection.py`) but is a separate script rather than a flag on `run_bench.py`:
M6a's matrix is the paper-reproduction path and must not gain a branch that changes its numbers
by one bit; this script reuses `bench.harness`'s machinery without touching M6a's call sites.

What this measures
-------------------
1. **The quantitative matrix.** Cases 1-3, both chains, both protocols, serialization ON (the
   same condition M6a settled on after DEV-30) — wall-clock, derived TPS, per-block marginal
   cost, total bus messages, and consensus-message ECDSA operations
   (`consensus.pbft.Cluster.signature_ops` / `consensus.raft.RaftCluster.signature_ops`, DEV-32).
2. **The qualitative fault tests**, run once at a small fixed scale (these are pass/fail
   structural findings, not something more repeats would sharpen):
   - crash tolerance: 1 of 4 nodes silent, both protocols still commit;
   - the Raft Byzantine-leader fork (`consensus/raft.py`'s module docstring,
     `tests/unit/test_raft_byzantine.py`) reproduced here with concrete digests, not just a
     pass/fail assertion, so the report can quote real block hashes.

Usage::

    python scripts/run_consensus_comparison.py --seed 20260924
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bsfr_sh.bench import harness  # noqa: E402
from bsfr_sh.blockchain.block import BlockDraft  # noqa: E402
from bsfr_sh.blockchain.chain import BC_DTBU  # noqa: E402
from bsfr_sh.blockchain.transaction import BackupPayload, Transaction, encrypt_backup  # noqa: E402
from bsfr_sh.consensus.network import LinkFaults  # noqa: E402
from bsfr_sh.consensus.pbft import Cluster, PBFTPolicy  # noqa: E402
from bsfr_sh.consensus.raft import (  # noqa: E402
    AppendEntries,
    LogEntry,
    RaftCluster,
    RaftMessage,
    RaftNode,
    RaftPolicy,
)
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

#: Kept modest — this script's own repeat count, independent of `configs/bench.yaml`'s M6a floor.
#: The comparison's point (message-count ratio, Byzantine vulnerability) does not need M6a's
#: variance-driven repeat inflation to be visible.
_REPEATS = 5
_WARMUP = 1


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


# --------------------------------------------------------------------------------------------
# Qualitative fault tests — small, fixed scale, run once
# --------------------------------------------------------------------------------------------
def _crash_tolerance_check(
    *, protocol: str, policy: PBFTPolicy | RaftPolicy, seed: int
) -> dict[str, Any]:
    """1 of 4 nodes silent from the start; 3 blocks submitted; the other 3 must still commit."""
    id_prefix = "CS"
    collector = keypair_from_secret(seed + 1)
    submitter_id = "crash-check"
    if isinstance(policy, PBFTPolicy):
        cluster: Cluster | RaftCluster = harness._cluster(
            chain_name=BC_DTBU,
            id_prefix=id_prefix,
            pbft_policy=policy,
            seed=seed,
            submitters={submitter_id: collector.public},
        )
        wait_s = policy.view_change_timeout_s * 40
    else:
        cluster = harness._cluster(
            chain_name=BC_DTBU,
            id_prefix=id_prefix,
            raft_policy=policy,
            seed=seed,
            submitters={submitter_id: collector.public},
        )
        wait_s = policy.election_timeout_max_s * 60

    crashed_id = f"{id_prefix}_3"
    cluster.network.set_faults(crashed_id, LinkFaults(drop_rate=1.0))
    for i in range(3):
        txs = (
            encrypt_backup(
                recipient=collector.public,
                tx_id=f"crash-{i}",
                payload=BackupPayload(system_id="SYS_1", data=b"x" * 64, captured_at=i),
                created_at=i,
            ),
        )
        pipeline.commit(
            cluster,
            [txs],
            timestamp=float(i + 1),
            wait_s=wait_s,
            submitter_id=submitter_id,
            key=collector.private,
        )
    live = {rid: r for rid, r in cluster.replicas.items() if rid != crashed_id}
    heights = {rid: r.chain.height for rid, r in live.items()}
    return {
        "protocol": protocol,
        "crashed_node": crashed_id,
        "live_heights": heights,
        "all_live_committed_all_blocks": all(h == 3 for h in heights.values()),
    }


def _raft_byzantine_fork_check(*, policy: RaftPolicy, seed: int) -> dict[str, Any]:
    """Reproduce `test_raft_byzantine.py`'s fork here so the report can quote real digests."""
    id_prefix = "CS"
    collector = keypair_from_secret(seed + 2)
    submitter_id = "byz-check"
    built = harness._cluster(
        chain_name=BC_DTBU,
        id_prefix=id_prefix,
        raft_policy=policy,
        seed=seed,
        submitters={submitter_id: collector.public},
    )
    assert isinstance(built, RaftCluster)
    cluster = built
    wait_s = policy.election_timeout_max_s * 60

    def txs(tag: str) -> tuple[Transaction, ...]:
        return (
            encrypt_backup(
                recipient=collector.public,
                tx_id=tag,
                payload=BackupPayload(system_id="SYS_1", data=b"x" * 64, captured_at=0),
                created_at=0,
            ),
        )

    pipeline.commit(
        cluster,
        [txs("warmup")],
        timestamp=1.0,
        wait_s=wait_s,
        submitter_id=submitter_id,
        key=collector.private,
    )
    leader_id = next(rid for rid, n in cluster.nodes.items() if n.is_leader)
    leader = cluster.nodes[leader_id]
    others = [rid for rid in cluster.nodes if rid != leader_id]
    side_b = frozenset(others[:1])
    variant_txs = txs("fabricated-by-the-leader")

    class _EquivocatingLeader:
        def __init__(self) -> None:
            self._variant: LogEntry | None = None

        def outgoing(
            self, node: RaftNode, recipient: str, message: RaftMessage
        ) -> Sequence[RaftMessage]:
            if isinstance(message, AppendEntries) and message.entries and recipient in side_b:
                original = message.entries[0]
                if self._variant is None or self._variant.index != original.index:
                    block = original.block
                    fabricated = BlockDraft(
                        owner_id=block.owner_id,
                        owner_pubkey=block.owner_pubkey,
                        transactions=variant_txs,
                        prev_hash=block.prev_hash,
                        timestamp=block.timestamp,
                    ).seal(node._private_key)
                    self._variant = LogEntry(
                        term=original.term, index=original.index, block=fabricated
                    )
                message = AppendEntries(
                    chain=message.chain,
                    term=message.term,
                    leader_id=message.leader_id,
                    prev_log_index=message.prev_log_index,
                    prev_log_term=message.prev_log_term,
                    entries=(self._variant,),
                    leader_commit=message.leader_commit,
                )
            return (message,)

    leader.behaviour = _EquivocatingLeader()
    cluster.submit(txs("real"), timestamp=2.0, submitter_id=submitter_id, key=collector.private)
    cluster.run(until=cluster.network.now + wait_s)

    heights = {rid: n.chain.height for rid, n in cluster.nodes.items()}
    side_a_hash = cluster.nodes[others[1]].chain.block_at(2).current_hash.hex()
    side_b_hash = cluster.nodes[others[0]].chain.block_at(2).current_hash.hex()
    return {
        "leader": leader_id,
        "side_a_nodes": others[1:],
        "side_b_nodes": list(side_b),
        "all_nodes_reached_height": heights,
        "side_a_block_hash": side_a_hash,
        "side_b_block_hash": side_b_hash,
        "forked": side_a_hash != side_b_hash,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260924)
    args = parser.parse_args()

    bench_config = load_config(REPO_ROOT / "configs" / "bench.yaml", expected_kind="bench")
    chain_config = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
    policy = harness.BenchPolicy.from_config(bench_config, chain_config)

    seed_all(args.seed)
    run_id = log.configure()
    logger = log.get_logger(__name__)
    started_at = time.time()

    # -- 1. the quantitative matrix --------------------------------------------------------------
    matrix: dict[tuple[str, str, str], harness.CaseResult] = {}
    for case in policy.cases:
        blocks = policy.case_blocks[case]
        for chain in policy.chains:
            for protocol in ("pbft", "raft"):
                kwargs: dict[str, Any] = {
                    "case": case,
                    "chain_name": chain,
                    "blocks": blocks,
                    "transactions_per_block": policy.transactions_per_block,
                    "payload_bytes": policy.payload_bytes,
                    "base_seed": args.seed + 10_000 * (hash((case, chain, protocol)) % 97),
                    "repeats": _REPEATS,
                    "warmup_runs": _WARMUP,
                }
                if protocol == "pbft":
                    kwargs["pbft_policy"] = policy.pbft
                else:
                    kwargs["raft_policy"] = policy.raft
                result = harness.run_case(**kwargs)
                matrix[(case, chain, protocol)] = result
                log.event(
                    logger,
                    "consensus_comparison_case_measured",
                    case=case,
                    chain=chain,
                    protocol=protocol,
                    blocks=blocks,
                    median_seconds=round(result.median_total_seconds, 5),
                    tps=round(result.tps, 1),
                    median_message_count=result.median_message_count,
                    median_signature_ops=result.median_signature_ops,
                )

    # -- 2. qualitative fault tests -------------------------------------------------------------
    crash_pbft = _crash_tolerance_check(
        protocol="pbft", policy=policy.pbft, seed=args.seed + 555_001
    )
    crash_raft = _crash_tolerance_check(
        protocol="raft", policy=policy.raft, seed=args.seed + 555_002
    )
    byzantine_raft = _raft_byzantine_fork_check(policy=policy.raft, seed=args.seed + 555_003)
    log.event(logger, "crash_tolerance_pbft", **crash_pbft)
    log.event(logger, "crash_tolerance_raft", **crash_raft)
    log.event(logger, "raft_byzantine_fork", **byzantine_raft)

    # -- 3. sidecar + RESULTS.md candidate lines -------------------------------------------------
    combined_hash = combined_config_hash(
        {
            "bench": config_hash(bench_config.kind, bench_config.data),
            "chain": config_hash(chain_config.kind, chain_config.data),
        }
    )
    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-4 — pBFT vs Raft consensus comparison",
        "seed": args.seed,
        "config_hash": combined_hash,
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": _host(),
        "started_at": started_at,
        "wall_seconds": time.time() - started_at,
        "repeats": _REPEATS,
        "warmup_runs": _WARMUP,
        "matrix": {
            f"{case}/{chain}/{protocol}": {
                "blocks": r.blocks,
                "median_total_seconds": r.median_total_seconds,
                "stdev_seconds": r.stdev_seconds,
                "marginal_seconds": list(r.marginal_seconds),
                "tps": r.tps,
                "median_message_count": r.median_message_count,
                "median_signature_ops": r.median_signature_ops,
            }
            for (case, chain, protocol), r in matrix.items()
        },
        "crash_tolerance": {"pbft": crash_pbft, "raft": crash_raft},
        "raft_byzantine_fork": byzantine_raft,
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(matrix, run_id)
    return 0


def _print_results_lines(
    matrix: dict[tuple[str, str, str], harness.CaseResult], run_id: str
) -> None:
    date = time.strftime("%Y-%m-%d")
    lines = [
        f"{date} | consensus/m7-4-comparison | {protocol} {chain} {case} {r.blocks}blk x "
        f"{r.transactions_per_block}tx, n={r.repeats} | "
        f"seconds={r.median_total_seconds:.5f} tps={r.tps:.1f} "
        f"messages={r.median_message_count:.0f} sig_ops={r.median_signature_ops:.0f} | "
        f"measured | {run_id} | serialization ON, DEV-32"
        for (case, chain, protocol), r in matrix.items()
    ]
    sys.stdout.write("\n---- RESULTS.md candidate lines (review, then append) ----\n")
    for line in lines:
        sys.stdout.write(line + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
