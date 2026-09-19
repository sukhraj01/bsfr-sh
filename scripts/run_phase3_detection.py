"""Run Phase 3 end to end from the honeypot's own data path. M4b, FLAW-2's framework half.

`scripts/run_detection.py` (M4a) reproduces the paper's *evaluation* — BitcoinHeist addresses.
This script builds the *framework* the paper actually describes: a honeypot, two pBFT clusters,
Phase 2's collection into `BC_SigRW`, and Phase 3's detection reading it back out. It never opens
`data/honeypot/corpus_*.csv` — those are Q9's fixed offline dataset for one-off experiments; this
is the live path.

Same two draws as Q9's committed corpus, through the real pipeline this time
-----------------------------------------------------------------------------
`--seed` is the honeypot's train-draw seed. `TRAIN_COUNT`/`EVAL_COUNT` match
`data/honeypot/manifest.json`'s requested counts (1500/750), and the eval draw's seed is the
train seed plus one automatically — `honeypot.collector.Honeypot.harvest()` derives it that way,
which is exactly how `scripts/make_honeypot_corpus.py` derived Q9's two seeds. Two independent
draws, never one played twice.

The number that matters (CLAUDE.md, PROJECT_STATE.md)
-------------------------------------------------------
The corpus's intended Bayes-optimal accuracy is ~0.85 (`honeypot.corpus.EXPECTED_BAYES_ACCURACY`).
A detector scoring far above that is reading a leak, not detecting — this script checks that
against the *trained* models' balanced accuracy (not just the raw features, which
`test_honeypot_features.py` already covers) and refuses to print a headline number if it fires.

Usage::

    python scripts/run_phase3_detection.py --seed 20260912
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

import numpy as np
from sklearn.metrics import balanced_accuracy_score

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bsfr_sh.blockchain.chain import BC_SigRW, build_genesis  # noqa: E402
from bsfr_sh.consensus.pbft import Cluster, PBFTPolicy  # noqa: E402
from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey, keypair_from_secret  # noqa: E402
from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, config_hash  # noqa: E402
from bsfr_sh.detection.detector import Detection  # noqa: E402
from bsfr_sh.framework import phase2_collection as phase2  # noqa: E402
from bsfr_sh.framework import phase3_detection as phase3  # noqa: E402
from bsfr_sh.framework._block_pipeline import PipelinePolicy, read_chain  # noqa: E402
from bsfr_sh.framework.entities import CloudServer, HoneypotNode  # noqa: E402
from bsfr_sh.honeypot.collector import Honeypot  # noqa: E402
from bsfr_sh.honeypot.corpus import EXPECTED_BAYES_ACCURACY  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402

#: Match `data/honeypot/manifest.json`'s Q9 draws — the framework's own path, at the same scale.
TRAIN_COUNT = 1500
EVAL_COUNT = 750
#: A leak, not a result, past this margin over the corpus's intended ceiling.
LEAK_MARGIN = 0.05


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


def _cluster(
    *, policy: PBFTPolicy, seed: int, id_prefix: str, submitters: dict[str, PublicKey]
) -> Cluster:
    """A fresh `BC_SigRW` cluster, keyed off `seed` so the run is reproducible (CLAUDE.md §4b)."""
    ids = tuple(f"{id_prefix}_{index}" for index in range(policy.replicas))
    keys: dict[str, PrivateKey] = {
        rid: keypair_from_secret(seed + index).private for index, rid in enumerate(ids)
    }
    genesis = build_genesis(owner_id=ids[0], private_key=keys[ids[0]], timestamp=0.0)
    return Cluster(
        chain_name=BC_SigRW,
        keys=keys,
        genesis=genesis,
        policy=policy,
        seed=seed,
        submitters=submitters,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seed", type=int, default=20260912, help="the honeypot's train-draw seed (Q9)"
    )
    args = parser.parse_args()

    ml_config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    chain_config = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
    seed_all(args.seed)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    pbft_policy = PBFTPolicy.from_config(chain_config)
    pipeline_policy = PipelinePolicy.from_config(chain_config)

    node = HoneypotNode(
        identity="HP_phase3",
        keypair=keypair_from_secret(args.seed + 900_001),
        honeypot=Honeypot(honeypot_id="HP_phase3", seed=args.seed),
    )
    collector = CloudServer(identity="CS_phase3", keypair=keypair_from_secret(args.seed + 900_002))
    submitters = {collector.identity: collector.public_key}
    train_cluster = _cluster(
        policy=pbft_policy, seed=args.seed, id_prefix="CS_train", submitters=submitters
    )
    eval_cluster = _cluster(
        policy=pbft_policy, seed=args.seed + 1, id_prefix="CS_eval", submitters=submitters
    )

    started = time.perf_counter()
    train_report = phase2.run(
        node=node,
        collector=collector,
        cluster=train_cluster,
        policy=pipeline_policy,
        count=TRAIN_COUNT,
        timestamp=0.0,
    )
    eval_report = phase2.run(
        node=node,
        collector=collector,
        cluster=eval_cluster,
        policy=pipeline_policy,
        count=EVAL_COUNT,
        timestamp=0.0,
    )
    collection_seconds = time.perf_counter() - started
    log.event(
        logger,
        "phase2_collected",
        train_committed=train_report.committed,
        eval_committed=eval_report.committed,
        seconds=round(collection_seconds, 2),
    )

    train_chain = read_chain(train_cluster)
    eval_chain = read_chain(eval_cluster)

    detections_log: list[dict[str, Any]] = []

    def _on_detect(detection: Detection) -> None:
        detections_log.append(detection.as_dict())

    started = time.perf_counter()
    report = phase3.run(
        train_chain=train_chain,
        eval_chain=eval_chain,
        decrypt=collector.decrypt,
        config=ml_config,
        seed=args.seed,
        on_detect=_on_detect,
    )
    phase3_seconds = time.perf_counter() - started

    predicted = np.array([1 if d.is_ransomware else 0 for d in report.detections], dtype=np.int8)
    balanced_accuracy = float(balanced_accuracy_score(report.evaluation.labels, predicted))
    leaking = balanced_accuracy > EXPECTED_BAYES_ACCURACY + LEAK_MARGIN
    log.event(
        logger,
        "phase3_detected",
        positives_detected=report.positives_detected,
        balanced_accuracy=round(balanced_accuracy, 4),
        precision=round(report.honest.precision, 4),
        recall=round(report.honest.recall, 4),
        pr_auc=round(report.honest.pr_auc, 4),
        mcc=round(report.honest.mcc, 4),
        expected_bayes_accuracy=EXPECTED_BAYES_ACCURACY,
        leak_suspected=leaking,
    )

    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M4b — honeypot detection path, Alg. 3 end to end from BC_SigRW",
        "seed": args.seed,
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": {
            "machine": platform.machine(),
            "processor": platform.processor() or platform.machine(),
            "system": f"{platform.system()} {platform.release()}",
            **log.env_snapshot(),
        },
        "train_count": TRAIN_COUNT,
        "eval_count": EVAL_COUNT,
        "collection_seconds": collection_seconds,
        "phase3_seconds": phase3_seconds,
        "balanced_accuracy": balanced_accuracy,
        "expected_bayes_accuracy": EXPECTED_BAYES_ACCURACY,
        "leak_margin": LEAK_MARGIN,
        "leak_suspected": leaking,
        "report": report.as_dict(),
    }

    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    if leaking:
        message = (
            f"balanced_accuracy={balanced_accuracy:.4f} is more than {LEAK_MARGIN:.2f} above the "
            f"corpus's intended Bayes-optimal {EXPECTED_BAYES_ACCURACY:.2f} (CLAUDE.md, "
            "PROJECT_STATE.md): this is a leak to find, not a result. Refusing to print a "
            "RESULTS.md line; the sidecar is written for post-mortem."
        )
        log.event(logger, "leak_refused_to_report", reason=message)
        sys.stderr.write(message + "\n")
        return 2

    _print_results_line(report, balanced_accuracy, run_id)
    return 0


def _print_results_line(report: phase3.Phase3Report, balanced_accuracy: float, run_id: str) -> None:
    date = time.strftime("%Y-%m-%d")
    honest = report.honest
    sys.stdout.write("\n--- RESULTS.md line ---\n")
    sys.stdout.write(
        f"{date} | detection/honeypot-phase3 | ensemble via NProf/AProf, "
        f"train n={report.train.n_rows} eval n={report.evaluation.n_rows} | "
        f"bal_acc={balanced_accuracy:.4f} prec={honest.precision:.4f} "
        f"rec={honest.recall:.4f} mcc={honest.mcc:.4f} pr_auc={honest.pr_auc:.4f} | "
        f"measured | {run_id} | FLAW-2 framework path, expect ~0.85\n"
    )


if __name__ == "__main__":
    raise SystemExit(main())
