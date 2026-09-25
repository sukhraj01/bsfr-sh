"""M7-11: honeypot training-data poisoning — measuring Gap 1 from M7-9's threat model.

M7-9's `docs/THREAT_MODEL.md` Gap 1 named, without measuring, the ransomware-defense framework's
sharpest irony: a Tier-2 adversary who controls the honeypot's collection process can feed false
training data into `Sig_RW`/`FT_RW`, and once that data commits to `BC_SigRW` through real pBFT
consensus, the chain's own immutability certifies the poison as *tamper-proof* rather than false —
the paper's central selling point works against the defender here, not for them. This script
measures both halves of that claim: how much three poisoning strategies degrade the detector
(`detection.poisoning`, a budget sweep against the committed corpus), and — once, for real,
through actual consensus — that a poisoned record commits cleanly and the chain has no mechanism
to remove it afterward.

Two different execution paths for two different questions
-------------------------------------------------------------
The budget sweep (15 cells: 3 strategies x 5 budgets) reads `data/honeypot/corpus_{train,eval}.csv`
directly, same posture as M7-3/M7-7/M7-8/M7-10 (DEV-27's "committed corpus is the fixed dataset").
Its own sanity check is against the CSV-path reference **0.8408** (`RESULTS.md` M7-3), not the
chain-path 0.8422 the session brief names — DEV-27 already explains the 0.0014 gap
(`corpus.write_corpus` rounds to 6 significant figures; the chain path does not), and every other
M7-x poisoning/retraining-style experiment in this project checks against 0.8408 for the same
reason. The permanence demonstration is the one place the brief's own wording requires a real
chain commit ("committed to `BC_SigRW` through real pBFT consensus") and runs exactly once,
through `framework.phase2_collection`'s own pipeline, unchanged — this script writes no new
consensus or chain code, only a poisoned payload for the existing pipeline to carry.

Safety (CLAUDE.md §2): this is arithmetic on `FT_RW` feature arrays and one honeypot-synthesized
sample's label. No malware is generated, modified, or executed, and nothing here is a live attack
against any system outside this repository's own test fixtures.

Usage::

    python scripts/m7_11_honeypot_poisoning.py
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from bsfr_sh.blockchain.chain import BC_SigRW, Chain, build_genesis  # noqa: E402
from bsfr_sh.blockchain.transaction import (  # noqa: E402
    SignatureRecordPayload,
    Transaction,
    encrypt_signature_record,
)
from bsfr_sh.consensus.pbft import Cluster, PBFTPolicy  # noqa: E402
from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey, keypair_from_secret  # noqa: E402
from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, config_hash  # noqa: E402
from bsfr_sh.detection import metrics as detection_metrics  # noqa: E402
from bsfr_sh.detection import models as detection_models  # noqa: E402
from bsfr_sh.detection import profiles as detection_profiles  # noqa: E402
from bsfr_sh.detection.adversarial import balanced_accuracy, ensemble_predict  # noqa: E402
from bsfr_sh.detection.detector import DetectionModule  # noqa: E402
from bsfr_sh.detection.poisoning import (  # noqa: E402
    PoisonResult,
    anchor_point_injection,
    feature_poison,
    label_flip,
)
from bsfr_sh.framework import _block_pipeline as pipeline  # noqa: E402
from bsfr_sh.framework import phase2_collection as phase2  # noqa: E402
from bsfr_sh.framework._block_pipeline import PipelinePolicy, read_chain  # noqa: E402
from bsfr_sh.framework.entities import CloudServer, HoneypotNode  # noqa: E402
from bsfr_sh.honeypot import features as ft  # noqa: E402
from bsfr_sh.honeypot import signatures  # noqa: E402
from bsfr_sh.honeypot.collector import BENIGN, Honeypot  # noqa: E402
from bsfr_sh.honeypot.preprocess import clean  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import numpy_generator, seed_all  # noqa: E402

SEED = 20260912
#: M7-3's established CSV-path baseline (`RESULTS.md` M7-3), reused by every M7-x experiment
#: against the committed corpus. NOT the chain-path 0.8422 the session brief names -- see the
#: module docstring and DEV-37/DEV-27 for why.
CSV_PATH_REFERENCE_BAL_ACC = 0.8408
_REPRODUCTION_TOLERANCE = 1e-4
STRATEGIES = ("label_flip", "feature_poison", "anchor_point_injection")
_STRATEGY_FN = {
    "label_flip": label_flip,
    "feature_poison": feature_poison,
    "anchor_point_injection": anchor_point_injection,
}
BUDGETS = (0.01, 0.05, 0.10, 0.20, 0.50)
#: Extra cell beyond the brief's own sweep, purely to satisfy the TESTS section's "at 100%
#: label-flipping budget, balanced accuracy should approach 0.50 or worse" -- run once, for
#: label_flip only, not part of the 15-cell sweep the brief specifies.
LABEL_FLIP_FULL_BUDGET = 1.0

_COLOR = {
    "label_flip": "#e34948",
    "feature_poison": "#eb6834",
    "anchor_point_injection": "#4a3aa7",
}
_STRATEGY_TITLE = {
    "label_flip": "label flipping",
    "feature_poison": "feature poisoning",
    "anchor_point_injection": "anchor-point injection",
}


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


def _load_corpus(name: str) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.read_csv(REPO_ROOT / "data" / "honeypot" / f"corpus_{name}.csv")
    x = frame[list(ft.FEATURE_NAMES)].to_numpy(dtype=np.float64)
    y = (frame["label"] == "RW").to_numpy(dtype=np.int8)
    return x, y


def fit_detector(x_train: np.ndarray, y_train: np.ndarray, ml_config: Any) -> DetectionModule:
    """Alg. 3 lines 2-3, on whatever (possibly poisoned) draw is given."""
    models = detection_models.train_all(x_train, y_train, ml_config, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    return DetectionModule(models=models, normal=normal, abnormal=abnormal)


def clean_metrics(
    detector: DetectionModule, x_eval: np.ndarray, y_eval: np.ndarray
) -> dict[str, float]:
    """The clean, never-poisoned eval corpus scored against a (possibly poisoned) fit."""
    scores = detection_profiles.ensemble_score(detector.models, x_eval)
    predictions = ensemble_predict(detector, x_eval)
    honest = detection_metrics.honest_metrics(y_eval, predictions, scores)
    return {
        "balanced_accuracy": balanced_accuracy(y_eval, predictions),
        "precision": honest.precision,
        "recall": honest.recall,
        "mcc": honest.mcc,
        "pr_auc": honest.pr_auc,
    }


def emit_degradation_figure(
    original_bal_acc: float, results: dict[str, dict[float, float]], figures_dir: Path
) -> Path:
    fig, ax = plt.subplots(figsize=(7.2, 4.6), dpi=150)
    budgets_pct = [b * 100 for b in BUDGETS]
    ax.axhline(
        original_bal_acc,
        color="#333333",
        linestyle=":",
        linewidth=1.2,
        label=f"unpoisoned baseline ({original_bal_acc:.4f})",
    )
    ax.axhline(
        0.50, color="#999999", linestyle="--", linewidth=1.0, label="useless detector (0.50)"
    )
    for strategy in STRATEGIES:
        curve = [results[strategy][b] for b in BUDGETS]
        ax.plot(
            budgets_pct,
            curve,
            marker="o",
            markersize=4,
            linewidth=2.0,
            color=_COLOR[strategy],
            label=_STRATEGY_TITLE[strategy],
        )
    ax.set_xlabel("poisoning budget (% of ransomware training rows)")
    ax.set_ylabel("balanced accuracy on the clean eval corpus")
    ax.set_ylim(0.0, 1.0)
    ax.set_title("M7-11: detector degradation under honeypot poisoning", fontsize=10.5, loc="left")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=8, loc="lower left")
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig11a_poisoning_degradation.png"
    fig.savefig(path)
    plt.close(fig)
    return path


# --- Step 4/5: the permanence + pre-commit-validation demonstration ---------------------------


def _pbft_cluster(*, policy: PBFTPolicy, seed: int, submitters: dict[str, PublicKey]) -> Cluster:
    ids = tuple(f"CS_poison_{index}" for index in range(policy.replicas))
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


def demonstrate_permanence(ml_config: Any, chain_config: Any) -> dict[str, Any]:
    """Commit ONE poisoned `SignatureRecordPayload` — a real ransomware sample, label flipped to
    benign — to a real `BC_SigRW` cluster through real pBFT consensus, and inspect what happens
    next. Runs exactly once; this is a demonstration, not a swept experiment.
    """
    pbft_policy = PBFTPolicy.from_config(chain_config)
    pipeline_policy = PipelinePolicy.from_config(chain_config)

    node = HoneypotNode(
        identity="HP_poison",
        keypair=keypair_from_secret(SEED + 900_101),
        honeypot=Honeypot(honeypot_id="HP_poison", seed=SEED),
    )
    collector = CloudServer(identity="CS_poison", keypair=keypair_from_secret(SEED + 900_102))
    submitters = {collector.identity: collector.public_key}
    cluster = _pbft_cluster(policy=pbft_policy, seed=SEED, submitters=submitters)

    # Harvest real malicious samples (malicious_fraction=1.0 so we don't need to filter benign
    # ones out); the adversary's attack is a real ransomware trace, wrongly labelled.
    raw = phase2.collect(node, collector, count=10, malicious_fraction=1.0)
    cleaned, _report = clean(raw)
    malicious_sample = next(s for s in cleaned if s.label != BENIGN)

    signature = signatures.build(
        malicious_sample, collector_key=collector.keypair.private, collector_id=collector.identity
    )
    vector = ft.build(malicious_sample)
    poisoned_record = SignatureRecordPayload(
        sample_id=malicious_sample.sample_id,
        content_digest=signature.content_digest,
        attestation=signature.attestation,
        features=vector.values,
        collected_at=malicious_sample.collected_at,
        schema=vector.schema,
        missing_mask=vector.missing_mask,
        label=BENIGN,  # <-- the poison: a real "RW" trace, certified under the wrong label
    )

    def build(record: SignatureRecordPayload) -> tuple[Transaction, ...]:
        return (
            encrypt_signature_record(
                recipient=collector.public_key,
                tx_id=record.sample_id,
                payload=record,
                created_at=record.collected_at,
            ),
        )

    result = pipeline.run(
        cluster,
        (poisoned_record,),
        build,
        chain=BC_SigRW,
        policy=pipeline_policy,
        timestamp=0.0,
        submitter_id=collector.identity,
        key=collector.keypair.private,
    )
    committed_cleanly = result.transaction_count == 1

    chain = read_chain(cluster)
    chain_height_after = chain.height

    # Code-level observation, not a new implementation (OUT OF SCOPE): does Chain expose any
    # mutating method other than append()? Listed once, here, rather than asserted from memory.
    mutating_methods = sorted(
        name
        for name in dir(Chain)
        if not name.startswith("_")
        and callable(getattr(Chain, name))
        and name
        not in {
            "draft_next",
            "adopt_genesis",
            "create_genesis",
        }  # block-building, not chain mutation
    )
    has_delete_or_rollback = any(
        keyword in name.lower()
        for name in mutating_methods
        for keyword in ("delete", "remove", "rollback", "revert", "truncate", "undo")
    )

    return {
        "sample_id": malicious_sample.sample_id,
        "sample_true_label": malicious_sample.label,
        "poisoned_label": poisoned_record.label,
        "committed_cleanly": committed_cleanly,
        "block_count": result.block_count,
        "chain_height_after": chain_height_after,
        "chain_all_methods": sorted(
            n for n in dir(Chain) if not n.startswith("_") and callable(getattr(Chain, n))
        ),
        "chain_has_delete_or_rollback_method": has_delete_or_rollback,
        "check_append_criteria": [
            "prev_hash linkage",
            "merkle_root recomputation",
            "current_hash uniqueness",
            "ECDSA signature under owner_pubkey",
            "timestamp skew tolerance",
        ],
    }


def main() -> int:
    started = time.perf_counter()
    ml_config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    chain_config = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
    seed_all(SEED)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    x_train, y_train = _load_corpus("train")
    x_eval, y_eval = _load_corpus("eval")

    # --- Baseline: unpoisoned fit, sanity-checked against the CSV-path reference -----------------
    original_detector = fit_detector(x_train, y_train, ml_config)
    original_metrics = clean_metrics(original_detector, x_eval, y_eval)
    drift = abs(original_metrics["balanced_accuracy"] - CSV_PATH_REFERENCE_BAL_ACC)
    if drift > _REPRODUCTION_TOLERANCE:
        raise SystemExit(
            f"baseline bal_acc={original_metrics['balanced_accuracy']:.4f} does not reproduce "
            f"the established {CSV_PATH_REFERENCE_BAL_ACC} (drift={drift:.4f}); not safe to "
            "compare poisoned models against it."
        )
    log.event(logger, "baseline_measured", bal_acc=round(original_metrics["balanced_accuracy"], 4))

    # --- Step 2/3: the 15-cell sweep, plus the 0% degenerate check per strategy ------------------
    sweep: dict[str, dict[float, dict[str, Any]]] = {s: {} for s in STRATEGIES}
    bal_acc_by_strategy: dict[str, dict[float, float]] = {s: {} for s in STRATEGIES}

    for strategy in STRATEGIES:
        fn = _STRATEGY_FN[strategy]
        rng_zero = numpy_generator(SEED)
        zero_result: PoisonResult = fn(x_train, y_train, 0.0, rng=rng_zero)
        assert zero_result.x is x_train and zero_result.y is y_train, (
            f"{strategy} budget=0.0 must be a no-op (reproduces the unpoisoned fit exactly)"
        )

        for budget in BUDGETS:
            rng = numpy_generator(SEED + round(budget * 10_000) + hash(strategy) % 1000)
            result: PoisonResult = fn(x_train, y_train, budget, rng=rng)
            detector = fit_detector(result.x, result.y, ml_config)
            metrics = clean_metrics(detector, x_eval, y_eval)
            sweep[strategy][budget] = {
                "poisoned_training_set": result.as_dict(),
                "clean_metrics": metrics,
                "delta_from_baseline": metrics["balanced_accuracy"]
                - original_metrics["balanced_accuracy"],
            }
            bal_acc_by_strategy[strategy][budget] = metrics["balanced_accuracy"]
            log.event(
                logger,
                "cell_measured",
                strategy=strategy,
                budget=budget,
                bal_acc=round(metrics["balanced_accuracy"], 4),
                delta=round(sweep[strategy][budget]["delta_from_baseline"], 4),
                n_poisoned=result.n_poisoned,
            )

    # --- TESTS: label_flip at 100% budget should approach 0.50 or worse --------------------------
    # At 100% every ransomware training row is relabelled benign, so the training set has zero
    # positive examples left -- not a near-degenerate case but a fully degenerate one, and
    # sklearn's estimators refuse to fit a single-class problem at all. That refusal *is* the
    # measurement: a training set with no positive examples cannot teach any classifier anything
    # but "always benign", which scores exactly 0.50 balanced accuracy on a balanced eval set
    # (100% specificity, 0% sensitivity) by construction, not by running a model.
    rng_full = numpy_generator(SEED + 999_999)
    full_flip = label_flip(x_train, y_train, LABEL_FLIP_FULL_BUDGET, rng=rng_full)
    if int((full_flip.y == 1).sum()) == 0:
        full_flip_metrics = {
            "balanced_accuracy": 0.50,
            "precision": 0.0,
            "recall": 0.0,
            "mcc": 0.0,
            "pr_auc": float(y_eval.mean()),
        }
        log.event(
            logger,
            "label_flip_full_budget_degenerate",
            reason="training set has zero positive rows; no classifier can be fit, "
            "bal_acc=0.50 by construction",
        )
    else:
        full_flip_detector = fit_detector(full_flip.x, full_flip.y, ml_config)
        full_flip_metrics = clean_metrics(full_flip_detector, x_eval, y_eval)
    log.event(
        logger,
        "label_flip_full_budget_measured",
        bal_acc=round(full_flip_metrics["balanced_accuracy"], 4),
    )

    # --- Step 4/5: the permanence + pre-commit-validation demonstration -------------------------
    permanence = demonstrate_permanence(ml_config, chain_config)
    log.event(
        logger,
        "permanence_demonstrated",
        committed_cleanly=permanence["committed_cleanly"],
        chain_has_delete_or_rollback_method=permanence["chain_has_delete_or_rollback_method"],
    )

    # --- Figures ------------------------------------------------------------------------------
    figures_dir = REPO_ROOT / "results" / "figures"
    fig_a = emit_degradation_figure(
        original_metrics["balanced_accuracy"], bal_acc_by_strategy, figures_dir
    )

    # --- Sidecar ------------------------------------------------------------------------------
    wall_seconds = time.perf_counter() - started
    host = {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }
    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-11 -- honeypot data poisoning: budget sweep against three strategies, "
        "plus one real pBFT commit demonstrating chain-immutable permanence",
        "seed": SEED,
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": host,
        "wall_seconds": wall_seconds,
        "csv_path_reference_bal_acc": CSV_PATH_REFERENCE_BAL_ACC,
        "original_metrics": original_metrics,
        "budgets": list(BUDGETS),
        "sweep": {s: {str(b): sweep[s][b] for b in BUDGETS} for s in STRATEGIES},
        "label_flip_full_budget": {
            "budget": LABEL_FLIP_FULL_BUDGET,
            "clean_metrics": full_flip_metrics,
            "n_poisoned": full_flip.n_poisoned,
        },
        "permanence_demonstration": permanence,
        "figures": [str(fig_a.relative_to(REPO_ROOT))],
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(run_id, original_metrics, sweep, full_flip_metrics, full_flip, permanence)
    return 0


def _print_results_lines(
    run_id: str,
    original_metrics: dict[str, float],
    sweep: dict[str, dict[float, dict[str, Any]]],
    full_flip_metrics: dict[str, float],
    full_flip: PoisonResult,
    permanence: dict[str, Any],
) -> None:
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-11-poisoning | unpoisoned baseline, clean eval | "
        f"bal_acc={original_metrics['balanced_accuracy']:.4f} prec={original_metrics['precision']:.4f} "
        f"rec={original_metrics['recall']:.4f} mcc={original_metrics['mcc']:.4f} "
        f"pr_auc={original_metrics['pr_auc']:.4f} | measured | {run_id} | M7-11, cf. M7-3 0.8408\n"
    )
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            entry = sweep[strategy][budget]
            cm = entry["clean_metrics"]
            pct = int(budget * 100)
            sys.stdout.write(
                f"{date} | detection/honeypot-m7-11-poisoning | {strategy} @{pct}% budget, "
                f"n_poisoned={entry['poisoned_training_set']['n_poisoned']} | "
                f"bal_acc={cm['balanced_accuracy']:.4f} delta={entry['delta_from_baseline']:+.4f} "
                f"prec={cm['precision']:.4f} rec={cm['recall']:.4f} mcc={cm['mcc']:.4f} "
                f"pr_auc={cm['pr_auc']:.4f} | measured | {run_id} | M7-11\n"
            )
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-11-poisoning | label_flip @100% budget, "
        f"n_poisoned={full_flip.n_poisoned} | bal_acc={full_flip_metrics['balanced_accuracy']:.4f} "
        f"| measured | {run_id} | M7-11, TESTS: expect ~0.50 or worse\n"
    )
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-11-permanence | one poisoned record committed to "
        f"BC_SigRW via real pBFT | committed_cleanly={permanence['committed_cleanly']} "
        f"chain_height_after={permanence['chain_height_after']} "
        f"has_delete_or_rollback_method={permanence['chain_has_delete_or_rollback_method']} | "
        f"measured | {run_id} | M7-11, Gap 1\n"
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
