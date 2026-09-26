"""M7-12: statistical poisoning detection -- the defense M7-11 measured the absence of.

M7-11 (`scripts/m7_11_honeypot_poisoning.py`, DEV-37) measured that a Tier-2 adversary can
permanently poison `BC_SigRW` through legitimate consensus, and that `Chain.check_append()`'s
five checks are all structural or cryptographic -- none of them semantic. This script builds and
measures `detection.drift.DriftDetector` / `consensus.validated_commit.ValidatedSigRWChain`
against exactly the three poisoning strategies and five budgets M7-11 already measured, so the
result is a defended-vs-undefended comparison, not a new, incomparable experiment.

Four measurements, in order
----------------------------
1. The 15-cell table: for each (strategy, budget), score the poisoned rows as a batch against a
   profile built from the unpoisoned training corpus, using both `DriftMethod.MAHALANOBIS` and
   `DriftMethod.PAGE_HINKLEY`. Where the (Mahalanobis) verdict is "prevented," the detector's
   accuracy is the unpoisoned baseline by construction; where it is not, the accuracy is measured
   by actually fitting on the poisoned draw, identically to M7-11.
2. False-positive rate: score held-out clean batches (the eval corpus, chunked, never poisoned)
   against the same profile.
3. A "new ransomware family" batch: a documented, fixed feature-space perturbation of real
   ransomware rows (never a call into `honeypot/collector.py`'s own generator -- this script does
   not touch that module), representing a family with genuinely different behaviour. Scored the
   same way, to surface the detection-vs-legitimate-drift tension the brief asks for.
4. Two real, end-to-end pBFT commits, both defended and undefended (small honest history seeded
   first, so the running profile is not judging with zero data): a burst of label-flipped real
   ransomware records and a burst of anchor-point-shifted records, each submitted as one block.
   A burst, not M7-11's single record: item 1's own measurement shows a lone record has too
   little statistical weight for a batch-level test to say anything about, at any threshold --
   see `POISON_BURST_SIZE`'s docstring.

Safety (CLAUDE.md §2): arithmetic on `FT_RW` feature arrays and one honeypot-synthesized sample's
label, plus real (local, in-process) pBFT consensus over synthetic data. No malware, no network
call outside this process, nothing that resembles a live attack.

Usage::

    python scripts/m7_12_poisoning_defense.py
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from bsfr_sh.blockchain.chain import BC_SigRW, build_genesis  # noqa: E402
from bsfr_sh.blockchain.transaction import (  # noqa: E402
    SignatureRecordPayload,
    Transaction,
    encrypt_signature_record,
)
from bsfr_sh.consensus.pbft import Cluster, PBFTPolicy  # noqa: E402
from bsfr_sh.consensus.validated_commit import build_validated_sigrw_chain_factory  # noqa: E402
from bsfr_sh.crypto.ecdsa import keypair_from_secret  # noqa: E402
from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, config_hash  # noqa: E402
from bsfr_sh.detection import metrics as detection_metrics  # noqa: E402
from bsfr_sh.detection import models as detection_models  # noqa: E402
from bsfr_sh.detection import profiles as detection_profiles  # noqa: E402
from bsfr_sh.detection.adversarial import balanced_accuracy, ensemble_predict  # noqa: E402
from bsfr_sh.detection.detector import DetectionModule  # noqa: E402
from bsfr_sh.detection.drift import DriftDetector, DriftMethod, DriftPolicy  # noqa: E402
from bsfr_sh.detection.poisoning import (  # noqa: E402
    PoisonResult,
    anchor_point_injection,
    feature_poison,
    label_flip,
)
from bsfr_sh.framework import _block_pipeline as pipeline  # noqa: E402
from bsfr_sh.framework import phase2_collection as phase2  # noqa: E402
from bsfr_sh.framework._block_pipeline import (  # noqa: E402
    PipelineError,
    PipelinePolicy,
    read_chain,
)
from bsfr_sh.framework.entities import CloudServer, HoneypotNode  # noqa: E402
from bsfr_sh.honeypot import features as ft  # noqa: E402
from bsfr_sh.honeypot.collector import BENIGN, Honeypot  # noqa: E402
from bsfr_sh.honeypot.preprocess import clean  # noqa: E402
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import numpy_generator, seed_all  # noqa: E402

SEED = 20260912
#: M7-3's/M7-11's established CSV-path baseline (`RESULTS.md` M7-3/M7-11).
CSV_PATH_REFERENCE_BAL_ACC = 0.8408
_REPRODUCTION_TOLERANCE = 1e-4
STRATEGIES = ("label_flip", "feature_poison", "anchor_point_injection")
_STRATEGY_FN = {
    "label_flip": label_flip,
    "feature_poison": feature_poison,
    "anchor_point_injection": anchor_point_injection,
}
BUDGETS = (0.01, 0.05, 0.10, 0.20, 0.50)
#: How many rows make up one simulated "already-committed block" when building the running
#: profile from the training corpus. Arbitrary but fixed -- not tuned per strategy or budget.
CHUNK_SIZE = 25
#: `min_history` in *batches* (`CHUNK_SIZE`-row chunks), not blocks-on-a-real-chain -- chosen so
#: the array-level sweep below and `RunningStats`' own cold-start rule (`detection/drift.py`)
#: both build a real profile before anything is judged.
DRIFT_MIN_HISTORY_BATCHES = 5

MAHALANOBIS_POLICY = DriftPolicy(
    method=DriftMethod.MAHALANOBIS,
    threshold=3.0,
    feature_threshold=3.0,
    min_history=DRIFT_MIN_HISTORY_BATCHES,
)
PAGE_HINKLEY_POLICY = DriftPolicy(
    method=DriftMethod.PAGE_HINKLEY,
    ph_delta=0.5,
    ph_threshold=6.0,
    min_history=DRIFT_MIN_HISTORY_BATCHES,
)

#: The documented "new ransomware family" perturbation (item 4 of the brief): a fixed, disclosed
#: feature-space shift applied to real ransomware rows, never a new call into
#: `honeypot/collector.py`'s own generator. Models a family that exfiltrates over C2 rather than
#: encrypting in bulk -- network/beacon features scaled up, crypto/encryption features scaled
#: down -- while remaining, at the label level, genuinely ransomware.
NEW_FAMILY_SCALE_UP = 3.0
NEW_FAMILY_SCALE_DOWN = 0.3
NEW_FAMILY_FEATURES_UP = ("c2_beacon_count", "dns_entropy", "outbound_burst_rate")
NEW_FAMILY_FEATURES_DOWN = ("crypto_call_rate", "key_generation_events", "write_entropy_mean")

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
    models = detection_models.train_all(x_train, y_train, ml_config, seed=SEED)
    normal, abnormal = detection_profiles.build(
        models, x_train, y_train, feature_names=ft.FEATURE_NAMES
    )
    return DetectionModule(models=models, normal=normal, abnormal=abnormal)


def clean_metrics(
    detector: DetectionModule, x_eval: np.ndarray, y_eval: np.ndarray
) -> dict[str, float]:
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


# --------------------------------------------------------------------------------------------
# Step 1: build the running profile from the unpoisoned committed corpus
# --------------------------------------------------------------------------------------------
def _chunks(x: np.ndarray, size: int) -> list[np.ndarray]:
    return [x[i : i + size] for i in range(0, len(x), size) if len(x[i : i + size]) > 0]


def _build_profile_detector(x_train: np.ndarray, *, policy: DriftPolicy) -> DriftDetector:
    """Feed the whole (unpoisoned) training corpus in, one `CHUNK_SIZE`-row batch at a time.

    Each chunk stands in for one already-committed block's worth of `Sig_RW` transactions --
    `detector.update()` is exactly what `ValidatedSigRWChain.append()` calls once a real block
    lands (`consensus/validated_commit.py`).
    """
    detector = DriftDetector(x_train.shape[1], feature_names=ft.FEATURE_NAMES, policy=policy)
    for chunk in _chunks(x_train, CHUNK_SIZE):
        detector.update(chunk)
    return detector


# --------------------------------------------------------------------------------------------
# Step 2/3: the 15-cell defended-vs-undefended sweep
# --------------------------------------------------------------------------------------------
def run_sweep(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    original_metrics: dict[str, float],
    ml_config: Any,
) -> dict[str, dict[float, dict[str, Any]]]:
    maha = _build_profile_detector(x_train, policy=MAHALANOBIS_POLICY)
    ph = _build_profile_detector(x_train, policy=PAGE_HINKLEY_POLICY)

    sweep: dict[str, dict[float, dict[str, Any]]] = {s: {} for s in STRATEGIES}
    for strategy in STRATEGIES:
        fn = _STRATEGY_FN[strategy]
        for budget in BUDGETS:
            rng = numpy_generator(SEED + round(budget * 10_000) + hash(strategy) % 1000)
            result: PoisonResult = fn(x_train, y_train, budget, rng=rng)
            poisoned_rows = result.x[np.array(result.poisoned_row_indices, dtype=int)]

            maha_report = maha.score_batch(poisoned_rows)
            ph_report = ph.score_batch(poisoned_rows)
            prevented = maha_report.drift_detected

            if prevented:
                defended_bal_acc = original_metrics["balanced_accuracy"]
                undefended_only_metrics = None
            else:
                detector = fit_detector(result.x, result.y, ml_config)
                undefended_only_metrics = clean_metrics(detector, x_eval, y_eval)
                defended_bal_acc = undefended_only_metrics["balanced_accuracy"]

            # The undefended number is always measured, whether or not the defended path needed
            # it, so the comparison table has both columns for every cell.
            if undefended_only_metrics is None:
                detector = fit_detector(result.x, result.y, ml_config)
                undefended_metrics = clean_metrics(detector, x_eval, y_eval)
            else:
                undefended_metrics = undefended_only_metrics

            sweep[strategy][budget] = {
                "n_poisoned": result.n_poisoned,
                "mahalanobis": {
                    "score": maha_report.score,
                    "threshold": maha_report.threshold,
                    "detected": maha_report.drift_detected,
                    "offending_features": list(maha_report.offending_features),
                },
                "page_hinkley": {
                    "score": ph_report.score,
                    "threshold": ph_report.threshold,
                    "detected": ph_report.drift_detected,
                },
                "prevented": prevented,
                "undefended_bal_acc": undefended_metrics["balanced_accuracy"],
                "undefended_delta": undefended_metrics["balanced_accuracy"]
                - original_metrics["balanced_accuracy"],
                "defended_bal_acc": defended_bal_acc,
                "defended_delta": defended_bal_acc - original_metrics["balanced_accuracy"],
            }
    return sweep


# --------------------------------------------------------------------------------------------
# Step 4: false-positive rate on clean batches, and the new-family tension
# --------------------------------------------------------------------------------------------
def false_positive_rates(x_train: np.ndarray, x_eval: np.ndarray) -> dict[str, float]:
    maha = _build_profile_detector(x_train, policy=MAHALANOBIS_POLICY)
    ph = _build_profile_detector(x_train, policy=PAGE_HINKLEY_POLICY)
    eval_chunks = _chunks(x_eval, CHUNK_SIZE)
    return {
        "mahalanobis": sum(maha.score_batch(c).drift_detected for c in eval_chunks)
        / len(eval_chunks),
        "page_hinkley": sum(ph.score_batch(c).drift_detected for c in eval_chunks)
        / len(eval_chunks),
        "n_batches": len(eval_chunks),
    }


#: `n_poisoned` values M7-11's own five budgets produce against this corpus (`RESULTS.md` M7-11),
#: plus the new-family probe's row count -- the exact batch sizes the noise floor below is
#: measured at, so each attack's score is compared against clean batches of its *own* size, not
#: an arbitrary one. A batch-level mean-shift test's power depends on n; comparing a 7-row attack
#: batch to a 358-row noise floor would be answering a different question.
NOISE_FLOOR_SIZES = (7, 36, 72, 143, 358, 353)
NOISE_FLOOR_TRIALS = 300


def noise_floor_by_batch_size(
    x_train: np.ndarray, x_eval: np.ndarray, *, seed: int
) -> dict[int, dict[str, float]]:
    """How high does a same-sized, genuinely clean batch score, just from sampling noise?

    Draws `NOISE_FLOOR_TRIALS` random (never-poisoned) batches of each size in
    `NOISE_FLOOR_SIZES` from the eval corpus -- data the profile below was never built from --
    and scores each against the same training-corpus profile every sweep cell is scored against.
    This is what item 4 of the brief means by "the false-positive rate matters as much as the
    detection rate" made concrete at the *specific* sizes this session's attacks actually are.
    """
    maha = _build_profile_detector(x_train, policy=MAHALANOBIS_POLICY)
    rng = np.random.default_rng(seed)
    out: dict[int, dict[str, float]] = {}
    for n in NOISE_FLOOR_SIZES:
        scores = np.array(
            [
                maha.score_batch(x_eval[rng.choice(len(x_eval), size=n, replace=False)]).score
                for _ in range(NOISE_FLOOR_TRIALS)
            ]
        )
        out[n] = {
            "p50": float(np.percentile(scores, 50)),
            "p95": float(np.percentile(scores, 95)),
            "max": float(scores.max()),
        }
    return out


def new_family_batch(x_eval: np.ndarray, y_eval: np.ndarray) -> np.ndarray:
    index = {name: i for i, name in enumerate(ft.FEATURE_NAMES)}
    positive = x_eval[y_eval == 1].copy()
    for name in NEW_FAMILY_FEATURES_UP:
        positive[:, index[name]] *= NEW_FAMILY_SCALE_UP
    for name in NEW_FAMILY_FEATURES_DOWN:
        positive[:, index[name]] *= NEW_FAMILY_SCALE_DOWN
    return positive


def new_family_scores(
    x_train: np.ndarray, x_eval: np.ndarray, y_eval: np.ndarray
) -> dict[str, Any]:
    maha = _build_profile_detector(x_train, policy=MAHALANOBIS_POLICY)
    ph = _build_profile_detector(x_train, policy=PAGE_HINKLEY_POLICY)
    batch = new_family_batch(x_eval, y_eval)
    maha_report = maha.score_batch(batch)
    ph_report = ph.score_batch(batch)
    return {
        "n_rows": len(batch),
        "features_scaled_up": list(NEW_FAMILY_FEATURES_UP),
        "features_scaled_down": list(NEW_FAMILY_FEATURES_DOWN),
        "mahalanobis": {
            "score": maha_report.score,
            "threshold": maha_report.threshold,
            "detected": maha_report.drift_detected,
            "offending_features": list(maha_report.offending_features),
        },
        "page_hinkley": {
            "score": ph_report.score,
            "threshold": ph_report.threshold,
            "detected": ph_report.drift_detected,
        },
    }


# --------------------------------------------------------------------------------------------
# Step 5: two real pBFT commits -- defended vs undefended, seeded with honest history first
# --------------------------------------------------------------------------------------------
#: A single poisoned record (M7-11's own permanence-demo shape) is the *worst* case for a
#: batch-level test: n=1 has no averaging to suppress sampling noise at all, so the noise floor
#: measured above (n=7's p95=0.55, and it only grows at smaller n) makes a lone record
#: undetectable regardless of threshold -- confirmed by running the single-record shape here
#: too (`SINGLE_RECORD_DEMO=True` below) before settling on the burst size used for the headline
#: demo. A coordinated poisoning *campaign* -- this module's own stated target, not one-off
#: mislabelling -- looks like a burst of several records in one block, which is what
#: `POISON_BURST_SIZE` models.
POISON_BURST_SIZE = 40


def _real_commit_demo(
    *,
    chain_config: Any,
    defended: bool,
    poisoned_records: Sequence[SignatureRecordPayload],
    n_history_blocks: int = 6,
) -> dict[str, Any]:
    """Seed `n_history_blocks` honest blocks, then attempt one poisoned commit.

    Real `framework._block_pipeline` + real `consensus.pbft.Cluster`, exactly M7-11's own
    `demonstrate_permanence` machinery -- the only differences from that function are (a) whether
    the cluster's `BC_SigRW` replicas run `ValidatedSigRWChain` (`defended=True`) or a plain
    `Chain` (`defended=False`), and (b) submitting a burst of `poisoned_records` in one block
    rather than M7-11's single record, per `POISON_BURST_SIZE`'s docstring above.
    """
    pbft_policy = PBFTPolicy.from_config(chain_config)
    pipeline_policy = PipelinePolicy.from_config(chain_config)

    node = HoneypotNode(
        identity="HP_defense",
        keypair=keypair_from_secret(SEED + 900_301),
        honeypot=Honeypot(honeypot_id="HP_defense", seed=SEED),
    )
    collector = CloudServer(identity="CS_defense", keypair=keypair_from_secret(SEED + 900_302))
    submitters = {collector.identity: collector.public_key}

    ids = tuple(f"CS_defense_{index}" for index in range(pbft_policy.replicas))
    keys = {rid: keypair_from_secret(SEED + i).private for i, rid in enumerate(ids)}
    genesis = build_genesis(owner_id=ids[0], private_key=keys[ids[0]], timestamp=0.0)
    kwargs: dict[str, Any] = {}
    if defended:
        kwargs["chain_factory"] = build_validated_sigrw_chain_factory(
            n_features=len(ft.FEATURE_NAMES),
            decrypt_keys=(collector.keypair.private,),
            feature_names=ft.FEATURE_NAMES,
            drift_policy=MAHALANOBIS_POLICY,
        )
    cluster = Cluster(
        chain_name=BC_SigRW,
        keys=keys,
        genesis=genesis,
        policy=pbft_policy,
        seed=SEED,
        submitters=submitters,
        **kwargs,
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

    for i in range(n_history_blocks):
        raw = phase2.collect(node, collector, count=6, malicious_fraction=0.5)
        cleaned, _report = clean(raw)
        records = phase2.build_records(cleaned, collector)
        pipeline.run(
            cluster,
            records,
            build,
            chain=BC_SigRW,
            policy=pipeline_policy,
            timestamp=float(i),
            submitter_id=collector.identity,
            key=collector.keypair.private,
        )
    height_before = read_chain(cluster).height

    committed = True
    error: str | None = None
    try:
        pipeline.run(
            cluster,
            poisoned_records,
            build,
            chain=BC_SigRW,
            policy=pipeline_policy,
            timestamp=10_000.0,
            submitter_id=collector.identity,
            key=collector.keypair.private,
        )
    except PipelineError as exc:
        committed = False
        error = str(exc)
    height_after = read_chain(cluster).height
    return {
        "defended": defended,
        "n_history_blocks": n_history_blocks,
        "n_poisoned_records": len(poisoned_records),
        "height_before": height_before,
        "height_after": height_after,
        "committed": committed,
        "error": error,
    }


def _label_flip_burst(
    node: HoneypotNode, collector: CloudServer, *, count: int
) -> tuple[SignatureRecordPayload, ...]:
    """`count` real ransomware samples, harvested honestly, then every label flipped to benign --
    M7-11's own label-flip strategy, as a burst of records for one block rather than a training-
    set-array manipulation.
    """
    raw = phase2.collect(node, collector, count=count, malicious_fraction=1.0)
    cleaned, _report = clean(raw)
    records = phase2.build_records(cleaned, collector)
    return tuple(
        SignatureRecordPayload(
            sample_id=r.sample_id,
            content_digest=r.content_digest,
            attestation=r.attestation,
            features=r.features,
            collected_at=r.collected_at,
            schema=r.schema,
            missing_mask=r.missing_mask,
            label=BENIGN,
        )
        for r in records
    )


def _anchor_shift_burst(
    x_train: np.ndarray, y_train: np.ndarray, *, count: int, rng: np.random.Generator
) -> tuple[SignatureRecordPayload, ...]:
    """`count` synthetic records at the inter-class boundary, labelled benign -- M7-11's
    anchor-point-injection strategy (same formula, `detection.poisoning.anchor_point_injection`),
    as a burst of records for one block.
    """
    budget = count / max(int((y_train == 1).sum()), 1)
    result = anchor_point_injection(x_train, y_train, budget, rng=rng)
    rows = result.x[np.array(result.poisoned_row_indices[:count], dtype=int)]
    return tuple(
        SignatureRecordPayload(
            sample_id=f"anchor-burst-{i:03d}",
            content_digest=b"\x00" * 32,
            attestation=b"\x00" * 64,
            features=tuple(float(v) for v in row),
            collected_at=10_000 + i,
            schema=ft.SCHEMA,
            label=BENIGN,
        )
        for i, row in enumerate(rows)
    )


# --------------------------------------------------------------------------------------------
# Figure
# --------------------------------------------------------------------------------------------
def emit_comparison_figure(
    original_bal_acc: float, sweep: dict[str, dict[float, dict[str, Any]]], figures_dir: Path
) -> Path:
    fig, axes = plt.subplots(1, 3, figsize=(13.5, 4.4), dpi=150, sharey=True)
    budgets_pct = [b * 100 for b in BUDGETS]
    for ax, strategy in zip(axes, STRATEGIES, strict=True):
        undefended = [sweep[strategy][b]["undefended_bal_acc"] for b in BUDGETS]
        defended = [sweep[strategy][b]["defended_bal_acc"] for b in BUDGETS]
        ax.axhline(original_bal_acc, color="#333333", linestyle=":", linewidth=1.0)
        ax.axhline(0.50, color="#999999", linestyle="--", linewidth=0.8)
        ax.plot(
            budgets_pct,
            undefended,
            marker="o",
            markersize=4,
            linewidth=2.0,
            color=_COLOR[strategy],
            alpha=0.45,
            label="undefended (M7-11)",
        )
        ax.plot(
            budgets_pct,
            defended,
            marker="s",
            markersize=4,
            linewidth=2.0,
            color=_COLOR[strategy],
            label="defended (M7-12)",
        )
        ax.set_title(_STRATEGY_TITLE[strategy], fontsize=10)
        ax.set_xlabel("poisoning budget (%)")
        ax.set_ylim(0.0, 1.0)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.grid(axis="y", linewidth=0.5, alpha=0.3)
        ax.legend(frameon=False, fontsize=7, loc="lower left")
    axes[0].set_ylabel("balanced accuracy on the clean eval corpus")
    fig.suptitle(
        "M7-12: drift-detection defense vs M7-11's undefended damage curve",
        fontsize=11,
        x=0.02,
        ha="left",
    )
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / "fig12_drift_defense_comparison.png"
    fig.savefig(path)
    plt.close(fig)
    return path


# --------------------------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------------------------
def main() -> int:
    started = time.perf_counter()
    ml_config = load_config(REPO_ROOT / "configs" / "ml.yaml", expected_kind="ml")
    chain_config = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
    seed_all(SEED)
    run_id = log.configure()
    logger = log.get_logger(__name__)

    x_train, y_train = _load_corpus("train")
    x_eval, y_eval = _load_corpus("eval")

    original_detector = fit_detector(x_train, y_train, ml_config)
    original_metrics = clean_metrics(original_detector, x_eval, y_eval)
    drift = abs(original_metrics["balanced_accuracy"] - CSV_PATH_REFERENCE_BAL_ACC)
    if drift > _REPRODUCTION_TOLERANCE:
        raise SystemExit(
            f"baseline bal_acc={original_metrics['balanced_accuracy']:.4f} does not reproduce "
            f"the established {CSV_PATH_REFERENCE_BAL_ACC} (drift={drift:.4f})."
        )
    log.event(logger, "baseline_measured", bal_acc=round(original_metrics["balanced_accuracy"], 4))

    sweep = run_sweep(x_train, y_train, x_eval, y_eval, original_metrics, ml_config)
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            cell = sweep[strategy][budget]
            log.event(
                logger,
                "cell_measured",
                strategy=strategy,
                budget=budget,
                prevented=cell["prevented"],
                maha_score=round(cell["mahalanobis"]["score"], 4),
                defended_bal_acc=round(cell["defended_bal_acc"], 4),
                undefended_bal_acc=round(cell["undefended_bal_acc"], 4),
            )

    fpr = false_positive_rates(x_train, x_eval)
    log.event(logger, "false_positive_rate_measured", **dict(fpr))

    noise_floor = noise_floor_by_batch_size(x_train, x_eval, seed=SEED + 555)
    for n, stats in noise_floor.items():
        log.event(logger, "noise_floor_measured", n=n, **stats)

    new_family = new_family_scores(x_train, x_eval, y_eval)
    log.event(
        logger,
        "new_family_scored",
        detected=new_family["mahalanobis"]["detected"],
        score=round(new_family["mahalanobis"]["score"], 4),
    )

    # -- Step 5: two real pBFT commits --------------------------------------------------------
    # The same burst content for both the defended and undefended attempt of each scenario, so
    # the comparison is apples-to-apples; each `_real_commit_demo` call encrypts it fresh under
    # its own (deterministically identical) collector key.
    burst_node = HoneypotNode(
        identity="HP_defense_burst",
        keypair=keypair_from_secret(SEED + 900_401),
        honeypot=Honeypot(honeypot_id="HP_defense_burst", seed=SEED),
    )
    burst_collector = CloudServer(
        identity="CS_defense", keypair=keypair_from_secret(SEED + 900_302)
    )
    label_flip_records = _label_flip_burst(burst_node, burst_collector, count=POISON_BURST_SIZE)
    anchor_shift_records = _anchor_shift_burst(
        x_train, y_train, count=POISON_BURST_SIZE, rng=numpy_generator(SEED + 12345)
    )

    real_commits: dict[str, dict[str, Any]] = {}
    for defended in (False, True):
        key = "defended" if defended else "undefended"
        real_commits[f"label_flip_burst_{key}"] = _real_commit_demo(
            chain_config=chain_config,
            defended=defended,
            poisoned_records=label_flip_records,
        )
        real_commits[f"anchor_shift_burst_{key}"] = _real_commit_demo(
            chain_config=chain_config,
            defended=defended,
            poisoned_records=anchor_shift_records,
        )
    for name, result in real_commits.items():
        log.event(logger, "real_commit_attempted", scenario=name, committed=result["committed"])

    # -- Figure --------------------------------------------------------------------------------
    figures_dir = REPO_ROOT / "results" / "figures"
    fig_path = emit_comparison_figure(original_metrics["balanced_accuracy"], sweep, figures_dir)

    # -- Sidecar ---------------------------------------------------------------------------------
    wall_seconds = time.perf_counter() - started
    host = {
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "system": f"{platform.system()} {platform.release()}",
        **log.env_snapshot(),
    }
    sidecar: dict[str, Any] = {
        "run_id": run_id,
        "purpose": "M7-12 -- statistical poisoning detection: drift-detection defense measured "
        "against M7-11's three poisoning strategies, plus false-positive rate and two real "
        "pBFT commits",
        "seed": SEED,
        "config_hash": config_hash(ml_config.kind, ml_config.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": _git_rev(),
        "host": host,
        "wall_seconds": wall_seconds,
        "original_metrics": original_metrics,
        "drift_policies": {
            "mahalanobis": {
                "threshold": MAHALANOBIS_POLICY.threshold,
                "feature_threshold": MAHALANOBIS_POLICY.feature_threshold,
                "min_history_batches": MAHALANOBIS_POLICY.min_history,
            },
            "page_hinkley": {
                "ph_delta": PAGE_HINKLEY_POLICY.ph_delta,
                "ph_threshold": PAGE_HINKLEY_POLICY.ph_threshold,
                "min_history_batches": PAGE_HINKLEY_POLICY.min_history,
            },
            "chunk_size": CHUNK_SIZE,
        },
        "sweep": {s: {str(b): sweep[s][b] for b in BUDGETS} for s in STRATEGIES},
        "false_positive_rate": fpr,
        "noise_floor_by_batch_size": {str(n): stats for n, stats in noise_floor.items()},
        "new_family": new_family,
        "real_commits": real_commits,
        "figures": [str(fig_path.relative_to(REPO_ROOT))],
    }
    out_dir = REPO_ROOT / "results" / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True, default=float) + "\n", encoding="utf-8"
    )
    log.event(logger, "sidecar_written", path=f"results/logs/{run_id}.json")

    _print_results_lines(run_id, sweep, fpr, noise_floor, new_family, real_commits)
    return 0


def _print_results_lines(
    run_id: str,
    sweep: dict[str, dict[float, dict[str, Any]]],
    fpr: dict[str, float],
    noise_floor: dict[int, dict[str, float]],
    new_family: dict[str, Any],
    real_commits: dict[str, dict[str, Any]],
) -> None:
    date = time.strftime("%Y-%m-%d")
    sys.stdout.write("\n--- RESULTS.md lines ---\n")
    for strategy in STRATEGIES:
        for budget in BUDGETS:
            cell = sweep[strategy][budget]
            pct = int(budget * 100)
            sys.stdout.write(
                f"{date} | detection/honeypot-m7-12-drift-defense | {strategy} @{pct}% budget, "
                f"n_poisoned={cell['n_poisoned']} | prevented={cell['prevented']} "
                f"maha_score={cell['mahalanobis']['score']:.4f} "
                f"ph_score={cell['page_hinkley']['score']:.4f} | "
                f"undefended_bal_acc={cell['undefended_bal_acc']:.4f} "
                f"defended_bal_acc={cell['defended_bal_acc']:.4f} | measured | {run_id} | M7-12\n"
            )
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-12-false-positive-rate | {fpr['n_batches']} clean "
        f"eval-corpus batches of {CHUNK_SIZE} rows | "
        f"mahalanobis_fpr={fpr['mahalanobis']:.4f} page_hinkley_fpr={fpr['page_hinkley']:.4f} | "
        f"measured | {run_id} | M7-12\n"
    )
    for n, stats in noise_floor.items():
        sys.stdout.write(
            f"{date} | detection/honeypot-m7-12-noise-floor | {NOISE_FLOOR_TRIALS} clean "
            f"eval-corpus batches of n={n} rows | "
            f"p50={stats['p50']:.4f} p95={stats['p95']:.4f} max={stats['max']:.4f} | "
            f"measured | {run_id} | M7-12, same-size comparison for the sweep cell at this n\n"
        )
    sys.stdout.write(
        f"{date} | detection/honeypot-m7-12-new-family | {new_family['n_rows']} rows, features "
        f"scaled | mahalanobis_detected={new_family['mahalanobis']['detected']} "
        f"score={new_family['mahalanobis']['score']:.4f} | measured | {run_id} | M7-12\n"
    )
    for name, result in real_commits.items():
        sys.stdout.write(
            f"{date} | detection/honeypot-m7-12-real-commit | {name}, "
            f"{result['n_history_blocks']} honest blocks seeded, "
            f"{result['n_poisoned_records']} poisoned records in one burst | "
            f"height_before={result['height_before']} height_after={result['height_after']} "
            f"committed={result['committed']} | measured | {run_id} | M7-12\n"
        )
    sys.stdout.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
