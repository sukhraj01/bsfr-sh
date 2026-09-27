"""Federated detection via cross-replica disagreement. M7-15, `docs/THREAT_MODEL.md` Gap 1.

M7-12 (`detection.drift`) caught poisoning by inspecting *feature distributions*: it fails when
the poison looks statistically normal (anchor-point injection, measured invisible at every budget).
M7-14 (`consensus.commit_reveal`) caught it by restricting *information*: it fails when historical
data alone already estimates the boundary the current round would have revealed anyway (measured
null on this corpus). Both look at the data. This module looks at something neither does: the
*model outputs* four independently-trained replicas produce, exploiting redundancy the paper's own
architecture already provides for free (`docs/ARCHITECTURE.md` §consensus: `n=4` cloud servers,
each with a decryption key and each capable of running Alg. 3 on its own view of `BC_SigRW`,
`docs/THREAT_MODEL.md` Trust Assumption 6). No new protocol message, no new trust assumption
beyond what pBFT already provides, no threshold to tune.

**The subtlety this module does not paper over.** If every node trains on the same committed
chain, why would their models ever disagree? Three reasons, each a distinct scenario the
evaluation script (`scripts/m7_15_federated_detection.py`) measures separately:

(a) A poisoner commits poisoned data (so honest replicas train on poison) but trains its *own*
    model on a clean view (so it can still detect ransomware for itself). Rational for an
    attacker who wants to degrade *others'* detection, not its own — and the honest consequence is
    that the "outlier" this module identifies can be the node with the *correct* model. This
    module states that possibility as a fact about what disagreement means, not a flaw: it names
    the most-divergent node and hands the caller both individual and post-exclusion accuracy so
    that fact is visible in the numbers rather than assumed away.
(b) Algorithm diversity: RF/DT/KNN/LR respond differently to identical poisoned data, so ensemble
    disagreement can come from differential model sensitivity with no data difference at all.
(c) A private, never-committed holdout (this project's own extension, not the paper's Algorithm 3,
    which trains exclusively on `BC_SigRW`) lets one node compare its chain-trained model against
    data it trusts, independent of any other node's vote — the one scenario that needs no
    cross-node communication at all.

This module supplies the generic mechanism common to all three (voting, disagreement scoring,
outlier identification); which scenario produced a given set of per-node predictions is the
calling script's concern, not this module's — same separation `detection.poisoning` (attack) and
`scripts/m7_11_honeypot_poisoning.py` (measurement) already established.

Safety (CLAUDE.md §2): this module only aggregates 0/1 arrays and calls `detection.adversarial`'s
already-tested `ensemble_predict`/`balanced_accuracy`. No new model training happens here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import numpy as np

from bsfr_sh.detection.adversarial import balanced_accuracy, ensemble_predict
from bsfr_sh.detection.detector import DetectionModule

__all__ = [
    "DisagreementReport",
    "FederatedDetector",
    "VotingResult",
    "analyze_disagreement",
    "majority_vote",
    "vote",
]


@dataclass(frozen=True)
class FederatedDetector:
    """N independently-fitted `DetectionModule`s, one per cloud-server node.

    A thin wrapper, not a new detection mechanism: each node's own module decides exactly as
    Alg. 3 lines 4-9 specify. What differs from a single-server deployment is only what happens
    *after* N independent verdicts exist on the same sample — that is `vote`/`analyze_disagreement`
    below, not this class.
    """

    nodes: Mapping[str, DetectionModule]

    def predict_all(self, x_eval: np.ndarray) -> dict[str, np.ndarray]:
        """Every node's independent 0/1 verdict on the same eval rows."""
        if not self.nodes:
            raise ValueError("FederatedDetector has no nodes to predict with")
        return {node_id: ensemble_predict(dm, x_eval) for node_id, dm in self.nodes.items()}


def majority_vote(per_node_predictions: Mapping[str, np.ndarray]) -> np.ndarray:
    """Strict-majority vote over N nodes' per-sample 0/1 predictions.

    Tie policy: an exact 50/50 split (reachable only at an even node count, e.g. 2-2 of 4) resolves
    to 0 (benign) — a tie is not a majority, and a detector that cannot agree with itself should
    not unilaterally declare positive. This is a stated convention, not a derived one: at `n=4`
    the paper's own deployment size, ties are the one case this function's answer is a choice
    rather than an arithmetic fact.
    """
    if not per_node_predictions:
        raise ValueError("no node predictions to vote over")
    votes = np.stack(list(per_node_predictions.values()), axis=0)
    result: np.ndarray = (votes.mean(axis=0) > 0.5).astype(np.int8)
    return result


@dataclass(frozen=True)
class VotingResult:
    """`VotingPolicy`'s output: the majority decision plus which nodes disagree with it often
    enough to flag."""

    per_node_predictions: dict[str, np.ndarray]
    majority: np.ndarray
    disagreement_fraction: dict[str, float]
    flagged_nodes: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        rounded = {k: round(v, 6) for k, v in self.disagreement_fraction.items()}
        return {
            "disagreement_fraction": rounded,
            "flagged_nodes": list(self.flagged_nodes),
        }


def vote(
    per_node_predictions: Mapping[str, np.ndarray], *, flag_threshold: float = 0.10
) -> VotingResult:
    """Majority-vote decision plus per-node flagging: a node whose predictions differ from the
    majority on more than `flag_threshold` of samples is flagged as a disagreement candidate.

    Kept separate from `DisagreementAnalyzer.analyze_disagreement` below (which additionally needs
    ground truth to say anything about *accuracy*) so a deployed voting step never needs labels it
    would not have at decision time — `vote` only ever needs what N independent detectors already
    produced.
    """
    majority = majority_vote(per_node_predictions)
    disagreement = {
        node_id: float(np.mean(pred != majority)) for node_id, pred in per_node_predictions.items()
    }
    flagged = tuple(node_id for node_id, frac in disagreement.items() if frac > flag_threshold)
    return VotingResult(
        per_node_predictions={k: np.asarray(v) for k, v in per_node_predictions.items()},
        majority=majority,
        disagreement_fraction=disagreement,
        flagged_nodes=flagged,
    )


@dataclass(frozen=True)
class DisagreementReport:
    """`DisagreementAnalyzer`'s output over one common eval set.

    `outlier_node` is named by disagreement alone, never by accuracy — this report does not know,
    and must not assume, that the most-divergent node is the wrong one. Scenario (a)'s own finding
    is that it can be the node with the *correct* model; `individual_accuracy` and
    `accuracy_excluding_outlier` are reported precisely so that fact is visible in the numbers
    rather than assumed away by the identification step itself.
    """

    agreement_rate: dict[str, float]
    per_sample_disagreement_count: np.ndarray
    outlier_node: str | None
    majority_accuracy: float | None
    individual_accuracy: dict[str, float] | None
    accuracy_excluding_outlier: float | None
    excluding_outlier_improves: bool | None

    def as_dict(self) -> dict[str, object]:
        return {
            "agreement_rate": {k: round(v, 6) for k, v in self.agreement_rate.items()},
            "outlier_node": self.outlier_node,
            "majority_accuracy": self.majority_accuracy,
            "individual_accuracy": self.individual_accuracy,
            "accuracy_excluding_outlier": self.accuracy_excluding_outlier,
            "excluding_outlier_improves": self.excluding_outlier_improves,
        }


def analyze_disagreement(
    per_node_predictions: Mapping[str, np.ndarray], y_true: np.ndarray | None = None
) -> DisagreementReport:
    """The disagreement fingerprint: per-node agreement with the majority, the single most-
    divergent node (the candidate poisoner — or, per scenario (a), the candidate honest outlier),
    and, when ground truth is available, whether excluding that node improves majority accuracy.

    `outlier_node` is `None` when there is nothing to single out: perfect agreement (every node's
    disagreement fraction is exactly 0) or an exact tie among the most-divergent nodes both leave
    "the one that disagrees most" undefined, and returning an arbitrary pick would misrepresent a
    non-finding as a finding.
    """
    if not per_node_predictions:
        raise ValueError("no node predictions to analyze")
    majority = majority_vote(per_node_predictions)
    disagreement_fraction = {
        node_id: float(np.mean(pred != majority)) for node_id, pred in per_node_predictions.items()
    }
    agreement_rate = {k: 1.0 - v for k, v in disagreement_fraction.items()}
    stacked = np.stack(list(per_node_predictions.values()), axis=0)
    per_sample_disagreement_count = (stacked != majority).sum(axis=0)

    most_divergent = max(disagreement_fraction, key=lambda k: disagreement_fraction[k])
    top = disagreement_fraction[most_divergent]
    tied_at_top = sum(1 for v in disagreement_fraction.values() if v == top)
    outlier_node: str | None = None if (top <= 0.0 or tied_at_top > 1) else most_divergent

    majority_accuracy: float | None = None
    individual_accuracy: dict[str, float] | None = None
    accuracy_excluding_outlier: float | None = None
    excluding_outlier_improves: bool | None = None
    if y_true is not None:
        majority_accuracy = balanced_accuracy(y_true, majority)
        individual_accuracy = {
            node_id: balanced_accuracy(y_true, pred)
            for node_id, pred in per_node_predictions.items()
        }
        if outlier_node is not None and len(per_node_predictions) > 1:
            remaining = {k: v for k, v in per_node_predictions.items() if k != outlier_node}
            excluded_majority = majority_vote(remaining)
            accuracy_excluding_outlier = balanced_accuracy(y_true, excluded_majority)
            excluding_outlier_improves = accuracy_excluding_outlier > majority_accuracy

    return DisagreementReport(
        agreement_rate=agreement_rate,
        per_sample_disagreement_count=per_sample_disagreement_count,
        outlier_node=outlier_node,
        majority_accuracy=majority_accuracy,
        individual_accuracy=individual_accuracy,
        accuracy_excluding_outlier=accuracy_excluding_outlier,
        excluding_outlier_improves=excluding_outlier_improves,
    )
