"""Distributional drift detection for `BC_SigRW` batches. M7-12.

`docs/THREAT_MODEL.md` Gap 1 (named M7-9, measured M7-11): `Chain.check_append()`'s five checks
(`docs/ARCHITECTURE.md` §blockchain) are all structural or cryptographic — none inspect what a
`Sig_RW`/`FT_RW` record actually says, so a validly-signed poisoned record commits exactly as
cleanly as an honest one. This module is the missing semantic check: each honest replica keeps a
running per-feature statistical profile of every `FT_RW` batch it has seen committed, and scores
a new batch's distributional shift against that profile before voting to accept it.

This is deliberately **not** per-sample outlier detection. DEV-26 already warned against that in
the honeypot's own design: a single unusual sample can be genuine, newly-observed ransomware
behaviour, not poison. What this module flags is a *batch* whose aggregate feature statistics
move further from history than any previously accepted batch has — the signature of a poisoning
campaign that systematically biases the corpus, not of one odd sample passing through.

Two independent methods, so `scripts/m7_12_poisoning_defense.py` can compare them rather than
trust one blindly:

* **Mahalanobis** (diagonal) — the batch centroid's standardized distance from the running
  per-feature mean, in running-standard-deviation units, aggregated as an RMS across features.
  Stateless given the running profile: two replicas with the same profile and the same batch
  always compute the same score (Trust Assumption, see `docs/THREAT_MODEL.md`).
* **Page-Hinkley** (Page 1954) — a classical streaming mean-shift test applied to the scalar
  Mahalanobis signal itself, so a slow, cumulative drift across many small batches — each too
  small to clear the Mahalanobis threshold alone — is still caught once its cumulative deviation
  does.

Both are built on Welford's online algorithm (`RunningStats`), so the running profile is a fixed
handful of floats per feature: no historical sample is ever stored or re-read. A full per-feature
Kolmogorov-Smirnov test needs the historical sample *values*, not just their moments, so it is not
implemented here — a scope choice, not an oversight; see `docs/DEVIATIONS.md` DEV-38.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

import numpy as np

__all__ = [
    "DriftDetector",
    "DriftMethod",
    "DriftPolicy",
    "DriftReport",
    "RunningStats",
]


class DriftMethod(Enum):
    """Which scalar test `DriftDetector.score_batch` reports `drift_detected` from."""

    MAHALANOBIS = "mahalanobis"
    PAGE_HINKLEY = "page_hinkley"


@dataclass
class RunningStats:
    """Welford's online mean/variance for one feature.

    `count`/`mean`/`m2` are the textbook three numbers (Welford 1962); no sample is ever kept.
    `merge_batch` is the parallel (Chan et al. 1979) variant — merging a whole batch is O(1)
    regardless of the batch's own size, rather than looping one `update()` call per row.
    """

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        """Fold in one more observation."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    @property
    def variance(self) -> float:
        return 0.0 if self.count < 2 else self.m2 / (self.count - 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def merge_batch(self, batch_mean: float, batch_variance: float, batch_n: int) -> None:
        """Fold in a whole batch's own mean/variance/count in one O(1) step."""
        if batch_n <= 0:
            return
        if self.count == 0:
            self.count = batch_n
            self.mean = batch_mean
            self.m2 = batch_variance * max(batch_n - 1, 0)
            return
        delta = batch_mean - self.mean
        total = self.count + batch_n
        batch_m2 = batch_variance * max(batch_n - 1, 0)
        self.m2 += batch_m2 + delta * delta * self.count * batch_n / total
        self.mean += delta * batch_n / total
        self.count = total


@dataclass(frozen=True)
class DriftPolicy:
    """Tunables shared by every honest replica scoring one `BC_SigRW` (Trust Assumption 7,
    `docs/THREAT_MODEL.md`: replicas that disagree on this policy disagree on whether to vote).
    """

    method: DriftMethod = DriftMethod.MAHALANOBIS
    #: Mahalanobis alarm threshold, in running-standard-deviation RMS units.
    threshold: float = 3.0
    #: Per-feature offending-feature-list threshold, same units as `threshold`.
    feature_threshold: float = 3.0
    #: Page-Hinkley's allowed per-batch slack, same units as the Mahalanobis signal it watches.
    ph_delta: float = 0.5
    #: Page-Hinkley alarm threshold (the classical "lambda").
    ph_threshold: float = 6.0
    #: Batches committed before the running profile is trusted enough to flag anything. Below
    #: this, `score_batch` always returns `drift_detected=False` — the honest reading of "we have
    #: no profile yet to compare against," not a silent false negative (see the cold-start note
    #: on `DriftDetector.score_batch`).
    min_history: int = 5

    def __post_init__(self) -> None:
        if self.threshold <= 0:
            raise ValueError("threshold must be positive")
        if self.feature_threshold <= 0:
            raise ValueError("feature_threshold must be positive")
        if self.ph_delta < 0:
            raise ValueError("ph_delta must be non-negative")
        if self.ph_threshold <= 0:
            raise ValueError("ph_threshold must be positive")
        if self.min_history < 1:
            raise ValueError("min_history must be at least 1")


@dataclass(frozen=True)
class DriftReport:
    """One `score_batch()` call's verdict."""

    method: DriftMethod
    score: float
    threshold: float
    drift_detected: bool
    #: Feature names whose own standardized deviation exceeds `DriftPolicy.feature_threshold` —
    #: what a replica's warning log names as "the offending feature(s)" (task brief, item 2).
    offending_features: tuple[str, ...]
    #: How many batches the running profile was built from when this batch was scored. Below
    #: `DriftPolicy.min_history`, this report is a cold-start pass, not a judgement.
    n_history_batches: int


class DriftDetector:
    """Per-replica running profile plus the two scoring methods `DriftPolicy.method` picks from.

    One instance per `BC_SigRW` replica `Chain` (`consensus.validated_commit.
    build_validated_sigrw_chain_factory` builds a fresh one per replica) — "each honest replica
    maintains a running statistical profile" (task brief) is this class, one per replica.
    """

    def __init__(
        self,
        n_features: int,
        *,
        feature_names: Sequence[str] | None = None,
        policy: DriftPolicy | None = None,
    ) -> None:
        if n_features <= 0:
            raise ValueError(f"n_features must be positive, got {n_features}")
        self._policy = policy if policy is not None else DriftPolicy()
        if feature_names is None:
            self._feature_names: tuple[str, ...] = tuple(f"f{i}" for i in range(n_features))
        else:
            names = tuple(feature_names)
            if len(names) != n_features:
                raise ValueError(
                    f"feature_names has {len(names)} entries, expected n_features={n_features}"
                )
            self._feature_names = names
        self._stats: tuple[RunningStats, ...] = tuple(RunningStats() for _ in range(n_features))
        self._n_batches = 0
        # Page-Hinkley state over the scalar Mahalanobis signal, kept separately from `_stats` so
        # `score_batch` can peek at "what would the PH statistic become" without mutating either.
        self._ph_signal_count = 0
        self._ph_mean_signal = 0.0
        self._ph_cumulative = 0.0
        self._ph_min = 0.0

    @property
    def policy(self) -> DriftPolicy:
        return self._policy

    @property
    def n_features(self) -> int:
        return len(self._stats)

    @property
    def n_history_batches(self) -> int:
        return self._n_batches

    def _check_batch_shape(self, batch: np.ndarray) -> np.ndarray:
        arr = np.asarray(batch, dtype=float)
        if arr.ndim != 2 or arr.shape[1] != self.n_features:
            raise ValueError(
                f"batch must be 2D with {self.n_features} columns, got shape {arr.shape}"
            )
        if arr.shape[0] == 0:
            raise ValueError("batch must have at least one row")
        return arr

    def _standardized_deviation(self, batch: np.ndarray) -> np.ndarray:
        """Per-feature `(batch_mean - running_mean) / running_std`.

        A feature with zero observed spread so far (cold start, or a genuinely constant feature)
        cannot be standardized by division; it scores 0 if the batch matches it exactly and the
        policy's threshold if it does not, rather than a `inf`/`NaN` from dividing by zero.
        """
        batch_mean = batch.mean(axis=0)
        dev = np.empty(self.n_features, dtype=float)
        for i, stats in enumerate(self._stats):
            std = stats.std
            if std <= 1e-12:
                dev[i] = 0.0 if abs(batch_mean[i] - stats.mean) <= 1e-12 else self._policy.threshold
            else:
                dev[i] = (batch_mean[i] - stats.mean) / std
        return dev

    def _mahalanobis_score(self, batch: np.ndarray) -> tuple[float, np.ndarray]:
        dev = self._standardized_deviation(batch)
        score = float(np.sqrt(np.mean(np.square(dev))))
        return score, dev

    def _offending(self, dev: np.ndarray) -> tuple[str, ...]:
        return tuple(
            name
            for name, d in zip(self._feature_names, dev, strict=True)
            if abs(d) >= self._policy.feature_threshold
        )

    def _peek_page_hinkley(self, signal: float) -> float:
        if self._ph_signal_count == 0:
            return 0.0
        cumulative = self._ph_cumulative + (signal - self._ph_mean_signal - self._policy.ph_delta)
        running_min = min(self._ph_min, cumulative)
        return cumulative - running_min

    def score_batch(self, batch: np.ndarray) -> DriftReport:
        """Score `batch` against the current profile. Never mutates the detector's state.

        Cold start: before `DriftPolicy.min_history` batches have been committed, there is no
        profile worth comparing against, so this always returns `drift_detected=False` — the
        honest statement that the very first blocks on a chain (M7-11's permanence demo is
        exactly this case) cannot be defended by a mechanism that needs history to compare
        against. `docs/THREAT_MODEL.md` states this as a limitation, not a silent gap.
        """
        arr = self._check_batch_shape(batch)
        threshold = (
            self._policy.threshold
            if self._policy.method is DriftMethod.MAHALANOBIS
            else self._policy.ph_threshold
        )
        if self._n_batches < self._policy.min_history:
            return DriftReport(self._policy.method, 0.0, threshold, False, (), self._n_batches)

        score, dev = self._mahalanobis_score(arr)
        offending = self._offending(dev)
        if self._policy.method is DriftMethod.MAHALANOBIS:
            return DriftReport(
                DriftMethod.MAHALANOBIS,
                score,
                threshold,
                score >= threshold,
                offending,
                self._n_batches,
            )
        ph_value = self._peek_page_hinkley(score)
        return DriftReport(
            DriftMethod.PAGE_HINKLEY,
            ph_value,
            threshold,
            ph_value >= threshold,
            offending,
            self._n_batches,
        )

    def update(self, batch: np.ndarray) -> None:
        """Commit an *accepted* batch into the running profile.

        Call only after the block this batch belongs to has actually been appended. A batch that
        failed to commit never happened, from the profile's point of view — an unappended batch
        must not shift what future batches are compared against.
        """
        arr = self._check_batch_shape(batch)
        if self._n_batches >= self._policy.min_history:
            score, _dev = self._mahalanobis_score(arr)
            self._commit_page_hinkley(score)
        for i, stats in enumerate(self._stats):
            column = arr[:, i]
            variance = float(column.var(ddof=1)) if len(column) > 1 else 0.0
            stats.merge_batch(float(column.mean()), variance, len(column))
        self._n_batches += 1

    def _commit_page_hinkley(self, signal: float) -> None:
        if self._ph_signal_count == 0:
            self._ph_mean_signal = signal
            self._ph_signal_count = 1
            self._ph_cumulative = 0.0
            self._ph_min = 0.0
            return
        self._ph_signal_count += 1
        self._ph_mean_signal += (signal - self._ph_mean_signal) / self._ph_signal_count
        self._ph_cumulative += signal - self._ph_mean_signal - self._policy.ph_delta
        self._ph_min = min(self._ph_min, self._ph_cumulative)
