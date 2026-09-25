"""Synthetic-vs-real per-feature distribution comparison. M7-7.

Synthetic-only evaluation (M4b's 0.8422, `docs/DEVIATIONS.md` DEV-27) can never say whether
`honeypot.collector`'s generated distributions resemble anything real — the detector and the
generator were built by the same hands. A two-sample Kolmogorov-Smirnov test per feature is the
direct check: for each `FT_RW` feature that has a real analogue at all (`honeypot.
external_mapping`'s `DIRECT`/`PROXY` features — a `MISSING` feature is a constant `0.0` under the
mapping and a KS test against a constant is a statement about the mapping, not the generator), how
different are the synthetic corpus's values from the mapped real dataset's?
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.stats import ks_2samp

__all__ = ["KSResult", "compare_distributions"]


@dataclass(frozen=True)
class KSResult:
    """One feature's two-sample KS test: synthetic corpus vs. mapped real data."""

    feature: str
    statistic: float
    p_value: float
    n_synthetic: int
    n_real: int
    synthetic_mean: float
    real_mean: float

    def as_dict(self) -> dict[str, object]:
        return {
            "feature": self.feature,
            "ks_statistic": self.statistic,
            "p_value": self.p_value,
            "n_synthetic": self.n_synthetic,
            "n_real": self.n_real,
            "synthetic_mean": self.synthetic_mean,
            "real_mean": self.real_mean,
        }


def compare_distributions(feature: str, synthetic: np.ndarray, real: np.ndarray) -> KSResult:
    """Two-sample KS test for one feature. A small `p_value` means the two samples are unlikely
    to be drawn from the same distribution -- the synthetic generator and the mapped real data
    disagree on that feature's shape, not just its mean."""
    result = ks_2samp(np.asarray(synthetic, dtype=np.float64), np.asarray(real, dtype=np.float64))
    return KSResult(
        feature=feature,
        statistic=float(result.statistic),
        p_value=float(result.pvalue),
        n_synthetic=len(synthetic),
        n_real=len(real),
        synthetic_mean=float(np.mean(synthetic)),
        real_mean=float(np.mean(real)),
    )
