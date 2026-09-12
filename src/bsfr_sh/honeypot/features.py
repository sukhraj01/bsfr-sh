"""`FT_RW` — the behavioural feature vector. Implements Alg. 2, line 6. DEV-03, DEV-27.

Twenty-two features in the seven groups `docs/ARCHITECTURE.md` §honeypot declares, in one fixed
order named by `SCHEMA` (`"ft_rw.v1"`). The order is part of the on-chain contract: a bare vector
of floats with no schema is not a dataset.

This module only *extracts*. Everything that decides how hard the classes are to tell apart lives
in `honeypot.collector`, so the generator and the feature map cannot quietly co-evolve into a
give-away.

The kill-chain group is truncated, and that is deliberate (DEV-27)
------------------------------------------------------------------
§II-C's chain runs infection → resource identification → encryption → notification → cleanup →
payment → decryption. Only ransomware reaches "notification" (dropping a ransom note) and beyond,
so `stage_reached` over the full chain is not a feature at all — it is the label wearing a
feature's clothes, and every model would find it and report a number about nothing.

Two honest options existed: drop the group, or keep only the part both classes produce. We keep
the prefix — arrival, enumeration, bulk transform, cleanup — because those four are genuinely
observable for benign software (an installer arrives, a backup agent enumerates, an archiver
transforms in bulk, a disk cleaner deletes), and the group then carries real signal without
carrying the answer. `observed_stages` is therefore capped at `OBSERVABLE_STAGES = 4`, and the
full walk stays in the raw and clean records for provenance where no model can reach it.
`tests/unit/test_honeypot_features.py` asserts that no single feature — this one included —
separates the classes on its own.

Unobserved features
-------------------
A honeypot does not see every stage of every sample, and the canonical encoder rejects NaN. So a
`FeatureVector` carries a `missing_mask`: bit `i` set means `values[i]` was not observed and is a
placeholder zero. Nothing is imputed here; M4 decides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from bsfr_sh.honeypot.collector import OBSERVABLE_STAGES
from bsfr_sh.honeypot.preprocess import CleanSample

__all__ = [
    "FEATURE_GROUPS",
    "FEATURE_NAMES",
    "SCHEMA",
    "FeatureVector",
    "build",
]

#: Names the feature order. Bump it if the order or meaning of any column changes.
SCHEMA: Final = "ft_rw.v1"

FEATURE_GROUPS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    (
        "filesystem",
        (
            "files_touched_per_s",
            "read_write_ratio",
            "rename_rate_per_s",
            "extension_change_rate",
            "directory_breadth",
        ),
    ),
    ("entropy", ("write_entropy_mean", "write_entropy_var", "entropy_delta")),
    ("crypto_api", ("crypto_call_rate", "key_generation_events", "crypto_ngram_novelty")),
    (
        "process",
        ("child_process_spawns", "injection_attempts", "privilege_escalation_attempts"),
    ),
    ("network", ("c2_beacon_count", "dns_entropy", "outbound_burst_rate")),
    ("persistence", ("autostart_writes", "shadow_copy_deletions", "backup_path_accesses")),
    ("kill_chain", ("observed_stages", "stage_dwell_mean_s")),
)

FEATURE_NAMES: Final[tuple[str, ...]] = tuple(
    name for _group, names in FEATURE_GROUPS for name in names
)

#: The kill-chain features are computed here rather than read from a counter.
_DERIVED: Final = frozenset({"observed_stages", "stage_dwell_mean_s"})


@dataclass(frozen=True)
class FeatureVector:
    """`FT_RW` for one sample: values in `FEATURE_NAMES` order, plus what was not observed."""

    values: tuple[float, ...]
    missing_mask: int
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if len(self.values) != len(FEATURE_NAMES):
            raise ValueError(
                f"{self.schema} has {len(FEATURE_NAMES)} features, got {len(self.values)}"
            )

    def missing(self) -> tuple[str, ...]:
        """Names of the features that were not observed."""
        return tuple(
            name for index, name in enumerate(FEATURE_NAMES) if self.missing_mask >> index & 1
        )

    def as_dict(self) -> dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.values, strict=True))


def build(sample: CleanSample) -> FeatureVector:
    """Implements Alg. 2, line 6: `DT_RWC` → `FT_RW`.

    Deterministic and total: every sample yields a full-length vector, with unobserved entries
    zeroed and flagged in `missing_mask` rather than dropped or imputed.
    """
    observed_stages = min(OBSERVABLE_STAGES, sum(1 for stage in sample.stages if stage.observed))
    dwell = [stage.dwell_s for stage in sample.stages[:OBSERVABLE_STAGES] if stage.observed]
    derived = {
        "observed_stages": float(observed_stages),
        "stage_dwell_mean_s": float(sum(dwell) / len(dwell)) if dwell else 0.0,
    }

    values: list[float] = []
    mask = 0
    for index, name in enumerate(FEATURE_NAMES):
        if name in _DERIVED:
            values.append(derived[name])
            if not dwell and name == "stage_dwell_mean_s":
                mask |= 1 << index
            continue
        value = sample.counters.get(name)
        if value is None or name in sample.missing:
            values.append(0.0)
            mask |= 1 << index
        else:
            values.append(float(value))
    return FeatureVector(values=tuple(values), missing_mask=mask)
