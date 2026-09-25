"""Maps ClaMP's real, static PE-header dataset onto `FT_RW`'s 22-feature schema. M7-7, DEV-34.

`honeypot.features` defines `FT_RW` as a 7-group *dynamic behavioural* schema: what a monitor
observes a running program *do* (files touched, entropy of writes, crypto calls, process
spawns, network beacons, persistence writes, kill-chain progress). ClaMP
(github.com/urwithajit9/ClaMP, `data/external/clamp/README.md`) is real malware/benign data, but
it is *static* — header fields read off a PE file that is never executed. The honest mapping this
produces is lopsided, and that lopsidedness is itself the finding this module exists to make
legible: only the entropy group has any real-world analogue at all, because entropy is one of the
few observables that is measurable both statically (a file's own byte distribution) and
dynamically (the byte distribution of what a process writes). The other six groups — filesystem,
crypto API, process, network, persistence, kill-chain — have **no** analogue in a dataset that
never ran the sample, and are marked `MISSING` rather than forced into a proxy that would not mean
anything.

`MISSING` features are handled exactly as `honeypot.features.build()` already handles an
unobserved sensor: value `0.0`, and the corresponding `missing_mask` bit set. Nothing new is
invented for "missing" here; this module only decides, once, which of the 22 slots that applies
to. The decision is structural, not per-row — the same slots are missing for every ClaMP row,
because the dataset's *schema* lacks them, not because of a per-sample sensor failure.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from bsfr_sh.honeypot.features import FEATURE_GROUPS, FEATURE_NAMES, FeatureVector

__all__ = [
    "CLAMP_MAPPING",
    "CLAMP_SOURCE_COLUMNS",
    "ClaMPMappingError",
    "FeatureMapping",
    "MappingKind",
    "build_from_clamp_row",
    "mapping_summary",
]


class ClaMPMappingError(ValueError):
    """Raised when a ClaMP row is missing a column this mapping depends on."""


class MappingKind(StrEnum):
    """How grounded one `FT_RW` feature is in ClaMP's real, static data."""

    #: The real column *is* the concept, no approximation.
    DIRECT = "direct"
    #: A real column stands in for a related-but-not-identical concept; flagged, not hidden.
    PROXY = "proxy"
    #: No real analogue exists in a static dataset; handled like an unobserved sensor.
    MISSING = "missing"


@dataclass(frozen=True)
class FeatureMapping:
    """One `FT_RW` feature's mapping decision, and why."""

    feature: str
    kind: MappingKind
    source_columns: tuple[str, ...]
    rationale: str
    compute: Callable[[Mapping[str, float]], float] | None = None


def _entropy_mean(row: Mapping[str, float]) -> float:
    """`write_entropy_mean` <- `E_file`: whole-file entropy stands in for mean write entropy.

    Not identical — `E_file` is one number over the whole artifact, `write_entropy_mean` is a mean
    over many observed write operations — but both measure "how close to random are this
    program's bytes," which is exactly what makes high entropy a ransomware indicator in either
    reading.
    """
    return float(row["E_file"])


def _entropy_var(row: Mapping[str, float]) -> float:
    """`write_entropy_var` <- population variance of `{E_text, E_data}`.

    A two-point variance is a weak stand-in for variance across many observed writes — flagged as
    the weakest of the three entropy proxies, kept anyway because ClaMP has no third entropy
    reading to add a third point.
    """
    text, data = float(row["E_text"]), float(row["E_data"])
    return ((text - data) / 2.0) ** 2


def _entropy_delta(row: Mapping[str, float]) -> float:
    """`entropy_delta` <- `|E_data - E_text|`.

    `honeypot.collector` draws `entropy_delta` from a log-normal distribution (strictly
    non-negative — it is a *magnitude* of change, not a signed difference), so the proxy takes
    the absolute value of the code/data section entropy gap rather than the signed gap, matching
    that convention rather than silently changing the feature's sign semantics.
    """
    return abs(float(row["E_data"]) - float(row["E_text"]))


#: Every `FT_RW` feature not listed with a `compute` here is `MISSING` — no real analogue exists
#: in a dataset that never executed the sample. Built as one literal table, in `FEATURE_NAMES`
#: order via `FEATURE_GROUPS`, so every feature is accounted for exactly once
#: (`test_honeypot_external_mapping.py::test_every_ft_rw_feature_has_a_mapping_decision`).
CLAMP_MAPPING: Final[dict[str, FeatureMapping]] = {
    # -- filesystem: no dynamic file I/O is observed in a static PE-header dataset. -------------
    "files_touched_per_s": FeatureMapping(
        "files_touched_per_s", MappingKind.MISSING, (), "No runtime file I/O in static PE data."
    ),
    "read_write_ratio": FeatureMapping(
        "read_write_ratio", MappingKind.MISSING, (), "No runtime file I/O in static PE data."
    ),
    "rename_rate_per_s": FeatureMapping(
        "rename_rate_per_s", MappingKind.MISSING, (), "No runtime file I/O in static PE data."
    ),
    "extension_change_rate": FeatureMapping(
        "extension_change_rate", MappingKind.MISSING, (), "No runtime file I/O in static PE data."
    ),
    "directory_breadth": FeatureMapping(
        "directory_breadth",
        MappingKind.MISSING,
        (),
        "No runtime filesystem traversal in static PE data; `NumberOfSections` (PE structure "
        "breadth) was considered as a proxy and rejected — a section count is not a directory "
        "count, and forcing the analogy would hide rather than inform the mismatch.",
    ),
    # -- entropy: the one group with real correspondence. ----------------------------------------
    "write_entropy_mean": FeatureMapping(
        "write_entropy_mean",
        MappingKind.PROXY,
        ("E_file",),
        "Whole-file entropy stands in for mean write-operation entropy; both measure closeness "
        "to random bytes.",
        compute=_entropy_mean,
    ),
    "write_entropy_var": FeatureMapping(
        "write_entropy_var",
        MappingKind.PROXY,
        ("E_text", "E_data"),
        "Population variance of the two available section-entropy readings; weak (n=2) but the "
        "only entropy spread ClaMP offers.",
        compute=_entropy_var,
    ),
    "entropy_delta": FeatureMapping(
        "entropy_delta",
        MappingKind.PROXY,
        ("E_text", "E_data"),
        "Absolute code/data section entropy gap, matching the non-negative (magnitude) "
        "convention `honeypot.collector` draws this feature under.",
        compute=_entropy_delta,
    ),
    # -- crypto_api: ClaMP's header fields carry no import table / API call information. --------
    "crypto_call_rate": FeatureMapping(
        "crypto_call_rate", MappingKind.MISSING, (), "No import/API-call data in static PE headers."
    ),
    "key_generation_events": FeatureMapping(
        "key_generation_events",
        MappingKind.MISSING,
        (),
        "No import/API-call data in static PE headers.",
    ),
    "crypto_ngram_novelty": FeatureMapping(
        "crypto_ngram_novelty",
        MappingKind.MISSING,
        (),
        "No API call sequence is observable without executing the sample.",
    ),
    # -- process: requires execution, which a static dataset never performs. --------------------
    "child_process_spawns": FeatureMapping(
        "child_process_spawns", MappingKind.MISSING, (), "Requires execution; ClaMP is static."
    ),
    "injection_attempts": FeatureMapping(
        "injection_attempts", MappingKind.MISSING, (), "Requires execution; ClaMP is static."
    ),
    "privilege_escalation_attempts": FeatureMapping(
        "privilege_escalation_attempts",
        MappingKind.MISSING,
        (),
        "Requires execution; ClaMP is static.",
    ),
    # -- network: requires execution. ------------------------------------------------------------
    "c2_beacon_count": FeatureMapping(
        "c2_beacon_count", MappingKind.MISSING, (), "Requires execution; ClaMP is static."
    ),
    "dns_entropy": FeatureMapping(
        "dns_entropy", MappingKind.MISSING, (), "Requires execution; ClaMP is static."
    ),
    "outbound_burst_rate": FeatureMapping(
        "outbound_burst_rate", MappingKind.MISSING, (), "Requires execution; ClaMP is static."
    ),
    # -- persistence: requires execution. --------------------------------------------------------
    "autostart_writes": FeatureMapping(
        "autostart_writes", MappingKind.MISSING, (), "Requires execution; ClaMP is static."
    ),
    "shadow_copy_deletions": FeatureMapping(
        "shadow_copy_deletions", MappingKind.MISSING, (), "Requires execution; ClaMP is static."
    ),
    "backup_path_accesses": FeatureMapping(
        "backup_path_accesses", MappingKind.MISSING, (), "Requires execution; ClaMP is static."
    ),
    # -- kill_chain: requires a monitored episode; ClaMP has no dynamic timeline at all. ---------
    "observed_stages": FeatureMapping(
        "observed_stages",
        MappingKind.MISSING,
        (),
        "No monitored kill-chain episode exists for a file that was never run.",
    ),
    "stage_dwell_mean_s": FeatureMapping(
        "stage_dwell_mean_s",
        MappingKind.MISSING,
        (),
        "No monitored kill-chain episode exists for a file that was never run.",
    ),
}

#: Every ClaMP column any mapping reads — used to validate a row before mapping it.
CLAMP_SOURCE_COLUMNS: Final[tuple[str, ...]] = tuple(
    sorted({col for m in CLAMP_MAPPING.values() for col in m.source_columns})
)


def build_from_clamp_row(row: Mapping[str, float]) -> FeatureVector:
    """One ClaMP row -> one `FT_RW` `FeatureVector`. Deterministic and total, like
    `honeypot.features.build()`: every row yields a full-length vector, missing slots zeroed and
    flagged rather than dropped.
    """
    missing_columns = [c for c in CLAMP_SOURCE_COLUMNS if c not in row]
    if missing_columns:
        raise ClaMPMappingError(f"row is missing required columns: {missing_columns}")
    values: list[float] = []
    mask = 0
    for index, name in enumerate(FEATURE_NAMES):
        spec = CLAMP_MAPPING[name]
        if spec.kind is MappingKind.MISSING or spec.compute is None:
            values.append(0.0)
            mask |= 1 << index
        else:
            values.append(spec.compute(row))
    return FeatureVector(values=tuple(values), missing_mask=mask)


def mapping_summary() -> dict[str, dict[str, object]]:
    """One row per `FT_RW` group: how many of its features are direct/proxy/missing. For the
    session's report table and `RESULTS.md` line — computed here so the table and the code that
    decided it can never drift apart.
    """
    summary: dict[str, dict[str, object]] = {}
    for group, names in FEATURE_GROUPS:
        counts = {kind.value: 0 for kind in MappingKind}
        for name in names:
            counts[CLAMP_MAPPING[name].kind.value] += 1
        summary[group] = {"n_features": len(names), **counts}
    return summary
