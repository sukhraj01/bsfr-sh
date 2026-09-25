"""Maps EMBER's real, static PE-feature dataset onto `FT_RW`'s 22-feature schema. M7-10, DEV-35.

Same posture as `honeypot.external_mapping` (M7-7, DEV-34): `FT_RW` is a *dynamic behavioural*
schema — what a monitor observes a running program *do*. EMBER (github.com/elastic/ember,
`ember_dataset_2018_2.tar.bz2`) is real malware/benign data, but it is *static* — LIEF-extracted
header/structure/string features read off a PE file that is never executed. That mismatch does
not go away with a richer dataset. What changes is how much of it a richer *static* dataset can
still ground: EMBER's raw per-sample record carries a 256-bin whole-file byte histogram, every PE
section's own Shannon entropy, section read/write/execute flags, and a full per-DLL import table
— none of which ClaMP's fixed handful of header floats exposed. This module reuses M7-7's
`MappingKind` convention (`DIRECT`/`PROXY`/`MISSING`) and maps every `FT_RW` feature against that
richer source, honestly: 6 of 22 features get a real (if often weak) proxy here, against ClaMP's
3 of 22 (`mapping_summary()` on each is the coverage-fraction comparison the session brief asks
for) — still zero for the five groups that are inherently execution-time observables (process,
network, persistence, kill-chain, plus filesystem's traversal/rename/rename-rate features).

`MISSING` features are handled exactly as `honeypot.features.build()` and `external_mapping`
already handle an unobserved sensor: value `0.0`, `missing_mask` bit set. The decision is
structural (the same slots are missing for every EMBER row, because the *schema* lacks the
observable, not because of a per-sample failure), same as `external_mapping`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import numpy as np

from bsfr_sh.honeypot.external_mapping import MappingKind
from bsfr_sh.honeypot.features import FEATURE_GROUPS, FEATURE_NAMES, FeatureVector

__all__ = [
    "EMBER_MAPPING",
    "EMBER_REQUIRED_TOP_LEVEL_FIELDS",
    "EmberMappingError",
    "FeatureMapping",
    "MappingKind",
    "build_from_ember_row",
    "mapping_summary",
]


class EmberMappingError(ValueError):
    """Raised when an EMBER row is missing a top-level field this mapping depends on."""


@dataclass(frozen=True)
class FeatureMapping:
    """One `FT_RW` feature's mapping decision against EMBER, and why."""

    feature: str
    kind: MappingKind
    source_fields: tuple[str, ...]
    rationale: str
    compute: Callable[[Mapping[str, Any]], float] | None = None


#: Every EMBER raw-feature top-level key any mapping reads. Present on every row of the dataset
#: (LIEF always emits these sections, even empty, for a file it can parse at all) — validated
#: once per row, same posture as `external_mapping.CLAMP_SOURCE_COLUMNS`.
EMBER_REQUIRED_TOP_LEVEL_FIELDS: Final = ("histogram", "section", "imports")

#: Substring match, case-insensitive, against imported function names. Deliberately broad rather
#: than an exhaustive API enumeration — a false-positive match (matching a non-crypto function
#: that happens to contain one of these substrings) is an acceptable cost for a feature already
#: documented as a weak count-not-rate PROXY; an exhaustive allowlist would suggest a precision
#: this mapping does not have either way.
_CRYPTO_KEYWORDS: Final = (
    "crypt",
    "aes",
    "rsa",
    "bcrypt",
    "ncrypt",
    "sha1",
    "sha256",
    "sha512",
    "md5",
    "rc4",
    "blowfish",
)
#: Exact match (case-insensitive) against known key-generation/derivation Win32 API names.
_KEYGEN_API_NAMES: Final = frozenset(
    {
        "cryptgenkey",
        "cryptgenrandom",
        "bcryptgeneratekeypair",
        "bcryptgenrandom",
        "cryptderivekey",
        "cryptimportkey",
        "cryptacquirecontext",
    }
)


def _section_entropies(row: Mapping[str, Any]) -> list[float]:
    sections: Sequence[Mapping[str, Any]] = row.get("section", {}).get("sections", [])
    return [float(s["entropy"]) for s in sections if "entropy" in s]


def _entropy_mean(row: Mapping[str, Any]) -> float:
    """`write_entropy_mean` <- Shannon entropy (bits) of the whole file's byte-value histogram.

    EMBER's raw `histogram` field is an unambiguous 256-bin count of byte values across the
    entire file — the same quantity ClaMP's precomputed `E_file` estimated (DEV-34), computed
    here directly from raw counts. EMBER also ships a `byteentropy` 2D histogram over sliding-
    window (entropy, byte-value) pairs, which the session brief names explicitly; it is not used
    here because its exact axis packing was not verified against the LIEF extractor source in
    this session, and a silently-transposed 256-value array would produce a wrong number that
    looks plausible — CLAUDE.md's "never claim a number we did not measure" extends to never
    computing one from an unverified assumption. The plain byte histogram has no such ambiguity.
    """
    counts = np.asarray(row["histogram"], dtype=np.float64)
    total = counts.sum()
    if total <= 0:
        return 0.0
    nonzero = counts[counts > 0]
    probabilities = nonzero / total
    return float(-(probabilities * np.log2(probabilities)).sum())


def _entropy_var(row: Mapping[str, Any]) -> float:
    """`write_entropy_var` <- population variance of every PE section's own entropy.

    EMBER reports each section's Shannon entropy directly (`section.sections[i].entropy`), N
    sections per file (typically 4-8) rather than ClaMP's fixed two-point `{E_text, E_data}` —
    a richer spread estimate over the same underlying quantity, using every section the file
    actually has rather than assuming two specific ones exist.
    """
    entropies = _section_entropies(row)
    return float(np.var(entropies)) if entropies else 0.0


def _entropy_delta(row: Mapping[str, Any]) -> float:
    """`entropy_delta` <- max minus min section entropy, across every section EMBER reports.

    ClaMP's mapping used the specific named `.text`/`.data` section pair (DEV-34); EMBER's
    section list carries no guaranteed canonical naming across the corpus (packed/obfuscated
    files rename sections freely), so the full section list's own spread — most- vs.
    least-random region of the file — generalises the same "entropy varies across the file"
    signal without assuming section names that may not exist for a given row.
    """
    entropies = _section_entropies(row)
    return float(max(entropies) - min(entropies)) if len(entropies) >= 2 else 0.0


def _import_names(row: Mapping[str, Any]) -> list[str]:
    imports: Mapping[str, Sequence[str]] = row.get("imports", {})
    return [name for names in imports.values() for name in names]


def _crypto_call_rate(row: Mapping[str, Any]) -> float:
    """`crypto_call_rate` <- count of imported functions whose name matches a crypto-API keyword.

    A PROXY, not a DIRECT mapping: `FT_RW`'s feature is a *rate* (calls observed per second of
    monitored execution); a static import table has no time axis, so only a raw count is
    observable at all, and the count is reported as-is rather than silently rescaled toward
    synthetic units the KS comparison would then be comparing dishonestly.
    """
    names = _import_names(row)
    return float(sum(1 for name in names if any(k in name.lower() for k in _CRYPTO_KEYWORDS)))


def _key_generation_events(row: Mapping[str, Any]) -> float:
    """`key_generation_events` <- count of imports matching a known key-generation API name.

    Same proxy caveat as `crypto_call_rate`: a static import's *presence* stands in for an
    observed *event*; nothing about a static import table guarantees the function is ever called.
    """
    names = _import_names(row)
    return float(sum(1 for name in names if name.lower() in _KEYGEN_API_NAMES))


def _read_write_ratio(row: Mapping[str, Any]) -> float:
    """`read_write_ratio` <- count of read-only sections over count of writable sections.

    The weakest of the six mapped features, kept because the session brief asks for it
    explicitly and it is a real, non-fabricated field (`section.sections[i].props`), not because
    it is a strong proxy: `FT_RW`'s feature is a *runtime file I/O* ratio; this substitutes a
    *structural* signal (how many of the PE's own sections are marked writable in its own section
    table) that is at best loosely correlated — packers and installers legitimately carry more
    writable sections without performing any ransomware-like file I/O at all.
    """
    sections: Sequence[Mapping[str, Any]] = row.get("section", {}).get("sections", [])
    n_writable = sum(1 for s in sections if "MEM_WRITE" in s.get("props", []))
    n_read_only = sum(
        1
        for s in sections
        if "MEM_READ" in s.get("props", []) and "MEM_WRITE" not in s.get("props", [])
    )
    return float(n_read_only) / float(max(n_writable, 1))


#: Every `FT_RW` feature, in `FEATURE_NAMES` order via `FEATURE_GROUPS`, so every feature is
#: accounted for exactly once (`test_honeypot_ember_mapping.py::
#: test_every_ft_rw_feature_has_a_mapping_decision`). Compare against `external_mapping.
#: CLAMP_MAPPING`: 6/22 mapped here (entropy 3/3, crypto_api 2/3, filesystem 1/5) vs. ClaMP's
#: 3/22 (entropy only) — the coverage-fraction finding the session brief asks for.
EMBER_MAPPING: Final[dict[str, FeatureMapping]] = {
    # -- filesystem: 4/5 still missing; read_write_ratio gets a structural proxy. --------------
    "files_touched_per_s": FeatureMapping(
        "files_touched_per_s", MappingKind.MISSING, (), "No runtime file I/O in static PE features."
    ),
    "read_write_ratio": FeatureMapping(
        "read_write_ratio",
        MappingKind.PROXY,
        ("section",),
        "Section read/write permission flags stand in for a runtime read:write ratio; see "
        "`_read_write_ratio` for why this is the weakest of the six mapped features.",
        compute=_read_write_ratio,
    ),
    "rename_rate_per_s": FeatureMapping(
        "rename_rate_per_s", MappingKind.MISSING, (), "No runtime file I/O in static PE features."
    ),
    "extension_change_rate": FeatureMapping(
        "extension_change_rate",
        MappingKind.MISSING,
        (),
        "No runtime file I/O in static PE features.",
    ),
    "directory_breadth": FeatureMapping(
        "directory_breadth",
        MappingKind.MISSING,
        (),
        "No runtime filesystem traversal in static PE features; PE section count was considered "
        "and rejected as a proxy, same reasoning M7-7's ClaMP mapping used for the identical "
        "feature — a section count is not a directory count.",
    ),
    # -- entropy: the richest-grounded group, all 3 real (still proxies, not identities). -------
    "write_entropy_mean": FeatureMapping(
        "write_entropy_mean",
        MappingKind.PROXY,
        ("histogram",),
        "Whole-file Shannon entropy computed from EMBER's raw 256-bin byte histogram stands in "
        "for mean write-operation entropy; both measure closeness to random bytes.",
        compute=_entropy_mean,
    ),
    "write_entropy_var": FeatureMapping(
        "write_entropy_var",
        MappingKind.PROXY,
        ("section",),
        "Population variance of every PE section's own entropy (N sections, typically 4-8) — a "
        "richer spread estimate than ClaMP's fixed two-point proxy for the same quantity.",
        compute=_entropy_var,
    ),
    "entropy_delta": FeatureMapping(
        "entropy_delta",
        MappingKind.PROXY,
        ("section",),
        "Max minus min section entropy across every section the file has, generalising ClaMP's "
        "named .text/.data pair to files whose section names are not canonical.",
        compute=_entropy_delta,
    ),
    # -- crypto_api: imports give a real (if count-not-rate) proxy for 2 of 3. ------------------
    "crypto_call_rate": FeatureMapping(
        "crypto_call_rate",
        MappingKind.PROXY,
        ("imports",),
        "Count of imported functions matching a crypto-API keyword; a count standing in for a "
        "rate, since a static import table has no time axis.",
        compute=_crypto_call_rate,
    ),
    "key_generation_events": FeatureMapping(
        "key_generation_events",
        MappingKind.PROXY,
        ("imports",),
        "Count of imports matching a known key-generation API name; presence standing in for an "
        "observed event, with no guarantee the import is ever called.",
        compute=_key_generation_events,
    ),
    "crypto_ngram_novelty": FeatureMapping(
        "crypto_ngram_novelty",
        MappingKind.MISSING,
        (),
        "EMBER's imports record which functions are imported, not the order they are called in; "
        "an API-sequence n-gram needs a call *sequence*. Import-set diversity (e.g. distinct "
        "imported DLLs) was considered and rejected as a substitute, for the same reason M7-7 "
        "rejected NumberOfSections for directory_breadth — it is a different quantity, and "
        "forcing the analogy would hide the mismatch rather than report it.",
    ),
    # -- process, network, persistence, kill_chain: unchanged from M7-7 -- all require execution.
    "child_process_spawns": FeatureMapping(
        "child_process_spawns", MappingKind.MISSING, (), "Requires execution; EMBER is static."
    ),
    "injection_attempts": FeatureMapping(
        "injection_attempts", MappingKind.MISSING, (), "Requires execution; EMBER is static."
    ),
    "privilege_escalation_attempts": FeatureMapping(
        "privilege_escalation_attempts",
        MappingKind.MISSING,
        (),
        "Requires execution; EMBER is static.",
    ),
    "c2_beacon_count": FeatureMapping(
        "c2_beacon_count", MappingKind.MISSING, (), "Requires execution; EMBER is static."
    ),
    "dns_entropy": FeatureMapping(
        "dns_entropy", MappingKind.MISSING, (), "Requires execution; EMBER is static."
    ),
    "outbound_burst_rate": FeatureMapping(
        "outbound_burst_rate", MappingKind.MISSING, (), "Requires execution; EMBER is static."
    ),
    "autostart_writes": FeatureMapping(
        "autostart_writes", MappingKind.MISSING, (), "Requires execution; EMBER is static."
    ),
    "shadow_copy_deletions": FeatureMapping(
        "shadow_copy_deletions", MappingKind.MISSING, (), "Requires execution; EMBER is static."
    ),
    "backup_path_accesses": FeatureMapping(
        "backup_path_accesses", MappingKind.MISSING, (), "Requires execution; EMBER is static."
    ),
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


def build_from_ember_row(row: Mapping[str, Any]) -> FeatureVector:
    """One EMBER raw-feature row (one parsed JSONL line) -> one `FT_RW` `FeatureVector`.

    Deterministic and total, like `external_mapping.build_from_clamp_row`: every row yields a
    full-length vector, missing slots zeroed and flagged rather than dropped.
    """
    missing_fields = [f for f in EMBER_REQUIRED_TOP_LEVEL_FIELDS if f not in row]
    if missing_fields:
        raise EmberMappingError(f"row is missing required top-level fields: {missing_fields}")
    values: list[float] = []
    mask = 0
    for index, name in enumerate(FEATURE_NAMES):
        spec = EMBER_MAPPING[name]
        if spec.kind is MappingKind.MISSING or spec.compute is None:
            values.append(0.0)
            mask |= 1 << index
        else:
            values.append(spec.compute(row))
    return FeatureVector(values=tuple(values), missing_mask=mask)


def mapping_summary() -> dict[str, dict[str, object]]:
    """One row per `FT_RW` group: how many of its features are direct/proxy/missing, computed
    here so the report table and the code that decided it can never drift apart — same pattern
    as `external_mapping.mapping_summary`.
    """
    summary: dict[str, dict[str, object]] = {}
    for group, names in FEATURE_GROUPS:
        counts = {kind.value: 0 for kind in MappingKind}
        for name in names:
            counts[EMBER_MAPPING[name].kind.value] += 1
        summary[group] = {"n_features": len(names), **counts}
    return summary
