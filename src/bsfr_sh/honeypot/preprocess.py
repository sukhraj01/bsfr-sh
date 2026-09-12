"""`DT_RW` → `DT_RWC`. Implements Alg. 2, lines 3-4. The definition is ours: DEV-26.

The paper says "pre-process and remove the abnormalities" and stops. That sentence has an obvious
reading and the obvious reading is catastrophic: **if "abnormalities" means statistical outliers,
this step deletes the positive class.** Ransomware behaviour *is* the outlier in a corpus of
ordinary software. A pipeline that removes anomalies before training a detector removes exactly
what the detector exists to find, and it would do so silently, leaving a clean-looking dataset and
a useless model.

So we read "abnormalities" as **sensor defects**, never as unusual behaviour, and implement five
concrete rules:

1. **Structural.** A sample with no observed stage, or a non-positive duration, describes no
   episode at all. Dropped.
2. **Impossible values.** A counter outside its physical range is a sensor fault, not a
   measurement: entropies live in [0, 8] bits/byte, rates and counts are non-negative, ratios in
   [0, 1]. Out-of-range values are clamped to the bound; negative counts are treated as
   unreadable and marked unobserved rather than clamped to zero, because "the sensor returned
   nonsense" and "the program did nothing" are different facts.
3. **Duplicates.** Two samples whose canonical trace is byte-identical are one observation
   reported twice. The first is kept.
4. **Missing, marked.** A counter the sensor never reported stays missing and is recorded in
   `missing`. Nothing is imputed here: imputation at collection time hides the honeypot's blind
   spots inside the data, where M4 cannot see them (DEV-27).
5. **Normalisation.** `files_touched`, `renames` and `crypto_calls` are absolute counts; divided
   by the episode duration they become the rates the feature schema declares.

What is deliberately *not* done: no outlier filtering, no smoothing, no winsorising, no class
balancing. `CleaningReport` counts what each rule did, so the number of survivors is reportable
rather than assumed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from bsfr_sh.honeypot.collector import COUNTER_NAMES, RawSample, StageObservation
from bsfr_sh.util.serialization import encode

__all__ = [
    "COUNTER_BOUNDS",
    "RATE_COUNTERS",
    "CleanSample",
    "CleaningReport",
    "clean",
    "trace_bytes",
]

#: Physical bounds per counter. `None` upper bound means "unbounded above".
COUNTER_BOUNDS: Final[Mapping[str, tuple[float, float | None]]] = {
    "read_write_ratio": (0.0, None),
    "extension_change_rate": (0.0, 1.0),
    "write_entropy_mean": (0.0, 8.0),
    "write_entropy_var": (0.0, 16.0),
    "entropy_delta": (-8.0, 8.0),
    "crypto_ngram_novelty": (0.0, 1.0),
    "dns_entropy": (0.0, 8.0),
}

#: Absolute counts that rule 5 turns into per-second rates, and the name each becomes.
RATE_COUNTERS: Final[Mapping[str, str]] = {
    "files_touched": "files_touched_per_s",
    "renames": "rename_rate_per_s",
    "crypto_calls": "crypto_call_rate",
}


@dataclass(frozen=True)
class CleanSample:
    """`DT_RWC` — one episode after the five rules. Counters are normalised; nothing is imputed."""

    sample_id: str
    label: str
    profile: str
    collected_at: int
    duration_s: float
    stages: tuple[StageObservation, ...]
    counters: Mapping[str, float]
    #: Counter names that were never observed, or were unreadable. Carried, never filled in.
    missing: frozenset[str]

    def trace(self) -> bytes:
        """The canonical behavioural trace `honeypot.signatures` digests.

        Behaviour only: `label` and `profile` are provenance from the emulator, not something a
        sensor saw, so they are outside the digest.
        """
        return trace_bytes(
            sample_id=self.sample_id,
            duration_s=self.duration_s,
            stages=self.stages,
            counters=self.counters,
            missing=self.missing,
        )


def trace_bytes(
    *,
    sample_id: str,
    duration_s: float,
    stages: Sequence[StageObservation],
    counters: Mapping[str, float],
    missing: frozenset[str],
) -> bytes:
    """Canonical encoding of what was observed. Mapping keys are sorted by the encoder."""
    return encode(
        {
            "sample_id": sample_id,
            "duration_s": duration_s,
            "stages": [
                {"stage": s.stage, "dwell_s": s.dwell_s, "observed": s.observed} for s in stages
            ],
            "counters": dict(counters),
            "missing": sorted(missing),
        }
    )


@dataclass
class CleaningReport:
    """What each rule did. Reported, so "how many samples survived" is measured, not assumed."""

    received: int = 0
    kept: int = 0
    dropped_structural: int = 0
    dropped_duplicate: int = 0
    clamped_values: int = 0
    marked_unreadable: int = 0
    already_missing: int = 0
    normalised: int = 0
    #: Defect labels the generator injected, counted as they are met. Diagnostic only.
    defects_seen: dict[str, int] = field(default_factory=dict)

    @property
    def dropped(self) -> int:
        return self.dropped_structural + self.dropped_duplicate


def clean(samples: Sequence[RawSample]) -> tuple[tuple[CleanSample, ...], CleaningReport]:
    """Implements Alg. 2, lines 3-4 — `DT_RW` → `DT_RWC` under DEV-26's five rules."""
    report = CleaningReport(received=len(samples))
    seen: set[bytes] = set()
    cleaned: list[CleanSample] = []

    for sample in samples:
        for defect in sample.defects:
            report.defects_seen[defect] = report.defects_seen.get(defect, 0) + 1

        # Rule 1 — structural.
        if sample.duration_s <= 0.0 or not any(stage.observed for stage in sample.stages):
            report.dropped_structural += 1
            continue

        missing = set(sample.unobserved)
        report.already_missing += len(sample.unobserved)
        counters: dict[str, float] = {}

        for name in COUNTER_NAMES:
            if name in missing:
                continue
            value = sample.counters.get(name)
            if value is None:
                missing.add(name)
                continue
            # Rule 2 — impossible values.
            if value < 0.0 and name not in COUNTER_BOUNDS:
                missing.add(name)  # a negative count is unreadable, not zero
                report.marked_unreadable += 1
                continue
            low, high = COUNTER_BOUNDS.get(name, (0.0, None))
            if value < low or (high is not None and value > high):
                value = min(max(value, low), high) if high is not None else max(value, low)
                report.clamped_values += 1
            counters[name] = value

        # Rule 5 — normalisation.
        for source, target in RATE_COUNTERS.items():
            if source in counters:
                counters[target] = counters.pop(source) / sample.duration_s
                report.normalised += 1
            else:
                missing.discard(source)
                missing.add(target)

        candidate = CleanSample(
            sample_id=sample.sample_id,
            label=sample.label,
            profile=sample.profile,
            collected_at=sample.collected_at,
            duration_s=sample.duration_s,
            stages=sample.stages,
            counters=counters,
            missing=frozenset(missing),
        )

        # Rule 3 — duplicates, by canonical trace.
        digestible = candidate.trace()
        if digestible in seen:
            report.dropped_duplicate += 1
            continue
        seen.add(digestible)
        cleaned.append(candidate)

    report.kept = len(cleaned)
    return tuple(cleaned), report
