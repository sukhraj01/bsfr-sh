"""`HP_RW` — the honeypot, and the synthesis behind it. Implements Alg. 2, lines 1-2.

**Safety (CLAUDE.md §2).** Nothing here is a program. A "sample" is a record of numbers: counters,
durations and stage dwell times drawn from a distribution. This module generates no code,
downloads nothing, executes nothing, and stores no executable content. `tests/unit/
test_honeypot_is_inert.py` asserts that as an import-level property.

What the honeypot is, in our model
----------------------------------
`HP_RW` is a decoy host under observation. Its monitor records *behavioural episodes*: a stretch
of activity by one program, described by the counters a real EDR sensor would produce. Some
episodes are emulated ransomware walking §II-C's seven-stage kill chain; the rest are ordinary
software doing ordinary work on the same host. Both are collected, because Phase 3 has to learn
`NProf` as well as `AProf` and cannot do so from ransomware alone.

The generator's one hard requirement
------------------------------------
We write the generator here and, in M4, the classifier that consumes it. If the two classes came
from visibly different distributions, M4 would report ~100% and the number would describe this
file rather than any detector. So the design target is an *intended Bayes-optimal accuracy of
about 0.85*, reached deliberately:

1. **Benign profiles that legitimately look like ransomware.** A backup agent touches thousands of
   files fast. A disk-encryption tool generates keys and writes high-entropy blocks. An installer
   spawns children and writes autostart entries. A cleanup utility deletes shadow copies. None of
   these is malicious and all of them trip the obvious heuristics.
2. **Confusable pairs.** `AMBIGUOUS_FRACTION` (0.25) of every draw comes from a pair whose two
   members share *one identical parameter set*. For those samples the features carry no
   information about the label whatsoever, so the Bayes error over that mass is exactly one half:
   0.25 x 0.5 = 0.125 of irreducible error before any other overlap is counted.
3. **Overlap everywhere else**, from lognormal spreads wide enough that the class-conditional
   densities cross, not merely differ in mean.
4. **Noise and blind spots.** Every counter is perturbed, and whole sensor groups go unobserved
   with a probability that is *independent of the label* — a honeypot misses stages, and if it
   missed them more often for one class, missingness itself would become a label.

`docs/DEVIATIONS.md` DEV-27 records the schema and this reasoning.

Determinism and train/test hygiene
----------------------------------
`synthesize()` takes an explicit seed and builds its own `numpy.random.Generator`; it never reads
global random state. Each sample draws its own latents, so no two samples share a hidden
parameter. Two draws that must not leak into each other (M4's train and eval) come from two
different seeds, never from shuffling one draw — see `honeypot.corpus`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

import numpy as np

from bsfr_sh.util.serialization import CanonicalEncodingError, Value, decode, encode

__all__ = [
    "AMBIGUOUS_FRACTION",
    "BENIGN",
    "BENIGN_PROFILES",
    "COUNTER_NAMES",
    "KILL_CHAIN_STAGES",
    "MALICIOUS",
    "MALICIOUS_PROFILES",
    "OBSERVABLE_STAGES",
    "Honeypot",
    "HoneypotError",
    "RawSample",
    "StageObservation",
    "pack_samples",
    "synthesize",
    "unpack_samples",
]

#: Ground-truth labels. Metadata on the record, never a feature (DEV-27).
MALICIOUS: Final = "RW"
BENIGN: Final = "benign"

#: §II-C's seven stages, in order. The last three have no benign analogue, which is exactly why
#: `honeypot.features` truncates the kill-chain group — see OBSERVABLE_STAGES and DEV-27.
KILL_CHAIN_STAGES: Final = (
    "infection",
    "resource_identification",
    "encryption",
    "notification",
    "cleanup",
    "payment",
    "decryption",
)

#: The prefix both classes can genuinely produce: arrival, enumeration, bulk transform, cleanup.
#: An installer arrives, a backup agent enumerates, an archiver transforms in bulk, a disk cleaner
#: removes files. "notification" (a ransom note) onward is malicious-only and never a feature.
OBSERVABLE_STAGES: Final = 4

#: Share of each class drawn from a confusable pair. See the module docstring.
AMBIGUOUS_FRACTION: Final = 0.25

#: Raw counter names, as the sensor reports them. Three are absolute counts that
#: `honeypot.preprocess` turns into rates (DEV-26); the rest are already intensive.
COUNTER_NAMES: Final = (
    "files_touched",
    "read_write_ratio",
    "renames",
    "extension_change_rate",
    "directory_breadth",
    "write_entropy_mean",
    "write_entropy_var",
    "entropy_delta",
    "crypto_calls",
    "key_generation_events",
    "crypto_ngram_novelty",
    "child_process_spawns",
    "injection_attempts",
    "privilege_escalation_attempts",
    "c2_beacon_count",
    "dns_entropy",
    "outbound_burst_rate",
    "autostart_writes",
    "shadow_copy_deletions",
    "backup_path_accesses",
)

#: Which sensor group each counter belongs to. Groups go blind together, as a real sensor does.
_GROUP_OF: Final[Mapping[str, str]] = {
    "files_touched": "filesystem",
    "read_write_ratio": "filesystem",
    "renames": "filesystem",
    "extension_change_rate": "filesystem",
    "directory_breadth": "filesystem",
    "write_entropy_mean": "entropy",
    "write_entropy_var": "entropy",
    "entropy_delta": "entropy",
    "crypto_calls": "crypto_api",
    "key_generation_events": "crypto_api",
    "crypto_ngram_novelty": "crypto_api",
    "child_process_spawns": "process",
    "injection_attempts": "process",
    "privilege_escalation_attempts": "process",
    "c2_beacon_count": "network",
    "dns_entropy": "network",
    "outbound_burst_rate": "network",
    "autostart_writes": "persistence",
    "shadow_copy_deletions": "persistence",
    "backup_path_accesses": "persistence",
}

#: Probability that a whole sensor group reports nothing for a sample. Identical for both classes
#: on purpose: class-dependent missingness would be a label in disguise.
_GROUP_BLIND_RATE: Final[Mapping[str, float]] = {
    "filesystem": 0.03,
    "entropy": 0.08,
    "crypto_api": 0.10,
    "process": 0.08,
    "network": 0.12,
    "persistence": 0.08,
}

#: Multiplicative observation noise, as a lognormal sigma.
_NOISE_SIGMA: Final = 0.12

#: Fraction of raw samples given a deliberate defect for `honeypot.preprocess` to handle (DEV-26).
_DEFECT_RATE: Final = 0.08


class HoneypotError(ValueError):
    """Raised when the honeypot is asked for something it cannot produce."""


# A draw spec: ("lognorm", median, sigma) | ("beta", a, b) scaled to `scale` | ("poisson", lam, 0).
_Draw = tuple[str, float, float]
_Profile = Mapping[str, _Draw]


def _ln(median: float, sigma: float) -> _Draw:
    return ("lognorm", median, sigma)


def _beta(a: float, b: float) -> _Draw:
    return ("beta", a, b)


def _pois(lam: float) -> _Draw:
    return ("poisson", lam, 0.0)


#: Counters whose beta draws are scaled beyond [0, 1].
_BETA_SCALE: Final[Mapping[str, float]] = {"write_entropy_mean": 8.0, "dns_entropy": 5.0}

# --------------------------------------------------------------------------------------------
# Behaviour profiles
# --------------------------------------------------------------------------------------------
# Each profile is a full parameter set over COUNTER_NAMES plus `duration_s` and `stage_reach`.
# Ransomware profiles are the four families §II describes; benign profiles are ordinary software,
# four of which are deliberately ransomware-shaped.

_FAST_CRYPTO: Final[_Profile] = {
    "duration_s": _ln(300.0, 0.5),
    "stage_reach": _ln(6.0, 0.12),
    "files_touched": _ln(4000.0, 0.55),
    "read_write_ratio": _ln(0.8, 0.6),
    "renames": _ln(1200.0, 0.7),
    # Kept deliberately wide. A narrow, high-mean draw here made this one feature separable on its
    # own (AUC 0.89 before tuning), which is the single-feature giveaway the leakage test forbids.
    "extension_change_rate": _beta(4.5, 3.0),
    "directory_breadth": _ln(110.0, 0.6),
    "write_entropy_mean": _beta(9.0, 1.3),
    "write_entropy_var": _ln(0.30, 0.5),
    "entropy_delta": _ln(2.6, 0.45),
    "crypto_calls": _ln(8000.0, 0.55),
    "key_generation_events": _pois(6.0),
    "crypto_ngram_novelty": _beta(5.0, 3.0),
    "child_process_spawns": _pois(2.0),
    "injection_attempts": _pois(1.2),
    "privilege_escalation_attempts": _pois(1.0),
    "c2_beacon_count": _pois(6.0),
    "dns_entropy": _beta(5.0, 3.0),
    "outbound_burst_rate": _ln(2.2, 0.7),
    "autostart_writes": _pois(1.5),
    "shadow_copy_deletions": _pois(2.2),
    "backup_path_accesses": _pois(4.0),
}

_LOW_AND_SLOW: Final[_Profile] = {
    **_FAST_CRYPTO,
    "duration_s": _ln(3000.0, 0.6),
    "stage_reach": _ln(5.5, 0.15),
    "files_touched": _ln(2500.0, 0.6),
    "renames": _ln(500.0, 0.8),
    "crypto_calls": _ln(3000.0, 0.6),
    "extension_change_rate": _beta(4.0, 4.0),
    "c2_beacon_count": _pois(3.0),
    "shadow_copy_deletions": _pois(1.2),
}

_DOUBLE_EXTORTION: Final[_Profile] = {
    **_FAST_CRYPTO,
    "duration_s": _ln(1200.0, 0.6),
    "files_touched": _ln(3000.0, 0.6),
    "c2_beacon_count": _pois(18.0),
    "dns_entropy": _beta(7.0, 2.0),
    "outbound_burst_rate": _ln(6.0, 0.6),
    "read_write_ratio": _ln(1.4, 0.6),
}

_WIPER_LIKE: Final[_Profile] = {
    **_FAST_CRYPTO,
    "duration_s": _ln(180.0, 0.5),
    "stage_reach": _ln(5.0, 0.2),
    "files_touched": _ln(6000.0, 0.5),
    "renames": _ln(2500.0, 0.6),
    "key_generation_events": _pois(0.5),
    "crypto_calls": _ln(1200.0, 0.7),
    "write_entropy_mean": _beta(10.0, 1.0),
}

_OFFICE_WORKLOAD: Final[_Profile] = {
    "duration_s": _ln(900.0, 0.7),
    "stage_reach": _ln(1.6, 0.3),
    "files_touched": _ln(120.0, 0.9),
    "read_write_ratio": _ln(2.2, 0.7),
    "renames": _ln(12.0, 1.0),
    "extension_change_rate": _beta(1.0, 9.0),
    "directory_breadth": _ln(14.0, 0.8),
    "write_entropy_mean": _beta(4.0, 4.0),
    "write_entropy_var": _ln(0.9, 0.6),
    "entropy_delta": _ln(0.5, 0.8),
    "crypto_calls": _ln(200.0, 0.9),
    "key_generation_events": _pois(0.4),
    "crypto_ngram_novelty": _beta(2.0, 6.0),
    "child_process_spawns": _pois(1.5),
    "injection_attempts": _pois(0.1),
    "privilege_escalation_attempts": _pois(0.1),
    "c2_beacon_count": _pois(1.5),
    "dns_entropy": _beta(3.0, 5.0),
    "outbound_burst_rate": _ln(0.8, 0.8),
    "autostart_writes": _pois(0.3),
    "shadow_copy_deletions": _pois(0.1),
    "backup_path_accesses": _pois(0.6),
}

#: Touches thousands of files quickly, reads far more than it writes, prunes old restore points.
_BACKUP_AGENT: Final[_Profile] = {
    **_OFFICE_WORKLOAD,
    "duration_s": _ln(2400.0, 0.6),
    "stage_reach": _ln(3.2, 0.25),
    "files_touched": _ln(5000.0, 0.6),
    "read_write_ratio": _ln(2.6, 0.7),
    "renames": _ln(300.0, 0.9),
    # Backup software rewrites extensions too (.bak, .part), so this stays in ransomware's range.
    "extension_change_rate": _beta(2.0, 5.0),
    "directory_breadth": _ln(150.0, 0.6),
    "write_entropy_mean": _beta(7.0, 2.5),
    "entropy_delta": _ln(1.6, 0.7),
    "crypto_calls": _ln(2000.0, 0.8),
    "shadow_copy_deletions": _pois(1.0),
    "backup_path_accesses": _pois(10.0),
}

#: Generates keys and writes high-entropy blocks all day. The confusable twin of `fast_crypto`.
_DISK_ENCRYPTOR: Final[_Profile] = {
    **_OFFICE_WORKLOAD,
    "duration_s": _ln(400.0, 0.6),
    "stage_reach": _ln(3.0, 0.25),
    "files_touched": _ln(2600.0, 0.6),
    "read_write_ratio": _ln(1.1, 0.6),
    "renames": _ln(250.0, 0.9),
    "extension_change_rate": _beta(3.0, 4.0),
    "directory_breadth": _ln(80.0, 0.7),
    "write_entropy_mean": _beta(8.5, 1.4),
    "write_entropy_var": _ln(0.35, 0.5),
    "entropy_delta": _ln(2.3, 0.5),
    "crypto_calls": _ln(7000.0, 0.6),
    "key_generation_events": _pois(5.0),
    "crypto_ngram_novelty": _beta(4.0, 3.5),
}

#: Spawns children and writes autostart entries — the process and persistence groups' false alarm.
_INSTALLER: Final[_Profile] = {
    **_OFFICE_WORKLOAD,
    "duration_s": _ln(240.0, 0.6),
    "stage_reach": _ln(3.4, 0.25),
    "files_touched": _ln(900.0, 0.7),
    "write_entropy_mean": _beta(6.5, 3.0),
    "entropy_delta": _ln(1.4, 0.7),
    "child_process_spawns": _pois(9.0),
    "privilege_escalation_attempts": _pois(1.6),
    "injection_attempts": _pois(0.5),
    "autostart_writes": _pois(4.0),
    "crypto_calls": _ln(900.0, 0.8),
}

#: Network-heavy and chatty. The confusable twin of `double_extortion`.
_SYNC_CLIENT: Final[_Profile] = {
    **_OFFICE_WORKLOAD,
    "duration_s": _ln(1500.0, 0.6),
    "stage_reach": _ln(2.6, 0.3),
    "files_touched": _ln(1400.0, 0.7),
    "read_write_ratio": _ln(1.5, 0.6),
    "c2_beacon_count": _pois(16.0),
    "dns_entropy": _beta(6.0, 2.5),
    "outbound_burst_rate": _ln(5.0, 0.7),
    "write_entropy_mean": _beta(6.0, 3.0),
}

#: Deletes shadow copies and walks backup paths, which is the persistence group's other false alarm.
_CLEANUP_UTILITY: Final[_Profile] = {
    **_OFFICE_WORKLOAD,
    "duration_s": _ln(600.0, 0.6),
    "stage_reach": _ln(3.6, 0.25),
    "files_touched": _ln(1800.0, 0.7),
    "renames": _ln(150.0, 0.9),
    "shadow_copy_deletions": _pois(3.0),
    "backup_path_accesses": _pois(6.0),
    "directory_breadth": _ln(70.0, 0.7),
    "extension_change_rate": _beta(2.0, 6.0),
}

MALICIOUS_PROFILES: Final[Mapping[str, _Profile]] = {
    "fast_crypto": _FAST_CRYPTO,
    "low_and_slow": _LOW_AND_SLOW,
    "double_extortion": _DOUBLE_EXTORTION,
    "wiper_like": _WIPER_LIKE,
}

BENIGN_PROFILES: Final[Mapping[str, _Profile]] = {
    "office_workload": _OFFICE_WORKLOAD,
    "backup_agent": _BACKUP_AGENT,
    "disk_encryptor": _DISK_ENCRYPTOR,
    "installer": _INSTALLER,
    "sync_client": _SYNC_CLIENT,
    "cleanup_utility": _CLEANUP_UTILITY,
}

# --------------------------------------------------------------------------------------------
# The confusable pairs: one parameter set, both labels
# --------------------------------------------------------------------------------------------
# A sample drawn here carries *no* information about its label. Its features are identical in
# distribution whichever class it belongs to, which is what puts a floor under the Bayes error.
# The floor is AMBIGUOUS_FRACTION / 2 = 0.125 of the whole corpus.


def _midpoint(a: _Profile, b: _Profile) -> _Profile:
    """The shared parameter set for a confusable pair: neither member, and reachable by both."""
    shared: dict[str, _Draw] = {}
    for name, (kind, first, second) in a.items():
        other = b[name]
        if other[0] != kind:
            raise HoneypotError(f"confusable pair disagrees on the draw kind for {name!r}")
        shared[name] = (kind, (first + other[1]) / 2.0, (second + other[2]) / 2.0)
    return shared


_AMBIGUOUS_PROFILES: Final[Mapping[str, _Profile]] = {
    "crypto_bulk": _midpoint(_FAST_CRYPTO, _DISK_ENCRYPTOR),
    "slow_bulk": _midpoint(_LOW_AND_SLOW, _BACKUP_AGENT),
    "network_bulk": _midpoint(_DOUBLE_EXTORTION, _SYNC_CLIENT),
}


# --------------------------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class StageObservation:
    """One §II-C kill-chain stage as the monitor saw it. `observed` False means it was missed."""

    stage: str
    dwell_s: float
    observed: bool


@dataclass(frozen=True)
class RawSample:
    """`DT_RW` — one observed behavioural episode, before cleaning.

    `label` and `profile` are provenance from the emulator. They are never features, and
    `honeypot.features` cannot see them.
    """

    sample_id: str
    label: str
    profile: str
    collected_at: int
    duration_s: float
    stages: tuple[StageObservation, ...]
    counters: Mapping[str, float]
    #: Names of counters the sensor did not report at all.
    unobserved: tuple[str, ...]
    #: Deliberate defects, for `honeypot.preprocess` to find. Never used as a feature.
    defects: tuple[str, ...]

    def to_fields(self) -> dict[str, Value]:
        return {
            "sample_id": self.sample_id,
            "label": self.label,
            "profile": self.profile,
            "collected_at": self.collected_at,
            "duration_s": self.duration_s,
            "stages": [
                {"stage": s.stage, "dwell_s": s.dwell_s, "observed": s.observed}
                for s in self.stages
            ],
            "counters": dict(self.counters),
            "unobserved": list(self.unobserved),
            "defects": list(self.defects),
        }


def pack_samples(samples: Sequence[RawSample]) -> bytes:
    """Canonical encoding of a harvest, for the `SK_{CS_l,HP_RW}` channel."""
    return encode([s.to_fields() for s in samples])


def unpack_samples(raw: bytes) -> tuple[RawSample, ...]:
    """Inverse of `pack_samples`. Raises `HoneypotError` on anything malformed."""
    try:
        decoded = decode(raw)
    except CanonicalEncodingError as exc:
        raise HoneypotError(f"harvest is not a canonical encoding: {exc}") from exc
    if not isinstance(decoded, list):
        raise HoneypotError("harvest is not a list of samples")
    return tuple(_sample_from_fields(item) for item in decoded)


def _sample_from_fields(item: Value) -> RawSample:
    if not isinstance(item, dict):
        raise HoneypotError("sample is not a mapping")
    try:
        stages_raw = item["stages"]
        counters_raw = item["counters"]
        if not isinstance(stages_raw, list) or not isinstance(counters_raw, dict):
            raise HoneypotError("sample has a malformed stage list or counter mapping")
        stages = tuple(_stage_from_fields(stage) for stage in stages_raw)
        counters = {str(k): float(v) for k, v in counters_raw.items() if isinstance(v, int | float)}
        unobserved = item["unobserved"]
        defects = item["defects"]
        if not isinstance(unobserved, list) or not isinstance(defects, list):
            raise HoneypotError("sample has a malformed unobserved/defect list")
        return RawSample(
            sample_id=str(item["sample_id"]),
            label=str(item["label"]),
            profile=str(item["profile"]),
            collected_at=int(item["collected_at"]),
            duration_s=float(item["duration_s"]),
            stages=stages,
            counters=counters,
            unobserved=tuple(str(name) for name in unobserved),
            defects=tuple(str(name) for name in defects),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise HoneypotError(f"sample is missing or misshaping a field: {exc}") from exc


def _stage_from_fields(stage: Value) -> StageObservation:
    if not isinstance(stage, dict):
        raise HoneypotError("stage is not a mapping")
    return StageObservation(
        stage=str(stage["stage"]),
        dwell_s=float(stage["dwell_s"]),
        observed=bool(stage["observed"]),
    )


# --------------------------------------------------------------------------------------------
# Synthesis
# --------------------------------------------------------------------------------------------
def _draw(rng: np.random.Generator, spec: _Draw, name: str) -> float:
    kind, first, second = spec
    if kind == "lognorm":
        return float(first * np.exp(second * rng.standard_normal()))
    if kind == "beta":
        return float(rng.beta(first, second) * _BETA_SCALE.get(name, 1.0))
    if kind == "poisson":
        return float(rng.poisson(first))
    raise HoneypotError(f"unknown draw kind {kind!r}")


def _stages(
    rng: np.random.Generator, reach: float, duration: float
) -> tuple[StageObservation, ...]:
    """Walk the kill chain up to `reach` stages, with per-stage dwell times and misses."""
    reached = max(1, min(len(KILL_CHAIN_STAGES), round(reach)))
    shares = rng.dirichlet(np.full(reached, 2.0))
    observations: list[StageObservation] = []
    for index in range(reached):
        observations.append(
            StageObservation(
                stage=KILL_CHAIN_STAGES[index],
                dwell_s=float(shares[index] * duration),
                # A monitor misses individual stages; the rate does not depend on the label.
                observed=bool(rng.random() > 0.10),
            )
        )
    return tuple(observations)


def _apply_defect(
    rng: np.random.Generator, counters: dict[str, float], duration: float
) -> tuple[float, tuple[str, ...]]:
    """Inject one sensor defect, so `honeypot.preprocess` has real work rather than a no-op."""
    choice = rng.integers(0, 4)
    if choice == 0:
        counters["files_touched"] = -abs(counters.get("files_touched", 1.0))
        return duration, ("negative_counter",)
    if choice == 1:
        counters["write_entropy_mean"] = 8.0 + float(rng.uniform(0.1, 1.5))
        return duration, ("entropy_out_of_range",)
    if choice == 2:
        counters["crypto_calls"] = float(rng.uniform(1e8, 1e9))
        return duration, ("absurd_outlier",)
    return 0.0, ("zero_duration",)


def synthesize(
    count: int,
    *,
    seed: int,
    malicious_fraction: float = 0.5,
    started_at: int = 1_757_548_800,
) -> tuple[RawSample, ...]:
    """Emulate `count` episodes on the decoy host. Implements Alg. 2, line 1's data production.

    Deterministic in `seed`: the same seed yields byte-identical records. Each sample draws its
    own latents, so no two samples share hidden parameters — which is what lets M4 hold out a
    *separate draw* rather than a shuffle (see the module docstring).
    """
    if count < 0:
        raise HoneypotError(f"count must be non-negative, got {count}")
    if not 0.0 <= malicious_fraction <= 1.0:
        raise HoneypotError(f"malicious_fraction must be in [0, 1], got {malicious_fraction}")
    rng = np.random.default_rng(seed)
    samples: list[RawSample] = []
    for index in range(count):
        label = MALICIOUS if rng.random() < malicious_fraction else BENIGN
        family = MALICIOUS_PROFILES if label == MALICIOUS else BENIGN_PROFILES
        if rng.random() < AMBIGUOUS_FRACTION:
            name = str(rng.choice(sorted(_AMBIGUOUS_PROFILES)))
            profile, profile_name = _AMBIGUOUS_PROFILES[name], f"ambiguous:{name}"
        else:
            profile_name = str(rng.choice(sorted(family)))
            profile = family[profile_name]

        duration = max(1.0, _draw(rng, profile["duration_s"], "duration_s"))
        counters: dict[str, float] = {}
        unobserved: list[str] = []
        blind = {group: rng.random() < rate for group, rate in sorted(_GROUP_BLIND_RATE.items())}
        for name in COUNTER_NAMES:
            if blind[_GROUP_OF[name]]:
                unobserved.append(name)
                continue
            value = _draw(rng, profile[name], name)
            noisy = value * float(np.exp(_NOISE_SIGMA * rng.standard_normal()))
            counters[name] = float(noisy)

        defects: tuple[str, ...] = ()
        if rng.random() < _DEFECT_RATE:
            duration, defects = _apply_defect(rng, counters, duration)

        samples.append(
            RawSample(
                sample_id=f"hp-{seed:08x}-{index:05d}",
                label=label,
                profile=profile_name,
                collected_at=started_at + index,
                duration_s=duration,
                stages=_stages(rng, _draw(rng, profile["stage_reach"], "stage_reach"), duration),
                counters=counters,
                unobserved=tuple(unobserved),
                defects=defects,
            )
        )
    return tuple(samples)


@dataclass
class Honeypot:
    """`HP_RW` (docs/NOTATION.md). Implements Alg. 2, lines 1-2.

    Deliberately has no network and no keys. `framework.entities.HoneypotNode` is what ships a
    harvest to `CS_l` over `SK_{CS_l,HP_RW}`; `honeypot/` sits below `framework/` and may not
    import it.
    """

    honeypot_id: str
    seed: int
    #: Incremented per harvest, so two harvests from one deployment never repeat a draw.
    harvests: int = 0
    deployed: bool = False

    def deploy(self) -> Honeypot:
        """Implements Alg. 2, line 1: bring the decoy host under observation."""
        if self.deployed:
            raise HoneypotError(f"{self.honeypot_id!r} is already deployed")
        self.deployed = True
        return self

    def harvest(self, count: int, *, malicious_fraction: float = 0.5) -> tuple[RawSample, ...]:
        """Implements Alg. 2, line 2: the episodes observed since the last harvest (`DT_RW`)."""
        if not self.deployed:
            raise HoneypotError(f"{self.honeypot_id!r} must be deployed before it can harvest")
        draw_seed = self.seed + self.harvests
        self.harvests += 1
        return synthesize(count, seed=draw_seed, malicious_fraction=malicious_fraction)
