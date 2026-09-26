"""Maps MalbehavD-V1's real, dynamic API-call-sequence dataset onto `FT_RW`. M7-13, DEV-39.

Same posture as `honeypot.external_mapping` (M7-7, DEV-34) and `honeypot.ember_mapping` (M7-10,
DEV-35): `FT_RW` is a *dynamic behavioural* schema — what a monitor observes a running program
*do*. ClaMP and EMBER are both real malware/benign data, but both are *static*: header/structure
features read off a file that is never executed, which is why only the entropy group (3/22, then
6/22) ever grounded. MalbehavD-V1 (github.com/mpasco/MalbehavD-V1, `data/external/malbehavd/
README.md`) inverts that: it is real data from files that *were* executed in a Cuckoo sandbox, so
it grounds the five groups a static dataset structurally cannot (filesystem, crypto_api, process,
network, persistence) while grounding *nothing* in entropy or kill_chain — the two groups ClaMP
and EMBER covered — because the dataset never captures byte content (no entropy signal) or
per-call wall-clock time (no stage-dwell signal), only an ordered sequence of API call *names*.

**What "mapped" means here, and the same discipline DEV-35 applied.** A call name being present
in the trace is not automatically a `PROXY`: DEV-35 rejected `NumberOfSections` as a proxy for
`directory_breadth` because a section count is a different quantity than a directory count, not
merely a noisier measurement of the same one. The same test is applied here. `directory_breadth`
needs distinct directory *paths* to measure breadth; this dataset has no call arguments at all
(no paths, registry keys, or domain-name strings — only call names and their position), so a
count of directory-related calls would measure *activity*, not *breadth*, and is marked `MISSING`
rather than forced into a proxy that would not mean what it claims to. `extension_change_rate`,
`dns_entropy`, `shadow_copy_deletions` and `backup_path_accesses` fail the same test for the same
underlying reason: each needs an argument value (a file extension, a resolved domain string, a
specific shadow-copy or backup API, a specific registry path) this dataset does not carry, even
though a same-category call sometimes appears in the vocabulary.

Every mapped feature here is deliberately `PROXY`, never `DIRECT` — matching DEV-34/DEV-35's own
bar (EMBER's `write_entropy_mean`, arguably the closest a real dataset has come to measuring
`FT_RW`'s exact quantity, was still `PROXY`, not `DIRECT` — see `ember_mapping._entropy_mean`'s
docstring). Every mapped count here is a raw count of matching API calls *within the trace*, with
no further normalisation by trace length or wall-clock time — the same "a count stands in for a
rate" convention `ember_mapping.py` documents for `crypto_call_rate`, since MalbehavD-V1 carries
no timestamps either.

`MISSING` features are handled exactly as `honeypot.features.build()` and both prior real-data
mappings already handle an unobserved sensor: value `0.0`, `missing_mask` bit set. The decision is
structural (the same slots are missing for every MalbehavD-V1 row, because the *schema* lacks the
observable, not because of a per-sample failure) — same as `external_mapping`/`ember_mapping`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from bsfr_sh.honeypot.external_mapping import MappingKind
from bsfr_sh.honeypot.features import FEATURE_GROUPS, FEATURE_NAMES, FeatureVector

__all__ = [
    "MALBEHAVD_MAPPING",
    "FeatureMapping",
    "MalbehavDMappingError",
    "MappingKind",
    "build_from_malbehavd_row",
    "mapping_summary",
    "parse_call_sequence",
]


class MalbehavDMappingError(ValueError):
    """Raised when a MalbehavD-V1 row cannot be parsed into a call sequence."""


@dataclass(frozen=True)
class FeatureMapping:
    """One `FT_RW` feature's mapping decision against MalbehavD-V1, and why."""

    feature: str
    kind: MappingKind
    source_apis: tuple[str, ...]
    rationale: str
    compute: Callable[[Mapping[str, Any]], float] | None = None


# -- API-name categories, built once against the 291-name vocabulary actually observed in the -----
# -- committed CSV (verified this session -- `sessions/2026-09-26-04-...md`), not assumed. --------

#: Genuine file-content read/write syscalls -- the NT-native pair, not the higher-level Win32
#: wrappers, so `read_write_ratio` measures the same two symmetric operations rather than mixing
#: read-only file-attribute queries in with true content reads.
_FILE_READ_APIS: Final = frozenset({"NtReadFile"})
_FILE_WRITE_APIS: Final = frozenset({"NtWriteFile"})

#: Every call that touches a file's existence, content, or attributes -- for `files_touched_per_s`.
_FILE_TOUCH_APIS: Final = frozenset(
    {
        "NtCreateFile",
        "NtOpenFile",
        "NtReadFile",
        "NtWriteFile",
        "NtSetInformationFile",
        "NtQueryInformationFile",
        "DeleteFileW",
        "CopyFileA",
        "CopyFileW",
        "CopyFileExW",
        "GetFileAttributesW",
        "GetFileAttributesExW",
        "SetFileAttributesW",
        "CreateDirectoryW",
        "CreateDirectoryExW",
        "RemoveDirectoryA",
        "RemoveDirectoryW",
    }
)

#: `MoveFileWithProgressW` is Windows' rename/move primitive -- the one call in the vocabulary
#: that is unambiguously a rename, not a proxy for one.
_RENAME_APIS: Final = frozenset({"MoveFileWithProgressW"})

#: Cryptographic API calls, matched by exact name against the vocabulary actually present.
_CRYPTO_CALL_APIS: Final = frozenset(
    {
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptCreateHash",
        "CryptDecodeObjectEx",
        "CryptDecrypt",
        "CryptEncrypt",
        "CryptExportKey",
        "CryptGenKey",
        "CryptHashData",
        "CryptProtectData",
        "CryptProtectMemory",
        "CryptUnprotectData",
        "CryptUnprotectMemory",
        "DecryptMessage",
        "EncryptMessage",
    }
)

#: The subset of `_CRYPTO_CALL_APIS` that is specifically key material generation/acquisition --
#: mirrors `ember_mapping._KEYGEN_API_NAMES`'s curated list, filtered to what this vocabulary has
#: (it has no `CryptGenRandom`, `BCryptGenerateKeyPair`, `BCryptGenRandom`, `CryptDeriveKey`, or
#: `CryptImportKey` -- none of those calls occur in any of the 2,570 traces).
_KEYGEN_APIS: Final = frozenset({"CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW"})

#: Classic injection-technique primitives: allocate/map into another process, then write or run.
_INJECTION_APIS: Final = frozenset(
    {
        "CreateRemoteThread",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "NtMapViewOfSection",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
    }
)

#: Privilege/service-installation primitives. Broad by necessity (service installation is not
#: always escalation) -- flagged in the mapping's rationale, same caution EMBER applied to its
#: own weakest proxy (`read_write_ratio`).
_PRIVESC_APIS: Final = frozenset(
    {
        "LookupPrivilegeValueW",
        "NtLoadDriver",
        "CreateServiceA",
        "CreateServiceW",
        "StartServiceA",
        "StartServiceW",
        "OpenSCManagerA",
        "OpenSCManagerW",
    }
)

_CHILD_PROCESS_APIS: Final = frozenset(
    {"CreateProcessInternalW", "NtCreateUserProcess", "ShellExecuteExW"}
)

#: Outbound-connection-establishing calls -- stands in for beacon *count*, not confirmed
#: periodicity: a single trace cannot establish that connections recur, only that they occur.
_C2_CONNECT_APIS: Final = frozenset(
    {
        "connect",
        "WSAConnect",
        "InternetConnectA",
        "InternetConnectW",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "socket",
        "WSASocketA",
        "WSASocketW",
    }
)

_OUTBOUND_SEND_APIS: Final = frozenset(
    {"send", "sendto", "WSASend", "HttpSendRequestA", "HttpSendRequestW", "InternetWriteFile"}
)

#: Registry-write calls -- stands in for autostart-specific writes without the registry-path
#: argument needed to confirm the key written was actually an autostart location.
_AUTOSTART_WRITE_APIS: Final = frozenset(
    {
        "RegSetValueExA",
        "RegSetValueExW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "NtSetValueKey",
        "NtCreateKey",
    }
)


def parse_call_sequence(row: Sequence[str]) -> tuple[str, ...]:
    """One CSV row's numbered columns -> the ordered, non-empty call sequence.

    The CSV is ragged (shorter traces leave the tail of the 153 position columns blank), so empty
    strings and NaN-as-empty-string are dropped, in order, rather than padded away.
    """
    return tuple(str(call).strip() for call in row if str(call).strip() and str(call) != "nan")


def _count(calls: Sequence[str], vocabulary: frozenset[str]) -> float:
    return float(sum(1 for call in calls if call in vocabulary))


def _files_touched_per_s(row: Mapping[str, Any]) -> float:
    return _count(row["calls"], _FILE_TOUCH_APIS)


def _read_write_ratio(row: Mapping[str, Any]) -> float:
    """`read_write_ratio` <- count(`NtReadFile`) / max(count(`NtWriteFile`), 1).

    The two canonical NT file-I/O syscalls, not a structural proxy: a real ratio of real observed
    read and write operations during actual execution, unlike ClaMP/EMBER's section-permission
    proxies (DEV-34/DEV-35) which stood in for a runtime ratio using a static structural property.
    """
    reads = _count(row["calls"], _FILE_READ_APIS)
    writes = _count(row["calls"], _FILE_WRITE_APIS)
    return reads / max(writes, 1.0)


def _rename_rate_per_s(row: Mapping[str, Any]) -> float:
    return _count(row["calls"], _RENAME_APIS)


def _crypto_call_rate(row: Mapping[str, Any]) -> float:
    return _count(row["calls"], _CRYPTO_CALL_APIS)


def _key_generation_events(row: Mapping[str, Any]) -> float:
    return _count(row["calls"], _KEYGEN_APIS)


def _crypto_ngram_novelty(row: Mapping[str, Any]) -> float:
    """`crypto_ngram_novelty` <- distinct adjacent-call bigrams / (trace length - 1).

    The weakest of the twelve mapped features, kept for the same reason EMBER kept
    `read_write_ratio` despite it being its weakest: it is a real, non-fabricated statistic of the
    actual call sequence, not because it is a strong proxy. `FT_RW`'s feature is a novelty score
    of API n-grams relative to *other samples'* sequences (DEV-27's synthetic generator draws it
    per-episode from a fitted distribution); this computes a purely self-referential diversity
    statistic of one trace's own bigram structure instead, because building a reference bigram
    vocabulary from this same evaluation set's benign rows would make the feature depend on the
    labels of the data being scored -- a leakage shape this module avoids on principle, the same
    way `honeypot.collector` avoids any feature that reads the label it is trying to predict
    (DEV-27's kill-chain truncation). A highly repetitive trace (a tight polling loop) scores low;
    a trace with little local repetition scores high. This is a genuine dynamic-behaviour
    computation MalbehavD-V1 uniquely makes possible (ClaMP/EMBER have no call sequence at all,
    hence `MISSING` for this feature in both), but it measures sequence diversity, not novelty
    against a reference population -- flagged rather than overstated.
    """
    calls = row["calls"]
    if len(calls) < 2:
        return 0.0
    bigrams = {(calls[i], calls[i + 1]) for i in range(len(calls) - 1)}
    return float(len(bigrams)) / float(len(calls) - 1)


def _child_process_spawns(row: Mapping[str, Any]) -> float:
    return _count(row["calls"], _CHILD_PROCESS_APIS)


def _injection_attempts(row: Mapping[str, Any]) -> float:
    return _count(row["calls"], _INJECTION_APIS)


def _privilege_escalation_attempts(row: Mapping[str, Any]) -> float:
    return _count(row["calls"], _PRIVESC_APIS)


def _c2_beacon_count(row: Mapping[str, Any]) -> float:
    return _count(row["calls"], _C2_CONNECT_APIS)


def _outbound_burst_rate(row: Mapping[str, Any]) -> float:
    return _count(row["calls"], _OUTBOUND_SEND_APIS)


def _autostart_writes(row: Mapping[str, Any]) -> float:
    return _count(row["calls"], _AUTOSTART_WRITE_APIS)


#: Every `FT_RW` feature, in `FEATURE_NAMES` order via `FEATURE_GROUPS`, so every feature is
#: accounted for exactly once (`test_honeypot_malbehavd_mapping.py::
#: test_every_ft_rw_feature_has_a_mapping_decision`). 12/22 mapped, across 5 of 7 groups
#: (filesystem 3/5, entropy 0/3, crypto_api 3/3, process 3/3, network 2/3, persistence 1/3,
#: kill_chain 0/2) -- the coverage-fraction and group-coverage finding the session brief asks for,
#: against ClaMP's 3/22 (entropy only) and EMBER's 6/22 (entropy + partial crypto_api/filesystem).
MALBEHAVD_MAPPING: Final[dict[str, FeatureMapping]] = {
    # -- filesystem: 3/5 mapped from real observed file syscalls; 2/5 need path/extension args. --
    "files_touched_per_s": FeatureMapping(
        "files_touched_per_s",
        MappingKind.PROXY,
        tuple(sorted(_FILE_TOUCH_APIS)),
        "Count of file-touching API calls observed in the trace, standing in for a rate: no "
        "timestamps exist to divide by, same 'count stands in for a rate' convention "
        "`ember_mapping.crypto_call_rate` uses.",
        compute=_files_touched_per_s,
    ),
    "read_write_ratio": FeatureMapping(
        "read_write_ratio",
        MappingKind.PROXY,
        ("NtReadFile", "NtWriteFile"),
        "Real count(NtReadFile)/count(NtWriteFile) from actual observed execution -- see "
        "`_read_write_ratio` for why this is stronger than ClaMP/EMBER's structural proxies for "
        "the same feature, while still not identical to FT_RW's synthetic definition.",
        compute=_read_write_ratio,
    ),
    "rename_rate_per_s": FeatureMapping(
        "rename_rate_per_s",
        MappingKind.PROXY,
        tuple(sorted(_RENAME_APIS)),
        "Count of MoveFileWithProgressW (Windows' rename/move primitive) observed in the trace, "
        "count standing in for a rate as above.",
        compute=_rename_rate_per_s,
    ),
    "extension_change_rate": FeatureMapping(
        "extension_change_rate",
        MappingKind.MISSING,
        (),
        "MalbehavD-V1 carries call names only, no arguments -- no filename or extension string "
        "is captured for any rename/write call, so an extension change cannot be observed even "
        "though the rename call itself can.",
    ),
    "directory_breadth": FeatureMapping(
        "directory_breadth",
        MappingKind.MISSING,
        (),
        "Breadth needs distinct directory paths; no call arguments are captured. A count of "
        "directory-related calls was considered and rejected as a proxy, same reasoning DEV-35 "
        "used to reject NumberOfSections for this identical feature -- an activity count is not "
        "a breadth (distinct-location) measure.",
    ),
    # -- entropy: fully missing -- no byte content is ever observed, only call identity/order. --
    "write_entropy_mean": FeatureMapping(
        "write_entropy_mean",
        MappingKind.MISSING,
        (),
        "No byte content is captured anywhere in an API-call-sequence dataset; NtWriteFile's "
        "presence says a write happened, not what was written.",
    ),
    "write_entropy_var": FeatureMapping(
        "write_entropy_var", MappingKind.MISSING, (), "Same reason as write_entropy_mean."
    ),
    "entropy_delta": FeatureMapping(
        "entropy_delta", MappingKind.MISSING, (), "Same reason as write_entropy_mean."
    ),
    # -- crypto_api: all 3 mapped -- the group EMBER only partially reached (2/3). --------------
    "crypto_call_rate": FeatureMapping(
        "crypto_call_rate",
        MappingKind.PROXY,
        tuple(sorted(_CRYPTO_CALL_APIS)),
        "Count of observed Crypt*/DecryptMessage/EncryptMessage calls -- actually invoked during "
        "execution, not merely imported (contrast with EMBER's import-table presence, DEV-35).",
        compute=_crypto_call_rate,
    ),
    "key_generation_events": FeatureMapping(
        "key_generation_events",
        MappingKind.PROXY,
        tuple(sorted(_KEYGEN_APIS)),
        "Count of observed CryptGenKey/CryptAcquireContext* calls -- an actual key-generation "
        "event occurring, not an import whose invocation is never confirmed (contrast with "
        "EMBER's identical feature, DEV-35).",
        compute=_key_generation_events,
    ),
    "crypto_ngram_novelty": FeatureMapping(
        "crypto_ngram_novelty",
        MappingKind.PROXY,
        (),
        "Distinct-bigram diversity ratio of the trace's own call sequence -- see "
        "`_crypto_ngram_novelty` for why this is self-referential rather than novelty against a "
        "reference population, and the weakest of the twelve mapped features.",
        compute=_crypto_ngram_novelty,
    ),
    # -- process: all 3 mapped -- a group ClaMP/EMBER could not touch at all. -------------------
    "child_process_spawns": FeatureMapping(
        "child_process_spawns",
        MappingKind.PROXY,
        tuple(sorted(_CHILD_PROCESS_APIS)),
        "Count of observed process-creation calls (CreateProcessInternalW, NtCreateUserProcess, "
        "ShellExecuteExW).",
        compute=_child_process_spawns,
    ),
    "injection_attempts": FeatureMapping(
        "injection_attempts",
        MappingKind.PROXY,
        tuple(sorted(_INJECTION_APIS)),
        "Count of observed injection-technique calls (CreateRemoteThread, WriteProcessMemory, "
        "ReadProcessMemory, NtMapViewOfSection, SetWindowsHookEx*).",
        compute=_injection_attempts,
    ),
    "privilege_escalation_attempts": FeatureMapping(
        "privilege_escalation_attempts",
        MappingKind.PROXY,
        tuple(sorted(_PRIVESC_APIS)),
        "Count of observed privilege/service-installation calls -- broad by necessity (service "
        "installation is not always escalation), flagged the same way EMBER flagged its own "
        "weakest proxy.",
        compute=_privilege_escalation_attempts,
    ),
    # -- network: 2/3 mapped -- dns_entropy needs the resolved name string, which is absent. -----
    "c2_beacon_count": FeatureMapping(
        "c2_beacon_count",
        MappingKind.PROXY,
        tuple(sorted(_C2_CONNECT_APIS)),
        "Count of observed outbound-connection-establishing calls, standing in for beacon count: "
        "a single trace shows connections occurred, not that they recur periodically.",
        compute=_c2_beacon_count,
    ),
    "dns_entropy": FeatureMapping(
        "dns_entropy",
        MappingKind.MISSING,
        (),
        "DnsQuery_A/W, getaddrinfo and gethostbyname all occur in the vocabulary, so DNS "
        "*activity* is observable -- but the resolved domain-name string itself (needed to "
        "compute the entropy of the name) is not captured, only the call name.",
    ),
    "outbound_burst_rate": FeatureMapping(
        "outbound_burst_rate",
        MappingKind.PROXY,
        tuple(sorted(_OUTBOUND_SEND_APIS)),
        "Count of observed outbound-send calls, standing in for burst rate: no timestamps exist "
        "to measure burstiness, only that sends occurred.",
        compute=_outbound_burst_rate,
    ),
    # -- persistence: 1/3 mapped -- the two MISSING need a specific API/registry-path this ------
    # -- vocabulary's calls are too generic to confirm. ------------------------------------------
    "autostart_writes": FeatureMapping(
        "autostart_writes",
        MappingKind.PROXY,
        tuple(sorted(_AUTOSTART_WRITE_APIS)),
        "Count of observed registry-write calls, standing in for autostart-specific writes: the "
        "registry-key-path argument that would confirm an autostart location is not captured, "
        "only that some registry write happened -- the weakest of the mapped persistence "
        "features, kept for the same reason EMBER kept its weakest.",
        compute=_autostart_writes,
    ),
    "shadow_copy_deletions": FeatureMapping(
        "shadow_copy_deletions",
        MappingKind.MISSING,
        (),
        "No vssadmin/WMI shadow-copy-specific call is confirmable in this vocabulary; the generic "
        "IWbemServices_ExecMethod/ExecQuery calls present were considered and rejected as too "
        "broad/speculative a proxy -- WMI is used for far more than shadow-copy deletion, and "
        "forcing the analogy would hide that mismatch rather than report it.",
    ),
    "backup_path_accesses": FeatureMapping(
        "backup_path_accesses",
        MappingKind.MISSING,
        (),
        "No backup-path-specific signal exists; volume-enumeration calls present "
        "(GetVolumePathNameW etc.) measure a different quantity (volume enumeration, not "
        "backup-path access) and were rejected as a proxy for the same reason DEV-35 rejected "
        "NumberOfSections for directory_breadth.",
    ),
    # -- kill_chain: fully missing -- no per-call timestamps, no principled stage boundary. ------
    "observed_stages": FeatureMapping(
        "observed_stages",
        MappingKind.MISSING,
        (),
        "No principled way to bucket a flat, argument-free API-call sequence into the four "
        "observable kill-chain stages without inventing a heuristic boundary this session cannot "
        "verify -- CLAUDE.md's 'never claim a number we did not measure' extends to never "
        "fabricating a stage-assignment rule.",
    ),
    "stage_dwell_mean_s": FeatureMapping(
        "stage_dwell_mean_s",
        MappingKind.MISSING,
        (),
        "No per-call timestamps exist in this dataset; dwell time cannot be measured at all.",
    ),
}


def build_from_malbehavd_row(row: Mapping[str, Any]) -> FeatureVector:
    """One MalbehavD-V1 row (already parsed into `{"calls": tuple[str, ...]}`) -> one `FT_RW`
    `FeatureVector`. Deterministic and total, like `external_mapping.build_from_clamp_row` and
    `ember_mapping.build_from_ember_row`: every row yields a full-length vector, missing slots
    zeroed and flagged rather than dropped.
    """
    if "calls" not in row:
        raise MalbehavDMappingError("row is missing the required 'calls' field")
    values: list[float] = []
    mask = 0
    for index, name in enumerate(FEATURE_NAMES):
        spec = MALBEHAVD_MAPPING[name]
        if spec.kind is MappingKind.MISSING or spec.compute is None:
            values.append(0.0)
            mask |= 1 << index
        else:
            values.append(spec.compute(row))
    return FeatureVector(values=tuple(values), missing_mask=mask)


def mapping_summary() -> dict[str, dict[str, object]]:
    """One row per `FT_RW` group: how many of its features are direct/proxy/missing, computed
    here so the report table and the code that decided it can never drift apart -- same pattern
    as `external_mapping.mapping_summary`/`ember_mapping.mapping_summary`.
    """
    summary: dict[str, dict[str, object]] = {}
    for group, names in FEATURE_GROUPS:
        counts = {kind.value: 0 for kind in MappingKind}
        for name in names:
            counts[MALBEHAVD_MAPPING[name].kind.value] += 1
        summary[group] = {"n_features": len(names), **counts}
    return summary
