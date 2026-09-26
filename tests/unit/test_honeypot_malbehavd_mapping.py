"""`honeypot.malbehavd_mapping`: the MalbehavD-V1 -> `FT_RW` mapping table. M7-13, DEV-39."""

from __future__ import annotations

import pytest

from bsfr_sh.honeypot.features import FEATURE_NAMES
from bsfr_sh.honeypot.malbehavd_mapping import (
    MALBEHAVD_MAPPING,
    MalbehavDMappingError,
    MappingKind,
    build_from_malbehavd_row,
    mapping_summary,
    parse_call_sequence,
)

_MAPPED = {
    "files_touched_per_s",
    "read_write_ratio",
    "rename_rate_per_s",
    "crypto_call_rate",
    "key_generation_events",
    "crypto_ngram_novelty",
    "child_process_spawns",
    "injection_attempts",
    "privilege_escalation_attempts",
    "c2_beacon_count",
    "outbound_burst_rate",
    "autostart_writes",
}


def _row(*calls: str) -> dict[str, object]:
    return {"calls": tuple(calls)}


def test_every_ft_rw_feature_has_a_mapping_decision() -> None:
    assert set(MALBEHAVD_MAPPING) == set(FEATURE_NAMES)


def test_exactly_the_twelve_named_features_are_non_missing() -> None:
    for name, mapping in MALBEHAVD_MAPPING.items():
        if name in _MAPPED:
            assert mapping.kind is not MappingKind.MISSING
        else:
            assert mapping.kind is MappingKind.MISSING

    counts = dict.fromkeys(MappingKind, 0)
    for mapping in MALBEHAVD_MAPPING.values():
        counts[mapping.kind] += 1
    assert counts[MappingKind.MISSING] == 10
    assert counts[MappingKind.DIRECT] + counts[MappingKind.PROXY] == 12
    assert counts[MappingKind.DIRECT] == 0  # never overclaimed, same bar as EMBER (DEV-35)


def test_maps_more_features_than_clamp_and_ember() -> None:
    """The coverage-fraction finding the session brief asks for: 12/22 vs. EMBER's 6/22 vs.
    ClaMP's 3/22."""
    from bsfr_sh.honeypot.ember_mapping import EMBER_MAPPING
    from bsfr_sh.honeypot.external_mapping import CLAMP_MAPPING

    malbehavd_mapped = sum(
        1 for m in MALBEHAVD_MAPPING.values() if m.kind is not MappingKind.MISSING
    )
    ember_mapped = sum(1 for m in EMBER_MAPPING.values() if m.kind is not MappingKind.MISSING)
    clamp_mapped = sum(1 for m in CLAMP_MAPPING.values() if m.kind is not MappingKind.MISSING)
    assert malbehavd_mapped == 12
    assert ember_mapped == 6
    assert clamp_mapped == 3
    assert malbehavd_mapped > ember_mapped > clamp_mapped


def test_entropy_and_kill_chain_are_fully_missing_the_inverse_of_clamp_ember() -> None:
    """ClaMP/EMBER ground only entropy; MalbehavD-V1 grounds everything except entropy and
    kill_chain -- the qualitative flip the session brief predicts."""
    from bsfr_sh.honeypot.features import FEATURE_GROUPS

    by_group = dict(FEATURE_GROUPS)
    for name in by_group["entropy"]:
        assert MALBEHAVD_MAPPING[name].kind is MappingKind.MISSING
    for name in by_group["kill_chain"]:
        assert MALBEHAVD_MAPPING[name].kind is MappingKind.MISSING
    for name in by_group["process"]:
        assert MALBEHAVD_MAPPING[name].kind is not MappingKind.MISSING
    for name in by_group["network"]:
        if name != "dns_entropy":
            assert MALBEHAVD_MAPPING[name].kind is not MappingKind.MISSING


def test_missing_features_get_zero_and_a_set_mask_bit() -> None:
    vector = build_from_malbehavd_row(_row("NtCreateFile", "NtReadFile"))
    for index, name in enumerate(FEATURE_NAMES):
        if MALBEHAVD_MAPPING[name].kind is MappingKind.MISSING:
            assert vector.values[index] == 0.0
            assert vector.missing_mask >> index & 1 == 1


def test_mapped_features_are_not_flagged_missing() -> None:
    vector = build_from_malbehavd_row(_row("NtCreateFile", "NtReadFile"))
    for index, name in enumerate(FEATURE_NAMES):
        if name in _MAPPED:
            assert vector.missing_mask >> index & 1 == 0


def test_files_touched_per_s_counts_file_touch_calls_only() -> None:
    vector = build_from_malbehavd_row(
        _row("NtCreateFile", "NtReadFile", "GetSystemInfo", "DeleteFileW", "CoInitializeEx")
    )
    index = FEATURE_NAMES.index("files_touched_per_s")
    assert vector.values[index] == pytest.approx(3.0)  # NtCreateFile, NtReadFile, DeleteFileW


def test_read_write_ratio_from_observed_calls() -> None:
    vector = build_from_malbehavd_row(_row("NtReadFile", "NtReadFile", "NtWriteFile"))
    index = FEATURE_NAMES.index("read_write_ratio")
    assert vector.values[index] == pytest.approx(2.0)


def test_read_write_ratio_never_divides_by_zero() -> None:
    vector = build_from_malbehavd_row(_row("NtReadFile"))
    index = FEATURE_NAMES.index("read_write_ratio")
    assert vector.values[index] == pytest.approx(1.0)


def test_rename_rate_counts_move_file_with_progress() -> None:
    vector = build_from_malbehavd_row(
        _row("MoveFileWithProgressW", "MoveFileWithProgressW", "NtClose")
    )
    index = FEATURE_NAMES.index("rename_rate_per_s")
    assert vector.values[index] == pytest.approx(2.0)


def test_crypto_call_rate_counts_crypto_keyword_calls() -> None:
    vector = build_from_malbehavd_row(
        _row("CryptGenKey", "CryptHashData", "NtClose", "CoCreateInstance")
    )
    index = FEATURE_NAMES.index("crypto_call_rate")
    assert vector.values[index] == pytest.approx(2.0)


def test_key_generation_events_is_a_curated_exact_match() -> None:
    vector = build_from_malbehavd_row(_row("CryptGenKey", "CryptHashData", "CryptAcquireContextW"))
    index = FEATURE_NAMES.index("key_generation_events")
    # CryptGenKey + CryptAcquireContextW; CryptHashData is crypto activity but not key generation.
    assert vector.values[index] == pytest.approx(2.0)


def test_crypto_ngram_novelty_is_distinct_bigram_ratio() -> None:
    # A B A B: bigrams (A,B) and (B,A), 2 distinct over 3 adjacent pairs.
    vector = build_from_malbehavd_row(_row("NtOpenKey", "NtCreateKey", "NtOpenKey", "NtCreateKey"))
    index = FEATURE_NAMES.index("crypto_ngram_novelty")
    assert vector.values[index] == pytest.approx(2.0 / 3.0)


def test_crypto_ngram_novelty_needs_at_least_two_calls() -> None:
    vector = build_from_malbehavd_row(_row("NtClose"))
    index = FEATURE_NAMES.index("crypto_ngram_novelty")
    assert vector.values[index] == 0.0


def test_child_process_spawns_counts_process_creation_calls() -> None:
    vector = build_from_malbehavd_row(_row("CreateProcessInternalW", "ShellExecuteExW", "NtClose"))
    index = FEATURE_NAMES.index("child_process_spawns")
    assert vector.values[index] == pytest.approx(2.0)


def test_injection_attempts_counts_injection_primitives() -> None:
    vector = build_from_malbehavd_row(_row("WriteProcessMemory", "CreateRemoteThread", "NtClose"))
    index = FEATURE_NAMES.index("injection_attempts")
    assert vector.values[index] == pytest.approx(2.0)


def test_c2_beacon_count_counts_outbound_connect_calls() -> None:
    vector = build_from_malbehavd_row(_row("connect", "socket", "NtClose"))
    index = FEATURE_NAMES.index("c2_beacon_count")
    assert vector.values[index] == pytest.approx(2.0)


def test_autostart_writes_counts_registry_write_calls() -> None:
    vector = build_from_malbehavd_row(_row("RegSetValueExW", "RegCreateKeyExA", "RegCloseKey"))
    index = FEATURE_NAMES.index("autostart_writes")
    assert vector.values[index] == pytest.approx(2.0)


def test_missing_calls_key_raises() -> None:
    with pytest.raises(MalbehavDMappingError, match="calls"):
        build_from_malbehavd_row({})


def test_parse_call_sequence_drops_empty_and_nan_tail() -> None:
    # "" is what `csv.reader` yields for a blank cell; "nan" is what `str(float("nan"))` yields
    # for the same blank cell once pandas has read it -- both ingestion paths are handled.
    row = ["NtCreateFile", "NtReadFile", "", "nan", "nan"]
    assert parse_call_sequence(row) == ("NtCreateFile", "NtReadFile")


def test_mapping_summary_totals_22_features_across_seven_groups() -> None:
    summary = mapping_summary()
    assert len(summary) == 7
    total = sum(int(row["n_features"]) for row in summary.values())
    assert total == len(FEATURE_NAMES) == 22
    assert summary["process"]["missing"] == 0
    assert summary["entropy"]["missing"] == 3
    assert summary["kill_chain"]["missing"] == 2
    assert sum(int(row["missing"]) for row in summary.values()) == 10
