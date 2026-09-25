"""`honeypot.ember_mapping`: the EMBER -> `FT_RW` mapping table. M7-10, DEV-35."""

from __future__ import annotations

import pytest

from bsfr_sh.honeypot.ember_mapping import (
    EMBER_MAPPING,
    EMBER_REQUIRED_TOP_LEVEL_FIELDS,
    EmberMappingError,
    MappingKind,
    build_from_ember_row,
    mapping_summary,
)
from bsfr_sh.honeypot.features import FEATURE_NAMES


def _row(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "histogram": [1] * 256,
        "section": {
            "entry": ".text",
            "sections": [
                {"name": ".text", "entropy": 6.5, "props": ["CNT_CODE", "MEM_READ", "MEM_EXECUTE"]},
                {
                    "name": ".data",
                    "entropy": 3.2,
                    "props": ["CNT_INITIALIZED_DATA", "MEM_READ", "MEM_WRITE"],
                },
            ],
        },
        "imports": {
            "ADVAPI32.dll": ["CryptGenKey", "CryptGenRandom"],
            "KERNEL32.dll": ["CreateFileA"],
        },
    }
    base.update(overrides)
    return base


def test_every_ft_rw_feature_has_a_mapping_decision() -> None:
    assert set(EMBER_MAPPING) == set(FEATURE_NAMES)


def test_exactly_the_six_named_features_are_non_missing() -> None:
    mapped = {
        "write_entropy_mean",
        "write_entropy_var",
        "entropy_delta",
        "crypto_call_rate",
        "key_generation_events",
        "read_write_ratio",
    }
    for name, mapping in EMBER_MAPPING.items():
        if name in mapped:
            assert mapping.kind is not MappingKind.MISSING
        else:
            assert mapping.kind is MappingKind.MISSING

    counts = dict.fromkeys(MappingKind, 0)
    for mapping in EMBER_MAPPING.values():
        counts[mapping.kind] += 1
    assert counts[MappingKind.MISSING] == 16
    assert counts[MappingKind.DIRECT] + counts[MappingKind.PROXY] == 6


def test_ember_maps_more_features_than_clamp_did() -> None:
    """The coverage-fraction finding the session brief asks for: 6/22 here vs. ClaMP's 3/22."""
    from bsfr_sh.honeypot.external_mapping import CLAMP_MAPPING

    ember_mapped = sum(1 for m in EMBER_MAPPING.values() if m.kind is not MappingKind.MISSING)
    clamp_mapped = sum(1 for m in CLAMP_MAPPING.values() if m.kind is not MappingKind.MISSING)
    assert ember_mapped == 6
    assert clamp_mapped == 3
    assert ember_mapped > clamp_mapped


def test_missing_features_get_zero_and_a_set_mask_bit() -> None:
    vector = build_from_ember_row(_row())
    for index, name in enumerate(FEATURE_NAMES):
        if EMBER_MAPPING[name].kind is MappingKind.MISSING:
            assert vector.values[index] == 0.0
            assert vector.missing_mask >> index & 1 == 1


def test_mapped_features_are_not_flagged_missing() -> None:
    vector = build_from_ember_row(_row())
    mapped = {
        "write_entropy_mean",
        "write_entropy_var",
        "entropy_delta",
        "crypto_call_rate",
        "key_generation_events",
        "read_write_ratio",
    }
    for index, name in enumerate(FEATURE_NAMES):
        if name in mapped:
            assert vector.missing_mask >> index & 1 == 0


def test_write_entropy_mean_is_shannon_entropy_of_the_byte_histogram() -> None:
    uniform = build_from_ember_row(_row(histogram=[1] * 256))
    index = FEATURE_NAMES.index("write_entropy_mean")
    # A perfectly uniform 256-value histogram has maximum entropy: log2(256) == 8.0 bits.
    assert uniform.values[index] == pytest.approx(8.0)

    skewed = build_from_ember_row(_row(histogram=[1000] + [0] * 255))
    assert skewed.values[index] == pytest.approx(0.0)


def test_write_entropy_var_uses_every_reported_section() -> None:
    two_sections = build_from_ember_row(
        _row(section={"sections": [{"entropy": 4.0, "props": []}, {"entropy": 2.0, "props": []}]})
    )
    three_sections = build_from_ember_row(
        _row(
            section={
                "sections": [
                    {"entropy": 4.0, "props": []},
                    {"entropy": 2.0, "props": []},
                    {"entropy": 3.0, "props": []},
                ]
            }
        )
    )
    index = FEATURE_NAMES.index("write_entropy_var")
    assert two_sections.values[index] == pytest.approx(1.0)  # population var of {4,2}
    assert three_sections.values[index] == pytest.approx(2.0 / 3.0)  # population var of {4,2,3}


def test_entropy_delta_is_max_minus_min_never_negative() -> None:
    vector = build_from_ember_row(
        _row(
            section={
                "sections": [
                    {"entropy": 1.0, "props": []},
                    {"entropy": 5.0, "props": []},
                    {"entropy": 3.0, "props": []},
                ]
            }
        )
    )
    index = FEATURE_NAMES.index("entropy_delta")
    assert vector.values[index] == pytest.approx(4.0)


def test_entropy_delta_needs_at_least_two_sections() -> None:
    vector = build_from_ember_row(_row(section={"sections": [{"entropy": 5.0, "props": []}]}))
    index = FEATURE_NAMES.index("entropy_delta")
    assert vector.values[index] == 0.0


def test_crypto_call_rate_counts_keyword_matches_across_every_dll() -> None:
    vector = build_from_ember_row(
        _row(
            imports={
                "ADVAPI32.dll": ["CryptGenKey", "CryptAcquireContextA"],
                "BCRYPT.dll": ["BCryptGenerateKeyPair"],
                "KERNEL32.dll": ["CreateFileA", "ReadFile"],
            }
        )
    )
    index = FEATURE_NAMES.index("crypto_call_rate")
    assert vector.values[index] == pytest.approx(3.0)


def test_key_generation_events_is_an_exact_api_name_match() -> None:
    vector = build_from_ember_row(
        _row(
            imports={
                "ADVAPI32.dll": ["CryptGenKey", "CryptEncrypt"],  # CryptEncrypt is not key-gen
            }
        )
    )
    index = FEATURE_NAMES.index("key_generation_events")
    assert vector.values[index] == pytest.approx(1.0)


def test_read_write_ratio_from_section_permission_flags() -> None:
    vector = build_from_ember_row(
        _row(
            section={
                "sections": [
                    {"props": ["MEM_READ"]},  # read-only
                    {"props": ["MEM_READ"]},  # read-only
                    {"props": ["MEM_READ", "MEM_WRITE"]},  # writable
                ]
            }
        )
    )
    index = FEATURE_NAMES.index("read_write_ratio")
    assert vector.values[index] == pytest.approx(2.0)  # 2 read-only / 1 writable


def test_read_write_ratio_never_divides_by_zero() -> None:
    vector = build_from_ember_row(_row(section={"sections": [{"props": ["MEM_READ"]}]}))
    index = FEATURE_NAMES.index("read_write_ratio")
    assert vector.values[index] == pytest.approx(1.0)  # 1 read-only / max(0, 1)


def test_missing_required_field_raises() -> None:
    incomplete = {"histogram": [1] * 256}  # missing section, imports
    with pytest.raises(EmberMappingError, match="missing required top-level fields"):
        build_from_ember_row(incomplete)


def test_required_fields_match_what_compute_functions_need() -> None:
    assert set(EMBER_REQUIRED_TOP_LEVEL_FIELDS) == {"histogram", "section", "imports"}


def test_mapping_summary_totals_22_features_across_seven_groups() -> None:
    summary = mapping_summary()
    assert len(summary) == 7
    total = sum(int(row["n_features"]) for row in summary.values())
    assert total == len(FEATURE_NAMES) == 22
    assert summary["entropy"]["missing"] == 0
    assert sum(int(row["missing"]) for row in summary.values()) == 16
