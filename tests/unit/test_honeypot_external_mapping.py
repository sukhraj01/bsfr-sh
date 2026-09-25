"""`honeypot.external_mapping`: the ClaMP -> `FT_RW` mapping table. M7-7, DEV-34."""

from __future__ import annotations

import pytest

from bsfr_sh.honeypot.external_mapping import (
    CLAMP_MAPPING,
    CLAMP_SOURCE_COLUMNS,
    ClaMPMappingError,
    MappingKind,
    build_from_clamp_row,
    mapping_summary,
)
from bsfr_sh.honeypot.features import FEATURE_NAMES


def _row(**overrides: float) -> dict[str, float]:
    base = {"E_text": 4.0, "E_data": 2.0, "E_file": 6.5}
    base.update(overrides)
    return base


def test_every_ft_rw_feature_has_a_mapping_decision() -> None:
    assert set(CLAMP_MAPPING) == set(FEATURE_NAMES)


def test_only_entropy_group_has_non_missing_features() -> None:
    entropy_features = {"write_entropy_mean", "write_entropy_var", "entropy_delta"}
    for name, mapping in CLAMP_MAPPING.items():
        if name in entropy_features:
            assert mapping.kind is not MappingKind.MISSING
        else:
            assert mapping.kind is MappingKind.MISSING

    counts = dict.fromkeys(MappingKind, 0)
    for mapping in CLAMP_MAPPING.values():
        counts[mapping.kind] += 1
    assert counts[MappingKind.MISSING] == 19
    assert counts[MappingKind.DIRECT] + counts[MappingKind.PROXY] == 3


def test_missing_features_get_zero_and_a_set_mask_bit() -> None:
    vector = build_from_clamp_row(_row())
    for index, name in enumerate(FEATURE_NAMES):
        if CLAMP_MAPPING[name].kind is MappingKind.MISSING:
            assert vector.values[index] == 0.0
            assert vector.missing_mask >> index & 1 == 1


def test_mapped_features_are_not_flagged_missing() -> None:
    vector = build_from_clamp_row(_row())
    mapped = {"write_entropy_mean", "write_entropy_var", "entropy_delta"}
    for index, name in enumerate(FEATURE_NAMES):
        if name in mapped:
            assert vector.missing_mask >> index & 1 == 0


def test_write_entropy_mean_is_e_file() -> None:
    vector = build_from_clamp_row(_row(E_file=7.25))
    index = FEATURE_NAMES.index("write_entropy_mean")
    assert vector.values[index] == pytest.approx(7.25)


def test_write_entropy_var_is_symmetric_in_its_two_inputs() -> None:
    a = build_from_clamp_row(_row(E_text=4.0, E_data=2.0))
    b = build_from_clamp_row(_row(E_text=2.0, E_data=4.0))
    index = FEATURE_NAMES.index("write_entropy_var")
    assert a.values[index] == pytest.approx(b.values[index])
    assert a.values[index] == pytest.approx(1.0)  # ((4-2)/2)**2 == 1.0


def test_entropy_delta_is_the_absolute_gap_never_negative() -> None:
    a = build_from_clamp_row(_row(E_text=5.0, E_data=1.0))
    b = build_from_clamp_row(_row(E_text=1.0, E_data=5.0))
    index = FEATURE_NAMES.index("entropy_delta")
    assert a.values[index] == pytest.approx(4.0)
    assert b.values[index] == pytest.approx(4.0)


def test_missing_required_column_raises() -> None:
    incomplete = {"E_text": 1.0, "E_data": 2.0}  # missing E_file
    with pytest.raises(ClaMPMappingError, match="missing required columns"):
        build_from_clamp_row(incomplete)


def test_source_columns_are_exactly_what_compute_functions_read() -> None:
    assert set(CLAMP_SOURCE_COLUMNS) == {"E_text", "E_data", "E_file"}


def test_mapping_summary_totals_22_features_across_seven_groups() -> None:
    summary = mapping_summary()
    assert len(summary) == 7
    total = sum(int(row["n_features"]) for row in summary.values())
    assert total == len(FEATURE_NAMES) == 22
    assert summary["entropy"]["missing"] == 0
    assert sum(int(row["missing"]) for row in summary.values()) == 19
