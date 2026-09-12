"""`honeypot.preprocess`: DEV-26's five rules, and the one thing the step must never do."""

from __future__ import annotations

import pytest
from m3b_harness import raw_draw

from bsfr_sh.honeypot.collector import BENIGN, MALICIOUS, RawSample, StageObservation
from bsfr_sh.honeypot.preprocess import clean

COUNTERS = {
    "files_touched": 600.0,
    "read_write_ratio": 1.2,
    "renames": 30.0,
    "extension_change_rate": 0.4,
    "directory_breadth": 12.0,
    "write_entropy_mean": 6.0,
    "write_entropy_var": 0.4,
    "entropy_delta": 1.0,
    "crypto_calls": 900.0,
    "key_generation_events": 2.0,
    "crypto_ngram_novelty": 0.3,
    "child_process_spawns": 1.0,
    "injection_attempts": 0.0,
    "privilege_escalation_attempts": 0.0,
    "c2_beacon_count": 2.0,
    "dns_entropy": 3.0,
    "outbound_burst_rate": 1.0,
    "autostart_writes": 0.0,
    "shadow_copy_deletions": 1.0,
    "backup_path_accesses": 2.0,
}


def _sample(sample_id: str = "s1", **overrides) -> RawSample:
    fields = {
        "sample_id": sample_id,
        "label": MALICIOUS,
        "profile": "fast_crypto",
        "collected_at": 100,
        "duration_s": 300.0,
        "stages": (
            StageObservation("infection", 100.0, True),
            StageObservation("resource_identification", 200.0, True),
        ),
        "counters": dict(COUNTERS),
        "unobserved": (),
        "defects": (),
    }
    fields.update(overrides)
    return RawSample(**fields)  # type: ignore[arg-type]


# -- rule 1: structural ------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"duration_s": 0.0}, "zero duration"),
        ({"stages": (StageObservation("infection", 1.0, False),)}, "nothing observed"),
    ],
)
def test_structurally_empty_samples_are_dropped(overrides, reason) -> None:
    cleaned, report = clean([_sample(**overrides)])
    assert cleaned == ()
    assert report.dropped_structural == 1, reason


# -- rule 2: impossible values -----------------------------------------------------------------
def test_an_out_of_range_value_is_clamped_to_its_bound() -> None:
    cleaned, report = clean([_sample(counters={**COUNTERS, "write_entropy_mean": 9.4})])
    assert cleaned[0].counters["write_entropy_mean"] == 8.0
    assert report.clamped_values == 1


def test_a_negative_count_is_unreadable_rather_than_zero() -> None:
    """ "The sensor returned nonsense" and "the program did nothing" are different facts."""
    cleaned, report = clean([_sample(counters={**COUNTERS, "directory_breadth": -5.0})])
    assert "directory_breadth" not in cleaned[0].counters
    assert "directory_breadth" in cleaned[0].missing
    assert report.marked_unreadable == 1


# -- rule 3: duplicates ------------------------------------------------------------------------
def test_a_repeated_observation_is_kept_once() -> None:
    cleaned, report = clean([_sample(), _sample()])
    assert len(cleaned) == 1
    assert report.dropped_duplicate == 1


def test_two_different_episodes_both_survive() -> None:
    cleaned, _ = clean([_sample("s1"), _sample("s2")])
    assert len(cleaned) == 2


# -- rule 4: missing, marked -------------------------------------------------------------------
def test_an_unobserved_counter_stays_missing_and_is_not_imputed() -> None:
    cleaned, _ = clean(
        [
            _sample(
                unobserved=("dns_entropy",),
                counters={k: v for k, v in COUNTERS.items() if k != "dns_entropy"},
            )
        ]
    )
    assert "dns_entropy" in cleaned[0].missing
    assert "dns_entropy" not in cleaned[0].counters


# -- rule 5: normalisation ---------------------------------------------------------------------
def test_absolute_counts_become_rates() -> None:
    cleaned, report = clean([_sample()])
    counters = cleaned[0].counters
    assert counters["files_touched_per_s"] == pytest.approx(600.0 / 300.0)
    assert counters["rename_rate_per_s"] == pytest.approx(30.0 / 300.0)
    assert counters["crypto_call_rate"] == pytest.approx(900.0 / 300.0)
    assert "files_touched" not in counters
    assert report.normalised == 3


def test_a_missing_count_leaves_its_rate_missing() -> None:
    cleaned, _ = clean(
        [
            _sample(
                unobserved=("files_touched",),
                counters={k: v for k, v in COUNTERS.items() if k != "files_touched"},
            )
        ]
    )
    assert "files_touched_per_s" in cleaned[0].missing


# -- what the step must never do ----------------------------------------------------------------
def test_cleaning_does_not_remove_the_positive_class() -> None:
    """DEV-26: read as anomaly removal, Alg. 2 line 3 would delete exactly what M4 must find."""
    raw = raw_draw(600)
    before = sum(1 for s in raw if s.label == MALICIOUS) / len(raw)
    cleaned, report = clean(raw)
    after = sum(1 for s in cleaned if s.label == MALICIOUS) / len(cleaned)
    assert abs(after - before) < 0.03
    assert report.kept == len(cleaned)
    assert report.received == len(raw)
    assert {MALICIOUS, BENIGN} == {s.label for s in cleaned}


def test_the_report_accounts_for_every_sample() -> None:
    raw = raw_draw(400)
    _, report = clean(raw)
    assert report.received == len(raw)
    assert report.kept + report.dropped == report.received
    assert sum(report.defects_seen.values()) >= report.dropped_structural
