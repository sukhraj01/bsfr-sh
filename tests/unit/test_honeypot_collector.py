"""`honeypot.collector`: Alg. 2 lines 1-2, and the properties the corpus depends on."""

from __future__ import annotations

import pytest
from m3b_harness import make_node, raw_draw

from bsfr_sh.honeypot.collector import (
    AMBIGUOUS_FRACTION,
    BENIGN,
    COUNTER_NAMES,
    KILL_CHAIN_STAGES,
    MALICIOUS,
    Honeypot,
    HoneypotError,
    pack_samples,
    synthesize,
    unpack_samples,
)

DRAW = raw_draw(800)


def test_the_same_seed_gives_byte_identical_samples() -> None:
    assert synthesize(40, seed=7) == synthesize(40, seed=7)


def test_a_different_seed_gives_different_samples() -> None:
    assert synthesize(40, seed=7) != synthesize(40, seed=8)


def test_labels_are_only_the_two_and_roughly_balanced() -> None:
    labels = [s.label for s in DRAW]
    assert set(labels) == {MALICIOUS, BENIGN}
    assert 0.44 < labels.count(MALICIOUS) / len(labels) < 0.56


def test_every_sample_walks_a_prefix_of_the_kill_chain() -> None:
    for sample in DRAW:
        stages = [s.stage for s in sample.stages]
        assert stages == list(KILL_CHAIN_STAGES[: len(stages)])
        assert sum(s.dwell_s for s in sample.stages) == pytest.approx(sample.duration_s, rel=1e-9)


def test_both_classes_reach_the_observable_stages() -> None:
    """If only ransomware ever got past stage 1, the kill-chain group would be the label."""
    reach = {
        label: {len(s.stages) for s in DRAW if s.label == label} for label in (MALICIOUS, BENIGN)
    }
    assert max(reach[BENIGN]) >= 4
    assert reach[MALICIOUS] & reach[BENIGN]


def test_the_confusable_pairs_carry_both_labels_at_the_declared_rate() -> None:
    ambiguous = [s for s in DRAW if s.profile.startswith("ambiguous:")]
    assert abs(len(ambiguous) / len(DRAW) - AMBIGUOUS_FRACTION) < 0.05
    for name in {s.profile for s in ambiguous}:
        labels = {s.label for s in ambiguous if s.profile == name}
        assert labels == {MALICIOUS, BENIGN}, f"{name} is not shared by both classes"


def test_sensor_groups_go_blind_together_and_rarely() -> None:
    blind = [s for s in DRAW if s.unobserved]
    assert blind, "no sample ever lost a sensor group; the corpus has no blind spots"
    groups = {
        "files_touched",
        "read_write_ratio",
        "renames",
        "extension_change_rate",
        "directory_breadth",
    }
    for sample in blind:
        missing = set(sample.unobserved)
        if missing & groups:
            assert groups <= missing, "a group went half-blind; groups fail together"


def test_samples_are_records_of_numbers_and_nothing_else() -> None:
    """CLAUDE.md §2: statistical records, never programs."""
    for sample in DRAW[:100]:
        assert set(sample.counters) <= set(COUNTER_NAMES)
        assert all(isinstance(value, float) for value in sample.counters.values())
        assert all(isinstance(stage.stage, str) for stage in sample.stages)


def test_a_harvest_round_trips_through_the_channel_encoding() -> None:
    assert unpack_samples(pack_samples(DRAW[:20])) == DRAW[:20]


def test_a_malformed_harvest_is_refused() -> None:
    with pytest.raises(HoneypotError):
        unpack_samples(b"not an encoding")


def test_the_honeypot_must_be_deployed_before_it_harvests() -> None:
    node = Honeypot(honeypot_id="HP_1", seed=1)
    with pytest.raises(HoneypotError, match="deployed"):
        node.harvest(5)
    node.deploy()
    assert len(node.harvest(5)) == 5
    with pytest.raises(HoneypotError, match="already deployed"):
        node.deploy()


def test_two_harvests_from_one_deployment_are_different_draws() -> None:
    device = make_node().honeypot
    assert device is not None
    device.deploy()
    assert device.harvest(20) != device.harvest(20)
