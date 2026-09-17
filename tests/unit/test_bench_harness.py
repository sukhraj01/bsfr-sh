"""M6a — `bench/harness.py`. Arithmetic and repeat-count logic get plain unit tests; anything
that spins up a real cluster stays deliberately tiny (a handful of blocks/transactions), because
this suite is not the place to measure Target 3 — `scripts/run_bench.py` is.

No timing assertions here. A test that asserts "X is faster than Y" on wall-clock is exactly the
kind of flaky test CLAUDE.md's determinism section warns about; the actual timing comparison
(`BC_SigRW` slower than `BC_DTBU`) is a measured finding recorded in `RESULTS.md`, not a unit
test invariant.
"""

from __future__ import annotations

import math

import pytest

from bsfr_sh.bench import harness
from bsfr_sh.blockchain.chain import BC_DTBU, BC_SigRW
from bsfr_sh.consensus.pbft import PBFTPolicy
from bsfr_sh.util.config import load_config

POLICY = PBFTPolicy()


# --------------------------------------------------------------------------------------------
# Repeat-count decision
# --------------------------------------------------------------------------------------------
def test_decide_repeat_count_zero_variance_is_the_floor() -> None:
    assert harness.decide_repeat_count(0.0, floor=5) == 5


def test_decide_repeat_count_rises_with_variance() -> None:
    low = harness.decide_repeat_count(0.02, floor=5)
    high = harness.decide_repeat_count(0.2, floor=5)
    assert low == 5
    assert high > low


def test_decide_repeat_count_always_odd_and_within_bounds() -> None:
    for cv in (0.0, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0):
        n = harness.decide_repeat_count(cv, floor=5, ceiling=25)
        assert n % 2 == 1
        assert 5 <= n <= 25


def test_decide_repeat_count_non_finite_cv_falls_back_to_floor() -> None:
    assert harness.decide_repeat_count(math.inf, floor=7) == 7
    assert harness.decide_repeat_count(math.nan, floor=7) == 7


# --------------------------------------------------------------------------------------------
# Trend resolvability
# --------------------------------------------------------------------------------------------
def test_trend_resolvable_when_gap_dwarfs_noise() -> None:
    variance = harness.VarianceReport(
        chain_name=BC_DTBU, case="case_3", samples=(0.470, 0.471, 0.469, 0.472, 0.468)
    )
    assert harness.trend_resolvable(variance, other_case_median_seconds=0.155, repeats=5)


def test_trend_not_resolvable_when_gap_is_within_noise() -> None:
    variance = harness.VarianceReport(
        chain_name=BC_DTBU, case="case_3", samples=(0.40, 0.55, 0.35, 0.60, 0.45)
    )
    assert not harness.trend_resolvable(variance, other_case_median_seconds=0.47, repeats=5)


def test_trend_not_resolvable_with_a_single_repeat() -> None:
    variance = harness.VarianceReport(chain_name=BC_DTBU, case="case_3", samples=(0.47,))
    assert not harness.trend_resolvable(variance, other_case_median_seconds=0.1, repeats=1)


# --------------------------------------------------------------------------------------------
# Modelled network — pure arithmetic, DEV-21
# --------------------------------------------------------------------------------------------
def test_modelled_network_seconds_formula() -> None:
    result = harness.modelled_network_seconds(blocks=10, delay_s=0.02)
    assert result.consensus_seconds == pytest.approx(10 * 3 * 0.02)
    assert result.total_seconds == pytest.approx(10 * 4 * 0.02)


def test_modelled_network_seconds_zero_delay_is_zero() -> None:
    result = harness.modelled_network_seconds(blocks=15, delay_s=0.0)
    assert result.total_seconds == 0.0
    assert result.consensus_seconds == 0.0


@pytest.mark.slow
def test_verify_modelled_network_formula_matches_a_real_run() -> None:
    predicted, actual = harness.verify_modelled_network_formula(
        chain_name=BC_DTBU,
        blocks=3,
        transactions_per_block=5,
        pbft_policy=POLICY,
        delay_s=0.05,
        seed=1,
    )
    assert actual == pytest.approx(predicted)
    assert predicted == pytest.approx(3 * 4 * 0.05)


# --------------------------------------------------------------------------------------------
# One run — small scale, both chains
# --------------------------------------------------------------------------------------------
@pytest.mark.slow
@pytest.mark.parametrize("chain_name", [BC_DTBU, BC_SigRW])
def test_run_once_commits_every_block(chain_name: str) -> None:
    measurement = harness.run_once(
        chain_name=chain_name,
        blocks=3,
        transactions_per_block=5,
        payload_bytes=64,
        pbft_policy=POLICY,
        seed=1,
        tag="unit",
    )
    assert len(measurement.block_seconds) == 3
    assert all(seconds >= 0.0 for seconds in measurement.block_seconds)
    assert measurement.transaction_count == 15
    assert measurement.last_block.transaction_count == 5


@pytest.mark.slow
def test_run_once_builds_the_backup_index_only_for_dtbu() -> None:
    dtbu = harness.run_once(
        chain_name=BC_DTBU,
        blocks=2,
        transactions_per_block=4,
        payload_bytes=64,
        pbft_policy=POLICY,
        seed=2,
        tag="unit-index",
    )
    sigrw = harness.run_once(
        chain_name=BC_SigRW,
        blocks=2,
        transactions_per_block=4,
        payload_bytes=64,
        pbft_policy=POLICY,
        seed=2,
        tag="unit-index",
    )
    assert dtbu.index_seconds is not None
    assert dtbu.index_seconds >= 0.0
    assert sigrw.index_seconds is None


@pytest.mark.slow
def test_run_once_is_deterministic_in_content_not_wall_clock() -> None:
    """Same seed twice: the same shape, every time — never the same block hash.

    `BlockDraft.nonce` (`RN`) is drawn from `secrets`, not the seeded `random` module — by
    design, `blockchain/block.py`'s module docstring calls it inert and random on purpose, the
    same way CLAUDE.md §4b says session ephemerals are. So two runs from one seed commit
    different block hashes but identical transaction counts every time.
    """
    first = harness.run_once(
        chain_name=BC_DTBU,
        blocks=2,
        transactions_per_block=4,
        payload_bytes=64,
        pbft_policy=POLICY,
        seed=9,
        tag="determinism",
    )
    second = harness.run_once(
        chain_name=BC_DTBU,
        blocks=2,
        transactions_per_block=4,
        payload_bytes=64,
        pbft_policy=POLICY,
        seed=9,
        tag="determinism",
    )
    assert first.transaction_count == second.transaction_count
    assert first.last_block.transaction_count == second.last_block.transaction_count


# --------------------------------------------------------------------------------------------
# Case aggregation — warm-up discard, median
# --------------------------------------------------------------------------------------------
@pytest.mark.slow
def test_run_case_discards_warmup_and_reports_every_kept_repeat() -> None:
    result = harness.run_case(
        case="case_test",
        chain_name=BC_DTBU,
        blocks=2,
        transactions_per_block=4,
        payload_bytes=64,
        pbft_policy=POLICY,
        base_seed=100,
        repeats=3,
        warmup_runs=1,
    )
    assert len(result.totals_seconds) == 3
    assert len(result.marginal_seconds) == 2
    assert result.median_total_seconds == pytest.approx(sorted(result.totals_seconds)[1])
    assert result.transaction_count == 8
    assert result.tps == pytest.approx(8 / result.median_total_seconds)
    assert result.index_seconds is not None


# --------------------------------------------------------------------------------------------
# D3 and Q2 helpers
# --------------------------------------------------------------------------------------------
@pytest.mark.slow
def test_estimate_d3_seconds_scales_linearly_with_blocks() -> None:
    measurement = harness.run_once(
        chain_name=BC_DTBU,
        blocks=2,
        transactions_per_block=5,
        payload_bytes=256,
        pbft_policy=POLICY,
        seed=3,
        tag="d3",
    )
    per_block = harness.estimate_block_encode_seconds(measurement.last_block, repeats=5)
    assert per_block > 0.0
    assert harness.estimate_d3_seconds(per_block, 15) == pytest.approx(per_block * 15)


@pytest.mark.slow
def test_estimate_overhead_factor_is_at_least_one() -> None:
    measurement = harness.run_once(
        chain_name=BC_DTBU,
        blocks=1,
        transactions_per_block=5,
        payload_bytes=256,
        pbft_policy=POLICY,
        seed=4,
        tag="overhead",
    )
    factor = harness.estimate_overhead_factor(256, measurement, transactions_per_block=5)
    assert factor >= 1.0


def test_projected_chain_bytes_scales_with_every_factor() -> None:
    baseline = harness.projected_chain_bytes(
        payload_bytes=4096, transactions_per_block=100, blocks=15, overhead_factor=1.1
    )
    assert baseline == int(4096 * 100 * 15 * 1.1)
    doubled_payload = harness.projected_chain_bytes(
        payload_bytes=8192, transactions_per_block=100, blocks=15, overhead_factor=1.1
    )
    assert doubled_payload == 2 * baseline


# --------------------------------------------------------------------------------------------
# Policy loading
# --------------------------------------------------------------------------------------------
def test_bench_policy_loads_from_the_real_configs() -> None:
    bench_config = load_config("configs/bench.yaml", expected_kind="bench")
    chain_config = load_config("configs/chain.yaml", expected_kind="chain")
    policy = harness.BenchPolicy.from_config(bench_config, chain_config)

    assert policy.cases == ("case_1", "case_2", "case_3")
    assert policy.case_blocks == {"case_1": 5, "case_2": 10, "case_3": 15}
    assert policy.chains == (BC_DTBU, BC_SigRW)
    assert policy.transactions_per_block == 100
    assert policy.repeats >= 5
    assert policy.payload_bytes == 4096
    assert policy.payload_bytes_sensitivity == (1024, 4096, 16384)
    assert policy.modelled_delay_s > 0.0
