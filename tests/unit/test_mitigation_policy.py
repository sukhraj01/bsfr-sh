"""Alg. 4 line 7's condition: `RW_amt < DT-SYS_i-amt`. Evaluated, never acted on (DEV-09)."""

from __future__ import annotations

import pytest

from bsfr_sh.mitigation.policy import PolicyDecision, evaluate


def test_ransom_cheaper_than_the_data_would_pay() -> None:
    decision = evaluate(ransom_amount=100.0, data_value=200.0, decided_at=1.0)
    assert decision.would_pay is True


def test_ransom_more_expensive_than_the_data_would_not_pay() -> None:
    decision = evaluate(ransom_amount=300.0, data_value=200.0, decided_at=1.0)
    assert decision.would_pay is False


def test_the_equal_boundary_resolves_to_would_not_pay() -> None:
    """Deliberate, per the module docstring: `<` is strict, so a tie is not "cheaper than"."""
    decision = evaluate(ransom_amount=150.0, data_value=150.0, decided_at=1.0)
    assert decision.would_pay is False


def test_zero_ransom_against_any_positive_data_value_would_pay() -> None:
    decision = evaluate(ransom_amount=0.0, data_value=0.01, decided_at=1.0)
    assert decision.would_pay is True


def test_zero_ransom_against_zero_data_value_is_the_boundary_too() -> None:
    decision = evaluate(ransom_amount=0.0, data_value=0.0, decided_at=1.0)
    assert decision.would_pay is False


@pytest.mark.parametrize("bad_ransom,bad_value", [(-1.0, 10.0), (10.0, -1.0), (-1.0, -1.0)])
def test_negative_amounts_are_rejected(bad_ransom: float, bad_value: float) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        evaluate(ransom_amount=bad_ransom, data_value=bad_value, decided_at=1.0)


def test_decision_carries_its_inputs_and_timestamp_for_the_audit_record() -> None:
    decision = evaluate(ransom_amount=5.0, data_value=9.0, decided_at=42.0)
    assert decision == PolicyDecision(
        ransom_amount=5.0, data_value=9.0, would_pay=True, decided_at=42.0
    )
    assert decision.as_dict() == {
        "ransom_amount": 5.0,
        "data_value": 9.0,
        "would_pay": True,
        "decided_at": 42.0,
    }
