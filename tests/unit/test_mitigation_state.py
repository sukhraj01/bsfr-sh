"""Alg. 4's state machine: every transition, legal and illegal.

"Illegal" here means "there is no method to call" rather than "a check rejects it" — see
`mitigation/state.py`'s module docstring. So the illegal-transition tests below assert
`AttributeError` on the missing method, which is what "unrepresentable rather than checked" means
operationally: there is no `MitigationError` to catch, because there is no code path to take.
"""

from __future__ import annotations

import pytest

from bsfr_sh.mitigation.policy import evaluate
from bsfr_sh.mitigation.state import (
    Cleaned,
    Detected,
    InfectedSystem,
    Isolated,
    PolicyBlocked,
    Remediating,
    Resolved,
    Restored,
)

INFECTED = InfectedSystem(system_id="SYS_1", sample_id="sample-7", score=0.93, detected_at=10.0)


def _detected() -> Detected:
    return Detected(infected=INFECTED)


def _isolated() -> Isolated:
    return _detected().isolate(isolated_at=11.0)


def _remediating() -> Remediating:
    return _isolated().remediate(started_at=12.0)


# --------------------------------------------------------------------------------------------
# Legal transitions
# --------------------------------------------------------------------------------------------
def test_detected_isolates_and_raises_amsg() -> None:
    isolated = _detected().isolate(isolated_at=11.0)
    assert isolated.isolated_at == 11.0
    assert isolated.alert.system_id == "SYS_1"
    assert isolated.alert.sample_id == "sample-7"
    assert isolated.alert.raised_at == 11.0
    assert isolated.infected == INFECTED


def test_isolated_remediates() -> None:
    remediating = _isolated().remediate(started_at=12.0)
    assert remediating.started_at == 12.0
    assert remediating.infected == INFECTED


def test_remediating_clean_produces_cleaned_case1() -> None:
    cleaned = _remediating().clean(integrity_verified=True, resolved_at=13.0)
    assert isinstance(cleaned, Cleaned)
    assert cleaned.integrity_verified is True
    resolved = cleaned.resolve()
    assert resolved.outcome == "CLEANED"
    assert resolved.infected == INFECTED


def test_remediating_restore_produces_restored_case2() -> None:
    restored = _remediating().restore(detail={"backup_id": "b1"}, resolved_at=14.0)
    assert isinstance(restored, Restored)
    assert restored.detail == {"backup_id": "b1"}
    resolved = restored.resolve()
    assert resolved.outcome == "RESTORED"


def test_remediating_block_produces_policy_blocked_case3() -> None:
    decision = evaluate(ransom_amount=1.0, data_value=2.0, decided_at=15.0)
    blocked = _remediating().block(decision=decision, resolved_at=15.0)
    assert isinstance(blocked, PolicyBlocked)
    assert blocked.decision.would_pay is True
    resolved = blocked.resolve()
    assert resolved.outcome == "POLICY_BLOCKED"


def test_full_history_is_reachable_from_resolved() -> None:
    """`Resolved` nests the whole chain rather than flattening it away."""
    remediating = _remediating()
    resolved = remediating.clean(integrity_verified=False, resolved_at=20.0).resolve()
    assert resolved.outcome_state.remediating is remediating
    assert resolved.outcome_state.remediating.isolated.detected.infected == INFECTED


# --------------------------------------------------------------------------------------------
# Illegal transitions: the method does not exist
# --------------------------------------------------------------------------------------------
def test_detected_cannot_skip_isolation() -> None:
    detected = _detected()
    for skipped in ("remediate", "clean", "restore", "block", "resolve"):
        assert not hasattr(detected, skipped), f"Detected exposes {skipped}()"


def test_isolated_cannot_skip_remediation() -> None:
    isolated = _isolated()
    for skipped in ("clean", "restore", "block", "resolve", "isolate"):
        assert not hasattr(isolated, skipped), f"Isolated exposes {skipped}()"


def test_remediating_cannot_resolve_directly_or_re_isolate() -> None:
    remediating = _remediating()
    for skipped in ("resolve", "isolate", "remediate"):
        assert not hasattr(remediating, skipped), f"Remediating exposes {skipped}()"


@pytest.mark.parametrize(
    "make_outcome",
    [
        lambda r: r.clean(integrity_verified=True, resolved_at=1.0),
        lambda r: r.restore(detail=None, resolved_at=1.0),
        lambda r: r.block(
            decision=evaluate(ransom_amount=1.0, data_value=1.0, decided_at=1.0), resolved_at=1.0
        ),
    ],
    ids=["cleaned", "restored", "policy_blocked"],
)
def test_terminal_outcomes_can_only_resolve(make_outcome) -> None:
    outcome = make_outcome(_remediating())
    for skipped in ("isolate", "remediate", "clean", "restore", "block"):
        assert not hasattr(outcome, skipped), f"{type(outcome).__name__} exposes {skipped}()"
    assert hasattr(outcome, "resolve")


def test_resolved_is_terminal() -> None:
    resolved: Resolved = _remediating().clean(integrity_verified=True, resolved_at=1.0).resolve()
    for skipped in ("isolate", "remediate", "clean", "restore", "block", "resolve"):
        assert not hasattr(resolved, skipped), f"Resolved exposes {skipped}()"


def test_remediating_requires_an_isolated_produced_by_detected_isolate() -> None:
    """The structural version of "cannot reach REMEDIATING without passing through ISOLATED".

    `Remediating` requires an `Isolated`; the only function in this module that produces one is
    `Detected.isolate()`. There is no second constructor path to check against here — that
    absence *is* the property.
    """
    remediating = _remediating()
    assert isinstance(remediating.isolated, Isolated)
    assert remediating.isolated.detected.infected == INFECTED
