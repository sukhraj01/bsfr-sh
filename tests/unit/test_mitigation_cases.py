"""`mitigation.cases`: the three Alg. 4 branches, exercised directly against `Remediating`.

Case-2's actual byte-identical restore through Phase 5 is covered at the framework level
(`tests/unit/test_phase4_mitigation.py`, `tests/integration/test_full_sequence.py`) — here it is
exercised with a fake `restore` callable, since `cases.py` itself never knows what `restore`
touches (that is the point of the injected-callable boundary, `docs/ARCHITECTURE.md`).
Case-3's inertness has its own dedicated file, `test_case3_is_inert.py`.
"""

from __future__ import annotations

import pytest

from bsfr_sh.mitigation.cases import case1_quarantine, case2_restore, case3_simulated_payment
from bsfr_sh.mitigation.state import Cleaned, Detected, InfectedSystem, PolicyBlocked, Restored

INFECTED = InfectedSystem(system_id="SYS_1", sample_id="sample-1", score=0.8, detected_at=1.0)


def _remediating():
    return Detected(infected=INFECTED).isolate(isolated_at=2.0).remediate(started_at=3.0)


def test_case1_quarantine_records_the_integrity_check_and_reaches_cleaned() -> None:
    cleaned = case1_quarantine(_remediating(), integrity_verified=True, resolved_at=4.0)
    assert isinstance(cleaned, Cleaned)
    assert cleaned.integrity_verified is True
    assert cleaned.resolve().outcome == "CLEANED"


def test_case1_quarantine_records_a_failed_integrity_check_too() -> None:
    """Recorded, not hidden: a caller deciding to re-run mitigation needs to see this."""
    cleaned = case1_quarantine(_remediating(), integrity_verified=False, resolved_at=4.0)
    assert cleaned.integrity_verified is False


def test_case2_restore_calls_the_injected_restorer_exactly_once() -> None:
    calls: list[int] = []

    def restore() -> dict[str, str]:
        calls.append(1)
        return {"backup_id": "b1"}

    restored = case2_restore(_remediating(), restore=restore, resolved_at=5.0)
    assert isinstance(restored, Restored)
    assert calls == [1]
    assert restored.detail == {"backup_id": "b1"}
    assert restored.resolve().outcome == "RESTORED"


def test_case2_restore_propagates_a_failing_restorer_rather_than_swallowing_it() -> None:
    class RestoreError(RuntimeError):
        pass

    def restore():
        raise RestoreError("no complete backup")

    with pytest.raises(RestoreError):
        case2_restore(_remediating(), restore=restore, resolved_at=5.0)


def test_case3_evaluates_the_policy_and_reaches_policy_blocked() -> None:
    blocked = case3_simulated_payment(
        _remediating(), ransom_amount=10.0, data_value=20.0, resolved_at=6.0
    )
    assert isinstance(blocked, PolicyBlocked)
    assert blocked.decision.would_pay is True
    assert blocked.resolve().outcome == "POLICY_BLOCKED"
