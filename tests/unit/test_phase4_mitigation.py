"""`framework.phase4_mitigation`: Alg. 4 lines 1-10, wired to the state machine and cases.

Case-2 here restores through a direct-append `BC_DTBU` chain (fast, no consensus) — this file is
about Phase 4's own wiring, not consensus fidelity. `tests/integration/test_full_sequence.py` runs
the same wiring, and every phase before it, through real pBFT consensus on both chains.
"""

from __future__ import annotations

import pytest
from m3a_harness import back_up_directly, dtbu_chain, make_server, make_system

from bsfr_sh.detection.detector import Detection
from bsfr_sh.framework import phase4_mitigation as phase4
from bsfr_sh.framework import phase5_recovery as phase5

POSITIVE = Detection(
    sample_id="sample-1",
    is_ransomware=True,
    score=0.95,
    normal_membership=0.1,
    abnormal_membership=0.9,
)
NEGATIVE = Detection(
    sample_id="sample-2",
    is_ransomware=False,
    score=0.05,
    normal_membership=0.9,
    abnormal_membership=0.1,
)
TIMES = {
    "detected_at": 1.0,
    "isolated_at": 2.0,
    "remediation_started_at": 3.0,
    "resolved_at": 4.0,
}


def test_run_rejects_a_non_positive_detection() -> None:
    with pytest.raises(ValueError, match="non-positive"):
        phase4.run(
            detection=NEGATIVE,
            system_id="SYS_1",
            case=phase4.MitigationCase.QUARANTINE,
            **TIMES,
        )


def test_case1_quarantine_end_to_end() -> None:
    report = phase4.run(
        detection=POSITIVE,
        system_id="SYS_1",
        case=phase4.MitigationCase.QUARANTINE,
        integrity_verified=True,
        **TIMES,
    )
    assert report.outcome == "CLEANED"
    assert report.resolved.infected.system_id == "SYS_1"


def test_case3_policy_end_to_end() -> None:
    report = phase4.run(
        detection=POSITIVE,
        system_id="SYS_1",
        case=phase4.MitigationCase.POLICY,
        ransom_amount=10.0,
        data_value=1.0,
        **TIMES,
    )
    assert report.outcome == "POLICY_BLOCKED"


def test_case2_requires_a_restore_callable() -> None:
    with pytest.raises(ValueError, match="restore"):
        phase4.run(
            detection=POSITIVE, system_id="SYS_1", case=phase4.MitigationCase.RESTORE, **TIMES
        )


def test_case3_requires_both_amounts() -> None:
    with pytest.raises(ValueError, match="ransom_amount"):
        phase4.run(
            detection=POSITIVE, system_id="SYS_1", case=phase4.MitigationCase.POLICY, **TIMES
        )


def test_case2_formats_then_restores_byte_identical_through_phase5() -> None:
    key_holder, front = make_server(10), make_server(11)
    system = make_system(9, 500)
    chain = dtbu_chain()
    back_up_directly(chain, [system], key_holder)
    original = system.data

    format_calls: list[int] = []

    def format_system() -> None:
        format_calls.append(1)
        system.wipe()

    report = phase4.run(
        detection=POSITIVE,
        system_id=system.identity,
        case=phase4.MitigationCase.RESTORE,
        format_system=format_system,
        restore=lambda: phase5.run(system=system, front=front, key_holder=key_holder, chain=chain),
        **TIMES,
    )
    assert format_calls == [1], "format_system must run before restore, exactly once"
    assert system.data == original
    assert report.outcome == "RESTORED"
    assert report.resolved.outcome_state.detail.system_id == system.identity  # RecoveryReport
