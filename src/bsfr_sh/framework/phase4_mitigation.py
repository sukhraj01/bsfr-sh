"""Phase 4: Alg. 4, mitigation of detected ransomware. Output: `SYS_i` `RESOLVED` through exactly
one of Case-1, Case-2 or Case-3.

| Alg. 4 | Step | Here |
|---|---|---|
| 1-2 | `DM_CSl` discovers `RW` in `SYS_i` | the `Detection` Phase 3's `Phase4Handoff` hands off |
| 3 | raise `AMsg`, isolate `SYS_i` | `mitigation.state.Detected.isolate` |
| 4 | remediate `InfSYS_i` via one of three cases | `mitigation.state.Isolated.remediate` |
| 5 | Case-1 | `mitigation.cases.case1_quarantine` |
| 6 | Case-2 | `mitigation.cases.case2_restore`, calling `framework.phase5_recovery.run` |
| 7 | Case-3 | `mitigation.cases.case3_simulated_payment` — SIMULATED ONLY, DEV-09 |
| 8-10 | else re-run mitigation | the caller's job, not a loop in `run()` — see below |

Two gaps this module fills rather than invents a rule for
-----------------------------------------------------------
**Which case applies.** The paper presents Case-1/2/3 as alternatives and never says how one is
chosen for a given detection. `run()` takes an explicit `case: MitigationCase` from its caller
instead of guessing (e.g. from whether a backup exists) — a rule invented here would be exactly
the kind of silent "fix" CLAUDE.md §2 forbids. See `docs/DEVIATIONS.md` DEV-29.

**Attributing a detection to a system.** Alg. 3's `Detection.sample_id` names a honeypot *sample*;
Alg. 4 mitigates a *system*, `SYS_i`. The paper's own Fig. 3 sequence draws an arrow from the
honeypot straight to "detect" with no system in between. `run()` takes `system_id` as an explicit
argument, supplied by the caller — in a real deployment, whichever system's telemetry correlated
with the honeypot's signature match. See `docs/DEVIATIONS.md` DEV-29.

Lines 8-10 are not a retry loop here
-------------------------------------
Case-1 and Case-3 always resolve (there is no "quarantine failed" or "policy undecided" outcome to
retry). Case-2 can fail if its injected `restore` callable raises (e.g. `RecoveryError` from a
genuinely incomplete backup); that exception propagates out of `run()` rather than being caught and
retried here, matching `framework.phase5_recovery`'s own rule: every failure raises, and the
caller — which holds the context needed to decide whether "re-run mitigation" means picking a
different case or trying the same one again — decides what happens next.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass

from bsfr_sh.detection.detector import Detection
from bsfr_sh.mitigation import cases as alg4_cases
from bsfr_sh.mitigation.state import (
    Cleaned,
    Detected,
    InfectedSystem,
    PolicyBlocked,
    Resolved,
    Restored,
)
from bsfr_sh.util.logging import event, get_logger

__all__ = ["MitigationCase", "Phase4Report", "run"]

_LOG = get_logger("framework.phase4")


class MitigationCase(enum.Enum):
    """Which of Alg. 4's three branches to run for one detection. See the module docstring."""

    QUARANTINE = "case1"
    RESTORE = "case2"
    POLICY = "case3"


@dataclass(frozen=True)
class Phase4Report:
    """What one Phase 4 run resolved to."""

    resolved: Resolved

    @property
    def outcome(self) -> str:
        return self.resolved.outcome


def run(
    *,
    detection: Detection,
    system_id: str,
    case: MitigationCase,
    detected_at: float,
    isolated_at: float,
    remediation_started_at: float,
    resolved_at: float,
    format_system: Callable[[], None] | None = None,
    restore: alg4_cases.Restorer | None = None,
    integrity_verified: bool = True,
    ransom_amount: float | None = None,
    data_value: float | None = None,
) -> Phase4Report:
    """Implements Alg. 4, lines 1-10, for one positive `Detection`.

    `format_system`, when given, runs before Case-2's restore — "format the system" (line 6) is a
    `framework`-level operation (`System.wipe`) that `mitigation/` cannot reach directly. Unused by
    Case-1 and Case-3.
    """
    if not detection.is_ransomware:
        raise ValueError("phase4_mitigation.run() called on a non-positive detection")

    infected = InfectedSystem(
        system_id=system_id,
        sample_id=detection.sample_id,
        score=detection.score,
        detected_at=detected_at,
    )
    detected = Detected(infected=infected)
    isolated = detected.isolate(isolated_at=isolated_at)
    event(_LOG, "phase4_isolated", system_id=system_id, sample_id=detection.sample_id)
    remediating = isolated.remediate(started_at=remediation_started_at)

    outcome: Cleaned | Restored | PolicyBlocked
    if case is MitigationCase.QUARANTINE:
        outcome = alg4_cases.case1_quarantine(
            remediating, integrity_verified=integrity_verified, resolved_at=resolved_at
        )
    elif case is MitigationCase.RESTORE:
        if restore is None:
            raise ValueError("case-2 requires restore=... (bound to framework.phase5_recovery.run)")
        if format_system is not None:
            format_system()
        outcome = alg4_cases.case2_restore(remediating, restore=restore, resolved_at=resolved_at)
    else:
        if ransom_amount is None or data_value is None:
            raise ValueError("case-3 requires ransom_amount and data_value")
        outcome = alg4_cases.case3_simulated_payment(
            remediating,
            ransom_amount=ransom_amount,
            data_value=data_value,
            resolved_at=resolved_at,
        )

    resolved = outcome.resolve()
    event(_LOG, "phase4_resolved", system_id=system_id, outcome=resolved.outcome)
    return Phase4Report(resolved=resolved)
