"""Alg. 4, lines 5-7: the three mitigation branches, each a transition out of `Remediating`.

**Case-1** (line 5, DEV-04) — quarantine + integrity verification. The paper says "erase `RW`"
and never says what that means (GAP-4). There is nothing real to erase: the honeypot corpus is
synthetic feature vectors and digests (CLAUDE.md §2), not executable samples, so a removal routine
here would have nothing to act on but would look like it does something. `case1_quarantine` is a
pure state transition instead — the quarantine already happened at isolation (Alg. 4 line 3); this
records whether the isolated system's integrity check passed.

**Case-2** (line 6) — format + restore, calling Phase 5. `mitigation/` may not import `framework/`
(`docs/ARCHITECTURE.md`, `PROJECT_STATE.md`), so `case2_restore` takes a zero-argument `restore`
callable. `framework.phase4_mitigation` binds it to `framework.phase5_recovery.run` (plus whatever
closure state that needs — the system, the chain, the key holder). This is the same dependency
direction `recovery/restore.py` already uses for `Decryptor` and `Channel`.

**Case-3** (line 7, DEV-09) — SIMULATED ONLY, per CLAUDE.md §2. `case3_simulated_payment` evaluates
`mitigation.policy.evaluate()`, writes exactly one audit log record, and returns `PolicyBlocked` —
never a "paid" state, because `mitigation.state` has no such state to return regardless of what the
policy decision says. `tests/unit/test_case3_is_inert.py` asserts this at the AST level (no
network/subprocess/socket import anywhere in this module) and by calling the function and checking
its only observable effect is the one log record, so "simulated" is enforced by a test that would
fail on a real payment path, not by this docstring.
"""

from __future__ import annotations

from collections.abc import Callable

from bsfr_sh.mitigation.policy import evaluate
from bsfr_sh.mitigation.state import Cleaned, PolicyBlocked, Remediating, Restored
from bsfr_sh.util.logging import event, get_logger

__all__ = [
    "Restorer",
    "case1_quarantine",
    "case2_restore",
    "case3_simulated_payment",
]

_LOG = get_logger("mitigation.cases")

#: What `framework.phase4_mitigation` binds Case-2's restore to. Opaque return value — see
#: `Remediating.restore()`.
Restorer = Callable[[], object]


def case1_quarantine(
    remediating: Remediating, *, integrity_verified: bool, resolved_at: float
) -> Cleaned:
    """Case-1 (Alg. 4 line 5, DEV-04): quarantine + integrity verification only."""
    cleaned = remediating.clean(integrity_verified=integrity_verified, resolved_at=resolved_at)
    event(
        _LOG,
        "mitigation_case1_quarantined",
        system_id=remediating.infected.system_id,
        integrity_verified=integrity_verified,
    )
    return cleaned


def case2_restore(remediating: Remediating, *, restore: Restorer, resolved_at: float) -> Restored:
    """Case-2 (Alg. 4 line 6): format + restore via Phase 5.

    `restore` is invoked exactly once. Any failure it raises propagates — a failed restore is not
    silently swallowed into a false `Restored` (lines 8-10's "else re-run mitigation" is the
    caller's job, the same idiom `recovery.restore` already uses: every failure raises, none
    returns data).
    """
    detail = restore()
    restored = remediating.restore(detail=detail, resolved_at=resolved_at)
    event(_LOG, "mitigation_case2_restored", system_id=remediating.infected.system_id)
    return restored


def case3_simulated_payment(
    remediating: Remediating, *, ransom_amount: float, data_value: float, resolved_at: float
) -> PolicyBlocked:
    """Case-3 (Alg. 4 line 7, DEV-09, CLAUDE.md §2): SIMULATED ONLY.

    Evaluates the paper's condition, writes one audit log record, and always terminates in
    `PolicyBlocked` — the comparison's outcome is recorded, never enacted. No network call, no
    wallet, no transaction, no key retrieval: the only side effect below is the `event()` call.
    """
    decision = evaluate(ransom_amount=ransom_amount, data_value=data_value, decided_at=resolved_at)
    event(
        _LOG,
        "mitigation_case3_policy_decision",
        system_id=remediating.infected.system_id,
        ransom_amount=decision.ransom_amount,
        data_value=decision.data_value,
        would_pay=decision.would_pay,
    )
    return remediating.block(decision=decision, resolved_at=resolved_at)
