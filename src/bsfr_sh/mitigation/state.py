"""Alg. 4's state machine: `DETECTED -> ISOLATED -> REMEDIATING -> (RESTORED | CLEANED |
POLICY_BLOCKED) -> RESOLVED`.

Illegal transitions are unrepresentable, not checked
-----------------------------------------------------
The same discipline `blockchain.block.BlockDraft.seal()` applies to a block header applies here to
a mitigation record: each state is its own frozen type, and the only way to obtain the next one is
to call the method its predecessor exposes. `Detected` has no `remediate()`; `Isolated` has no
`restore()`, `clean()` or `block()`. There is no `if state != ISOLATED: raise` anywhere in this
module, because there is nothing to check — a `Remediating` object cannot be built without an
`Isolated` one to build it from, and the only `Isolated` in existence came from
`Detected.isolate()`. That is what makes "a system cannot reach `REMEDIATING` without passing
through `ISOLATED`"
structural: Alg. 4's containment argument (isolate first, remediate second) is the type graph, not
a runtime guard on it. (As with `Block`, nothing stops a caller from constructing a later state's
dataclass by hand in Python — see that module's docstring for the same caveat. The type signatures
mean no *code path* through this module can skip a step, which is the property the paper's
containment claim actually needs.)

Each state nests its predecessor (`Isolated.detected`, `Remediating.isolated`, ...) rather than
copying `infected`/`alert` fields forward, so the full history is reachable from any point and
`.infected` is one property lookup away everywhere.

`InfSYS_i` and `AMsg`
---------------------
`InfectedSystem` is `InfSYS_i` (docs/NOTATION.md): what a detection says about one system.
`AlertMessage` is `AMsg`, raised at isolation (Alg. 4 line 3). Both are plain records — there is no
paging system or human notification loop in scope here, only the artifact the paper names.

Line 4: "erase" read as "remediate"
------------------------------------
The paper's line 4 says `InfSYS_i` is "erased" using one of the following cases, but Case-2
restores data and Case-3 (simulated) would decrypt it — neither erases anything, and only Case-1
even gestures at removal. `docs/ALGORITHMS.md` already records this as the paper's own ordering
defect. `Isolated.remediate()` is named for what the three cases actually do, not for what line 4
calls it.
"""

from __future__ import annotations

from dataclasses import dataclass

from bsfr_sh.mitigation.policy import PolicyDecision

__all__ = [
    "AlertMessage",
    "Cleaned",
    "Detected",
    "InfectedSystem",
    "Isolated",
    "PolicyBlocked",
    "Remediating",
    "Resolved",
    "Restored",
]


@dataclass(frozen=True)
class InfectedSystem:
    """`InfSYS_i` — what one detection says about one system. Alg. 4, lines 1-2."""

    system_id: str
    sample_id: str
    score: float
    detected_at: float


@dataclass(frozen=True)
class AlertMessage:
    """`AMsg` — raised at isolation (Alg. 4, line 3)."""

    system_id: str
    sample_id: str
    raised_at: float


@dataclass(frozen=True)
class Detected:
    """`DETECTED`. Alg. 4, lines 1-2: `DM_CSl` discovered `RW` in `SYS_i`.

    The only step from here is `isolate()`.
    """

    infected: InfectedSystem

    def isolate(self, *, isolated_at: float) -> Isolated:
        """Alg. 4, line 3: raise `AMsg` and isolate `SYS_i`."""
        alert = AlertMessage(
            system_id=self.infected.system_id,
            sample_id=self.infected.sample_id,
            raised_at=isolated_at,
        )
        return Isolated(detected=self, alert=alert, isolated_at=isolated_at)


@dataclass(frozen=True)
class Isolated:
    """`ISOLATED`. `SYS_i` is contained and `AMsg` has been raised.

    Reachable only from `Detected.isolate()`.
    """

    detected: Detected
    alert: AlertMessage
    isolated_at: float

    @property
    def infected(self) -> InfectedSystem:
        return self.detected.infected

    def remediate(self, *, started_at: float) -> Remediating:
        """Alg. 4, line 4, read as *remediate* rather than *erase* — see the module docstring."""
        return Remediating(isolated=self, started_at=started_at)


@dataclass(frozen=True)
class Remediating:
    """`REMEDIATING`. Reachable only from `Isolated.remediate()`.

    Exactly one of `clean()`, `restore()` or `block()` ends this state — Case-1, Case-2 and Case-3
    respectively (`mitigation.cases`). None of them is reachable except from here.
    """

    isolated: Isolated
    started_at: float

    @property
    def infected(self) -> InfectedSystem:
        return self.isolated.infected

    def clean(self, *, integrity_verified: bool, resolved_at: float) -> Cleaned:
        """Case-1 (Alg. 4 line 5, DEV-04): quarantine + integrity verification."""
        return Cleaned(
            remediating=self, integrity_verified=integrity_verified, resolved_at=resolved_at
        )

    def restore(self, *, detail: object, resolved_at: float) -> Restored:
        """Case-2 (Alg. 4 line 6): format + restore via Phase 5.

        `detail` is whatever the restore call produced (e.g. `framework.phase5_recovery
        .RecoveryReport`) — opaque here, since `mitigation` may not import `framework`.
        """
        return Restored(remediating=self, detail=detail, resolved_at=resolved_at)

    def block(self, *, decision: PolicyDecision, resolved_at: float) -> PolicyBlocked:
        """Case-3 (Alg. 4 line 7): SIMULATED ONLY (DEV-09, CLAUDE.md §2). Always terminal here —
        there is no state in this module representing a completed payment, regardless of
        `decision.would_pay`.
        """
        return PolicyBlocked(remediating=self, decision=decision, resolved_at=resolved_at)


@dataclass(frozen=True)
class Cleaned:
    """`CLEANED`. Case-1's outcome. Reachable only from `Remediating.clean()`."""

    remediating: Remediating
    integrity_verified: bool
    resolved_at: float

    @property
    def infected(self) -> InfectedSystem:
        return self.remediating.infected

    def resolve(self) -> Resolved:
        return Resolved(outcome_state=self, outcome="CLEANED", resolved_at=self.resolved_at)


@dataclass(frozen=True)
class Restored:
    """`RESTORED`. Case-2's outcome. Reachable only from `Remediating.restore()`."""

    remediating: Remediating
    detail: object
    resolved_at: float

    @property
    def infected(self) -> InfectedSystem:
        return self.remediating.infected

    def resolve(self) -> Resolved:
        return Resolved(outcome_state=self, outcome="RESTORED", resolved_at=self.resolved_at)


@dataclass(frozen=True)
class PolicyBlocked:
    """`POLICY_BLOCKED`. Case-3's outcome, always — see `Remediating.block()`."""

    remediating: Remediating
    decision: PolicyDecision
    resolved_at: float

    @property
    def infected(self) -> InfectedSystem:
        return self.remediating.infected

    def resolve(self) -> Resolved:
        return Resolved(outcome_state=self, outcome="POLICY_BLOCKED", resolved_at=self.resolved_at)


@dataclass(frozen=True)
class Resolved:
    """`RESOLVED`. Terminal: no method here produces another state.

    `outcome_state` keeps the whole history reachable (`resolved.outcome_state.remediating
    .isolated.detected.infected`, etc.) rather than flattening it away at the last step.
    """

    outcome_state: Cleaned | Restored | PolicyBlocked
    outcome: str
    resolved_at: float

    @property
    def infected(self) -> InfectedSystem:
        return self.outcome_state.infected
