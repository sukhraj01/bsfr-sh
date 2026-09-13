"""CLAUDE.md §2 / DEV-09, enforced at import and call level: Case-3 is simulated only, forever.

The companion of `tests/unit/test_honeypot_is_inert.py`. A `mitigation` module that grew a
`socket`, a `subprocess`, or a second observable effect beyond its one audit log record would be
a payment path — exactly the thing CLAUDE.md §2 forbids — and that change would be easy to make by
accident while "making Case-3 more realistic". A comment saying "simulated" is not an enforcement
mechanism; this file is.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest

from bsfr_sh.mitigation.cases import case3_simulated_payment
from bsfr_sh.mitigation.state import Detected, InfectedSystem, PolicyBlocked
from bsfr_sh.util.logging import get_logger

MITIGATION = Path(__file__).resolve().parents[2] / "src" / "bsfr_sh" / "mitigation"
MODULES = sorted(MITIGATION.glob("*.py"))

#: Anything that could reach a network, a wallet, or another process.
FORBIDDEN_IMPORTS = {
    "socket",
    "subprocess",
    "urllib",
    "http",
    "requests",
    "ftplib",
    "smtplib",
    "asyncio",
    "multiprocessing",
    "ctypes",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "system", "popen", "spawn", "connect"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _remediating():
    infected = InfectedSystem(system_id="SYS_1", sample_id="sample-1", score=0.9, detected_at=100.0)
    isolated = Detected(infected=infected).isolate(isolated_at=101.0)
    return isolated.remediate(started_at=102.0)


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_no_module_in_mitigation_can_reach_a_network_wallet_or_subprocess(path: Path) -> None:
    tree = _tree(path)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & FORBIDDEN_IMPORTS, (
        f"{path.name} imports {sorted(imported & FORBIDDEN_IMPORTS)}"
    )

    called = {
        node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    assert not called & FORBIDDEN_CALLS, f"{path.name} calls {sorted(called & FORBIDDEN_CALLS)}"


def test_case3_has_no_effect_beyond_one_audit_log_record() -> None:
    """The function's only observable side effect is the single `event()` call in its body."""
    logger = get_logger("mitigation.cases")
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append  # type: ignore[method-assign]
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        blocked = case3_simulated_payment(
            _remediating(), ransom_amount=100.0, data_value=500.0, resolved_at=200.0
        )
    finally:
        logger.removeHandler(handler)

    assert len(records) == 1
    assert records[0].getMessage() == "mitigation_case3_policy_decision"
    assert isinstance(blocked, PolicyBlocked)


def test_case3_always_terminates_in_policy_blocked_regardless_of_the_decision() -> None:
    """Even when the paper's own condition says "pay", nothing here produces a payment.

    `mitigation.state` has no state representing a completed or attempted payment — `would_pay`
    is data on the returned `PolicyDecision`, never a branch to a different outcome type.
    """
    cheap_ransom = case3_simulated_payment(
        _remediating(), ransom_amount=1.0, data_value=1_000_000.0, resolved_at=0.0
    )
    expensive_ransom = case3_simulated_payment(
        _remediating(), ransom_amount=1_000_000.0, data_value=1.0, resolved_at=0.0
    )
    assert cheap_ransom.decision.would_pay is True
    assert expensive_ransom.decision.would_pay is False
    assert type(cheap_ransom) is type(expensive_ransom) is PolicyBlocked
    assert cheap_ransom.resolve().outcome == expensive_ransom.resolve().outcome == "POLICY_BLOCKED"


def test_case3_is_a_pure_function_of_its_inputs() -> None:
    """Same inputs, same decision — nothing here reads clock, environment or network state."""
    first = case3_simulated_payment(
        _remediating(), ransom_amount=42.0, data_value=100.0, resolved_at=7.0
    )
    second = case3_simulated_payment(
        _remediating(), ransom_amount=42.0, data_value=100.0, resolved_at=7.0
    )
    assert first.decision == second.decision
