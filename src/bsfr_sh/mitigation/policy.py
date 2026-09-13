"""`RW_amt` vs `DT-SYS_i-amt` — Alg. 4 line 7's payment condition. Evaluated, never acted on.

The paper undercuts its own branch before it reaches Alg. 4
------------------------------------------------------------
Alg. 4 line 7 says: if `RW_amt < DT-SYS_i-amt`, pay the ransom and obtain `K_d`. But §II-C, four
sections earlier, already concedes there is **no guarantee the decryption key arrives, or that it
works** if it does. Line 7 is an automated action built on a premise the paper's own text disputes:
an amount comparison cannot price a probability of nothing being delivered. `evaluate()` below
still computes the comparison faithfully — the arithmetic is not what is wrong with line 7 — but
`would_pay` is data about what the paper's condition would decide, not a recommendation this
project acts on. `mitigation.cases.case3_simulated_payment` reads `would_pay`, writes it to an
audit log, and terminates in `POLICY_BLOCKED` regardless of its value (DEV-09, CLAUDE.md §2).

The `<` boundary
----------------
`RW_amt == DT-SYS_i-amt` resolves to `would_pay = False`. Paying exactly what the data is assessed
to be worth is not a saving — it is a wash before counting the cost of §II-C's undelivered-key
risk, the operational cost of arranging payment, and the incentive effect of paying at all. Strict
inequality is what makes "cheaper than the data" the actual condition rather than "no more
expensive than the data": the paper writes `<`, and this keeps the tie on the side the sign says.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["PolicyDecision", "evaluate"]


@dataclass(frozen=True)
class PolicyDecision:
    """Alg. 4 line 7's condition, evaluated and recorded.

    `would_pay` is what the paper's condition alone would decide. It is never turned into a
    payment by anything in this codebase — see the module docstring and DEV-09.
    """

    ransom_amount: float
    data_value: float
    would_pay: bool
    decided_at: float

    def as_dict(self) -> dict[str, object]:
        return {
            "ransom_amount": self.ransom_amount,
            "data_value": self.data_value,
            "would_pay": self.would_pay,
            "decided_at": self.decided_at,
        }


def evaluate(*, ransom_amount: float, data_value: float, decided_at: float) -> PolicyDecision:
    """Implements Alg. 4 line 7's condition: `RW_amt < DT-SYS_i-amt`. A pure function of its inputs.

    Raises on a negative amount rather than silently comparing nonsense — an amount is a fact
    about the world (a demand, an assessment), and a negative one means the caller has a bug, not
    that this function should have an opinion about negative money.
    """
    if ransom_amount < 0:
        raise ValueError(f"ransom_amount must be non-negative, got {ransom_amount!r}")
    if data_value < 0:
        raise ValueError(f"data_value must be non-negative, got {data_value!r}")
    return PolicyDecision(
        ransom_amount=ransom_amount,
        data_value=data_value,
        would_pay=ransom_amount < data_value,
        decided_at=decided_at,
    )
