"""Byzantine replicas — silent, equivocating, wrong-signature, stale-view — at f=1 and f=2.

The two directions, per the M2b brief:

* **f = 1 (within tolerance): the chain still commits**, every honest replica agrees, and each
  behaviour is stopped by the specific check meant to stop it.
* **f = 2 (beyond tolerance): the chain fails to commit rather than committing something wrong.**
  This is the more important direction — safety under excess faults, not liveness.

One qualification, pinned by the last test in this file rather than left as a footnote: pBFT's
safety guarantee is *exactly* `f`. Two byzantine replicas that **coordinate** — one equivocating
as primary, the other voting for each honest replica's block — can make two honest replicas
commit different blocks at n=4. That is not a bug in this implementation; it is what
`n >= 3f+1` means, and it is the precise boundary of the §V-3 claim. The four behaviours below
act independently, and against those, f=2 costs liveness and nothing else.
"""

from __future__ import annotations

import pytest
from pbft_harness import (
    BEHAVIOURS,
    HORIZON_S,
    Colluding,
    Collusion,
    Equivocating,
    StaleView,
    WrongSignature,
    assert_no_fork,
    honest,
    make_cluster,
    run_for,
    submit_block,
)

from bsfr_sh.consensus.network import LinkFaults
from bsfr_sh.consensus.protocol import RejectReason

#: The view-0 primary, and a backup that is never primary in the first three views.
POSITIONS = {"primary": "CS_0", "backup": "CS_3"}
#: f=2: the primaries of views 0 and 1, so the first two view changes land on byzantine leaders.
F2 = ("CS_0", "CS_1")

#: The check each behaviour is meant to hit. Silent is stopped by nothing — it sends nothing.
EXPECTED_REJECTION = {
    "equivocating": RejectReason.DIGEST_MISMATCH,
    "wrong_signature": RejectReason.BAD_SIGNATURE,
    "stale_view": RejectReason.WRONG_VIEW,
}


# --------------------------------------------------------------------------------------------
# f = 1 — within tolerance
# --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("position", POSITIONS)
@pytest.mark.parametrize("behaviour", BEHAVIOURS)
def test_f1_the_chain_commits_and_honest_replicas_agree(behaviour: str, position: str) -> None:
    cluster = make_cluster()
    bad = POSITIONS[position]
    cluster.replicas[bad].behaviour = BEHAVIOURS[behaviour]()
    for i in range(3):
        submit_block(cluster, i)
        run_for(cluster)
    rest = honest(cluster, {bad})
    for replica in rest:
        assert replica.height == 3, f"{replica} did not reach height 3 with {behaviour} {bad}"
        replica.chain.verify_integrity()
    assert_no_fork(rest)
    if position == "primary":
        assert all(r.view >= 1 for r in rest), "a faulty primary must be replaced"
    if behaviour in EXPECTED_REJECTION:
        reason = EXPECTED_REJECTION[behaviour]
        assert any(
            rej.reason is reason and rej.sender == bad for r in rest for rej in r.rejections
        ), f"{behaviour} should be caught as {reason.value}"


def test_f1_wrong_signature_never_counts_toward_any_certificate() -> None:
    cluster = make_cluster()
    cluster.replicas["CS_3"].behaviour = WrongSignature()
    submit_block(cluster, 0)
    run_for(cluster)
    for replica in honest(cluster, {"CS_3"}):
        block = replica.chain.head()
        assert "CS_3" not in replica.prepare_voters(0, 1, block.current_hash)
        assert replica.rejected(RejectReason.BAD_SIGNATURE)


def test_f1_stale_view_messages_are_refused_after_the_cluster_has_moved_on() -> None:
    """A node stuck one view behind, in a cluster that has already changed view once.

    The first view change is forced by a *transient* fault (CS_0's link is down, then restored),
    so that afterwards CS_3 is the only faulty replica. A permanently silent CS_0 plus a stale
    CS_3 would be f=2, and the cluster would — correctly — stall.
    """
    cluster = make_cluster()
    timeout = cluster.policy.view_change_timeout_s
    cluster.network.set_faults("CS_0", LinkFaults(drop_rate=1.0))
    cluster.network.schedule(3 * timeout, lambda: cluster.network.clear_faults("CS_0"))
    submit_block(cluster, 0)
    run_for(cluster)  # -> view 1, CS_0 reachable again
    assert all(r.view == 1 and r.height == 1 for r in cluster.replicas.values())
    cluster.replicas["CS_3"].behaviour = StaleView(lag=1)  # now sends view-0 messages
    submit_block(cluster, 1)
    run_for(cluster)
    rest = honest(cluster, {"CS_3"})
    for replica in rest:
        assert replica.height == 2 and replica.view == 1
        stale = [r for r in replica.rejected(RejectReason.WRONG_VIEW) if r.sender == "CS_3"]
        assert stale, "the stale node's view-0 messages must be refused in view 1"
    assert_no_fork(rest)


# --------------------------------------------------------------------------------------------
# f = 2 — beyond tolerance: no commit, and certainly no wrong commit
# --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("behaviour", BEHAVIOURS)
def test_f2_the_chain_fails_to_commit_rather_than_committing_wrongly(behaviour: str) -> None:
    cluster = make_cluster()
    for rid in F2:
        cluster.replicas[rid].behaviour = BEHAVIOURS[behaviour]()
    submit_block(cluster, 0)
    run_for(cluster, 4 * HORIZON_S)
    rest = honest(cluster, F2)
    for replica in rest:
        assert replica.height == 0, f"{replica} committed with only 2 honest replicas of 4"
        assert replica.view >= 1, "honest replicas keep trying — liveness lost, not abandoned"
    assert_no_fork(rest)


# --------------------------------------------------------------------------------------------
# Equivocation — the specific mechanism
# --------------------------------------------------------------------------------------------
def test_two_conflicting_pre_prepares_leave_honest_replicas_unable_to_prepare_either() -> None:
    """The primary sends block A to CS_1 and block B to CS_2 under one (view 0, seq 1), and
    withholds from CS_3. Each honest replica's prepare certificate needs 2f = 2 matching prepares
    from distinct backups; the only backup votes are CS_1 for A and CS_2 for B."""
    cluster = make_cluster()
    equivocator = Equivocating(assignment={"CS_1": [0], "CS_2": [1]})
    cluster.replicas["CS_0"].behaviour = equivocator
    submit_block(cluster, 0)
    cluster.run(until=0.5 * cluster.policy.view_change_timeout_s)  # before any timeout

    cs1, cs2, cs3 = (cluster.replicas[r] for r in ("CS_1", "CS_2", "CS_3"))
    a = cs1.proposal_at(0, 1)
    b = cs2.proposal_at(0, 1)
    assert a is not None and b is not None
    digest_a, digest_b = a.pre_prepare.digest, b.pre_prepare.digest
    assert digest_a != digest_b, "two conflicting pre-prepares under one (view, seq)"
    assert (a.pre_prepare.view, a.pre_prepare.seq) == (b.pre_prepare.view, b.pre_prepare.seq)

    for replica in (cs1, cs2, cs3):
        assert not replica.is_prepared(0, 1, digest_a)
        assert not replica.is_prepared(0, 1, digest_b)
        assert replica.height == 0
    # Why: each holder has only its own prepare for its block; the other's was refused.
    assert cs1.prepare_voters(0, 1, digest_a) == {"CS_1"}
    assert cs2.prepare_voters(0, 1, digest_b) == {"CS_2"}
    assert any(r.sender == "CS_2" for r in cs1.rejected(RejectReason.DIGEST_MISMATCH))
    assert any(r.sender == "CS_1" for r in cs2.rejected(RejectReason.DIGEST_MISMATCH))
    # CS_3 holds no block, so neither vote can count for it.
    assert cs3.proposal_at(0, 1) is None

    # Liveness: the view change replaces the equivocator and a third block commits everywhere.
    run_for(cluster)
    for replica in (cs1, cs2, cs3):
        assert replica.height == 1 and replica.view == 1
        assert replica.chain.head().current_hash not in (digest_a, digest_b)
    assert_no_fork([cs1, cs2, cs3])


def test_a_replica_shown_both_pre_prepares_accepts_the_first_and_refuses_the_second() -> None:
    """CS_3 receives A then B and refuses B. A is then prepared by CS_1 and CS_3 — but the
    equivocator also garbles its commits, so A cannot reach 2f+1 commits in view 0. The view
    change carries A's prepared certificate into view 1, and CS_2, which had been shown B,
    accepts A there: all three honest replicas converge on A."""
    cluster = make_cluster()
    cluster.replicas["CS_0"].behaviour = Equivocating(
        assignment={"CS_1": [0], "CS_2": [1], "CS_3": [0, 1]}
    )
    submit_block(cluster, 0)
    cluster.run(until=0.5 * cluster.policy.view_change_timeout_s)
    cs1, cs2, cs3 = (cluster.replicas[r] for r in ("CS_1", "CS_2", "CS_3"))
    digest_a = cs1.proposal_at(0, 1).pre_prepare.digest  # type: ignore[union-attr]
    assert cs3.rejected(RejectReason.CONFLICTING_PRE_PREPARE)
    assert cs3.proposal_at(0, 1).pre_prepare.digest == digest_a  # type: ignore[union-attr]
    assert cs1.is_prepared(0, 1, digest_a) and cs3.is_prepared(0, 1, digest_a)
    assert all(r.height == 0 for r in (cs1, cs2, cs3))

    run_for(cluster)
    for replica in (cs1, cs2, cs3):
        assert replica.view == 1 and replica.height == 1
        assert replica.chain.head().current_hash == digest_a, "carried over, not replaced"
    assert_no_fork([cs1, cs2, cs3])


def test_equivocation_with_honest_votes_strands_one_honest_replica() -> None:
    """The same split, but the equivocator votes honestly, so A commits in view 0 at CS_1 and
    CS_3. CS_2 holds B, can never prepare, and has no state transfer to fetch A (DEV-20 item 2):
    it stays at height 0. Safe — no fork — but it now counts against f, which is the concrete
    cost DEV-20 records."""
    cluster = make_cluster()
    cluster.replicas["CS_0"].behaviour = Equivocating(
        assignment={"CS_1": [0], "CS_2": [1], "CS_3": [0, 1]}, votes=False
    )
    submit_block(cluster, 0)
    run_for(cluster)
    cs1, cs2, cs3 = (cluster.replicas[r] for r in ("CS_1", "CS_2", "CS_3"))
    assert cs1.height == cs3.height == 1 and cs1.view == 0
    assert cs2.height == 0
    assert_no_fork([cs1, cs2, cs3])


# --------------------------------------------------------------------------------------------
# The boundary of the guarantee
# --------------------------------------------------------------------------------------------
def test_f2_colluding_equivocators_can_fork_honest_replicas_the_bound_is_exactly_f() -> None:
    """Not a property we want — a property pBFT *has*, pinned so nobody reads §V-3 as more.

    CS_0 (primary) sends A to CS_2 and B to CS_3. CS_0 and CS_1 then vote A to CS_2 and B to CS_3.
    Each honest replica sees its own prepare plus CS_1's (2f = 2) and commits from itself, CS_0
    and CS_1 (2f+1 = 3): two honest replicas commit different blocks at height 1. With f=1 this
    is impossible — any two quorums of 3 out of 4 share an honest replica — and the f=1 tests
    above hold. If this test ever fails, the protocol changed, and the §V-3 write-up with it.
    """
    cluster = make_cluster()
    collusion = Collusion(side_b=frozenset({"CS_3"}))
    for rid in F2:
        cluster.replicas[rid].behaviour = Colluding(collusion)
    submit_block(cluster, 0)
    run_for(cluster)
    cs2, cs3 = cluster.replicas["CS_2"], cluster.replicas["CS_3"]
    assert cs2.height == cs3.height == 1
    assert cs2.chain.head().current_hash != cs3.chain.head().current_hash
