"""`consensus.view_change` — leader timeout, view change, prepared-certificate carry-over (DEV-20).

§V-3's resistance claim needs liveness: a leader that goes quiet must not stall the chain. These
tests show it does not, and that moving to a new view never loses a block that was prepared.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence

from pbft_harness import (
    POLICY,
    Compose,
    DropCommitsInView,
    Silent,
    assert_no_fork,
    honest,
    key_of,
    make_cluster,
    run_for,
    submit_block,
)

from bsfr_sh.consensus.network import LinkFaults
from bsfr_sh.consensus.pbft import Cluster, Replica
from bsfr_sh.consensus.protocol import (
    Message,
    NewView,
    PreparedCertificate,
    RejectReason,
    resign,
)
from bsfr_sh.consensus.view_change import (
    build_new_view,
    build_view_change,
    select_reproposal,
    verify_new_view,
    verify_view_change,
)

TIMEOUT = POLICY.view_change_timeout_s


def _prepared_but_uncommitted() -> tuple[Cluster, bytes]:
    """Every replica prepares block A in view 0, and every view-0 commit is lost."""
    cluster = make_cluster()
    for replica in cluster.replicas.values():
        replica.behaviour = DropCommitsInView(0)
    submit_block(cluster, 0)
    cluster.run(until=TIMEOUT / 2)
    digest = cluster.replicas["CS_0"].proposal_at(0, 1).pre_prepare.digest  # type: ignore[union-attr]
    for replica in cluster.replicas.values():
        assert replica.is_prepared(0, 1, digest)
        assert replica.height == 0
    return cluster, digest


# --------------------------------------------------------------------------------------------
# Liveness
# --------------------------------------------------------------------------------------------
def test_a_silent_leader_triggers_a_view_change_and_the_chain_continues() -> None:
    cluster = make_cluster()
    cluster.replicas["CS_0"].behaviour = Silent()
    submit_block(cluster, 0)
    run_for(cluster)
    rest = honest(cluster, {"CS_0"})
    for replica in rest:
        assert replica.view == 1 and replica.active
        assert replica.height == 1
        assert replica.chain.head().owner_id == "CS_1"  # the view-1 primary proposed it
    # ...and keeps going, in the same view, with the old leader still silent.
    for i in range(1, 4):
        submit_block(cluster, i)
        run_for(cluster)
    for replica in rest:
        assert replica.height == 4 and replica.view == 1
        replica.chain.verify_integrity()
    assert_no_fork(rest)


def test_the_view_change_happens_at_the_configured_timeout() -> None:
    cluster = make_cluster()
    cluster.replicas["CS_0"].behaviour = Silent()
    submit_block(cluster, 0)
    cluster.run(until=TIMEOUT * 0.99)
    assert all(r.view == 0 for r in cluster.replicas.values())
    cluster.run(until=TIMEOUT * 1.01)
    assert all(r.height == 1 for r in honest(cluster, {"CS_0"}))


def test_a_stalled_view_change_escalates_to_the_next_view() -> None:
    """CS_0's link is down until t=1 (it misses its own proposal); CS_1, primary of view 1, is
    silent. View 1 never gets a new-view, so the cluster escalates to view 2 and commits there."""
    cluster = make_cluster()
    cluster.network.set_faults("CS_0", LinkFaults(drop_rate=1.0))
    cluster.network.schedule(TIMEOUT / 2, lambda: cluster.network.clear_faults("CS_0"))
    cluster.replicas["CS_1"].behaviour = Silent()
    submit_block(cluster, 0)
    run_for(cluster)
    for replica in honest(cluster, {"CS_1"}):
        assert replica.view == 2
        assert replica.height == 1
        assert replica.chain.head().owner_id == "CS_2"


# --------------------------------------------------------------------------------------------
# Safety across views — prepared certificates carry over
# --------------------------------------------------------------------------------------------
def test_a_prepared_block_is_re_proposed_and_committed_in_the_new_view() -> None:
    cluster, digest = _prepared_but_uncommitted()
    run_for(cluster)
    for replica in cluster.replicas.values():
        assert replica.view == 1
        assert replica.height == 1
        head = replica.chain.head()
        assert head.current_hash == digest, "the view-0 block, not a fresh one"
        assert head.owner_id == "CS_0"


class _DropReproposals:
    """A byzantine new primary that announces its view without the block the evidence forces."""

    def outgoing(self, replica: Replica, recipient: str, message: Message) -> Sequence[Message]:
        if isinstance(message, NewView) and message.proposals:
            return (resign(message, key_of(replica), proposals=()),)
        return (message,)


def test_a_byzantine_new_primary_cannot_drop_a_prepared_block() -> None:
    cluster, digest = _prepared_but_uncommitted()
    cluster.replicas["CS_1"].behaviour = Compose((DropCommitsInView(0), _DropReproposals()))
    run_for(cluster)
    rest = honest(cluster, {"CS_1"})
    for replica in rest:
        assert replica.rejected(RejectReason.BAD_NEW_VIEW)
        assert replica.view == 2, "the forged view is refused, and the cluster moves past it"
        assert replica.height == 1
        assert replica.chain.head().current_hash == digest
    assert_no_fork(rest)


def test_select_reproposal_takes_the_highest_proven_height_and_highest_view() -> None:
    cluster, digest = _prepared_but_uncommitted()
    vcs = tuple(_view_change(cluster, rid) for rid in ("CS_1", "CS_2", "CS_3"))
    forced = select_reproposal(vcs)
    assert forced.min_seq == 0
    assert forced.certificate is not None and forced.certificate.digest == digest


# --------------------------------------------------------------------------------------------
# Evidence checks
# --------------------------------------------------------------------------------------------
def _view_change(cluster: Cluster, rid: str, **overrides: object):
    replica = cluster.replicas[rid]
    fields = {
        "chain": cluster.chain_name,
        "new_view": 1,
        "last_seq": replica.height,
        "commit_proof": replica._commit_proof,
        "prepared": tuple(replica._prepared_certs.values()),
        "replica_id": rid,
        "key": key_of(replica),
    }
    fields.update(overrides)
    return build_view_change(**fields)  # type: ignore[arg-type]


def test_a_new_view_that_omits_or_swaps_the_forced_block_fails_verification() -> None:
    cluster, _ = _prepared_but_uncommitted()
    vcs = tuple(_view_change(cluster, rid) for rid in ("CS_1", "CS_2", "CS_3"))
    key = key_of(cluster.replicas["CS_1"])
    honest_nv = build_new_view(
        chain=cluster.chain_name, view=1, view_changes=vcs, replica_id="CS_1", key=key
    )
    membership = cluster.membership
    assert verify_new_view(honest_nv, membership, cluster.chain_name) is None

    dropped = resign(honest_nv, key, proposals=())
    assert "do not match" in (verify_new_view(dropped, membership, cluster.chain_name) or "")

    too_few = resign(honest_nv, key, view_changes=vcs[:2])
    assert "need 3" in (verify_new_view(too_few, membership, cluster.chain_name) or "")


def test_a_new_view_from_anyone_but_the_views_primary_is_rejected() -> None:
    cluster, _ = _prepared_but_uncommitted()
    vcs = tuple(_view_change(cluster, rid) for rid in ("CS_1", "CS_2", "CS_3"))
    forged = build_new_view(
        chain=cluster.chain_name,
        view=1,
        view_changes=vcs,
        replica_id="CS_2",
        key=key_of(cluster.replicas["CS_2"]),
    )
    assert "not its primary" in (verify_new_view(forged, cluster.membership, "BC_DTBU") or "")


def test_a_view_change_claiming_a_height_without_proof_is_rejected() -> None:
    """Otherwise a byzantine replica could push `min_s` past a committed block."""
    cluster, _ = _prepared_but_uncommitted()
    liar = _view_change(cluster, "CS_2", last_seq=7, prepared=())
    reason = verify_view_change(liar, cluster.membership, cluster.chain_name)
    assert reason is not None and "without a commit certificate" in reason


def test_a_view_change_carrying_an_undersized_certificate_is_rejected() -> None:
    cluster, _ = _prepared_but_uncommitted()
    cert = next(iter(cluster.replicas["CS_2"]._prepared_certs.values()))
    thin = PreparedCertificate(cert.pre_prepare, cert.prepares[:1], cert.block)
    vc = _view_change(cluster, "CS_2", prepared=(thin,))
    reason = verify_view_change(vc, cluster.membership, cluster.chain_name)
    assert reason is not None and "need 2" in reason


def test_a_view_change_padded_with_one_senders_prepare_is_rejected() -> None:
    cluster, _ = _prepared_but_uncommitted()
    cert = next(iter(cluster.replicas["CS_2"]._prepared_certs.values()))
    padded = PreparedCertificate(cert.pre_prepare, (cert.prepares[0],) * 3, cert.block)
    vc = _view_change(cluster, "CS_2", prepared=(padded,))
    assert "distinct" in (verify_view_change(vc, cluster.membership, cluster.chain_name) or "")


def test_a_view_change_from_a_non_member_is_rejected() -> None:
    from pbft_harness import OUTSIDER

    cluster, _ = _prepared_but_uncommitted()
    vc = _view_change(cluster, "CS_2", replica_id="CS_9", key=OUTSIDER.private)
    assert "non-member" in (verify_view_change(vc, cluster.membership, cluster.chain_name) or "")


def test_a_tampered_view_change_fails_its_signature() -> None:
    cluster, _ = _prepared_but_uncommitted()
    vc = dataclasses.replace(_view_change(cluster, "CS_2"), new_view=5)
    assert "bad signature" in (verify_view_change(vc, cluster.membership, "BC_DTBU") or "")


# --------------------------------------------------------------------------------------------
# Join rule
# --------------------------------------------------------------------------------------------
def test_f_plus_one_view_changes_pull_a_replica_along_without_its_own_timeout() -> None:
    cluster = make_cluster()
    target = cluster.replicas["CS_1"]
    for rid in ("CS_2", "CS_3"):
        target.receive(rid, _view_change(cluster, rid))
    # It joined, and as view 1's primary with 3 view-changes it announced and installed view 1.
    assert target.view == 1 and target.active
    assert cluster.network.now == 0.0, "no timeout elapsed"


def test_a_single_view_change_does_not_drag_a_replica_out_of_its_view() -> None:
    """A lone byzantine replica cannot force view changes: the join rule needs f+1."""
    cluster = make_cluster()
    target = cluster.replicas["CS_1"]
    target.receive("CS_3", _view_change(cluster, "CS_3", new_view=3))
    assert target.view == 0 and target.active
