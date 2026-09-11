"""`consensus.pbft` — the normal case: pre-prepare, prepare, commit, and what a replica rejects.

Tests that need exact control over which messages a replica sees drive `Replica.receive()`
directly and never run the bus, so the replica's own broadcasts just queue unread.
"""

from __future__ import annotations

import dataclasses

import pytest
from pbft_harness import (
    DTBU_IDS,
    GENESIS_TIME,
    OUTSIDER,
    POLICY,
    SIGRW_IDS,
    assert_no_fork,
    key_of,
    make_cluster,
    make_transactions,
    submit_block,
)

from bsfr_sh.blockchain.block import BlockDraft
from bsfr_sh.blockchain.chain import BC_SigRW
from bsfr_sh.consensus.network import LinkFaults
from bsfr_sh.consensus.pbft import CLIENT_ID, Cluster, PBFTPolicy
from bsfr_sh.consensus.protocol import (
    ClientRequest,
    Commit,
    Prepare,
    PrePrepare,
    Proposal,
    RejectReason,
)


def _propose(cluster: Cluster) -> Proposal:
    """Have the view-0 primary build and propose a block, without delivering anything."""
    request = ClientRequest(make_transactions("direct"), timestamp=GENESIS_TIME + 1)
    primary = cluster.replicas["CS_0"]
    primary.receive(CLIENT_ID, request)
    proposal = primary.proposal_at(0, 1)
    assert proposal is not None
    return proposal


def _vote(cluster: Cluster, kind: type, rid: str, proposal: Proposal, **overrides: object):
    pre_prepare = proposal.pre_prepare
    fields = {
        "chain": pre_prepare.chain,
        "view": pre_prepare.view,
        "seq": pre_prepare.seq,
        "digest": pre_prepare.digest,
        "replica_id": rid,
    }
    fields.update(overrides)
    return kind.create(key=key_of(cluster.replicas[rid]), **fields)


# --------------------------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------------------------
def test_happy_path_all_four_replicas_commit_the_same_block() -> None:
    cluster = make_cluster()
    request_id = submit_block(cluster, 0)
    cluster.run()
    assert cluster.heights() == dict.fromkeys(DTBU_IDS, 1)
    assert_no_fork(list(cluster.replicas.values()))
    block = cluster.replicas["CS_2"].chain.head()
    assert block.owner_id == "CS_0"  # OID is the view-0 primary that proposed it
    assert block.merkle_root == request_id
    for replica in cluster.replicas.values():
        assert replica.pending_requests == 0
        # The only thing an honest run rejects: the fourth commit, arriving after three sufficed.
        assert {r.reason for r in replica.rejections} <= {RejectReason.ALREADY_COMMITTED}


def test_several_blocks_commit_in_order_and_the_chains_verify() -> None:
    cluster = make_cluster()
    for i in range(5):
        submit_block(cluster, i)
        cluster.run()
    for replica in cluster.replicas.values():
        assert replica.height == 5
        replica.chain.verify_integrity()
    assert_no_fork(list(cluster.replicas.values()))


def test_message_count_per_block_is_the_textbook_pbft_count() -> None:
    """n=4: 4 requests + 3 pre-prepares + 3x3 prepares + 4x3 commits = 28."""
    cluster = make_cluster()
    submit_block(cluster, 0)
    cluster.run()
    assert cluster.network.stats.sent == 28


def test_a_duplicate_request_is_committed_once() -> None:
    cluster = make_cluster()
    txs = make_transactions("same")
    cluster.submit(txs, timestamp=GENESIS_TIME + 1)
    cluster.run()
    cluster.submit(txs, timestamp=GENESIS_TIME + 2)
    cluster.run()
    assert cluster.heights() == dict.fromkeys(DTBU_IDS, 1)


# --------------------------------------------------------------------------------------------
# Latency (DEV-21)
# --------------------------------------------------------------------------------------------
def test_configured_delay_defaults_to_zero_and_a_commit_takes_no_modelled_time() -> None:
    assert POLICY.message_delay_s == 0.0
    cluster = make_cluster()
    submit_block(cluster, 0)
    cluster.run()
    assert cluster.network.now == 0.0


@pytest.mark.parametrize("delay", [0.01, 0.05, 0.38])
def test_a_commit_takes_four_hops_of_modelled_time(delay: float) -> None:
    """Request delivery, then pre-prepare -> prepare -> commit: 3 hops inside consensus."""
    cluster = make_cluster(policy=dataclasses.replace(POLICY, message_delay_s=delay))
    for i in range(3):
        submit_block(cluster, i)
        cluster.run()
    assert cluster.heights() == dict.fromkeys(DTBU_IDS, 3)
    assert cluster.network.now == pytest.approx(3 * 4 * delay)


# --------------------------------------------------------------------------------------------
# Certificates count distinct signed senders
# --------------------------------------------------------------------------------------------
def test_one_backup_sending_its_prepare_three_times_does_not_prepare_the_primary() -> None:
    cluster = make_cluster()
    proposal = _propose(cluster)
    primary = cluster.replicas["CS_0"]
    prepare = _vote(cluster, Prepare, "CS_1", proposal)
    for _ in range(3):
        primary.receive("CS_1", prepare)
    assert not primary.is_prepared(0, 1, proposal.pre_prepare.digest)
    assert len(primary.rejected(RejectReason.DUPLICATE)) == 2
    primary.receive("CS_2", _vote(cluster, Prepare, "CS_2", proposal))
    assert primary.is_prepared(0, 1, proposal.pre_prepare.digest)


def test_commits_count_distinct_senders_not_arrivals() -> None:
    cluster = make_cluster()
    proposal = _propose(cluster)
    backup = cluster.replicas["CS_1"]
    backup.receive("CS_0", proposal)
    backup.receive("CS_2", _vote(cluster, Prepare, "CS_2", proposal))
    assert backup.is_prepared(0, 1, proposal.pre_prepare.digest)  # own prepare + CS_2 = 2f
    commit = _vote(cluster, Commit, "CS_2", proposal)
    for _ in range(3):
        backup.receive("CS_2", commit)
    assert backup.height == 0, "own commit + one sender three times is two senders, not four"
    backup.receive("CS_3", _vote(cluster, Commit, "CS_3", proposal))
    assert backup.height == 1


def test_a_prepare_from_the_primary_does_not_count() -> None:
    """The pre-prepare is the primary's vote; a prepare from it would count it twice."""
    cluster = make_cluster()
    proposal = _propose(cluster)
    backup = cluster.replicas["CS_1"]
    backup.receive("CS_0", proposal)
    backup.receive("CS_0", _vote(cluster, Prepare, "CS_0", proposal))
    assert not backup.is_prepared(0, 1, proposal.pre_prepare.digest)
    assert backup.rejected(RejectReason.PRIMARY_PREPARE)


def test_a_sender_that_votes_twice_differently_is_counted_once() -> None:
    cluster = make_cluster()
    proposal = _propose(cluster)
    backup = cluster.replicas["CS_1"]
    other = bytes(32)
    backup.receive("CS_2", _vote(cluster, Prepare, "CS_2", proposal, digest=other))
    backup.receive("CS_2", _vote(cluster, Prepare, "CS_2", proposal))
    assert backup.rejected(RejectReason.CONFLICTING_VOTE)


# --------------------------------------------------------------------------------------------
# Replay across views and sequences
# --------------------------------------------------------------------------------------------
def test_replay_across_views_is_rejected() -> None:
    """A correctly signed view-0 prepare is refused once the replica is in view 1 — and
    moving it to view 1 by editing the field breaks its signature."""
    cluster = make_cluster()
    proposal = _propose(cluster)
    captured = _vote(cluster, Prepare, "CS_2", proposal)  # (view 0, seq 1), validly signed
    backup = cluster.replicas["CS_3"]
    backup.view = 1  # as after a view change; the view-change path itself is test_view_change.py

    backup.receive("CS_2", captured)
    assert backup.rejected(RejectReason.WRONG_VIEW)

    backup.receive("CS_2", dataclasses.replace(captured, view=1))
    assert backup.rejected(RejectReason.BAD_SIGNATURE)


def test_replay_across_sequences_is_rejected() -> None:
    """A commit for height 1 is refused once 1 is committed — and moving it to height 2 by
    editing the field breaks its signature."""
    cluster = make_cluster()
    proposal = _propose(cluster)
    cluster.run()
    backup = cluster.replicas["CS_3"]
    assert backup.height == 1
    before = len(backup.rejected(RejectReason.ALREADY_COMMITTED))
    captured = _vote(cluster, Commit, "CS_2", proposal)

    backup.receive("CS_2", captured)
    assert len(backup.rejected(RejectReason.ALREADY_COMMITTED)) == before + 1

    backup.receive("CS_2", dataclasses.replace(captured, seq=2))
    assert backup.rejected(RejectReason.BAD_SIGNATURE)


def test_a_vote_signed_for_the_other_chain_is_rejected_even_under_the_same_key() -> None:
    """DEV-19: `chain` is in the signed body, so key reuse across chains does not leak votes."""
    cluster = make_cluster()
    proposal = _propose(cluster)
    backup = cluster.replicas["CS_1"]
    foreign = _vote(cluster, Prepare, "CS_2", proposal, chain=BC_SigRW)
    backup.receive("CS_2", foreign)
    assert backup.rejected(RejectReason.WRONG_CHAIN)
    backup.receive("CS_2", dataclasses.replace(foreign, chain=proposal.pre_prepare.chain))
    assert backup.rejected(RejectReason.BAD_SIGNATURE)


def test_votes_beyond_the_log_window_are_rejected() -> None:
    cluster = make_cluster()
    proposal = _propose(cluster)
    far = POLICY.log_window + 1
    cluster.replicas["CS_1"].receive("CS_2", _vote(cluster, Prepare, "CS_2", proposal, seq=far))
    assert cluster.replicas["CS_1"].rejected(RejectReason.OUT_OF_WINDOW)


# --------------------------------------------------------------------------------------------
# Membership — §V-3's permissioned property
# --------------------------------------------------------------------------------------------
def test_a_message_from_outside_the_membership_is_rejected() -> None:
    cluster = make_cluster()
    proposal = _propose(cluster)
    primary = cluster.replicas["CS_0"]
    stranger = Prepare.create(
        chain=proposal.pre_prepare.chain,
        view=0,
        seq=1,
        digest=proposal.pre_prepare.digest,
        replica_id="CS_9",
        key=OUTSIDER.private,
    )
    primary.receive("CS_9", stranger)
    assert primary.rejected(RejectReason.NON_MEMBER)


def test_an_outsider_claiming_a_members_id_fails_the_signature() -> None:
    cluster = make_cluster()
    proposal = _propose(cluster)
    primary = cluster.replicas["CS_0"]
    impostor = Prepare.create(
        chain=proposal.pre_prepare.chain,
        view=0,
        seq=1,
        digest=proposal.pre_prepare.digest,
        replica_id="CS_1",
        key=OUTSIDER.private,
    )
    primary.receive("CS_1", impostor)
    assert primary.rejected(RejectReason.BAD_SIGNATURE)
    assert not primary.is_prepared(0, 1, proposal.pre_prepare.digest)


def test_a_sybil_swarm_of_outsider_identities_cannot_form_a_certificate() -> None:
    """Minting identities buys nothing in a permissioned cluster."""
    cluster = make_cluster()
    proposal = _propose(cluster)
    primary = cluster.replicas["CS_0"]
    for i in range(50):
        primary.receive(
            f"sybil-{i}",
            Prepare.create(
                chain=proposal.pre_prepare.chain,
                view=0,
                seq=1,
                digest=proposal.pre_prepare.digest,
                replica_id=f"sybil-{i}",
                key=OUTSIDER.private,
            ),
        )
    assert not primary.is_prepared(0, 1, proposal.pre_prepare.digest)
    assert len(primary.rejected(RejectReason.NON_MEMBER)) == 50


def test_a_block_owned_by_a_non_member_is_not_prepared() -> None:
    cluster = make_cluster()
    primary = cluster.replicas["CS_0"]
    block = primary.chain.draft_next(
        owner_id="CS_9",
        owner_pubkey=OUTSIDER.public.to_bytes(),
        transactions=make_transactions("outsider"),
        timestamp=GENESIS_TIME + 1,
    ).seal(OUTSIDER.private)
    pre_prepare = PrePrepare.create(
        chain=cluster.chain_name,
        view=0,
        seq=1,
        digest=block.current_hash,
        replica_id="CS_0",
        key=key_of(primary),
    )
    backup = cluster.replicas["CS_1"]
    backup.receive("CS_0", Proposal(pre_prepare, block))
    assert backup.rejected(RejectReason.INVALID_BLOCK)
    assert backup.proposal_at(0, 1) is None


# --------------------------------------------------------------------------------------------
# Digest and proposal checks
# --------------------------------------------------------------------------------------------
def test_a_block_that_does_not_match_the_signed_digest_is_rejected() -> None:
    """Q7: the block travels outside the signature; `current_hash == digest` is what binds it."""
    cluster = make_cluster()
    proposal = _propose(cluster)
    primary = cluster.replicas["CS_0"]
    other_block = BlockDraft(
        owner_id="CS_0",
        owner_pubkey=proposal.block.owner_pubkey,
        transactions=make_transactions("swapped"),
        prev_hash=proposal.block.prev_hash,
        timestamp=proposal.block.timestamp,
    ).seal(key_of(primary))
    backup = cluster.replicas["CS_1"]
    backup.receive("CS_0", Proposal(proposal.pre_prepare, other_block))
    assert backup.rejected(RejectReason.DIGEST_MISMATCH)
    assert backup.proposal_at(0, 1) is None


def test_a_vote_for_a_block_the_replica_does_not_hold_is_rejected() -> None:
    cluster = make_cluster()
    proposal = _propose(cluster)
    backup = cluster.replicas["CS_1"]
    backup.receive("CS_0", proposal)
    backup.receive("CS_2", _vote(cluster, Prepare, "CS_2", proposal, digest=bytes(32)))
    backup.receive("CS_2", _vote(cluster, Commit, "CS_2", proposal, digest=bytes(32)))
    assert len(backup.rejected(RejectReason.DIGEST_MISMATCH)) == 2
    assert backup.prepare_voters(0, 1, bytes(32)) == frozenset()


def test_votes_held_before_the_proposal_are_discarded_if_they_do_not_match_it() -> None:
    cluster = make_cluster()
    proposal = _propose(cluster)
    backup = cluster.replicas["CS_1"]
    backup.receive("CS_2", _vote(cluster, Prepare, "CS_2", proposal, digest=bytes(32)))
    backup.receive("CS_3", _vote(cluster, Prepare, "CS_3", proposal))  # early, and matching
    backup.receive("CS_0", proposal)
    assert backup.prepare_voters(0, 1, proposal.pre_prepare.digest) == {"CS_1", "CS_3"}
    assert backup.is_prepared(0, 1, proposal.pre_prepare.digest)
    assert backup.rejected(RejectReason.DIGEST_MISMATCH)


def test_a_pre_prepare_from_a_non_primary_is_rejected() -> None:
    cluster = make_cluster()
    proposal = _propose(cluster)
    usurper = cluster.replicas["CS_2"]
    forged = Proposal(
        PrePrepare.create(
            chain=cluster.chain_name,
            view=0,
            seq=1,
            digest=proposal.pre_prepare.digest,
            replica_id="CS_2",
            key=key_of(usurper),
        ),
        proposal.block,
    )
    cluster.replicas["CS_1"].receive("CS_2", forged)
    assert cluster.replicas["CS_1"].rejected(RejectReason.NOT_PRIMARY)


def test_a_block_the_chain_would_refuse_is_never_prepared() -> None:
    """Validity comes from `Chain.check_append`, not from a second copy in the protocol."""
    cluster = make_cluster()
    primary = cluster.replicas["CS_0"]
    orphan = BlockDraft(
        owner_id="CS_0",
        owner_pubkey=primary.chain.head().owner_pubkey,
        transactions=make_transactions("orphan"),
        prev_hash=bytes(range(32)),  # links to nothing
        timestamp=GENESIS_TIME + 1,
    ).seal(key_of(primary))
    pre_prepare = PrePrepare.create(
        chain=cluster.chain_name,
        view=0,
        seq=1,
        digest=orphan.current_hash,
        replica_id="CS_0",
        key=key_of(primary),
    )
    backup = cluster.replicas["CS_1"]
    backup.receive("CS_0", Proposal(pre_prepare, orphan))
    assert backup.rejected(RejectReason.INVALID_BLOCK)
    assert cluster.network.pending == 0, "a replica that refused the block must not prepare it"


def test_a_bare_pre_prepare_without_its_block_is_malformed() -> None:
    cluster = make_cluster()
    proposal = _propose(cluster)
    cluster.replicas["CS_1"].receive("CS_0", proposal.pre_prepare)
    assert cluster.replicas["CS_1"].rejected(RejectReason.MALFORMED)


# --------------------------------------------------------------------------------------------
# Unreliable links between honest replicas
# --------------------------------------------------------------------------------------------
def test_duplicated_and_reordered_messages_still_commit_one_agreed_block() -> None:
    cluster = make_cluster(seed=11)
    for rid in DTBU_IDS:
        cluster.network.set_faults(rid, LinkFaults(duplicates=2, jitter_s=0.05))
    for i in range(4):
        submit_block(cluster, i)
        cluster.run(until=cluster.network.now + 1.0)
    assert cluster.heights() == dict.fromkeys(DTBU_IDS, 4)
    assert_no_fork(list(cluster.replicas.values()))
    assert any(r.rejected(RejectReason.DUPLICATE) for r in cluster.replicas.values())


# --------------------------------------------------------------------------------------------
# Construction guards
# --------------------------------------------------------------------------------------------
def test_cluster_size_must_match_the_configured_miner_count() -> None:
    from bsfr_sh.consensus.pbft import ConsensusError

    with pytest.raises(ConsensusError, match="miner_nodes"):
        make_cluster(policy=PBFTPolicy(replicas=5))


def test_policy_reads_the_consensus_section_of_the_config() -> None:
    assert (POLICY.replicas, POLICY.f, POLICY.commit_threshold) == (4, 1, 3)
    assert POLICY.log_window >= 1 and POLICY.view_change_timeout_s > 0


def test_two_clusters_share_no_state() -> None:
    """CLAUDE.md §4 — independent pBFT node sets for BC_DTBU and BC_SigRW."""
    dtbu = make_cluster()
    sigrw = make_cluster(BC_SigRW, SIGRW_IDS)
    submit_block(dtbu, 0)
    dtbu.run()
    assert dtbu.network is not sigrw.network
    assert sigrw.heights() == dict.fromkeys(SIGRW_IDS, 0)
    assert sigrw.network.stats.sent == 0
    assert not set(dtbu.replicas) & set(sigrw.replicas)
    for a in dtbu.replicas.values():
        for b in sigrw.replicas.values():
            assert a.chain is not b.chain
