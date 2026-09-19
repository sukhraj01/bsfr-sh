"""`consensus.protocol` — `ClientRequest` authentication (D4) and the D3 wire round-trip.

`encode_message`/`decode_message` back `consensus.network.P2PCSNetwork`'s `serialize=` hook
(DEV-30's magnitude, quantified). Every message shape a replica can receive round-trips to an
object equal to the original — frozen dataclasses compare by value, so `decode(encode(x)) == x`
is the whole correctness claim; `__post_init__`'s own checks (block hash/signature, transaction
`payload_type`, ...) run again on the reconstructed object for free.
"""

from __future__ import annotations

from pbft_harness import (
    GENESIS_TIME,
    OUTSIDER,
    POLICY,
    SUBMITTER,
    SUBMITTER_ID,
    DropCommitsInView,
    key_of,
    make_cluster,
    make_request,
    submit_block,
)

from bsfr_sh.consensus.pbft import CLIENT_ID
from bsfr_sh.consensus.protocol import (
    ClientRequest,
    Commit,
    Prepare,
    RejectReason,
    check_request_identity,
    decode_message,
    encode_message,
)
from bsfr_sh.consensus.view_change import build_new_view, build_view_change

TIMEOUT = POLICY.view_change_timeout_s


# --------------------------------------------------------------------------------------------
# D3 — wire round-trip
# --------------------------------------------------------------------------------------------
def test_client_request_round_trips() -> None:
    cluster = make_cluster()
    request = make_request(cluster, "wire", timestamp=GENESIS_TIME + 1)
    assert decode_message(encode_message(request)) == request


def test_proposal_round_trips_with_its_block() -> None:
    cluster = make_cluster()
    request = make_request(cluster, "wire", timestamp=GENESIS_TIME + 1)
    primary = cluster.replicas["CS_0"]
    primary.receive(CLIENT_ID, request)
    proposal = primary.proposal_at(0, 1)
    assert proposal is not None
    assert decode_message(encode_message(proposal)) == proposal


def test_prepare_round_trips() -> None:
    cluster = make_cluster()
    prepare = Prepare.create(
        chain=cluster.chain_name,
        view=0,
        seq=1,
        digest=bytes(32),
        replica_id="CS_1",
        key=key_of(cluster.replicas["CS_1"]),
    )
    assert decode_message(encode_message(prepare)) == prepare


def test_commit_round_trips() -> None:
    cluster = make_cluster()
    commit = Commit.create(
        chain=cluster.chain_name,
        view=0,
        seq=1,
        digest=bytes(32),
        replica_id="CS_2",
        key=key_of(cluster.replicas["CS_2"]),
    )
    assert decode_message(encode_message(commit)) == commit


def test_view_change_round_trips_with_a_real_prepared_certificate() -> None:
    """Exercises the nested `PreparedCertificate` (and the block inside it), not an empty one."""
    cluster = make_cluster()
    for replica in cluster.replicas.values():
        replica.behaviour = DropCommitsInView(0)
    submit_block(cluster, 0)
    cluster.run(until=TIMEOUT / 2)
    replica = cluster.replicas["CS_1"]
    assert replica._prepared_certs, "setup should have left CS_1 with a prepared certificate"
    vc = build_view_change(
        chain=cluster.chain_name,
        new_view=1,
        last_seq=replica.height,
        commit_proof=replica._commit_proof,
        prepared=tuple(replica._prepared_certs.values()),
        replica_id="CS_1",
        key=key_of(replica),
    )
    assert decode_message(encode_message(vc)) == vc


def test_new_view_round_trips_with_its_forced_reproposal() -> None:
    cluster = make_cluster()
    for replica in cluster.replicas.values():
        replica.behaviour = DropCommitsInView(0)
    submit_block(cluster, 0)
    cluster.run(until=TIMEOUT / 2)
    vcs = tuple(
        build_view_change(
            chain=cluster.chain_name,
            new_view=1,
            last_seq=r.height,
            commit_proof=r._commit_proof,
            prepared=tuple(r._prepared_certs.values()),
            replica_id=rid,
            key=key_of(r),
        )
        for rid, r in cluster.replicas.items()
        if rid != "CS_0"
    )
    nv = build_new_view(
        chain=cluster.chain_name,
        view=1,
        view_changes=vcs,
        replica_id="CS_1",
        key=key_of(cluster.replicas["CS_1"]),
    )
    assert nv.proposals, "setup should have forced a reproposal"
    assert decode_message(encode_message(nv)) == nv


# --------------------------------------------------------------------------------------------
# D4 — `ClientRequest` authentication (DEV-20 item 5, closed)
# --------------------------------------------------------------------------------------------
def test_check_request_identity_accepts_a_configured_submitter() -> None:
    cluster = make_cluster()
    request = make_request(cluster, "ok", timestamp=GENESIS_TIME + 1)
    assert check_request_identity(request, cluster.submitters, cluster.chain_name) is None


def test_check_request_identity_rejects_a_non_member_submitter() -> None:
    cluster = make_cluster()
    forged = ClientRequest.create(
        chain=cluster.chain_name,
        transactions=(),
        timestamp=GENESIS_TIME + 1,
        submitter_id="INTRUDER",
        key=OUTSIDER.private,
    )
    reason = check_request_identity(forged, cluster.submitters, cluster.chain_name)
    assert reason is RejectReason.NON_MEMBER


def test_check_request_identity_rejects_a_forged_signature() -> None:
    cluster = make_cluster()
    impostor = ClientRequest.create(
        chain=cluster.chain_name,
        transactions=(),
        timestamp=GENESIS_TIME + 1,
        submitter_id=SUBMITTER_ID,
        key=OUTSIDER.private,
    )
    reason = check_request_identity(impostor, cluster.submitters, cluster.chain_name)
    assert reason is RejectReason.BAD_SIGNATURE


def test_check_request_identity_rejects_the_wrong_chain() -> None:
    cluster = make_cluster()
    request = ClientRequest.create(
        chain="some-other-chain",
        transactions=(),
        timestamp=GENESIS_TIME + 1,
        submitter_id=SUBMITTER_ID,
        key=SUBMITTER.private,
    )
    reason = check_request_identity(request, cluster.submitters, cluster.chain_name)
    assert reason is RejectReason.WRONG_CHAIN
