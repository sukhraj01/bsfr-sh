"""`consensus.protocol` — what every pBFT signature covers (DEV-19), and the certificate checks.

Every field of `(chain, view, seq, digest, replica_id)` must be inside the signature. The
parametrized tamper test is the structural half of "replay across views / sequences is
rejected"; the replica-level half is in `test_pbft.py`.
"""

from __future__ import annotations

import dataclasses

import pytest
from pbft_harness import DTBU_IDS, OUTSIDER, replica_keys

from bsfr_sh.consensus.protocol import (
    VOTE_FIELDS,
    Commit,
    CommitCertificate,
    Membership,
    MembershipError,
    Prepare,
    PrePrepare,
    RejectReason,
    check_vote_identity,
    resign,
    verify_commit_certificate,
)

KEYS = replica_keys(DTBU_IDS)
MEMBERS = Membership({r: k.public_key for r, k in KEYS.items()}, f=1, commit_threshold=3)
DIGEST = bytes(range(32))

_TAMPERED = {
    "chain": "BC_SigRW",
    "view": 1,
    "seq": 2,
    "digest": bytes(32),
    "replica_id": "CS_3",
}


def _prepare(**overrides: object) -> Prepare:
    fields = {"chain": "BC_DTBU", "view": 0, "seq": 1, "digest": DIGEST, "replica_id": "CS_2"}
    fields.update(overrides)
    return Prepare.create(key=KEYS[str(fields["replica_id"])], **fields)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", VOTE_FIELDS)
@pytest.mark.parametrize("kind", [PrePrepare, Prepare, Commit])
def test_every_signed_field_is_covered_by_the_signature(kind: type, field: str) -> None:
    """Change any one field, keep the signature: it no longer verifies under the signer's key."""
    signed = kind.create(
        chain="BC_DTBU", view=0, seq=1, digest=DIGEST, replica_id="CS_2", key=KEYS["CS_2"]
    )
    assert signed.verify(KEYS["CS_2"].public_key)
    moved = dataclasses.replace(signed, **{field: _TAMPERED[field]})
    assert not moved.verify(KEYS["CS_2"].public_key), f"{field} is not covered by the signature"


def test_view_is_in_the_signed_body() -> None:
    """Without it a view-0 prepare would be a valid view-1 prepare."""
    assert _prepare(view=0).signed_body() != _prepare(view=1).signed_body()


def test_seq_is_in_the_signed_body() -> None:
    """Without it a vote at height n would count at height n+1."""
    assert _prepare(seq=1).signed_body() != _prepare(seq=2).signed_body()


def test_a_prepare_signature_is_not_a_commit_signature() -> None:
    """Per-type domains: having prepared is not having committed."""
    prepare = _prepare()
    as_commit = Commit(
        prepare.chain,
        prepare.view,
        prepare.seq,
        prepare.digest,
        prepare.replica_id,
        prepare.signature,
    )
    assert not as_commit.verify(KEYS["CS_2"].public_key)


def test_pbft_bodies_do_not_reuse_the_block_signing_domain() -> None:
    body = _prepare().signed_body()
    assert b"bsfr_sh.pbft.prepare.v1" in body
    assert b"block" not in body


def test_resign_produces_a_valid_variant_under_the_given_key() -> None:
    moved = resign(_prepare(), KEYS["CS_2"], view=5)
    assert moved.view == 5
    assert moved.verify(KEYS["CS_2"].public_key)


def test_identity_check_reasons() -> None:
    assert check_vote_identity(_prepare(), MEMBERS, "BC_DTBU") is None
    assert check_vote_identity(_prepare(), MEMBERS, "BC_SigRW") is RejectReason.WRONG_CHAIN
    stranger = Prepare.create(
        chain="BC_DTBU", view=0, seq=1, digest=DIGEST, replica_id="CS_9", key=OUTSIDER.private
    )
    assert check_vote_identity(stranger, MEMBERS, "BC_DTBU") is RejectReason.NON_MEMBER
    impostor = Prepare.create(
        chain="BC_DTBU", view=0, seq=1, digest=DIGEST, replica_id="CS_2", key=OUTSIDER.private
    )
    assert check_vote_identity(impostor, MEMBERS, "BC_DTBU") is RejectReason.BAD_SIGNATURE


def _commit(rid: str) -> Commit:
    return Commit.create(
        chain="BC_DTBU", view=0, seq=1, digest=DIGEST, replica_id=rid, key=KEYS[rid]
    )


def test_commit_certificate_counts_distinct_senders_not_messages() -> None:
    assert (
        verify_commit_certificate(
            CommitCertificate((_commit("CS_0"), _commit("CS_1"), _commit("CS_2"))),
            MEMBERS,
            "BC_DTBU",
        )
        is None
    )
    padded = CommitCertificate((_commit("CS_0"), _commit("CS_1"), _commit("CS_1")))
    reason = verify_commit_certificate(padded, MEMBERS, "BC_DTBU")
    assert reason is not None and "2 distinct" in reason


@pytest.mark.parametrize(
    ("n", "f", "threshold"),
    [(3, 1, 3), (4, 1, 2), (4, 1, 4), (4, -1, 1)],
    ids=["n<3f+1", "threshold<2f+1", "threshold>n-f", "negative-f"],
)
def test_membership_rejects_configurations_that_are_not_pbft(
    n: int, f: int, threshold: int
) -> None:
    keys = {f"CS_{i}": KEYS[f"CS_{i}"].public_key for i in range(n)}
    with pytest.raises(MembershipError):
        Membership(keys, f=f, commit_threshold=threshold)


def test_membership_quorums_for_the_papers_four_nodes() -> None:
    assert (MEMBERS.n, MEMBERS.f) == (4, 1)
    assert MEMBERS.prepare_quorum == 2
    assert MEMBERS.commit_threshold == 3
    assert MEMBERS.view_change_quorum == 3
    assert MEMBERS.join_quorum == 2
    assert [MEMBERS.primary(v) for v in range(5)] == ["CS_0", "CS_1", "CS_2", "CS_3", "CS_0"]
