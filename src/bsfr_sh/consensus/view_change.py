"""Leader timeout and view change — the reduced Castro-Liskov form (DEV-20).

Implements the "else re-run consensus" branch of Alg. 1, lines 9-10 (and Alg. 2, lines 10-15),
which the paper leaves unspecified.

Why this exists at all
----------------------
The paper describes no view change (DEV-10). Without one, a leader that stops sending — crashed,
partitioned, or byzantine and silent — stalls its chain for good, and §V-3's claim that pBFT
makes BSFR-SH resistant to a class of attacks is undercut by the simplest attack there is.

Protocol
--------
1. A replica holding an uncommitted request starts a timer (`consensus.view_change_timeout_s`,
   simulated seconds). On expiry it moves to `view+1`, stops taking normal-case messages for the
   old view, and broadcasts a signed `ViewChange` carrying:
     * `last_seq` — its committed height — and a `CommitCertificate` proving it;
     * every `PreparedCertificate` it holds above that height (the highest view for each).
2. A replica that sees `f+1` valid view-changes for views above its own joins the smallest of
   them without waiting for its own timer (`Membership.join_quorum`).
3. The new primary, on `2f+1` valid view-changes for its view from distinct replicas, broadcasts a
   signed `NewView` carrying them and the re-proposals they force (`select_reproposal`).
4. Every receiver re-verifies each carried view-change and recomputes the re-proposals, rejecting
   a `NewView` that differs — so a byzantine new primary cannot quietly drop a prepared block.
5. If no valid `NewView` arrives, the replica escalates to `view+2` after twice the timeout, then
   four times, and so on.

The re-proposal rule
--------------------
`min_s` is the highest committed height *proven* in the view-change set. If any carried prepared
certificate is for `min_s + 1`, the one from the highest view is re-proposed at `min_s + 1` in the
new view; otherwise nothing is, and the new primary proposes fresh from its pending requests.

Why this is safe with at most `f` byzantine replicas: a block committed at height `n` was prepared
by at least `f+1` honest replicas, and any `2f+1` view-changes include at least one of them. That
replica either has committed `n` — its proof lifts `min_s` to `n`, so `n` is never re-proposed —
or still holds the prepared certificate, and the highest-view rule picks it. Proof of committed
height is required, rather than trusting `last_seq`, because a replica that could simply *claim*
a height could push `min_s` past a block that only it knows was committed elsewhere.

Only `min_s + 1` can carry a certificate: a replica prepares height `n+1` only after it has
committed `n` (it cannot validate `n+1`'s `prev_hash` otherwise), so a certificate for `n+1` always
comes with a proven height of at least `n`. Hence no gaps, and no null requests (DEV-20 item 4).

What is omitted — DEV-20 has the full list and the costs
--------------------------------------------------------
No checkpoint messages (the commit certificate is a one-block checkpoint), no state transfer, no
pipelining, no null requests, no retransmission.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bsfr_sh.consensus.protocol import (
    CommitCertificate,
    Membership,
    NewView,
    PreparedCertificate,
    PrePrepare,
    Proposal,
    ViewChange,
    resign,
    verify_commit_certificate,
    verify_prepared_certificate,
)
from bsfr_sh.crypto.ecdsa import PrivateKey

__all__ = [
    "Reproposal",
    "ViewChangeLog",
    "build_new_view",
    "build_view_change",
    "select_reproposal",
    "verify_new_view",
    "verify_view_change",
]


def build_view_change(
    *,
    chain: str,
    new_view: int,
    last_seq: int,
    commit_proof: CommitCertificate | None,
    prepared: tuple[PreparedCertificate, ...],
    replica_id: str,
    key: PrivateKey,
) -> ViewChange:
    """Sign a `VIEW-CHANGE` for `new_view`. Step 1 of the module docstring."""
    carried = tuple(sorted((c for c in prepared if c.seq > last_seq), key=lambda c: c.seq))
    return resign(ViewChange(chain, new_view, last_seq, commit_proof, carried, replica_id), key)


def verify_view_change(vc: ViewChange, membership: Membership, chain: str) -> str | None:
    """Return why `vc` is not a valid view-change, or `None` if it is.

    Checks the signature, then every piece of evidence it carries: the committed height is proven
    (height 0 is the genesis and needs no proof), each prepared certificate is valid, is from an
    earlier view than the one being moved to, and is above the proven height.
    """
    if vc.chain != chain:
        return "view-change for a different chain"
    key = membership.key(vc.replica_id)
    if key is None:
        return f"view-change from non-member {vc.replica_id!r}"
    if not vc.verify(key):
        return f"view-change from {vc.replica_id!r} has a bad signature"
    if vc.new_view < 1:
        return "view-change must target a view of at least 1"
    if vc.last_seq < 0:
        return "negative committed height"
    if vc.last_seq == 0:
        if vc.commit_proof is not None:
            return "height 0 is the genesis and carries no commit proof"
    else:
        if vc.commit_proof is None:
            return f"claims committed height {vc.last_seq} without a commit certificate"
        if (reason := verify_commit_certificate(vc.commit_proof, membership, chain)) is not None:
            return f"commit proof: {reason}"
        if vc.commit_proof.seq != vc.last_seq:
            return "commit proof is for a different height than claimed"
    seen: set[int] = set()
    for cert in vc.prepared:
        if (reason := verify_prepared_certificate(cert, membership, chain)) is not None:
            return f"prepared certificate at seq {cert.seq}: {reason}"
        if cert.view >= vc.new_view:
            return "prepared certificate is not from an earlier view"
        if cert.seq <= vc.last_seq:
            return "prepared certificate is at or below the committed height"
        if cert.seq in seen:
            return "two prepared certificates for one height"
        seen.add(cert.seq)
    return None


@dataclass(frozen=True)
class Reproposal:
    """What a `2f+1` view-change set forces the new primary to do."""

    #: Highest proven committed height in the set.
    min_seq: int
    #: The certificate to re-propose at `min_seq + 1`, if any.
    certificate: PreparedCertificate | None


def select_reproposal(view_changes: tuple[ViewChange, ...]) -> Reproposal:
    """The deterministic re-proposal rule — see the module docstring. Inputs must be verified."""
    min_seq = max(vc.last_seq for vc in view_changes)
    candidates = [cert for vc in view_changes for cert in vc.prepared if cert.seq == min_seq + 1]
    if not candidates:
        return Reproposal(min_seq, None)
    # Highest view wins. Two certificates in one view with different digests cannot both be valid
    # with at most f faults; the digest tie-break only makes the choice deterministic if they are.
    best = max(candidates, key=lambda c: (c.view, c.digest))
    return Reproposal(min_seq, best)


def verify_new_view(nv: NewView, membership: Membership, chain: str) -> str | None:
    """Return why `nv` is not a valid new-view, or `None` if it is. Step 4 of the module docstring.

    The re-proposals are recomputed from the carried view-changes, not read from the message.
    """
    if nv.chain != chain:
        return "new-view for a different chain"
    if nv.replica_id != membership.primary(nv.view):
        return f"new-view for view {nv.view} is from {nv.replica_id!r}, not its primary"
    key = membership.key(nv.replica_id)
    if key is None or not nv.verify(key):
        return "new-view has a bad signature"
    senders: set[str] = set()
    for vc in nv.view_changes:
        if (reason := verify_view_change(vc, membership, chain)) is not None:
            return f"carried {reason}"
        if vc.new_view != nv.view:
            return f"carried view-change targets view {vc.new_view}, not {nv.view}"
        if vc.replica_id in senders:
            return f"two view-changes from {vc.replica_id!r}"
        senders.add(vc.replica_id)
    if len(senders) < membership.view_change_quorum:
        return f"{len(senders)} view-changes, need {membership.view_change_quorum} (2f+1)"

    forced = select_reproposal(nv.view_changes)
    expected = (
        [] if forced.certificate is None else [(forced.min_seq + 1, forced.certificate.digest)]
    )
    actual = [(p.pre_prepare.seq, p.pre_prepare.digest) for p in nv.proposals]
    if actual != expected:
        return (
            "re-proposals do not match what the view-changes force — a prepared block would be "
            "dropped or replaced"
        )
    for proposal in nv.proposals:
        pre_prepare = proposal.pre_prepare
        if pre_prepare.view != nv.view or pre_prepare.replica_id != nv.replica_id:
            return "re-proposal is not a pre-prepare by the new primary in the new view"
        if not pre_prepare.verify(key):
            return "re-proposal pre-prepare has a bad signature"
        if not proposal.digest_matches:
            return "re-proposed block does not match its digest"
    return None


def build_new_view(
    *,
    chain: str,
    view: int,
    view_changes: tuple[ViewChange, ...],
    replica_id: str,
    key: PrivateKey,
) -> NewView:
    """Sign a `NEW-VIEW` with exactly the re-proposals `view_changes` force. Step 3."""
    forced = select_reproposal(view_changes)
    proposals: tuple[Proposal, ...] = ()
    if forced.certificate is not None:
        pre_prepare = PrePrepare.create(
            chain=chain,
            view=view,
            seq=forced.min_seq + 1,
            digest=forced.certificate.digest,
            replica_id=replica_id,
            key=key,
        )
        proposals = (Proposal(pre_prepare, forced.certificate.block),)
    return resign(NewView(chain, view, view_changes, proposals, replica_id), key)


@dataclass
class ViewChangeLog:
    """Valid view-changes a replica has received, one per sender per target view."""

    _by_view: dict[int, dict[str, ViewChange]] = field(default_factory=dict)

    def record(self, vc: ViewChange) -> None:
        self._by_view.setdefault(vc.new_view, {}).setdefault(vc.replica_id, vc)

    def for_view(self, view: int) -> tuple[ViewChange, ...]:
        votes = self._by_view.get(view, {})
        return tuple(votes[r] for r in sorted(votes))

    def join_target(self, above: int, quorum: int) -> int | None:
        """Smallest view `> above` if at least `quorum` distinct replicas asked for views `> above`.

        Counts each sender once, at its highest requested view — the Castro-Liskov join rule.
        """
        highest: dict[str, int] = {}
        for view, votes in self._by_view.items():
            if view <= above:
                continue
            for sender in votes:
                highest[sender] = max(highest.get(sender, view), view)
        if len(highest) < quorum:
            return None
        return min(highest.values())

    def discard_below(self, view: int) -> None:
        for stale in [v for v in self._by_view if v < view]:
            del self._by_view[stale]
