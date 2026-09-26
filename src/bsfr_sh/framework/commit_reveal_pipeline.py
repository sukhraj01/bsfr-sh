"""Wraps `_block_pipeline` with the M7-14 commit-reveal protocol for `BC_SigRW`. DEV-40.

`consensus.commit_reveal` provides Phases 1-2 (commit, reveal-and-verify) and the merge decision,
but may not itself call into `_block_pipeline.run` — `consensus/` depends only on
`crypto`/`blockchain`/`util` (CLAUDE.md §3), and `consensus/validated_commit.py`'s dependency on
`detection/` is already this project's one named exception to that rule (`docs/ARCHITECTURE.md`
§consensus, DEV-38); this module is not a second one. `framework` already sits above `consensus`
(`_block_pipeline.py` itself imports `consensus.interface`), so Phase 3 — "the verified batches
are merged and committed through normal pBFT" — belongs here: this is the one function that turns
a `RoundResult` into an actual pipeline call, unmodified from what direct submission already does.

Config flag (item 2)
----------------------
`configs/chain.yaml`'s `consensus.commit_reveal.enabled` is the switch the session brief asks
for. It is read by *callers* (this session's evaluation script, and any future
`phase2_collection` wiring), not by this module itself — a module cannot sensibly "be enabled",
only be called or not. `submit_with_commit_reveal` and `_block_pipeline.run` are the two
interchangeable entry points the flag chooses between; both take the same shape of caller-visible
inputs (a chain, a policy, a submitter) precisely so the choice is a one-line dispatch, not two
divergent call sites.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from bsfr_sh.blockchain.transaction import SignatureRecordPayload, Transaction
from bsfr_sh.consensus.commit_reveal import CommitRevealRound, Reveal, RoundResult, commit_batch
from bsfr_sh.consensus.interface import ConsensusCluster
from bsfr_sh.crypto.ecdsa import PrivateKey
from bsfr_sh.framework import _block_pipeline as pipeline
from bsfr_sh.framework._block_pipeline import PipelinePolicy, PipelineResult

__all__ = ["submit_with_commit_reveal"]


def submit_with_commit_reveal(
    cluster: ConsensusCluster,
    node_batches: Mapping[str, Sequence[SignatureRecordPayload]],
    builder: Callable[[SignatureRecordPayload], Sequence[Transaction]],
    *,
    chain: str,
    policy: PipelinePolicy,
    timestamp: float,
    submitter_id: str,
    key: PrivateKey,
    blinding_factors: Mapping[str, bytes] | None = None,
    reveal_node_ids: Sequence[str] | None = None,
) -> tuple[PipelineResult, RoundResult]:
    """Phases 1-3, end to end, for one round: commit every node's batch, reveal (all of
    `reveal_node_ids`, default every participant), verify, merge, then hand the merged, verified
    payloads to the existing block pipeline unchanged — `_block_pipeline.run`, the identical call
    `phase2_collection` already makes for direct submission.

    `reveal_node_ids` lets a caller model a withholding or crashed participant: omit its id and
    `finalize()` excludes it, exactly as it would a node that tried and failed to reveal — this is
    how the TESTS section's "commit-reveal + pBFT together still tolerate f=1 crash fault" is
    modelled: a crashed node simply never appears in `reveal_node_ids`.

    `submitter_id`/`key` sign the ONE `ClientRequest` carrying the merged batch. pBFT does not
    need to know which participant originated which payload inside it, only that a registered
    submitter vouches for the request — the same posture every other pipeline call in this
    project already has (`docs/ARCHITECTURE.md` §consensus, "who builds the block", DEV-22).
    """
    participant_ids = tuple(node_batches)
    round_ = CommitRevealRound(participant_ids)
    kept_blinding: dict[str, bytes] = {}
    for node_id, node_batch in node_batches.items():
        supplied = None if blinding_factors is None else blinding_factors.get(node_id)
        commitment, r = commit_batch(node_id, node_batch, blinding_factor=supplied)
        round_.submit_commitment(commitment)
        kept_blinding[node_id] = r

    revealing = participant_ids if reveal_node_ids is None else tuple(reveal_node_ids)
    for node_id in revealing:
        round_.submit_reveal(
            Reveal(
                node_id=node_id,
                batch=tuple(node_batches[node_id]),
                blinding_factor=kept_blinding[node_id],
            )
        )

    round_result = round_.finalize()
    pipeline_result = pipeline.run(
        cluster,
        round_result.merged,
        builder,
        chain=chain,
        policy=policy,
        timestamp=timestamp,
        submitter_id=submitter_id,
        key=key,
    )
    return pipeline_result, round_result
