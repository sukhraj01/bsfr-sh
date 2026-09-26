"""`consensus.commit_reveal`: the commit-then-reveal protocol primitives. M7-14, DEV-40."""

from __future__ import annotations

import pytest

from bsfr_sh.blockchain.transaction import SignatureRecordPayload
from bsfr_sh.consensus.commit_reveal import (
    Commitment,
    CommitRevealError,
    CommitRevealRound,
    Reveal,
    WithholdTracker,
    commit_batch,
    verify_reveal,
)


def _payload(sample_id: str, *, value: float = 1.0, label: str = "RW") -> SignatureRecordPayload:
    return SignatureRecordPayload(
        sample_id=sample_id,
        content_digest=b"\x00" * 32,
        attestation=b"\x01" * 64,
        features=(value, value * 2.0),
        collected_at=0,
        schema="ft_rw.v1",
        missing_mask=0,
        label=label,
    )


def _batch(*values: float) -> tuple[SignatureRecordPayload, ...]:
    return tuple(_payload(f"s{i}", value=v) for i, v in enumerate(values))


# --------------------------------------------------------------------------------------------
# commit_batch / verify_reveal
# --------------------------------------------------------------------------------------------
def test_commitment_verification_passes_for_an_honest_reveal() -> None:
    batch = _batch(1.0, 2.0, 3.0)
    commitment, r = commit_batch("CS_a", batch)
    reveal = Reveal(node_id="CS_a", batch=batch, blinding_factor=r)
    assert verify_reveal(commitment, reveal)


def test_commitment_verification_fails_if_the_batch_changes_after_committing() -> None:
    original = _batch(1.0, 2.0, 3.0)
    commitment, r = commit_batch("CS_a", original)
    tampered = _batch(1.0, 2.0, 999.0)  # one feature value changed post-commit
    reveal = Reveal(node_id="CS_a", batch=tampered, blinding_factor=r)
    assert not verify_reveal(commitment, reveal)


def test_commitment_verification_fails_if_only_the_blinding_factor_changes() -> None:
    batch = _batch(1.0, 2.0)
    commitment, r = commit_batch("CS_a", batch)
    wrong_r = bytes((r[0] ^ 0xFF,)) + r[1:]
    reveal = Reveal(node_id="CS_a", batch=batch, blinding_factor=wrong_r)
    assert not verify_reveal(commitment, reveal)


def test_commitment_verification_fails_on_node_id_mismatch() -> None:
    batch = _batch(1.0)
    commitment, r = commit_batch("CS_a", batch)
    reveal = Reveal(node_id="CS_b", batch=batch, blinding_factor=r)
    assert not verify_reveal(commitment, reveal)


def test_commit_binds_labels_not_just_feature_values() -> None:
    """Item 1's requirement: the commitment covers the ENTIRE batch, not a count or a label
    hash alone -- changing only a label after committing must also fail verification."""
    original = (_payload("s0", value=5.0, label="benign"),)
    commitment, r = commit_batch("CS_a", original)
    relabelled = (_payload("s0", value=5.0, label="RW"),)
    reveal = Reveal(node_id="CS_a", batch=relabelled, blinding_factor=r)
    assert not verify_reveal(commitment, reveal)


def test_same_batch_and_blinding_factor_is_deterministic() -> None:
    batch = _batch(1.0, 2.0)
    r = b"\x42" * 32
    commitment_a, _ = commit_batch("CS_a", batch, blinding_factor=r)
    commitment_b, _ = commit_batch("CS_a", batch, blinding_factor=r)
    assert commitment_a.digest == commitment_b.digest


def test_different_blinding_factors_hide_identical_batches() -> None:
    """Two nodes committing to the identical batch content produce different digests, so an
    observer cannot infer batch equality from commitments alone before reveal."""
    batch = _batch(1.0, 2.0)
    commitment_a, _ = commit_batch("CS_a", batch)
    commitment_b, _ = commit_batch("CS_b", batch)
    assert commitment_a.digest != commitment_b.digest


# --------------------------------------------------------------------------------------------
# CommitRevealRound
# --------------------------------------------------------------------------------------------
def _run_round(
    node_batches: dict[str, tuple[SignatureRecordPayload, ...]],
    *,
    revealing: set[str] | None = None,
    tamper: set[str] = frozenset(),
):
    round_ = CommitRevealRound(tuple(node_batches))
    blinding: dict[str, bytes] = {}
    for node_id, batch in node_batches.items():
        commitment, r = commit_batch(node_id, batch)
        round_.submit_commitment(commitment)
        blinding[node_id] = r
    reveal_ids = set(node_batches) if revealing is None else revealing
    for node_id in reveal_ids:
        batch = node_batches[node_id]
        if node_id in tamper:
            batch = _batch(*(v.features[0] + 1000.0 for v in batch)) if batch else batch
        round_.submit_reveal(
            Reveal(node_id=node_id, batch=batch, blinding_factor=blinding[node_id])
        )
    return round_.finalize()


def test_all_honest_nodes_are_included_and_merged_in_sorted_order() -> None:
    node_batches = {
        "CS_b": _batch(2.0),
        "CS_a": _batch(1.0),
    }
    result = _run_round(node_batches)
    assert result.included_node_ids == ("CS_a", "CS_b")
    assert result.excluded_node_ids == ()
    assert [p.features[0] for p in result.merged] == [1.0, 2.0]


def test_non_revealing_node_is_excluded() -> None:
    node_batches = {"CS_a": _batch(1.0), "CS_b": _batch(2.0)}
    result = _run_round(node_batches, revealing={"CS_a"})
    assert result.included_node_ids == ("CS_a",)
    assert result.excluded_node_ids == ("CS_b",)
    assert result.exclusion_reasons["CS_b"] == "withheld reveal"


def test_excluded_nodes_batch_is_not_in_the_merged_set() -> None:
    node_batches = {"CS_a": _batch(1.0), "CS_b": _batch(999.0)}
    result = _run_round(node_batches, revealing={"CS_a"})
    assert 999.0 not in [p.features[0] for p in result.merged]
    assert [p.features[0] for p in result.merged] == [1.0]


def test_node_whose_reveal_does_not_match_its_commitment_is_excluded() -> None:
    node_batches = {"CS_a": _batch(1.0), "CS_b": _batch(2.0)}
    result = _run_round(node_batches, tamper={"CS_b"})
    assert result.excluded_node_ids == ("CS_b",)
    assert result.exclusion_reasons["CS_b"] == "reveal does not match commitment"
    assert result.included_node_ids == ("CS_a",)


def test_produces_identical_merged_content_to_direct_submission_when_no_node_is_byzantine() -> None:
    node_batches = {"CS_a": _batch(1.0, 2.0), "CS_b": _batch(3.0), "CS_c": _batch(4.0, 5.0)}
    result = _run_round(node_batches)
    direct = tuple(p for node_id in sorted(node_batches) for p in node_batches[node_id])
    assert result.merged == direct
    assert set(result.included_node_ids) == set(node_batches)
    assert result.excluded_node_ids == ()


def test_round_rejects_empty_participant_list() -> None:
    with pytest.raises(CommitRevealError, match="at least one participant"):
        CommitRevealRound(())


def test_round_rejects_duplicate_participant_ids() -> None:
    with pytest.raises(CommitRevealError, match="duplicate"):
        CommitRevealRound(("CS_a", "CS_a"))


def test_commitment_from_a_non_participant_is_rejected() -> None:
    round_ = CommitRevealRound(("CS_a",))
    commitment, _ = commit_batch("CS_intruder", _batch(1.0))
    with pytest.raises(CommitRevealError, match="not a participant"):
        round_.submit_commitment(commitment)


def test_double_commitment_from_the_same_node_is_rejected() -> None:
    round_ = CommitRevealRound(("CS_a",))
    commitment, _ = commit_batch("CS_a", _batch(1.0))
    round_.submit_commitment(commitment)
    with pytest.raises(CommitRevealError, match="already committed"):
        round_.submit_commitment(commitment)


def test_a_node_that_never_commits_is_excluded_for_that_reason() -> None:
    round_ = CommitRevealRound(("CS_a", "CS_b"))
    commitment, r = commit_batch("CS_a", _batch(1.0))
    round_.submit_commitment(commitment)
    round_.submit_reveal(Reveal(node_id="CS_a", batch=_batch(1.0), blinding_factor=r))
    result = round_.finalize()
    assert result.excluded_node_ids == ("CS_b",)
    assert result.exclusion_reasons["CS_b"] == "no commitment submitted"


# --------------------------------------------------------------------------------------------
# WithholdTracker
# --------------------------------------------------------------------------------------------
def test_withholding_node_is_not_permanently_excluded_before_the_threshold() -> None:
    tracker = WithholdTracker(max_consecutive_withholds=3)
    node_batches = {"CS_a": _batch(1.0), "CS_b": _batch(2.0)}
    for _ in range(2):
        result = _run_round(node_batches, revealing={"CS_a"})
        tracker.record_round(result)
    assert "CS_b" not in tracker.permanently_excluded
    assert tracker.eligible_participants(("CS_a", "CS_b")) == ("CS_a", "CS_b")


def test_withholding_node_is_permanently_excluded_at_exactly_the_threshold() -> None:
    tracker = WithholdTracker(max_consecutive_withholds=3)
    node_batches = {"CS_a": _batch(1.0), "CS_b": _batch(2.0)}
    for round_index in range(3):
        result = _run_round(node_batches, revealing={"CS_a"})
        tracker.record_round(result)
        if round_index < 2:
            assert "CS_b" not in tracker.permanently_excluded
    assert "CS_b" in tracker.permanently_excluded
    assert tracker.eligible_participants(("CS_a", "CS_b")) == ("CS_a",)


def test_a_single_good_reveal_resets_the_withhold_streak() -> None:
    tracker = WithholdTracker(max_consecutive_withholds=3)
    node_batches = {"CS_a": _batch(1.0), "CS_b": _batch(2.0)}
    tracker.record_round(_run_round(node_batches, revealing={"CS_a"}))
    tracker.record_round(_run_round(node_batches, revealing={"CS_a"}))
    tracker.record_round(_run_round(node_batches))  # CS_b reveals this round: streak resets
    tracker.record_round(_run_round(node_batches, revealing={"CS_a"}))
    tracker.record_round(_run_round(node_batches, revealing={"CS_a"}))
    assert "CS_b" not in tracker.permanently_excluded


def test_withhold_tracker_rejects_non_positive_threshold() -> None:
    with pytest.raises(CommitRevealError, match="at least 1"):
        WithholdTracker(max_consecutive_withholds=0)


def test_commitment_and_reveal_are_frozen_dataclasses() -> None:
    commitment = Commitment(node_id="CS_a", digest=b"\x00" * 32)
    with pytest.raises(AttributeError):
        commitment.node_id = "CS_b"  # type: ignore[misc]
