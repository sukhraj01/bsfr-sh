"""`honeypot.signatures`: DEV-03's two senses of `Sig_RW`, kept apart and both checkable."""

from __future__ import annotations

import dataclasses

import pytest
from m3b_harness import clean_draw

from bsfr_sh.crypto.ecdsa import keypair_from_secret
from bsfr_sh.honeypot.signatures import SampleSignature, SignatureError, build, content_digest

COLLECTOR = keypair_from_secret(0xC0_11EC)
OTHER = keypair_from_secret(0xBAD_51_6E)
SAMPLES = clean_draw(40)


def _signed(index: int = 0) -> tuple[SampleSignature, object]:
    sample = SAMPLES[index]
    return build(sample, collector_key=COLLECTOR.private, collector_id="CS_10"), sample


def test_an_attestation_verifies_under_the_collectors_key() -> None:
    signature, _ = _signed()
    assert signature.verify(COLLECTOR.public)


def test_an_attestation_does_not_verify_under_another_key() -> None:
    signature, _ = _signed()
    assert not signature.verify(OTHER.public)


def test_a_signature_built_by_the_wrong_signer_is_rejected() -> None:
    sample = SAMPLES[1]
    forged = build(sample, collector_key=OTHER.private, collector_id="CS_10")
    assert not forged.verify(COLLECTOR.public)


def test_the_content_digest_identifies_the_episode() -> None:
    signature, sample = _signed()
    assert signature.matches(sample)
    assert signature.content_digest == content_digest(sample)


def test_a_tampered_counter_changes_the_digest() -> None:
    _, sample = _signed()
    altered = dataclasses.replace(sample, counters={**sample.counters, "write_entropy_mean": 1.0})
    assert content_digest(altered) != content_digest(sample)


def test_a_tampered_stage_changes_the_digest() -> None:
    _, sample = _signed()
    stages = (
        dataclasses.replace(sample.stages[0], dwell_s=sample.stages[0].dwell_s + 1.0),
        *sample.stages[1:],
    )
    assert content_digest(dataclasses.replace(sample, stages=stages)) != content_digest(sample)


def test_a_signature_does_not_match_a_different_episode() -> None:
    signature, _ = _signed(0)
    assert not signature.matches(SAMPLES[2])


def test_the_attestation_is_bound_to_collector_and_time() -> None:
    signature, _ = _signed()
    for changed in (
        dataclasses.replace(signature, collector_id="CS_99"),
        dataclasses.replace(signature, collected_at=signature.collected_at + 1),
        dataclasses.replace(signature, content_digest=bytes(32)),
    ):
        assert not changed.verify(COLLECTOR.public)


def test_an_empty_attestation_never_verifies() -> None:
    signature, _ = _signed()
    assert not dataclasses.replace(signature, attestation=b"").verify(COLLECTOR.public)


def test_an_unattributed_attestation_is_refused() -> None:
    with pytest.raises(SignatureError, match="collector_id"):
        build(SAMPLES[0], collector_key=COLLECTOR.private, collector_id="")


def test_the_digest_covers_behaviour_not_provenance() -> None:
    """Two identical episodes digest alike whatever the emulator labelled them: it is a content
    digest, which is exactly why the label has to travel as separate metadata (DEV-27)."""
    _, sample = _signed()
    relabelled = dataclasses.replace(sample, label="benign", profile="office_workload")
    assert content_digest(relabelled) == content_digest(sample)
