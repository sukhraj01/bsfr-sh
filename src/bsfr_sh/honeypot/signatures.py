"""`Sig_RW` — both senses of it. Implements Alg. 2, line 5. DEV-03.

§IV-B says signatures are "built" for malicious programs using ECDSA (ref [23]), which conflates
two unrelated things:

* a **malware signature**, which identifies a sample — a digest over what the sample did;
* a **digital signature**, which attests authenticity — who vouches for that digest.

ECDSA only does the second. Both are needed, so both exist here and are kept apart:

* `content_digest = H(tag_trace || canonical trace)` over `DT_RWC`'s behavioural trace. Two
  identical episodes give one digest; one altered counter gives another.
* `attestation = ECDSA_{CS_l}(H(tag_attest || content_digest || collected_at || collector_id))`,
  which is the paper's `digest || timestamp || collector_id` with a domain tag so an attestation
  can never be replayed as some other signature in this system.

The two travel together on-chain in `SignatureRecordPayload`. `verify()` checks the second against
`KU_CSl`; `matches()` checks the first against a sample that is claimed to be the same episode.
"""

from __future__ import annotations

from dataclasses import dataclass

from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey, sign, verify
from bsfr_sh.crypto.hashing import DOMAIN_SAMPLE_ATTESTATION, DOMAIN_SAMPLE_TRACE, tagged_h
from bsfr_sh.honeypot.preprocess import CleanSample
from bsfr_sh.util.serialization import encode

__all__ = ["SampleSignature", "SignatureError", "build", "content_digest"]


class SignatureError(ValueError):
    """Raised when a sample signature cannot be built or does not verify."""


def content_digest(sample: CleanSample) -> bytes:
    """The identification digest over a sample's canonical behavioural trace."""
    return tagged_h(DOMAIN_SAMPLE_TRACE, sample.trace())


def _attestation_preimage(digest: bytes, collected_at: int, collector_id: str) -> bytes:
    return tagged_h(DOMAIN_SAMPLE_ATTESTATION, digest, encode(collected_at), encode(collector_id))


@dataclass(frozen=True)
class SampleSignature:
    """`Sig_RW`: the identification digest plus `CS_l`'s attestation to it."""

    content_digest: bytes
    attestation: bytes
    collector_id: str
    collected_at: int

    def verify(self, collector_public: PublicKey) -> bool:
        """Whether `collector_public` attested this digest for this collector and time."""
        if not self.attestation:
            return False
        preimage = _attestation_preimage(self.content_digest, self.collected_at, self.collector_id)
        return verify(collector_public, self.attestation, preimage)

    def matches(self, sample: CleanSample) -> bool:
        """Whether `sample` is the episode this signature identifies."""
        return content_digest(sample) == self.content_digest


def build(sample: CleanSample, *, collector_key: PrivateKey, collector_id: str) -> SampleSignature:
    """Implements Alg. 2, line 5: digest the trace, then attest to the digest as `CS_l`."""
    if not collector_id:
        raise SignatureError(
            "collector_id is required: an unattributed attestation attests nothing"
        )
    digest = content_digest(sample)
    preimage = _attestation_preimage(digest, sample.collected_at, collector_id)
    return SampleSignature(
        content_digest=digest,
        attestation=sign(collector_key, preimage),
        collector_id=collector_id,
        collected_at=sample.collected_at,
    )
