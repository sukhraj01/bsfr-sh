"""Threshold key wrapping — Phase 2 / P2-F (DEV-48): no single server can open, or lose, a backup.

`crypto.kem.seal_payload` wraps a backup's data key to *one* recipient. This module wraps it to
`n` recipients so that any `t` of them together can open the payload and fewer than `t` cannot:

1. Fresh AES-256-GCM data key, exactly as in `kem.seal_payload`.
2. Split the data key into `n` Shamir shares, threshold `t` (`crypto.secret_sharing`).
3. Wrap share `i` to recipient `i` with `kem.wrap_key`, bound to the transaction metadata, the share
   index and the threshold. A wrapped share cannot be moved to another transaction or another slot.
4. Seal the payload under the data key with associated data covering the metadata, the threshold,
   and every wrapped share, so no share can be swapped or dropped without breaking the tag.

Recovery is two steps on purpose. `unwrap_share` runs on each share holder and returns only that
holder's share. `open_with_shares` runs wherever the shares are combined (in the deployment, the
front server `CS_l` that recovers `SYS_i`, DEV-25). The combiner learns the data key of *that one
backup*, and nothing about any other backup, because every backup has its own data key.

Fewer than `t` shares, a wrong share, or tampering all surface the same way: the GCM tag fails and
`KemError` is raised. A wrong answer is never returned.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from bsfr_sh.crypto.aead import AeadError, AeadKey, Sealed
from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey
from bsfr_sh.crypto.kem import KemError, WrappedKey, unwrap_key, wrap_key
from bsfr_sh.crypto.secret_sharing import SecretSharingError, Share, combine, split
from bsfr_sh.util.serialization import CanonicalEncodingError, Value, encode

__all__ = [
    "ThresholdCiphertext",
    "open_with_shares",
    "seal_payload_threshold",
    "unwrap_share",
]


@dataclass(frozen=True)
class ThresholdCiphertext:
    """A payload whose data key is split across `len(wrapped_shares)` recipients, threshold `t`.

    `recipients[i]` is the public key share `i + 1` was wrapped to; `wrapped_shares[i]` is that
    wrapped share's canonical bytes.
    """

    threshold: int
    recipients: tuple[bytes, ...]
    wrapped_shares: tuple[bytes, ...]
    nonce: bytes
    ciphertext: bytes

    def key_material_bytes(self) -> int:
        """Bytes of wrapped-key material carried per transaction (the storage overhead)."""
        return sum(len(w) for w in self.wrapped_shares)


def _metadata_bytes(metadata: Mapping[str, Value]) -> bytes:
    try:
        return encode(dict(metadata))
    except CanonicalEncodingError as exc:
        raise KemError(f"transaction metadata is not canonically encodable: {exc}") from exc


def _share_aad(aad_metadata: bytes, index: int, threshold: int) -> bytes:
    return encode([aad_metadata, index, threshold])


def _payload_aad(aad_metadata: bytes, threshold: int, wrapped: Sequence[bytes]) -> bytes:
    return encode([aad_metadata, threshold, list(wrapped)])


def seal_payload_threshold(
    recipients: Sequence[PublicKey],
    threshold: int,
    plaintext: bytes,
    metadata: Mapping[str, Value],
) -> ThresholdCiphertext:
    """Encrypt `plaintext` so that any `threshold` of `recipients` can open it, and fewer cannot."""
    if len({r.to_bytes() for r in recipients}) != len(recipients):
        raise KemError("recipients must be distinct keys")
    aad_metadata = _metadata_bytes(metadata)
    data_key = AeadKey.generate()
    try:
        shares = split(data_key.key_bytes, shares=len(recipients), threshold=threshold)
    except SecretSharingError as exc:
        raise KemError(str(exc)) from exc
    wrapped = tuple(
        wrap_key(
            recipient, share.value, _share_aad(aad_metadata, share.index, threshold)
        ).to_bytes()
        for recipient, share in zip(recipients, shares, strict=True)
    )
    sealed = data_key.seal(plaintext, _payload_aad(aad_metadata, threshold, wrapped))
    return ThresholdCiphertext(
        threshold=threshold,
        recipients=tuple(r.to_bytes() for r in recipients),
        wrapped_shares=wrapped,
        nonce=sealed.nonce,
        ciphertext=sealed.ciphertext,
    )


def unwrap_share(
    holder: PrivateKey, ciphertext: ThresholdCiphertext, metadata: Mapping[str, Value]
) -> Share:
    """One share holder's step: recover *its own* share. Raises `KemError` if it holds none."""
    mine = holder.public_key.to_bytes()
    if mine not in ciphertext.recipients:
        raise KemError("this key holds no share of this payload")
    slot = ciphertext.recipients.index(mine)
    index = slot + 1
    aad = _share_aad(_metadata_bytes(metadata), index, ciphertext.threshold)
    value = unwrap_key(holder, WrappedKey.from_bytes(ciphertext.wrapped_shares[slot]), aad)
    return Share(index=index, value=value)


def open_with_shares(
    ciphertext: ThresholdCiphertext, shares: Sequence[Share], metadata: Mapping[str, Value]
) -> bytes:
    """The combiner's step. Raises `KemError` unless the shares rebuild the right data key."""
    if len(shares) < ciphertext.threshold:
        raise KemError(
            f"{len(shares)} share(s) given, {ciphertext.threshold} needed to open this payload"
        )
    try:
        key = combine(shares)
        data_key = AeadKey(key)
    except (SecretSharingError, AeadError) as exc:
        raise KemError(f"shares do not form a key: {exc}") from exc
    aad = _payload_aad(_metadata_bytes(metadata), ciphertext.threshold, ciphertext.wrapped_shares)
    try:
        return data_key.unseal(
            Sealed(nonce=ciphertext.nonce, ciphertext=ciphertext.ciphertext), aad
        )
    except AeadError as exc:
        raise KemError(
            "cannot open payload: a share is wrong, or the ciphertext, a wrapped share or the "
            "metadata was altered"
        ) from exc
