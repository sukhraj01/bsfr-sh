"""`DT_BU` across transactions — the contract between Phase 1 and Phase 5. DEV-23, DEV-24.

Alg. 1 line 2 encrypts `DT_BU` into transactions `Tx_m, m = 1..N_dTx` and never says how one
backup maps onto them. With DEV-15's declared 4 KiB payload, any real backup spans many. Alg. 5
restores `DT_BU` and never asks whether what came back is what went in. Both answers live here
because they are one contract: `split` is the only producer of the chunks `reassemble` accepts,
and changing one without the other is exactly the bug a round-trip test exists to catch.

Split — DEV-24
--------------
A backup becomes `ceil(len / chunk_bytes)` chunks, and the last one holds the remainder. An empty
backup becomes one empty chunk, so "backed up nothing" and "no backup" stay different things. Each
chunk carries its `chunk_index` and the `chunk_count`. Order is never inferred from the chain,
because consensus decides which height a batch lands at and the submitter does not.

Attestation — DEV-23
--------------------
Before `DT_BU` leaves `SYS_i`, `attest()` computes
`payload_digest = H(tag_payload || system_id || captured_at || DT_BU)` and signs
`H(tag_attest || system_id || captured_at || payload_digest)` with the system's ECDSA key. Every
chunk carries both. `backup_id` is derived from `(system_id, captured_at, payload_digest)` and never
stored, so a chunk cannot claim to belong to a backup it does not match.

Who checks what
---------------
* `reassemble()` checks structure: each index present exactly once, every chunk agreeing on one
  manifest, and the bytes matching the manifest's digest. Anyone holding the plaintext chunks can
  run it. `CS'_l` does, so a broken backup fails before it is shipped anywhere.
* `verify_restored()` checks end to end: the digest *and* `SYS_i`'s signature over it, under
  `SYS_i`'s own key. It is only meaningful on `SYS_i`. Both servers on the way back hold plaintext
  and could rewrite the data and the digest together, but they cannot forge the signature.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from bsfr_sh.blockchain.transaction import BackupPayload
from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey, sign, verify
from bsfr_sh.crypto.hashing import (
    DIGEST_SIZE,
    DOMAIN_BACKUP_ATTESTATION,
    DOMAIN_BACKUP_ID,
    DOMAIN_BACKUP_PAYLOAD,
    DOMAIN_BACKUP_TX_ID,
    tagged_h,
)
from bsfr_sh.util.serialization import CanonicalEncodingError, Value, decode, encode

__all__ = [
    "BackupError",
    "BackupManifest",
    "attest",
    "chunk_tx_id",
    "manifest_of",
    "pack",
    "payload_digest",
    "reassemble",
    "split",
    "unpack",
    "verify_restored",
]


class BackupError(ValueError):
    """Raised when a backup cannot be split, reassembled, or verified."""


def payload_digest(system_id: str, captured_at: int, data: bytes) -> bytes:
    """`H(DT_BU)` per DEV-23, bound to the system and capture time as well as the bytes.

    Because `system_id` is bound in, one system's backup never verifies as another's, even when the
    two hold identical data. Binding `captured_at` does the same for two captures of one system.
    """
    return tagged_h(DOMAIN_BACKUP_PAYLOAD, encode(system_id), encode(captured_at), data)


def _attestation_preimage(system_id: str, captured_at: int, digest: bytes) -> bytes:
    return tagged_h(DOMAIN_BACKUP_ATTESTATION, encode(system_id), encode(captured_at), digest)


@dataclass(frozen=True)
class BackupManifest:
    """What `SYS_i` attests about one whole `DT_BU` before it leaves the device. DEV-23."""

    system_id: str
    captured_at: int
    payload_digest: bytes
    attestation: bytes

    @property
    def backup_id(self) -> str:
        """Derived, never stored, so no chunk can carry an id that disagrees with its manifest."""
        return tagged_h(
            DOMAIN_BACKUP_ID, encode(self.system_id), encode(self.captured_at), self.payload_digest
        ).hex()

    def matches(self, data: bytes) -> bool:
        """Whether `data` is the backup this manifest describes."""
        return payload_digest(self.system_id, self.captured_at, data) == self.payload_digest

    def verify(self, system_public: PublicKey) -> bool:
        """Whether `system_public` signed this manifest's digest."""
        if not self.attestation:
            return False
        preimage = _attestation_preimage(self.system_id, self.captured_at, self.payload_digest)
        return verify(system_public, self.attestation, preimage)

    def to_fields(self) -> dict[str, Value]:
        return {
            "system_id": self.system_id,
            "captured_at": self.captured_at,
            "payload_digest": self.payload_digest,
            "attestation": self.attestation,
        }

    @classmethod
    def from_fields(cls, fields: Mapping[str, Value]) -> BackupManifest:
        system_id = fields.get("system_id")
        captured_at = fields.get("captured_at")
        digest = fields.get("payload_digest")
        attestation = fields.get("attestation")
        if (
            not isinstance(system_id, str)
            or isinstance(captured_at, bool)
            or not isinstance(captured_at, int)
            or not isinstance(digest, bytes)
            or not isinstance(attestation, bytes)
        ):
            raise BackupError("manifest fields are missing or of the wrong type")
        return cls(system_id, captured_at, digest, attestation)


def attest(
    private_key: PrivateKey, *, system_id: str, captured_at: int, data: bytes
) -> BackupManifest:
    """`SYS_i`'s side of DEV-23: digest and sign `DT_BU` before Alg. 1 line 1 ships it."""
    digest = payload_digest(system_id, captured_at, data)
    signature = sign(private_key, _attestation_preimage(system_id, captured_at, digest))
    return BackupManifest(system_id, captured_at, digest, signature)


def manifest_of(chunk: BackupPayload) -> BackupManifest:
    """The manifest a chunk claims to belong to."""
    return BackupManifest(
        chunk.system_id, chunk.captured_at, chunk.payload_digest, chunk.attestation
    )


def chunk_tx_id(chunk: BackupPayload) -> str:
    """A chunk's public `tx_id`.

    It is derived from the backup id and the chunk position, so it is unique per chunk. It reveals
    neither `system_id` nor which chunks belong together: M2a kept `system_id` out of the clear on
    purpose, and a readable id would undo that.
    """
    backup_id = bytes.fromhex(manifest_of(chunk).backup_id)
    tag = tagged_h(
        DOMAIN_BACKUP_TX_ID, backup_id, encode(chunk.chunk_index), encode(chunk.chunk_count)
    )
    return f"dtbu-{tag[:16].hex()}"


def split(manifest: BackupManifest, data: bytes, *, chunk_bytes: int) -> tuple[BackupPayload, ...]:
    """Cut `DT_BU` into the chunks Alg. 1 line 2 encrypts as `Tx_m, m = 1..N_dTx`. DEV-24.

    `chunk_bytes` is `transaction.payload_bytes`: backup bytes per transaction, before framing.
    """
    if chunk_bytes <= 0:
        raise BackupError(f"chunk_bytes must be positive, got {chunk_bytes}")
    if not manifest.matches(data):
        raise BackupError("data does not match the manifest it is being split under")
    count = max(1, -(-len(data) // chunk_bytes))
    return tuple(
        BackupPayload(
            system_id=manifest.system_id,
            data=data[index * chunk_bytes : (index + 1) * chunk_bytes],
            captured_at=manifest.captured_at,
            chunk_index=index,
            chunk_count=count,
            payload_digest=manifest.payload_digest,
            attestation=manifest.attestation,
        )
        for index in range(count)
    )


def reassemble(chunks: Iterable[BackupPayload]) -> tuple[BackupManifest, bytes]:
    """Put one backup back together from its chunks, given in any order. DEV-24.

    Checks the structure and the digest, not the attestation, which needs `SYS_i`'s key (see
    `verify_restored`). Refuses the following: no chunks; a chunk with no digest or attestation
    (the paper-shaped record, DEV-23); chunks that disagree on their manifest or count; two
    *different* chunks at one index; a missing index; bytes that do not match the digest.
    A byte-identical duplicate is accepted, because it is the same chunk committed twice.
    """
    received = tuple(chunks)
    if not received:
        raise BackupError("no chunks to reassemble")
    manifest = manifest_of(received[0])
    if len(manifest.payload_digest) != DIGEST_SIZE or not manifest.attestation:
        raise BackupError(
            "chunk carries no payload digest or attestation; an unverifiable backup record is "
            "refused, not restored (DEV-23)"
        )
    count = received[0].chunk_count
    by_index: dict[int, bytes] = {}
    for chunk in received:
        if manifest_of(chunk) != manifest or chunk.chunk_count != count:
            raise BackupError("chunks from different backups cannot be reassembled together")
        held = by_index.setdefault(chunk.chunk_index, chunk.data)
        if held != chunk.data:
            raise BackupError(f"two different chunks claim index {chunk.chunk_index}")
    missing = sorted(set(range(count)) - by_index.keys())
    if missing:
        raise BackupError(f"backup is incomplete: missing chunks {missing[:8]} of {count}")
    data = b"".join(by_index[index] for index in range(count))
    if not manifest.matches(data):
        raise BackupError("reassembled bytes do not match the backup's payload digest")
    return manifest, data


def verify_restored(
    manifest: BackupManifest, data: bytes, *, system_id: str, system_public: PublicKey
) -> None:
    """DEV-23's end-to-end check, run by `SYS_i` after the last decryption. Raises `BackupError`."""
    if manifest.system_id != system_id:
        raise BackupError(f"restored backup belongs to {manifest.system_id!r}, not {system_id!r}")
    if not manifest.matches(data):
        raise BackupError(
            "restored bytes do not match the payload digest: the data changed after it was "
            "backed up"
        )
    if not manifest.verify(system_public):
        raise BackupError(
            f"the payload digest was not attested by {system_id!r}: data and digest were "
            f"replaced together"
        )


def pack(manifest: BackupManifest, data: bytes) -> bytes:
    """Canonical encoding of a whole backup and its manifest, for the session hops."""
    return encode({"manifest": manifest.to_fields(), "data": data})


def unpack(raw: bytes) -> tuple[BackupManifest, bytes]:
    try:
        decoded = decode(raw)
    except CanonicalEncodingError as exc:
        raise BackupError(f"backup message is not a canonical encoding: {exc}") from exc
    if not isinstance(decoded, dict):
        raise BackupError("backup message is not a mapping")
    manifest = decoded.get("manifest")
    data = decoded.get("data")
    if not isinstance(manifest, dict) or not isinstance(data, bytes):
        raise BackupError("backup message is missing its manifest or data")
    return BackupManifest.from_fields(manifest), data
