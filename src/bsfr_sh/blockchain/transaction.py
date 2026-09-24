"""`Tx_m` / `Tx_i` — the encrypted transaction. Implements Alg. 1 line 2 and Alg. 2 line 7.

Both algorithm lines write the same thing, `E_KU_CSl(Tx)`: a payload encrypted so that only the
cloud server `CS_l` can read it. They differ only in what the payload *is* — Alg. 1 carries
`DT_BU` (a healthcare data backup), Alg. 2 carries a ransomware signature record (`Sig_RW` plus
`FT_RW`). docs/ALGORITHMS.md notes that Alg. 2 lines 3-10 are structurally identical to Alg. 1
lines 2-10 and says to factor the pipeline once. This module is where that happens: one
`encrypt()`, two payload builders.

Encryption is DEV-01's hybrid construction, applied through `crypto.kem.seal_payload` — never by
assembling the wrap and the AEAD separately. `seal_payload` binds the wrapped key and the
ciphertext to each other *and* to the transaction metadata, so a wrapped key lifted from one
transaction onto another fails to open even though every block signature still verifies. That
binding only holds if there is exactly one place that applies it.

What `digest` is
----------------
`Transaction.digest` is the content digest over the *ciphertext side* of the transaction —
everything a verifier can check without holding `CS_l`'s private key. It is what goes into the
Merkle tree, so `MTR` binds the block to its transactions without any node needing to decrypt
them. Miners in M2b validate blocks they cannot read; that is the point.

`digest` is therefore **not** a field the caller supplies. It is derived in `encrypt()` and
recomputed by `verify_digest()`, so a transaction whose digest does not match its own contents
cannot be built through the public API and is detected if one arrives from outside.

Transaction signatures
----------------------
The paper shows no per-transaction signature — only `Sig_βj` over the block (Alg. 1 line 3). We
follow it: authenticity comes from the block signature, and a transaction's integrity comes from
`MTR`. That closes open question Q6. A per-transaction signature would be a deviation and would
need a DEV entry; it is not needed, because a transaction only ever reaches a chain inside a
signed block.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from bsfr_sh.crypto.ecdsa import PrivateKey, PublicKey
from bsfr_sh.crypto.hashing import DOMAIN_TRANSACTION, tagged_h
from bsfr_sh.crypto.kem import HybridCiphertext, KemError, open_payload, seal_payload
from bsfr_sh.util.serialization import (
    TRANSACTION_FIELD_ORDER,
    Value,
    encode,
    encode_transaction,
)

__all__ = [
    "PAYLOAD_TYPE_ANCHOR",
    "PAYLOAD_TYPE_BACKUP",
    "PAYLOAD_TYPE_SIGNATURE_RECORD",
    "BackupPayload",
    "SignatureRecordPayload",
    "Transaction",
    "TransactionError",
    "decrypt",
    "encrypt",
    "encrypt_backup",
    "encrypt_signature_record",
    "read_anchor_record",
    "wrap_anchor_record",
]

#: `DT_BU` — Alg. 1 line 2.
PAYLOAD_TYPE_BACKUP: Final = "DT_BU"
#: `Sig_RW` + `FT_RW` — Alg. 2 line 7.
PAYLOAD_TYPE_SIGNATURE_RECORD: Final = "SIG_RW"
#: M7-5/DEV-33. Not an algorithm line the paper defines — §VIII lists hybrid blockchain as its
#: own future work. See `wrap_anchor_record` for why this payload type is never encrypted.
PAYLOAD_TYPE_ANCHOR: Final = "ANCHOR"

_PAYLOAD_TYPES: Final = frozenset(
    {PAYLOAD_TYPE_BACKUP, PAYLOAD_TYPE_SIGNATURE_RECORD, PAYLOAD_TYPE_ANCHOR}
)


class TransactionError(ValueError):
    """Raised when a transaction is malformed, undecryptable, or fails its digest check."""


# --------------------------------------------------------------------------------------------
# Payloads
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class BackupPayload:
    """`DT_BU` — one chunk of a healthcare data backup from `SYS_i`. Alg. 1 line 2.

    `data` is opaque bytes: this layer neither interprets nor compresses it. `system_id` is the
    `SYS_i` the backup came from, which `recovery.locator.BackupIndex` (DEV-05) keys on — it is
    inside the encrypted payload rather than in the transaction header, so the chain does not
    leak which systems have been backed up and when.

    The last four fields are M3a's (`blockchain.backup` builds and consumes them):

    * `chunk_index` / `chunk_count` — DEV-24. A backup larger than `transaction.payload_bytes`
      spans several transactions; its order is carried explicitly, never inferred from where a
      transaction landed on the chain.
    * `payload_digest` / `attestation` — DEV-23. The digest `SYS_i` took over the *whole* backup
      before it left the device, and its ECDSA signature over that digest. Opaque bytes here;
      `blockchain.backup` defines and checks them.

    Their defaults describe the paper's own record — one transaction, no digest, no attestation.
    Such a record still encrypts, commits and decrypts; `blockchain.backup.reassemble` refuses to
    restore it, because nothing about it can be verified (DEV-23).
    """

    system_id: str
    data: bytes
    captured_at: int
    chunk_index: int = 0
    chunk_count: int = 1
    payload_digest: bytes = b""
    attestation: bytes = b""

    def __post_init__(self) -> None:
        if self.chunk_count < 1:
            raise TransactionError(f"chunk_count must be at least 1, got {self.chunk_count}")
        if not 0 <= self.chunk_index < self.chunk_count:
            raise TransactionError(
                f"chunk_index {self.chunk_index} is outside 0..{self.chunk_count - 1}"
            )

    def to_bytes(self) -> bytes:
        """Canonical plaintext encoding. Order-fixed, so it round-trips exactly."""
        return encode(
            {
                "system_id": self.system_id,
                "data": self.data,
                "captured_at": self.captured_at,
                "chunk_index": self.chunk_index,
                "chunk_count": self.chunk_count,
                "payload_digest": self.payload_digest,
                "attestation": self.attestation,
            }
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> BackupPayload:
        fields = _decode_mapping(raw, _BACKUP_FIELDS)
        return cls(
            system_id=_as_str(fields["system_id"], "system_id"),
            data=_as_bytes(fields["data"], "data"),
            captured_at=_as_int(fields["captured_at"], "captured_at"),
            chunk_index=_as_int(fields["chunk_index"], "chunk_index"),
            chunk_count=_as_int(fields["chunk_count"], "chunk_count"),
            payload_digest=_as_bytes(fields["payload_digest"], "payload_digest"),
            attestation=_as_bytes(fields["attestation"], "attestation"),
        )


_BACKUP_FIELDS: Final = (
    "system_id",
    "data",
    "captured_at",
    "chunk_index",
    "chunk_count",
    "payload_digest",
    "attestation",
)


@dataclass(frozen=True)
class SignatureRecordPayload:
    """`Sig_RW` + `FT_RW` — one ransomware sample record from the honeypot. Alg. 2 line 7.

    `content_digest` and `attestation` are DEV-03's two senses of `Sig_RW`, kept apart: the
    identification digest and the `CS_l` authenticity signature. `features` is `FT_RW`. M3b builds
    the real values; this layer only transports them, so the fields are typed as bytes and a
    float vector rather than as honeypot types — `blockchain` must not depend on `honeypot`.

    The last three fields are M3b's, and they are what makes the vector readable by a consumer
    that did not build it (`detection.dataset.HoneypotBackend` in M4, docs/ARCHITECTURE.md
    §honeypot):

    * `schema` names the feature order, e.g. `"ft_rw.v1"`. A bare vector of floats with no schema
      is not a dataset, it is a guess.
    * `missing_mask` — bit `i` set means `features[i]` was **not observed**. The canonical encoder
      rejects NaN, and imputing here would hide the honeypot's blind spots inside the data, so
      absence is carried explicitly and the consumer decides what to do with it (DEV-27).
    * `label` is the emulator's ground truth, `"RW"` or `"benign"`, and is **metadata, never a
      feature**. Real deployments get it from an analyst; ours knows it because it synthesized
      the sample (DEV-27).

    The defaults keep M2a's five-field construction valid.
    """

    sample_id: str
    content_digest: bytes
    attestation: bytes
    features: tuple[float, ...]
    collected_at: int
    schema: str = ""
    missing_mask: int = 0
    label: str = ""

    def __post_init__(self) -> None:
        if self.missing_mask < 0:
            raise TransactionError(f"missing_mask must be non-negative, got {self.missing_mask}")
        if self.missing_mask >= 1 << len(self.features):
            raise TransactionError(
                f"missing_mask {self.missing_mask:#x} has bits set beyond the "
                f"{len(self.features)} features it describes"
            )

    def to_bytes(self) -> bytes:
        return encode(
            {
                "sample_id": self.sample_id,
                "content_digest": self.content_digest,
                "attestation": self.attestation,
                "features": list(self.features),
                "collected_at": self.collected_at,
                "schema": self.schema,
                "missing_mask": self.missing_mask,
                "label": self.label,
            }
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> SignatureRecordPayload:
        fields = _decode_mapping(raw, _RECORD_FIELDS)
        features = fields["features"]
        if not isinstance(features, list):
            raise TransactionError("payload field 'features' is not a list")
        return cls(
            sample_id=_as_str(fields["sample_id"], "sample_id"),
            content_digest=_as_bytes(fields["content_digest"], "content_digest"),
            attestation=_as_bytes(fields["attestation"], "attestation"),
            features=tuple(_as_float(value, "features") for value in features),
            collected_at=_as_int(fields["collected_at"], "collected_at"),
            schema=_as_str(fields["schema"], "schema"),
            missing_mask=_as_int(fields["missing_mask"], "missing_mask"),
            label=_as_str(fields["label"], "label"),
        )


_RECORD_FIELDS: Final = (
    "sample_id",
    "content_digest",
    "attestation",
    "features",
    "collected_at",
    "schema",
    "missing_mask",
    "label",
)


# --------------------------------------------------------------------------------------------
# Transaction
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Transaction:
    """An encrypted transaction, ready to go into a block.

    Field order matches `util.serialization.TRANSACTION_FIELD_ORDER`, which is asserted below so
    the dataclass and the encoder cannot drift apart.

    Frozen: once a transaction is in a Merkle tree, changing it changes `MTR` and invalidates
    every block hash downstream. `bytes` fields are immutable, so this is genuinely immutable
    rather than shallowly so.
    """

    tx_id: str
    payload_type: str
    ciphertext: bytes
    wrapped_key: bytes
    nonce: bytes
    digest: bytes
    created_at: int

    def __post_init__(self) -> None:
        if self.payload_type not in _PAYLOAD_TYPES:
            raise TransactionError(
                f"unknown payload_type {self.payload_type!r}; expected one of "
                f"{sorted(_PAYLOAD_TYPES)}"
            )
        if not self.tx_id:
            raise TransactionError("tx_id must be non-empty")

    def metadata(self) -> dict[str, Value]:
        """The AAD bound into both halves of the DEV-01 construction.

        Everything that identifies *which* transaction this is, and nothing that is itself
        encrypted. Both `encrypt()` and `decrypt()` derive it the same way, so a mismatch is
        impossible rather than merely unlikely.
        """
        return {
            "tx_id": self.tx_id,
            "payload_type": self.payload_type,
            "created_at": self.created_at,
        }

    def to_fields(self) -> dict[str, Value]:
        """The transaction as a field mapping, in the declared order."""
        return {
            "tx_id": self.tx_id,
            "payload_type": self.payload_type,
            "ciphertext": self.ciphertext,
            "wrapped_key": self.wrapped_key,
            "nonce": self.nonce,
            "digest": self.digest,
            "created_at": self.created_at,
        }

    def compute_digest(self) -> bytes:
        """Recompute `digest` from the ciphertext side of this transaction.

        Covers everything except `digest` itself — a digest that covered itself would be
        self-referential and unverifiable.
        """
        return _content_digest(
            tx_id=self.tx_id,
            payload_type=self.payload_type,
            ciphertext=self.ciphertext,
            wrapped_key=self.wrapped_key,
            nonce=self.nonce,
            created_at=self.created_at,
        )

    def verify_digest(self) -> bool:
        """Whether `digest` matches this transaction's contents.

        `Chain.append` does not call this per transaction: `MTR` is computed over `digest`, so a
        transaction whose digest is wrong changes the Merkle root and is caught there. This is
        for transactions arriving from outside — a decoded chain, a test fixture, M2b's network.
        """
        return self.digest == self.compute_digest()

    def encoded(self) -> bytes:
        """Canonical encoding of the whole transaction, for block serialization."""
        return encode_transaction(self.to_fields())


# The dataclass and the encoder must agree on field order forever; PROJECT_STATE flagged drift
# here as the failure that silently invalidates every block hash. Checked at import.
assert tuple(f for f in Transaction.__dataclass_fields__) == TRANSACTION_FIELD_ORDER, (
    "Transaction fields have drifted from util.serialization.TRANSACTION_FIELD_ORDER"
)


def _content_digest(
    *,
    tx_id: str,
    payload_type: str,
    ciphertext: bytes,
    wrapped_key: bytes,
    nonce: bytes,
    created_at: int,
) -> bytes:
    """Domain-separated digest over the publicly verifiable part of a transaction."""
    return tagged_h(
        DOMAIN_TRANSACTION,
        encode(tx_id),
        encode(payload_type),
        ciphertext,
        wrapped_key,
        nonce,
        encode(created_at),
    )


# --------------------------------------------------------------------------------------------
# The pipeline — one encrypt, two payload builders
# --------------------------------------------------------------------------------------------
def encrypt(
    *,
    recipient: PublicKey,
    tx_id: str,
    payload_type: str,
    plaintext: bytes,
    created_at: int,
) -> Transaction:
    """Encrypt a payload to `CS_l` and build the transaction. Alg. 1 line 2 / Alg. 2 line 7.

    `recipient` is `KU_CSl`. The metadata bound as AEAD associated data is derived from the
    transaction's own identifying fields, so the returned transaction can only be decrypted as
    itself.
    """
    if payload_type not in _PAYLOAD_TYPES:
        raise TransactionError(
            f"unknown payload_type {payload_type!r}; expected one of {sorted(_PAYLOAD_TYPES)}"
        )
    metadata: dict[str, Value] = {
        "tx_id": tx_id,
        "payload_type": payload_type,
        "created_at": created_at,
    }
    sealed = seal_payload(recipient, plaintext, metadata)
    digest = _content_digest(
        tx_id=tx_id,
        payload_type=payload_type,
        ciphertext=sealed.ciphertext,
        wrapped_key=sealed.wrapped_key,
        nonce=sealed.nonce,
        created_at=created_at,
    )
    return Transaction(
        tx_id=tx_id,
        payload_type=payload_type,
        ciphertext=sealed.ciphertext,
        wrapped_key=sealed.wrapped_key,
        nonce=sealed.nonce,
        digest=digest,
        created_at=created_at,
    )


def encrypt_backup(
    *, recipient: PublicKey, tx_id: str, payload: BackupPayload, created_at: int
) -> Transaction:
    """Implements Alg. 1, line 2 — `DT_BU` into `E_KU_CSl(Tx_m)`."""
    return encrypt(
        recipient=recipient,
        tx_id=tx_id,
        payload_type=PAYLOAD_TYPE_BACKUP,
        plaintext=payload.to_bytes(),
        created_at=created_at,
    )


def encrypt_signature_record(
    *, recipient: PublicKey, tx_id: str, payload: SignatureRecordPayload, created_at: int
) -> Transaction:
    """Implements Alg. 2, line 7 — `Sig_RW` + `FT_RW` into `E_KU_CSl(Tx_i)`."""
    return encrypt(
        recipient=recipient,
        tx_id=tx_id,
        payload_type=PAYLOAD_TYPE_SIGNATURE_RECORD,
        plaintext=payload.to_bytes(),
        created_at=created_at,
    )


def wrap_anchor_record(*, tx_id: str, plaintext: bytes, created_at: int) -> Transaction:
    """Carry a public-chain `AnchorRecord` (M7-5, `blockchain.anchor`) as a transaction.

    Every other payload here is `E_KU_CSl(Tx)` — encrypted so only one cloud server can read it
    (Alg. 1 line 2 / Alg. 2 line 7). An anchor record is the opposite: its whole purpose is
    external verifiability, so encrypting it would defeat the point of publishing it. `ciphertext`
    therefore holds `plaintext` directly and `wrapped_key`/`nonce` are empty — the tell, on
    inspection, that this transaction was never sealed to a recipient at all. `digest` still
    covers the same content-digest construction `encrypt()` produces, so the anchor chain's
    `Block`/`Chain` machinery (Merkle root, header hash, signature) is unmodified by this being
    public.
    """
    digest = _content_digest(
        tx_id=tx_id,
        payload_type=PAYLOAD_TYPE_ANCHOR,
        ciphertext=plaintext,
        wrapped_key=b"",
        nonce=b"",
        created_at=created_at,
    )
    return Transaction(
        tx_id=tx_id,
        payload_type=PAYLOAD_TYPE_ANCHOR,
        ciphertext=plaintext,
        wrapped_key=b"",
        nonce=b"",
        digest=digest,
        created_at=created_at,
    )


def read_anchor_record(transaction: Transaction) -> bytes:
    """Recover an anchor record's plaintext. No key needed — see `wrap_anchor_record`."""
    if transaction.payload_type != PAYLOAD_TYPE_ANCHOR:
        raise TransactionError(
            f"transaction {transaction.tx_id!r} is not an anchor record "
            f"(payload_type={transaction.payload_type!r})"
        )
    if not transaction.verify_digest():
        raise TransactionError(
            f"anchor record {transaction.tx_id!r} digest does not match its contents"
        )
    return transaction.ciphertext


def decrypt(recipient: PrivateKey, transaction: Transaction) -> bytes:
    """Recover a transaction's plaintext. Only `CS_l` can do this.

    Verifies the digest first: a transaction whose digest does not cover its own ciphertext has
    been altered somewhere that `MTR` would have caught, and decrypting it anyway would be
    answering a question nobody should be asking.
    """
    if not transaction.verify_digest():
        raise TransactionError(
            f"transaction {transaction.tx_id!r} digest does not match its contents"
        )
    hybrid = HybridCiphertext(
        wrapped_key=transaction.wrapped_key,
        nonce=transaction.nonce,
        ciphertext=transaction.ciphertext,
    )
    try:
        return open_payload(recipient, hybrid, transaction.metadata())
    except KemError as exc:
        raise TransactionError(f"cannot decrypt transaction {transaction.tx_id!r}: {exc}") from exc


# --------------------------------------------------------------------------------------------
# Decoding helpers
# --------------------------------------------------------------------------------------------
def _decode_mapping(raw: bytes, expected: tuple[str, ...]) -> dict[str, Value]:
    from bsfr_sh.util.serialization import CanonicalEncodingError, decode

    try:
        decoded = decode(raw)
    except CanonicalEncodingError as exc:
        raise TransactionError(f"payload is not a canonical encoding: {exc}") from exc
    if not isinstance(decoded, dict):
        raise TransactionError("payload is not a mapping")
    missing = [name for name in expected if name not in decoded]
    if missing:
        raise TransactionError(f"payload is missing {missing}")
    return decoded


def _as_str(value: Value, name: str) -> str:
    if not isinstance(value, str):
        raise TransactionError(f"payload field {name!r} is not a string")
    return value


def _as_bytes(value: Value, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TransactionError(f"payload field {name!r} is not bytes")
    return value


def _as_int(value: Value, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TransactionError(f"payload field {name!r} is not an integer")
    return value


def _as_float(value: Value, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TransactionError(f"payload field {name!r} contains a non-numeric entry")
    return float(value)
