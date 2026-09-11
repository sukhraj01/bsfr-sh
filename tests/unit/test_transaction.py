"""`blockchain.transaction` — Alg. 1 line 2 and Alg. 2 line 7.

§V mapping: §V-4 (leakage — only `CS_l` can read a transaction) is `test_tx_confidentiality.py`.
This file covers the structure: the digest, the two payload builders, and the round trip.
"""

from __future__ import annotations

import pytest

from bsfr_sh.blockchain.transaction import (
    PAYLOAD_TYPE_BACKUP,
    PAYLOAD_TYPE_SIGNATURE_RECORD,
    BackupPayload,
    SignatureRecordPayload,
    Transaction,
    TransactionError,
    decrypt,
    encrypt_backup,
    encrypt_signature_record,
)
from bsfr_sh.crypto.ecdsa import KeyPair
from bsfr_sh.util.serialization import TRANSACTION_FIELD_ORDER

BACKUP = BackupPayload(
    system_id="SYS_1", data=b"patient record fragment" * 100, captured_at=1_757_548_800
)
RECORD = SignatureRecordPayload(
    sample_id="RW-0001",
    content_digest=b"\x11" * 32,
    attestation=b"\x22" * 70,
    features=(0.1, 2.5, -3.0, 0.0),
    collected_at=1_757_548_801,
)


def backup_tx(keys: KeyPair, tx_id: str = "tx-0001") -> Transaction:
    return encrypt_backup(recipient=keys.public, tx_id=tx_id, payload=BACKUP, created_at=1)


# --------------------------------------------------------------------------------------------
# Structure
# --------------------------------------------------------------------------------------------
def test_field_order_matches_the_declared_encoding() -> None:
    """The dataclass and `util.serialization` must never drift — block hashes depend on it."""
    assert tuple(Transaction.__dataclass_fields__) == TRANSACTION_FIELD_ORDER


def test_transaction_is_frozen(cs1_keys: KeyPair) -> None:
    tx = backup_tx(cs1_keys)
    with pytest.raises(Exception, match=r"frozen|immutable|cannot assign"):
        tx.tx_id = "other"  # type: ignore[misc]


def test_unknown_payload_type_is_rejected(cs1_keys: KeyPair) -> None:
    tx = backup_tx(cs1_keys)
    with pytest.raises(TransactionError, match="unknown payload_type"):
        Transaction(**{**tx.to_fields(), "payload_type": "NOT_A_TYPE"})


def test_empty_tx_id_is_rejected(cs1_keys: KeyPair) -> None:
    tx = backup_tx(cs1_keys)
    with pytest.raises(TransactionError, match="tx_id must be non-empty"):
        Transaction(**{**tx.to_fields(), "tx_id": ""})


# --------------------------------------------------------------------------------------------
# Round trip — the same pipeline, two payloads
# --------------------------------------------------------------------------------------------
def test_backup_round_trip(cs1_keys: KeyPair) -> None:
    """Alg. 1 line 2."""
    tx = encrypt_backup(recipient=cs1_keys.public, tx_id="tx-0001", payload=BACKUP, created_at=1)
    assert tx.payload_type == PAYLOAD_TYPE_BACKUP
    assert BackupPayload.from_bytes(decrypt(cs1_keys.private, tx)) == BACKUP


def test_signature_record_round_trip(cs1_keys: KeyPair) -> None:
    """Alg. 2 line 7 — different payload, identical pipeline."""
    tx = encrypt_signature_record(
        recipient=cs1_keys.public, tx_id="tx-0002", payload=RECORD, created_at=2
    )
    assert tx.payload_type == PAYLOAD_TYPE_SIGNATURE_RECORD
    assert SignatureRecordPayload.from_bytes(decrypt(cs1_keys.private, tx)) == RECORD


def test_both_payload_types_use_the_same_pipeline(cs1_keys: KeyPair) -> None:
    """docs/ALGORITHMS.md: factor once. Only the payload differs, so the shapes must match."""
    a = encrypt_backup(recipient=cs1_keys.public, tx_id="t", payload=BACKUP, created_at=1)
    b = encrypt_signature_record(recipient=cs1_keys.public, tx_id="t", payload=RECORD, created_at=1)
    assert len(a.digest) == len(b.digest) == 32
    assert len(a.nonce) == len(b.nonce) == 12
    assert a.wrapped_key and b.wrapped_key


def test_empty_payload_round_trips(cs1_keys: KeyPair) -> None:
    empty = BackupPayload(system_id="SYS_1", data=b"", captured_at=0)
    tx = encrypt_backup(recipient=cs1_keys.public, tx_id="tx", payload=empty, created_at=0)
    assert BackupPayload.from_bytes(decrypt(cs1_keys.private, tx)) == empty


# --------------------------------------------------------------------------------------------
# Digest
# --------------------------------------------------------------------------------------------
def test_digest_is_derived_not_supplied(cs1_keys: KeyPair) -> None:
    assert backup_tx(cs1_keys).verify_digest()


def test_digest_covers_every_ciphertext_side_field(cs1_keys: KeyPair) -> None:
    """Change any field the digest covers and the digest must stop matching."""
    tx = backup_tx(cs1_keys)
    mutations = {
        "tx_id": "tx-9999",
        "ciphertext": tx.ciphertext[:-1] + bytes([tx.ciphertext[-1] ^ 0x01]),
        "wrapped_key": tx.wrapped_key[:-1] + bytes([tx.wrapped_key[-1] ^ 0x01]),
        "nonce": bytes(12),
        "created_at": tx.created_at + 1,
    }
    for name, value in mutations.items():
        altered = Transaction(**{**tx.to_fields(), name: value})
        assert not altered.verify_digest(), f"digest does not cover {name}"


def test_digest_differs_between_payload_types(cs1_keys: KeyPair) -> None:
    tx = backup_tx(cs1_keys)
    relabelled = Transaction(**{**tx.to_fields(), "payload_type": PAYLOAD_TYPE_SIGNATURE_RECORD})
    assert not relabelled.verify_digest()


def test_two_encryptions_of_one_payload_differ(cs1_keys: KeyPair) -> None:
    """Fresh data key and ephemeral key per transaction, so ciphertexts are not comparable."""
    first = backup_tx(cs1_keys, "tx-a")
    second = backup_tx(cs1_keys, "tx-a")
    assert first.ciphertext != second.ciphertext
    assert first.digest != second.digest


# --------------------------------------------------------------------------------------------
# Payload encoding
# --------------------------------------------------------------------------------------------
def test_payload_round_trips_through_bytes() -> None:
    assert BackupPayload.from_bytes(BACKUP.to_bytes()) == BACKUP
    assert SignatureRecordPayload.from_bytes(RECORD.to_bytes()) == RECORD


def test_malformed_payload_is_rejected() -> None:
    with pytest.raises(TransactionError, match="not a canonical encoding"):
        BackupPayload.from_bytes(b"not an encoding")


def test_payload_missing_a_field_is_rejected() -> None:
    from bsfr_sh.util.serialization import encode

    with pytest.raises(TransactionError, match="missing"):
        BackupPayload.from_bytes(encode({"system_id": "SYS_1"}))


def test_payload_with_a_wrong_field_type_is_rejected() -> None:
    from bsfr_sh.util.serialization import encode

    raw = encode({"system_id": 7, "data": b"x", "captured_at": 1})
    with pytest.raises(TransactionError, match="not a string"):
        BackupPayload.from_bytes(raw)
