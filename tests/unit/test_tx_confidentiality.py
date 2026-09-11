"""§V-4 confidentiality and leakage, at the transaction level.

The paper's `E_KU_CSl(Tx)` promises that only the cloud server `CS_l` can read a transaction.
DEV-01 keeps that promise with a hybrid construction; these tests check the promise rather than
the construction. The key-swap cases matter most: they describe an attack that leaves every
ECDSA signature in the chain verifying, so `Sig_βj` alone does not substantiate §V-4.

Named to match the test file docs/EXPERIMENTS.md Target 5 maps §V-4 to.
"""

from __future__ import annotations

import pytest

from bsfr_sh.blockchain.transaction import (
    BackupPayload,
    Transaction,
    TransactionError,
    decrypt,
    encrypt_backup,
)
from bsfr_sh.crypto.ecdsa import KeyPair

PAYLOAD = BackupPayload(system_id="SYS_1", data=b"confidential record" * 64, captured_at=1)
OTHER = BackupPayload(system_id="SYS_2", data=b"someone else's record" * 64, captured_at=2)


def test_only_the_named_cloud_server_can_decrypt(cs1_keys: KeyPair, cs2_keys: KeyPair) -> None:
    tx = encrypt_backup(recipient=cs1_keys.public, tx_id="tx-1", payload=PAYLOAD, created_at=1)
    assert BackupPayload.from_bytes(decrypt(cs1_keys.private, tx)) == PAYLOAD
    with pytest.raises(TransactionError, match="cannot decrypt"):
        decrypt(cs2_keys.private, tx)


def test_an_attacker_key_cannot_decrypt(cs1_keys: KeyPair, attacker_keys: KeyPair) -> None:
    tx = encrypt_backup(recipient=cs1_keys.public, tx_id="tx-1", payload=PAYLOAD, created_at=1)
    with pytest.raises(TransactionError, match="cannot decrypt"):
        decrypt(attacker_keys.private, tx)


def test_the_plaintext_does_not_appear_in_the_transaction(cs1_keys: KeyPair) -> None:
    tx = encrypt_backup(recipient=cs1_keys.public, tx_id="tx-1", payload=PAYLOAD, created_at=1)
    on_chain = tx.encoded()
    assert PAYLOAD.data[:32] not in on_chain
    assert b"SYS_1" not in on_chain  # the system id is inside the payload, not the header


def test_tampered_ciphertext_is_rejected(cs1_keys: KeyPair) -> None:
    tx = encrypt_backup(recipient=cs1_keys.public, tx_id="tx-1", payload=PAYLOAD, created_at=1)
    flipped = bytearray(tx.ciphertext)
    flipped[0] ^= 0x01
    altered = Transaction(**{**tx.to_fields(), "ciphertext": bytes(flipped)})
    with pytest.raises(TransactionError, match="digest does not match"):
        decrypt(cs1_keys.private, altered)


def test_a_recomputed_digest_does_not_rescue_a_tampered_ciphertext(cs1_keys: KeyPair) -> None:
    """An attacker who fixes up the digest still fails: the AEAD tag is not forgeable.

    Fixing the digest is what a serious attacker would do, since the digest is public and
    recomputable. The confidentiality claim has to survive that, and it does — the digest is an
    integrity aid for `MTR`, not the thing protecting the payload.
    """
    tx = encrypt_backup(recipient=cs1_keys.public, tx_id="tx-1", payload=PAYLOAD, created_at=1)
    flipped = bytearray(tx.ciphertext)
    flipped[0] ^= 0x01
    altered = Transaction(**{**tx.to_fields(), "ciphertext": bytes(flipped)})
    repaired = Transaction(**{**altered.to_fields(), "digest": altered.compute_digest()})
    assert repaired.verify_digest()
    with pytest.raises(TransactionError, match="cannot decrypt"):
        decrypt(cs1_keys.private, repaired)


def test_a_wrapped_key_cannot_be_moved_between_transactions(cs1_keys: KeyPair) -> None:
    """DEV-01's binding, exercised at the transaction layer rather than the KEM layer.

    Both transactions are addressed to the same server, so key ownership is not what stops this.
    The AAD binding is.
    """
    first = encrypt_backup(recipient=cs1_keys.public, tx_id="tx-1", payload=PAYLOAD, created_at=1)
    second = encrypt_backup(recipient=cs1_keys.public, tx_id="tx-2", payload=OTHER, created_at=2)
    swapped = Transaction(**{**second.to_fields(), "wrapped_key": first.wrapped_key})
    repaired = Transaction(**{**swapped.to_fields(), "digest": swapped.compute_digest()})
    with pytest.raises(TransactionError, match="cannot decrypt"):
        decrypt(cs1_keys.private, repaired)


def test_relabelling_a_transaction_breaks_decryption(cs1_keys: KeyPair) -> None:
    """`tx_id` and `created_at` are bound as associated data, so the header cannot be rewritten."""
    tx = encrypt_backup(recipient=cs1_keys.public, tx_id="tx-1", payload=PAYLOAD, created_at=1)
    relabelled = Transaction(**{**tx.to_fields(), "tx_id": "tx-9"})
    repaired = Transaction(**{**relabelled.to_fields(), "digest": relabelled.compute_digest()})
    with pytest.raises(TransactionError, match="cannot decrypt"):
        decrypt(cs1_keys.private, repaired)
