"""`blockchain.backup`: DEV-24 chunking and DEV-23 attestation, off-chain."""

from __future__ import annotations

import dataclasses
import random

import pytest

from bsfr_sh.blockchain.backup import (
    BackupError,
    attest,
    chunk_tx_id,
    manifest_of,
    pack,
    payload_digest,
    reassemble,
    split,
    unpack,
    verify_restored,
)
from bsfr_sh.blockchain.transaction import BackupPayload, TransactionError

DATA = bytes(range(256)) * 3 + b"tail"  # 772 bytes


def _manifest(keys, data: bytes = DATA, system_id: str = "SYS_1", captured_at: int = 100):
    return attest(keys.private, system_id=system_id, captured_at=captured_at, data=data)


# -- DEV-24: split -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("size", "chunk", "count", "last"),
    [
        (0, 4, 1, 0),
        (1, 4, 1, 1),
        (4, 4, 1, 4),
        (5, 4, 2, 1),
        (8, 4, 2, 4),
        (9, 4, 3, 1),
        (772, 100, 8, 72),
    ],
)
def test_split_sizes_and_the_remainder(sys_keys, size, chunk, count, last) -> None:
    data = bytes(i % 251 for i in range(size))
    chunks = split(_manifest(sys_keys, data), data, chunk_bytes=chunk)
    assert len(chunks) == count
    assert [c.chunk_index for c in chunks] == list(range(count))
    assert {c.chunk_count for c in chunks} == {count}
    assert all(len(c.data) == chunk for c in chunks[:-1])
    assert len(chunks[-1].data) == last
    assert b"".join(c.data for c in chunks) == data


def test_an_empty_backup_is_one_empty_chunk_and_round_trips(sys_keys) -> None:
    manifest = _manifest(sys_keys, b"")
    assert reassemble(split(manifest, b"", chunk_bytes=8)) == (manifest, b"")


def test_split_refuses_data_its_manifest_does_not_describe(sys_keys) -> None:
    with pytest.raises(BackupError, match="does not match"):
        split(_manifest(sys_keys), DATA + b"!", chunk_bytes=50)
    with pytest.raises(BackupError, match="positive"):
        split(_manifest(sys_keys), DATA, chunk_bytes=0)


# -- DEV-24: reassemble ------------------------------------------------------------------------
@pytest.mark.parametrize("seed", range(10))
def test_reassembly_is_independent_of_arrival_order(sys_keys, seed) -> None:
    manifest = _manifest(sys_keys)
    chunks = list(split(manifest, DATA, chunk_bytes=50))
    random.Random(seed).shuffle(chunks)
    assert reassemble(chunks) == (manifest, DATA)


def test_a_byte_identical_duplicate_is_accepted(sys_keys) -> None:
    chunks = split(_manifest(sys_keys), DATA, chunk_bytes=50)
    assert reassemble((*chunks, chunks[3]))[1] == DATA


def test_two_different_chunks_at_one_index_are_refused(sys_keys) -> None:
    chunks = split(_manifest(sys_keys), DATA, chunk_bytes=50)
    impostor = dataclasses.replace(chunks[3], data=b"x" * 50)
    with pytest.raises(BackupError, match="two different chunks claim index 3"):
        reassemble((*chunks, impostor))


def test_a_missing_chunk_is_refused(sys_keys) -> None:
    chunks = split(_manifest(sys_keys), DATA, chunk_bytes=50)
    with pytest.raises(BackupError, match="incomplete"):
        reassemble(chunks[:4] + chunks[5:])


def test_chunks_of_two_backups_do_not_mix(sys_keys) -> None:
    ours = split(_manifest(sys_keys), DATA, chunk_bytes=50)
    other_data = DATA[::-1]
    theirs = split(_manifest(sys_keys, other_data), other_data, chunk_bytes=50)
    with pytest.raises(BackupError, match="different backups"):
        reassemble((*ours[:-1], theirs[-1]))


def test_the_paper_shaped_record_is_refused() -> None:
    """DEV-23: one transaction, no digest, no attestation. It decrypts, and cannot be verified."""
    with pytest.raises(BackupError, match="unverifiable"):
        reassemble([BackupPayload("SYS_1", DATA, 100)])


def test_consistent_chunks_that_do_not_match_the_digest_are_refused(sys_keys) -> None:
    manifest = _manifest(sys_keys)
    forged = tuple(
        dataclasses.replace(c, data=bytes(len(c.data)))
        for c in split(manifest, DATA, chunk_bytes=50)
    )
    with pytest.raises(BackupError, match="do not match"):
        reassemble(forged)


# -- DEV-23: end to end ------------------------------------------------------------------------
def test_verify_restored_accepts_the_genuine_backup(sys_keys) -> None:
    verify_restored(_manifest(sys_keys), DATA, system_id="SYS_1", system_public=sys_keys.public)


def test_verify_restored_rejects_another_systems_backup(sys_keys) -> None:
    with pytest.raises(BackupError, match="belongs to"):
        verify_restored(_manifest(sys_keys), DATA, system_id="SYS_2", system_public=sys_keys.public)


def test_verify_restored_rejects_changed_bytes(sys_keys) -> None:
    with pytest.raises(BackupError, match="payload digest"):
        verify_restored(
            _manifest(sys_keys), DATA[:-1] + b"?", system_id="SYS_1", system_public=sys_keys.public
        )


def test_data_and_digest_replaced_together_fail_the_attestation(sys_keys) -> None:
    """Why DEV-23 signs: a dishonest server can recompute the digest, not the signature."""
    genuine = _manifest(sys_keys)
    forged_data = b"ransom note"
    forged = dataclasses.replace(genuine, payload_digest=payload_digest("SYS_1", 100, forged_data))
    assert forged.matches(forged_data)
    with pytest.raises(BackupError, match="not attested"):
        verify_restored(forged, forged_data, system_id="SYS_1", system_public=sys_keys.public)


def test_an_attestation_by_another_key_fails(sys_keys, attacker_keys) -> None:
    manifest = attest(attacker_keys.private, system_id="SYS_1", captured_at=100, data=DATA)
    with pytest.raises(BackupError, match="not attested"):
        verify_restored(manifest, DATA, system_id="SYS_1", system_public=sys_keys.public)


# -- identifiers and encodings -----------------------------------------------------------------
def test_backup_id_is_bound_to_system_and_time(sys_keys) -> None:
    ids = {_manifest(sys_keys, DATA, s, t).backup_id for s in ("SYS_1", "SYS_2") for t in (1, 2)}
    assert len(ids) == 4


def test_chunk_tx_ids_are_unique_and_do_not_name_the_system(sys_keys) -> None:
    ids = [chunk_tx_id(c) for c in split(_manifest(sys_keys), DATA, chunk_bytes=50)]
    assert len(set(ids)) == len(ids)
    assert not any("SYS" in i for i in ids)


def test_pack_round_trips_and_garbage_is_refused(sys_keys) -> None:
    manifest = _manifest(sys_keys)
    assert unpack(pack(manifest, DATA)) == (manifest, DATA)
    with pytest.raises(BackupError):
        unpack(b"garbage")


def test_a_chunk_carries_its_fields_through_bytes(sys_keys) -> None:
    chunk = split(_manifest(sys_keys), DATA, chunk_bytes=50)[2]
    assert BackupPayload.from_bytes(chunk.to_bytes()) == chunk
    assert manifest_of(chunk) == _manifest(sys_keys)


@pytest.mark.parametrize(("index", "count"), [(-1, 1), (1, 1), (0, 0)])
def test_chunk_position_must_be_inside_the_count(index, count) -> None:
    with pytest.raises(TransactionError):
        BackupPayload("SYS_1", b"", 1, chunk_index=index, chunk_count=count)
