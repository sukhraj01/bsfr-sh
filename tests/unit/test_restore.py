"""`recovery.restore` + `framework.phase5_recovery`: Alg. 5 end to end over a direct-append chain.

What the prompt required, and where:
* wipe → restore → byte-identical: `test_a_wiped_system_is_restored_byte_identical_over_two_hops`
* chunks committed out of order: `test_restore_with_chunks_committed_in_reverse_order`
* one system cannot recover another's: the four `..._another_system...` tests
* tampered ciphertext caught at restore: `test_tampered_ciphertext_is_caught_at_restore`
* payload digest mismatch: `test_a_payload_changed_between_the_hops_fails_the_digest_check`

The consensus path is in `test_phase1_backup.py` and `tests/integration/`.
"""

from __future__ import annotations

import dataclasses

import pytest
from m3a_harness import (
    append_in_blocks,
    back_up_directly,
    collect_transactions,
    dtbu_chain,
    make_server,
    make_system,
    tamper_ciphertext,
)

from bsfr_sh.blockchain.backup import pack, payload_digest, unpack
from bsfr_sh.blockchain.transaction import BackupPayload, encrypt_backup
from bsfr_sh.crypto.channel import ChannelError
from bsfr_sh.framework import phase5_recovery as phase5
from bsfr_sh.framework.entities import establish_session
from bsfr_sh.recovery import restore as alg5
from bsfr_sh.recovery.locator import BackupIndex, RecoveryError, identify

SIZES = {1: 40, 2: 100, 3: 0}


@pytest.fixture
def world():
    chain = dtbu_chain()
    key_holder, front = make_server(10), make_server(11)
    systems = {i: make_system(i, size) for i, size in SIZES.items()}
    back_up_directly(chain, list(systems.values()), key_holder)
    originals = {i: s.data for i, s in systems.items()}
    return chain, key_holder, front, systems, originals


def _up_to_transfer(world, system_id: str = "SYS_2"):
    """Alg. 5 lines 1-4 by hand, returning the transfer envelope `CS_l` receives."""
    chain, key_holder, front, systems, _ = world
    for system in systems.values():
        if not system.has_session(front.identity):
            establish_session(system, front)
    establish_session(front, key_holder)
    plan = alg5.begin(system_id, identify(chain, system_id, decrypt=key_holder.decrypt))
    manifest, data = alg5.request_decrypt(chain, plan, key_holder.decrypt)
    return alg5.transfer(manifest, data, key_holder.channel(front.identity))


# -- the round trip ----------------------------------------------------------------------------
def test_a_wiped_system_is_restored_byte_identical_over_two_hops(world) -> None:
    chain, key_holder, front, systems, originals = world
    systems[2].wipe()
    assert systems[2].data is None
    assert not systems[2].has_session(key_holder.identity)
    report = phase5.run(system=systems[2], front=front, key_holder=key_holder, chain=chain)
    assert systems[2].data == originals[2]
    assert (report.hops, report.located_by, report.chunk_count) == (2, "scan", 7)
    assert {i: s.data for i, s in systems.items()} == originals


def test_an_empty_backup_restores_to_empty_not_to_absent(world) -> None:
    chain, key_holder, front, systems, _ = world
    systems[3].wipe()
    phase5.run(system=systems[3], front=front, key_holder=key_holder, chain=chain)
    assert systems[3].data == b""


def test_one_server_in_both_roles_skips_the_fidelity_hop(world) -> None:
    chain, key_holder, _, systems, originals = world
    systems[1].wipe()
    report = phase5.run(system=systems[1], front=key_holder, key_holder=key_holder, chain=chain)
    assert report.hops == 1
    assert systems[1].data == originals[1]


def test_the_index_path_restores_the_same_bytes(world) -> None:
    chain, key_holder, front, systems, originals = world
    index = BackupIndex(key_holder.decrypt)
    index.sync(chain)
    systems[2].wipe()
    report = phase5.run(
        system=systems[2], front=front, key_holder=key_holder, chain=chain, index=index
    )
    assert report.located_by == "index"
    assert systems[2].data == originals[2]


def test_the_newest_complete_backup_is_restored(world) -> None:
    chain, key_holder, front, systems, _ = world
    systems[1].data = b"a newer capture"
    back_up_directly(chain, [systems[1]], key_holder, captured_at=200)
    systems[1].wipe()
    report = phase5.run(system=systems[1], front=front, key_holder=key_holder, chain=chain)
    assert systems[1].data == b"a newer capture"
    assert report.captured_at == 200


def test_a_newer_incomplete_backup_is_passed_over_and_reported(world) -> None:
    chain, key_holder, front, systems, originals = world
    systems[1].data = b"a newer capture that never finished committing"  # 3 chunks
    append_in_blocks(chain, collect_transactions([systems[1]], key_holder, captured_at=200)[:-1])
    systems[1].wipe()
    report = phase5.run(system=systems[1], front=front, key_holder=key_holder, chain=chain)
    assert systems[1].data == originals[1]
    assert len(report.skipped) == 1


def test_restore_with_chunks_committed_in_reverse_order() -> None:
    chain = dtbu_chain()
    key_holder, front = make_server(10), make_server(11)
    system = make_system(5, 100)
    append_in_blocks(chain, collect_transactions([system], key_holder)[::-1])
    height_of = {
        loc.chunk_index: loc.height for loc in identify(chain, "SYS_5", decrypt=key_holder.decrypt)
    }
    assert height_of[0] > height_of[max(height_of)]  # the first chunk landed last
    original = system.data
    system.wipe()
    phase5.run(system=system, front=front, key_holder=key_holder, chain=chain)
    assert system.data == original


def test_no_backup_is_an_error_not_an_empty_restore(world) -> None:
    chain, key_holder, front, _, _ = world
    stranger = make_system(9)
    with pytest.raises(RecoveryError, match="no complete backup"):
        phase5.run(system=stranger, front=front, key_holder=key_holder, chain=chain)
    assert stranger.data is None


# -- one system cannot recover another's ---------------------------------------------------------
def test_a_request_to_recover_another_system_is_refused(world) -> None:
    _, _, front, systems, _ = world
    establish_session(systems[1], front)
    forged = alg5.request(systems[1].channel(front.identity), "SYS_2")
    with pytest.raises(RecoveryError, match="only its own"):
        front.accept_recovery_request(forged)


def test_the_front_server_will_not_deliver_to_another_system(world) -> None:
    _, key_holder, front, systems, _ = world
    handed_over = _up_to_transfer(world, "SYS_2")
    with pytest.raises(RecoveryError, match="refusing to deliver"):
        alg5.deliver(
            handed_over,
            inbound=front.channel(key_holder.identity),
            outbound=front.channel(systems[1].identity),
        )


def test_an_intercepted_delivery_does_not_open_for_another_system(world) -> None:
    _, key_holder, front, systems, originals = world
    victim, thief = systems[2], systems[1]
    delivery = alg5.deliver(
        _up_to_transfer(world, "SYS_2"),
        inbound=front.channel(key_holder.identity),
        outbound=front.channel(victim.identity),
    )
    with pytest.raises(ChannelError, match="different session"):
        thief.restore(delivery)
    readdressed = dataclasses.replace(
        delivery, recipient=thief.identity, session_id=thief.channel(front.identity).session_id
    )
    with pytest.raises(ChannelError, match="authenticate"):
        thief.restore(readdressed)
    assert thief.data == originals[1]
    victim.data = None
    victim.restore(delivery)  # the same envelope, untouched, opens for its addressee
    assert victim.data == originals[2]


def test_the_recovery_request_is_bound_to_the_requesters_session(world) -> None:
    _, _, front, systems, _ = world
    establish_session(systems[1], front)
    establish_session(systems[2], front)
    genuine = alg5.request(systems[2].channel(front.identity), "SYS_2")
    stolen = dataclasses.replace(
        genuine, sender="SYS_1", session_id=front.channel("SYS_1").session_id
    )
    with pytest.raises(ChannelError, match="authenticate"):
        front.accept_recovery_request(stolen)


# -- integrity ---------------------------------------------------------------------------------
@pytest.mark.parametrize("recompute_digest", [False, True], ids=["stale-digest", "fixed-digest"])
@pytest.mark.parametrize("use_index", [False, True], ids=["scan", "index"])
def test_tampered_ciphertext_is_caught_at_restore(world, recompute_digest, use_index) -> None:
    chain, key_holder, front, systems, _ = world
    index = None
    if use_index:
        index = BackupIndex(key_holder.decrypt)
        index.sync(chain)
    target = identify(chain, "SYS_2", decrypt=key_holder.decrypt)[3]
    tamper_ciphertext(chain, target.height, target.tx_index, recompute_digest=recompute_digest)
    systems[2].wipe()
    with pytest.raises(RecoveryError, match=r"fail(s|ed) verification"):
        phase5.run(system=systems[2], front=front, key_holder=key_holder, chain=chain, index=index)
    assert systems[2].data is None


def test_a_payload_changed_between_the_hops_fails_the_digest_check(world) -> None:
    _, key_holder, front, systems, _ = world
    victim = systems[2]
    handed_over = _up_to_transfer(world)  # before front.channel(): it establishes the session
    raw = front.channel(key_holder.identity).open(handed_over, alg5.PURPOSE_TRANSFER)
    manifest, data = unpack(raw)
    altered = data[:-1] + bytes([data[-1] ^ 1])
    delivery = front.channel(victim.identity).seal(alg5.PURPOSE_DELIVERY, pack(manifest, altered))
    victim.data = None
    with pytest.raises(RecoveryError, match="payload digest"):
        victim.restore(delivery)
    assert victim.data is None


def test_a_server_that_rewrites_data_and_digest_fails_the_attestation(world) -> None:
    _, key_holder, front, systems, _ = world
    victim = systems[2]
    handed_over = _up_to_transfer(world)
    raw = front.channel(key_holder.identity).open(handed_over, alg5.PURPOSE_TRANSFER)
    manifest, _ = unpack(raw)
    planted = b"ransom note"
    forged = dataclasses.replace(
        manifest, payload_digest=payload_digest("SYS_2", manifest.captured_at, planted)
    )
    delivery = front.channel(victim.identity).seal(alg5.PURPOSE_DELIVERY, pack(forged, planted))
    victim.data = None
    with pytest.raises(RecoveryError, match="not attested"):
        victim.restore(delivery)
    assert victim.data is None


def test_a_paper_shaped_backup_record_is_refused_at_restore(world) -> None:
    chain, key_holder, front, _, _ = world
    record = BackupPayload("SYS_8", b"no digest, no attestation", 100)
    tx = encrypt_backup(
        recipient=key_holder.public_key, tx_id="paper-1", payload=record, created_at=100
    )
    append_in_blocks(chain, [tx])
    system = make_system(8)
    with pytest.raises(RecoveryError, match="unverifiable"):
        phase5.run(system=system, front=front, key_holder=key_holder, chain=chain)
    assert system.data is None
