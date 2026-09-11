"""`framework.entities`: `SYS_i` and `CS_l`, and Alg. 1 line 1's authenticated collection. §V-1."""

from __future__ import annotations

import pytest
from m3a_harness import make_server, make_system

from bsfr_sh.blockchain.backup import attest, pack
from bsfr_sh.crypto.ecdsa import keypair_from_secret
from bsfr_sh.framework.entities import PURPOSE_BACKUP, EntityError, System, establish_session


def test_establishing_a_session_installs_one_key_on_both_sides() -> None:
    system, server = make_system(1, 10), make_server(10)
    establish_session(system, server)
    assert system.channel(server.identity).session_id == server.channel(system.identity).session_id
    assert server.peer_key(system.identity) == system.public_key


def test_a_backup_arrives_intact_and_attested_by_its_sender() -> None:
    system, server = make_system(1, 10), make_server(10)
    establish_session(system, server)
    manifest, data = server.receive_backup(system.ship_backup(server.identity, captured_at=5))
    assert data == system.data
    assert manifest.system_id == "SYS_1"
    assert manifest.verify(system.public_key)


def test_a_system_cannot_back_up_in_another_systems_name() -> None:
    impostor, server = make_system(2, 10), make_server(10)
    establish_session(impostor, server)
    forged = attest(impostor.keypair.private, system_id="SYS_1", captured_at=5, data=b"planted")
    envelope = impostor.channel(server.identity).seal(PURPOSE_BACKUP, pack(forged, b"planted"))
    with pytest.raises(EntityError, match="claiming to be 'SYS_1'"):
        server.receive_backup(envelope)


def test_a_backup_attested_with_the_wrong_key_is_refused() -> None:
    system, server = make_system(1, 10), make_server(10)
    establish_session(system, server)
    wrong = attest(keypair_from_secret(0xBAD).private, system_id="SYS_1", captured_at=5, data=b"x")
    envelope = system.channel(server.identity).seal(PURPOSE_BACKUP, pack(wrong, b"x"))
    with pytest.raises(EntityError, match="not attested"):
        server.receive_backup(envelope)


def test_nothing_is_shipped_without_a_session() -> None:
    system, server = make_system(1, 10), make_server(10)
    with pytest.raises(EntityError, match="no session"):
        system.ship_backup(server.identity, captured_at=5)


def test_a_wipe_removes_data_and_sessions_but_not_identity() -> None:
    system, server = make_system(1, 10), make_server(10)
    establish_session(system, server)
    keypair = system.keypair
    system.wipe()
    assert system.data is None
    assert not system.has_session(server.identity)
    assert system.keypair is keypair
    with pytest.raises(EntityError, match="no data"):
        system.ship_backup(server.identity, captured_at=5)


def test_an_entity_needs_an_identity() -> None:
    with pytest.raises(EntityError):
        System(identity="", keypair=keypair_from_secret(0x1))
