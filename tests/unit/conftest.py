"""Shared fixtures for the crypto tests.

CLAUDE.md §4b: *"Crypto keypairs in tests are fixture-loaded, never freshly generated, so test
runs are byte-reproducible."* These derive from fixed scalars, so every machine and every run
gets the same keys, and — with RFC 6979 deterministic signing — the same signature bytes.
"""

from __future__ import annotations

import pytest

from bsfr_sh.crypto.ecdsa import KeyPair, keypair_from_secret

#: Arbitrary but fixed scalars. Distinct so that a test which accidentally uses the wrong key
#: fails rather than passing by coincidence.
_SECRETS = {
    "sys": 0x1111111111111111111111111111111111111111111111111111111111111111,
    "cs_1": 0x2222222222222222222222222222222222222222222222222222222222222222,
    "cs_2": 0x3333333333333333333333333333333333333333333333333333333333333333,
    "attacker": 0x4444444444444444444444444444444444444444444444444444444444444444,
}


@pytest.fixture(scope="session")
def sys_keys() -> KeyPair:
    """`SYS_i` — a protected smart-healthcare system, the session initiator."""
    return keypair_from_secret(_SECRETS["sys"])


@pytest.fixture(scope="session")
def cs1_keys() -> KeyPair:
    """`CS_1` — the cloud server a session is addressed to."""
    return keypair_from_secret(_SECRETS["cs_1"])


@pytest.fixture(scope="session")
def cs2_keys() -> KeyPair:
    """`CS_2` — a *different* cloud server, for the cross-identity replay test."""
    return keypair_from_secret(_SECRETS["cs_2"])


@pytest.fixture(scope="session")
def attacker_keys() -> KeyPair:
    """`A` — the adversary of docs/NOTATION.md, holding a key nobody trusts."""
    return keypair_from_secret(_SECRETS["attacker"])


class FakeClock:
    """A clock the tests move by hand, so timestamp expiry has no `sleep` in it.

    `crypto.session` takes its clock through `SessionPolicy` for exactly this reason: a replay
    window that can only be tested by waiting is a replay window that does not get tested.
    """

    def __init__(self, start: float = 1_757_548_800.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds
