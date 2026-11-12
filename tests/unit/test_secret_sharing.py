"""P2-F (DEV-48): Shamir secret sharing over GF(2^8) and threshold key wrapping."""

from __future__ import annotations

import dataclasses
import itertools
import random

import pytest

from bsfr_sh.crypto import secret_sharing as ss
from bsfr_sh.crypto import threshold_kem as tk
from bsfr_sh.crypto.aead import AeadError, AeadKey, Sealed
from bsfr_sh.crypto.ecdsa import keypair_from_secret
from bsfr_sh.crypto.kem import KemError

SECRET = bytes(range(32))
HOLDERS = [keypair_from_secret(0x7E5E_0000 + i) for i in range(4)]
META = {"tx_id": "tx-1", "payload_type": "backup", "created_at": 100}


def _rng(seed: int = 1):
    r = random.Random(seed)
    return r.randbytes


# --- field arithmetic --------------------------------------------------------------------------
def test_every_nonzero_field_element_has_an_inverse() -> None:
    for a in range(1, 256):
        assert ss._mul(a, ss._div(1, a)) == 1


def test_field_multiplication_matches_carryless_multiply_mod_0x11b() -> None:
    def slow(a: int, b: int) -> int:
        out = 0
        while b:
            if b & 1:
                out ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11B
            b >>= 1
        return out

    r = random.Random(3)
    for _ in range(500):
        a, b = r.randrange(256), r.randrange(256)
        assert ss._mul(a, b) == slow(a, b)


# --- Shamir ------------------------------------------------------------------------------------
@pytest.mark.parametrize(("n", "t"), [(1, 1), (4, 1), (4, 2), (4, 3), (4, 4), (7, 4)])
def test_every_threshold_sized_subset_rebuilds_the_secret(n: int, t: int) -> None:
    shares = ss.split(SECRET, shares=n, threshold=t, randbytes=_rng())
    for subset in itertools.combinations(shares, t):
        assert ss.combine(list(subset)) == SECRET
    assert ss.combine(list(shares)) == SECRET  # more than t is fine too


def test_one_share_below_threshold_is_consistent_with_every_secret_byte() -> None:
    """t=2: one share (x, y) fits a line through (0, s) for *every* s: it says nothing about s."""
    (share, _, _, _) = ss.split(SECRET, shares=4, threshold=2, randbytes=_rng())
    y = share.value[0]
    for s in range(256):
        slope = ss._div(y ^ s, share.index)  # the coefficient that makes the line pass through
        assert ss._mul(slope, share.index) ^ s == y


def test_below_threshold_combine_does_not_return_the_secret() -> None:
    shares = ss.split(SECRET, shares=4, threshold=3, randbytes=_rng())
    for subset in itertools.combinations(shares, 2):
        assert ss.combine(list(subset)) != SECRET


def test_a_threshold_of_one_is_plain_replication() -> None:
    shares = ss.split(SECRET, shares=4, threshold=1, randbytes=_rng())
    assert all(s.value == SECRET for s in shares)


@pytest.mark.parametrize(("n", "t"), [(4, 0), (3, 4), (256, 2)])
def test_bad_parameters_are_refused(n: int, t: int) -> None:
    with pytest.raises(ss.SecretSharingError):
        ss.split(SECRET, shares=n, threshold=t, randbytes=_rng())


def test_duplicate_or_mismatched_shares_are_refused() -> None:
    a, b, _, _ = ss.split(SECRET, shares=4, threshold=2, randbytes=_rng())
    with pytest.raises(ss.SecretSharingError):
        ss.combine([a, a])
    with pytest.raises(ss.SecretSharingError):
        ss.combine([a, ss.Share(index=b.index, value=b.value[:-1])])


# --- threshold key wrapping --------------------------------------------------------------------
def _seal(t: int = 2) -> tk.ThresholdCiphertext:
    return tk.seal_payload_threshold([k.public for k in HOLDERS], t, b"patient record", META)


def test_any_two_of_four_holders_open_a_2_of_4_payload() -> None:
    ct = _seal(2)
    for pair in itertools.combinations(HOLDERS, 2):
        shares = [tk.unwrap_share(k.private, ct, META) for k in pair]
        assert tk.open_with_shares(ct, shares, META) == b"patient record"


def test_one_holder_alone_cannot_open_even_bypassing_the_count_check() -> None:
    """The adversarial case: a single compromised server rebuilds a key from its one share."""
    ct = _seal(2)
    share = tk.unwrap_share(HOLDERS[0].private, ct, META)
    with pytest.raises(KemError):
        tk.open_with_shares(ct, [share], META)
    # bypass the API's count check and try the AEAD directly with whatever one share rebuilds
    guess = AeadKey(ss.combine([share]))
    aad = tk._payload_aad(tk._metadata_bytes(META), ct.threshold, ct.wrapped_shares)
    with pytest.raises(AeadError):
        guess.unseal(Sealed(nonce=ct.nonce, ciphertext=ct.ciphertext), aad)


def test_an_outsider_key_holds_no_share() -> None:
    with pytest.raises(KemError):
        tk.unwrap_share(keypair_from_secret(0xBAD).private, _seal(), META)


def test_a_wrong_share_is_detected_not_silently_accepted() -> None:
    ct = _seal(2)
    good = tk.unwrap_share(HOLDERS[0].private, ct, META)
    other = tk.unwrap_share(HOLDERS[1].private, ct, META)
    forged = ss.Share(index=other.index, value=bytes(b ^ 1 for b in other.value))
    with pytest.raises(KemError):
        tk.open_with_shares(ct, [good, forged], META)


def test_wrapped_shares_are_bound_to_their_transaction() -> None:
    ct = _seal(2)
    with pytest.raises(KemError):
        tk.unwrap_share(HOLDERS[0].private, ct, {**META, "tx_id": "tx-2"})


def test_swapping_a_wrapped_share_from_another_payload_breaks_the_tag() -> None:
    ct, other = _seal(2), _seal(2)
    spliced = dataclasses.replace(
        ct, wrapped_shares=(other.wrapped_shares[0], *ct.wrapped_shares[1:])
    )
    shares = [tk.unwrap_share(HOLDERS[i].private, spliced, META) for i in (0, 1)]
    with pytest.raises(KemError):
        tk.open_with_shares(spliced, shares, META)


def test_lowering_the_declared_threshold_breaks_the_tag() -> None:
    ct = _seal(3)
    lowered = dataclasses.replace(ct, threshold=1)
    with pytest.raises(KemError):
        share = tk.unwrap_share(HOLDERS[0].private, lowered, META)
        tk.open_with_shares(lowered, [share], META)
