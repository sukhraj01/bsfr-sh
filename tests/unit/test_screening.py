"""P2-G (DEV-49): backup content screening, and Alg. 5 restoring the newest backup that passes it.

The adversarial case this exists for: slow-burn ransomware whose ciphertext was backed up. The
paper's Alg. 5 restores it faithfully; with screening, the newest *clean* backup is restored.
"""

from __future__ import annotations

import random

import numpy as np
import pytest
from m3a_harness import back_up_directly, dtbu_chain, make_server, make_system

from bsfr_sh.framework import phase5_recovery as phase5
from bsfr_sh.recovery import restore as alg5
from bsfr_sh.recovery import screening as sc
from bsfr_sh.recovery.locator import RecoveryError, identify

FORMAT = sc.ScreenPolicy(level=sc.ScreenLevel.FORMAT)
HISTORY = sc.ScreenPolicy(level=sc.ScreenLevel.HISTORY)
ENTROPY = sc.ScreenPolicy(level=sc.ScreenLevel.ENTROPY)


def _text() -> bytes:
    r = random.Random(1)
    return "".join(f"P{r.randrange(10**6):06d},ICU,{r.uniform(0, 300):.1f}\n"
                   for _ in range(800)).encode()  # fmt: skip


def _dicom() -> bytes:
    npr = np.random.default_rng(2)
    yy, xx = np.mgrid[0:128, 0:128]
    img = 1500 + 600 * np.sin(xx / 17.0) * np.cos(yy / 23.0) + npr.normal(0, 25, (128, 128))
    return b"\x00" * 128 + b"DICM" + b"Modality=CT;".ljust(256) + img.astype("<u2").tobytes()


def _jpeg() -> bytes:
    return b"\xff\xd8\xff\xe0" + random.Random(3).randbytes(20_000) + b"\xff\xd9"


def _office() -> bytes:
    return b"PK\x03\x04" + random.Random(4).randbytes(20_000) + b"PK\x05\x06"


def _stripe(data: bytes, *, at: int = 4096, size: int = 512) -> bytes:
    """Overwrite one stripe with random bytes (the modelled ciphertext), header left intact."""
    return data[:at] + random.Random(9).randbytes(size) + data[at + size :]


def test_entropy_bounds() -> None:
    assert sc.entropy(b"\x00" * 1000) == 0.0
    assert sc.entropy(bytes(range(256)) * 4) == pytest.approx(8.0)


KINDS = [
    ("a.csv", sc.FileKind.TEXT),
    ("b.DCM", sc.FileKind.DICOM),
    ("c.jpg", sc.FileKind.JPEG),
    ("d.docx", sc.FileKind.OFFICE),
    ("e.bin", sc.FileKind.OTHER),
    ("noext", sc.FileKind.OTHER),
]


@pytest.mark.parametrize(("name", "kind"), KINDS)
def test_kind_from_extension(name: str, kind: sc.FileKind) -> None:
    assert sc.kind_of(name) is kind


@pytest.mark.parametrize("policy", [FORMAT, HISTORY])
def test_clean_files_pass(policy: sc.ScreenPolicy) -> None:
    for name, data in {"r.csv": _text(), "s.dcm": _dicom(), "p.jpg": _jpeg(),
                       "d.docx": _office()}.items():  # fmt: skip
        assert sc.screen_file(name, data, first_seen=data, policy=policy) == ()


def test_entropy_level_flags_clean_compressed_files() -> None:
    """The naive check's documented false positive: every JPEG and office file."""
    assert sc.screen_file("p.jpg", _jpeg(), first_seen=None, policy=ENTROPY) == ("high_entropy",)
    assert sc.screen_file("d.docx", _office(), first_seen=None, policy=ENTROPY)


def test_entropy_level_misses_a_partially_encrypted_text_file() -> None:
    assert sc.screen_file("r.csv", _stripe(_text()), first_seen=None, policy=ENTROPY) == ()


def test_format_level_catches_a_destroyed_header_and_a_striped_text_file() -> None:
    bad_header = b"\x13\x37" + _jpeg()[2:]
    assert "bad_magic" in sc.screen_file("p.jpg", bad_header, first_seen=None, policy=FORMAT)
    assert "not_text" in sc.screen_file("r.csv", _stripe(_text(), size=64), first_seen=None,
                                        policy=FORMAT)  # fmt: skip


def test_format_level_catches_a_512_byte_stripe_in_dicom_pixels_but_not_a_64_byte_one() -> None:
    dicom = _dicom()
    assert sc.screen_file("s.dcm", _stripe(dicom), first_seen=None, policy=FORMAT) == (
        "random_window",
    )
    assert sc.screen_file("s.dcm", _stripe(dicom, size=64), first_seen=None, policy=FORMAT) == ()


def test_history_level_catches_any_change_to_a_write_once_image() -> None:
    jpeg, dicom = _jpeg(), _dicom()
    assert sc.screen_file("p.jpg", _stripe(jpeg), first_seen=jpeg, policy=FORMAT) == ()
    assert sc.screen_file("p.jpg", _stripe(jpeg), first_seen=jpeg, policy=HISTORY) == (
        "write_once_file_changed",
    )
    assert "write_once_file_changed" in sc.screen_file(
        "s.dcm", _stripe(dicom, size=64), first_seen=dicom, policy=HISTORY
    )


def test_the_documented_blind_spot_striped_office_file_passes_every_level_but_entropy() -> None:
    office = _office()
    for policy in (FORMAT, HISTORY):
        assert sc.screen_file("d.docx", _stripe(office), first_seen=office, policy=policy) == ()


def test_screen_backup_reports_only_flagged_files() -> None:
    files = {"r.csv": _stripe(_text(), size=64), "p.jpg": _jpeg()}
    report = sc.screen_backup(files, first_seen=files, policy=HISTORY)
    assert not report.clean
    assert set(report.flagged) == {"r.csv"}
    assert report.files_screened == 2


# --- Alg. 5 with screening ----------------------------------------------------------------
@pytest.fixture
def two_backups():
    """SYS_1 backed up clean at t=100, then again at t=200 after its data was 'encrypted'."""
    chain = dtbu_chain()
    key_holder, front = make_server(10), make_server(11)
    system = make_system(1, 40)
    back_up_directly(chain, [system], key_holder, captured_at=100)
    clean = system.data
    system.data = random.Random(5).randbytes(40)  # the ransomware's output, backed up faithfully
    back_up_directly(chain, [system], key_holder, captured_at=200)
    return chain, key_holder, front, system, clean


def test_paper_alg5_restores_the_encrypted_newest_backup(two_backups) -> None:
    chain, key_holder, front, system, clean = two_backups
    system.wipe()
    report = phase5.run(system=system, front=front, key_holder=key_holder, chain=chain)
    assert report.captured_at == 200
    assert system.data != clean


def test_screened_alg5_passes_over_the_rejected_backup(two_backups) -> None:
    chain, key_holder, front, system, clean = two_backups
    system.wipe()
    report = phase5.run(system=system, front=front, key_holder=key_holder, chain=chain,
                        accept=lambda plan: plan.captured_at < 200)  # fmt: skip
    assert report.captured_at == 100
    assert system.data == clean
    assert len(report.skipped) == 1


def test_screened_begin_raises_when_no_backup_passes(two_backups) -> None:
    chain, key_holder, _, system, _ = two_backups
    locations = identify(chain, system.identity, decrypt=key_holder.decrypt)
    with pytest.raises(RecoveryError, match="passed screening"):
        alg5.begin_screened(system.identity, locations, lambda plan: False)
