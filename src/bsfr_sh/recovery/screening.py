"""Backup content screening — Phase 2 / P2-G (DEV-49), not part of the paper.

The gap
-------
Alg. 5 restores the newest complete backup. Ransomware that encrypts slowly ("slow-burn"), over
more than one backup interval, has its ciphertext backed up as faithfully as any other data. The
chain then guarantees that *the encrypted files* can be restored, byte for byte, forever. Every
integrity check in the pipeline passes, because the infected system really did send those bytes
(DEV-23's attestation is signed by the system itself).

What this module does
---------------------
Looks *inside* a backup (a set of named files) and flags files that look like ransomware output.
It is meant to run on a cloud server, never on the protected system, at two points:

* backup time — `CS_l` sees the plaintext between `receive_backup` and encryption (Alg. 1), so a
  flagged backup is an early ransomware alarm, independent of Phase 3's classifier;
* restore time — Alg. 5 line 2 can pass over backups that fail screening
  (`recovery.restore.begin_screened`) instead of restoring the newest one blindly.

Three levels, each the obvious next step after the previous one is bypassed:

`ENTROPY`     — whole-file Shannon entropy above a threshold. Type-agnostic. Encrypted data is
                ~8 bits/byte, but so are JPEGs and .docx files (already compressed), and partial
                encryption keeps the whole-file average low.
`FORMAT`      — knows each file type: the magic bytes must be intact, text must be clean text, and
                medium-entropy images (DICOM pixel data) must not contain random-looking windows.
                Bypassed by encryption that skips the header and stripes already-compressed files.
`HISTORY`     — FORMAT plus: medical images are write-once, so an image that differs from its
                first-seen version is flagged. The chain itself supplies the trustworthy first-seen
                version, because old backups cannot be altered.

Known blind spot of all three (measured in P2-G, not hidden): a file type that is both already
compressed *and* legitimately rewritten (office documents) and is encrypted in stripes that leave
the header intact.

File kinds are inferred from the extension. Thresholds are constructor parameters, defaulted from
P2-G's clean-corpus calibration.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field

import numpy as np

__all__ = [
    "FileKind",
    "ScreenLevel",
    "ScreenPolicy",
    "ScreenReport",
    "entropy",
    "kind_of",
    "max_window_entropy",
    "screen_backup",
    "screen_file",
]


class FileKind(enum.Enum):
    TEXT = "text"  # .csv / .hl7 / .txt — mutable, plain text
    DICOM = "dicom"  # .dcm — write-once, 128-byte preamble then b"DICM"
    JPEG = "jpeg"  # .jpg — write-once, already compressed
    OFFICE = "office"  # .docx / .xlsx — mutable, zip container (already compressed)
    OTHER = "other"


_EXTENSIONS = {
    ".csv": FileKind.TEXT, ".hl7": FileKind.TEXT, ".txt": FileKind.TEXT,
    ".dcm": FileKind.DICOM, ".jpg": FileKind.JPEG, ".jpeg": FileKind.JPEG,
    ".docx": FileKind.OFFICE, ".xlsx": FileKind.OFFICE,
}  # fmt: skip
_WRITE_ONCE = frozenset({FileKind.DICOM, FileKind.JPEG})
_ALLOWED_CONTROL = frozenset(b"\n\r\t")


class ScreenLevel(enum.IntEnum):
    ENTROPY = 1
    FORMAT = 2
    HISTORY = 3


def kind_of(name: str) -> FileKind:
    dot = name.rfind(".")
    return _EXTENSIONS.get(name[dot:].lower(), FileKind.OTHER) if dot >= 0 else FileKind.OTHER


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def max_window_entropy(data: bytes, *, window: int, step: int, start: int = 0) -> float:
    """Highest entropy of any `window`-byte slice from `start`, sliding by `step`."""
    best = 0.0
    for offset in range(start, max(start, len(data) - window) + 1, step):
        chunk = data[offset : offset + window]
        if len(chunk) < window // 2:
            break
        best = max(best, entropy(chunk))
    return best


def _magic_ok(kind: FileKind, data: bytes) -> bool:
    if kind is FileKind.DICOM:
        return data[128:132] == b"DICM"
    if kind is FileKind.JPEG:
        return data[:3] == b"\xff\xd8\xff"
    if kind is FileKind.OFFICE:
        return data[:4] == b"PK\x03\x04"
    return True


def _clean_text(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(ch.isprintable() or ord(ch) in _ALLOWED_CONTROL for ch in text)


@dataclass(frozen=True)
class ScreenPolicy:
    level: ScreenLevel = ScreenLevel.HISTORY
    #: ENTROPY level: whole-file bits/byte above which a file is flagged.
    file_entropy_threshold: float = 7.2
    #: FORMAT level, DICOM pixel data: window size/step and the per-window threshold. Calibrated
    #: on P2-G's synthetic corpus: clean max 5.89 bits/byte, 512-byte random stripe min 7.61.
    #: Real DICOM in a compressed transfer syntax is ~8 bits/byte and would need HISTORY instead.
    window: int = 512
    step: int = 128
    window_entropy_threshold: float = 7.0
    dicom_header_bytes: int = 132


@dataclass(frozen=True)
class ScreenReport:
    """`flagged` maps file name -> reasons. A backup is clean iff nothing is flagged."""

    flagged: dict[str, tuple[str, ...]] = field(default_factory=dict)
    files_screened: int = 0

    @property
    def clean(self) -> bool:
        return not self.flagged


def screen_file(
    name: str, data: bytes, *, first_seen: bytes | None, policy: ScreenPolicy
) -> tuple[str, ...]:
    """Reasons `name` looks like ransomware output; empty when it passes. See module docstring."""
    reasons: list[str] = []
    kind = kind_of(name)
    if policy.level is ScreenLevel.ENTROPY:
        if entropy(data) > policy.file_entropy_threshold:
            reasons.append("high_entropy")
        return tuple(reasons)
    if not _magic_ok(kind, data):
        reasons.append("bad_magic")
    if kind is FileKind.TEXT and not _clean_text(data):
        reasons.append("not_text")
    if (
        kind is FileKind.DICOM
        and max_window_entropy(
            data, window=policy.window, step=policy.step, start=policy.dicom_header_bytes
        )
        > policy.window_entropy_threshold
    ):
        reasons.append("random_window")
    if (
        policy.level is ScreenLevel.HISTORY
        and kind in _WRITE_ONCE
        and first_seen is not None
        and data != first_seen
    ):
        reasons.append("write_once_file_changed")
    return tuple(reasons)


def screen_backup(
    files: Mapping[str, bytes],
    *,
    first_seen: Mapping[str, bytes] | None = None,
    policy: ScreenPolicy | None = None,
) -> ScreenReport:
    """Screen every file of one backup. `first_seen` is each file's earliest backed-up version."""
    policy = policy or ScreenPolicy()
    reference = first_seen or {}
    flagged = {}
    for name, data in files.items():
        reasons = screen_file(name, data, first_seen=reference.get(name), policy=policy)
        if reasons:
            flagged[name] = reasons
    return ScreenReport(flagged=flagged, files_screened=len(files))
