"""Phase 2 / P2-G: slow-burn ransomware poisons the backups that recovery depends on.

BSFR-SH's recovery promise (Alg. 5) is "restore the newest complete backup from the chain". That
works against ransomware that encrypts everything at once, after the last backup. Ransomware that
encrypts gradually over several days (slow-burn) gets its *ciphertext* backed up, and the immutable
chain then preserves the encrypted files as faithfully as anything else.

SAFETY (CLAUDE.md §2): nothing here encrypts real files or touches the file system. A "hospital
system" is an in-memory dict of synthetic files; "ransomware encryption" is modelled by overwriting
bytes with seeded uniform random bytes, which is what AES output is indistinguishable from.

Part A — real pipeline. One system backs up daily through real pBFT on `BC_DTBU` (Alg. 1). Slow-
burn ransomware starts on day 10 and encrypts over 7 days. Alg. 5 is run as the paper specifies,
and again with restore-time screening (`recovery.screening`, `restore.begin_screened`).

Part B — the screening check vs ransomware encryption styles (attack -> check -> bypass). For each
file type and encryption style: how often each screening level flags an encrypted file, and how
often it falsely flags a clean or legitimately edited one.

Part C — timeline sweep. Slow-burn duration 0..14 days, two encryption styles, recovery policies:
paper (newest backup), restore-time screening, and backup-time screening (alarm -> isolate).

Usage::

    python scripts/p2g_slow_burn_backups.py --seed 20261112
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import subprocess
import sys
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bsfr_sh.blockchain.chain import BC_DTBU, build_genesis  # noqa: E402
from bsfr_sh.consensus.pbft import Cluster, PBFTPolicy  # noqa: E402
from bsfr_sh.crypto.ecdsa import keypair_from_secret  # noqa: E402
from bsfr_sh.crypto.hashing import CONFIG_HASH_SCHEME, config_hash  # noqa: E402
from bsfr_sh.framework import phase1_backup as phase1  # noqa: E402
from bsfr_sh.framework import phase5_recovery as phase5  # noqa: E402
from bsfr_sh.framework._block_pipeline import read_chain  # noqa: E402
from bsfr_sh.framework.entities import CloudServer, System  # noqa: E402
from bsfr_sh.recovery import restore as alg5  # noqa: E402
from bsfr_sh.recovery.locator import identify  # noqa: E402
from bsfr_sh.recovery.screening import (  # noqa: E402
    FileKind,
    ScreenLevel,
    ScreenPolicy,
    entropy,
    kind_of,
    max_window_entropy,
    screen_file,
)
from bsfr_sh.util import logging as log  # noqa: E402
from bsfr_sh.util.config import load_config  # noqa: E402
from bsfr_sh.util.seeding import seed_all  # noqa: E402
from bsfr_sh.util.serialization import decode, encode  # noqa: E402

Files = dict[str, bytes]
ATTACK_START = 10
HEADER_SKIP = 4096

# ============================================================================================
# Synthetic hospital files (statistical stand-ins, no real data)
# ============================================================================================
_WARDS = ["ICU", "ER", "CARD", "ONC", "PED", "RAD", "NEURO", "ORTHO"]
_CODES = ["I10", "E11.9", "J18.9", "N39.0", "R07.9", "K21.9", "M54.5", "F32.9", "Z00.0"]


def _records(rng: random.Random, n: int) -> str:
    return "".join(
        f"P{rng.randrange(10**6):06d},{rng.choice(_WARDS)},2026-{rng.randrange(1, 13):02d}-"
        f"{rng.randrange(1, 29):02d},{rng.choice(_CODES)},{rng.uniform(0, 300):.1f}\n"
        for _ in range(n)
    )


def make_text(rng: random.Random, kb: int) -> bytes:
    return ("patient_id,ward,date,code,value\n" + _records(rng, kb * 1024 // 34)).encode()


def make_dicom(rng: random.Random, side: int) -> bytes:
    npr = np.random.default_rng(rng.randrange(2**32))
    yy, xx = np.mgrid[0:side, 0:side]
    img = 1500 + 600 * np.sin(xx / 17.0) * np.cos(yy / 23.0) + npr.normal(0, 25, (side, side))
    tags = f"PatientID=P{rng.randrange(10**6):06d};Modality=CT;Rows={side};Cols={side};".encode()
    return b"\x00" * 128 + b"DICM" + tags.ljust(256, b" ") + img.astype("<u2").tobytes()


def make_jpeg(rng: random.Random, kb: int) -> bytes:
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + rng.randbytes(kb * 1024) + b"\xff\xd9"


def make_office(rng: random.Random, kb: int) -> bytes:
    body = zlib.compress(_records(rng, kb * 1024 // 12).encode(), 9)
    return b"PK\x03\x04" + body + b"PK\x05\x06" + b"\x00" * 18


def make_corpus(rng: random.Random, *, text: int, dicom: int, jpeg: int, office: int,
                scale: float = 1.0) -> Files:  # fmt: skip
    files: Files = {}
    for i in range(text):
        files[f"records_{i:02d}.csv"] = make_text(rng, max(2, int(rng.randint(8, 32) * scale)))
    for i in range(dicom):
        files[f"scan_{i:02d}.dcm"] = make_dicom(rng, max(48, int(rng.choice([128, 160, 192]) * scale)))
    for i in range(jpeg):
        files[f"photo_{i:02d}.jpg"] = make_jpeg(rng, max(4, int(rng.randint(16, 48) * scale)))
    for i in range(office):
        files[f"report_{i:02d}.docx"] = make_office(rng, max(4, int(rng.randint(8, 24) * scale)))
    return files


def legit_day(files: Files, rng: random.Random, day: int, frozen: set[str]) -> None:
    """One day of normal hospital activity. Encrypted files (`frozen`) are no longer edited."""
    for name in list(files):
        if name in frozen:
            continue
        kind = kind_of(name)
        if kind is FileKind.TEXT and rng.random() < 0.3:
            files[name] = files[name] + _records(rng, rng.randint(5, 40)).encode()
        elif kind is FileKind.OFFICE and rng.random() < 0.1:
            files[name] = make_office(rng, rng.randint(8, 24))
    files[f"scan_new_day{day:02d}.dcm"] = make_dicom(rng, 128)


# ============================================================================================
# Modelled encryption (uniform random bytes, in memory)
# ============================================================================================
def _stripes(frac: float, stripe: int) -> Callable[[bytes, np.random.Generator], bytes]:
    period = max(stripe, int(round(stripe / frac)))

    def apply(data: bytes, npr: np.random.Generator) -> bytes:
        out = bytearray(data)
        for off in range(HEADER_SKIP, len(out), period):
            end = min(off + stripe, len(out))
            out[off:end] = npr.bytes(end - off)
        return bytes(out)

    return apply


STYLES: dict[str, Callable[[bytes, np.random.Generator], bytes]] = {
    "full": lambda d, npr: npr.bytes(len(d)),
    "header_only": lambda d, npr: npr.bytes(min(HEADER_SKIP, len(d))) + d[HEADER_SKIP:],
    "stripes_50pct": _stripes(0.50, 512),
    "stripes_10pct": _stripes(0.10, 512),
    "stripes_2pct": _stripes(0.02, 512),
    "stripes_10pct_tiny": _stripes(0.10, 64),
}
STYLE_NOTES = {
    "full": "whole file, header included",
    "header_only": "first 4 KiB only (fast; destroys the header)",
    "stripes_50pct": "intermittent: 512 B of every 1 KiB after the first 4 KiB",
    "stripes_10pct": "intermittent: 512 B of every 5 KiB after the first 4 KiB",
    "stripes_2pct": "intermittent: 512 B of every 25 KiB after the first 4 KiB",
    "stripes_10pct_tiny": "intermittent: 64 B of every 640 B after the first 4 KiB",
}
LEVELS = (ScreenLevel.ENTROPY, ScreenLevel.FORMAT, ScreenLevel.HISTORY)


# ============================================================================================
# Screening with a cache (identical bytes objects recur across daily snapshots)
# ============================================================================================
class Screener:
    def __init__(self, level: ScreenLevel) -> None:
        self.policy = ScreenPolicy(level=level)
        self._cache: dict[tuple[str, bytes, bytes | None], bool] = {}

    def flags(self, name: str, data: bytes, first_seen: bytes | None) -> bool:
        key = (name, data, first_seen)
        if key not in self._cache:
            self._cache[key] = bool(screen_file(name, data, first_seen=first_seen, policy=self.policy))
        return self._cache[key]

    def backup_clean(self, files: Files, first_seen: Files) -> bool:
        return not any(self.flags(n, d, first_seen.get(n)) for n, d in files.items())


# ============================================================================================
# Part B — check vs style
# ============================================================================================
def part_b(seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    npr = np.random.default_rng(seed)
    corpus = make_corpus(rng, text=60, dicom=60, jpeg=60, office=60)
    calibration = {
        k.value: {
            "file_entropy_min": min(entropy(d) for n, d in corpus.items() if kind_of(n) is k),
            "file_entropy_max": max(entropy(d) for n, d in corpus.items() if kind_of(n) is k),
        }
        for k in (FileKind.TEXT, FileKind.DICOM, FileKind.JPEG, FileKind.OFFICE)
    }
    calibration["dicom"]["max_window_entropy_clean"] = max(
        max_window_entropy(d, window=1024, step=256, start=132)
        for n, d in corpus.items() if kind_of(n) is FileKind.DICOM
    )  # fmt: skip
    # legitimately edited versions: text appended, office re-saved, images untouched (write-once)
    edited: Files = {}
    for n, d in corpus.items():
        k = kind_of(n)
        edited[n] = (d + _records(rng, 30).encode() if k is FileKind.TEXT
                     else make_office(rng, rng.randint(8, 24)) if k is FileKind.OFFICE else d)  # fmt: skip
    out: dict[str, Any] = {"calibration": calibration, "cells": []}
    for level in LEVELS:
        policy = ScreenPolicy(level=level)
        for kind in (FileKind.TEXT, FileKind.DICOM, FileKind.JPEG, FileKind.OFFICE):
            names = [n for n in corpus if kind_of(n) is kind]
            fp_clean = statistics.fmean(
                bool(screen_file(n, corpus[n], first_seen=corpus[n], policy=policy)) for n in names)
            fp_edit = statistics.fmean(
                bool(screen_file(n, edited[n], first_seen=corpus[n], policy=policy)) for n in names)
            row: dict[str, Any] = {"level": level.name, "kind": kind.value,
                                   "false_alarm_clean": fp_clean, "false_alarm_edited": fp_edit}  # fmt: skip
            for style, fn in STYLES.items():
                row[f"detect_{style}"] = statistics.fmean(
                    bool(screen_file(n, fn(corpus[n], npr), first_seen=corpus[n], policy=policy))
                    for n in names
                )
            out["cells"].append(row)
            sys.stderr.write(f"B {level.name:<8} {kind.value:<7} fa={fp_clean:.2f}/{fp_edit:.2f} "
                             + " ".join(f"{s}={row[f'detect_{s}']:.2f}" for s in STYLES) + "\n")  # fmt: skip
    return out


# ============================================================================================
# Part C — timeline sweep
# ============================================================================================
def _timeline(seed: int, duration: int, style: str, policy: str, level: ScreenLevel | None,
              screeners: dict[ScreenLevel, Screener]) -> dict[str, Any]:  # fmt: skip
    """One run. Backups at the end of each day. Ransom note on day ATTACK_START + duration."""
    rng = random.Random(seed)
    npr = np.random.default_rng(seed)
    files = make_corpus(rng, text=20, dicom=12, jpeg=8, office=8, scale=0.5)
    note_day = ATTACK_START + duration
    targets = sorted(files)
    transform = style
    if style.endswith("_office_only"):  # the attacker picks the screening's blind spot
        transform = style.removesuffix("_office_only")
        targets = [n for n in targets if kind_of(n) is FileKind.OFFICE]
    rng.shuffle(targets)
    when = {name: ATTACK_START + (j * duration) // len(targets) for j, name in enumerate(targets)}
    encrypted: set[str] = set()
    cipher: Files = {}  # the encrypted content of each encrypted file
    backups: list[tuple[int, Files]] = []
    first_seen: Files = {}
    alarm_day: int | None = None
    screener = screeners[level] if level is not None else None
    for day in range(note_day + 1):
        legit_day(files, rng, day, encrypted)
        halted = alarm_day is not None
        if day >= ATTACK_START and not halted:
            for name in targets:
                if when[name] <= day and name not in encrypted:
                    new = STYLES[transform](files[name], npr)
                    if new != files[name]:  # a file shorter than the skipped header is untouched
                        files[name] = new
                        encrypted.add(name)
                        cipher[name] = new
        if day == note_day or halted:
            break
        snap = dict(files)
        backups.append((day, snap))
        for n, d in snap.items():
            first_seen.setdefault(n, d)
        if policy == "backup_time_screening" and screener is not None:
            if not screener.backup_clean(snap, first_seen):
                alarm_day = day
    detected_day = alarm_day if alarm_day is not None else note_day
    # recovery
    if policy == "paper_newest":
        chosen = backups[-1]
    else:
        assert screener is not None
        chosen = next(((d, s) for d, s in reversed(backups) if screener.backup_clean(s, first_seen)),
                      None)  # fmt: skip
    if chosen is None:
        return {"restorable": False, "damaged_files": None, "days_rolled_back": None,
                "detected_after_days": detected_day - ATTACK_START,
                "files_encrypted": len(encrypted)}  # fmt: skip
    day, snap = chosen
    damaged = sum(1 for n, d in snap.items() if n in cipher and d == cipher[n])
    return {
        "restorable": True,
        "damaged_files": damaged,
        "damaged_share": damaged / len(snap),
        "days_rolled_back": detected_day - 1 - day,
        "detected_after_days": detected_day - ATTACK_START,
        "files_encrypted": len(encrypted),
    }


POLICIES = (("paper_newest", None), ("restore_time_screening", ScreenLevel.FORMAT),
            ("restore_time_screening", ScreenLevel.HISTORY),
            ("backup_time_screening", ScreenLevel.FORMAT),
            ("backup_time_screening", ScreenLevel.HISTORY),
            ("restore_time_screening", ScreenLevel.ENTROPY))  # fmt: skip
DURATIONS = (0, 1, 3, 7, 14)
TIMELINE_STYLES = ("full", "stripes_10pct", "stripes_10pct_office_only")
REPS = 10


def part_c(seed: int) -> list[dict[str, Any]]:
    cells = []
    for style in TIMELINE_STYLES:
        for duration in DURATIONS:
            for policy, level in POLICIES:
                screeners = {lv: Screener(lv) for lv in LEVELS}
                runs = [_timeline(seed + r, duration, style, policy, level, screeners)
                        for r in range(REPS)]  # fmt: skip
                ok = [r for r in runs if r["restorable"]]
                cell = {
                    "style": style, "slow_burn_days": duration, "policy": policy,
                    "level": level.name if level else "none", "reps": REPS,
                    "restorable_share": len(ok) / REPS,
                    "damaged_share_mean": statistics.fmean(r["damaged_share"] for r in ok) if ok else None,
                    "any_damage_share": statistics.fmean(r["damaged_files"] > 0 for r in ok) if ok else None,
                    "days_rolled_back_mean": statistics.fmean(r["days_rolled_back"] for r in ok) if ok else None,
                    "detected_after_days_mean": statistics.fmean(r["detected_after_days"] for r in runs),
                    "files_encrypted_mean": statistics.fmean(r["files_encrypted"] for r in runs),
                }  # fmt: skip
                cells.append(cell)
                sys.stderr.write(
                    f"C {style:<14} D={duration:<2} {policy:<23} {cell['level']:<8} "
                    f"restorable={cell['restorable_share']:.1f} damaged={cell['damaged_share_mean']} "
                    f"rolled_back={cell['days_rolled_back_mean']} "
                    f"detect+{cell['detected_after_days_mean']:.1f}d enc={cell['files_encrypted_mean']:.1f}\n"
                )
    return cells


# ============================================================================================
# Part A — real pipeline
# ============================================================================================
def part_a(seed: int, duration: int = 7, style: str = "full") -> dict[str, Any]:
    chain_cfg = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")
    servers = [CloudServer(identity=f"CS_{i}", keypair=keypair_from_secret(0xC5C5_1000 + i))
               for i in range(4)]  # fmt: skip
    collector, front = servers[0], servers[1]
    keys = {s.identity: s.keypair.private for s in servers}
    cluster = Cluster(
        chain_name=BC_DTBU, keys=keys,
        genesis=build_genesis(owner_id="CS_0", private_key=keys["CS_0"], timestamp=1000.0),
        policy=PBFTPolicy.from_config(chain_cfg), seed=seed,
        submitters={collector.identity: collector.public_key},
    )  # fmt: skip
    policy = phase1.BackupPolicy.from_config(chain_cfg)
    rng = random.Random(seed)
    npr = np.random.default_rng(seed)
    files = make_corpus(rng, text=6, dicom=4, jpeg=3, office=3, scale=0.25)
    system = System(identity="SYS_ward", keypair=keypair_from_secret(0x5E5E_1000), data=None)
    note_day = ATTACK_START + duration
    targets = sorted(files)
    rng.shuffle(targets)
    when = {n: ATTACK_START + (j * duration) // len(targets) for j, n in enumerate(targets)}
    encrypted: set[str] = set()
    cipher: Files = {}
    for day in range(note_day):
        legit_day(files, rng, day, encrypted)
        if day >= ATTACK_START:
            for n in targets:
                if when[n] <= day and n not in encrypted:
                    new = STYLES[style](files[n], npr)
                    if new != files[n]:
                        files[n] = new
                        encrypted.add(n)
                        cipher[n] = new
        system.data = encode(dict(files))
        phase1.run(systems=[system], collector=collector, cluster=cluster, policy=policy,
                   captured_at=day, timestamp=1001.0 + 10 * day)  # fmt: skip
    chain = read_chain(cluster)

    def damaged_in(restored: Files) -> int:
        return sum(1 for n, d in restored.items() if n in cipher and d == cipher[n])

    # Alg. 5 as the paper specifies: newest complete backup
    system.wipe()
    rep_paper = phase5.run(system=system, front=front, key_holder=collector, chain=chain)
    assert system.data is not None
    restored_paper = decode(system.data)
    assert isinstance(restored_paper, dict)

    # Alg. 5 with restore-time screening (HISTORY level). First-seen versions come from the chain.
    locations = identify(chain, system.identity, decrypt=collector.decrypt)
    by_backup: dict[str, list[Any]] = {}
    for loc in locations:
        by_backup.setdefault(loc.backup_id, []).append(loc)
    decrypted: dict[str, Files] = {}
    first_seen: Files = {}
    for bid, locs in sorted(by_backup.items(), key=lambda kv: kv[1][0].captured_at):
        _, data = alg5.request_decrypt(chain, alg5.begin(system.identity, locs), collector.decrypt)
        content = decode(data)
        assert isinstance(content, dict)
        decrypted[bid] = content  # type: ignore[assignment]
        for n, d in content.items():
            first_seen.setdefault(n, d)  # type: ignore[arg-type]
    screener = Screener(ScreenLevel.HISTORY)
    system.wipe()
    rep_screened = phase5.run(
        system=system, front=front, key_holder=collector, chain=chain,
        accept=lambda plan: screener.backup_clean(decrypted[plan.backup_id], first_seen),
    )  # fmt: skip
    assert system.data is not None
    restored_screened = decode(system.data)
    assert isinstance(restored_screened, dict)
    return {
        "style": style,
        "slow_burn_days": duration,
        "files_on_note_day": len(files),
        "files_encrypted": len(encrypted),
        "backups_on_chain": len(by_backup),
        "chain_height": len(chain),
        "paper": {"restored_backup_day": rep_paper.captured_at,
                  "damaged_files": damaged_in(restored_paper),  # type: ignore[arg-type]
                  "attestation_check_passed": True},  # fmt: skip
        "screened_history": {"restored_backup_day": rep_screened.captured_at,
                             "damaged_files": damaged_in(restored_screened),  # type: ignore[arg-type]
                             "backups_rejected": len(rep_screened.skipped),
                             "days_rolled_back": note_day - 1 - rep_screened.captured_at},  # fmt: skip
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261112)
    args = parser.parse_args()
    seed_all(args.seed)
    run_id = log.configure()
    chain_cfg = load_config(REPO_ROOT / "configs" / "chain.yaml", expected_kind="chain")

    a = {style: part_a(args.seed, style=style) for style in ("full", "stripes_10pct")}
    sys.stderr.write(f"A: {json.dumps(a)}\n")
    b = part_b(args.seed)
    c = part_c(args.seed)

    tables = REPO_ROOT / "results" / "tables"
    cols_b = list(b["cells"][0])
    (tables / "p2g_screening_vs_style.csv").write_text(
        "\n".join([",".join(cols_b)] + [",".join(
            f"{r[k]:.3f}" if isinstance(r[k], float) else str(r[k]) for k in cols_b)
            for r in b["cells"]]) + "\n", encoding="utf-8")  # fmt: skip
    cols_c = list(c[0])
    (tables / "p2g_slow_burn_timeline.csv").write_text(
        "\n".join([",".join(cols_c)] + [",".join(
            "" if r[k] is None else f"{r[k]:.3f}" if isinstance(r[k], float) else str(r[k])
            for k in cols_c) for r in c]) + "\n", encoding="utf-8")  # fmt: skip
    sidecar = {
        "run_id": run_id,
        "purpose": "P2-G: slow-burn ransomware poisons backups; content screening and its bypasses",
        "seed": args.seed,
        "config_hash": config_hash(chain_cfg.kind, chain_cfg.data),
        "config_hash_scheme": CONFIG_HASH_SCHEME,
        "git_rev": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                                  text=True, cwd=REPO_ROOT).stdout.strip(),  # fmt: skip
        "host": log.env_snapshot(),
        "protocol": {"attack_start_day": ATTACK_START, "header_skip_bytes": HEADER_SKIP,
                     "styles": STYLE_NOTES, "reps": REPS, "durations": DURATIONS,
                     "screen_policy_defaults": ScreenPolicy().__dict__ | {"level": "per cell"}},  # fmt: skip
        "part_a_real_pipeline": a,
        "part_b_screening_vs_style": b,
        "part_c_timeline": c,
    }
    (REPO_ROOT / "results" / "logs" / f"{run_id}.json").write_text(
        json.dumps(sidecar, indent=2, default=str) + "\n", encoding="utf-8"
    )
    print(json.dumps({"run_id": run_id}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
