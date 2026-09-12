"""Fetch and verify BitcoinHeist into `data/raw/`. This is `make data`.

Thin wrapper: the download is `urllib`, and the verification that matters —
2,916,697 rows / 2,875,284 benign / 41,413 ransomware — lives in
`bsfr_sh.detection.dataset.verify_counts`, because it is the anchor for every reproduction claim
in M4 and belongs with the loader rather than in a script.

The dataset is ~50 MB zipped and gitignored, so it is fetched per machine. A provenance file
(`data/raw/provenance.json`) records the URL, the SHA-256 of the archive and the verified counts,
so a later run can tell "the same dataset" from "a dataset with the same name".

Usage::

    python scripts/fetch_bitcoinheist.py            # fetch, extract, verify
    python scripts/fetch_bitcoinheist.py --verify-only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bsfr_sh.detection.dataset import (  # noqa: E402
    BENIGN_LABEL,
    LABEL_COLUMN,
    DatasetError,
    verify_counts,
)
from bsfr_sh.util import logging as log  # noqa: E402

#: UCI ML Repository, dataset 526 (paper ref [15]).
URL = "https://archive.ics.uci.edu/static/public/526/bitcoinheistransomwareaddressdataset.zip"
RAW_DIR = REPO_ROOT / "data" / "raw"
CSV_NAME = "BitcoinHeistData.csv"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _count(csv_path: Path) -> tuple[int, int, int, int]:
    """Stream the file once: (rows, benign, ransomware, families). Never loads it into memory."""
    import csv as csv_module

    rows = benign = 0
    families: set[str] = set()
    with csv_path.open(encoding="utf-8", newline="") as handle:
        reader = csv_module.DictReader(handle)
        if reader.fieldnames is None or LABEL_COLUMN not in reader.fieldnames:
            raise DatasetError(f"{csv_path.name} has no {LABEL_COLUMN!r} column")
        for row in reader:
            rows += 1
            if row[LABEL_COLUMN] == BENIGN_LABEL:
                benign += 1
            else:
                families.add(row[LABEL_COLUMN])
    return rows, benign, rows - benign, len(families)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=URL)
    parser.add_argument("--verify-only", action="store_true", help="skip the download")
    args = parser.parse_args()

    log.configure()
    logger = log.get_logger(__name__)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = RAW_DIR / CSV_NAME
    archive = RAW_DIR / "bitcoinheist.zip"

    if not args.verify_only and not csv_path.exists():
        log.event(logger, "dataset_download_started", url=args.url)
        with urllib.request.urlopen(args.url) as response, archive.open("wb") as out:  # noqa: S310
            shutil.copyfileobj(response, out)
        with zipfile.ZipFile(archive) as bundle:
            members = [n for n in bundle.namelist() if n.lower().endswith(".csv")]
            if len(members) != 1:
                raise DatasetError(f"expected one CSV in the archive, found {members}")
            with bundle.open(members[0]) as src, csv_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        log.event(logger, "dataset_extracted", csv=csv_path.name, bytes=csv_path.stat().st_size)

    if not csv_path.exists():
        raise DatasetError(f"{csv_path} is missing; run without --verify-only to fetch it")

    rows, benign, ransomware, families = _count(csv_path)
    verify_counts(rows, ransomware, benign)  # raises unless it is the paper's dataset
    log.event(
        logger,
        "dataset_verified",
        rows=rows,
        benign=benign,
        ransomware=ransomware,
        families=families,
        positive_rate=round(ransomware / rows, 6),
    )

    provenance = {
        "url": args.url,
        "csv_sha256": _sha256(csv_path),
        "archive_sha256": _sha256(archive) if archive.exists() else None,
        "csv_bytes": csv_path.stat().st_size,
        "rows": rows,
        "benign": benign,
        "ransomware": ransomware,
        "ransomware_families": families,
        "verified_against": "docs/EXPERIMENTS.md Target 2 (paper §VII)",
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    (RAW_DIR / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    log.event(logger, "provenance_written", path="data/raw/provenance.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
