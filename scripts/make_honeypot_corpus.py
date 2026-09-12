"""Generate the honeypot corpus into `data/honeypot/`. Thin wrapper; the logic is in the package.

    python scripts/make_honeypot_corpus.py --seed 20260912 --train 1500 --eval 750

Writes two *independent draws* (different seeds, never one draw shuffled) and a manifest that
records the seeds, the schema, the class balance and the corpus's intended difficulty.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from bsfr_sh.honeypot.corpus import build_draw, manifest_for, write_corpus, write_manifest
from bsfr_sh.util.logging import configure, event, get_logger

_LOG = get_logger("scripts.make_honeypot_corpus")
_REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260912, help="seed of the training draw")
    parser.add_argument("--train", type=int, default=1500, help="training draw size")
    parser.add_argument("--eval", type=int, default=750, help="evaluation draw size")
    parser.add_argument(
        "--malicious-fraction", type=float, default=0.5, help="share of malicious episodes"
    )
    parser.add_argument(
        "--out", type=Path, default=_REPO_ROOT / "data" / "honeypot", help="output directory"
    )
    args = parser.parse_args()

    configure()
    # The eval draw must come from a different generator call, not a shuffle of the train draw:
    # samples within one call can share latent parameters.
    eval_seed = args.seed + 1
    draws = {
        "train": {"seed": args.seed, "requested": args.train},
        "eval": {"seed": eval_seed, "requested": args.eval},
    }

    for name, (seed, count) in {
        "train": (args.seed, args.train),
        "eval": (eval_seed, args.eval),
    }.items():
        records, report = build_draw(
            seed=seed, count=count, malicious_fraction=args.malicious_fraction
        )
        path = write_corpus(args.out / f"corpus_{name}.csv", records)
        draws[name]["kept"] = len(records)
        draws[name]["dropped"] = report.dropped
        event(
            _LOG,
            "corpus_draw_written",
            draw=name,
            seed=seed,
            requested=count,
            kept=len(records),
            dropped=report.dropped,
            path=str(path.relative_to(_REPO_ROOT)),
        )

    manifest_path = write_manifest(
        args.out / "manifest.json",
        manifest_for(draws, malicious_fraction=args.malicious_fraction),
    )
    event(_LOG, "corpus_manifest_written", path=str(manifest_path.relative_to(_REPO_ROOT)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
