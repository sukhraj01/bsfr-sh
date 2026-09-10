# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-11 · **Milestone:** M2 (blockchain + consensus) · **Sessions completed:** 2

---

## One-line status

M1 is closed: all six `crypto/` modules are built, `make test` runs 347 tests and `make lint` is
clean, Q1 is decided on measured numbers, and every §V-1 property has a passing test. Next is
`blockchain/` — the first consumer of these primitives.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Docs (`CLAUDE.md`, `docs/*`) | done | DEV-01/02/11 amended in M1 |
| `pyproject.toml`, `Makefile`, `.gitignore`, `configs/` | done | 8 make targets; later-milestone ones fail loudly |
| `util/` (config, logging, seed, serialization) | done | cross-process determinism re-verified in M1 |
| `crypto/` | **done** | hashing, merkle, ecdsa, aead, kem, session — 161 tests |
| `blockchain/`, `consensus/` | not started | **M2 — start here** |
| `honeypot/`, `recovery/`, phases 1/2/5 | not started | M3 |
| `detection/`, phase 3 | not started | M4 |
| `mitigation/`, phase 4 | not started | M5 |
| `bench/`, figures | not started | M6 |

## Current numbers

One `measured` row exists: the Q1 ECDSA backend bake-off (`RESULTS.md` §Ours). Every
reproduction target in `docs/EXPERIMENTS.md` is still `paper_reported`.

## What M2 must not re-derive

Established in M1; take these as given rather than re-litigating them.

- **`util.serialization` is deterministic across processes.** Re-verified under four
  `PYTHONHASHSEED` values in separate interpreters. No `json`, no `pickle`, no `hash()`.
- **`crypto.hashing.tagged_h` is the positional hash.** `h()` is the bare primitive. A block
  header digest, a transaction digest and a Merkle leaf must use different domains — the
  constants already exist (`DOMAIN_BLOCK_HEADER`, `DOMAIN_TRANSACTION`, ...).
- **`MTR` binds the leaf count.** Call `crypto.merkle.merkle_root(...)`; do not recompute a root
  by hand. See DEV-11's amendment for why.
- **Transaction encryption is `crypto.kem.seal_payload` / `open_payload`.** Do not assemble the
  wrap and the AEAD separately — the DEV-01 binding only holds when applied in one place.
- **ECDSA is deterministic (RFC 6979).** Signatures over identical bytes are byte-identical, so
  fixture keys give reproducible test runs.

## Next task

**M2-1 — `blockchain/`.** Build `transaction.py`, `block.py` and `chain.py` against the field
orders already declared in `util.serialization` (`TRANSACTION_FIELD_ORDER`, `BLOCK_FIELD_ORDER`,
`BlockPart.HASH` / `.SIGN`), using `crypto.kem.seal_payload` for payloads and
`crypto.merkle.merkle_root` for `MTR`. `Block` should assert its own field names against
`BLOCK_FIELD_ORDER` so the dataclass and the encoder cannot drift. Consensus is M2-2, not this
task.

## Blockers

None.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q2 | Transaction payload size — 4096 B *declared* in `configs/chain.yaml` (DEV-15), not yet justified | M6 result validity | sensitivity sweep over 1024/4096/16384 in M6 |
| Q3 | Does BitcoinHeist need the full 2.9M rows locally, or is a stratified subsample enough for `paper_mode`? | M4 | measure at M4 start; full runs go to Ada regardless |
| Q4 | Do we need real feature-space evasion for M7, or is that out of scope for a course deliverable? | M7 | defer until M6 lands |
| Q5 | Should entry points load one merged config object or the three files independently? | M6 | decide when `bench/` becomes the first multi-config consumer; `combined_config_hash()` exists |
| Q6 | Does `Transaction` carry its own ECDSA signature, or is `Sig_βj` over the block the only signature? | M2 | the paper shows only `Sig_βj`; decide in M2-1 and record as a DEV if we add one |

**Q1 is closed.** `cryptography` (C/OpenSSL), on measured throughput: 39,371 sign/s and 23,306
verify/s versus 2,307 and 588 for pure-Python `ecdsa` — 17x and 40x. At the pure-Python rate,
case-3's 1500 transactions would spend ~2.6 s on verification alone, ~45% of the 5.71 s the paper
reports for the entire case, so Fig. 6 would be measuring the signature library. Both rows are in
`RESULTS.md`; `ecdsa` stays in the dev extras so the comparison is re-runnable.

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D1 | `util/config.py` still calls `hashlib` directly. **M1 could not retire this as written.** The M0 plan was for it to import `crypto.hashing.h()`, but `util` may not import upward — `test_util_depends_on_nothing_else_in_the_package` forbids it and `docs/ARCHITECTURE.md` fixes the direction as `util <- crypto`. Both rules cannot hold while `util.config` computes its own digest. Fix: move `config_hash()`/`combined_config_hash()` into `crypto.hashing`, drop the `config_hash` field from the `Config` dataclass, and let `bench`/`scripts` compose the two. | M2 — it touches `Config` and the M0 tests that pin it, so it wants its own task |
| D2 | `make lint` runs `ruff check src tests` but not `scripts/`, and `mypy` only covers `src`. `scripts/bench_ecdsa_backends.py` is therefore unchecked. | M6, when `scripts/` stops being nearly empty |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Python timings diverge so far from the paper's Java that trends don't reproduce | Targets 3 and 4 unverifiable | report ratios and shape, not seconds (DEV-13); already declared |
| KNN OOMs the 8 GB local box on full BitcoinHeist | M4 stalls | subsample by default, `--full` goes to Ada |
| `honest_mode` numbers come out poor enough to look like implementation failure | write-up confusion | publish the constant-classifier baseline next to every number |
| Scope creep from M7 extensions before M6 lands | nothing ships | M7 is stretch; do not start before M6 exit |
| The canonical encoding changes after hashes exist | every stored hash silently unreproducible | `ENCODING_VERSION` plus pinned golden vectors; a format change must fail those tests first |
| M2 recomputes a digest or a Merkle root by hand instead of calling `crypto/` | domain separation and the DEV-11 count binding silently lost | `crypto/` exposes exactly one function per job; see "What M2 must not re-derive" above |

---

## Maintenance rule

This file is **replaced, not appended.** At session end:

1. Rewrite the tables above so they describe reality *now*.
2. Delete anything resolved. A closed question leaves this file entirely — its reasoning lives in
   the session log that closed it.
3. Do not paste benchmark output here. One aggregate number max; details go to `RESULTS.md`.
4. Do not paste narrative here. Narrative goes to `sessions/`.
5. If you are about to add a fifth row to a table that already has ten, something is being
   tracked at the wrong granularity — move it to `docs/ROADMAP.md`.

**Why the cap exists:** we run one session per task, so this file is read at the start of *every*
session. A 200-line file costs a few seconds of context. A 2,500-line one costs a meaningful
fraction of the window before any work begins, and the agent will skim rather than read it — which
is worse than not having it.

## Boundaries with other docs

| File | Holds | Volatility |
|---|---|---|
| `PROJECT_STATE.md` | what is true right now | rewritten every session |
| `docs/ROADMAP.md` | the plan, M0–M7, checkboxes | ticked, rarely restructured |
| `RESULTS.md` | every benchmark ever run, one line each | append-only |
| `sessions/` | what happened in each session | append-only, one file per session |
| `docs/DEVIATIONS.md` | departures from the paper | append-only |
| `CLAUDE.md` | how to work here | near-stable |

If a fact could go in two of these, it goes in exactly one — the leftmost row that fits.
