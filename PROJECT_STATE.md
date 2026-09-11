# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-11 · **Milestone:** M2b (consensus) · **Sessions completed:** 3

---

## One-line status

M2a is closed: `Transaction`, `Block` and `Chain` are built, both chains reach 15 blocks x 100
transactions by direct append, `make test` runs 465 tests and `make lint` is clean. Debt D1 is
retired. Next is pBFT.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Docs (`CLAUDE.md`, `docs/*`) | done | DEV-01/02/11 amended in M1; DEV-17/18 added in M2a |
| `pyproject.toml`, `Makefile`, `.gitignore`, `configs/` | done | 8 make targets; later-milestone ones fail loudly |
| `util/` (config, logging, seed, serialization) | done | `Config` no longer carries a digest — see D1 below |
| `crypto/` | done | hashing, merkle, ecdsa, aead, kem, session — 161 tests |
| `blockchain/` | **done** | transaction, block, chain — 107 tests |
| `consensus/` | not started | **M2b — start here** |
| `honeypot/`, `recovery/`, phases 1/2/5 | not started | M3 |
| `detection/`, phase 3 | not started | M4 |
| `mitigation/`, phase 4 | not started | M5 |
| `bench/`, figures | not started | M6 |

## Current numbers

One `measured` row exists: the Q1 ECDSA backend bake-off (`RESULTS.md` §Ours). M2a produced no
benchmark — the case-3 build is a correctness test, not a timing run, and timing it before
consensus exists would measure the wrong thing. Every reproduction target is still
`paper_reported`.

## What M2b must not re-derive

Established in M1 and M2a; take these as given.

- **`crypto/` exposes one function per job.** `merkle_root()` for `MTR`, `tagged_h()` for any
  positional digest, `seal_payload()`/`open_payload()` for transaction payloads. Recomputing any
  of them by hand silently loses domain separation or the DEV-11 count binding.
- **A `Block` is always self-consistent.** `merkle_root` and `current_hash` are derived, not
  stored; the signature is verified in `__post_init__`. If you hold a `Block`, its hash covers
  its contents and its signature verifies under its own `owner_pubkey`. Do not re-check that —
  check the things `Chain.append` checks: linkage, freshness, and quorum.
- **`Sig_βj` covers `BlockPart.SIGN`** — every header field except `signature`. pBFT messages
  need their own domain separation; do not reuse the block signing pre-image for a pre-prepare.
- **`RN` is inert.** It is in the header for fidelity only. There is no difficulty target and no
  mining loop, and adding one would make Fig. 6 a measurement of an arbitrary difficulty setting.
- **Chains share no state.** No class attributes, no mutable defaults, no registry.
  `test_chains_independent.py` asserts it from outside; keep it passing when nodes are added.
- **`config_hash` lives in `crypto.hashing`,** not on `Config`. Compose the two layers.

## Next task

**M2b — consensus.** Build `consensus/network.py` (in-process P2PCS message bus) and
`consensus/pbft.py` (pre-prepare / prepare / commit at `2f+1` of `n=3f+1`, view change on leader
timeout, per DEV-10), with the four byzantine fixtures — silent, equivocating, wrong-signature,
stale-view. Consensus decides *whether* a block is appended; `Chain.append` still decides whether
it is valid, so do not move validation into the protocol. Exit: both chains build 15 blocks x 100
tx with 4 nodes and `f=1` tolerated.

## Blockers

None.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q2 | Transaction payload size — 4096 B *declared* in `configs/chain.yaml` (DEV-15), not justified | M6 result validity | **Deferred, deliberately.** Closing it means *justifying* the value, which needs M6's 1024/4096/16384 sweep against real timings; asserting a number now without that evidence is what DEV-15 exists to avoid. M2a closed the part that could be closed: the value is read from config everywhere, never literalled, pinned by `test_chain_scale.py::test_payload_size_comes_from_config_not_from_a_literal`. So the sweep will actually move it. |
| Q3 | Does BitcoinHeist need the full 2.9M rows locally, or is a stratified subsample enough for `paper_mode`? | M4 | measure at M4 start; full runs go to Ada regardless |
| Q4 | Do we need real feature-space evasion for M7, or is that out of scope for a course deliverable? | M7 | defer until M6 lands |
| Q5 | Should entry points load one merged config object or the three files independently? | M6 | decide when `bench/` becomes the first multi-config consumer; `combined_config_hash()` now takes `{kind: hash}` |
| Q7 | Does a pBFT pre-prepare carry the whole block or just its `current_hash`? | M2b | the paper says only "broadcast `β_j`"; whole-block is simpler and matches the text, hash-only is what real pBFT does. Decide in M2b and record as a DEV if we depart from the text. |

**Q6 is closed.** `Transaction` carries **no** signature of its own. The paper shows only
`Sig_βj` (Alg. 1 line 3), and that is sufficient: a transaction reaches a chain only inside a
signed block, `MTR` binds it to that block, and the DEV-01 AAD binding stops it being moved
between transactions. A per-transaction signature would have been a deviation needing a DEV
entry, and it would have added 100 ECDSA operations per block to every Fig. 6 timing.

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D2 | `make lint` runs `ruff check src tests` but not `scripts/`, and `mypy` only covers `src`. `scripts/bench_ecdsa_backends.py` is still unchecked. Unchanged in M2a — no new script was added, and widening the targets mid-session would have mixed a tooling change into a milestone. | M6, when `scripts/` stops being nearly empty |

**D1 is retired.** `config_hash()` and `combined_config_hash()` moved to `crypto.hashing`, the
`config_hash` field is gone from `Config`, and `util/config.py` no longer imports `hashlib` —
`crypto/hashing.py` is the tree's only importer, as CLAUDE.md §7 requires. Pinned by
`test_module_boundaries.py` and `test_config.py::test_config_carries_no_digest_field`.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Python timings diverge so far from the paper's Java that trends don't reproduce | Targets 3 and 4 unverifiable | report ratios and shape, not seconds (DEV-13); already declared |
| KNN OOMs the 8 GB local box on full BitcoinHeist | M4 stalls | subsample by default, `--full` goes to Ada |
| `honest_mode` numbers come out poor enough to look like implementation failure | write-up confusion | publish the constant-classifier baseline next to every number |
| Scope creep from M7 extensions before M6 lands | nothing ships | M7 is stretch; do not start before M6 exit |
| The canonical encoding changes after hashes exist | every stored hash silently unreproducible | `ENCODING_VERSION` plus pinned golden vectors; a format change must fail those tests first |
| M2b implements a proof-of-work loop around the inert `RN` field | Fig. 6 measures an invented difficulty setting, not BSFR-SH | documented in `block.py`, `docs/ARCHITECTURE.md` and above; pBFT has no mining step |
| Validation migrates from `Chain.append` into the consensus layer | two places decide what a valid block is, and they drift | `append` stays the sole validator; consensus decides *whether*, not *whether valid* |

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
