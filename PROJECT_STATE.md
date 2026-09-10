# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-11 · **Milestone:** M1 (crypto) · **Sessions completed:** 1

---

## One-line status

M0 is closed: `clone → make setup → make test` works and runs 186 real tests. The `util/` layer
(canonical serialization, config + hash, structured logging, seeding) is built and green. Next is
the crypto layer.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Docs (`CLAUDE.md`, `docs/*`) | done | deviations DEV-01..16 pre-registered |
| `pyproject.toml`, `Makefile`, `.gitignore`, `configs/` | **done** | 8 make targets; later-milestone ones fail loudly |
| `util/` (config, logging, seed, serialization) | **done** | 186 unit tests, `mypy --strict` clean |
| `crypto/` | not started | **M1 — start here**, zero internal deps beyond `util` |
| `blockchain/`, `consensus/` | not started | M2 |
| `honeypot/`, `recovery/`, phases 1/2/5 | not started | M3 |
| `detection/`, phase 3 | not started | M4 |
| `mitigation/`, phase 4 | not started | M5 |
| `bench/`, figures | not started | M6 |

## Current numbers

None. No benchmark has been run; `RESULTS.md` holds only `paper_reported` rows. Every target in
`docs/EXPERIMENTS.md` is `paper_reported`, zero are `measured`.

## Next task

**M1-1 — crypto layer.** Start with `crypto/hashing.py` (the single SHA-256 entry point), which
also retires the temporary `hashlib` exemption in `util/config.py`. Then settle Q1 by benchmarking
`cryptography` against a pure-Python ECDSA, then `merkle.py`, `ecdsa.py`, `aead.py`, `kem.py`,
`session.py`. Exit: every §V-1 property has a passing test.

## Blockers

None.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q1 | Which ECDSA library — `cryptography` (fast, C-backed) or pure-Python for auditability? | M1 | benchmark both in M1, pick on speed since bench timings depend on it |
| Q2 | Transaction payload size — 4096 B now *declared* in `configs/chain.yaml` (DEV-15), but not yet justified | M6 result validity | sensitivity sweep over 1024/4096/16384 in M6 |
| Q3 | Does BitcoinHeist need the full 2.9M rows locally, or is a stratified subsample sufficient for `paper_mode`? | M4 | measure at M4 start; full runs go to Ada regardless |
| Q4 | Do we need real feature-space evasion for M7, or is that out of scope for a course deliverable? | M7 | defer until M6 lands |
| Q5 | Should entry points load one merged config object or the three files independently? | M6 | decide when `bench/` becomes the first multi-config consumer; `combined_config_hash()` already exists |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D1 | `util/config.py` calls `hashlib` directly, against CLAUDE.md §7. It is the only such call site, pinned by `HASHLIB_ALLOWED` in `tests/unit/test_module_boundaries.py`, because `crypto.hashing` did not exist yet. | M1-1: switch to `crypto.hashing.h()` and delete the exemption |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Python timings diverge so far from the paper's Java that trends don't reproduce | Targets 3 and 4 unverifiable | report ratios and shape, not seconds (DEV-13); already declared |
| KNN OOMs the 8 GB local box on full BitcoinHeist | M4 stalls | subsample by default, `--full` goes to Ada |
| `honest_mode` numbers come out poor enough to look like implementation failure | write-up confusion | publish the constant-classifier baseline next to every number so the comparison is unambiguous |
| Scope creep from M7 extensions before M6 lands | nothing ships | M7 is stretch; do not start before M6 exit |
| The canonical encoding changes after hashes exist | every stored hash silently unreproducible | `ENCODING_VERSION` plus pinned golden vectors in `test_serialization.py`; a format change must fail those tests first |

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
