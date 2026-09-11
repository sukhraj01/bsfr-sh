# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-11 · **Milestone:** M3 (phases 1, 2, 5) · **Sessions completed:** 4

---

## One-line status

M2b is closed: pBFT consensus runs each chain as a 4-replica cluster; both chains build 15 blocks
x 100 transactions through full consensus with one byzantine replica tolerated. `make test` runs
618 tests and `make lint` is clean. Next is M3, starting with Phase 1 end to end.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Docs (`CLAUDE.md`, `docs/*`) | done | DEV-19–22 added in M2b; DEV-10 amended |
| `pyproject.toml`, `Makefile`, `.gitignore`, `configs/` | done | 8 make targets; later-milestone ones fail loudly |
| `util/` (config, logging, seed, serialization) | done | |
| `crypto/` | done | hashing, merkle, ecdsa, aead, kem, session |
| `blockchain/` | done | transaction, block, chain; `check_append` / `adopt_genesis` added in M2b |
| `consensus/` | **done** | network, protocol, view_change, pbft — 153 tests; 15 safety mutants all killed |
| `honeypot/`, `recovery/`, phases 1/2/5 | not started | **M3 — start here** |
| `detection/`, phase 3 | not started | M4 |
| `mitigation/`, phase 4 | not started | M5 |
| `bench/`, figures | not started | M6 |

## Current numbers

One `measured` row exists: the Q1 ECDSA backend bake-off (`RESULTS.md` §Ours). M2b produced no
benchmark by design — consensus timing is M6. Every reproduction target is still
`paper_reported`.

## What M3 must not re-derive

Established in M1–M2b; take these as given.

- **Submit transactions, never blocks.** `CS_l` encrypts (`encrypt_backup` /
  `encrypt_signature_record`) and calls `Cluster.submit(transactions, timestamp=...)`. The pBFT
  primary assembles and signs `β_j` (DEV-22). Do not build blocks in `framework/`.
- **Consensus decides whether; `Chain` decides valid.** Replicas call `Chain.check_append()`
  before preparing and `append()` on commit. Do not add block checks to `consensus/` or
  `framework/` — add them to `Chain.check_append`, which both paths run.
- **One `Cluster` per chain.** `BC_DTBU` and `BC_SigRW` each get their own cluster, bus and
  replica keys. Replicas of one chain share one genesis block via `build_genesis` +
  `adopt_genesis`; two clusters share nothing (`test_pbft.py::test_two_clusters_share_no_state`).
- **Read a committed chain from any honest replica,** e.g. `cluster.replicas[rid].chain`. All
  honest replicas hold the same blocks; a lagging one may hold fewer (DEV-20 item 2).
- **The bus runs on simulated time.** `cluster.run()` drains; with a faulty replica it may never
  go idle — use `cluster.run(until=network.now + T)`. Never add `sleep`.
- **`ClientRequest` is unauthenticated at the consensus layer** (DEV-20 item 5). M3's Phase 1 is
  where the submitter is authenticated, via a `crypto.session` key.
- **`crypto/` exposes one function per job**; `Block` is self-consistent by construction; `RN` is
  inert; chains share no state; `config_hash` lives in `crypto.hashing`. (M1/M2a, unchanged.)

## Next task

**M3 — Phase 1 end to end.** Build `framework/_block_pipeline.py` and `framework/phase1_backup.py`
(Alg. 1): a `SYS_i` ships backups to `CS_l` over a `crypto.session` key; `CS_l` encrypts them with
`encrypt_backup` and submits them through `Cluster.submit`, authenticating the submitter at the
session layer. Exit: an integration test in `tests/integration/` backs up a system's data onto
`BC_DTBU` through consensus and reads it back byte-identical. Honeypot and recovery follow in later
M3 sessions.

## Blockers

None.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q2 | Transaction payload size — 4096 B *declared* (DEV-15), not justified | M6 result validity | **Deferred, deliberately.** Justifying it needs M6's 1024/4096/16384 sweep against real timings. The value is read from config everywhere and pinned by a test, so the sweep will actually move it. |
| Q3 | Does BitcoinHeist need the full 2.9M rows locally, or is a stratified subsample enough for `paper_mode`? | M4 | measure at M4 start; full runs go to Ada regardless |
| Q4 | Do we need real feature-space evasion for M7, or is that out of scope for a course deliverable? | M7 | defer until M6 lands |
| Q5 | Should entry points load one merged config object or the three files independently? | M6 | decide when `bench/` becomes the first multi-config consumer |
| Q8 | Does anything before M7 need pBFT state transfer (DEV-20 item 2)? Without it a replica that misses a commit stays behind and counts against `f`. | M6 | only matters if M6 benchmarks a lossy network; decide at M6 start |

**Q7 is closed** — DEV-19. Pre-prepare signs `(chain, view, seq, digest, replica_id)`; the block
travels alongside and must satisfy `current_hash == digest`.

## For the write-up — §V-3

§V-3's "pBFT resists 51% attacks" is inverted: pBFT is safe only below **one third** byzantine.
Two colluding nodes of four fork it, and a test asserts the fork. FINDING in `docs/PAPER_NOTES.md`
§V; full claim-by-claim mapping in `sessions/2026-09-11-03-m2b-pbft-consensus.md`.

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D2 | `make lint` runs `ruff check src tests` but not `scripts/`, and `mypy` only covers `src`. `scripts/bench_ecdsa_backends.py` is still unchecked. | M6, when `scripts/` stops being nearly empty |
| D3 | The bus passes Python objects and never serialises, so wire-encoding cost is absent from the consensus span. At zero delay that understates consensus cost further. | M6 — serialise at the bus, or state in Target 3 that it was not |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Python timings diverge so far from the paper's Java that trends don't reproduce | Targets 3 and 4 unverifiable | report ratios and shape, not seconds (DEV-13) |
| Zero-delay consensus is ~1 ms/block, so Fig. 6 measures encryption, not consensus | Target 3 claims something different from the paper | DEV-21: M6 runs delay 0 and delay > 0, reports compute and modelled network time as separate columns (`configs/bench.yaml`) |
| KNN OOMs the 8 GB local box on full BitcoinHeist | M4 stalls | subsample by default, `--full` goes to Ada |
| `honest_mode` numbers come out poor enough to look like implementation failure | write-up confusion | publish the constant-classifier baseline next to every number |
| Scope creep from M7 extensions before M6 lands | nothing ships | M7 is stretch; do not start before M6 exit |
| The canonical encoding changes after hashes exist | every stored hash silently unreproducible | `ENCODING_VERSION` plus pinned golden vectors |
| Validation migrates out of `Chain` into `consensus/` or `framework/` | two definitions of a valid block, drifting | `check_append` is the single validator; see "must not re-derive" |

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
