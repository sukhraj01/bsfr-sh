# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-12 · **Milestone:** M3b (Phase 2) · **Sessions completed:** 5

---

## One-line status

M3a is closed. Phases 1 and 5 run end to end. Systems back up through pBFT onto `BC_DTBU`, and a
wiped system restores byte-identical over the two-hop path, including a 201-chunk backup across
three blocks at the configured sizes. `make test` runs 831 tests, `make test-all` 840, and
`make lint` is clean. Next is M3b, Phase 2, on the pipeline M3a built.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Docs (`CLAUDE.md`, `docs/*`) | done | DEV-23–25 opened and DEV-05, DEV-20 amended in M3a; M3 split into M3a/M3b |
| `pyproject.toml`, `Makefile`, `.gitignore`, `configs/` | done | `consensus.client_wait_timeouts` added (DECLARED) |
| `util/` | done | |
| `crypto/` | done | + `channel.py` (M3a): messages under `SK` |
| `blockchain/` | done | + `backup.py` (M3a): the `DT_BU` chunk/attest contract; `Chain.verify_block` |
| `consensus/` | done | unchanged in M3a |
| `framework/` entities, pipeline, phases 1 and 5 | **done** | M3a |
| `recovery/` | **done** | M3a: `locator` (index + scan), `restore` (Alg. 5) |
| `honeypot/`, `framework/phase2_collection.py` | not started | **M3b — start here** |
| `detection/`, phase 3 | not started | M4 |
| `mitigation/`, phase 4 | not started | M5 |
| `bench/`, figures | not started | M6 |

## Current numbers

One `measured` row exists: the Q1 ECDSA backend bake-off (`RESULTS.md` §Ours). M3a ran no
benchmark, by design. Every reproduction target is still `paper_reported`.

## What M3b must not re-derive

Established in M1–M3a; take these as given.

- **Phase 2 is a payload builder, nothing more.** Call
  `framework._block_pipeline.run(cluster, items, builder, chain=BC_SigRW, policy=..., timestamp=...)`
  with a builder that returns `encrypt_signature_record(...)` transactions. Do not edit the pipeline.
  If it seems to need a change, that is a finding to record, not a patch. It refuses a cluster
  whose chain is not the `chain` argument, batches `block.transactions_per_block` per request, and
  returns when `f+1` replicas hold every block. Read the result with `read_chain(cluster)`.
- **Submit transactions, never blocks** (DEV-22). The primary assembles `β_j`.
- **Consensus decides whether; `Chain` decides valid.** Block checks go in `Chain.check_append`
  and nowhere else.
- **Do not add per-transaction digest checks to `Chain`.** `MTR` covers only digests, but the block
  signature covers every transaction's full encoding. M3a added such a check, then reverted it as
  redundant: see the dead end in `sessions/2026-09-12-01-m3a-backup-and-recovery.md` and
  `test_chain_verify_block.py`.
- **Sessions carry data through `crypto.channel`.** Use `framework.entities.establish_session(a, b)`,
  then `a.channel(b.identity).seal(purpose, bytes)` / `.open(envelope, purpose)`. The AAD binds the
  session, the direction, the purpose string and a counter. `HP_RW` should be a
  `framework.entities.Participant` subclass that talks to `CS_l` this way (`SK_{CS_l,HP_RW}`).
- **One `Cluster` per chain**, sharing nothing (`test_pbft.py::test_two_clusters_share_no_state`).
  Replicas share `Block` *objects* (the bus never serialises, D3). So a storage-tamper test
  replaces a block in one chain's list rather than mutating it (`m3a_harness.tamper_ciphertext`).
- **The bus runs on simulated time.** The pipeline never advances the clock past the last commit
  (`test_a_zero_delay_run_leaves_no_phantom_simulated_time`). Never add `sleep`.
- **`recovery/` and everything below `framework/` never import `framework/`.** Pinned by
  `test_module_boundaries.py`.
- **Test harnesses:** `tests/unit/pbft_harness.py` (clusters, byzantine behaviours) and
  `tests/unit/m3a_harness.py` (fixture-keyed entities, direct-append chains).
  `tests/integration/conftest.py` puts both on the path.

## Next task

**M3b — Phase 2 on `BC_SigRW`.** Build `honeypot/collector.py` + `preprocess.py` (Alg. 2 lines
1–4, synthesized feature records only, never executable code) and `honeypot/signatures.py` +
`features.py` (Alg. 2 lines 5–6, DEV-03's two-sense `Sig_RW` and 7-group `FT_RW` per
`docs/ARCHITECTURE.md` §honeypot). Then build `framework/phase2_collection.py` (Alg. 2) as a payload builder
over M3a's `_block_pipeline` with no change to the pipeline. Exit: signature records land on
`BC_SigRW` through consensus and decrypt to exactly what was built. If DEV-03's feature design and
the phase wiring do not fit one session, split them the way M3 was split, and say so first.

## Blockers

None.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q2 | Transaction payload size — 4096 B *declared* (DEV-15), not justified | M6 result validity | **Deferred, deliberately.** Needs M6's 1024/4096/16384 sweep. DEV-24 now pins the meaning: backup bytes per transaction, before 215 B of framing and 161 B of encryption overhead (measured). |
| Q3 | Does BitcoinHeist need the full 2.9M rows locally, or is a stratified subsample enough for `paper_mode`? | M4 | measure at M4 start; full runs go to Ada regardless |
| Q4 | Do we need real feature-space evasion for M7, or is that out of scope for a course deliverable? | M7 | defer until M6 lands |
| Q5 | Should entry points load one merged config object or the three files independently? | M6 | decide when `bench/` becomes the first multi-config consumer |
| Q8 | Does anything before M7 need pBFT state transfer (DEV-20 item 2)? | M6 | only matters if M6 benchmarks a lossy network; decide at M6 start |

## For the write-up

**§V-3.** This is a substantive critique. §V-3 argues that "PoW is 51%-vulnerable, so we use
pBFT". But pBFT's threshold is **one third**, so the switch lowers the bar. With four nodes, two
colluders (50%) fork the chain, and a test asserts the fork. The fair concession: pBFT counts
identities, not hash power. [FLAW-5] is in `docs/PAPER_NOTES.md` §V, and the mapping is in the
M2b session file.

**§V-1 / §V-5 after M3a.** §V-1 holds at both places Phases 1 and 5 use session keys: replay,
reflection, re-purposing and impersonation are each refused by a test. But session keys protect
bytes in *transit*, not at the servers. §IV-E's two plaintext-holding hops meant GAP-8 needed
DEV-23's attestation. §V-5 is substantiated only structurally: recovery reads only `BC_DTBU`, and
the pipeline refuses the other chain's cluster. Its actual point, that compromising detection
does not reach recovery, needs Phases 2–3. The claim-by-claim mapping is in the M3a session file.

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D2 | `make lint` runs `ruff check src tests` but not `scripts/`, and `mypy` only covers `src`. `scripts/bench_ecdsa_backends.py` is still unchecked. | M6, when `scripts/` stops being nearly empty |
| D3 | The bus passes Python objects and never serialises, so wire-encoding cost is absent from the consensus span and backup wire size is measured nowhere. In M3a it shaped the tamper tests (see above), but no claim depends on it. | M6 — serialise at the bus, or state in Target 3 that it was not |
| D4 | `ClientRequest` from `CS_l` to the replicas is still unauthenticated (DEV-20 item 5, M3a amendment). Junk transactions can be committed; they cannot be restored as anyone's data. | when a claim needs it — sign requests with the submitting server's key |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Python timings diverge so far from the paper's Java that trends don't reproduce | Targets 3 and 4 unverifiable | report ratios and shape, not seconds (DEV-13) |
| Zero-delay consensus is ~1 ms/block, so Fig. 6 measures encryption, not consensus | Target 3 claims something different from the paper | DEV-21: M6 runs delay 0 and delay > 0 and reports them in separate columns |
| KNN OOMs the 8 GB local box on full BitcoinHeist | M4 stalls | subsample by default, `--full` goes to Ada |
| `honest_mode` numbers come out poor enough to look like implementation failure | write-up confusion | publish the constant-classifier baseline next to every number |
| Scope creep from M7 extensions before M6 lands | nothing ships | M7 is stretch; do not start before M6 exit |
| The canonical encoding changes after hashes exist | every stored hash silently unreproducible | `ENCODING_VERSION` plus pinned golden vectors |
| Validation migrates out of `Chain` into `consensus/`, `framework/` or `recovery/` | two definitions of a valid block, drifting | `check_append` / `verify_block` are the only validators |
| On-chain backups are large: at 4 KiB per transaction, 1 MB is 250 transactions and 2.5 blocks | GAP-2's practicality question gets worse, not better | report storage honestly (M7); M6's payload sweep states that framing is included |

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
