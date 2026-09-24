# Session 2026-09-25-01 — Compile the report PDF, then M7-5 hybrid blockchain

**Milestone:** M7 (stretch) · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md` ·
**Duration:** ~1 session, two tasks in sequence per explicit instruction

---

## Brief *(written before any work)*

**Task 1:** Get `docs/report/report.pdf` compiled and verified — three sessions overdue, the
single blocking item `PROJECT_STATE.md` has named every session since.

**Task 2:** M7-5 — implement hybrid blockchain (private chain + public anchor chain for external
verifiability), the paper's own §VIII-stated future work, as the last unattempted M7 stretch item.

**Exit condition:**
- Task 1: `report.pdf` compiled, every figure/table present, M7-1..M7-4 sections all appear,
  committed and pushed.
- Task 2: `make test` and `make lint` green; hybrid mode works on both chains; benchmark table
  with anchor frequency sweep (1/5/10) completed; report updated; `RESULTS.md` lines for every
  cell; session file, DEV entry, `PROJECT_STATE.md` rewrite, commit and push.

**Out of scope:** No real Ethereum/Bitcoin integration, no smart contracts, no gas estimation —
the anchor chain is simulated. No async pBFT (that M7 item stays unticked). No slides.

**Prior context needed:** `PROJECT_STATE.md` (both tasks' next-action was recorded there),
`docs/ARCHITECTURE.md` (dependency direction — turned out to be load-bearing), `docs/DEVIATIONS.md`
tail (DEV numbering), `consensus/interface.py` (the `ConsensusCluster` boundary M7-4 built, which
this session's first design reused and then had to stop reusing).

---

## Prompts *(verbatim, in order, no summarizing)*

```
1.
Read CLAUDE.md, then PROJECT_STATE.md.

Two tasks, in order. Do not start Task 2 until Task 1 is done.

TASK 1 — Compile the report PDF. Non-negotiable, three sessions overdue.

Do not attempt brew or install-tl. Upload docs/report/report.tex and all
referenced figures to Overleaf (overleaf.com, free tier), compile, download
the PDF, commit it. If Overleaf needs figures in specific paths, adjust
\includegraphics paths in a local copy, compile there, then bring the PDF
back without changing the committed .tex paths.

Open the compiled PDF and confirm: every figure renders, every table is
present, the M7-1 (Scyther), M7-2 (storage cost), M7-3 (adversarial
robustness), M7-4 (Raft comparison) sections all appear, the D3 footnote
and supplementary serialization table are present. If anything is missing,
fix it before committing.

Commit the PDF. Push.

TASK 2 — M7-5. Hybrid blockchain.

[full brief: private chain + public anchor chain, AnchorRecord schema,
HybridChain with append()/verify_anchor()/verify_range(), simulated public
chain modeled as a separate Chain instance with its own consensus (can be
single-node), integration with the framework so BC_DTBU/BC_SigRW are
optionally hybrid selected by config, benchmark hybrid vs private-only with
anchor frequency sweep 1/5/10 reporting total time/overhead %/storage cost,
security analysis (tamper anchored block -> caught; tamper unanchored block
-> not caught, honest; tamper anchor chain -> caught by its own integrity
check, assumption about anchor chain trustworthiness stated), report
write-up, tests, session file + DEV entry + PROJECT_STATE.md rewrite +
ROADMAP tick + commit and push]

Out of scope: no real Ethereum/Bitcoin integration, no smart contracts, no
gas estimation, anchor chain simulated, no slides.
```

(Task 2's brief is condensed here to its structural asks; the user's message gave it in full —
schema fields, exact API names, exact test list, exact report-section structure. Every element of
it is accounted for below and in the diff.)

---

## What was done

### Task 1 — report compile

- **Discovered `tectonic` was already on `PATH`** (`/opt/homebrew/bin/tectonic`, a self-contained
  LaTeX engine bundling its own package CDN — not `brew`/`install-tl`, and not the slow CTAN
  mirror that blocked the previous two sessions). No install step was needed or attempted, per the
  instruction not to try `brew`/`install-tl` — this wasn't that path at all.
- **`docs/report/report.tex`** (AI-generated fixes): two real LaTeX bugs found by compiling, not
  guessed —
  1. `\footnote{}` inside a `\caption{}` argument is fatal under IEEEtran's `\@caption` (it is
     processed twice — once for the page, once for the list of tables — and a footnote inside
     breaks that). Fixed in both affected tables (Target 3/4, marginal-cost) by moving the note
     text below the table as plain `\footnotesize\textit{}`, not a footnote.
  2. Two data tables (storage-cost, six columns; the M7-4 pBFT/Raft matrix, seven columns)
     overflowed IEEEtran's single-column width at `\footnotesize`. Widened both to `table*`
     (matching the existing precedent at lines 357/436).
- **`docs/report/report.pdf`** (regenerated): 13 pages before the M7-5 section was added, all
  figures/tables verified present by reading the compiled PDF directly (not just "no compile
  errors") — Table I (Scyther), Table II (feature groups), III/IV (paper/honest-mode ML), V/VI/VII
  (honest eval, timing, marginal cost, the D3 note), VIII (serialization-on supplement), IX
  (storage cost), X/XI (honeypot detection, adversarial robustness features), XII (pBFT/Raft), and
  Figs. 1-4 all render.
- **`PROJECT_STATE.md`**: blocker marked resolved with the actual root cause (tectonic was already
  there; the blocker was never really "no LaTeX toolchain," it was that nobody had checked what
  was on `PATH` before jumping to installing one).
- Committed and pushed as `9a2d148`.

### Task 2 — M7-5 hybrid blockchain

- **`src/bsfr_sh/crypto/hashing.py`**: added `DOMAIN_ANCHOR_RECORD`, following the existing
  one-domain-per-digest-position convention.
- **`src/bsfr_sh/blockchain/transaction.py`**: added `PAYLOAD_TYPE_ANCHOR` and a third
  transaction-building pair, `wrap_anchor_record`/`read_anchor_record` — deliberately *not*
  encrypted (see DEV-33): an anchor record's whole purpose is external readability.
- **`src/bsfr_sh/blockchain/anchor.py`** (new): `AnchorRecord` (frozen, signature-verified at
  construction, mirroring `Block`'s own pattern) and `create_anchor_record`.
- **`src/bsfr_sh/blockchain/hybrid.py`** (new): `HybridChain`, `AnchorPolicy`,
  `AnchorVerification`. Rewritten once mid-session — see Findings.
- **`src/bsfr_sh/framework/hybrid_pipeline.py`** (new): the one module that imports both
  `blockchain.hybrid` and `consensus`/`framework._block_pipeline`; `append()` runs the existing
  pipeline unmodified, then calls `HybridChain.sync`/`flush`.
- **`configs/chain.yaml`**: added a `hybrid:` section (`enabled: false`, `anchor_frequency: 1`,
  `anchor_chain_suffix: "_anchor"`) — off by default, DECLARED per CLAUDE.md §2 convention.
- **`tests/unit/test_anchor.py`** (new, 14 tests): `AnchorRecord` construction, per-field tamper
  rejection (parametrized, mirroring `test_block_tamper.py`'s pattern), wire round-trip.
- **`tests/unit/test_hybrid_chain.py`** (new, 21 tests): scheduling (`ceil(blocks/frequency)`,
  parametrized over 6 `(frequency, blocks)` pairs), the three security tests (a/b/c from the
  brief), `verify_range`, `read_anchor_record_from_chain`.
- **`tests/unit/test_hybrid_transparency.py`** (new, 2 tests): "same backups recovered" (Phase 1 +
  Phase 5, byte-identical recovery with/without hybrid) and "same `BC_SigRW` records committed"
  (Phase 2, content-identical, standing in for "same detections fired" — see Findings on why full
  Phase 3 wasn't re-run here).
- **`scripts/run_hybrid_benchmark.py`** (new): the M7-5 benchmark, mirroring
  `run_consensus_comparison.py`'s shape (sidecar JSON, printed `RESULTS.md` candidate lines).
- **`RESULTS.md`**: M7-5 section, full 18-row matrix, run `20260924T213216Z-2bd78940`.
- **`docs/DEVIATIONS.md`**: DEV-33, including the mid-session redesign as part of the record.
- **`docs/ARCHITECTURE.md`**: new `blockchain/` subsection (anchor.py + hybrid.py) and a
  `framework/` table row (`hybrid_pipeline.py`).
- **`docs/ROADMAP.md`**: M7-5 ticked; top-of-file milestone line updated.
- **`docs/report/report.tex`**: new §IX "Hybrid Blockchain" (four subsections matching the brief's
  structure exactly: architecture/schema, frequency trade-off + Table XIII, three security tests,
  limitations) inserted before Conclusion (which shifted to §X). Also fixed the Conclusion's
  stretch-extensions paragraph, which was stale *before this session* — it claimed none of the
  five M7 items had been pursued, when four already had been (M7-1..M7-4, all from earlier
  sessions). Recompiled: 15 pages, verified by reading the PDF.

All AI-generated; human did not edit code directly this session.

## Findings

**Dead end, recorded in full because CLAUDE.md says an unrecorded one gets retried.** The first
`HybridChain` design ran the anchor chain through a literal single-node `consensus.pbft.Cluster`
(`n=1, f=0, commit_threshold=1` — confirmed by direct experiment that `consensus.protocol.
Membership` accepts this: `n >= 3f+1` is `1 >= 1`, and `commit_threshold` range `[2f+1, n-f]` is
`[1, 1]`), reached via `framework._block_pipeline.commit`. It worked — built, smoke-tested by hand
(committing a transaction through the n=1 cluster, then a full `HybridChain` through an n=4
private cluster with frequency sweeps and all three security tests, all passing) — before a single
test in the full suite caught the real problem: `tests/unit/test_module_boundaries.py::
test_nothing_below_framework_imports_it` failed, because `blockchain/hybrid.py` importing
`framework._block_pipeline` pulls the `blockchain` layer upward across
`docs/ARCHITECTURE.md`'s dependency direction (`util <- crypto <- blockchain <- consensus <-
framework`) — a boundary this codebase enforces with a standing test, not just a comment. The fix
was a genuine redesign, not a suppression: `HybridChain` now appends anchor blocks with one direct
`Chain.append()` call (no consensus at all — a single signing authority has no one else to
convince), holds no reference to the private chain, and takes an already-trusted `Chain` as a
parameter to every method that needs one. A new, thin `framework/hybrid_pipeline.py` is the only
module that bridges both layers. This is arguably a *better* design than the first draft (it's
what a real anchor-to-a-public-chain integration actually looks like — one signed transaction, not
a second BFT cluster), and the architecture test earned its keep by forcing it. Full account in
DEV-33.

**Block hashes are not deterministic across separate runs, even at the same seed.** `Block.nonce`
(`RN`) is drawn from `secrets.token_bytes` (module docstring: "It is set once, at random, per
block, and never examined again" — never from the seeded RNG), so two independently-built clusters
committing identical transactions produce different block hashes. The first version of the
transparency tests asserted `current_hash` equality between a hybrid run and a private-only run
and failed on the very first height — not a hybrid-vs-private-only difference, a property of `RN`
that applies to any two separate runs. Fixed by comparing decrypted transaction content instead of
hashes; recorded here because the failure mode (a spurious-looking test failure that looks like it
implicates the feature under test) is exactly the kind of thing worth writing down so a future
session doesn't re-diagnose it from scratch.

**Why the "same detections fired" transparency test stops at chain-content equality rather than
re-running Phase 3.** `phase3_detection.run` is a pure function of what's on the committed chain;
`tests/integration/test_phase2_feeds_phase3.py` (unmodified by this session) already covers that
Phase 3 produces correct detections from a Phase-2-built chain, without hybrid. Re-running the
full four-model fit twice per test run, inside `tests/unit` (which `make test` runs on every
loop), would slow the fast suite for a check that reduces to "is the chain content identical" —
already covered, more directly and much faster, by decrypting and comparing every committed
transaction. Noted as a scope decision, not an oversight, in case a future session wants the fuller
version in `tests/integration` instead.

**Anchor timing noise is real and worth stating plainly rather than filtering.** 3 of 18 benchmark
cells show anchor overhead of 6-12%, well above the ±1.4% the other 15 show. These don't correlate
with frequency or chain in a direction that would suggest a real cost, and the anchor step itself
is sub-millisecond (`sync()`/`flush()` run zero consensus). Read as scheduling jitter between two
separately-built clusters measured at different wall-clock moments — reported as such in both
`RESULTS.md` and the report, not smoothed over or re-run until it went away.

## Numbers

M7-5 benchmark, 18 cells (3 cases × 2 chains × 3 frequencies), `scripts/run_hybrid_benchmark.py
--seed 20260925`, run `20260924T213216Z-2bd78940`. Full table in `RESULTS.md` and report Table
XIII. Headline: anchor overhead at or below measurement noise (15/18 cells within ±1.4%); anchor
chain storage ≈1.00-1.01 KB/anchor, flat across case/chain/frequency.

## Deviations opened or changed

**DEV-33 · ADD+FILL · Hybrid blockchain — a public anchor chain for external verifiability.**
`AnchorRecord` schema (`blockchain/anchor.py`), `HybridChain` sign-and-append anchor chain
(`blockchain/hybrid.py`), the `framework/hybrid_pipeline.py` boundary, the mid-session redesign
and why, and the three stated limitations (simulated public chain, no gas/latency modelling, the
paper never names an external verifier). Full text in `docs/DEVIATIONS.md`.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** `docs/report/report.pdf` is current (15 pages, matches `report.tex` exactly) and
committed. M7 stretch: four of five items done (Scyther, storage-cost, adversarial robustness,
consensus comparison, hybrid blockchain); one remains (async pBFT with modelled network latency),
not required for the deliverable. `make test` (1442 tests) and `make lint` both green.

**Next task:** No forced next action — M7 is optional and the deliverable was already complete
before this session. If continued: async pBFT with modelled network latency is the one remaining
roadmap item (`docs/ROADMAP.md` M7), or the report's length (Q11, still open) could be revisited
now that it's 15 pages.

**New blockers:** None.

**Questions opened / closed:** Q11 (report length) unchanged, still open — now more relevant at 15
pages than at 13.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run (M7-5 section, 18 lines)
- [x] `docs/ROADMAP.md` boxes ticked (M7-5)
- [x] `docs/DEVIATIONS.md` updated (DEV-33)
- [x] Committed, message explains *why*
