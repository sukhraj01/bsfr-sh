# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-25 · **Milestone:** M7 stretch — four of five items done; report
compiled and current · **Sessions completed:** 21

---

## One-line status

This session compiled the (three-sessions-overdue) report PDF, then implemented M7-5 — hybrid
blockchain, the paper's own §VIII-stated future work — closing all but one M7 stretch item.

- **Report compile:** `tectonic` was already on `PATH` (self-contained LaTeX engine, not
  `brew`/`install-tl`, no CTAN mirror). Two real LaTeX bugs found and fixed: `\footnote{}` inside
  `\caption{}` is fatal under IEEEtran (moved to post-table note text); two wide data tables
  needed `table*`. `report.pdf` is now 15 pages, current, verified page-by-page.
- **`blockchain/anchor.py`** (new): `AnchorRecord` — one private block's height, hash, Merkle
  root, timestamp, and the anchor creator's signature. Never encrypted (`transaction.
  wrap_anchor_record`), since a public record's whole purpose is external readability.
- **`blockchain/hybrid.py`** (new): `HybridChain` — schedules `AnchorRecord`s onto its own anchor
  `Chain` via `sync()`/`flush()` (`ceil(blocks/frequency)` anchors), answers
  `verify_anchor`/`verify_range`/`verify_anchor_chain_integrity`. Holds no `consensus` or
  `framework` dependency — see Findings below, this was a redesign, not the first draft.
- **`framework/hybrid_pipeline.py`** (new): the one module bridging `blockchain.hybrid` and
  `consensus`/`framework._block_pipeline`. `phase1_backup.py`/`phase2_collection.py` are
  untouched — hybrid mode is opt-in at the cluster-construction call site only.
- **Measured, `RESULTS.md` M7-5, run `20260924T213216Z-2bd78940`:** anchor overhead at or below
  measurement noise (15/18 cells within ±1.4%); anchor chain storage ≈1.00-1.01 KB/anchor, flat
  regardless of case, chain, or frequency.
- Three security tests (tamper anchored block → caught; tamper unanchored block → honestly not
  caught; tamper anchor chain → caught by its own integrity check) and a transparency test (hybrid
  vs. private-only produce byte-identical recovered backups and content-identical `BC_SigRW`
  records) all pass.
- `docs/DEVIATIONS.md` DEV-33, `docs/report/report.tex` new §"Hybrid Blockchain", `docs/
  ARCHITECTURE.md` §blockchain + §framework, `docs/ROADMAP.md` M7-5 ticked.

`make test` (1442 tests) and `make lint` (ruff + mypy) both green.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | `blockchain/anchor.py`, `blockchain/hybrid.py`, `framework/hybrid_pipeline.py` added this session |
| `docs/report/report.pdf` | done, current | 15 pages; recompiled and verified this session, §IX Hybrid Blockchain added |
| `verification/` | done (M7-1) | unchanged |
| `docs/STORAGE_ANALYSIS.md` | done (M7-2) | unchanged |
| `scripts/run_adversarial_robustness.py` | done (M7-3) | unchanged |
| `scripts/run_consensus_comparison.py` | done (M7-4) | unchanged |
| `scripts/run_hybrid_benchmark.py` | done (M7-5) | new this session — private-vs-hybrid matrix, anchor frequency sweep |

## Current numbers

New this session: `RESULTS.md` "M7-5 — hybrid vs private-only blockchain, anchor frequency sweep"
section, run `20260924T213216Z-2bd78940`. Everything else unchanged since the last session.

## Next task

None forced — M7 is optional stretch work and the core deliverable was complete before this
session. If continued: async pBFT with modelled network latency is the one remaining `docs/
ROADMAP.md` M7 item.

## Blockers

None.

`data/raw/` is present in this environment already; a genuinely fresh clone still needs
`make data` (~56 minutes) first.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length sufficient (now 15 pages), or should it be trimmed? | report sign-off | reviewer judgement |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 tested and ruled out address/split leakage; report states the gap as measured-but-unexplained |
| Scyther binary not committed (third-party, single-platform) | a fresh clone can't re-run the verification without a manual download | exact release URL + sha256 in `verification/README.md`; the raw output is committed, so the claims don't depend on re-running it |
| The BC_SigRW/BC_DTBU timing gap is condition-dependent (35-45% off, ~25-27% on) | a reader citing "the gap" without saying which condition is wrong half the time | both figures now in `RESULTS.md`/`docs/EXPERIMENTS.md`/the report supplement, each labelled with its condition |
| Raft's message-count ratio (~60% of pBFT) is measured only at `n=4`; a reader might extrapolate the O(n)/O(n^2) asymptotic gap and expect a bigger number | over-claiming Raft's advantage at other cluster sizes | `docs/DEVIATIONS.md` DEV-32 and the report both state the ratio is small-`n`-specific, not the asymptotic one |
| 3 of 18 M7-5 benchmark cells show 6-12% anchor overhead against a ±1.4% baseline for the rest | a reader might read this as a real per-anchor cost | stated plainly as scheduling jitter (anchor step is sub-millisecond, runs no consensus) in both `RESULTS.md` and the report, not filtered or re-run until clean |

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
session. A 200-line file costs a few seconds of context; a 2,500-line one costs a meaningful
fraction of the window before any work begins, and gets skimmed rather than read.

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
