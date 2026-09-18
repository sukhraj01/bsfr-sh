# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-19 · **Milestone:** M7-2 done (stretch, optional) · **Sessions completed:** 15

---

## One-line status

The core deliverable (report, M0–M6) has been done since before M7 and is unchanged. This
session closed a second M7 stretch item: **M7-2, the storage-cost analysis GAP-2 flagged at M0
and never answered.** `docs/STORAGE_ANALYSIS.md` computes per-backup on-chain cost from
already-measured values only (DEV-15's 4096B payload + 1.14× full-block overhead factor, DEV-24's
215B+161B per-chunk framing/encryption) — no new code, no new benchmark runs. It gives three
deployment scenarios (small/medium/large, daily 1MiB backups, ×4 replication: 81 GiB/yr cluster
at 50 patients up to 79 TiB/yr at 50,000), the backup-frequency lever for the medium scenario
(daily costs ~7× weekly, ~30× monthly), an on-chain-hash/off-chain-data alternative
(~504B/backup vs. ~1.14MiB, a ratio that widens with backup size — stated as a trade-off against
the paper's design, not a replacement for it), and a compute-cost cross-check (large-network
scenario's block rate: ~4,045 CPU-s/day, feasible on the measured dev-laptop throughput). The
report (`docs/report/report.tex`) gained `\subsection{GAP-2 -- storage-cost analysis}` in
§Critique, before "What the paper gets right" — one table, one hash-only paragraph, one
compute-cost sentence — and recompiles clean via `tectonic`, no new overfull/underfull warnings.
`make test` (1321 passed) and `make lint` (ruff + mypy clean) reconfirmed green — no source
touched.

**Worth knowing for next time:** this codebase has no separately measured block-header-only or
Merkle-only byte count, and none should be invented — `bench.harness.estimate_overhead_factor`'s
measured 1.14× full-block ratio is the right substitute (it already includes header + Merkle root
+ struct/list encoding, amortised over 100 tx), cross-checked for consistency against DEV-24's
transaction-level 1.092× in `docs/STORAGE_ANALYSIS.md` §1. Reconstructing header bytes field-by-
field would require guessing the DER ECDSA signature's exact length, which is logged nowhere in
this project — resist the temptation next time this comes up.

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | M0–M6, unchanged this session |
| `docs/report/report.tex` + `.pdf` | done | M6 + M7-1 Scyther subsection + this session's GAP-2 subsection |
| `verification/` | done (M7-1) | Scyther models, raw output, README |
| `docs/STORAGE_ANALYSIS.md` | done (M7-2) | three scenarios, frequency lever, hash-only alternative, compute cross-check |

## Current numbers

No new benchmark runs this session (arithmetic over M6a/M1/M3a's already-recorded values —
nothing appended to `RESULTS.md`, correctly). See `RESULTS.md` for every benchmark figure;
unchanged since M6b. See `docs/STORAGE_ANALYSIS.md` for this session's derived (not measured)
storage-cost figures.

## Next task

**M7 has three remaining stretch items, none required for the deliverable** (`docs/ROADMAP.md`
M7). Pick one if continuing, or stop here — the core deliverable was already complete before M7:

1. Adversarial evaluation: does the honeypot detector survive feature-space evasion? (Q4, open)
2. Async pBFT with realistic network latency (relates to DEV-20 item 2, DEV-21).
3. Hybrid blockchain, which the paper lists as its own future work.

None of these follows naturally from M7-2; each is an independent unit of work.

## Blockers

None. `data/raw/` is gitignored; a fresh clone needs `make data` (~56 minutes here) before any
BitcoinHeist run — unchanged, not touched this session.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is 9-page report (now +1 short subsection) sufficient, or expand toward 10-12 pages? | report sign-off | reviewer judgement |
| Q4 | Do we need real feature-space evasion for M7? | M7 item 1 | decide if that item is picked up |
| Q8 | Does anything before M7 need pBFT state transfer (DEV-20 item 2)? | M7 item 3 | only if that item is picked up |

## Carried debt

| # | Item | Retire by |
|---|---|---|
| D2 | `make lint` covers `src` and `tests` but not `scripts/`, and `mypy` only covers `src`. | low priority; not cited as a report claim |
| D3 | The bus never serialises; magnitude quantified (DEV-30) but the omission itself is unfixed. | M7 item 3, if async pBFT lands |
| D4 | `ClientRequest` is unauthenticated (DEV-20 item 5). | when a claim needs it |
| D5 | `LogisticRegression(penalty=…)` is deprecated in sklearn 1.8, removed in 1.10. | before sklearn 1.10 |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| The non-reproduction (detection headline) is read as our bug rather than a finding | the report's central claim collapses | baselines published beside every number; Q10 tested and ruled out address/split leakage; report states the gap as measured-but-unexplained |
| `data/raw/` is gitignored and slow to fetch | a fresh machine cannot rerun M4a quickly | `make data` verifies counts; README + `provenance.json` state the wait and the sha256 |
| Scyther binary not committed (third-party, single-platform) | a fresh clone can't re-run the verification without a manual download | exact release URL + sha256 in `verification/README.md`; the raw output is committed, so the claims don't depend on re-running it |

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
