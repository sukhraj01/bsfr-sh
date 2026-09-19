# Project State

> **Current truth only.** Not a history. History lives in `sessions/` and `RESULTS.md`.
> **Hard cap: 200 lines.** If this file exceeds it, the fix is to *delete resolved content*,
> not to add a summary. See the maintenance rule at the bottom.

**Last updated:** 2026-09-19 · **Milestone:** debt clearance (D2/D3/D4 closed) · **Sessions completed:** 16

---

## One-line status

The core deliverable (report, M0–M6) and both M7 stretch items done so far (M7-1 Scyther, M7-2
storage analysis) are unchanged. This session closed three items carried since M2b–M6a instead of
picking up a new M7 stretch item:

- **D2** — `scripts/bench_ecdsa_backends.py`'s logic moved into `src/bsfr_sh/bench/ecdsa_backends.py`
  (CLAUDE.md §3: scripts carry no logic); the script is now a thin CLI wrapper, so `make lint`'s
  `mypy --strict`/`ruff` over `src/` cover it. Faster than extending lint to all of `scripts/`,
  which would have meant type-annotating six other, never-checked scripts.
- **D4** — `ClientRequest` is now signed and authenticated: `Cluster`/`Replica` take a `submitters:
  Mapping[str, PublicKey]` distinct from the replica `Membership` (a submitting `CS_l` need not be
  a miner, DEV-22), and `check_request_identity` rejects a non-member the same way
  `check_vote_identity` rejects a non-member vote. Every `Cluster.submit`/`pipeline.run`/`.commit`
  call site now takes `submitter_id`/`key`; new tests confirm both a non-member and a forged
  signature are rejected (`tests/unit/test_protocol.py`, `test_pbft.py`).
- **D3** — `consensus.network.P2PCSNetwork` gained a `serialize=` hook (opaque `object -> object`,
  so the bus still imports nothing internal); `Cluster` wires it to
  `consensus.protocol.encode_message`/`decode_message` when `PBFTPolicy.serialize_messages` is set
  (`configs/chain.yaml` default off, `configs/bench.yaml` override on for bench runs). Measured
  case-3 both chains, n=25, serialize on vs. off: **BC_DTBU +67.6%, BC_SigRW +48.8%**
  (`RESULTS.md` `bench/d3-measured`, run `20260919T013422Z-1cf934ad`) — an order of magnitude
  larger than DEV-30's ~0.2-0.3% encode-only estimate, because the estimate priced one encode per
  block and the real bus pays encode+decode on every one of 28 hops per block. `docs/DEVIATIONS.md`
  DEV-30 amended; `docs/report/report.tex` was checked and never stated the old figure, so there
  was no report number to correct.
- Report cosmetics: refs [4]-[7] filled in with journal/vol/year; Table V's ("Honest-mode
  evaluation" — see note below) constant-negative precision changed from `--` to `undef.` with a
  footnote (0/0, not zero); the "every leakage source" overclaim fixed in both the Conclusion and
  the abstract (task named only §VII/Conclusion; the abstract had the identical overclaim as
  "exhaustive leakage ablation" and was fixed too, for consistency — flagging this since it goes
  slightly beyond what was asked).

**Worth knowing for next time:** the task instructions referred to "Table IV" for the
constant-negative-precision fix; the actual table (confirmed via `report.aux`'s `\newlabel`
after compiling) is **Table V** (`\label{tab:honest}`) — Table IV is the Q10 leakage-ablation
table, which has no precision column or constant-negative row at all. Fixed by content match, not
by the stated number. If a future prompt names a table number, verify against a compile before
trusting it.

`make test` (1348 passed, +27 this session) and `make lint` (ruff + mypy clean) green.
`docs/report/report.tex` recompiles; one pre-existing overfull-hbox warning
(`83.3953pt`, storage table) reproduces identically from the unmodified git-HEAD `report.tex`
compiled in this same directory (verified directly), so it is not a regression from this
session's edits — environment/font-cache dependent, not content-dependent (confirmed: identical
bytes compiled in a fresh `/tmp` directory never show it).

---

## What is built

| Layer | State | Notes |
|---|---|---|
| Full implementation (crypto/blockchain/consensus/honeypot/detection/mitigation/recovery/framework/bench) | done | consensus gained `ClientRequest` auth (D4) + bus `serialize=` hook (D3) this session |
| `docs/report/report.tex` + `.pdf` | done | this session's four cosmetic fixes (refs, Table V, Conclusion + abstract wording) |
| `verification/` | done (M7-1) | unchanged |
| `docs/STORAGE_ANALYSIS.md` | done (M7-2) | unchanged |

## Current numbers

New this session: `RESULTS.md` `bench/d3-measured` (case-3, both chains, serialize on vs. off,
run `20260919T013422Z-1cf934ad`) — see One-line status above for the two deltas. Everything else
unchanged since M6b/M7-2.

## Next task

**M7 has two remaining stretch items, none required for the deliverable** (`docs/ROADMAP.md` M7).
Pick one if continuing, or stop here — the core deliverable was already complete before M7:

1. Adversarial evaluation: does the honeypot detector survive feature-space evasion? (Q4, open)
2. Hybrid blockchain, which the paper lists as its own future work.

Async pBFT with realistic network latency (the third stretch item) no longer has a debt-closure
reason to pick it up now that D3 is closed on its own; it stands purely on its own merits if
picked up.

## Blockers

None. `data/raw/` is gitignored; a fresh clone needs `make data` (~56 minutes here) before any
BitcoinHeist run — unchanged, not touched this session.

## Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q11 | Is the report's length sufficient, or expand toward 10-12 pages? | report sign-off | reviewer judgement |
| Q4 | Do we need real feature-space evasion for M7? | M7 item 1 | decide if that item is picked up |

## Carried debt

| # | Item | Retire by |
|---|---|---|
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
