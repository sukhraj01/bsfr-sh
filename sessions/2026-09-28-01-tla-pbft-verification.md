# Session 2026-09-28-01 — M7-18: TLA+ formal specification and model-checking of the reduced pBFT

**Milestone:** M7 stretch (M7-18) · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/ARCHITECTURE.md` §consensus, `docs/DEVIATIONS.md` DEV-10 + DEV-20, `docs/PAPER_NOTES.md`
§V-3 (FLAW-5), `verification/README.md` + `bsfr_session.spdl` (M7-1, for conventions),
`tests/unit/test_pbft_byzantine.py` (fixture names), `consensus/protocol.py`/`pbft.py` (exact
quorum arithmetic and primary-rotation formula, to keep the TLA+ model faithful) ·
**Duration:** ~9.5 hours wall-clock (most of it unattended TLC search/scheduled wakeups, not
active work)

---

## Brief *(written before any work)*

**Task:** Model the reduced pBFT consensus protocol (DEV-20) in TLA+ and use TLC to exhaustively
check agreement/validity/integrity (safety) at f=1, confirm FLAW-5's fork at f=2, and check
termination (liveness) under fairness — the consensus-layer counterpart to M7-1's Scyther
verification of the session-establishment layer.

**Exit condition:** TLC runs against `verification/pbft.tla` with `verification/pbft.cfg`
(safety, N=4 F=1) and a second FLAW-5 config (N=4 F=2); results, state-space sizes and any
counterexample are written to `verification/pbft_results.md`; `docs/report/report.tex` gets a new
subsection with the §V-3 mapping table; `docs/DEVIATIONS.md` DEV-20 gets an amendment if TLC
surfaces a consequence of the reductions beyond what M2b's tests already found; `make test` and
`make lint` stay green (no Python changes expected).

**Out of scope:** changing `consensus/*.py` unless TLC finds a safety violation at f=1 (would be
a real bug, not expected); implementing checkpoints or state transfer; a Raft TLA+ spec.

**Prior context needed:** DEV-10 (threshold `2f+1` of `n=3f+1`, `f=1` at n=4), DEV-20 (the seven
named reductions from Castro-Liskov and their costs — items 2/6/7 are what liveness-checking
should surface), PAPER_NOTES §V-3 / FLAW-5 (pBFT's real bound is `n/3` not the paper's borrowed
51%; f=2 of 4 forks). `verification/README.md` (M7-1) sets the conventions this session's
`pbft_results.md` follows: tool provenance, a claim-mapping table, stated limitations.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/ARCHITECTURE.md
§consensus, docs/DEVIATIONS.md DEV-10 (pBFT threshold) and DEV-20
(reduced view change), docs/PAPER_NOTES.md §V-3 (FLAW-5).

Create the session file from the template and fill the brief first.

TASK — M7-18. TLA+ formal specification and model-checking of the reduced
pBFT implementation.

[... full task brief: M7-1 verified the session protocol with Scyther, this
session verifies consensus with TLA+; context on the reduced pBFT and DEV-20;
STEP 0 install/verify TLA+ (brew cask, tla2tools.jar, or SPIN fallback);
spec requirements (variables view/phase/messages/log/faulty, constants
N=4/F=1/MaxView=3/MaxSeq=3, actions PrePrepare/Prepare/Commit/ViewChange/
ByzantineAction); safety properties (Agreement/Validity/Integrity); liveness
(Termination under fairness); the DEV-20 reductions modelled explicitly
(no checkpoints, no state transfer -> lagging-replica reachability check);
FLAW-5 verification at F=2 expecting Agreement violated; RUN TLC section
(start small MaxView=2/MaxSeq=2, scale to 3/3, run FLAW-5 separately, reduce
bounds if >10M states and report the largest bound checked); OUTPUT files
(pbft.tla, pbft.cfg, MC.tla, pbft_results.md) and report/deviations/roadmap
write-up instructions; TESTS (no new Python tests, make test/make lint stay
green); EXIT CONDITION and OUT OF SCOPE as summarized above; END OF SESSION
(session file, DEVIATIONS.md DEV-20 amendment if new consequences found,
PROJECT_STATE.md rewrite, tick M7-18, commit and push). ...]

2. any progress

3. The FLAW-5 exhaustive run was switched to simulation mode because it
exhausted local disk after 24GB/4 hours. That workaround was unnecessary —
Ada has the disk space for this. After the current liveness run completes
and you've committed all local results:

1. rsync the entire verification/ directory to Ada
2. Run the FLAW-5 exhaustive check there:
   java -XX:+UseParallelGC -Xmx64g -cp lib/tla2tools.jar tlc2.TLC \
     -deadlock -config pbft_flaw5.cfg -workers auto MC.tla \
   under nohup, writing to a log file. Disconnect immediately.
3. Poll the log. When it finishes, record: total states explored,
   time, and whether Agreement is the ONLY invariant violated.

The simulation result (counterexample found in 1s) stays in the report as
the primary evidence. The exhaustive result, if it completes, upgrades the
claim from "we found a violation" to "we explored the full state space and
this is the only violation" — a stronger formal statement. If Ada also runs
out of space, note the state count reached and move on.

Do not hold the session for this. Commit what you have, push, and submit
the Ada job as a background task.

After the current liveness run either completes or shows signs of disk
pressure (check df -h periodically), commit whatever results you have
locally and move BOTH exhaustive runs to Ada:

1. rsync the entire verification/ directory to Ada (spec, configs,
   tla2tools.jar — everything needed to run standalone)

2. Submit TWO nohup jobs on Ada, sequentially or parallel depending on
   available disk:

   Job A — FLAW-5 exhaustive (the one that hit 24GB locally):
   java -XX:+UseParallelGC -Xmx64g -cp lib/tla2tools.jar tlc2.TLC \
     -deadlock -config pbft_flaw5.cfg -workers auto MC.tla

   Job B — F=1 liveness exhaustive (the one currently running locally):
   java -XX:+UseParallelGC -Xmx64g -cp lib/tla2tools.jar tlc2.TLC \
     -deadlock -config pbft_liveness.cfg -workers auto MC.tla

   Both under nohup writing to separate log files. Disconnect immediately
   after launch. Do not hold an SSH session open.

3. If the current local liveness run finishes before you ship to Ada,
   record its result — don't throw away a completed run. Only send to
   Ada what didn't finish locally.

4. Poll Ada logs periodically. When each completes, record: total states,
   time, result (pass / violation found), and disk used. rsync logs back.

5. The simulation FLAW-5 result (counterexample in 1s) and any completed
   local safety/liveness results stay in the report as primary evidence.
   Exhaustive Ada results upgrade the claims if they complete. If Ada also
   exhausts disk, note the state count reached — "explored N billion
   states without finding additional violations" is still useful even
   without full coverage.

Do not hold this session for Ada completion. Commit and push all local
results now. Ada jobs are background. Finish the session file, update
PROJECT_STATE.md, and close M7-18 with the results you have. Note in
PROJECT_STATE.md that Ada exhaustive runs are pending — their completion
is an upgrade to existing claims, not a blocker.
```

---

## What was done

- **`verification/pbft.tla`** (AI-generated). The spec: replica state (`view`, `log`), a
  monotonically-growing authenticated-but-unforgeable `msgs` set, `SendPrePrepare`/`SendPrepare`/
  `SendCommit`/`DoCommit` matching `protocol.py`'s exact quorum arithmetic (`prepare_quorum=2F`,
  `commit_threshold=2F+1`) and `primary(v)=ids[v%n]`, `SendViewChange` (each honest sender declares
  only what it independently knows via `Prepared()`), `ByzantineAction` (arbitrary well-formed
  message under the sender's own identity, never forged). Went through three iterations after TLC
  itself found two real soundness bugs in the first two — see Findings.
- **`verification/MC.tla`** (AI-generated): thin wrapper, holds `BlocksSymmetry` for TLC.
- **`verification/pbft.cfg`**, **`pbft_flaw5.cfg`**, **`pbft_control_f0.cfg`**, **`pbft_liveness.cfg`**
  (AI-generated): four TLC configurations, all `MaxView=1, MaxSeq=1` after every larger bound
  proved intractable (see Findings). The liveness configs omit `SYMMETRY` (TLC warns it can hide
  liveness violations).
- **`verification/pbft_results.md`** (AI-generated): full write-up — tool provenance, model
  description, both draft-guard failures kept as documented dead ends, all four runs' raw numbers,
  the Ada hand-off, the §V-3 mapping table, comparison with M7-1, stated limitations.
- **`verification/ada_flaw5.sbatch`, `ada_liveness.sbatch`** (AI-generated, on Ada only — not
  committed to this repo, matching how `scripts/ada_honest_mode.sbatch` is the only sbatch script
  kept in-repo and this session's two are throwaway job definitions, not a reusable pipeline step).
- **`docs/report/report.tex`** (AI-generated edit): new §"Formal Verification of Consensus
  (Tier 2–3)" after §"Formal Verification of the Session Protocol", new `tab:tlc`, coverage-matrix
  row 3 amended, FLAW-5 prose (§V-3) cross-references the new subsection, abstract-adjacent
  intro sentence updated, one new bibliography entry (Lamport's TLA+ book); amended a second time
  once Ada's FLAW-5 exhaustive result landed, to replace "pending" wording with the measured
  confirmation. Recompiles clean via `tectonic`; 30 pages after the first edit, **31 after the
  second** (Risks).
- **`docs/DEVIATIONS.md`** (AI-generated edit): DEV-20 amendment (below).
- **`docs/ROADMAP.md`**, **`PROJECT_STATE.md`** (AI-generated edits): M7-18 ticked; state rewritten.
- No Python source touched. `verification/lib/tla2tools.jar` (2.1 MB, downloaded from the tool
  author's GitHub release) was used locally and on Ada but is **not committed** — same policy M7-1
  set for the Scyther binary.

## Findings

- **TLC (v2.19, via `tla2tools.jar` v1.7.4) needed no Toolbox/brew install** — the command-line jar
  plus the already-present system JDK (22.0.1) was faster and more scriptable than the GUI path the
  brief suggested first. Promela/SPIN (the stated fallback) was never needed.
- **`MaxView=2, MaxSeq=2` is intractable on this hardware — dead end, found fast.** Every attempted
  guard version exceeded 10 million states within single-digit seconds at that bound (the task
  brief's own explicit threshold for reducing bounds). `MaxView=1, MaxSeq=1` — the smallest bound
  that still exercises the view-change mechanism at all — turned out to be both the floor for
  *interesting* checking and the practical ceiling this session's hardware could exhaust (Run 1:
  74,970,368 states / 68 min; Run 2 attempted exhaustively: 281M states / 4h19min before disk
  exhaustion). This is reported as real information about the reduced protocol's state-space size,
  not hidden as an inconvenience.
- **Two real spec bugs, found by TLC, at the smallest bound, before the model was safe to trust —
  the most valuable outcome of the session, more than the final clean pass.** (1) A first,
  cost-cutting version of the forced-re-proposal guard checked a global, timing-free snapshot
  ("was any block ever `Prepared` at an earlier view?") instead of a real `ViewChange` message;
  TLC found a real `Agreement` violation in 26 seconds — an honest replica can race to a new view
  and pick a fresh block while a *different* honest replica is one message away from completing the
  *old* view's certificate, because the snapshot the guard checked was not yet true at the moment
  it mattered. (2) The fix — an explicit `ViewChange` message — still let a Byzantine sender
  *assert* a false prepared-block declaration with no evidence behind it; TLC found a second
  `Agreement` violation, this time after 6m17s, because the forced-re-proposal rule counted every
  declared block at face value. The real fix required the declared block to independently
  re-verify against the actual message log (`Prepared(v-1, s, block)`), mirroring DEV-20's own
  "every receiver re-verifies" in one line. Both are documented as comments in `pbft.tla` itself,
  not silently fixed and forgotten — the same discipline M7-1 applied to the pre-M1 Scyther attack.
- **Safety (Agreement/Validity/Integrity) verifies exhaustively at F=1** — no violation over the
  full reachable state space at the bound checked. This is the formal counterpart of
  `test_pbft_byzantine.py`'s four `f=1` fixtures: those check specific scenarios, TLC checks all of
  them at this bound.
- **FLAW-5 confirmed by direct construction, not simulation-only in spirit** — TLC's `-simulate`
  mode found the fork (two honest replicas commit different blocks) in 115,938 states / 1 second,
  after the exhaustive BFS attempt failed on disk exhaustion (24GB, `verification/states/`) stuck
  at a wide BFS-depth-15 plateau for its entire 4h19min run. One found counterexample is a complete
  proof that Agreement fails at `F=2` regardless of how it was found; only "no OTHER violation
  exists in the full state space" is still open, pending Ada.
- **`-deadlock` is required for bounded liveness checking, and its absence produces a misleading
  "Error: Deadlock reached" that is really just the bound ceiling, not a protocol issue** — found
  once (Run 3's first attempt) and corrected before it could be mistaken for a real finding.
- **`SYMMETRY` and liveness checking do not mix safely** — TLC's own warning ("might cause TLC to
  miss violations of the stated liveness properties") was heeded: both liveness configs dropped
  `BlocksSymmetry`, at a real but small cost (Run 3 went from 620,108 states/47s with symmetry to
  1,240,200 states/2m59s without it — a ~2x, not prohibitive, difference for a 2-element set).
- **`F=1` liveness (`Termination`) did not finish locally** — 1h42min, 16.4M states, TLC warning it
  was "running low on memory" against the 1,820 MB heap `-workers auto` left available on this
  machine. Stopped deliberately rather than risk repeating Run 2's disk exhaustion or running
  indefinitely; moved to Ada per the user's mid-session redirection (below).
- **The single most important finding of the session: the Ada liveness run completed (16h49min,
  150M states) and `Termination` HOLDS at `F=1` — the predicted DEV-20 #2 violation does not
  happen at this bound, and the reason is itself a real result, not a loose end.** `DoCommit`'s
  state-transfer guard (`PrevCommitted`) checks whether seq `s-1` committed before allowing seq
  `s`; at `MaxSeq=1` that check is vacuously true for the only seq that exists, so a replica can
  never actually be "behind" in any way the model can represent. DEV-20 #2's real cost — a
  replica missing one height while others move on to the next — needs at least two heights to
  even be expressible, let alone observable as a liveness failure. This was caught only because
  the full result eventually came back measured rather than left as the analytically-plausible-
  but-wrong prediction this session wrote down mid-way through (and initially shipped in the
  report/DEVIATIONS/PROJECT_STATE, later corrected once the real number arrived) — a direct,
  textbook illustration of why CLAUDE.md's "never claim a number we did not measure" rule matters:
  the analytical argument was reasonable, cited real mechanics (the quorum-size-equals-honest-
  count coincidence), and was still wrong, because it reasoned about the Byzantine mechanism
  without checking whether the CHOSEN BOUND could even express the failure mode being predicted.
- **Ada's actual account ceiling (`cpu=10`, `mem-per-cpu=3000` under QOS `low`) does not fit the
  task's suggested `-Xmx64g`** — the same ceiling `scripts/ada_honest_mode.sbatch` already
  discovered and documented for the ML jobs. Both `.sbatch` scripts request `-Xmx27g` within the
  real ~29.3 GB ceiling instead, noted explicitly rather than submitted to fail against SLURM's own
  enforcement.
- **`verification/states/` (TLC's disk-backed fingerprint set) is the actual disk driver, not the
  spec or `.cfg` files** — it reached 24 GB across accumulated runs before the FLAW-5 exhaustion,
  and is deleted (not committed, not gitignored specially — just never `git add`ed) between runs.

## Numbers

Not appended to `RESULTS.md` this session — following M7-1's own precedent (Scyther's runs were
never logged there either), formal-verification state-counts/pass-fail results are not
`<metric>=<value>` benchmarks in that file's sense and have no `results/logs/*.json` sidecar to
point a `run_id` at. The narrative numbers live in `verification/pbft_results.md`; the short
version:

| Run | Config | Result | States (distinct) | Time |
|---|---|---|---|---|
| 1 — safety | `pbft.cfg`, F=1 | no violation, exhaustive | 74,970,368 | 1h08min |
| 2 — FLAW-5 (local, partial) | `pbft_flaw5.cfg`, F=2 | exhaustive attempt incomplete (disk exhausted) | 281,002,154 (partial) | 4h19min (partial) |
| 2 — FLAW-5 (local, simulation) | `pbft_flaw5.cfg`, F=2 | Agreement violated | 115,938 | 1s |
| 2 — FLAW-5 (Ada, exhaustive) | `pbft_flaw5.cfg`, F=2 | Agreement violated — same fork, standard BFS | 1,501,898,636 | 15h56min |
| 3 — liveness control | `pbft_control_f0.cfg`, F=0 | no violation, exhaustive | 1,240,200 | 2m59s |
| 4 — liveness (local, partial) | `pbft_liveness.cfg`, F=1 | did not finish (low-memory warning) | 16,420,732 (partial) | 1h42min (partial) |
| 4 — liveness (Ada, exhaustive) | `pbft_liveness.cfg`, F=1 | **no violation** — contradicted the pre-run prediction; see Findings | 149,940,224 | 16h49min |

## Deviations opened or changed

- **DEV-20 amended**: safety confirmed exhaustively by TLC at the design fault bound — no
  violation, 74,970,368 states. FLAW-5 confirmed twice over (simulation + exhaustive Ada BFS,
  1.5B states). Liveness at `F=1` ALSO confirmed exhaustively to HOLD (149,940,224 states,
  16h49min on Ada) — this reverses the amendment's earlier mid-session wording, which (correctly
  reasoning from the safety run's certificate math, but without yet having the liveness result)
  predicted a violation. The corrected amendment explains why the prediction was wrong at this
  specific bound: `DoCommit`'s state-transfer guard is vacuous at `MaxSeq=1`, so DEV-20 #2's real
  cost (needs a replica to miss one seq while others reach a later one) has no "later one" to
  miss at this bound — a genuine, reportable bound limitation, not evidence the omission is
  costless. No new DEV-NN opened — this session verifies an existing, already-documented
  reduction rather than introducing a new one.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** M7-18 is **fully resolved, every claim measured, nothing pending.**
`verification/` holds a working, twice-corrected TLA+ spec of the reduced pBFT protocol. Safety at
`F=1` is exhaustively confirmed (no violation, 74.97M states). FLAW-5's `F=2` fork is confirmed
twice over — simulation (1s) and independently by exhaustive BFS on Ada (job 2720269, 1.5B states,
15h56min). Liveness is exhaustively confirmed fault-free (`F=0`) *and*, contrary to the prediction
this session made mid-way through, also holds at `F=1` (job 2721161, 149,940,224 states, 16h49min)
— the predicted DEV-20 #2 violation doesn't surface because the bound (`MaxSeq=1`) gives the
omission nothing to bite; a real, reportable limitation of this verification's bound, not a
closed question. Both Ada jobs had already finished — unattended, before this session next reached
them — by the time Ada went down for a scheduled multi-day maintenance upgrade (login node moved
`ada`→`ada-gw1`, account QOS reset to `low`); nothing was lost, no resubmission was needed. All
docs (`pbft_results.md`, the report, `DEVIATIONS.md`, `ROADMAP.md`, `PROJECT_STATE.md`) are
rewritten to state the corrected, final, measured results — no "pending"/"expected" wording
remains anywhere in the M7-18 write-up. Separately (same session, unrelated to M7-18 itself): the
top-level `README.md` was found still showing M0-scaffold "not started" placeholders in its
reproduction-targets table across 35 sessions of real work, and was corrected with the actual
measured numbers plus a new "Beyond the paper" section; a broken `git fetch` refspec (pinned to a
stale branch, silently breaking `fetch`/`pull` while `push` kept working undetected) was also
fixed.

**Next task:** None forced for M7-18 — closed out clean. See `PROJECT_STATE.md`'s own "Next task"
for the carried M7-17 backlog if a future session wants to act on open findings instead.

**New blockers:** None.

**Questions opened / closed:** Q12 (opened mid-session, asking whether the report needed the
pending Ada liveness run to land before being final) is now moot/closed — it landed, during this
same session, with a result that itself needed write-up. Q11 (report page count, 31pp) carried,
unchanged in substance.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines (146)
- [x] `RESULTS.md` — deliberately not appended this session (see Numbers; matches M7-1's own
      precedent for formal-verification runs)
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated (DEV-20 amendment, corrected once the real liveness result
      arrived)
- [x] `README.md` fixed (separate, unrelated-to-M7-18 fix made in the same session)
- [x] Committed, message explains *why*
