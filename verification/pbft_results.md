# Formal verification of the reduced pBFT consensus protocol (M7-18)

**What this is.** Exhaustive (and, where exhaustive proved computationally infeasible on this
project's hardware, simulation-based) model checking of the reduced pBFT protocol implemented in
`consensus/pbft.py`, `consensus/protocol.py`, `consensus/view_change.py` (DEV-10's `2f+1` of
`n=3f+1`, DEV-20's named Castro-Liskov reductions). Companion to M7-1's Scyther verification of
`crypto.session` (DEV-14): that verified the point-to-point session-establishment layer
symbolically, under a Dolev-Yao adversary with a bounded/unbounded search; this verifies the
multi-party consensus layer by exhaustive state-space enumeration (TLC), the standard complement
for a protocol whose interesting behaviour is in how *several* parties' local states interleave,
not in what one adversary can forge in a two-party exchange.

**Result, in one line:** at the design fault bound (F=1, one Byzantine replica of four), Agreement,
Validity and Integrity all verify clean over the full reachable state space at the largest bound
this project's hardware could exhaust (74,970,368 states); at two Byzantine replicas — one more
than the design tolerates — Agreement is violated, confirming FLAW-5 by direct construction of the
fork rather than by argument; and liveness (Termination) holds exhaustively with zero Byzantine
replicas but did not finish checking under one Byzantine replica within this session's practical
compute budget, and was moved to Ada rather than left unresolved (§ Ada runs).

---

## Tool

TLA+ Toolbox's model checker, TLC, via the command-line `tla2tools.jar` (v1.7.4,
`https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar`, sha256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`), run under the system JDK
(Java 22.0.1, Oracle). Verified runnable before use (`java -jar tla2tools.jar -h` reports
"TLC - ... Version 2.19 of 08 August 2024"). Not committed to the repo, the same policy M7-1 set
for Scyther's binary: it is a third-party, platform-independent but still external `.jar`; anyone
reproducing this downloads the same release from the URL above. `verification/lib/` is where this
session kept it locally; it is `.gitignore`d in spirit by simply never being added (matching how
`verification/Scyther/` was handled in M7-1 — never committed, not specially excluded either).

Java is required, not optional here: Promela/SPIN (this task's stated fallback) was not needed —
`brew install --cask tla-plus-toolbox` was not attempted since the command-line jar plus a
system JDK (already present, `/Library/Java/JavaVirtualMachines/jdk-22.jdk`) is the more portable,
scriptable path for a project that runs everything else from the CLI.

## Model

`verification/pbft.tla` — the spec, `verification/MC.tla` — the model-checking wrapper (mostly
empty; it exists to hold `BlocksSymmetry` and give TLC a module name distinct from the spec
itself). Four `.cfg` files, one per run below, all pointing at the same two `.tla` files and
differing only in `Faulty`, `MaxView`/`MaxSeq`, and which properties are declared.

**Variables.** `view` (per replica, current view number), `msgs` (the set of every message ever
sent — Dolev-Yao delivery: any process may "read" any sent message in any order, but a message's
`sender` field can never be forged), `log` (per replica, per seq, the committed block or
`NoBlock`).

**Constants.** `r1..r4` (the four replica identities — DEV-10 fixes `n=4` for this paper's
configuration, so this was not made generic over an arbitrary `N`), `F` (the *design* fault bound,
fixed at 1 throughout — `QuorumSize = 2F+1 = 3`, exactly `protocol.py`'s `commit_threshold`),
`Faulty` (the *actual* Byzantine replicas this run models — varied between runs; **the crux of the
FLAW-5 check is that `QuorumSize` is never recomputed from `Cardinality(Faulty)`**, exactly as the
real protocol has no way to know how many replicas are really faulty, only what threshold it was
configured with), `MaxView`/`MaxSeq` (TLC bounds, unbounded in the real protocol), `Blocks = {b1,
b2}` (two distinct proposable values — enough to detect any equivocation/fork; a third value adds
state without adding checking power), `NoBlock` (sentinel).

**Actions.** `SendPrePrepare`/`SendPrepare`/`SendCommit`/`DoCommit` for the normal-case protocol
(mirroring `protocol.py`'s exact quorum arithmetic: `prepare_quorum = 2F` non-primary prepares,
`commit_threshold = 2F+1`); `SendViewChange` for the timeout-triggered view change (DEV-20), each
message honestly declaring only what its own sender already knows is prepared, mirroring
`view_change.py`'s "broadcasts a signed ViewChange carrying every prepared certificate it holds";
`ByzantineAction` for a faulty replica sending any message that is well-formed under its own
identity (equivocation, false prepares/commits, false ViewChange declarations) but never under
another replica's forged identity.

**The DEV-20 reductions, modelled explicitly:**
- *No checkpoints* (#1): not represented as a separate mechanism — bounded instead via `MaxSeq`,
  exactly as the task brief anticipated ("TLC handles this via the MaxSeq bound").
- *No state transfer* (#2): `DoCommit`'s `PrevCommitted` guard — a replica cannot commit seq `s`
  without already having committed `s-1`. This is the omission the liveness runs below are built
  to exercise.
- *No pipelining* (#3): only one seq's messages are meaningful at a time in any single run (the
  spec does not special-case this; `MaxSeq=1` for every run below makes it moot in practice, and a
  larger `MaxSeq` would still only allow independent per-seq certificates, never overlapping
  in-flight heights, since nothing in the guards references more than one seq at a time except
  `PrevCommitted`).
- *No null requests* (#4): vacuous with one seq in flight, as DEV-20 itself says.
- *No retransmission* (#6): not modelled as message loss at all — `msgs` only grows. Liveness is
  checked under Dolev-Yao delivery (arbitrary order/timing), not under loss.

## Modelling choices that turned out to be load-bearing (two dead ends, kept as documentation)

Two successive draft versions of the view-change safety guard were each shown **unsound** by TLC
itself, at the smallest possible bound, before the third version verified clean. Both are kept as
comments in `pbft.tla` (next to `ViewChangeSenders` and `ForcedBlocks` respectively) because the
mistake is instructive, in the same spirit M7-1's README kept the pre-M1 attack trace rather than
only reporting the final clean result.

**Draft 1 — a timing-free global snapshot.** The first version of the forced-re-proposal rule
checked a plain, global predicate: "was any block ever `Prepared` at an earlier view?" with no
`ViewChange` message at all. At `MaxView=1, MaxSeq=1, F=1` (one Byzantine replica), TLC found a
real `Agreement` violation in **26 seconds** (9,369,031 states generated, 1,096,603 distinct, depth
17): an honest replica can advance to a new view and freely propose a fresh block while a
*different* honest replica is one `Prepare` message away from completing the *old* view's
certificate for something else — the global snapshot the guard consulted was simply not yet true
at the moment the new primary acted, though it inevitably becomes true moments later in the same
trace. This was a **spec** bug, not a protocol one: the real safety argument is a
quorum-*intersection* argument (the `2f+1` commit-senders for the old value and the `2f+1`
view-change-senders for the new view share at least `2f+1+2f+1-n` members — 2, at `F=1/n=4` — so
at least one *honest* replica is in both), and it depends on each `ViewChange` message honestly
reporting what its own sender already knew *at the time it sent it*, not on a fact becoming true
globally at some possibly-later moment.

**Fix 1 / Draft 2 — an explicit but unverified ViewChange message.** Modelled `ViewChange` as a
real message, each honest sender declaring its own `Prepared` block (or `NoBlock`) truthfully, and
gated `SendPrePrepare` on a real `2f+1` `ViewChangeQuorumReached`. At the same bound, TLC found a
**second** `Agreement` violation, this time after **6 min 17 s** (175,325,048 states generated,
17,437,293 distinct, depth 18): a Byzantine replica's `ViewChange` message can simply *assert* a
false prepared-block claim with no evidence behind it, and the forced-re-proposal rule counted the
declared block of every `ViewChange` message at face value. Real Castro-Liskov does not trust the
bare claim — "every receiver re-verifies each carried view-change and certificate" (DEV-20) — a
Byzantine replica cannot forge the `2f` genuine `Prepare` signatures from other replicas it does
not control, so a false claim would never independently verify.

**Fix 2 — verify the claim, don't just count it.** `ForcedBlocks(v, s)` now only counts a declared
block if `Prepared(v-1, s, block)` independently holds against the real message log, mirroring
DEV-20's "re-verifies" in one line rather than a second trust-the-sender check. At the same bound,
TLC completed the **full** reachable state space with no error (below). Both earlier counterexample
traces are the shape of a real formal-methods result: the tool did not just fail to find problems
in the fixed version, it visibly found two real ones — in the *specification*, not the
implementation — when they were still there, at the same bound that later verifies clean.

---

## Runs

All runs below use `MaxView=1, MaxSeq=1` — see **§ Why this bound, and not larger** for why every
attempt at `MaxView=2, MaxSeq=2` was abandoned. Local machine: 8 GB RAM Darwin/arm64 dev box (the
same one every other session's `make test`/`make lint` runs on), 8 cores, `-workers auto`
throughout.

### Run 1 — Safety, F=1 (design bound met): `pbft.cfg`

`Faulty = {r4}`. `INVARIANT`s: `TypeOK`, `Agreement`, `Validity`. `SYMMETRY BlocksSymmetry` (sound
here — this run declares no `PROPERTY`, and TLC's symmetry-unsoundness warning is specific to
liveness checking).

```
Model checking completed. No error has been found.
1,126,925,825 states generated, 74,970,368 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 33.
Finished in 01h 08min.
```

**Agreement, Validity, Integrity (TypeOK) all hold, exhaustively, at the design fault bound.**
This is the formal counterpart of `test_pbft_byzantine.py`'s four `f=1` fixtures (silent,
equivocating, wrong-signature, stale-view) — those check specific scenarios; this checks every
scenario reachable at this bound.

### Run 2 — FLAW-5, F=2 (one more fault than the design tolerates): `pbft_flaw5.cfg`

`Faulty = {r3, r4}`. `QuorumSize` stays 3 (computed from the *design* `F=1`, never from
`Cardinality(Faulty)=2` — see **Model** above). `INVARIANT`s: `TypeOK`, `Validity`, `Agreement`.

**Exhaustive attempt (local): did not complete.** Ran from 2026-09-28 03:29 to 08:48 (4 h 19 min)
before failing on `No space left on device` — TLC's disk-backed fingerprint/state files
(`verification/states/`) had grown to 24 GB on a machine with ~21 GB free at the time. The search
was **stuck at BFS depth 15 the entire run**, a wide plateau rather than genuine non-termination:
3,781,020,280 states generated, 281,002,154 distinct states found, 138,098,226 still on the queue
when it died. No counterexample had been found in that partial exploration; this is expected under
BFS if the specific interleaving that produces the fork is not the shallowest one, not evidence the
fork is absent.

**Simulation (local): found the counterexample in 1 second.**

```
$ java -XX:+UseParallelGC -cp lib/tla2tools.jar tlc2.TLC -simulate -depth 60 -config pbft_flaw5.cfg -workers auto MC.tla
Error: Invariant Agreement is violated.
The number of states generated: 114810
Simulation using seed 5005532579891441155 and aril 0
Progress: 115938 states checked.
Finished in 01s.
```

The trace: `r1` (honest) commits `b1` at seq 1, view 0 — its commit-quorum `{r1, r3, r4}` uses
both Byzantine replicas padding a real certificate (`r3`/`r4` sent genuine-format `Prepare`/`Commit`
for `b1`, matching what `r1`'s own honest primary pre-prepared). `r2` (honest) later commits `b2`
at seq 1, view 1 — the view-change quorum for entering view 1, `{r2, r3, r4}`, forms with `r2`
honestly declaring `NoBlock` (it moved to view 1 *before* observing `b1`'s prepared certificate —
a legitimate, honest thing to do; nothing requires a replica to wait) and `r3`/`r4`'s declarations
never claiming `b1` (a Byzantine replica gains nothing by honestly reporting the value that would
force safety, so it simply declares something else). `ForcedBlocks(1, 1) = {}` — nobody who
actually sent a `ViewChange` message declared `b1` — so `r2`'s primary is free to propose `b2`.
**`r1` has committed `b1`; `r2` has committed `b2`; both are honest. Agreement violated at `F=2`,
exactly as FLAW-5 predicts:** the "at least one honest replica in the quorum intersection"
guarantee that makes Run 1 safe requires `|Faulty| <= F`; at `|Faulty|=2 > F=1` on `n=4`, both
members of a 2-element intersection can be the two Byzantine replicas, and the argument simply does
not apply.

**Exhaustive attempt (Ada): submitted, pending.** See **§ Ada runs**.

### Run 3 — Liveness control, F=1 design/zero actual faults: `pbft_control_f0.cfg`

`Faulty = {}`. `INVARIANT`s as above plus `PROPERTY Termination`
(`\A s \in Seqs: <>(\A r \in Honest: log[r][s] # NoBlock)`), under `Fairness` (weak fairness on
every honest action; deliberately none on `ByzantineAction` — vacuous here since there is none).
**No `SYMMETRY`**: TLC warns "Declaring symmetry during liveness checking is dangerous. It might
cause TLC to miss violations of the stated liveness properties" — correctness was preferred over
the (small, two-element) speedup symmetry would have given.

First attempt used the default deadlock check and hit `Error: Deadlock reached` at the state where
every replica has committed and `view` has hit `MaxView` — a real fact about the *bounded model*
(nothing is left to explore once the bound ceiling is hit), not a protocol liveness failure.
Re-run with `-deadlock` (which, in TLC's flag naming, *disables* the deadlock check, letting TLC
treat a terminal state as stuttering forever, the standard way to bounded-model-check a liveness
property):

```
Model checking completed. No error has been found.
4,919,485 states generated, 1,240,200 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 27.
Finished in 02min 59s.
```

**Termination holds exhaustively with zero Byzantine replicas.** This isolates that the liveness
question in Run 4 (below) is genuinely about the Byzantine/no-state-transfer interaction, not an
artifact of the model itself.

### Run 4 — Liveness, F=1 (one Byzantine replica): `pbft_liveness.cfg`

`Faulty = {r4}`. Same properties, fairness and no-`SYMMETRY` as Run 3. **Expected result** (by the
same certificate-quorum argument Run 1's exhaustive safety pass already confirms structurally):
`Termination` should be *violated* — DEV-20 omission #2 (no state transfer) plus a Byzantine
equivocation should be able to strand one honest replica permanently behind a seq it can never
validate `prev_hash` for, exactly `test_pbft_byzantine.py::
test_equivocation_with_honest_votes_strands_one_honest_replica` on one constructed run, generalised
to every reachable way of reaching the same outcome.

**Did not complete locally.** Ran 1 h 42 min (2026-09-28 08:58 to 10:00), reaching 16,420,732
distinct states (160,428,354 generated) at BFS depth 16, with TLC issuing "Warning: Liveness
checking will be extremely slow because TLC is running low on memory" against the 1,820 MB heap
this machine's `-workers auto` default left available, and individual "checking temporal
properties" passes costing minutes each (one took 3 min 27 s) rather than seconds. Stopped rather
than left running indefinitely or allowed to repeat Run 2's disk exhaustion — **moved to Ada**
(§ below) with real memory headroom instead. No pass/fail result is claimed for this run locally;
per CLAUDE.md, an unmeasured number is not reported as one.

---

## Ada runs

Both exhaustive attempts that did not finish locally (Run 2's exhaustive leg and Run 4 in full)
were shipped to the Ada HPC cluster (CLAUDE.md §6) rather than re-attempted or abandoned on the 8
GB dev box. This account's SLURM ceiling at submission time (`sacctmgr show qos low`: `MaxTRESPU =
cpu=10`; partition `u22`'s `MaxMemPerCPU=3000` — the same ceiling `scripts/ada_honest_mode.sbatch`
already discovered and documented) was `--cpus-per-task=10 --mem-per-cpu=3000` (~29.3 GB), not the
`-Xmx64g` this task's own brief first suggested — adjusted down to what the account could actually
be granted, the same correction M6b already made once for the ML jobs. Both `.sbatch` scripts run
the identical unmodified `.cfg`/`.tla` files from a `/scratch/$SLURM_JOB_ID` working copy
(disk-heavy TLC checkpoint files never touch the NFS home checkout), and copy back only a
human-readable result log.

**Both jobs ended up running concurrently** (`gnode080` for FLAW-5, a separate node for liveness) —
apparently this account's QOS accounting did not serialize two 10-CPU jobs the way the `MaxTRESPU
cpu=10` figure implied it should; not investigated further since it only helped.

**The account's QOS was upgraded from `low` to `medium` mid-session** (`MaxTRESPU` `cpu=10` →
`cpu=40`), noticed and confirmed by re-running `sacctmgr show qos` after the user flagged it. The
FLAW-5 job (already ~7 hours in with real structural progress — BFS depth advanced 15→17, hundreds
of millions of states accumulated) was left running rather than restarted purely to claim the new
headroom. The liveness job was young enough (~13 minutes, 2.6M states) that the trade was worth it:
cancelled and resubmitted under `qos=medium` with `--cpus-per-task=20 --mem-per-cpu=3000` (~58.6 GB,
`-Xmx54g`) instead of the original ~29.3 GB, to reduce the chance of repeating the same
low-memory-driven slowdown seen both locally and in the first Ada attempt.

| Job | Config | SLURM job ID | Resources | Status at session end |
|---|---|---|---|---|
| `ada_flaw5.sbatch` | `pbft_flaw5.cfg`, exhaustive (upgrades Run 2's simulation-based finding) | 2720269 | `qos=low`, 10 cpu/~29.3GB | running, in progress |
| `ada_liveness.sbatch` (1st submit, cancelled) | `pbft_liveness.cfg`, exhaustive (Run 4, unresolved locally) | 2720270 | `qos=low`, 10 cpu/~29.3GB | cancelled at ~13min/2.6M states, superseded |
| `ada_liveness.sbatch` (resubmit) | `pbft_liveness.cfg`, exhaustive (Run 4, unresolved locally) | 2721161 | `qos=medium`, 20 cpu/~58.6GB | running, in progress |

The session was not held open for either to complete; `PROJECT_STATE.md` records both as an open
item for the next session (or a wakeup within this one, if the harness re-invokes before Ada
finishes). **These are upgrades, not blockers**: Run 2's simulation-found counterexample already
conclusively demonstrates FLAW-5 (one counterexample is one counterexample regardless of search
strategy); Run 4's expected result is already argued analytically from Run 1's own
exhaustively-confirmed certificate math (below). What Ada adds, if it finishes, is "we searched
everything" in place of
"we searched enough to find one."

---

## Why this bound, and not larger

`MaxView=2, MaxSeq=2` (the brief's suggested starting point) exceeded 10 million states within
single-digit seconds on every attempted variant of the guard, well past the brief's own
>10M-states-reduce-bounds threshold. `MaxView=1, MaxSeq=1` — one possible view change, one sequence
number — is the smallest bound that still exercises the view-change mechanism at all (the entire
point of this verification, since the normal-case pigeonhole safety argument was never in serious
doubt), and it is also the **largest bound this project's hardware could exhaust**: Run 1 (safety,
`F=1`) took 68 minutes for 74,970,368 states; Run 2 (`F=2`) did not finish 4+ hours and 281 million
distinct states before running out of disk. Both numbers are reported rather than hidden because
the state-space *size itself* is informative: it says the reduced protocol's reachable behaviour,
even bounded to the smallest interesting case, is already large enough that this is Byzantine-fault
model checking at the edge of what a single machine can exhaust, not a toy check.

---

## The §V-3 / DEV-20 mapping table

Parallels M7-1's §V-1 table (`verification/README.md`) — one row per informal claim, the formal
property TLC checked for it, and the measured result.

| Informal claim (PAPER_NOTES §V-3 / DEV-20) | Formal property (TLC) | Result |
|---|---|---|
| Reduced pBFT preserves safety (no fork) at the design fault bound, despite omitting checkpoints/state-transfer/pipelining/null-requests/retransmission | `Agreement`, `F=1`, `\|Faulty\|=1` | **VERIFIED**, exhaustive — 74,970,368 states, depth 33, 1h08min |
| A committed block was really proposed by some replica (never fabricated) | `Validity`, same run | **VERIFIED** (same run) |
| An honest replica commits at most once per seq | `TypeOK` / state-representation argument | **HOLDS BY CONSTRUCTION** — `log[r][s]` is a single-value slot, checked every state |
| FLAW-5: pBFT's real safety bound is `n/3`, not the paper's borrowed 51% — two colluding replicas of four (50%, below 51%) can fork | `Agreement`, `F=1` (design)/`\|Faulty\|=2` | **VIOLATED** — counterexample found (simulation, 1s/115,938 states); exhaustive attempt reached 281M states/4h19min without completing (Ada job 2720269 pending) |
| Termination under fairness, fault-free (sanity control) | `Termination`, `\|Faulty\|=0` | **VERIFIED**, exhaustive — 1,240,200 states, depth 27, 2min59s |
| DEV-20 #2 (no state transfer): a lagging honest replica can become permanently unable to progress once one Byzantine replica equivocates | `Termination`, `F=1`, `\|Faulty\|=1` | **EXPECTED VIOLATED** (argued from Run 1's certificate math: at `F=1/n=4`, `QuorumSize` equals the honest-replica count exactly, so *any* progress requires *every* honest replica to commit — DEV-20 confirmed formally, not just by the one Python fixture, **once Ada job 2721161 completes**); **UNRESOLVED as measured fact** at session end |

---

## Comparison with M7-1 (Scyther)

Two different formal techniques, on two different protocol layers, for a reason: `crypto.session`
is a two-party exchange whose interesting properties (secrecy, mutual authentication, freshness)
are naturally expressed as trace properties checked under a symbolic Dolev-Yao adversary — Scyther's
exact domain. pBFT's interesting properties (agreement across four replicas, safety under quorum
intersection, liveness under fairness) are about how *many* parties' local states interleave, which
is naturally expressed as reachable-state exploration — TLC's exact domain. Using Scyther for
consensus or TLC for a two-message key exchange would each be the wrong tool forcing an awkward
encoding; using the tool each protocol's model naturally fits is why this pairing was chosen over
picking one tool and stretching it to cover both layers. Both share the same discipline: state the
adversary model precisely (Scyther's Dolev-Yao vs. this spec's `ByzantineAction`), state what is
*not* covered (Scyther's stateless nonce-cache gap vs. this spec's fixed `n=4`/two-`Blocks`
abstraction), and — the strongest form of confirmation either gives — show the tool finding a real
violation when pointed at a version of the model that should have one (Scyther's pre-M1 sketch;
this session's two draft view-change guards).

## Limitations, stated plainly

1. **Bounded, not unbounded.** `MaxView=1, MaxSeq=1` is exhaustive *at that bound*; a real deployment
   runs unboundedly many views and sequence numbers. The state-space growth observed here (10M+
   states within seconds at `MaxView=2`) means this is a hardware/time limitation of this project,
   not a choice that trades away meaningful coverage cheaply available at larger bounds.
2. **Two block values, not an open domain.** Sufficient to detect any equivocation/fork (the
   interesting failure mode always involves two DIFFERENT committed values); does not model
   richer payload semantics, which are irrelevant to consensus safety/liveness.
3. **`F=2` exhaustive result is pending (Ada).** The FLAW-5 finding itself does not depend on it —
   a single found counterexample already refutes universal Agreement at `F=2` — but "no OTHER kind
   of violation exists in the full `F=2` state space" is not yet a checked fact.
4. **`F=1` liveness result is pending (Ada), not merely un-triple-checked.** Unlike the `F=2` case,
   no counterexample has been found for this property at all yet, locally or otherwise. The
   expected-violated call is an argument from Run 1's exhaustively-confirmed certificate math (the
   quorum-size-equals-honest-count coincidence at this exact configuration), not yet a TLC-measured
   fact, and is reported as such rather than as one.
5. **The forced-re-proposal mechanism is modelled at the granularity DEV-20 describes** (a
   `ViewChange` message declares one seq's known-prepared block, verified against the real message
   log), not as a byte-faithful re-implementation of `view_change.py`'s certificate wire format.
   The two draft-guard bugs this session found and fixed (above) are direct evidence this
   granularity is not too coarse to catch a real safety gap — it caught two, in the spec itself.
