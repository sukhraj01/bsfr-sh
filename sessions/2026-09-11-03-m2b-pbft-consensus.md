# Session 2026-09-11-03 — M2b, pBFT consensus

**Milestone:** M2b · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/ARCHITECTURE.md`, `docs/NOTATION.md`, `sessions/_TEMPLATE.md`; then, because the task
departs from the paper (view-change reduction, Q7), `docs/DEVIATIONS.md` (DEV-10, DEV-17/18 for
format); and the §V paragraph of `docs/PAPER_NOTES.md` only, because the prompt asks for the
§V-3 mapping; and a `grep` of `docs/ALGORITHMS.md` for the pBFT rows only, for the CLAUDE.md
§4b line references · **Duration:** one working session, split by a usage-limit pause

Per the context ladder, `docs/EXPERIMENTS.md` was **not** read. The "~1 ms vs ~380 ms" figures
below are quoted from the prompt, not from that file, and are not ours.

---

## Brief *(written before any work)*

**Task:** Build `consensus/network.py` (in-process P2PCS bus with drop/delay/duplicate/reorder
and a configurable, zero-default per-message delay), `consensus/pbft.py` (three-phase commit,
certificates counted by distinct signed sender, `(chain, view, seq, digest)` inside every
signature) and `consensus/view_change.py` (timeout-driven view change with prepared-certificate
carry-over), with the four byzantine behaviours as drop-in test fixtures.

**Exit condition:** `make test` and `make lint` exit 0; `BC_DTBU` and `BC_SigRW` each build
15 blocks x 100 tx through full consensus on their own 4-replica clusters with one byzantine
replica tolerated; the delay parameter exists in `configs/chain.yaml`, defaults to 0, and its
effect on Target 3 is written in `configs/bench.yaml`.

**Out of scope:** honeypot, ML, bench harness, figures, any timing row in `RESULTS.md`.
Consensus timing is M6. Block *validity* stays in `Chain` — consensus asks the chain, it does not
re-implement the checks.

**Prior context needed:** `blockchain/block.py` and `chain.py` (what a replica holds and appends),
`crypto/ecdsa.py` (sign/verify), `util/serialization.encode_struct` (canonical signed bodies),
DEV-10 (threshold, view change), Q7 answer from the prompt.

### Decision — does the bus model latency? *(required before coding)*

**Yes, configurably, on a simulated clock, defaulting to zero.** Recorded here before any code.

1. **The parameter.** `configs/chain.yaml` → `consensus.message_delay_s`, DECLARED, default
   `0.0`. Per-node extra delay and jitter exist on top of it for the byzantine fixtures. Nothing
   hardcodes either value.
2. **The clock is simulated, not slept.** The bus is a discrete-event scheduler: a message sent at
   simulated time `t` with delay `d` is delivered at `t + d`, and view-change timeouts run on the
   same clock. Nothing calls `time.sleep`. Reasons: (a) the view-change tests would otherwise
   need real multi-second waits, which is exactly the "a timeout that can only be tested by
   waiting does not get tested" failure `crypto.session` already avoids with an injected clock;
   (b) `sleep` on this box has millisecond-scale jitter, which is the same order as the
   zero-delay consensus cost M6 wants to measure, so sleeping would add noise to the very
   number being isolated; (c) a simulated clock makes the modelled network time exact and
   reproducible from the seed.
3. **Consequence for M6 / Target 3.** With delay `0`, wall-clock around consensus measures pure
   compute (ECDSA sign/verify, hashing, chain validation) — the prompt's ~1 ms per 100-tx block
   against the paper's ~380 ms — and Fig. 6's shape will be dominated by hybrid encryption. With
   delay `d > 0`, wall-clock is **unchanged**; the modelled network cost appears as simulated time
   (`network.now`), roughly `3d` per committed block on the pre-prepare → prepare → commit
   critical path. M6 must therefore report the two components side by side — measured compute
   seconds and modelled network seconds — and never fold them into one "measured" number, since
   the network part is modelled, not measured (CLAUDE.md §2).

### Decisions taken from the prompt, recorded so they are not re-derived

- **Q7 closed:** a pre-prepare's *signed* body is `(chain, view, seq, digest)`; the `Block`
  travels alongside, outside the signature, and a replica rejects the pair unless
  `block.current_hash == digest`. `chain` is our addition — see Findings.
- **Certificates:** prepared = accepted pre-prepare + `2f` matching prepares from distinct
  non-primary replicas; committed = prepared + `2f+1` matching commits from distinct replicas.
  Counted by signed sender identity, never by arrival.
- **View change:** reduced form unless full Castro–Liskov fits; any reduction gets a DEV entry
  naming what is omitted and what it costs.

### §V-3 — the claim this milestone substantiates

§V-3 argues pBFT resists 51% / selfish mining and that permissioned membership handles Sybil,
purely by asserting pBFT was used. What M2b can actually show, and the tests that will show it,
is mapped in Findings at the end.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/ARCHITECTURE.md
and docs/NOTATION.md. Not docs/EXPERIMENTS.md.

Create the session file from the template and fill the brief first.

TASK — M2b, pBFT consensus. src/bsfr_sh/consensus/.

Q7 is answered: pre-prepare carries (view, seq, digest), signed. The block
travels alongside, outside the signed message. Replicas verify the block's
current_hash equals the digest before accepting.

1. network.py — in-process P2PCS message bus.

   DECISION REQUIRED BEFORE CODING, record it in the session brief:
   does the bus model latency, or deliver instantly?

   With instant delivery, consensus for a 100-tx block costs ~1 ms against the
   paper's ~380 ms, and Fig. 6's shape ends up dominated by hybrid encryption
   rather than by consensus. That is a defensible result but it changes what
   Target 3 claims. Build the bus with a configurable per-message delay
   defaulting to zero, so M6 can run both and report the difference. Do not
   hardcode either. Note in configs/bench.yaml that the delay parameter exists
   and what it does to Target 3's interpretation.

   The bus must support: drop, delay, duplicate, and reorder per-node, since
   the byzantine fixtures need them.

2. pbft.py — three-phase commit.

   n = 3f+1 with the paper's 4 nodes, so f = 1. Get the certificate counts
   right, they are the usual place this goes wrong:
     - prepared = own pre-prepare + 2f matching prepares from distinct replicas
     - committed = 2f+1 matching commits from distinct replicas
   "Distinct" is load-bearing. Count by sender identity, not by message
   arrival, or one replica sending the same prepare three times forms a
   certificate alone.

   Every message carries (view, sequence, digest) and is ECDSA-signed. All
   three must be inside the signature. A message missing view in its signed
   body can be replayed into a later view; missing sequence can be replayed at
   a different height. Both are tests.

   Reject: messages for a sequence already committed, messages from outside
   the configured membership (this is the permissioned property §V-3 leans on
   for Sybil resistance), and messages whose digest doesn't match a block the
   replica holds.

3. view_change.py — leader timeout and view change.

   §V-3 claims resistance to a class of attacks that a liveness failure would
   undercut, so a silent leader must not stall the chain permanently. Implement
   timeout-triggered view change with new-view justification carrying the
   prepared certificates from the previous view.

   If full Castro-Liskov view change with checkpointing and garbage collection
   is more than this task can hold, implement the reduced form — timeout,
   view increment, prepared-certificate carry-over, no checkpointing — and
   record it as a DEV entry naming precisely what is omitted and what that
   costs. A documented reduction is fine; an undocumented one is not.

4. Byzantine fixtures, in tests.
   Silent (never responds), equivocating (different blocks under the same
   view+seq), wrong-signature, stale-view. Each as a node behaviour that can
   be dropped into a running network.

   Assert both directions: with f = 1 byzantine node the chain still commits,
   and with f = 2 it correctly fails to commit rather than committing
   something wrong. The second is the more important test — safety under
   excess faults, not liveness.

   The equivocation test should assert the specific mechanism: two conflicting
   pre-prepares under one (view, seq) leave honest replicas unable to form a
   prepared certificate for either.

TESTS
Happy path commit. Certificate counting by distinct sender. Replay across
views rejected. Replay across sequences rejected. Non-member rejected.
Digest mismatch rejected. All four byzantine behaviours, at f=1 and f=2.
View change on leader timeout, and chain continues after it.

Map to §V-3 in the session file. §V-3 is the claim this milestone
substantiates; it is also the claim the paper argues purely by asserting PBFT
was used.

EXIT CONDITION
make test and make lint green. Both chains build 15 blocks × 100 tx through
full consensus with 4 nodes, f=1 tolerated. Bus latency configurable,
defaulting to zero, with the Target-3 consequence documented.

OUT OF SCOPE
No honeypot, no ML, no bench harness, no figures. Still no timing rows in
RESULTS.md — consensus timing is M6 with a proper harness and repeat counts.

END OF SESSION
Session file with attribution and dead ends. DEV entry for any view-change
reduction. Close Q7. Rewrite PROJECT_STATE.md, under 200 lines. Tick M2b.
Commit explaining why.

2. session limit is restored continue where left off
```

*(Prompt 2 followed a usage-limit interruption after the brief was written and before any code.
Nothing was lost; work resumed from the DEV entries.)*

---

## What was done

All new code and tests are **AI-generated, human-directed** — the task, the Q7 answer, the
certificate definitions, the zero-default configurable delay, the reduced-view-change option and
the f=1/f=2 test directions were specified in the prompt; the design choices below (simulated
clock, `protocol.py` split, commit-certificate height proofs, `check_append`, DEV-22) and all
implementations are Claude's.

**`src/bsfr_sh/consensus/` (4 modules, all new)**

| Module | What it does | Notable |
|---|---|---|
| `network.py` | `P2PCSNetwork` — discrete-event bus, simulated clock, timers, per-sender `LinkFaults` | imports nothing internal; seeded RNG; cancelled timers never move the clock |
| `protocol.py` | signed messages, `Proposal`, `ClientRequest`, `Membership`, certificate checks, `RejectReason` | `(chain, view, seq, digest, replica_id)` in every signed body, per-type domains |
| `view_change.py` | build/verify `ViewChange` and `NewView`; `select_reproposal` | committed height must be *proven* by a commit certificate |
| `pbft.py` | `Replica`, `PBFTPolicy`, `Behaviour` hook, `Cluster` | asks `Chain.check_append` before preparing; never re-implements validity |

**Also changed**

| File | Change |
|---|---|
| `blockchain/chain.py` | `append()` split into `check_append()` + two assignments; `adopt_genesis()`; `build_genesis()` |
| `configs/chain.yaml` | `consensus.message_delay_s: 0.0`, `consensus.log_window: 4` (both DECLARED) |
| `configs/bench.yaml` | comment block: what the delay parameter does to Target 3's interpretation |
| `docs/DEVIATIONS.md` | DEV-10 amended; DEV-19, DEV-20, DEV-21, DEV-22 opened |
| `docs/ARCHITECTURE.md` | `consensus/` section rewritten — four modules, dependency table, boundaries |
| `docs/NOTATION.md` | `L` row corrected; new Consensus table (`v`, `s`, `d`, messages, certificates) |
| `docs/ALGORITHMS.md` | Alg. 1 lines 4–10 now name real code (was a `PBFTEngine` that never existed) |
| `docs/PAPER_NOTES.md` | FINDING under §V: the "51%" framing is inverted for pBFT |
| `docs/ROADMAP.md` | M2b ticked, current milestone → M3 |

**Tests (7 new files + 3 amended; suite 465 → 618)** — `test_network.py` (18),
`test_pbft_messages.py` (27), `test_pbft.py` (30), `test_view_change.py` (16),
`test_pbft_byzantine.py` (18), `test_consensus_scale.py` (1), harness `pbft_harness.py`; plus
`test_chain.py` (+4, `check_append`/`adopt_genesis`), `test_module_boundaries.py` (+1
parametrized, consensus dependency direction), `test_config.py` (delay default is 0).

## Findings

**§V-3 mapping — what M2b substantiates, and what it contradicts**

| §V-3 sub-claim | Status after M2b | Tests |
|---|---|---|
| Permissioned deployment resists Sybil | **Substantiated.** Votes from non-members are refused; 50 minted identities cannot form a certificate; an outsider claiming a member's id fails the signature; a block owned by a non-member is never prepared. | `test_pbft.py::test_a_message_from_outside_the_membership_is_rejected`, `::test_a_sybil_swarm_of_outsider_identities_cannot_form_a_certificate`, `::test_an_outsider_claiming_a_members_id_fails_the_signature`, `::test_a_block_owned_by_a_non_member_is_not_prepared` |
| pBFT keeps one agreed chain under byzantine miners | **Substantiated for f=1.** All four behaviours, as primary and as backup: chain commits, no fork. | `test_pbft_byzantine.py::test_f1_the_chain_commits_and_honest_replicas_agree` (8 cases), `::test_two_conflicting_pre_prepares_leave_honest_replicas_unable_to_prepare_either`, `test_consensus_scale.py` |
| Safety beyond the bound | **f=2 non-colluding: stops, never commits wrongly** (4 cases). **f=2 colluding: forks** — the bound is exactly `f`. | `::test_f2_the_chain_fails_to_commit_rather_than_committing_wrongly`, `::test_f2_colluding_equivocators_can_fork_honest_replicas_the_bound_is_exactly_f` |
| "Resists 51% attack" | **Contradicted as worded.** pBFT tolerates `< n/3`, not `< n/2`; 2 of 4 nodes (50%) fork it. FINDING recorded in `docs/PAPER_NOTES.md` §V. | the colluding test above |
| "Resists selfish mining" | **Not applicable** — nothing is mined. The analogue, a withholding leader, is handled by view change. | `test_view_change.py::test_a_silent_leader_triggers_a_view_change_and_the_chain_continues`, `::test_a_stalled_view_change_escalates_to_the_next_view` |
| Liveness (implicit — a stalled chain undercuts every claim) | **Substantiated** with the DEV-20 reduction; the stranding cost is pinned. | `test_view_change.py` (whole file), `test_pbft_byzantine.py::test_equivocation_with_honest_votes_strands_one_honest_replica` |
| Vote integrity (replay) | **Substantiated.** view/seq/digest/chain each in the signature; old-view and committed-height messages refused. | `test_pbft_messages.py::test_every_signed_field_is_covered_by_the_signature` (15), `test_pbft.py::test_replay_across_views_is_rejected`, `::test_replay_across_sequences_is_rejected`, `::test_a_vote_signed_for_the_other_chain_is_rejected_even_under_the_same_key` |

**The f=2 requirement needed a qualification, and it is now a test rather than a footnote.**
The brief asked that with f=2 the chain "correctly fails to commit rather than committing
something wrong". For the four behaviours acting independently, that holds and is tested. It
cannot hold against colluders: at n=4, a primary that equivocates plus one backup that votes each
honest replica's block gives each honest replica a full certificate for a different block. That is
pBFT's specified bound, not an implementation defect, so the colluding test *asserts the fork* —
if it ever stops forking, the protocol has changed and the §V-3 write-up must change with it.

**A safety hole in my first view-change design, caught before code.** The first sketch dropped
prepared certificates on commit and took each view-change's `last_seq` on trust, with `min_s`
chosen from the claimed heights. Walking the quorum-intersection argument showed a byzantine
replica reporting a *low* height, plus an honest replica whose certificate for the committed
block had already been garbage-collected, could let a new primary propose a *different* block at
an already-committed height and get it committed with f=1. Fix: every view-change carries the
`2f+1` commits that committed its height (a one-block checkpoint), `min_s` is the highest
*proven* height, and heights cannot be inflated or hidden. Pinned by
`test_view_change.py::test_a_view_change_claiming_a_height_without_proof_is_rejected` and the
"height proof not required" mutant.

**Mutation check: 15 mutants of the safety rules, all killed**, each by the test written for it
— count arrivals not senders, count the primary's prepare, drop view/seq/chain from the signed
body, prepare quorum `2f-1`, commit quorum `2f`, no membership check, no digest check, accept a
conflicting pre-prepare, skip `check_append`, skip new-view recomputation, ignore carried
certificates, no view-change timer, no height proof. Script is not committed (scratchpad); the
result is recorded here so a later "are the tests real?" has an answer.

**Dead ends and corrections**

- *Cancelled timers advanced the clock.* The first smoke run showed `now = 6.0` after three
  zero-delay blocks: every commit cancels a view-change timer, and popping the cancelled event
  still set `now` to its expiry. That would have added `view_change_timeout_s` of phantom
  "network time" per block to exactly the number DEV-21 tells M6 to read. Fixed in the scheduler;
  regression test `test_network.py::test_a_cancelled_timer_does_not_advance_the_clock`.
- *The stale-view test first built an f=2 cluster by accident* — a permanently silent CS_0 to force
  the first view change, then a stale CS_3. The cluster stalled, correctly. Rewritten with a
  transient link fault on CS_0 so only CS_3 is faulty afterwards.
- *My prediction for the "replica shown both pre-prepares" test was wrong.* I expected the replica
  holding the losing block to be stranded. It was rescued: the equivocator also garbles its own
  commits, so nothing commits in view 0, and the view change carries the winning block's prepared
  certificate into view 1, where the stranded replica accepts it. Kept as a test; a second test
  with an equivocator that *votes honestly* is the one that actually strands a replica, and it now
  pins DEV-20 item 2 (DEV-20's text, which said no tested scenario produced lag, was corrected).
- *Three of my first mutants were mis-specified* (one equivalent — `_check_prepared`'s
  primary filter is defence-in-depth behind `_on_prepare`'s guard; one broke storage wholesale; one
  matched twice). Rewritten; all 15 then killed.
- *`docs/ALGORITHMS.md` mapped Alg. 1 lines 5–10 to a `PBFTEngine.run_round()/commit()`* that
  never existed. Updated to the real code. Doing so exposed that the paper has `CS_l` assemble the
  block and a separate leader run pBFT; ours has the primary assemble — recorded as DEV-22.
- *Rejected: sleeping for latency.* See the brief. *Rejected: dropping pre-prepares for future
  heights* — under reordering a replica would lose the next block's proposal; they are buffered up
  to `log_window` instead.

**For M6, not fixed here.** The bus passes Python objects and never serialises, so wire-encoding
cost is not in the consensus span. At zero delay that understates consensus cost further; if M6
wants a network-shaped number it should either serialise at the bus or say it did not.

## Numbers

No benchmark this session, by instruction — consensus timing is M6. `RESULTS.md` is untouched.
Structural facts only, none of them timings: 28 messages per committed block at n=4 (4 requests +
3 pre-prepares + 9 prepares + 12 commits — the textbook count, pinned by a test); modelled time per
block is exactly `4 x message_delay_s` from submission (`3 x` inside consensus), pinned for three
delays; the case-3 consensus build of both chains runs inside a 3.4 s full suite. None has a
run_id or sidecar, and none may be quoted as a result.

## Deviations opened or changed

- **DEV-10** amended — built; points to DEV-19/20/21, states the certificate sizes.
- **DEV-19** opened (FILL) — digest-only signed pre-prepare with block alongside (closes Q7);
  `chain` added to every signed body; per-message-type signing domains.
- **DEV-20** opened (FILL) — reduced view change; seven omissions named with costs; the
  commit-certificate height proof that replaces checkpoints.
- **DEV-21** opened (FILL) — simulated-clock bus, zero default delay, Target 3 consequence.
- **DEV-22** opened (FILL) — the primary assembles `β_j`; the collecting `CS_l` submits
  transactions.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** `consensus/` is complete. Each chain runs as a `Cluster` of four `Replica`s on
its own `P2PCSNetwork`; both chains build 15 blocks x 100 tx through full pBFT with one byzantine
replica tolerated. `make test` runs 618 tests (153 new) and `make lint` is clean. Q7 is closed.

**Next task:** Build M3's `framework/_block_pipeline.py` and `framework/phase1_backup.py`
(Alg. 1 end to end): a `SYS_i` ships backups to `CS_l` over a `crypto.session` key, `CS_l`
encrypts them with `encrypt_backup` and submits them through `consensus.pbft.Cluster.submit`,
authenticating the submitter at the session layer (closing DEV-20 item 5); exit when an
integration test in `tests/integration/` backs up a system's data onto `BC_DTBU` through
consensus and reads it back byte-identical.

**New blockers:** none.

**Questions opened / closed:** **Q7 closed** — DEV-19. **Q8 opened** — does anything before M7
need state transfer (DEV-20 item 2)? Only if M6 benchmarks a lossy network; decide at M6 start.

**Debt:** D2 unchanged. **D3 opened** — the bus does not serialise, so wire-encoding cost is
absent from the consensus span; M6 serialises at the bus or says in Target 3 that it did not.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended — **not applicable**, no benchmark was run, by instruction
- [x] `docs/ROADMAP.md` boxes ticked — M2b `[x]`, current milestone → M3
- [x] `docs/DEVIATIONS.md` updated — DEV-10 amended, DEV-19–22 opened
- [x] Committed, message explains *why*
