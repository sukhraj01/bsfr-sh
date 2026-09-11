# Session 2026-09-12-01 — M3a, Phases 1 and 5 (backup and recovery)

**Milestone:** M3a · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`, `docs/ALGORITHMS.md`,
`docs/PAPER_NOTES.md` §IV-A and §IV-E (plus the five-line §V summary, for the §V-1/§V-5 mapping the
prompt asks for), `docs/NOTATION.md`, `sessions/_TEMPLATE.md`. Because the task departs from the
paper, also `docs/DEVIATIONS.md` (DEV-01, -02, -05, -15, -20 item 5, -22), the M3 block of
`docs/ROADMAP.md`, the dependency and recovery sections of `docs/ARCHITECTURE.md`, and the code
this builds on (`crypto/session.py`, `crypto/kem.py`, `crypto/aead.py`, `blockchain/transaction.py`,
`blockchain/chain.py`, `blockchain/block.py`, `consensus/pbft.py`, `consensus/network.py`,
`tests/unit/pbft_harness.py`). `docs/ARCHITECTURE.md` was read in full at the end, to update it.
`docs/EXPERIMENTS.md` was **not** read. · **Duration:** one working session

---

## Brief *(written before any work)*

**Task:** Build Phase 1 (Alg. 1, backup onto `BC_DTBU` through pBFT) and Phase 5 (Alg. 5, two-hop
recovery from `BC_DTBU`) together, on a block pipeline Phase 2 will reuse unchanged.

**Exit condition:** `make test` and `make lint` exit 0; a test backs up N systems through
consensus on `BC_DTBU`, wipes one, restores it via `CS'_l -> CS_l -> SYS_i`, and asserts the data
is byte-identical; the index and the cold scan return identical locations; tampered ciphertext and
a payload-digest mismatch both raise rather than return data.

**Out of scope:** honeypot, signatures, features, ML, mitigation, bench, any timing row in
`RESULTS.md`. Phase 1 runs before any infection exists, so it needs no ransomware concept. Phase 2
(`honeypot/`, `phase2_collection.py`) is M3b.

**Prior context needed:** M1's session protocol and hybrid encryption (the two keys every hop
uses), M2a's `Transaction`/`Chain`, M2b's `Cluster.submit` and DEV-22 (submit transactions, never
blocks), DEV-05 (the index), DEV-15 (payload size).

### Decisions taken before coding

1. **Chunk framing lives in `BackupPayload` itself** (`DT_BU` is that type per
   `docs/NOTATION.md`). New fields go on the end with defaults that describe the paper's own
   record (one transaction, no digest, no attestation), so M2a's twelve construction sites keep
   compiling, and restore can refuse that paper-shaped record — the refusal *is* the DEV entry.
   Chunk order comes from an explicit `chunk_index`/`chunk_count`, never from block height.
2. **The payload digest is attested by `SYS_i`.** The digest travels with the data through two
   cloud servers that each hold plaintext. A digest they can recompute catches accidents
   (reassembly bugs, chunk mixing) and nothing else. `SYS_i` therefore signs
   `(system_id, captured_at, payload_digest)` with its ECDSA identity key before shipping, and
   verifies that signature against its own public key after the final hop. That is what lets the
   check survive a wipe (no local receipt is needed) and a dishonest server. One signature per
   backup.
3. **`CS'_l` is the key holder, `CS_l` is the front server.** Alg. 1 encrypts to `KU_CSl` of the
   *collecting* server; Alg. 5 has `CS'_l` decrypt. Consistent reading: `CS'_l` is Phase 1's
   collector, and `CS_l` is the server `SYS_i` recovers through. If the two are the same server,
   the first hop is redundant, and the docstring says so.
4. **The index is built by the key holder.** M2a put `system_id` *inside* the ciphertext so the
   chain does not leak who backed up when. So an index keyed on `system_id` can only be built by
   the key holder decrypting on append. The cost moves from recovery time to append time. It does
   not disappear. That goes in the DEV-05 amendment.
5. **Session transport is a new `crypto/channel.py`.** `recovery/` implements the two hops and
   may not import `framework/`, so sealing under `SK_{A,B}` has to sit below both. Direction,
   session and purpose are bound as AEAD associated data, and a receive counter rejects replays.

### Paper claims this milestone substantiates

§V-1 (session keys defeat replay / MITM / impersonation) at the two places Phases 1 and 5 use
them, and §V-5 (two chains isolate detection from recovery) as far as recovery reads only
`BC_DTBU`. Mapping is in Findings.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: this touches paper
phases, so docs/ALGORITHMS.md, docs/PAPER_NOTES.md §IV-A and §IV-E only, and
docs/NOTATION.md. Not docs/EXPERIMENTS.md.

Create the session file from the template and fill the brief first.

M3 is being split. This is M3a — Phases 1 and 5 together, because a backup
that cannot be recovered is not a verified backup. Phase 2 (honeypot,
signatures, features) is M3b. Update docs/ROADMAP.md to reflect the split.

TASK — M3a. Phases 1 and 5.

1. framework/entities.py
   System (SYS_i), CloudServer (CS_l) per docs/NOTATION.md. Identity,
   keypair, session establishment via M1's session.py. Keep these thin —
   participants, not orchestrators.

2. framework/_block_pipeline.py
   docs/ALGORITHMS.md says Alg. 1 lines 2-10 and Alg. 2 lines 3-10 are the
   same pipeline with different payload builders. Factor it now, before
   Phase 2 exists, so M3b has nothing to duplicate. Parametrize on payload
   builder and target chain. DEV-22 applies — the leader builds blocks from
   submitted transactions; keep that consistent.

3. framework/phase1_backup.py — Alg. 1.
   SYS_i ships DT_BU over SK_{CS_l,SYS_i}, CS_l encrypts to transactions,
   pipeline does the rest.

   Chunking: a backup larger than the configured payload size spans multiple
   transactions and possibly multiple blocks. Alg. 1's loop doesn't address
   this. Reassembly must be deterministic and independent of block arrival
   order — carry an explicit sequence number, don't infer order from block
   position. Handle the non-even remainder case.

4. recovery/locator.py — BackupIndex (DEV-05).
   Per-system index maintained on append, falling back to full scan when
   cold so paper semantics are preserved. Test both paths return identical
   results — the fallback is what proves the index is an optimization rather
   than a behaviour change.

5. recovery/restore.py + framework/phase5_recovery.py — Alg. 5.
   Preserve the two-hop transfer: CS'_l decrypts and hands to CS_l over
   SK_{CS'_l,CS_l}, then CS_l to SYS_i over SK_{CS_l,SYS_i}. One server would
   suffice; §IV-E specifies two, so build two and note in the docstring that
   the second hop is fidelity, not necessity.

   The integrity question Alg. 5 never asks: how does SYS_i know the restored
   data matches what it backed up? The chain proves the transaction wasn't
   altered; nothing verifies plaintext round-trip. Add a payload digest taken
   before encryption and checked after decryption. DEV entry — this is a gap
   in the paper, not a detail of ours.

TESTS
Backup N systems, wipe one, restore, assert byte-identical. Multi-block
backup reassembles. Restore with blocks arriving out of order. Index and
cold-scan agree. One system cannot recover another's backup — session keys
should make this impossible, so assert it. Tampered ciphertext caught at
restore, not silently returned. Payload digest mismatch detected.

Map to §V-1 and §V-5 in the session file.

EXIT CONDITION
make test and make lint green. A system's data survives a simulated full wipe
and returns byte-identical, through consensus, on BC_DTBU.

OUT OF SCOPE
No honeypot, no signatures, no features, no ML, no mitigation, no bench.
If Phase 1 seems to need a ransomware concept, it doesn't — Phase 1 runs
before any infection exists.

END OF SESSION
Session file with attribution and dead ends. DEV entries for the payload
digest and the chunking decision. Note whether D3 (bus doesn't serialize)
affects anything here. Rewrite PROJECT_STATE.md, under 200 lines. Tick M3a
and record the split. Commit explaining why.
```

---

## What was done

**Attribution.** All new code, tests and doc text in this session are **AI-generated (Claude,
Opus 5), human-directed**. The prompt specified these: the M3a/M3b split, the six modules, the
factored pipeline, explicit chunk sequence numbers, the two hops, the requirement for a payload
digest and its DEV entry, and the test list. These are Claude's: the attestation *signature* on
the digest, the key-holder index, `crypto/channel.py`, the `f+1` commit rule, derived
`backup_id`/`tx_id`, the paper-shaped defaults, `consensus.client_wait_timeouts`, and
`Chain.verify_block`. No file was human-edited this session.

**New modules**

| Module | What it does |
|---|---|
| `crypto/channel.py` | `Channel`/`Envelope`: AES-256-GCM under `SK`. The AAD binds session, sender, recipient, purpose and a counter. The counter advances only after the tag verifies |
| `blockchain/backup.py` | `payload_digest`, `BackupManifest`, `attest`, `split`, `reassemble`, `verify_restored`, `chunk_tx_id`, `pack`/`unpack`. The DEV-23/24 contract |
| `framework/entities.py` | `Participant`, `System`, `CloudServer`, `establish_session` |
| `framework/_block_pipeline.py` | `run(cluster, items, builder, chain=..., policy, timestamp)`, `batch`, `commit`, `read_chain`, `PipelinePolicy`. Uses the pBFT client rule (`f+1` holders) |
| `framework/phase1_backup.py` | Alg. 1: `collect`, `backup_transactions`, `run` (optionally syncs the key holder's index) |
| `recovery/locator.py` | `scan`, `BackupIndex` (`on_append`, `sync`, `lookup`, anchor-checked rebuild), `identify`, `RecoveryError` |
| `recovery/restore.py` | Alg. 5: `request`/`accept_request`, `begin`, `request_decrypt`, `transfer`, `deliver`, `open_delivery` |
| `framework/phase5_recovery.py` | Alg. 5 end to end, `RecoveryReport`. Skips the fidelity hop when one server holds both roles |

**Changed**

| File | Change |
|---|---|
| `blockchain/transaction.py` | `BackupPayload` gains `chunk_index`, `chunk_count`, `payload_digest`, `attestation`, with paper-shaped defaults; encodes all seven fields |
| `blockchain/chain.py` | `verify_block(height)` added; `verify_integrity` calls it (same checks, same messages as M2a) |
| `crypto/hashing.py` | four backup domains: payload, attestation, id, tx_id |
| `configs/chain.yaml` | `consensus.client_wait_timeouts: 32`, DECLARED |
| `tests/unit/test_transaction.py` | the wrong-field-type test now supplies all seven fields, so it still tests the type check |
| `tests/unit/test_module_boundaries.py` | +2 rules: nothing below `framework` imports it; `crypto` depends only on `util` |
| docs | DEVIATIONS (DEV-23, -24, -25 opened; DEV-05, DEV-20 item 5 amended); PAPER_NOTES (GAP-8); NOTATION (`CS'_l`, `KU_SYSi`, digest, attestation); ALGORITHMS (Alg. 1, 2, 5 rows now name real code; line 3's non-existent `Block.assemble()` removed); ARCHITECTURE (`channel`, `backup`, `framework/` section, recovery rewritten); ROADMAP (split, M3a ticked) |

**Tests: 618 → 831 unit (+213 including parametrised cases), plus 9 integration (840 under
`make test-all`).** New files: `test_channel.py`, `test_backup_chunks.py`, `test_block_pipeline.py`,
`test_backup_index.py`, `test_restore.py`, `test_entities.py`, `test_phase1_backup.py`,
`test_chain_verify_block.py`, harness `m3a_harness.py`, and `tests/integration/test_backup_recovery.py`
with a `conftest.py` that puts the unit harnesses on the path.

Where each required test lives:

| Required | Test |
|---|---|
| backup N, wipe one, restore, byte-identical | `integration/test_backup_recovery.py::test_a_wiped_system_returns_byte_identical_through_consensus` (configured sizes, 4 systems, pBFT); `test_restore.py::test_a_wiped_system_is_restored_byte_identical_over_two_hops` |
| multi-block backup reassembles | the integration test above (201 chunks over 3 blocks); `test_phase1_backup.py::test_a_backup_larger_than_a_block_spans_blocks` |
| blocks arriving out of order | `integration/...::test_restore_when_consensus_commits_the_chunks_out_of_order` (batches submitted in reverse through pBFT; chunk 0 at height 3, chunk 200 at height 1); `test_restore.py::test_restore_with_chunks_committed_in_reverse_order`; `test_backup_chunks.py::test_reassembly_is_independent_of_arrival_order` (10 seeds) |
| index and cold scan agree | `test_backup_index.py::test_index_and_cold_scan_return_identical_locations` (5 systems incl. none); `integration/...::test_index_and_cold_scan_agree_on_the_committed_chain` |
| one system cannot recover another's | `test_restore.py::test_a_request_to_recover_another_system_is_refused`, `::test_the_recovery_request_is_bound_to_the_requesters_session`, `::test_the_front_server_will_not_deliver_to_another_system`, `::test_an_intercepted_delivery_does_not_open_for_another_system` |
| tampered ciphertext caught at restore | `test_restore.py::test_tampered_ciphertext_is_caught_at_restore` (stale and recomputed digest × scan and index; `SYS_i` stores nothing) |
| payload digest mismatch detected | `test_restore.py::test_a_payload_changed_between_the_hops_fails_the_digest_check`; `::test_a_server_that_rewrites_data_and_digest_fails_the_attestation` |

**Not done:** no mutation check this session. M2b killed 15 safety mutants; M3a's tests have not
been mutated. The obvious candidates are dropping the attestation check in `verify_restored`,
ordering by height in `reassemble`, and skipping the anchor check in `BackupIndex.sync`.

## Findings

**§V-1 mapping: session keys at the two places Phases 1 and 5 use them**

| §V-1 property | Status after M3a | Tests |
|---|---|---|
| Replay resistance | **Substantiated inside a session**, not only at establishment (M1). A replayed envelope is refused, and a forged one cannot burn the counter. | `test_channel.py::test_a_replayed_envelope_is_rejected`, `::test_a_forged_envelope_does_not_burn_the_counter` |
| MITM / session binding | **Substantiated.** Envelopes do not open in another session, under a third party's key, or re-labelled. | `test_channel.py::test_an_envelope_from_another_session_does_not_open`, `::test_a_third_party_holding_its_own_session_cannot_open_it`; `test_restore.py::test_an_intercepted_delivery_does_not_open_for_another_system` |
| Impersonation | **Substantiated at both phases.** A backup in another system's name is refused at `CS_l`; so is a recovery request for another system, or a stolen one. | `test_entities.py::test_a_system_cannot_back_up_in_another_systems_name`, `::test_a_backup_attested_with_the_wrong_key_is_refused`; `test_restore.py::test_a_request_to_recover_another_system_is_refused`, `::test_the_recovery_request_is_bound_to_the_requesters_session` |
| (not claimed by §V-1) reflection, cross-step reuse | Refused. | `test_channel.py::test_a_message_reflected_to_its_sender_does_not_open`, `::test_a_message_for_one_step_cannot_be_opened_as_another` |
| **What §V-1 cannot give** | Session keys protect bytes *in transit*. §IV-E's two servers hold plaintext at rest between hops, and nothing in §V addresses them. That is GAP-8, closed by DEV-23's attestation. | `test_restore.py::test_a_server_that_rewrites_data_and_digest_fails_the_attestation` |

**§V-5 mapping: two chains isolate detection from recovery**

| §V-5 sub-claim | Status after M3a | Tests |
|---|---|---|
| Recovery reads only `BC_DTBU` | **Substantiated structurally.** `identify`, `BackupIndex.sync` and `request_decrypt` refuse any chain not named `BC_DTBU`. | `test_backup_index.py::test_backups_are_only_looked_for_on_bc_dtbu` |
| Backup writes cannot land on the other chain | **Substantiated.** The pipeline refuses a cluster whose chain is not the one named, and sends nothing. | `test_block_pipeline.py::test_payloads_are_refused_by_the_other_chains_cluster` |
| Compromising detection does not reach recovery (the claim's point) | **Not yet testable.** It needs Phase 2–3 on `BC_SigRW`. Also note that the isolation is by construction (separate `Cluster`s, separate replica keys) plus a *name* check, not a cryptographic separation. A `Chain` object named `BC_DTBU` is trusted as such. | M3b/M4 |

**Does D3 (the bus doesn't serialise) affect M3a?** In two places, and no M3a claim depends on
either:

1. Replicas share `Block` objects by reference. A storage-corruption test therefore has to
   *replace* a block in one chain's list; mutating the object would corrupt every replica at once.
   `m3a_harness.tamper_ciphertext` does the replacement, and its docstring says why.
2. Nothing on the bus is ever encoded, so the wire size of a backup is measured nowhere. That is
   relevant to GAP-2 / M7's storage question, and to Target 3 as D3 already records. Channel
   envelopes are Python objects too, but AEAD covers their byte fields, so the tamper tests on
   them are meaningful.

**Framing is not free.** Measured for one 4096-byte chunk: 215 bytes of plaintext framing (112 of
them in the paper-shaped record already, 103 from M3a's fields), then 161 bytes of DEV-01
encryption overhead. This is recorded in DEV-24, so M6's payload-size sweep can say what it varies.

**Dead ends and corrections**

- ***A false "M2a hole", caught before commit.*** While designing the tamper tests I reasoned that
  `MTR` covers only `Transaction.digest` fields, so a ciphertext altered with its digest left
  alone would keep the root, `HC_βj` and the signature. I added a per-transaction
  `verify_digest()` loop to `Chain.check_append` and `verify_integrity`, and started writing it up
  as an M2a finding. The tests written to pin the "hole" failed: `dataclasses.replace(block, ...)`
  raised `BlockError` on signature verification. `Block._hashed_fields()` carries
  `[tx.encoded() for tx in transactions]`, so both `HC_βj` and `Sig_βj` cover every transaction's
  full encoding, ciphertext included, and M2a's `block.py` docstring says so. There was never a
  hole. **Reverted:** the loop was redundant, and it was per-transaction hashing on every replica
  inside Target 3's measured span. `Chain.verify_block` kept M2a's three checks, and
  `test_chain_verify_block.py` now pins the *correct* behaviour so the next person who reasons
  from `MTR` alone does not redo this. PROJECT_STATE carries a "do not re-add" line.
- *The pipeline's first wait loop ran `cluster.run(until=now + tick)` unconditionally.* That
  advances the simulated clock to `now + tick` even when every commit happened at `now`, which is
  phantom modelled latency of exactly the kind DEV-21 says M6 reads. The loop now drains the
  current instant first and stops as soon as everything is committed.
  Pinned: `test_a_zero_delay_run_leaves_no_phantom_simulated_time`.
- *The duplicate-batch check first ran after submission.* pBFT deduplicates identical requests, so
  the second would never commit and the wait would run to its deadline. It now runs before
  anything is sent.
- *Two hand-driven restore tests failed with "no session".* In
  `front.channel(key_holder.identity).open(_up_to_transfer(world), ...)`, Python evaluates
  `front.channel(...)` before the argument that establishes the session. This was a test bug, not
  a code bug; the tests now call `_up_to_transfer` first.
- *DEV-25's first wording* said that with one server the first hop "carries data from a server to
  itself". `crypto.session` refuses a session with oneself, so the hop is *skipped*. Corrected
  before commit.
- *Rejected: chunk framing inside `BackupPayload.data`.* That would have double-framed the record
  and duplicated `system_id`/`captured_at`; extending `BackupPayload` with defaulted fields was
  cleaner.
- *Rejected: passing `CloudServer` into `recovery/`.* It would have broken the dependency direction;
  recovery takes a `Decryptor` and `Channel`s instead.
- *Rejected: a digest without a signature.* Both servers on the way back could recompute it; see
  DEV-23.

## Numbers

No benchmark this session, by instruction, and `RESULTS.md` is untouched. There are structural
facts only, none of them timings and none of them for quoting as results: 215 B of chunk framing
and 161 B of encryption overhead per 4096-byte chunk (DEV-24). The configured-size integration
test commits 206 transactions in 3 blocks. Suite wall-clock is about 4 s (unit) and 5.5 s (all).
None of these has a run_id or a sidecar.

## Deviations opened or changed

- **DEV-23** opened (FILL): `SYS_i` attests a payload digest before shipping and verifies it after
  the last hop. The paper-shaped record is refused. Closes GAP-8.
- **DEV-24** opened (FILL): chunking with explicit `chunk_index`/`chunk_count`; the remainder and
  the empty-backup rule; the measured framing overhead.
- **DEV-25** opened (FILL): `CS'_l` is the key holder; the first hop is fidelity and is skipped
  with one server.
- **DEV-05** amended: only the key holder can build the index; the cost moves to append time; the
  anchor-checked rebuild.
- **DEV-20** item 5 amended: wired for backups (session + attestation), not for `ClientRequest`,
  which is carried as debt D4.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** Phases 1 and 5 work end to end through pBFT on `BC_DTBU`. The block pipeline
exists and is chain-agnostic, and Phase 2 needs only a payload builder. Sessions carry data through
`crypto.channel`. Recovery verifies every block it reads and every byte it returns. `make test`
runs 831 tests, `make test-all` 840, and `make lint` is clean.

**Next task:** Build M3b, Phase 2 on `BC_SigRW`. First `honeypot/collector.py` + `preprocess.py`
(Alg. 2 lines 1–4, synthesized feature records only, never executable code), then
`honeypot/signatures.py` + `features.py` (Alg. 2 lines 5–6, DEV-03's two-sense `Sig_RW` and
7-group `FT_RW` per `docs/ARCHITECTURE.md` §honeypot), then `framework/phase2_collection.py`
(Alg. 2) as a payload builder over `framework._block_pipeline.run` with no change to the pipeline.
Exit when signature records land on `BC_SigRW` through consensus and decrypt to exactly what was
built. If the feature design and the phase wiring do not fit one session, split them first and
say so.

**New blockers:** none.

**Questions opened / closed:** none opened or closed. Q2's row now carries DEV-24's measured
framing. **Debt D4 opened:** `ClientRequest` is still unauthenticated (DEV-20 item 5 remainder).
D3 was re-examined: it affects M3a's tamper tests and backup-size accounting, and no claim.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended — **not applicable**, no benchmark was run, by instruction
- [x] `docs/ROADMAP.md` boxes ticked — split recorded, M3a `[x]`, current milestone → M3b
- [x] `docs/DEVIATIONS.md` updated — DEV-23, -24, -25 opened; DEV-05, DEV-20 amended
- [x] Committed, message explains *why*
