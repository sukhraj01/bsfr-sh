# Session 2026-09-11-02 — M2a, blockchain data structures

**Milestone:** M2a · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/ARCHITECTURE.md` (§blockchain), `docs/NOTATION.md`, `docs/ALGORITHMS.md` (Alg. 1–2, per
CLAUDE.md §4b), `sessions/_TEMPLATE.md` · **Duration:** one working session

Per the context ladder, `docs/EXPERIMENTS.md` and `docs/PAPER_NOTES.md` were **not** read.

---

## Brief *(written before any work)*

**Task:** Build `blockchain/transaction.py`, `block.py` and `chain.py` — the paper's data
structures only, with a two-type seal so a block cannot exist whose hash fails to cover its
contents — and retire debt D1 first so `crypto.hashing` is again the only `hashlib` importer.

**Exit condition:** `make test` and `make lint` both exit 0; both `BC_DTBU` and `BC_SigRW` build
15 blocks × 100 transactions by direct single-node append with no consensus involved; `hashlib`
has exactly one importer in `src/`; Q2 is closed or explicitly deferred with a reason in
`PROJECT_STATE.md`.

**Out of scope:** no pBFT, no leader election, no message bus, no byzantine nodes, no network
simulation — all M2b. Where append needs "who proposed this", it is a parameter, not a node
abstraction. No honeypot, no ML, no benchmark harness.

**Prior context needed:** `docs/ARCHITECTURE.md` §blockchain for the header field order and the
validation order; `docs/NOTATION.md` for `β_j`, `MTR`, `HC_βj`, `HP_βj-1`, `OID`, `OKU`,
`Sig_βj`, `RN`; `docs/ALGORITHMS.md` Alg. 1 lines 2–3 and Alg. 2 lines 7–8 for the two payload
builders and the assemble step; `util.serialization`'s `BLOCK_FIELD_ORDER`,
`TRANSACTION_FIELD_ORDER` and `BlockPart`, which already declare the encoding this must match.

**Pre-flight (STEP 0):** retire D1. Move `config_hash()` / `combined_config_hash()` into
`crypto.hashing`, drop the `config_hash` field from `Config`, update the M0 tests that pin the
dataclass, and remove `util/config.py` from `HASHLIB_ALLOWED`. Then version the sidecar format
and backfill the existing Q1 sidecar, whose `config_hash` was computed under the pre-
domain-separation construction and will not reproduce under the new one — M6 must not read that
as config drift.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/ARCHITECTURE.md
and docs/NOTATION.md. Not docs/EXPERIMENTS.md.

Create the session file from the template and fill the brief first.

Note: M2 is being split. This is M2a, blockchain data structures only.
Consensus is M2b. Update docs/ROADMAP.md to reflect the split as part of
this task.

STEP 0 — retire D1.
Move config_hash() into crypto.hashing, drop the field from Config, and have
bench/scripts compose the two. Remove util/config.py from HASHLIB_ALLOWED so
crypto/hashing.py is once again the only hashlib importer, as CLAUDE.md §7
requires. The M0 tests pinning the Config dataclass change with it.

Then: the existing Q1 sidecar in results/logs/ carries a config_hash under
the old construction. Once the new one is domain-separated, that value no
longer reproduces from the same config. Add a scheme version to the sidecar
format and backfill the existing one, so M6 doesn't read the mismatch as
config drift.

TASK — M2a. Transaction, Block, Chain under src/bsfr_sh/blockchain/.

1. transaction.py
   Frozen dataclass per docs/ARCHITECTURE.md: tx_id, payload_type, ciphertext,
   wrapped_key, nonce, digest, created_at. Encryption goes through M1's kem +
   aead — this is DEV-01 in use, including the mutual AAD binding you added.
   Two payload builders: BackupPayload (Alg. 1 line 2) and the signature
   record (Alg. 2 line 7). Same pipeline, different payload.

   Q2 (payload size) gets closed here or explicitly deferred with a reason.
   The paper never specifies it, and Fig. 6 timings depend on it — an
   unrecorded default silently determines Target 3.

2. block.py
   Header field order exactly as Alg. 1 line 3 / Alg. 2 line 8, matching what
   serialization.py already encodes.

   The structural trap: current_hash and signature are header fields computed
   over the other header fields. Do not build one dataclass that contains its
   own digest. Use two types — an unsealed draft, and a sealed Block produced
   by seal() — so it is impossible to construct a Block whose hash doesn't
   cover its contents. Make the illegal state unrepresentable rather than
   checked.

   State explicitly in the docstring what Sig_β covers. Signing current_hash
   is fine if current_hash provably covers every other field; signing a subset
   is a hole. Whichever you choose, write it down — §V's tamper-resistance
   claim rests on it.

   RN (random nonce) is in the paper's header. Under PoW it's the mining
   nonce; under pBFT there is nothing to mine, so it has no consensus role.
   Keep the field for fidelity, and document in the docstring that it is
   inert — otherwise someone in M2b sees a nonce field and implements a
   proof-of-work loop around it.

3. chain.py
   Genesis, validated append, integrity walk, iteration. Validation order per
   docs/ARCHITECTURE.md: prev_hash linkage, Merkle root recomputation,
   current_hash recomputation, ECDSA verify under owner_pubkey, timestamp.

   Two things to get right:

   Timestamp validation. The paper implies monotonicity, but blocks come from
   different cloud servers with independent clocks, so strict monotonicity
   will reject honest blocks under normal skew. Use non-decreasing with a
   tolerance, and reuse the same configured skew window as session.py rather
   than introducing a second clock-tolerance constant.

   Chain independence. BC_DTBU and BC_SigRW must share no state whatsoever.
   The failure mode is mundane and silent: a mutable class attribute, a
   mutable default argument, a module-level registry, or a cached genesis.
   Write the test that builds both chains, appends only to one, and asserts
   the other is untouched — including its length, head, and any internal
   index. That test substantiates §V-5, which the paper claims and never
   demonstrates.

TESTS
Round-trip through encrypt/append/read. Tampered transaction rejected.
Tampered header field rejected — parametrize over every header field
individually, not just one. Reordered transactions change MTR. Broken
prev_hash linkage rejected. Wrong signer rejected. Clock skew inside
tolerance accepted, outside rejected. Chain independence as above.

Map the tests to §V-4 and §V-5 in the session file.

EXIT CONDITION
make test and make lint green. Both chains build 15 blocks × 100 transactions
via direct single-node append — no consensus involved. D1 retired; hashlib
has exactly one importer again.

OUT OF SCOPE
No pBFT, no leader election, no message bus, no byzantine nodes, no network
simulation. If append needs a "who proposed this" concept, take it as a
parameter; don't build the node abstraction. That's M2b.

END OF SESSION
Session file with attribution and dead ends. Close or defer Q2 in
PROJECT_STATE.md with reasoning. Retire D1, note D2 status. Rewrite
PROJECT_STATE.md, under 200 lines. Tick M2a and record the M2 split in
ROADMAP. Commit explaining why.
```

---

## What was done

All new files are **AI-generated, human-directed** — the task, the M2 split, the two-type seal,
the skew-tolerance requirement and the independence test were specified in the prompt; the
implementations and tests are Claude's.

**STEP 0 — D1 retired**

| File | Change |
|---|---|
| `crypto/hashing.py` | gained `config_hash()`, `combined_config_hash()`, `CONFIG_HASH_SCHEME` |
| `util/config.py` | lost the `hashlib` import, both hash functions, and the `config_hash` field on `Config` |
| `tests/unit/test_config.py` | composes the layers via a `hash_of(cfg)` helper; new `test_config_carries_no_digest_field` |
| `tests/unit/test_module_boundaries.py` | `HASHLIB_ALLOWED = {"crypto/hashing.py"}` |
| `scripts/bench_ecdsa_backends.py`, `configs/bench.yaml` | sidecars carry `config_hash_scheme` |
| `results/logs/20260910T213021Z-f07b5fbf.json` | backfilled with `config_hash_scheme: 1` and a note |

**`src/bsfr_sh/blockchain/` (3 modules, all new)**

| Module | What it does | Notable |
|---|---|---|
| `transaction.py` | `Transaction`, `BackupPayload`, `SignatureRecordPayload`, one `encrypt()` with two builders | `digest` is derived, never supplied; encryption goes only through `crypto.kem.seal_payload` |
| `block.py` | `BlockDraft` -> `seal()` -> `Block` | `merkle_root` and `current_hash` are cached properties, not fields; signature verified in `__post_init__` |
| `chain.py` | `Chain`, `ChainPolicy`, genesis/append/walk/iterate | `__slots__`, per-instance state only, skew tolerance read through `SessionPolicy` |

**Tests (7 new files, 107 tests; suite 358 -> 465)** — `test_transaction.py` (16),
`test_tx_confidentiality.py` (7), `test_block.py` (22), `test_block_tamper.py` (24),
`test_chain.py` (23), `test_chains_independent.py` (12), `test_chain_scale.py` (3).

**Also changed** — `docs/ARCHITECTURE.md` §blockchain (two block types, what `Sig_βj` covers,
`RN` inert, timestamps); `docs/DEVIATIONS.md` (DEV-17, DEV-18); `docs/ROADMAP.md` (M2 split,
M2a ticked, current milestone -> M2b).

## Findings

**D1 came out clean, and the shape of the fix was the one M1 predicted.** Moving `config_hash()`
into `crypto.hashing` touched six files and broke nothing structural. The `Config` dataclass
losing a field was the only invasive part, and it turned out that only four assertions in
`test_config.py` actually read `cfg.config_hash`; the rest tested loading and validation, which
did not move. `combined_config_hash()` changed signature from `Iterable[Config]` to
`Mapping[str, str]` so that `crypto` need not know what a `Config` is — which also moved the
"two configs of one kind" guard to `load_configs`, where it can name both paths.

**The Q1 sidecar had `config_hash: null`, so there was no stale value to reconcile.** That run
had no governing config file. The scheme field was added and backfilled anyway: the hazard is
real for M6's first sidecar carrying an actual digest, and adding the field after figures exist
costs far more than adding it now. Recorded as DEV-18 with the nuance stated rather than implied,
so nobody later reads the backfill as having fixed a live mismatch. Confirmed the construction
really did change: `configs/chain.yaml` hashed to `4a7f2612...` under scheme 1 and `3bbdea06...`
under scheme 2, with the file untouched.

**Deriving the digests instead of storing them is what made "unrepresentable" real.** The first
design had `Block` storing all ten header fields with a `__post_init__` that recomputed and
compared — which is *checked*, not unrepresentable, and the prompt asked for the stronger thing.
Making `merkle_root` and `current_hash` `cached_property` computations over the stored fields
removed the constructor argument through which a wrong value could arrive at all. What remains
stored is `signature`, which genuinely cannot be derived without the private key, so it is
verified at construction instead. The honest summary: the hash half is unrepresentable, the
signature half is checked-once-at-construction, and the two-type split means an *unsealed* block
has neither field to get wrong.

That also made the tamper sweep sharper than planned. There are two distinct tamper routes, not
one — in-memory (stored fields only, caught by the signature check) and on-the-wire (all ten,
caught by `from_fields` recomputation) — so `test_block_tamper.py` parametrizes over both.

**The `RN` warning earned its place immediately.** Writing `block.py` I reached for
`secrets.token_bytes` for the nonce and briefly wondered whether `Chain.append` should check
anything about it. It should not, and the answer is only obvious if you already know the paper
uses pBFT rather than PoW. The docstring now says so at length, and it is also a risk row in
`PROJECT_STATE.md` and a paragraph in `docs/ARCHITECTURE.md` — three places, because the cost of
someone adding a mining loop in M2b is a Fig. 6 that measures an invented difficulty setting.

**Chain independence: the mechanisms, not just the symptom.** The prompt asked for the
build-both-append-to-one test, which is in `test_chains_independent.py` and checks length, head,
transaction count, block hashes and the private `_index`. Four more tests rule out the specific
mechanisms directly — no mutable class attribute, `__slots__` pinned, no module-level mutable
state in `blockchain.chain`, and two default-constructed chains not sharing a `ChainPolicy`
object. The symptom test would pass today even if a registry existed but happened to be keyed
correctly; the mechanism tests fail the moment one is added.

**Dead ends and small corrections**

- *A bulk regex rewrite to satisfy ruff's RUF043 broke three M0 tests.* Converting `match="..."`
  to raw strings across the whole test tree also converted patterns that were already correctly
  escaped, doubling their backslashes, so `"not 2f\\+1"` stopped matching. Caught by the full
  suite immediately. Fixed by hand. The lesson is the ordinary one: a regex applied to every file
  in a tree needs to be checked against the files that were already right.
- *`test_integrity_walk_detects_an_in_place_mutation` asserted the wrong error.* Duplicating a
  block in `_blocks` trips the hash-index check before the linkage check, because the index is
  walked first. The test was asserting on the linkage message. Rather than loosen the match, it
  was split into three — duplicated block, broken linkage with the index kept consistent, and a
  genesis with a non-zero `prev_hash` — so each check is exercised on its own.
- *`Chain.append`'s step 3 does not recompute `current_hash`.* It cannot: `current_hash` is
  derived, so there is nothing to disagree with. The step is a duplicate-block check instead, and
  the docstring says explicitly that checks 2–4 are already guaranteed by the `Block` type and are
  re-asserted because `append` is where a block from M2b's network will arrive.
- *No `RESULTS.md` line this session.* The case-3 build is a correctness test, and timing it
  before consensus exists would produce a number that changes the moment M2b lands. Recording it
  would have meant a `measured` row that nothing later reproduces.

**§V claim -> test mapping**

| §V claim | Test |
|---|---|
| §V-4 data manipulation — block header | `test_block_tamper.py::test_tampering_with_any_stored_header_field_is_rejected` and `::test_tampering_with_any_header_field_on_the_wire_is_rejected`, both parametrized over every field in `BLOCK_FIELD_ORDER` |
| §V-4 data manipulation — transactions | `test_block_tamper.py::test_reordering_transactions_changes_the_merkle_root`, `::test_reordered_transactions_invalidate_the_signature`, `::test_substituting_a_transaction_is_rejected`, `::test_tampering_with_a_transaction_inside_a_block_changes_mtr` |
| §V-4 data manipulation — chain linkage | `test_block_tamper.py::test_broken_prev_hash_linkage_is_rejected`, `::test_a_block_signed_by_the_wrong_owner_is_rejected_on_append`, `test_chain.py::test_integrity_walk_detects_broken_linkage` |
| §V-4 leakage / confidentiality | `test_tx_confidentiality.py` (whole file) — only `CS_l` decrypts; a recomputed digest does not rescue a tampered ciphertext; a wrapped key cannot be moved between transactions |
| §V-5 chain separation | `test_chains_independent.py` (whole file) — the append-to-one test plus four tests ruling out the specific sharing mechanisms |
| Scale, both chains | `test_chain_scale.py::test_both_chains_build_case_3_and_stay_independent` |

§V-1 was covered in M1. §V-2 and §V-3 need consensus and a membership model — M2b and M3.

## Numbers

No benchmark this session; see the dead-ends note above. The only figures worth recording are
structural: 465 tests total, 107 of them new, full suite 1.68 s including the two case-3 builds
(1500 transactions each) at roughly 5,200 hybrid encryptions per second on the dev box. That rate
is an observation from the test run, not a measurement — it has no run_id and no sidecar, so it
does not go in `RESULTS.md` and must not be quoted as a result.

## Deviations opened or changed

- **DEV-17** opened (FIX) — block timestamps are non-decreasing within a tolerance rather than
  strictly monotonic, because blocks come from cloud servers with independent clocks and strict
  monotonicity rejects honest blocks under ordinary skew. The tolerance is the same configured
  value `crypto.session` uses, not a second constant.
- **DEV-18** opened (ADD) — the config-hash construction is versioned, and sidecars record
  `config_hash_scheme`, so the M2a change of construction is never read as config drift.
- No existing entries amended. DEV-01 and DEV-11 are now *used* by `blockchain/` as written.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** `blockchain/` is complete and is what M2b's consensus layer will commit blocks
into. `make test` runs 465 tests (107 new) and `make lint` — ruff check, ruff format --check,
`mypy --strict` — is clean. Both chains reach 15 blocks x 100 transactions by direct append with
no consensus involved. `hashlib` has exactly one importer in `src/`. `docs/ROADMAP.md` records the
M2a/M2b split.

**Next task:** Build `consensus/` — `network.py` (in-process P2PCS message bus) and `pbft.py`
(pre-prepare / prepare / commit at `2f+1` of `n=3f+1`, view change on leader timeout, per DEV-10)
— with byzantine fixtures for silent, equivocating, wrong-signature and stale-view nodes, keeping
block validation in `Chain.append` rather than moving it into the protocol; exit when both chains
build 15 blocks x 100 tx with 4 nodes and `f=1` tolerated.

**New blockers:** none.

**Questions opened / closed:** **Q6 closed** — no per-transaction signature; `Sig_βj` plus `MTR`
plus the DEV-01 binding is sufficient, and a second signature would add 100 ECDSA operations per
block to every Fig. 6 timing. **Q2 deferred deliberately**, with the closeable part closed: the
payload size is read from config everywhere and pinned by a test, so M6's sweep will actually
move it; justifying the value itself needs that sweep. **Q7 opened** — does a pBFT pre-prepare
carry the whole block or just its `current_hash`?

**Debt:** **D1 retired.** D2 unchanged — `make lint` still does not cover `scripts/`.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines — 142
- [x] `RESULTS.md` appended — **not applicable this session**, no benchmark was run; reasoning in
      Findings and in Numbers above
- [x] `docs/ROADMAP.md` boxes ticked — M2 split into M2a `[x]` / M2b `[ ]`, milestone -> M2b
- [x] `docs/DEVIATIONS.md` updated — DEV-17 and DEV-18 opened
- [x] Committed, message explains *why*
