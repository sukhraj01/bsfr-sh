# Session 2026-09-11-01 — M1, the crypto layer

**Milestone:** M1 · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/ARCHITECTURE.md` (§crypto), `docs/NOTATION.md`, `sessions/_TEMPLATE.md`, plus
`docs/DEVIATIONS.md` DEV-01/02/11 (departing from the paper) and `docs/EXPERIMENTS.md` Target 5
mapping table only · **Duration:** one working session

Per the context ladder, `docs/PAPER_NOTES.md` and the rest of `docs/EXPERIMENTS.md` were **not**
read.

---

## Brief *(written before any work)*

**Task:** Build the six `crypto/` modules — `hashing`, `merkle`, `ecdsa`, `aead`, `kem`,
`session` — with domain-separated hashing, count-bound Merkle roots, deterministic ECDSA,
nonce-safe AEAD, ciphertext-bound key wrapping and a replay-resistant session protocol, and close
Q1 by benchmarking the ECDSA backends.

**Exit condition:** `make test` and `make lint` both exit 0; every §V-1 property
(replay, MITM, impersonation, illegal session key) has a passing test; Q1 is closed in
`PROJECT_STATE.md` with the benchmark numbers that decided it, and those numbers are in
`RESULTS.md` with `mode=measured`.

**Out of scope:** no `Block`, `Transaction`, `Chain` or pBFT — M2. `crypto/` imports from `util/`
and nothing else internal; where a test wants a block it gets raw bytes instead. No honeypot, no
ML, no benchmarks other than the Q1 ECDSA throughput measurement.

**Prior context needed:** `docs/ARCHITECTURE.md` §crypto for the module table and the session
sketch; `docs/NOTATION.md` for `KU_CSl`, `SK_{E_A,E_B}`, `MTR`, `Sig_βj`; `docs/DEVIATIONS.md`
DEV-01 (hybrid encryption), DEV-02 (session protocol), DEV-11 (Merkle odd-node policy) — all
three are amended by this session; `docs/EXPERIMENTS.md` Target 5 for the §V-claim → test map.

**Pre-flight (STEP 0):** verify the M0 canonical encoding is byte-identical across *separate
interpreter processes*, not merely twice in one process. Every hash in this project is downstream
of it. If it turns out to depend on dict insertion order or `PYTHONHASHSEED`, stop and report.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder says this task reads
docs/ARCHITECTURE.md (§crypto) and docs/NOTATION.md. Do not read
docs/EXPERIMENTS.md or docs/PAPER_NOTES.md.

Create sessions/2026-09-11-01-m1-crypto-layer.md from the template and fill
the brief before writing code. (Match the date convention M0's session file
used.)

STEP 0 — verify the M0 assumption before building on it.
Write one throwaway check that util/serialization.py produces byte-identical
output for the same logical input across two separate interpreter processes,
not just twice in one process. If it uses json.dumps under the hood, or
anything whose ordering depends on dict insertion or PYTHONHASHSEED, stop and
report before continuing. Every hash in this project is downstream of this.

TASK — M1, the crypto layer. Six modules under src/bsfr_sh/crypto/.

1. hashing.py
   h(bytes) -> bytes, SHA-256. The single hashing entry point for the whole
   project; nothing else may import hashlib. Add domain separation: hashing a
   transaction, a block header, and a Merkle node must use distinct prefixes,
   so a value valid in one position can never be reinterpreted in another.

2. merkle.py
   Binary tree over transaction digests, root plus inclusion proofs. DEV-11
   specifies Bitcoin-style duplication of the last hash on odd node counts.

   Implement that, then handle its known consequence: last-hash duplication
   means two different transaction lists can produce an identical root (the
   CVE-2012-2459 shape — a list of N and that list with its final element
   repeated collide). Since MTR is what binds a block to its contents, that
   collision is a real integrity hole in the paper's design, not a
   theoretical one. Fix it by binding the transaction count into the root
   computation, keep DEV-11's stated construction, and record the fix as an
   amendment to DEV-11 with the reasoning. This is exactly the kind of gap
   docs/DEVIATIONS.md exists for.

3. ecdsa.py
   secp256r1 keygen, sign, verify. Use RFC 6979 deterministic nonces if the
   backend supports it — nonce reuse is the standard way ECDSA implementations
   leak private keys, and deterministic signing also makes our tests
   reproducible.

   This is where Q1 gets closed. Benchmark sign and verify throughput for the
   `cryptography` backend against a pure-Python alternative (`ecdsa` package).
   Decide on the numbers and log both to RESULTS.md with mode=measured.
   Do not decide on preference. Fig. 6 timings are downstream of this choice,
   so a slow backend contaminates every later benchmark.

4. aead.py
   AES-256-GCM. Nonces must be unique per key — generate, never accept a
   caller-supplied nonce, and make nonce reuse structurally impossible rather
   than documented as forbidden.

5. kem.py
   ECIES-style wrapping: ephemeral ECDH to KU_CSl, KDF to an AES key, wrap the
   data key. This is DEV-01, our hybrid replacement for the paper's
   E_KU_CSl(Tx).

   Bind the wrapped key to the ciphertext it protects — pass the wrapped key
   and the transaction metadata as AEAD associated data. Without that binding
   an attacker can swap a wrapped key from one transaction onto another, which
   would defeat the confidentiality claim in §V-4 while every signature still
   verifies.

6. session.py
   DEV-02: ECDH over secp256r1 with an ECDSA-signed transcript, nonces and
   timestamps. docs/ARCHITECTURE.md §crypto sketches it as:

     A -> B : ID_A, N_A, TS_A, g^a, Sig_A(ID_A || N_A || TS_A || g^a)
     B -> A : ID_B, N_B, TS_B, g^b, Sig_B(ID_B || N_B || TS_B || g^b || N_A)

   That sketch has a flaw I introduced when I wrote it — fix it rather than
   implementing it as written. A's signed message does not bind ID_B, so a
   captured first message can be replayed to a different cloud server, which
   will accept it as a genuine session opening from A. Bind the intended
   responder identity into A's signature.

   Also: a timestamp window alone does not give replay protection, it only
   bounds the replay interval. §V-1 explicitly claims replay resistance, so
   add a seen-nonce cache with an eviction horizon at least as long as the
   accepted clock skew. Reject on replay, and test that path.

   Make the skew window configurable via configs/, defaulting to 30s.

TESTS
Known-answer vectors for SHA-256, ECDSA and AES-GCM taken from published test
vectors — not self-generated, which only proves the code agrees with itself.
Plus: tampered ciphertext rejected, tampered signature rejected, wrong key
rejected, Merkle inclusion proof verifies and a forged one does not, the
duplicate-list collision is rejected, session replay rejected, expired
timestamp rejected, cross-identity replay rejected.

Map each test to the §V security claim it substantiates in the session file.
docs/EXPERIMENTS.md Target 5 has that mapping table; you don't need to read
the rest of that file to use it.

EXIT CONDITION
make test and make lint green. Q1 closed in PROJECT_STATE.md with the
benchmark numbers that decided it. Every §V-1 property has a passing test.

OUT OF SCOPE
No Block, Chain, Transaction, or pBFT. crypto/ imports from util/ and nothing
else internal — if you find yourself wanting a Block to test against, use raw
bytes instead. That pull is the dependency direction failing, and M2 is where
it belongs.

END OF SESSION
Session file with attribution and dead ends. Amend DEV-11 (Merkle count
binding) and DEV-02 (responder-identity binding, nonce cache) in
docs/DEVIATIONS.md — both are changes to what those entries currently say.
Append the Q1 benchmark to RESULTS.md. Rewrite PROJECT_STATE.md, confirm under
200 lines. Tick M1 in docs/ROADMAP.md. Commit explaining why.
```

---

## What was done

All new files are **AI-generated, human-directed** — the task, the two protocol corrections and
the Merkle fix were specified in the prompt; the implementations and tests are Claude's.

**`src/bsfr_sh/crypto/` (6 modules, all new)**

| Module | What it does | Notable |
|---|---|---|
| `hashing.py` | `h()` bare SHA-256; `tagged_h(domain, *parts)` positional | parts are length-prefixed via `util.serialization.encode`, so the pre-image is prefix-free and `(b"ab", b"c")` ≠ `(b"a", b"bc")` |
| `merkle.py` | tree, root, inclusion proofs | DEV-11 duplication kept; leaf count bound into the root |
| `ecdsa.py` | secp256r1 keygen/sign/verify | RFC 6979 deterministic; `verify()` returns `bool`, `load_public_key` rejects off-curve points |
| `aead.py` | AES-256-GCM | `seal()` has no nonce parameter at all; per-key seal counter caps at SP 800-38D's 2^32 |
| `kem.py` | ECIES wrap + `seal_payload`/`open_payload` | wrapped key and payload bound to each other and to tx metadata |
| `session.py` | DEV-02 protocol | `ID_B` bound into A's signature; `NonceCache` with a `2 x window` horizon; clock injected |

**Tests (8 new files, 161 tests; suite 186 → 347)** — `test_hashing.py` (11), `test_merkle.py`
(41), `test_ecdsa.py` (18), `test_aead.py` (19), `test_kem.py` (15), `test_session.py` (17),
`test_session_replay.py` (12), `test_session_mitm.py` (10), plus `tests/unit/conftest.py` with
fixture-loaded keypairs and a `FakeClock`.

**Also changed**
- `scripts/bench_ecdsa_backends.py` — new, the Q1 measurement, emits a sidecar to `results/logs/`.
- `pyproject.toml` — `ecdsa>=0.19` added to dev extras, benchmark-only, so Q1 stays re-runnable.
- `tests/unit/test_module_boundaries.py` — `HASHLIB_ALLOWED` now `{util/config.py,
  crypto/hashing.py}`; see the D1 finding below for why `util/config.py` did not leave.
- `docs/ARCHITECTURE.md` §crypto — the session sketch was the source of defect (a); corrected
  in place, with the hashing and Merkle details it was missing.
- `docs/DEVIATIONS.md` — DEV-01, DEV-02, DEV-11 amended. `docs/ROADMAP.md` — M1 ticked, current
  milestone moved to M2.

## Findings

**STEP 0 passed, and it was worth running.** `util/serialization.py` produced byte-identical
output across four separate interpreter processes under `PYTHONHASHSEED` 0, 1, 12345 and
`random`, for insertion-order-shuffled dicts, mixed key types, NFC-sensitive strings, and the
`encode_block`/`encode_transaction` struct paths. No `json`, no `pickle`, no `hash()` — the
encoder sorts mapping entries by *encoded key bytes*, which is what makes it insertion-order
independent. The throwaway script was not kept; the property is pinned by `test_serialization.py`
and restated in `PROJECT_STATE.md` so M2 does not re-derive it.

**The RFC 6979 vector matched byte-for-byte on the first run.** `cryptography` 50.0.1 against
OpenSSL 4.0.2 supports `deterministic_signing=True`, and the A.2.5 `(r, s)` for "sample" and
"test" came out exactly as published. That is a much stronger check than a round-trip: it proves
the nonce derivation, the hash binding and the DER encoding all agree with an independent
implementation. `DETERMINISTIC_SIGNING` is exported so a bench sidecar can record which mode was
in force, and the tests `skip` rather than fail on a backend without it.

**The Merkle collision is real, and there is now a test asserting it still is.**
`test_the_underlying_tree_really_does_collide_without_the_count_binding` checks that the *bare*
root of `[a, b, c]` equals that of `[a, b, c, c]`, and that the count-bound roots differ. Without
that test the binding looks like redundant ceremony and a later reader deletes it.

**D1 cannot be retired as written — this is the one thing M1 was asked to do and did not.**
`PROJECT_STATE.md` and a comment in `test_module_boundaries.py` both said M1 would make
`util/config.py` import `crypto.hashing.h()` and drop its `hashlib` exemption. It cannot:
`test_util_depends_on_nothing_else_in_the_package` forbids `util` importing anything above it, and
`docs/ARCHITECTURE.md` fixes the direction as `util <- crypto`. The M0 plan for D1 contradicted
M0's own boundary test. Options considered:

1. *Let `util` import `crypto`.* Inverts the documented architecture to save one `hashlib` call.
   Rejected.
2. *Add a `util/digest.py` holding the primitive, with `crypto.hashing` wrapping it.* Honours the
   real invariant (one implementation) but not CLAUDE.md §7's literal wording, and adds a module
   to M0's layer during an M1 session.
3. *Move `config_hash()` into `crypto.hashing`, drop the field from `Config`, let `bench`/`scripts`
   compose them.* Architecturally correct. Changes the `Config` dataclass and the M0 tests pinning
   it, so it is a task, not a side effect.

Went with (3), deferred to M2 and recorded as D1 with that plan. `crypto/hashing.py` was added to
`HASHLIB_ALLOWED` alongside `util/config.py` rather than replacing it. Flagging rather than
silently doing (1) or (2) mid-session.

**Dead ends and small corrections**

- *First draft of `AeadKey` used a per-key random 4-byte prefix plus an 8-byte counter for the
  nonce.* Abandoned: loading the same key material into two `AeadKey` instances restarts the
  counter with a fresh prefix, so it trades a clean 2^-32-per-pair collision bound for a subtler
  one while looking more rigorous. Settled on SP 800-38D's RBG-based construction (96-bit random
  nonce, no caller input) plus an explicit exhaustion counter, which is the documented approach
  and easier to argue about.
- *`AeadKey.open()` was renamed to `unseal()`* to avoid shadowing the builtin, which ruff's `A`
  ruleset would flag and which reads badly next to `seal`.
- *`FakeClock` initially lived in `test_session.py` and was imported by `test_session_replay.py`.*
  Ruff's import sorting rejected the cross-test import ordering; moved to `conftest.py`, which is
  where it belonged anyway.
- *`scripts/bench_ecdsa_backends.py` bends CLAUDE.md §3's "scripts/ — thin CLI wrappers, no
  logic".* It has real logic. The alternative was standing up `src/bsfr_sh/bench/` — a whole M6
  structure — to answer one library question. Judged the lesser deviation; recorded here rather
  than left for someone to notice. Its docstring says it is a one-off decision benchmark, not part
  of the reproduction suite.
- *`make lint` does not cover `scripts/`* (`ruff check src tests`, `mypy files = ["src"]`), so the
  new script is unchecked. Recorded as debt D2 rather than widening the lint target mid-session.

**§V claim → test mapping** (per `docs/EXPERIMENTS.md` Target 5)

| §V-1 property | Test |
|---|---|
| replay resistance | `test_session_replay.py::test_replayed_session_opening_is_rejected`, `::test_replay_is_rejected_even_inside_the_timestamp_window`, `::test_a_replay_after_the_window_fails_on_the_timestamp`, `::test_initiator_can_reject_a_replayed_response_with_a_cache` |
| cross-identity replay | `test_session_replay.py::test_opening_addressed_to_one_server_is_refused_by_another`, `::test_rewriting_the_responder_id_breaks_the_signature` |
| MITM resistance | `test_session_mitm.py::test_substituted_initiator_ephemeral_key_is_rejected`, `::test_substituted_responder_ephemeral_key_is_rejected`, `::test_tampered_nonce_or_timestamp_is_rejected`, `::test_tampered_signature_is_rejected` |
| impersonation resistance | `test_session_mitm.py::test_an_attacker_cannot_impersonate_the_initiator`, `::test_an_attacker_cannot_impersonate_the_responder`, `test_ecdsa.py::test_wrong_key_is_rejected` |
| illegal session-key computation | `test_session.py::test_the_session_key_never_travels_on_the_wire`, `::test_each_session_produces_a_distinct_key`, `test_session_mitm.py::test_an_unknown_key_share_does_not_yield_a_shared_key` |
| freshness / expiry | `test_session.py::test_expired_timestamp_is_rejected`, `::test_a_future_dated_message_is_rejected`, `::test_stale_response_is_rejected_by_the_initiator` |
| §V-4 data manipulation | `test_merkle.py` (whole file, esp. `test_duplicate_last_transaction_does_not_collide`), `test_aead.py::test_tampered_ciphertext_is_rejected` |
| §V-4 leakage / confidentiality | `test_kem.py::test_wrong_recipient_cannot_open`, `::test_wrapped_key_cannot_be_swapped_onto_another_transaction`, `::test_ciphertext_cannot_be_swapped_under_a_wrapped_key` |

§V-2, §V-3 and §V-5 need `blockchain/`, `consensus/` and two live `Chain` objects; they are M2/M3
and are not claimed here.

## Numbers

Q1, ECDSA backend bake-off. secp256r1 / SHA-256 / RFC 6979 deterministic, 200 operations per
sample, median of 7 after 1 warm-up, local 8 GB dev box. Run `20260910T213021Z-f07b5fbf`, sidecar
in `results/logs/`. Also in `RESULTS.md`.

| Backend | sign (ops/s) | verify (ops/s) |
|---|---|---|
| `cryptography` 50.0.1 (C/OpenSSL 4.0.2) | **39,371** | **23,306** |
| `ecdsa` 0.19.2 (pure Python) | 2,307 | 588 |

17.1x on sign, 39.6x on verify. The decisive figure is the second one against Fig. 6: case-3 is
1500 transactions, so at 588 verify/s signature verification alone would cost ~2.6 s — roughly 45%
of the 5.71 s the paper reports for the entire case. The benchmark would be measuring `ecdsa`, not
BSFR-SH. Chose `cryptography`.

## Deviations opened or changed

- **DEV-01** amended — wrapped key bound to its ciphertext and to the transaction metadata via
  AEAD associated data, closing a key-swap that leaves every signature verifying.
- **DEV-02** amended — (a) `ID_B` bound into A's signed message, closing a cross-server replay
  that impersonated A with no key material; (b) seen-nonce cache with a `2 x window` horizon,
  because a timestamp window bounds the replay interval rather than preventing replay. Full
  corrected protocol recorded in the entry.
- **DEV-11** amended, now FILL+FIX — leaf count bound into `MTR`, closing the CVE-2012-2459-shaped
  collision between a list of N and that list with its final element repeated.
- No new DEV numbers opened.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** `crypto/` is complete and is the only module M2 needs to build on. `make test`
runs 347 tests (161 new) and `make lint` — ruff check, ruff format --check, `mypy --strict` — is
clean. Q1 is closed with measured numbers. `docs/ARCHITECTURE.md` §crypto now describes the
protocol that was actually built rather than the flawed sketch. Nothing in `crypto/` imports
anything internal except `util/`, checked by `test_module_boundaries.py`.

**Next task:** Build `blockchain/` — `transaction.py`, `block.py`, `chain.py` — against the field
orders already declared in `util.serialization` (`TRANSACTION_FIELD_ORDER`, `BLOCK_FIELD_ORDER`,
`BlockPart.HASH`/`.SIGN`), using `crypto.kem.seal_payload` for payloads and
`crypto.merkle.merkle_root` for `MTR`, with `Block` asserting its own field names against
`BLOCK_FIELD_ORDER` so the dataclass and the encoder cannot drift; pBFT is M2-2 and out of scope.

**New blockers:** none.

**Questions opened / closed:** **Q1 closed** — `cryptography` backend, on the throughput above.
**Q6 opened** — does `Transaction` carry its own ECDSA signature, or is `Sig_βj` over the block
the only one? The paper shows only `Sig_βj`; M2-1 decides and records a DEV if a second signature
is added. Q2–Q5 unchanged.

**Debt:** D1 restated with a concrete plan and deferred to M2 (it could not be done as originally
specified — see Findings). D2 opened: `make lint` does not cover `scripts/`.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines — 131
- [x] `RESULTS.md` appended, one line per run — two rows, one per backend
- [x] `docs/ROADMAP.md` boxes ticked — M1 `[x]`, current milestone moved to M2
- [x] `docs/DEVIATIONS.md` updated — DEV-01, DEV-02, DEV-11 amended
- [x] Committed, message explains *why*
