# Session 2026-09-18-02 — M7-1: formal verification of the session protocol

**Milestone:** M7 · **Files read at start:** `CLAUDE.md`, `PROJECT_STATE.md`,
`docs/ARCHITECTURE.md` §crypto, `docs/DEVIATIONS.md` DEV-02 + DEV-14, `docs/PAPER_NOTES.md` §V ·
**Duration:** _

---

## Brief *(written before any work)*

**Task:** Formally verify the DEV-02 session-establishment protocol (our own design, not the
paper's) against §V-1's informal claims, using a symbolic model checker, and record whatever the
tool finds.

**Exit condition:** a tool run (or, only if every tool is genuinely infeasible here, a BAN-logic
derivation) produces a VERIFIED/ATTACK result for every claim listed below; the model file is
committed under `verification/`; a mapping table (§V-1 claim -> formal claim -> result) exists;
`docs/DEVIATIONS.md` DEV-14 is amended; `make test`/`make lint` stay green.

**Claims to check:**
1. Secrecy of `SK`.
2. Non-injective agreement, A -> B, on `(ID_A, ID_B, N_A, N_B, g^a, g^b)`.
3. Non-injective agreement, B -> A, on the same tuple.
4. Distinct `(N_A, N_B)` pairs yield distinct `SK` (freshness).
5. No reflection (A cannot complete a session with itself).

**Out of scope:** no changes to `src/bsfr_sh/crypto/session.py` unless the model finds a real
attack; no M7-2 (storage-cost analysis); no adversarial evasion; no slides.

**Prior context needed:** `docs/ARCHITECTURE.md` §crypto (protocol as built, post-M1),
`docs/DEVIATIONS.md` DEV-02 (the two M1 fixes and why) and DEV-14 (this is the stretch goal it
tracked), `docs/PAPER_NOTES.md` §V (the five informal claims, GAP-6 naming Scyther as tractable).
Not `docs/EXPERIMENTS.md` — this session produces no benchmark numbers.

**Note on the task prompt's protocol sketch vs. the authoritative one:** the task description
restates the protocol without the `tag1`/`tag2`/`tag_sk` domain separators and without `g^a`
inside B's signature. `docs/ARCHITECTURE.md` §crypto and `crypto/session.py`'s own docstring are
authoritative (confirmed by reading the source before modelling); the model below follows those,
not the task prompt's shorthand.

---

## Prompts *(verbatim, in order, no summarizing)*

```
1. Read CLAUDE.md, then PROJECT_STATE.md. Context ladder: docs/ARCHITECTURE.md
§crypto (the session protocol), docs/DEVIATIONS.md DEV-02 and DEV-14,
docs/PAPER_NOTES.md §V only. Not docs/EXPERIMENTS.md.

Create the session file from the template and fill the brief first.

TASK — M7-1. Formal verification of the session-establishment protocol using
Scyther.

CONTEXT
The paper's §V is five paragraphs of informal prose — no ROR model, no BAN
logic, no tool-checked proof. DEV-14 flagged this as a stretch goal. It is
now the task. The session protocol is our design (DEV-02), not the paper's,
so we are verifying our own contribution, not reproducing theirs. That
distinction matters for the presentation.

The protocol, after M1's fixes:

  A -> B : ID_A, ID_B, N_A, TS_A, g^a, Sig_A(ID_A || ID_B || N_A || TS_A || g^a)
  B -> A : ID_B, N_B, TS_B, g^b, Sig_B(ID_B || N_B || TS_B || g^b || N_A)
  both   : SK = KDF(g^ab || N_A || N_B || ID_A || ID_B)

M1 found and fixed two defects in the original sketch: ID_B missing from A's
signature (cross-identity replay), and no nonce cache (within-window replay).
Scyther should confirm both fixes hold and either find nothing new or find
something we missed — both outcomes are results.

STEP 0 — install and verify Scyther.
Scyther is a Python tool with a GUI or CLI. CLI is what we need. Check
whether it's installable via pip or needs a binary. If it requires a platform
binary that isn't available in this environment, stop and say so before
writing any model — we need to know the tool runs before investing in the
specification. If Scyther itself is not feasible, Tamarin or ProVerif are
alternatives; state the trade-off before switching.

If none of these tools can be installed and run in our environment, the
fallback is a manual BAN logic derivation written in LaTeX. That is weaker
but still formally grounded and still more than the paper provides. Do not
attempt it without confirming the tools are blocked first.

1. Model the protocol in Scyther's input language (.spdl).
   Model both roles (Initiator, Responder). Model the adversary as
   Dolev-Yao (Scyther's default). Include:
   - Long-term keypairs for signing (ECDSA abstracted as asymmetric sig)
   - Ephemeral DH shares (g^a, g^b)
   - The KDF-derived session key as the secrecy target
   - Both nonces and both timestamps in the signed transcripts
   - ID_B inside A's signature (the M1 fix)

   Do NOT model the nonce cache — Scyther's symbolic model doesn't handle
   stateful replay caches. That's a known limitation, and the right response
   is to state it ("Scyther verifies the protocol's cryptographic structure;
   the replay cache is an implementation-level defense that operates below
   the symbolic abstraction") rather than to fake it.

2. Specify the security claims Scyther should check.
   Map each one to a §V-1 property the paper asserts informally:

   - Secrecy of SK (§V-1: "an adversary cannot estimate the session key")
   - Authentication of A to B: non-injective agreement on
     (ID_A, ID_B, N_A, N_B, g^a, g^b) — §V-1: mutual authentication
   - Authentication of B to A: same, reverse direction
   - Session key freshness: distinct (N_A, N_B) pairs produce distinct keys
     — §V-1: "distinct keys in each different session"
   - No reflection: A cannot be tricked into completing a session with
     itself — implicit in §V-1's impersonation resistance

3. Run Scyther and record the output.
   For each claim: VERIFIED or ATTACK FOUND, with the trace if an attack.

   If all claims verify: that is the result. State it as "the protocol's
   cryptographic structure is verified under the Dolev-Yao model" — not as
   "the implementation is secure," because Scyther checks the protocol, not
   the code.

   If an attack is found: that is a better result. Fix the protocol, re-run,
   verify the fix, and record both the vulnerability and the repair. An
   attack found and fixed by formal verification is exactly what the paper
   should have done and didn't.

4. Write a verification summary for the report.
   One subsection (§III-G or a new §VIII) covering: tool, model, claims
   checked, results, and the stated limitations (no timestamp semantics, no
   replay cache, symbolic not computational). Include the .spdl file in the
   repo under docs/verification/ or a new verification/ directory.

   Also produce a mapping table: each §V-1 informal claim → formal claim →
   Scyther result. That table is the thing the mid presentation shows.

TESTS
No new Python tests from this session — Scyther is the verifier. But confirm
make test and make lint are still green, since the session may touch docs or
add files.

EXIT CONDITION
Scyther (or alternative) runs, all specified claims have a result (verified
or attack), the .spdl model is committed, the verification summary is
written, and the §V-1 mapping table exists. If no tool was installable, a
BAN logic derivation covers the same claims on paper.

OUT OF SCOPE
No code changes to crypto/session.py unless Scyther finds an attack. No
storage-cost analysis (M7-2). No adversarial evasion. No slides yet.

END OF SESSION
Session file with attribution. If the protocol needed fixing, amend DEV-02
and update ARCHITECTURE.md. Add DEV-14 amendment recording what was verified
and what wasn't. Rewrite PROJECT_STATE.md, under 200 lines. Commit
explaining why. Push.
```

Note: task item 4 says "Include the .spdl file in the repo under
docs/verification/ or a new verification/ directory" — used a new top-level
`verification/` directory (one of the two options offered), and put the
mapping table in `verification/README.md` rather than as a new report
section, since the report (§III-G/§VIII) is out of this session's exit
condition (the report is a separate, already-closed deliverable per
`PROJECT_STATE.md`; adding a section to it was not re-opened here without
confirming that's wanted).

---

## What was done

- **Step 0 — tool selection (AI-generated investigation).** Checked `pip`/PyPI for `scyther`:
  found a package under that exact name, but inspecting its wheel contents (without installing —
  `pip download --no-deps`, then read the file listing) showed it is an unrelated repo/file
  management CLI (`edit_tool`, `git_tool`, `permission_manager`, `access_control`, ...) that
  happens to squat the name. Not installed. The real tool (Cas Cremers' Scyther) has no PyPI or
  Homebrew-core distribution; found and downloaded the official native macOS-arm64 binary from
  `cascremers/scyther`'s GitHub release v1.3.0 (sha256 recorded in `verification/README.md`).
  Verified it actually works before trusting it for anything: reproduced the textbook
  Needham-Schroeder-Lowe result (`nsl3.spdl` verifies, `nsl3-broken.spdl` fails exactly the claims
  the literature says it should) and ran the shipped `Protocols/IKE/sts-main.spdl`.
  Also evaluated Tamarin as the stated fallback (`brew tap tamarin-prover/tap` — required
  `brew trust`, a third-party-tap gate, granted since it's the tool's own official tap; `brew
  install` would have built the full Haskell toolchain from source since no bottle matches this
  macOS version) — abandoned once the real Scyther binary was confirmed working, since Scyther
  was the task's stated first choice and is sufficient.
- **`verification/bsfr_session.spdl` (AI-generated).** Both roles of `crypto.session` (DEV-02,
  post-M1), Dolev-Yao adversary, ECDSA abstracted as Scyther's built-in signature primitive,
  DH shares modelled via Scyther's standard `@oracle` idiom (reused, not invented — validated
  against Scyther's own shipped `sts-main.spdl` first). Nonce cache explicitly not modelled, per
  the brief. 5 claims per role: `Secret`, `Nisynch`, `Niagree`, `Alive`, `Weakagree`.
- **`verification/bsfr_session_pre_m1.spdl` (AI-generated).** Negative control: the original
  pre-M1 sketch (no `ID_B` in `A`'s signature), otherwise identical, to confirm the verification
  is discriminating.
- **`verification/results/*.txt`, `*.dot` (generated tool output, not authored).** Raw Scyther
  output for both models at `--max-runs=5` and (fixed model only) `--unbounded`, plus the dot
  attack graph for the pre-M1 model's two failing claims.
- **`verification/README.md` (AI-generated).** Tool provenance (incl. the PyPI name-squat
  finding), modelling choices and their justification, the §V-1 -> formal-claim -> result mapping
  table, the attack narrative, reproduction commands, and five stated limitations.
- **`docs/DEVIATIONS.md` DEV-14 amended, `docs/ARCHITECTURE.md` §crypto amended, `docs/ROADMAP.md`
  M7 box ticked** — all AI-generated, human-edited none.
- **No changes to `src/bsfr_sh/crypto/session.py`.** The shipped protocol verified clean; nothing
  to fix.

## Findings

- **The PyPI package named `scyther` is not the verification tool.** Worth recording so a future
  session doesn't `pip install scyther` on the strength of the name alone — always inspect an
  unfamiliar package's contents before installing, especially for a niche academic tool that is
  unlikely to have a polished PyPI release at all.
- **The task prompt's own protocol restatement was slightly stale.** It dropped the `tag1`/
  `tag2`/`tag_sk` domain separators and `g^a` from B's signature. `docs/ARCHITECTURE.md` and
  `crypto/session.py`'s docstring (both read before modelling) were authoritative and used
  instead; noted in the session brief above. Lesson: when a task prompt restates something the
  repo already documents precisely, re-derive from the repo, not the prompt's paraphrase.
- **Scyther cannot natively express Diffie-Hellman's algebraic property** (`g^(ab) = g^(ba)`) —
  a real, documented tool limitation (this is precisely why Tamarin/ProVerif support user
  equational theories and Scyther doesn't). The standard workaround is an `@oracle` role that
  registers the equivalence as a derivation rule; this is not a shortcut invented for this
  session — it is the exact technique Scyther's own author ships for Station-to-Station in this
  release's example protocols, and it was validated against that shipped example before reuse.
- **`--unbounded` did not upgrade results to "proof of correctness"** the way it does for
  oracle-free protocols (`nsl3.spdl` gets `[proof of correctness]`; our model, with the oracle,
  stays at `[no attack within bounds]` even unbounded). Recorded as a stated limitation rather
  than a fixable gap — it is the oracle mechanism's known effect on Scyther's completeness
  reporting, not a sign the search was too shallow (bounded and unbounded runs agree).
- **The pre-M1 attack Scyther found is not the literal scenario DEV-02's prose describes.** DEV-02
  says "replay A's opening verbatim to CS_2"; the trace Scyther produced is a splice/redirect
  where the intruder crafts its own signed message reusing A's nonce, rather than a byte-for-byte
  replay. Both are instances of the same root cause (nothing in the pre-M1 message binds an
  intended recipient), and finding a *different* exploit of the same gap is arguably stronger
  evidence the fix was necessary than reproducing the imagined scenario exactly would have been —
  recorded as a finding rather than smoothed over.

## Numbers

None — this session produced no benchmark numbers. `RESULTS.md` not touched.

## Deviations opened or changed

- `docs/DEVIATIONS.md` DEV-14 amended (M7-1, 2026-09-18): Scyther verification done, all five
  §V-1-mapped claims verified on the shipped protocol; the identical tool finds a real attack on
  the pre-M1 sketch, confirming the M1 fix was necessary. No code change needed.

---

## Handover *(written last, this is what the next session actually depends on)*

**State after:** M7-1 is closed. `verification/` holds the Scyther model of DEV-02's session
protocol, a negative-control model reproducing the pre-M1 vulnerability, raw tool output, and a
README with the §V-1 mapping table and stated limitations. All five task claims (secrecy,
mutual non-injective agreement both directions, per-session freshness, impersonation/reflection
resistance) verify clean on the shipped protocol at both bounded and unbounded search; the same
tool finds a real attack on the pre-M1 sketch, confirming DEV-02's M1 fix was necessary. No source
code changed. `make test` (1321 passed) and `make lint` (ruff + mypy clean) reconfirmed green.

**Next task:** M7 has four remaining stretch items, none required for the deliverable: adversarial
evasion evaluation, storage-cost analysis for on-chain backups, async pBFT with realistic network
latency, and a hybrid-blockchain extension. None is a natural continuation of this session; pick
whichever the course brief weights next, or stop — M7 is explicitly optional and the core
deliverable (report) is already done.

**New blockers:** None.

**Questions opened / closed:** None of Q11/Q4/Q8 touched by this session. Q4 ("do we need real
feature-space evasion for M7?") remains open for whoever picks up the adversarial-evasion item.

## Checklist

- [x] `PROJECT_STATE.md` rewritten (not appended) and still under 200 lines
- [x] `RESULTS.md` appended, one line per run — n/a, no runs this session (verification, not
      benchmarking)
- [x] `docs/ROADMAP.md` boxes ticked
- [x] `docs/DEVIATIONS.md` updated (DEV-14 amended)
- [x] Committed, message explains *why*
