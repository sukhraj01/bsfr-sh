# Formal verification of the session-establishment protocol (M7-1)

**What this is.** A symbolic (Dolev-Yao) verification of `crypto.session` (DEV-02) — **our own
design**, built to fill the gap the paper leaves at §V-1/§IV-A ("any standard mutual
authentication and key establishment mechanism"). This verifies our contribution, not the
paper's; the paper has no protocol here to check. See `docs/DEVIATIONS.md` DEV-14.

**Result, in one line:** the shipped protocol (post-M1) verifies clean against every claim
below, at bounded and unbounded search; the same tool, pointed at the pre-M1 sketch, finds a real
attack exactly where DEV-02 says one existed. That is the strongest form of confirmation
available short of a computational proof: the tool doesn't just fail to find problems in the
fixed version, it visibly finds the one that was fixed when pointed at the broken one.

---

## Tool

[Scyther](https://people.cispa.io/cas.cremers/scyther/) v1.3.0 (Cas Cremers), native macOS
arm64 binary from the project's own GitHub release —
`https://github.com/cascremers/scyther/releases/download/v1.3.0/scyther-macos-arm-v1.3.0.tgz`,
sha256 `5dd8d98fb7d84cd5e11598be848de327f1dffe58ace9b39706e459ffa4fd9511`. Not installed via pip:
the PyPI package literally named `scyther` (0.10.0) is an unrelated repo/file-management CLI
tool that happens to squat the name — inspected its wheel contents before touching it and it has
nothing to do with protocol verification, so it was never installed. The real tool has no PyPI or
Homebrew-core distribution; the author ships prebuilt per-platform binaries (linux/macos-arm/
macos-intel/win32) from the GitHub release, which is what `Scyther/scyther-mac` here is. Verified
runnable and correct before use: it reproduces the textbook Needham-Schroeder / NSL result
(`nsl3.spdl` verifies clean, `nsl3-broken.spdl` — the version without the fix Lowe found — fails
exactly the claims the literature says it should) and correctly runs the shipped
`Protocols/IKE/sts-main.spdl` (Station-to-Station, an authenticated-DH protocol), which is where
the Diffie-Hellman modelling technique below comes from.

Not committed to the repo: it is a third-party, single-platform binary. Anyone reproducing this
needs the same release from the URL above (or to rebuild from `cascremers/scyther` source for
their platform).

Tamarin was evaluated as the stated fallback and not needed: `brew tap tamarin-prover/tap &&
brew install tamarin-prover` resolves and (per `brew info`) needs `graphviz` + `maude`, but no
prebuilt bottle exists for this machine's exact macOS version, so it would have built the whole
Haskell toolchain from source — a large, slow path abandoned once the real Scyther binary was
confirmed working directly.

## Model

`bsfr_session.spdl` — both roles (`A`, `B`), Dolev-Yao adversary (Scyther's default: full network
control, can compromise agents, cannot break the abstracted crypto primitives).

Modelling choices, each stated rather than silently assumed:

- **ECDSA** is abstracted as Scyther's built-in asymmetric signature primitive (`{m}sk(A)`,
  opened with `pk(A)`) — standard perfect-cryptography abstraction for a Dolev-Yao model; Scyther
  never re-derives signature unforgeability, the same way it never re-derives that AES is IND-CPA.
- **Ephemeral DH shares (`g^a`, `g^b`)** use the standard Scyther idiom for Diffie-Hellman:
  `g(x)` stands for `g^x`, and an `@oracle(DHO)` role registers `dhkey(g(y),x) <-> dhkey(g(x),y)`
  as a derivation rule. **This is a real, documented limitation of Scyther, not a shortcut taken
  here**: Scyther's term algebra is free (no equational theory), so it cannot natively express
  `g^(ab) = g^(ba)` the way Tamarin's `diffie-hellman` builtin or a ProVerif equation would. The
  oracle idiom is the standard workaround, and this file did not invent it — it is the same
  construction Scyther's own author ships in this release's `Protocols/IKE/sts-main.spdl` for the
  Station-to-Station protocol, confirmed to run correctly on this binary before reuse (see
  above). Under this oracle, computing the shared secret still requires holding one of the two
  private exponents — an adversary who only sees `g^a`/`g^b` on the wire cannot derive it, which
  is the property that matters for the secrecy claim below.
- **Timestamps** are modelled as opaque fresh values inside the signed transcript. Scyther has no
  wall-clock model, so this checks that the timestamp is bound into the signature (tamper-evident)
  but not real elapsed-time freshness — a stated limitation, not a gap in the model.
- **The nonce cache is deliberately not modelled.** Per the task brief: Scyther's state space is
  symbolic and stateless across sessions; a persistent per-peer seen-nonce cache has no
  representation in it. Scyther verifies the protocol's cryptographic structure — the message
  flows, the signatures, the DH exchange; the replay cache (`crypto.session.NonceCache`) is an
  implementation-level defense that operates below this abstraction and is exercised instead by
  `tests/unit/test_session_replay.py`.

`bsfr_session_pre_m1.spdl` is the original, pre-M1 sketch (`ID_B` missing from `A`'s signature) —
a negative control, not a second thing being shipped. It exists to show the verification is
actually discriminating rather than vacuously passing everything.

## Claims checked, and results

Both bounded (`--max-runs=5`) and unbounded (`--unbounded`) search agree on every claim below;
raw tool output in `results/bsfr_session.txt`. Unbounded search still reports `[no attack within
bounds]` rather than `[proof of correctness]` — this is expected and is the `@oracle` mechanism's
known effect on Scyther's completeness reporting (the DH oracle role can in principle be invoked
without bound, so the backend does not claim exhaustive proof the way it does for `nsl3.spdl`,
which has no oracle). Both depths were run because that gap is worth being explicit about rather
than silently reporting only the bounded number.

| §V-1 informal claim (paper / DEV-02) | Formal claim (Scyther) | Result |
|---|---|---|
| "An adversary cannot estimate the session key" | `Secret` on `kdf(dhkey(...), ...)`, both roles | **VERIFIED** (`Secret_A1`, `Secret_B1`) |
| Mutual authentication, A authenticated to B | Non-injective agreement (`Niagree`) + synchronization (`Nisynch`) on the full transcript, role B | **VERIFIED** (`Niagree_B3`, `Nisynch_B2`) |
| Mutual authentication, B authenticated to A | Same, role A | **VERIFIED** (`Niagree_A3`, `Nisynch_A2`) |
| "Distinct keys in each different session" | Structural: `Na`, `Nb` are `fresh` per role instantiation and both appear inside `kdf(...)`; Scyther's free term algebra treats distinct fresh values as unequal, so two sessions cannot produce syntactically identical `kdf(...)` terms unless both nonces coincide, which fresh generation prevents | **HOLDS by construction** (not a Scyther claim type — an argument from the model's own term algebra, stated rather than run) |
| Impersonation resistance (implicit in §V-1) | `Weakagree`, `Alive`, both roles | **VERIFIED** (`Weakagree_A5`/`B5`, `Alive_A4`/`B4`) |
| No reflection (A tricked into a session with itself) | Not a separate claim type: Scyther's default agent-instantiation search already includes an agent playing both roles opposite itself; a reflection attack would have to show up as a `Niagree`/`Nisynch` violation, and none was found | **NO ATTACK FOUND** under the same claims above, not independently re-verified |
| Cross-identity replay (DEV-02 M1 fix (a)) | `Niagree`/`Nisynch`, fixed model vs. pre-M1 model | **FIXED MODEL VERIFIED; PRE-M1 MODEL: ATTACK FOUND** — see below |
| Within-window replay (DEV-02 M1 fix (b)) | N/A — requires the nonce cache | **OUT OF SCOPE for this tool** (stated limitation, not modelled) |

## The attack Scyther found (pre-M1 sketch only)

Running `bsfr_session_pre_m1.spdl` (`results/bsfr_session_pre_m1.txt`):

```
claim  bsfrsessionprem1,A  Secret_A1  ...             Ok    [no attack within bounds]
claim  bsfrsessionprem1,A  Nisynch_A2  -              Fail  [at least 1 attack]
claim  bsfrsessionprem1,A  Niagree_A3  -              Fail  [at least 1 attack]
claim  bsfrsessionprem1,B  Secret_B1  ...             Ok    [no attack within bounds]
claim  bsfrsessionprem1,B  Nisynch_B2  -              Fail  [at least 1 attack]
claim  bsfrsessionprem1,B  Niagree_B3  -              Fail  [at least 1 attack]
```

The attack trace (`results/bsfr_session_pre_m1_attack.dot`): the intruder (`Eve`) intercepts
Alice's opening to Bob, then opens her own signed message to Bob — using her own key, since
nothing in the message binds it to a specific intended recipient — while splicing in Alice's
nonce `Na`. Bob replies, addressed (in his own belief) to Eve; the intruder redirects that reply
to Alice, who accepts it because it matches her own `Na`. The result: a completed run in which
Alice believes she talked to Bob, but Bob's own run record shows he believed his partner was Eve.
That is a genuine agreement violation, not a false positive — Secrecy of the derived key still
holds even here (the intruder still needs an exponent to compute it), but authentication does
not, which is exactly the "impersonation requiring no key material" DEV-02 describes for the
missing-`ID_B` defect. Interesting side note: this is not literally the "replay A's message
verbatim to CS_2" scenario DEV-02's prose describes — the tool found a related but distinct
splice/redirect route to the same class of failure (identity confusion from an unbound
recipient), which is a stronger confirmation than the literal scenario alone would have been: the
missing binding is exploitable in more than one way, all closed by the same fix.

Fixing exactly what M1 fixed (adding `ID_B` into `A`'s signed transcript) is the only difference
between `bsfr_session_pre_m1.spdl` and `bsfr_session.spdl`, and it is what makes `Niagree`/
`Nisynch` verify clean in the latter. **No new attack was found in the shipped (post-M1)
protocol** — the honest, if less dramatic, result the task brief called out as equally valid.

## Reproducing this

```
./Scyther/scyther-mac --max-runs=5 verification/bsfr_session.spdl
./Scyther/scyther-mac --unbounded   verification/bsfr_session.spdl
./Scyther/scyther-mac --max-runs=5 verification/bsfr_session_pre_m1.spdl
./Scyther/scyther-mac --max-runs=5 -d verification/bsfr_session_pre_m1.spdl   # attack graphs
```

using the binary from the release URL above (`Scyther/scyther-mac` inside the extracted tarball).

## Limitations, stated plainly

1. **Symbolic, not computational.** This is a Dolev-Yao proof: perfect cryptography assumed for
   ECDSA and the KDF. It says nothing about implementation bugs, side channels, or a real break of
   secp256r1/SHA-256/HKDF.
2. **No timestamp semantics.** `TS_A`/`TS_B` are opaque values; real elapsed-time freshness is not
   modelled.
3. **No replay cache.** `crypto.session.NonceCache` is a stateful, per-peer defense with no
   representation in Scyther's model. Its correctness rests on
   `tests/unit/test_session_replay.py`, not on this verification.
4. **DH via the oracle idiom, not a native equational theory.** Correctly captures "you need one
   of the two exponents," reusing a construction validated against Scyther's own shipped example
   before use here, but it is Scyther's standard workaround for a known gap, not first-party
   support the way Tamarin's `diffie-hellman` builtin would be.
5. **Unbounded search did not report a completeness proof** (see above) — the `@oracle` mechanism
   is the stated reason; results at max-runs=5 and unbounded agree, which is the confirmation
   available given that.
