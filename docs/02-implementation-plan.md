# Implementation plan — stages 0 → 2 (frozen)

Version: 1.0 — 2026-11-16
Status: **frozen**. Changes require an amendment entry in §11, not a quiet edit.

---

## 1. What this plan covers

We build three things here, in order:

| Stage | Deliverable | Why it exists |
|---|---|---|
| **0** | A checker that can truthfully read CKB transactions | The oracle. Everything else is tested against it |
| **1** | PSCT: a documented container + two independent implementations | The standard other wallets can adopt |
| **2** | Watch-only coordinator + offline software signer, end-to-end on testnet | Proof the format works before hardware exists |

**Out of scope for this plan:** QR transport, hardware, mainnet funds, third-party wallet plugins,
a hosted service, mobile apps. Those begin after stage 2, funded separately.

---

## 2. Decisions carried into this plan

- **D1 — strict trust.** The signer trusts only canonical bytes and its own pre-paired account.
  Unknown lock, unknown contract, unbound input ⇒ refuse. No silent downgrade.
  (Defined in `docs/00-research-and-plan.md` §6.0.)
- **D2 — no Raspberry Pi.** Pi is excluded from v1. The software signer is the reference
  implementation; the hardware target is chosen after stage 2 funding, and must have no radio.
- **D3 — funding path.** Stages 0–2 are built here. Stage 3+ (QR, device, image, case) goes to the
  **CKB Community Fund DAO**, not the Spark micro-grant programme.
- **D4 — corpus discipline.** Only locks and types this project models enter the registry. Everything
  else is `unknown` and refused. Fixtures are selected by lock class, never by input count.
- **D5 — the spec describes the verifier.** PSCT v0 is written from what the checker already enforces,
  with vectors, and must pass in two independent implementations. No spec-first guessing.

---

## 3. Vocabulary (so "done" is unambiguous)

| Term | Meaning |
|---|---|
| **Bound** | An input's claimed cell has been hash-checked against the transaction that created it |
| **Verified** | A signature was recovered and matched the lock's arguments |
| **Refused** | No signature is produced; CLI exits non-zero |
| **Profile** | A named rule set for one lock or type script (message construction + placeholder) |
| **Fixture** | A stored transaction plus its input proofs, verifiable with no network |
| **Verdict** | Per-lock-group result: verified / no-profile / unknown-lock / no-signature / bad-signature |

---

## 4. Stage 0 — finish the checker

Current state: plain secp256k1-blake160 payments are fully covered (25/25 hashes and signatures on
mainnet, 17 hostile tests, 6 fixtures). The rest of the surface is not.

| # | Work item | Acceptance | Est. |
|---|---|---|---|
| 0.1 | Legacy multisig profile | A real 2-of-3 mainnet spend verifies; under-threshold and wrongly-ordered sets are rejected; signature ordering is derived, not guessed | 4 d |
| 0.2 | Multisig v2 / v2beta profiles | Same test against a real spend if one exists; otherwise documented as unsupported | 2 d |
| 0.3 | Nervos DAO deposit + withdraw | A real withdraw verifies, including header binding and the type-group witness field; a withdraw without its header is refused | 4 d |
| 0.4 | xUDT | Real transfer fixture; per-script balance deltas across multiple cells; owner-mode args handled | 2 d |
| 0.5 | Spore | Real create + transfer fixture; content hash and capacity floor shown; melting flagged | 3 d |
| 0.6 | OmniLock | At minimum: recognise it, name it, show its auth mode, refuse to sign | 2 d |
| 0.7 | `since` policy | Absolute and relative locks decoded and displayed; "dark" values warn and block | 2 d |
| 0.8 | Corpus to 20+ fixtures | Every class above represented, plus negative fixtures for each refusal type | 2 d |
| 0.9 | CLI contract | Stable exit codes and a `--json` output for automation | 1 d |
| 0.10 | Portability audit | Core has no Node-only APIs; a handoff note lists exactly what a Rust/Python port must reproduce | 1 d |

**Exit criteria**

- Every class in §4 is bindable, inspectable and verifiable from fixtures.
- Malformed input never throws: 10k random byte mutations produce verdicts, not crashes.
- Every refusal carries a stable reason code.
- `psct verify` exits non-zero if any lock group is not verified.

*(≈ 23 working days)*

---

## 5. Stage 1 — PSCT format, vectors, second implementation

| # | Work item | Acceptance | Est. |
|---|---|---|---|
| 1.1 | Freeze the data model | CBOR envelope, field table, canonical ordering rules, version field; no ambiguous types | 3 d |
| 1.2 | Digest and display binding | A single transaction fingerprint the user can compare across two screens; what it covers and what it does not is written down | 2 d |
| 1.3 | TS encoder/decoder | Round-trips every fixture; rejects non-canonical input | 4 d |
| 1.4 | Second implementation (Rust) | Byte-identical output on all vectors; independent reader, not a port of the TS code | 8 d |
| 1.5 | Conformance vectors | Valid, invalid, hostile, unknown-field preservation, commutative combine; each vector has an expected reason code | 4 d |
| 1.6 | `ckb-cli` interop projection | Export a PSCT as a `ckb-cli tx` file that `ckb-cli tx send` accepts; import back without loss | 2 d |
| 1.7 | Spec document | Written from §1.1–1.6; includes the threat model and the "cannot verify" list | 4 d |

**Exit criteria**

- Two implementations produce identical bytes and identical signing messages on every vector.
- Unknown fields survive combine, in any order (the lesson BIP-174 only wrote down in 2026).
- A format fuzzer runs in CI.
- The spec has no field that the verifier does not use.

*(≈ 27 working days)*

---

## 6. Stage 2 — coordinator + software signer

| # | Work item | Acceptance | Est. |
|---|---|---|---|
| 2.1 | Coordinator (watch-only) | Builds transfer, multisig payout, DAO deposit/withdraw, token transfer; resolves proofs; exports PSCT; never touches a key | 8 d |
| 2.2 | Software signer (CLI) | Imports an account out of band; binds, displays, signs, exports; works with networking disabled | 6 d |
| 2.3 | Round-trip state machine | create → sign → combine → finalize → broadcast, resumable, with a stable artifact format | 4 d |
| 2.4 | Multisig rounds | 2-of-3 across three signers by file handoff; partial files combine commutatively | 4 d |
| 2.5 | Testnet scenarios | Three recorded end-to-end runs: plain transfer, 2-of-3 payout, DAO withdraw. Each has a tx hash and a script to replay it | 4 d |
| 2.6 | Threat-model review | Walk the D1 checklist against the built system; every gap becomes a ticket or a documented limit | 2 d |

**Exit criteria**

- The three scenarios complete on testnet from a clean machine, following the docs only.
- No private key material in the coordinator, ever (checked by test).
- A refused transaction is refused at the signer, not at broadcast.

*(≈ 28 working days)*

---

## 7. Order of work and dependencies

```
0.1 multisig ─┐
0.2 v2        ├─> 0.8 corpus ─> 1.1 model ─> 1.3 TS codec ─┬─> 1.5 vectors ─> 1.7 spec
0.3 DAO       │                          └> 1.4 Rust codec ─┘
0.4 xUDT      │
0.5 Spore     │
0.6 OmniLock  │
0.7 since     ┘
                                  ↓
                    2.1 coordinator ─> 2.2 signer ─> 2.3 round trip ─> 2.4 multisig ─> 2.5 scenarios
```

Rules:

- No stage-1 work starts before 0.1–0.7 are closed. The model must not be designed around missing
  knowledge.
- 1.3 and 1.4 may run in parallel, but neither is "done" until they agree.
- 2.1 may start once 1.1 is frozen (it only needs the envelope), but must not ship before 1.5.

---

## 8. Interfaces (frozen now, so parallel work is possible)

**`psct-core` public API**

```
bindAll(tx, proofs) -> BoundCell[]                  // throws on any mismatch
inspect(tx, bound) -> Inspection                    // fee, deltas, warnings, change
verifyTx(tx, bound) -> GroupResult[]                // one verdict per lock group
classifyLock(script) -> { name, kind, profile }     // naming is not trust
```

**CLI contract**

```
psct inspect <txhash|file> [--rpc mainnet|testnet] [--json]
psct verify  <txhash|file> [--rpc ...] [--json]
psct sign    <psct-file> --account <account-file> --out <file>
```

Exit codes: `0` all verified · `1` refused or failed · `2` usage error.

**Artifact**

Stage 2 uses file handoff. The bytes are the same ones stage 3 will put in QR frames; no format change
is allowed between them.

---

## 9. Test strategy

| Layer | What it proves |
|---|---|
| Vectors | Encoding is unambiguous |
| Fixtures | Real chain data still verifies offline |
| Hostile suite | Every known attack fails closed |
| Fuzz-lite | Random mutation never crashes |
| Testnet scenarios | The whole loop works with real nodes |
| Threat-model walk | Nothing in D1 was quietly dropped |

---

## 10. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Multisig placeholder/ordering guessed wrong | Invalid transactions that look fine | Derive from the lock source; validate against a real on-chain spend before writing the spec |
| DAO withdraw needs headers we did not plan for | A class of transactions cannot be verified offline | Prove it on a real withdraw in 0.3; size the payload then |
| Unknown contracts are common in the wild | Refusal rate makes the product feel broken | Measure the rate on real blocks in 0.8; decide on an explicit opt-in after data |
| Two implementations drift | The spec becomes one team's opinion | Shared vectors in CI from day one; no code sharing between them |
| `ckb-cli` / Neuron format drift | Interop projection breaks | Fixture the projection; test against `ckb-cli` releases |
| Solo-maintainer bus factor | Project stalls | Spec + vectors + replayable scenarios are the handoff |
| Local devnet / testnet availability | Blocks stage 2 | Use a local devnet (`offckb`) for repeatable runs |

---

## 11. Amendments

| Date | Change | Reason |
|---|---|---|
| 2026-11-16 | 0.8 acceptance changed from "20+ fixtures" to "every class represented" | 20 was arbitrary; the corpus now covers every class with 13 fixtures, and more plain transfers would add no information |
| 2026-11-16 | v1.0 frozen | Initial scope agreement: stages 0–2 here, DAO funding afterwards |

## 11a. Progress log (status only; scope unchanged)

| Date | Item | State |
|---|---|---|
| 2026-11-16 | 0.1 legacy multisig | **closed** — 2-of-3 spend built from source, accepted by a devnet |
| 2026-11-16 | 0.2 multisig V2 | **closed** — mainnet 3-of-5 spend (fiber-scripts PR #34) |
| 2026-11-16 | 0.3 DAO withdraw | **closed** — mainnet, interest and fee reconcile |
| 2026-11-16 | 0.3 DAO prepare | **closed** — the withdraw's input creator, mainnet |
| 2026-11-16 | 0.4 xUDT | **closed** on testnet evidence; mainnet has no indexed xUDT token |
| 2026-11-16 | 0.5 Spore | **closed** on testnet evidence (V1 transfer) |
| 2026-11-16 | 0.6 OmniLock | descriptor done (auth scheme + modes); still refused |
| 2026-11-16 | 0.7 `since` | absolute/relative block, epoch and timestamp decoded and shown |
| 2026-11-16 | 0.8 corpus | **amended** — every class represented (13 fixtures); 20+ dropped as an arbitrary number |
| 2026-11-16 | 0.9 CLI | `--json` + exit codes 0/1/2 |
| 2026-11-16 | 0.10 portability | contract written in `docs/03-portability.md` |
| 2026-11-16 | 1.1 data model | **frozen** — `spec/psct-v0.md` |
| 2026-11-16 | 1.2 digest | `tx_hash` + display fingerprint; covers tx, not witnesses/proofs |
| 2026-11-16 | 1.3 TypeScript codec | canonical CBOR, envelope, combine, finalize |
| 2026-11-16 | 1.5 conformance vectors | 3 signed vectors: secp, multisig, DAO withdraw |
| 2026-11-16 | 1.4 Rust implementation | **closed** — byte-identical `tx_hash` and `full_tx_hash`, all groups verified |
| 2026-11-16 | 1.7 spec | written from what the verifier enforces |
| 2026-11-16 | 1.6 `ckb-cli` interop | **closed** — export/import round-trip; lossy exports refused |
| 2026-11-16 | 2.1 coordinator | **closed** — transfer builder, live cells, proofs, PSCT export |
| 2026-11-16 | 2.2 software signer | **closed** — bind, display, refuse, sign, self-check |
| 2026-11-16 | 2.3 round trip | **closed** — create → sign → finalize → broadcast (devnet) |
| 2026-11-16 | 2.4 multisig rounds | **closed** — two signers, combine, finalize, broadcast (devnet) |
| 2026-11-16 | 2.5 testnet scenarios | **closed** — coordinator → signer → broadcast, committed at block 23,084,406 |
| 2026-11-16 | 2.6 threat-model walk | **closed** — `docs/05-threat-model.md`; found and fixed the unknown-type gap |
| 2026-11-16 | R3 account pairing | **closed** — BIP32 account xpub, change derived and certified; pairing tests + devnet run |

---

## 12. Effort summary

| Stage | Estimate (1 developer, full time) |
|---|---|
| 0 | ~5 weeks |
| 1 | ~5–6 weeks |
| 2 | ~6 weeks |
| **Total** | **~16 weeks** |

Estimates are relative effort, not deadlines. If any stage overruns by more than 50%, stop and amend
this plan rather than quietly absorbing it.
