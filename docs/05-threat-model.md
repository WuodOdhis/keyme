# Threat model walk — D1 against the built system

Date: 2026-11-16
Scope: the verifier, the PSCT container, the coordinator, the signer, and their interop.

D1 says: the signer trusts only canonical bytes and its own pre-paired account, and refuses what it
cannot establish. This document checks that claim against the code, lists the residual risks, and
maps every defence to a test or an observed run.

---

## 1. Boundaries

| Party | Trust |
|---|---|
| Coordinator | **untrusted.** May be compromised and may lie in every field. |
| PSCT file | **untrusted data.** May be modified in transit. |
| Signer | **trusted** (subject to review; reproducible build is future work). |
| Node / chain | not trusted for liveness; consensus validates scripts. |

The coordinator never receives a private key; the signer never talks to a node.

---

## 2. What the signer establishes for itself

1. Every input cell is hash-bound to the outpoint it claims to spend.
2. The exact transaction hash it will sign.
3. The fee, from bound capacities.
4. Which outputs return to a lock it controls.
5. Which signatures are valid, and from which pubkeys.
6. DAO maturity and interest, when the required headers are present.
7. That every lock has a modelled signing profile.
8. That every type script is one it can name.
9. That every output claimed as change derives from its paired account (xpub), not from the file.

If any of 1, 7, 8 or 9 fails, it refuses the whole transaction — not the group, not a warning.

---

## 3. Attack matrix

| # | Attack | Stopped by | Evidence |
|---|---|---|---|
| 1 | Inflate an input's capacity to hide fee | binding to `prev_tx` + index | `redteam`, binding tests |
| 2 | Supply a different previous transaction | hash preimage | binding tests |
| 3 | Swap the output index inside the proof | index match | binding tests |
| 4 | Mutate the claimed cell data | binding compares `outputs_data` | binding tests |
| 5 | Change an output after signing | signature over `tx_hash` | hostile tests |
| 6 | Reorder inputs | `tx_hash` changes | hostile tests |
| 7 | Swap a `cell_dep` | `tx_hash` changes | hostile tests |
| 8 | Change the number of witnesses | message framing stops at missing witnesses | xUDT fixture, hostile suite |
| 9 | Flip a signature bit | recovery yields a different pubkey | hostile tests |
| 10 | Malformed signature | verdict, never an exception | hostile tests |
| 11 | Unknown lock | refuse, named | hostile tests |
| 12 | Known lock with no profile (OmniLock) | refuse, named | hostile tests |
| 13 | Unknown type script | **refuse** (added by this walk) | `signer policy` test |
| 14 | Multisig under threshold | `finalize` throws | container tests |
| 15 | Multisig signatures out of order | assembled by pubkey position | mainnet 3-of-5, devnet 2-of-3 |
| 16 | Duplicate signer in a set | matched against unused pubkeys | hostile tests |
| 17 | Conflicting partial signatures | `combine` throws | container tests |
| 18 | Conflicting unknown field | `combine` throws | container tests |
| 19 | DAO withdraw without its header | signer refuses before prompting | code + DAO tests |
| 20 | Lying DAO interest | computed from bound headers | DAO test (fee reconciles) |
| 21 | Token amount lie | xUDT data parsed; non-16-byte data warned | xUDT tests |
| 22 | Fake change output | signer derives change from the paired account | pairing tests, pairing demo |
| 23 | Replay a signature on another tx | `tx_hash` differs | hostile tests |
| 24 | Coordinator rewrites the sigs map | finalize verifies every group | container tests |
| 25 | ckb-cli export drops witness slots | placeholders preserve the layout | interop test |
| 26 | Lossy export of DAO/xUDT witness data | export throws | interop test |
| 27 | PSCT account swapped for another xpub | xpub + fingerprint must match the paired account | pairing tests |

---

## 4. Residual risks (accepted, documented, not hidden)

**R1 — Liveness.** The signer cannot prove a cell is unspent. A coordinator can build a transaction
that the network rejects. Consequence: failed broadcast, not loss of funds.

**R2 — Header canonicity.** Headers are hash-bound to `header_deps`/`block_hash`, but not proven to be
on the best chain. A lying coordinator can cause a rejected transaction. Same class as R1.

**R3 — Account pairing. Fixed (2026-11-16).** The signer is configured with an account xpub before
it sees a PSCT. It derives a 20-address look-ahead window on both chains, requires the PSCT account's
xpub and fingerprint to match, and refuses an output that claims to be change but does not derive from
the account. A transaction with no output back to the account still signs, but the fee (the whole
difference) is displayed; that is a deliberate choice, not a blind spot.

**R3a — Look-ahead window.** Only 20 addresses per chain are derived. An output to index 20 that the
coordinator calls change is treated as a payment (and refused if it claims change). Widen or scan on
demand; the format carries derivation hints, but the signer does not trust them.

**R4 — Code-dep identity.** `type`-hash dependencies rely on the signer's registry; dep cells are not
carried. For `data`/`data1`/`data2` the `code_hash` is the code. A `type`-hash dep outside the
registry is refused because the lock/type is unknown.

**R5 — Type-script semantics.** Known scripts are named, not executed. xUDT extensions and mutants,
Spore cluster rules and DAO edge cases are displayed with warnings where not modelled. Unknown scripts
are refused (finding F1).

**R6 — Transport tampering.** Files can be modified in transit; binding and signatures detect it, but
a user can still be socially engineered into signing a valid, malicious transaction. The approval
screen, not the transport, is the control.

**R7 — No hardware.** The signer is software on a networked machine. The air gap is stage 5. Until
then the "offline" claim is procedural, not enforced.

**R8 — Side channels.** Power/EM analysis is out of scope until hardware exists.

---

## 5. Findings from this walk

| Finding | Status |
|---|---|
| **F1** Signer refused unknown locks but only warned on unknown type scripts | **fixed** — signer now refuses uncertifiable contracts |
| F2 DAO epoch flag was `1n` instead of `0x20` | fixed earlier |
| F3 Occupied capacity was molecule size, not the flat field sum | fixed earlier |
| F4 Fee treated `inputs − outputs`, wrong for DAO interest | fixed earlier |
| F5 Sighash padded missing witnesses instead of stopping | fixed earlier |
| F6 ckb-cli export dropped witness slots | fixed earlier |
| **F7** Change ownership was a heuristic (compare with input locks) | **fixed** — paired account and derived change, with tests |

---

## 6. Test coverage

`npm test` runs 66 tests: 42 in the verifier/hostile suite, 24 in the container/interop/signer/pairing
suite. Thirteen fixtures cover mainnet, testnet and devnet. Three PSCT vectors are checked against an
independent Rust implementation. End-to-end flows are committed on devnet, testnet, and a paired-account
devnet run.

The matrix above is the acceptance list: every row has a test or an observed run, except the residual
risks, which are stated rather than covered.
