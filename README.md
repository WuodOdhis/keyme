# KeyMe

Open standard + open-source air-gapped signer for Nervos CKB.

**Scope (frozen):** [`docs/02-implementation-plan.md`](docs/02-implementation-plan.md) — stages 0–2
(checker, PSCT format, coordinator + software signer). QR and hardware come afterwards under a
separate DAO-funded scope.

**Background:** [`docs/00-research-and-plan.md`](docs/00-research-and-plan.md) — ecosystem state,
corrections to the original brief, PSCT v0 data model, and the strict trust model (D1).

## Short version

CKB has partial-signing workflows (`ckb-cli`, Neuron, CCC) but no cross-tool container, no hash-bound
input data in the signed payload, and no open-source offline signer. Closed air-gapped CKB signing
exists (SafePal S1); an open standard does not.

The defining constraint: a CKB signature does not commit to the capacity of the cells being spent, so
a signer that trusts a supplied `CellOutput` can be tricked into approving an enormous fee. Every input
must therefore be hash-bound to the transaction that created it.

## Artifacts

| Path | What |
|---|---|
| `docs/00` | Research, corrections, PSCT v0 draft, trust model |
| `docs/01` | Phase 0 findings and the fee-inflation attack |
| `docs/02` | **Frozen implementation plan, stages 0–2** |
| `packages/psct-core` | Molecule, sighash, binding, inspect, verify (TypeScript, dependency-light) |
| `fixtures/` | Mainnet transactions + input proofs, offline-verifiable |

Later: `spec/`, a second implementation (Rust), the coordinator, the software signer.

## Status

Stage 0 is in progress:

- `tx_hash` reproduces the node on 25/25 transactions.
- Signatures verify on 25/25 secp256k1 lock groups.
- 6 offline-verifiable mainnet fixtures.
- The input-claim attack (fee inflation without touching the signed bytes) is reproduced and
  rejected by the binding check.
- 17 hostile tests; malformed input produces verdicts, never crashes.

Not yet covered: multisig, Nervos DAO, xUDT, Spore, OmniLock. See stage 0 in the plan.

```bash
cd packages/psct-core
npm install
npm test                                          # hostile suite + offline fixtures
npm run redteam                                   # the attack demo
npx tsx src/cli.ts inspect <txhash>
```
