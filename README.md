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

Stage 0 complete; stage 1 in progress.

- 13 offline-verifiable fixtures: mainnet (plain, V2 multisig, DAO prepare + withdraw), testnet
  (xUDT, Spore), devnet (legacy 2-of-3 multisig accepted by consensus). 15 lock groups verified.
- The input-claim attack (fee inflation without touching the signed bytes) is reproduced and
  rejected by the binding check.
- PSCT v0 frozen ([`spec/psct-v0.md`](spec/psct-v0.md)): canonical CBOR, witness templates,
  hash-bound input proofs, per-group signatures, commutative combine, finalize-or-throw.
- TypeScript codec and 3 signed conformance vectors (secp, multisig, DAO).
- 56 tests across the verifier and the container.

Not modelled (and refused): OmniLock auth schemes, JoyID, NostrLock, Spore clusters/DIDs.

```bash
cd packages/psct-core
npm install
npm test                                          # verifier + PSCT + offline fixtures
npm run vectors                                   # regenerate conformance vectors
npm run redteam                                   # the attack demo
npx tsx src/cli.ts inspect <txhash> --json
```

Exit codes: `0` ok · `1` refused/failed · `2` usage. JSON encodes bigints as decimal strings.

## Docs

- `docs/00-research-and-plan.md` — research, trust model D1
- `docs/01-phase0-findings.md` — what was proven, and what broke
- `docs/02-implementation-plan.md` — frozen scope for stages 0–2
- `docs/03-portability.md` — the rules a Rust implementation must reproduce
