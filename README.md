# KeyMe

Open standard + open-source air-gapped signer for Nervos CKB.

**Read first:** [`docs/00-research-and-plan.md`](docs/00-research-and-plan.md) — current state of the
ecosystem, corrections to the original brief, PSCT v0 draft data model, and the build order.

## Short version

CKB has partial-signing workflows (`ckb-cli`, Neuron, CCC) but no cross-tool container, no resolved cell
data in the signed payload, and no open-source offline signer. Closed air-gapped CKB signing exists
(SafePal S1); an open standard does not.

## Artifacts (planned)

| Path | What |
|---|---|
| `docs/` | Research, PSCT v0 spec, signing-profile registry, Phase 0 findings |
| `packages/psct-core` | Schema, digest, inspect, verify, combine, finalize (TypeScript, dependency-light) |
| `packages/signer-core` | Independent implementation for the offline side (Rust or Python) |
| `apps/coordinator` | Watch-only web coordinator, animated QR in/out |
| `apps/signer` | Offline signer: CLI → browser → hardware image |
| `fixtures/` | Golden + hostile transaction corpus, raw molecule bytes |

## Status

Phase 0 (inspector + verifier) is running against mainnet:

- `tx_hash` reproduces the node on 25/25 transactions.
- Signatures verify on 25/25 secp256k1 lock groups.
- 6 offline-verifiable fixtures, including an 11-input transaction.
- The input-claim attack (fee inflation without touching the signed bytes) is reproduced and
  rejected by the binding check.

See [`docs/01-phase0-findings.md`](docs/01-phase0-findings.md).

```bash
cd packages/psct-core
npm install
npm test                                          # offline, no network
npm run redteam                                   # the attack demo
npx tsx src/cli.ts inspect <txhash>
```

## Start here

Phase 0 is the inspector/verifier over real mainnet transactions, not a spec document. See §7 of the
research note.
