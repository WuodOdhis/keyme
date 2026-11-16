# @keyme/psct-core

Reference implementation for PSCT: molecule codec, sighash, input-proof binding, inspection and
verification.

Deliberately dependency-light (two audited crypto libs) so it can be ported to the signer's
language and compared byte-for-byte. **Do not add CCC here** — the coordinator may use CCC; this
package is the oracle.

## Commands

```bash
npm install
npm run typecheck
npm test                 # hostile corpus (17 tests) + offline fixture verification
npm run selftest         # live: 25 mainnet txs, hash + signature
npm run redteam          # the input-claim attack demo
npm run devnet:multisig  # 2-of-3 legacy spend against a local devnet (needs `offckb node`)
npx tsx src/cli.ts inspect <txhash>
npx tsx src/cli.ts verify  <txhash>
npx tsx src/cli.ts redteam [txhash]
npx tsx src/scripts/collect.ts 10   # add fixtures from mainnet
```

Add `--rpc testnet` to the CLI for testnet.

## Layout

```
src/
  bytes.ts        hex / bigint helpers
  molecule.ts     molecule codec (struct, table, vec, option, array)
  ckb.ts          CKB types + RPC JSON mapping + encoders
  hash.ts         blake2b("ckb-default-hash"), tx_hash, script hash
  sighash.ts      WitnessArgs, zeroed-lock placeholder, sighash-all message
  verify.ts       pubkey recovery, per-group verification
  cbor.ts         canonical CBOR for the PSCT envelope
  address.ts      bech32m addresses (short = bech32, full = bech32m)
  profiles.ts     lock/type registry: names + verifiability
  rpc.ts          minimal JSON-RPC client
  psct/
    container.ts  PSCT v0: encode/decode, build, combine, finalize
    bind.ts       hash-bind every input to its creating transaction
    inspect.ts    fee, deltas, change candidates, warnings - from bound data only
    proofs.ts     resolve proofs from a node (dev convenience)
  cli.ts
  fixtures.ts     fixture loading
  hostile.test.ts verifier acceptance tests
  psct.test.ts    container conformance tests
  scripts/
    selftest.ts   live hash/signature check
    offline.ts    fixture check, no network
    redteam.ts    the attack demo
    collect.ts    fixture collector
    make-vectors.ts  regenerate conformance vectors
    devnet-multisig.ts  2-of-3 legacy spend against a local devnet
    identify-lock.ts  name an unknown code hash from its deployment cell
fixtures/         transactions + proofs + manifest
vectors/          signed PSCT conformance vectors (base64)
```

## Invariants

1. Nothing is displayed from a label. Everything comes from bytes that were hash-bound.
2. An unbindable input is a hard failure, never a warning.
3. Unknown lock profile ⇒ refuse to verify, do not guess.
4. Token amounts are reported only for 16-byte data (xUDT). Everything else is "unknown".
5. `tx_hash` is over `RawTransaction`; witnesses are not included.
