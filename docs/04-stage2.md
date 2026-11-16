# Stage 2 demo — coordinator + offline signer

Status: working on a local devnet. 2026-11-16.

The point of this stage is that the format stops being a specification and becomes a workflow: an
online coordinator builds a PSCT, an offline signer inspects and signs it, a third step combines and
broadcasts. No private key ever reaches the coordinator.

---

## 1. Pieces

| Piece | File | Holds keys? |
|---|---|---|
| Coordinator | `src/apps/coordinator.ts` | no |
| Signer | `src/apps/signer.ts` | reads a key file, never the network |
| Demo | `src/apps/demo.ts` | devnet only |

Shared: `buildTransfer` (live-cell selection, proofs, PSCT), `signPsct` (bind, refuse, sign,
self-check), `finalizePsct` (assemble witnesses, verify or throw).

---

## 2. Coordinator

```bash
npm run coordinator -- transfer \
  --network devnet --from <address> --to <address> --amount 100 \
  --out transfer.psct.b64

# multisig: the signer set and threshold are the coordinator's business, not the file's
npm run coordinator -- transfer --network devnet \
  --signers <a>,<b>,<c> --threshold 2 --to <address> --amount 100 \
  --out spend.psct.b64
```

What it does:

1. Decodes the address into a lock script.
2. Queries live cells (`get_cells`) for that lock.
3. Selects cells until the change is zero or at least 61 CKB.
4. Rejects outputs below their occupied-capacity minimum (the first demo run failed exactly here:
   a 10 CKB output is not a valid cell).
5. Resolves every input's creating transaction into the PSCT.
6. For multisig, attaches the lock template (script part with the signature region zeroed).

```bash
npm run coordinator -- combine a.psct.b64 b.psct.b64 --out c.psct.b64
npm run coordinator -- finalize c.psct.b64 --out tx.json
npm run coordinator -- send tx.json --network devnet
```

---

## 3. Signer

```bash
npm run signer -- show transfer.psct.b64
npm run signer -- sign transfer.psct.b64 --privkey-file key.hex --out signed.psct.b64 --yes
```

`show` prints the fingerprint, fee, every output with its role and address, the lock groups, and all
inspection warnings. `sign` does the same, then:

- binds every input; a mismatch aborts before the prompt;
- refuses the whole transaction if any lock has no modelled profile (OmniLock, JoyID, unknown);
- refuses if a DAO input has unresolved issues (missing header, since mismatch);
- prompts unless `--yes`, and refuses to sign non-interactively without it;
- adds one signature per script group the key controls;
- **self-checks** the signature by recovering the pubkey and comparing it with the lock args before
  writing anything.

For multisig it adds one signature; a second signer produces a second file. `combine` merges them
commutatively; `finalize` orders them by pubkey position and verifies the result.

---

## 4. Observed run

`npm run demo` against `offckb node`:

```
== secp transfer
coordinator: 0xf7a35ec8…0bc5 inputs=1
signer:      groups=1 signer=0x8e42b199…
transfer: committed in 26812

== 2-of-3 legacy multisig
multisig ckt1qpw9q60…quzxn3x
fund: committed in 26815
coordinator: 0x983d3604…ce68 inputs=1
signer 1:    0x758d311c…
signer 2:    0x9ed1debe…
spend: committed in 26818
```

The spend transaction was built with no key present, signed by two separate processes, combined, and
accepted by consensus. That is the stage-2 exit criterion, on devnet.

### Testnet

The same code path against `https://testnet.ckb.dev`, funded from the Pudge faucet:

```
from ckt1qyqwafr8dknhpd5v6n7u4kvxrgmms4pef0cs79x3um
coordinator 0xbb10d0b6…1a85 inputs=1 fee=1000
signer      0xeea4676d… groups=1
sent        0xbb10d0b6fb9ad72f6618f29020a1f065e73b4435f5ce24515afcbcb5c50a1a85
committed in 23084406
```

Only the network dep table changed. No code was forked for testnet.

---

## 6. Paired account (R3)

The signer can be given an account xpub at setup. It then derives its own external and change locks
(BIP32, `m/44'/309'/0'` mainnet, `m/44'/1'/0'` testnet, `/0/i` external, `/1/i` change) and checks:

- the PSCT's account xpub and fingerprint match the paired account;
- an output claiming to be change actually derives from the account;
- an output that derives from the account is change even if the file calls it a payment.

`npm run pairing-demo` on devnet:

```
account 0x61db34b5
external ckt1qyqgwkx638mu742azjfg9dg6atr5whyufk4sl4p2wf
change   ckt1qyqfrejz0zpfx0r7qfja8pr53zj5k9cqcumqxhsqsg
coordinator 0xa6d9e3af…0ae9
outputs
  0             100 CKB  payment  ckt1qyqfve0x…
  1       399.99999 CKB  CHANGE   ckt1qyqfrejz0…
signer 0x8758da89… groups=1
spend: committed in 26837
```

The change output is on the change chain, not the input's own lock. Before pairing, the signer would
have had to guess; now it derives.

The xpub uses the Bitcoin version bytes (`xpub`/`tpub`) because CKB has no xpub standard of its own.
The derivation and address rules are CKB's (`m/44'/coin'/0'`, blake160 locks); the encoding is
BIP32's.

---

## 7. Nervos DAO

`npm run dao-demo` (needs 1-block epochs, see §9):

```
tip epoch 100
deposit 0xe3b88299…  committed in 105
prepare 0x5cafab59… (deposit block 105)  committed in 211
waiting for epoch 285 …
withdraw 502.69385601 CKB (interest 2.69386601), since epoch 285
committed in 492
```

Three rules made this harder than it looks:

1. **Phase 1 needs the deposit header in `header_deps`.** Without it the node rejects the prepare.
2. **Phase 2 needs two headers.** The witness points at the deposit header (index 0), and the fee
   calculator also requires the withdrawing cell's block header in `header_deps`. Missing the second
   gives `PoolRejectedMalformedTransaction: InvalidOutPoint`, which sounds like a bad outpoint and is
   actually a missing header.
3. **The lock period rounds elapsed epochs up to a multiple of 180.** A deposit prepared at +181
   epochs cannot withdraw until +360. `minimalSince` reproduces the contract's rounding and is
   unit-tested.

The signer refuses a DAO withdraw unless it can see both headers and recompute the interest.

## 8. xUDT

`npm run xudt-demo`:

```
mint     1000000 units, 1000 CKB cell   committed in 530
transfer 400000 units, change 600000    committed in 533
```

Minting needed no special deployment: an xUDT is `owner_lock_script_hash ‖ flags`, and owner mode is
true because the input lock hashes to the declared owner. The transfer spends one token cell and
creates two (recipient + change) with the same type script.

## 9. Devnet epochs

The stock offckb devnet uses 1800-block epochs, which makes a 180-epoch DAO cycle impossible. For the
DAO run the chain spec was edited to `genesis_epoch_length = 1`, `epoch_duration_target = 1`, the chain
data removed, and the bundled `ckb` binary started directly (`ckb -C <dir> run`, `ckb -C <dir> miner`).
`offckb clean` followed by `offckb node` restores the stock spec.

This is a local test environment, not a product configuration; it is recorded so the numbers above can
be reproduced.

---

## 5. Known limits

- **Devnet only so far.** The same code targets mainnet/testnet (network dep table in
  `src/network.ts`), but no testnet run has been recorded. That is 2.5 in the plan.
- **Web UI pending.** The coordinator is a CLI. The plan calls for a watch-only web app; the builder
  it needs is the same `buildTransfer`.
- **xpub pairing pending.** The coordinator identifies the sender by address, not by an extended
  public key with a derivation path. Change verification already works from the lock, but the
  signer-side "this is your change" check needs the account pairing from D1.
- **No QR.** Files only; QR is stage 3. The bytes will not change.
