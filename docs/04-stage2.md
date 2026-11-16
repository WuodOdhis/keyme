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
