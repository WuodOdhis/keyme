# Phase 0 findings — molecule, sighash, and the input-claim attack

Date: 2026-11-15
Code: `packages/psct-core`
Status: core verified against mainnet; fixtures offline-verifiable

---

## 1. The attack is real, and it is cheap to demonstrate

Command:

```
npx tsx src/scripts/redteam.ts 0x00b6d14f5567f2076ed3f975783b0cafda297a74795cef44803cfc265197c7cb
```

Output (abridged):

```
1. honest coordinator (every cell bound to its outpoint)
   input capacity   1130.98841 CKB
   output capacity  1130.98811 CKB
   fee              0.0003 CKB

2. malicious coordinator (input 0's claimed capacity inflated 1000x)
   displayed fee    399600.0003 CKB
   real fee         0.0003 CKB
   hidden overpay   399600 CKB  -> miner

3. binding check
   result           REJECTED
   reason           capacity claim 40000000000000 != bound 40000000000

4. signature check (unchanged by the lie)
   sighash identical yes
   signature valid   yes
```

The important part is step 4. The transaction never changes, so the signature never changes.
Only the number on the signer's screen changes. A signer that trusts an unbound `CellOutput`
approves a 399,600 CKB fee as if it were 0.0003 CKB.

This is why rule 0 ("bind before you believe") exists, and why a PSCT must carry the creating
transaction per input, not just a resolved cell.

## 2. Molecule facts that were wrong in my first pass

All verified by byte-comparing our encoder against a node's serialization, and by recomputing
hashes and recovering signatures.

| Thing | Reality | Consequence |
|---|---|---|
| `Transaction` | `table { raw: RawTransaction, witnesses: BytesVec }` — **not** a flat 7-field table | `tx_hash = blake2b(RawTransaction)`; the witness wrapper is a separate nesting level |
| `Byte32` | `array [byte; 32]` — raw 32 bytes, no prefix | `OutPoint` = 36 bytes |
| `Bytes` | `vector <byte>` → fixed-size item → **count prefix, no total** | a 65-byte lock is `41 00 00 00 ‖ sig` (69 bytes), not `45 00 00 00 ‖ sig` |
| `option<T>` | **zero bytes** for None, bare `T` for Some | no 8-byte union header; an empty `WitnessArgs` is 16 bytes of `10 00 00 00` |
| dynamic vector | `total | offsets… | items`, count implied by total | empty = `04 00 00 00` |
| fixed vector | `count | items` | empty = `00 00 00 00` — different from an empty dynamic vector |
| `dep_type` in JSON | `"dep_group"`, not `"depGroup"` | silently defaults to `code` and changes the serialized bytes |
| table decoding | field count comes from the **schema**, not from `size` | inferring it from size reads 20 offsets for a 3-field table |

## 3. Signing mechanics confirmed

- Sighash-all message framing verified on mainnet:
  `blake2b(tx_hash ‖ u64le(len)‖w0' ‖ …)`, with the group's first witness' lock replaced by
  65 zero bytes.
- **One signature per lock group**, placed on the group's first input. Other inputs in the same
  group carry an empty `WitnessArgs` (16 bytes). Our first selftest wrongly expected a signature
  per input; the mainnet data corrected it.
- `tx_hash` matched the node on 25/25 transactions; signature recovery matched the lock args on
  25/25 lock groups.

## 4. Inspection is honest before it is complete

`inspect` currently reports:

- fee = Σ bound input capacity − Σ output capacity;
- `ckb` delta (equals −fee) and `ckb-locked` (capacity sitting inside typed cells);
- token deltas **only** when the cell data is 16 bytes (the xUDT convention);
- an explicit "semantics unknown" warning for any other typed cell.

That last point came from a real transaction: two typed cells with 2-byte and 10-byte data. A
naive inspector would have reported "token moved, delta 0" — a lie. It now says it does not know.

## 5. Fixtures

Six mainnet fixtures in `packages/psct-core/fixtures`, including an 11-input transaction. The
offline test (`npm test`) re-hashes, re-binds, and re-verifies all of them with no RPC:

```
fixtures              6
groups verified       6
groups w/o profile    4
failures              0
```

The four unprofiled lock code hashes turned out to be **Godwoken L2 infrastructure locks**, not user
wallets. All four appear in a single fixture transaction (`0x10c4c285…`), and their deployment cells
contain `gw-utils/src/cells/lock_cells.rs`, `custodian-lock/src/entry.rs` and `stake-lock/src/entry.rs`.

Consequences:

- They are now registered as `kind: "infrastructure"` and refused by name, not as "unknown".
- The fixture was misleading: four "unknown locks" were really one L2 settlement transaction.
- `collect.ts` now skips infrastructure and unknown locks so future fixtures represent signable
  payments. The Godwoken fixture is kept deliberately as a refusal case.

```
fixtures              6
groups verified       6
refused: L2/infra     4
refused: no profile   0
refused: unknown lock 0
failures              0
```

Use `npx tsx src/scripts/identify-lock.ts <codeHash>` to repeat this for any future unknown lock: it
finds a fixture that uses it and dumps readable strings from the deployment cell.

## 6. What this changes in the spec

- `input_proofs[].prev_tx` is mandatory (already reflected in §6.1).
- PSCT partial signatures are keyed by **script group**, not by input.
- The signer must know, per profile, the exact placeholder length. v0 only ships
  `sighash-all/secp256k1-blake160/v1`; multisig needs its own placeholder and ordering rules.
- An empty witness is not "no witness": it is a 16-byte empty `WitnessArgs` for sighash-all.

## 7. Next

1. Identify the remaining lock kinds that matter for users (OmniLock, multisig deployments, JoyID,
   NostrLock are named in the registry but have no profile).
2. Collect labelled fixtures: DAO deposit, DAO withdraw (headers + `input_type`), xUDT transfer,
   Spore create/transfer, 2-of-3 multisig.
3. Implement the hostile corpus as assertions, not demos (forged capacity, wrong prev-tx hash,
   index mismatch, substituted `cell_dep`, mutated `outputs_data`, dark `since`).
4. Then, and only then, write `spec/psct-v0.md` as a description of what the verifier enforces.
