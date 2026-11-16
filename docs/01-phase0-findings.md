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

Six mainnet fixtures in `packages/psct-core/fixtures`. The offline test (`npm test`) re-hashes,
re-binds, and re-verifies all of them with no RPC:

```
fixtures              8
groups verified       9
refused: no profile   0
refused: unknown lock 0
failures              0
```

### Corpus quality gate

The first collection pass was misleading: one transaction contributed four "unknown locks" that were
not user wallets at all, but custom locks belonging to an L2 settlement system. Naming them was a dead
end — they are outside this project's threat surface, and the project has no reason to model them.

What changed:

- `collect.ts` now skips any lock that is not in the registry, so fixtures represent signable
  payments rather than L2 bookkeeping.
- The registry only carries scripts this project actually cares about: the standard user locks and the
  type scripts we decode. Anything else is `unknown` and refused. That is the correct outcome either
  way, so there is no need to enumerate the world.
- Lesson kept: **input count is not a proxy for kind.** Fixture selection must filter by lock class,
  not by shape. The same mistake had already made a test flip the wrong witness.

Use `npx tsx src/scripts/identify-lock.ts <codeHash>` to inspect any future unknown lock: it finds a
fixture that uses it and dumps readable strings from the deployment cell.

## 6. Hostile corpus, executable

`src/hostile.test.ts` runs under `npm test` (26 tests). It is the acceptance criteria for D1:

| Case | Expected |
|---|---|
| inflated input capacity | bind rejects |
| previous tx that does not hash to the outpoint | bind rejects |
| index mismatch / swapped output / mutated data claim | bind rejects |
| proof count mismatch | bind rejects |
| changed output capacity | signature fails |
| changed `cell_dep` | signature fails |
| reordered inputs | nothing verifies |
| perturbed signature bytes | signature fails |
| malformed signature | verdict, never an exception |
| multisig: real 3-of-5 spend | verified |
| multisig: swapped signature order | still verified (order-independent) |
| multisig: zeroed signature / truncated lock | rejected |
| DAO withdraw: interest + fee reconcile | positive fee, interest shown |
| DAO withdraw without its header | interest unknown, warned |
| occupied capacity | flat field sum, 102 bytes for the DAO cell |
| unknown code hash | refused |
| known lock with no profile (OmniLock) | refused, named |

One fix came out of this: `recoverPublicKey` throws on a non-canonical signature. That is now caught and
reported as `bad-signature`, because a verifier that crashes on hostile input is itself a denial of
service.

## 7. What this changes in the spec

- `input_proofs[].prev_tx` is mandatory (already reflected in §6.1).
- PSCT partial signatures are keyed by **script group**, not by input.
- The signer must know, per profile, the exact placeholder length. v0 only ships
  `sighash-all/secp256k1-blake160/v1`; multisig needs its own placeholder and ordering rules.
- An empty witness is not "no witness": it is a 16-byte empty `WitnessArgs` for sighash-all.

## 8. Multisig (stage 0.1 / 0.2)

Rules derived from `ckb-system-scripts/c/secp256k1_blake160_multisig_all.c`, not from docs:

```
script args   = blake160(multisig_script) [20B] + optional since [8B LE]
multisig_script = [0][require_first_n][threshold][pubkeys_cnt][pubkey_hash × n]
witness lock  = multisig_script + [signature × threshold]        (exact length, no padding)
```

Three things make it different from a single-key lock:

1. **The placeholder is not 65 zero bytes.** The lock zeroes the trailing `65 × threshold` bytes of
   the lock field in place, so the witness length and every table offset stay unchanged.
2. **Signatures are matched, not slotted.** Each signature is recovered and matched to the first
   unused pubkey hash. Order is therefore not required — but canonical finalization should order by
   pubkey position so the result is deterministic.
3. **`require_first_n` is positional.** After threshold matching, the first N pubkey positions must
   all be used.

Optional `since` in args is enforced with `check_since`: every group input must carry the same since
flags and a value at least as large, with epoch-fraction comparison for the epoch flag.

### Evidence

Validated against a real mainnet **3-of-5** spend: the fiber-scripts PR #34 upgrade transaction
`0x4396de69818bd88b7fce64797ccec25d1294912d56846432f29fd192120992ee`.

- lock: `Secp256k1MultisigV2`, `hash_type: data1`, 20-byte args (no since)
- witness lock field: 299 bytes = 4 + 20×5 + 65×3
- 3 signers recovered and matched; `require_first_n = 0`
- fee: 81,893 shannons
- verified offline from the deploy file's embedded `used_input_txs` — no RPC at verify time

That fixture is 1.27 MB because the transaction is a contract deployment, so the spent cell's data is
a compiled binary. It is committed as-is; if repo size becomes a problem, the fix is fetch-on-demand
with a pinned hash, not dropping the proof.

Legacy multisig is implemented from the same source but has not yet appeared in the corpus. Stage 0.1
needs one observed legacy spend before it can be called closed; until then it is "implemented, V2
validated".

## 9. Nervos DAO (stage 0.3)

Two shapes of DAO input cell, distinguished by their 8-byte data:

| cell | data | spent in |
|---|---|---|
| deposit | `0` | withdraw phase 1 (prepare) |
| withdrawing | deposit block number | withdraw phase 2 (withdraw) |

Rules read from `dao.c`:

- **Phase 1**: output at the same index must be a DAO cell with the same capacity, and its data
  must equal the block number of the block containing the input cell.
- **Phase 2**: the witness `input_type` is 8 bytes, and the script reads **only the first byte** as an
  index into `header_deps`. That header is the deposit block; its number must equal the cell data.
  The input `since` must have flags `0x20` (absolute epoch) and be at least deposit epoch + 180.

### Two bugs this exposed

**Occupied capacity is not the molecule size.** ckb's `capacity.rs` computes:

```
Script     = args.len + 32 + 1
CellOutput = 8 + data.len + lock + (type if present)
```

Table headers, vector prefixes and the option tag are *not* counted. My first version used the
molecule size, overstating a typical typed cell by 64 bytes. That understated DAO interest by
0.103 CKB and made the fee look negative. It also made every "storage cost" figure wrong.

**The fee is not `inputs - outputs`.** A DAO withdrawal *mints* interest, so outputs legitimately
exceed inputs. The fee is `inputs + interest - outputs`. A signer that rejects a negative delta would
refuse every valid withdrawal.

### Evidence

Real mainnet withdraw `0xfdf1c26c9d4eae42e6e53d3ea6ad9490fc01e9d17ed1bcd09c9eef51232bc160`:

- deposit block 20,752,684 (epoch 15125.568/1702), withdrawn at 21,018,543
- deposit header and the withdrawing cell's block header both supplied and hash-checked
- interest **393.99530246 CKB**, fee **936 shannons**
- balloon: 4.6 KB fixture (two 208-byte headers, hex-encoded)

Phase 1 is implemented from the same source but no prepare transaction appeared in 500 scanned
blocks. Like legacy multisig, it is "implemented, not yet observed".

### Consequence for PSCT

A withdraw proof needs **two headers**: the deposit header (already in `header_deps`) and the header
of the block that created the withdrawing cell, which is not in the transaction at all. That is why
`InputProof` carries `blockHash` and the fixture carries a header map. Stage 1 must treat headers as
first-class proof data, not an optional convenience.

## 10. Next

1. Profiles for the user-facing locks that still have none: OmniLock, the three multisig deployments,
   JoyID, NostrLock. Multisig first — it is the actual treasury use case and it exercises the
   placeholder/ordering rules.
2. Collect labelled fixtures: DAO deposit, DAO withdraw (headers + `input_type`), xUDT transfer,
   Spore create/transfer, 2-of-3 multisig.
3. Then write `spec/psct-v0.md` as a description of what the verifier enforces.
