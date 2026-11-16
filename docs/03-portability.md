# Portability contract — what a second implementation must reproduce

Version: 1.0 — 2026-11-16
Audience: whoever writes the Rust (signer-side) implementation in stage 1.

`psct-core` is TypeScript, but the *rules* are the deliverable. This document lists exactly what a
second implementation has to match. If two implementations disagree on any line here, the spec is
wrong, not the code.

---

## 1. Scope

| In scope | Out of scope |
|---|---|
| Molecule encode/decode | Networking / RPC |
| `tx_hash`, sighash messages | Wallet UI |
| Input binding | Key management |
| Inspection (fee, tokens, DAO, Spore) | Persistence |
| Verification verdicts | — |

The signer-side port needs §2–§5. The RPC client and fixture loader are conveniences and can be
rewritten freely.

---

## 2. Molecule, exactly

Integers are little-endian. Sizes are bytes, not elements.

| Type | Encoding |
|---|---|
| `array [byte; N]` | N raw bytes, no prefix (`Byte32` = 32) |
| `struct` | fields concatenated, no header |
| `table` | `u32 total ‖ u32 offset × fields ‖ fields` (offsets from table start) |
| fixed vector | `u32 count ‖ items` |
| dynamic vector | `u32 total ‖ u32 offset × items ‖ items` (count implied by total) |
| `option<T>` | **zero bytes** for None, bare `T` for Some |
| `Bytes` (`vector <byte>`) | `u32 length ‖ data` |

Traps that cost time here:

- An empty dynamic vector is `04 00 00 00`; an empty fixed vector is `00 00 00 00`.
- `Bytes` has a **count** prefix, not a total-size prefix. A 65-byte value is `41 00 00 00 ‖ …`.
- A table's field count comes from the schema, never inferred from `total`.
- `Transaction` is `table { raw: RawTransaction, witnesses: BytesVec }`. `tx_hash` hashes the
  **six-field RawTransaction**, so witnesses are not part of it.

---

## 3. Hashing

- `blake2b-256` with personalisation `ckb-default-hash` (16 bytes), used for tx hashes, script
  hashes, header hashes and lock-arg comparison.
- `tx_hash = blake2b(molecule(RawTransaction))`.
- `script_hash = blake2b(molecule(Script))`.
- `header_hash = blake2b(molecule(Header))`; Header is a 208-byte struct:
  `u32 version ‖ u32 compact_target ‖ u64 timestamp ‖ u64 number ‖ u64 epoch ‖ 32 parent ‖
  32 tx_root ‖ 32 proposals ‖ 32 extra ‖ 32 dao ‖ u128 nonce`.
- DAO accumulate rate = bytes 8..16 of the header's `dao` field (u64 LE).

---

## 4. Sighash

### 4.1 Message

```
blake2b( tx_hash
       ‖ u64le(len(w0')) ‖ w0'            // first input of the group, transformed
       ‖ u64le(len(wi))  ‖ wi  …          // remaining group inputs, in ascending index order
       ‖ u64le(len(wj))  ‖ wj  … )        // witnesses with index >= inputs.len()
```

**Stop at the first missing witness.** The lock scripts call `ckb_load_witness` per index and break
on `CKB_INDEX_OUT_OF_BOUND`. A transaction with fewer witnesses than inputs does **not** pad with
empty entries. This applies to every profile.

### 4.2 Transform per profile

| Profile | First witness transform |
|---|---|
| secp256k1-blake160 | parse `WitnessArgs`, replace `lock` with 65 zero bytes, re-serialise |
| multisig legacy / V2 | keep the lock field length; zero only its trailing `65 × threshold` bytes |
| DAO | same as secp (the DAO rule lives in the type script, not the lock) |

For a missing first witness, secp uses a default `WitnessArgs` with a 65-byte zero lock; in practice
the group's first input always carries one.

### 4.3 Lock offsets

- secp: signature is the 65-byte lock field: `r(32) ‖ s(32) ‖ recid(1)`; recover, blake160, compare
  with `lock.args`.
- multisig lock field: `[0][require_first_n][threshold][pubkeys_cnt][pubkey_hash × n][sig × t]`
  with exact length `4 + 20n + 65t`. Script hash in args is `blake160` of the first `4 + 20n` bytes.
  Signatures match the first unused pubkey (order-independent); then the first `require_first_n`
  positions must be used.

---

## 5. Profiles

### 5.1 DAO

- Cell data is 8 bytes: `0` = deposit, otherwise the deposit block number.
- Withdraw phase 2:
  - witness `input_type` is 8 bytes; **only byte 0** is the `header_deps` index (the rest is ignored
    by the script, but should be zero).
  - the referenced header's `number` must equal the cell data.
  - input `since` flags must be `0x20` (absolute epoch), and the epoch must be ≥ deposit epoch + 180,
    comparing the fraction as `index × other.length`.
- Interest: `occupied = 8 + data.len + (args.len + 33) per script present`;
  `counted = capacity − occupied`; `max = occupied + floor(counted × withdrawAR / depositAR)`;
  `fee = inputs + interest − outputs`.
- Phase 1 needs the header of the block containing the deposit cell (not in `header_deps`).

### 5.2 xUDT / sUDT

- Amount = first 16 bytes as u128 LE; trailing data allowed.
- xUDT args: `owner_hash (32) ‖ flags (u32 LE) ‖ extension data`.
- Owner mode: `flags & 0x80000000` → compare owner hash with **input type script** hashes;
  `0x40000000` → output type script hashes; otherwise input lock script hashes.
- The same code hash may appear with `hash_type: type` or `data1`; both are the same code.

### 5.3 Spore

- `SporeData` = table `{ content_type: Bytes, content: Bytes, cluster_id: BytesOpt }`.
- Type args = 32-byte id.
- Transfer requires byte-identical data; lock and capacity may change.
- No output with the id = melt; no input = mint.

---

## 6. Occupied capacity

Not the molecule size. From ckb's `capacity.rs`:

```
Script     = args.len + 32 + 1
CellOutput = 8 + data.len + lock + (type if present)
```

Table headers, vector prefixes and the option tag are excluded. Using the molecule size overstates
a typed cell by 64 bytes and silently understates DAO interest.

---

## 7. `since` (RFC-0017)

`flags = (relative << 7) | (metric << 5)` over the top byte of a u64:

| flags | meaning |
|---|---|
| `0x00` | absolute block |
| `0x20` | absolute epoch (with fraction) |
| `0x40` | absolute timestamp (ms) |
| `0x80` / `0xA0` / `0xC0` | relative block / epoch / timestamp |

Epoch value = `number (24) | index (16) | length (16)`.

---

## 8. Numeric handling

- u64/u128 must be arbitrary-precision integers (`bigint`, `u128`, `BigInt`), never floats.
- No `number` for capacity, amounts or since.
- JSON output encodes bigints as decimal strings.

---

## 9. Conformance procedure

1. Load every fixture in `packages/psct-core/fixtures` (transaction + input proofs + headers).
2. For each: recompute `tx_hash` and compare with the manifest.
3. Bind every input (previous transaction must hash to the outpoint; output index must match).
4. Run inspection and compare with the manifest `fee`.
5. Verify every lock group and compare verdicts with the TS results.
6. The Rust port is conformant when it produces identical values for all fixtures and identical
   verdicts on the hostile corpus.

`npm test` is the reference run. A Rust harness should read the same fixture files; do not copy the
TypeScript code book-for-book — the point is an independent reader.

---

## 10. Known Node-only code (safe to ignore in the port)

| File | Why |
|---|---|
| `src/cli.ts` | `process.argv`, exit codes |
| `src/fixtures.ts` | `node:fs` fixture loader |
| `src/scripts/*` | tooling |
| `src/hostile.test.ts` | `node:test`, `Buffer` |

Core modules (`molecule`, `ckb`, `hash`, `sighash`, `secp`, `verify`, `capacity`, `since`, `dao`,
`xudt`, `spore`, `bind`, `inspect`) have no Node dependencies.
