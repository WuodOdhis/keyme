# PSCT v0 — Partially Signed CKB Transaction

Status: **frozen** for stage 1. 2026-11-16.
Reference implementation: `packages/psct-core/src/psct/container.ts`.
Conformance vectors: `packages/psct-core/vectors/`.

---

## 1. Purpose

PSCT is an interchange format for a CKB transaction that is not fully signed, together with the
evidence a signer needs to verify it without a network.

It exists because CKB's signing message does **not** commit to the capacity, lock, type or data of
the cells being spent. A signer that trusts a supplied `CellOutput` can be made to approve an
enormous fee. Therefore the format carries, for every input, the transaction that created it, and
the signer hash-binds each claim before displaying anything.

Three roles use it:

- **Coordinator** (online, watch-only): builds the transaction, resolves proofs, combines signatures.
- **Signer** (offline): binds, verifies, displays, signs.
- **Broadcaster**: finalizes and submits.

---

## 2. Transport

```
magic   = 70 73 63 74        ("psct")
version = 00
body    = canonical CBOR
```

A file is `magic ‖ version ‖ CBOR`. Base64 of a PSCT therefore starts with `cHNjdAA`.

### 2.1 Canonical CBOR

Only this subset is allowed:

| Type | Encoding |
|---|---|
| unsigned integer | major 0, shortest form, up to u64 |
| byte string | major 2 |
| text string | major 3, valid UTF-8 |
| array | major 4 |
| map | major 5, **text keys**, sorted by encoded key length then bytewise |
| false / true / null | `f4` / `f5` / `f6` |

Rejected: indefinite lengths, tags, floats, negative integers, duplicate map keys, non-minimal
integers, trailing bytes. A non-canonical input is an error, not something to normalise.

---

## 3. Envelope

Top-level map. Unknown keys **must be preserved** verbatim and re-emitted.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `psct` | uint | yes | format version, `0` |
| `network` | text | yes | `"ckb"` or `"ckt"` |
| `tx` | bytes | yes | molecule `RawTransaction` (six fields, **witnesses emptied**) |
| `witness_templates` | array | yes | one entry per witness in the original transaction; index-aligned with inputs |
| `input_proofs` | array | yes | one per input, index-aligned |
| `headers` | array of bytes | yes | raw 208-byte headers, at most one per hash |
| `account` | map | no | advisory account hint from the coordinator |
| `inputs` | array | no | derivation hints, index-aligned |
| `outputs` | array | no | role hints, index-aligned |
| `sigs` | map | yes | `script_hash → [signature]` |
| `meta` | any CBOR | no | advisory only; **never rendered as fact** |

### 3.1 `witness_templates[i]`

A witness is not only a signature. DAO stores a header index in `input_type`; xUDT stores extension
data in `output_type`. Emptying witnesses would make the signed message unreconstructable.

```
{ "input_type": bytes?, "output_type": bytes?, "lock_template": bytes? }
```

- `input_type` / `output_type`: the non-signature fields of `WitnessArgs` for that index.
- `lock_template`: only for multisig. The lock field with its trailing `65 × threshold` signature
  bytes zeroed. Finalize uses it to assemble signatures in pubkey order.

A template present for an input that has no witness in the original transaction is invalid: the
array length must equal the original witness count. A transaction with fewer witnesses than inputs
is legal, and the signing message stops at the first missing witness.

### 3.2 `input_proofs[i]`

```
{ "prev_tx": bytes, "index": uint, "block_hash": bytes? }
```

- `prev_tx` is the creating transaction as `RawTransaction` (**witness-free**). The signer recomputes
  its blake2b hash and compares it with `tx.inputs[i].previous_output.tx_hash`.
- `index` must equal the outpoint index.
- `block_hash` is the block containing the creating transaction. Required for DAO interest and
  useful for `since`. It is not itself hash-bound; a signer that needs it must have the header.

### 3.3 `headers`

Raw headers. The signer indexes them by `blake2b(header)`, and every `header_deps` entry used by the
transaction must be present. A DAO withdraw also needs the header of the block that created the
withdrawing cell (`input_proofs[i].block_hash`).

### 3.4 `sigs`

```
"0x<script_hash>": [
  { "signer": bytes, "signature": bytes, "profile": text }
]
```

- Key: `blake2b(molecule(Script))` of the **lock script**, not the input index. CKB signs per script
  group.
- `signer`: the public key hash (20 bytes) for the profiles in §5.
- Signatures are order-independent. Finalization imposes the order the lock requires.
- Two different signatures for the same `(script_hash, signer)` is a conflict, not a merge.

### 3.5 Hints

`account`, `inputs[].derivation`, `outputs[].role` are hints. A signer **must** ignore them for
truth: the account must match its own paired account, change must be re-derived, and a role is never
rendered as fact.

---

## 4. Digest and display

- `tx_hash = blake2b(RawTransaction)`, identical to the network's transaction hash.
- Display fingerprint: first 10 hex characters, ellipsis, last 4. Both screens show it so a user can
  compare.
- It covers: version, cell deps, header deps, inputs, outputs, output data.
- It does **not** cover: witnesses, proofs, hints, signatures. Those are validated separately.

A signer should show the fingerprint on the approval screen and on the result. If the coordinator's
screen and the device disagree, nothing is signed.

---

## 5. Profiles

A profile names the signing rules for one lock script. Finalization refuses a lock it has no profile
for.

| Profile | Lock | Finalize |
|---|---|---|
| `sighash-all/secp256k1-blake160/v1` | Secp256k1Blake160 (`type`) | witness lock = the 65-byte signature |
| `sighash-all/multisig-legacy/v1` | secp256k1-blake160 multisig (`type`) | assemble `flags + sigs` in pubkey order |
| `sighash-all/multisig-v2/v1` | Secp256k1MultisigV2 (`data1`) | same, different deployment |

Other locks are named by the registry but refused: OmniLock, JoyID, NostrLock, anyone-can-pay, and
anything unknown.

Type scripts (DAO, xUDT, Spore, custom) are not signed per se; their witness fields are preserved
through `witness_templates` and their effects are checked during inspection.

---

## 6. Combine

```
combine(a, b) -> c
```

- `network`, `tx`, `witness_templates` and `input_proofs` must be identical.
- Headers are unioned by hash.
- Signatures are merged by `(script_hash, signer)`; identical duplicates collapse, differing
  signatures from the same signer are an error.
- Unknown top-level keys are preserved; a differing value for the same unknown key is an error.
- `combine` is commutative and associative. Encoding the result is deterministic (headers sorted by
  hash).

---

## 7. Finalize

1. Bind every input against `input_proofs`. Any mismatch aborts.
2. Group inputs by lock script hash.
3. For each group, look up its profile:
   - secp: take the matching signature; the lock field is exactly 65 bytes.
   - multisig: decode `lock_template`, assemble the available signatures in pubkey order, respect
     `require_first_n` and `threshold`.
   - no profile: abort.
4. Rebuild every witness as `WitnessArgs{ lock, input_type, output_type }` from the template and the
   group lock. Group members other than the first carry no lock.
5. Verify the result with the same verifier the signer used. **If any group is not verified, throw.**
   Finalization never returns a transaction it cannot prove.

---

## 8. Rejection rules (non-negotiable)

| Condition | Result |
|---|---|
| magic or version wrong | reject |
| non-canonical CBOR | reject |
| unknown network | reject |
| `input_proofs` count ≠ inputs | reject |
| proof hash ≠ outpoint tx hash | reject |
| proof index ≠ outpoint index | reject |
| witness template non-empty for a missing witness | reject |
| unknown lock profile | refuse to finalize |
| required header missing | refuse to display DAO figures; interest unknown |
| signature conflict on combine | reject |
| finalized tx does not verify | throw |

---

## 9. What v0 does not carry, and why

- **Cell dep proofs.** Code identity is anchored in the lock's `code_hash` plus the signer's
  registry. For `data`/`data1`/`data2` the hash is the code; for `type` the registry pins the
  deployment. A signer does not accept an unknown code hash. Carrying dep cells would add weight
  without adding a safety property.
- **Labels.** They belong in the signer's trusted database, never in the file.
- **Encryption.** The format is public data. Transport confidentiality is out of scope.
- **QR framing.** Stage 3 wraps these same bytes; the format does not change.

---

## 10. Vectors

`packages/psct-core/vectors/`:

| File | Note |
|---|---|
| `0xd45dcad9….psct.b64` | single-key secp256k1, 3 inputs |
| `0x4396de69….psct.b64` | 3-of-5 multisig (large: contract-deployment proof) |
| `0xfdf1c26c….psct.b64` | Nervos DAO withdraw, 2 headers |

`manifest.json` records `tx_hash`, `fingerprint`, input/output counts, `final_tx_hash` and
`full_tx_hash` for each. `tx_hash` and `final_tx_hash` are the same value because transaction hashes
exclude witnesses; `full_tx_hash` is `blake2b(molecule(Transaction))` over the **finalized** bytes and
therefore covers witness assembly, signature order and templates.

A second implementation is conformant when it decodes each file, reproduces `tx_hash`, finalizes to
`full_tx_hash`, and verifies every signature. `packages/psct-rs` is that implementation; run
`npm run conformance` from `packages/psct-core` to compare it with this manifest.

---

## 11. Versioning

- The version byte and `psct` field must agree.
- New optional fields do not bump the version; unknown keys must be preserved.
- A change to existing field semantics, canonical encoding, or the digest requires version 1.
