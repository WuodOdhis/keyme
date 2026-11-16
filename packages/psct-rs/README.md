# psct-rs

Independent Rust implementation of PSCT v0, used as a conformance check against the TypeScript
reference. It is deliberately not a line-by-line port: it has its own CBOR decoder, molecule codec,
sighash framing and finalizer.

What it proves:

- decodes the PSCT envelope and rejects non-canonical CBOR
- reproduces `tx_hash` from the raw transaction bytes
- finalizes witnesses (secp256k1 and multisig) and reproduces `full_tx_hash` byte-for-byte
- recovers every signer and matches the lock args

## Build

```bash
cargo build --release
```

On Windows without the MSVC linker (Visual Studio Build Tools), use the GNU toolchain:

```bash
cargo +stable-x86_64-pc-windows-gnu build --release
```

## Run

```bash
target/release/psct-rs ../psct-core/vectors/*.psct.b64
```

One JSON line per file:

```json
{ "file": "...", "network": "ckb", "tx_hash": "0x…", "full_tx_hash": "0x…",
  "groups": [{ "script_hash": "…", "profile": "…", "verdict": "verified", "signers": ["…"] }],
  "ok": true }
```

Exit code is non-zero if any group is not verified.

## Conformance

From `packages/psct-core`:

```bash
npm run conformance
```

compares the Rust output with `vectors/manifest.json`.

## Layout

```
src/cbor.rs      canonical CBOR subset
src/molecule.rs  molecule decode/encode, sighash framing
src/psct.rs      envelope, finalize, verify
src/main.rs      CLI
```

## Dependencies

`base64`, `blake2b_simd`, `secp256k1` (with recovery), `serde_json`.
