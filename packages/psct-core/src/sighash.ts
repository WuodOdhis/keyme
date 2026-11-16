/** WitnessArgs + sighash-all signing message. */

import { concat, hexToBytes } from "./bytes.js";
import { ckbHash, txHash } from "./hash.js";
import { readBytes, readBytesOpt, readU32, tableOffsets, u64 } from "./molecule.js";
import type { Transaction } from "./ckb.js";

export interface WitnessArgs {
  lock: Uint8Array | null;
  inputType: Uint8Array | null;
  outputType: Uint8Array | null;
}

export function decodeWitnessArgs(w: Uint8Array): WitnessArgs {
  const offs = tableOffsets(w, 0, 3);
  const size = w.length;
  const end = (i: number) => (i + 1 < offs.length ? offs[i + 1]! : size);
  return {
    lock: readBytesOpt(w, offs[0]!, end(0)),
    inputType: readBytesOpt(w, offs[1]!, end(1)),
    outputType: readBytesOpt(w, offs[2]!, end(2)),
  };
}

export function encodeWitnessArgs(a: WitnessArgs): Uint8Array {
  const enc = (b: Uint8Array | null) => (b === null ? new Uint8Array(0) : concat(u32le(b.length), b));
  const fields = [enc(a.lock), enc(a.inputType), enc(a.outputType)];
  const header = 4 + 4 * fields.length;
  const total = header + fields.reduce((n, f) => n + f.length, 0);
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, total, true);
  let off = header;
  fields.forEach((f, i) => {
    dv.setUint32(4 + 4 * i, off, true);
    out.set(f, off);
    off += f.length;
  });
  return out;
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

/**
 * Sighash-all placeholder: the group's first witness with the lock field replaced by `sigLen`
 * zero bytes. This is what makes the message signature-length-dependent, and why a PSCT cannot
 * define one universal "empty slot".
 */
export function withZeroedLock(witness: Uint8Array, sigLen = 65): Uint8Array {
  if (witness.length === 0) {
    return encodeWitnessArgs({ lock: new Uint8Array(sigLen), inputType: null, outputType: null });
  }
  const args = decodeWitnessArgs(witness);
  return encodeWitnessArgs({ ...args, lock: new Uint8Array(sigLen) });
}

export function assertWitnessArgs(w: Uint8Array, where: string): void {
  if (w.length < 16) throw new Error(`${where}: witness too short for WitnessArgs (${w.length})`);
  const size = new DataView(w.buffer, w.byteOffset, w.byteLength).getUint32(0, true);
  if (size !== w.length) throw new Error(`${where}: not a table (size=${size}, len=${w.length})`);
}

/**
 * Multi-signature placeholder: zero the trailing signature region of the lock field, leaving the
 * lock field's length and every table offset untouched.
 *
 * The lock field is `[reserved][require_first_n][threshold][pubkeys_cnt][pubkey_hash × n][sig × t]`,
 * and the script hashes the witness with the last `65 * threshold` bytes zeroed.
 */
export function zeroSignatureRegion(witness: Uint8Array, sigBytes: number): Uint8Array {
  if (witness.length === 0) throw new Error("empty witness: expected WitnessArgs");
  const lockStart = tableOffsets(witness, 0, 3)[0]!;
  const lockLen = readU32(witness, lockStart);
  if (sigBytes > lockLen) throw new Error(`signature region ${sigBytes} exceeds lock length ${lockLen}`);
  const out = witness.slice();
  const dataStart = lockStart + 4;
  out.fill(0, dataStart + lockLen - sigBytes, dataStart + lockLen);
  return out;
}

/**
 * Sighash-all message for one lock group.
 *
 * blake2b( tx_hash
 *        || u64le(len(w0')) || w0'          // group's first input, transformed by the profile
 *        || u64le(len(wi))  || wi  ...      // other inputs sharing this lock
 *        || u64le(len(wj))  || wj  ... )    // witnesses with index >= inputs.length
 */
export function sighashMessage(
  tx: Transaction,
  groupIndices: number[],
  transformFirst: (witness: Uint8Array) => Uint8Array,
): Uint8Array {
  if (groupIndices.length === 0) throw new Error("empty script group");
  const sorted = [...groupIndices].sort((a, b) => a - b);
  const parts: Uint8Array[] = [hexToBytes(txHash(tx))];

  const first = sorted[0]!;
  const w0 = transformFirst(hexToBytes(tx.witnesses[first] ?? "0x"));
  parts.push(u64(w0.length), w0);

  for (const idx of sorted.slice(1)) {
    // The lock scripts load each group witness by index and break on CKB_INDEX_OUT_OF_BOUND.
    // A transaction with fewer witnesses than inputs therefore stops the message there; it is
    // not padded with empty witnesses.
    if (idx >= tx.witnesses.length) break;
    const w = hexToBytes(tx.witnesses[idx]!);
    parts.push(u64(w.length), w);
  }
  for (let i = tx.inputs.length; i < tx.witnesses.length; i++) {
    const w = hexToBytes(tx.witnesses[i]!);
    parts.push(u64(w.length), w);
  }
  return ckbHash(concat(...parts));
}

/** Sighash-all with the secp256k1-blake160 placeholder (65 zero bytes). */
export function sighashAllMessage(tx: Transaction, groupIndices: number[]): Uint8Array {
  return sighashMessage(tx, groupIndices, (w) => withZeroedLock(w, 65));
}

/** Lock field of a witness, or null if absent / not WitnessArgs. */
export function witnessLock(witnessHex: string): Uint8Array | null {
  const w = hexToBytes(witnessHex);
  if (w.length === 0) return null;
  try {
    return decodeWitnessArgs(w).lock;
  } catch {
    return null;
  }
}
