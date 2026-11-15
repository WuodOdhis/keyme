/**
 * Minimal molecule codec for the CKB subset PSCT needs.
 *
 * Written from the molecule spec + ckb's blockchain.mol, not copied from an SDK, because this is
 * the reference implementation the signer will be compared against.
 *
 * Rules (verified against real mainnet transaction hashes in src/scripts/selftest.ts):
 *   struct        = fields concatenated (no size prefix)
 *   table         = u32 total | u32 offset per field | fields        (offsets from struct start)
 *   fixed vec     = u32 count | items                                (items fixed-size, e.g. Byte32, structs, Bytes)
 *   dynamic vec   = u32 total | u32 offset per item | items          (count implied by total; empty = 0x04000000)
 *   option<T>     = zero bytes (None) | T's encoding (Some)
 *   array [T; N]  = N items, no prefix                                (Byte32 = 32 raw bytes)
 *
 * Note: `Bytes` is `vector <byte>` => fixed-size item => count prefix, no total.
 * That is why a 65-byte lock field serialises as `0x41 00 00 00 || sig`.
 */

import { concat } from "./bytes.js";

export function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

export function u64(n: bigint | number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

export function byte(n: number): Uint8Array {
  return Uint8Array.of(n);
}

export function struct(...fields: Uint8Array[]): Uint8Array {
  return concat(...fields);
}

/** array [byte; 32] */
export function byte32(b: Uint8Array): Uint8Array {
  if (b.length !== 32) throw new Error(`Byte32 expects 32 bytes, got ${b.length}`);
  return b;
}

/** vector <byte> — count prefix only */
export function bytesVec(b: Uint8Array): Uint8Array {
  return concat(u32(b.length), b);
}

/** fixed-size item vector — count prefix only */
export function fixVec(items: Uint8Array[]): Uint8Array {
  return concat(u32(items.length), ...items);
}

/** dynamic-size item vector — total + offsets, count implied */
export function dynVec(items: Uint8Array[]): Uint8Array {
  if (items.length === 0) return u32(4);
  const header = 4 + 4 * items.length;
  const total = header + items.reduce((n, f) => n + f.length, 0);
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, total, true);
  let off = header;
  items.forEach((f, i) => {
    dv.setUint32(4 + 4 * i, off, true);
    out.set(f, off);
    off += f.length;
  });
  return out;
}

/** table — total + one offset per field */
export function table(...fields: Uint8Array[]): Uint8Array {
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

/** option<T> */
export function option(x: Uint8Array | null): Uint8Array {
  return x ?? new Uint8Array(0);
}

// ---------------------------------------------------------------- decoding

function dv(buf: Uint8Array) {
  return new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
}

export function readU32(buf: Uint8Array, off: number): number {
  return dv(buf).getUint32(off, true);
}

/** Table field offsets, absolute. A table's field count comes from the schema, not from size. */
export function tableOffsets(buf: Uint8Array, start: number, count: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < count; i++) out.push(start + readU32(buf, start + 4 + 4 * i));
  return out;
}

/** field slice of a table by index */
export function tableField(
  buf: Uint8Array,
  start: number,
  index: number,
  count: number,
): Uint8Array {
  const offs = tableOffsets(buf, start, count);
  const from = offs[index]!;
  const to = index + 1 < count ? offs[index + 1]! : start + readU32(buf, start);
  return buf.slice(from, to);
}

/** Bytes: count-prefixed */
export function readBytes(buf: Uint8Array, start: number): Uint8Array {
  const n = readU32(buf, start);
  return buf.slice(start + 4, start + 4 + n);
}

/** option<Bytes> */
export function readBytesOpt(buf: Uint8Array, start: number, end: number): Uint8Array | null {
  if (end <= start) return null;
  return readBytes(buf, start);
}

export const EMPTY_DYNVEC = Uint8Array.of(4, 0, 0, 0);
export const EMPTY_FIXVEC = Uint8Array.of(0, 0, 0, 0);
