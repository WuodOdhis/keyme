/**
 * Canonical CBOR (RFC 8949 §4.2) for the PSCT envelope.
 *
 * Supported subset: unsigned integers (number/bigint), text strings, byte strings, arrays, maps
 * with text keys, booleans and null. No tags, no indefinite lengths, no floats, no negative ints.
 *
 * Deterministic encoding: shortest form for every integer and length, and map keys sorted by
 * encoded length then bytewise. The decoder enforces the same rules, so a non-canonical input is
 * rejected rather than silently accepted — two implementations must not disagree about bytes.
 */

export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | CborValue[]
  | { [key: string]: CborValue };

const MAX_U64 = (1n << 64n) - 1n;

function head(major: number, n: bigint): Uint8Array {
  if (n < 0n) throw new Error("negative integers are not supported");
  if (n < 24n) return Uint8Array.of((major << 5) | Number(n));
  if (n < 256n) return Uint8Array.of((major << 5) | 24, Number(n));
  if (n < 65536n) {
    const b = new Uint8Array(3);
    b[0] = (major << 5) | 25;
    new DataView(b.buffer).setUint16(1, Number(n), false);
    return b;
  }
  if (n < 4294967296n) {
    const b = new Uint8Array(5);
    b[0] = (major << 5) | 26;
    new DataView(b.buffer).setUint32(1, Number(n), false);
    return b;
  }
  if (n <= MAX_U64) {
    const b = new Uint8Array(9);
    b[0] = (major << 5) | 27;
    new DataView(b.buffer).setBigUint64(1, n, false);
    return b;
  }
  throw new Error("integer exceeds u64");
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function compareEncoded(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return 0;
}

export function encodeCbor(value: CborValue): Uint8Array {
  if (value === null) return Uint8Array.of(0xf6);
  if (typeof value === "boolean") return Uint8Array.of(value ? 0xf5 : 0xf4);
  if (typeof value === "bigint") return head(0, value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`unsupported number ${value}`);
    return head(0, BigInt(value));
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concat([head(3, BigInt(bytes.length)), bytes]);
  }
  if (value instanceof Uint8Array) {
    return concat([head(2, BigInt(value.length)), value]);
  }
  if (Array.isArray(value)) {
    return concat([head(4, BigInt(value.length)), ...value.map(encodeCbor)]);
  }
  if (typeof value === "object") {
    const entries = Object.entries(value).map(([k, v]) => {
      const key = encodeCbor(k);
      return { key, value: encodeCbor(v) };
    });
    entries.sort((a, b) => compareEncoded(a.key, b.key));
    return concat([head(5, BigInt(entries.length)), ...entries.flatMap((e) => [e.key, e.value])]);
  }
  throw new Error(`unsupported CBOR value: ${typeof value}`);
}

class Reader {
  constructor(
    private readonly buf: Uint8Array,
    private off = 0,
  ) {}

  private byte(): number {
    if (this.off >= this.buf.length) throw new Error("unexpected end of CBOR");
    return this.buf[this.off++]!;
  }

  private uint(info: number, major: number): bigint {
    if (info < 24) return BigInt(info);
    if (info === 24) {
      const v = BigInt(this.byte());
      if (v < 24n) throw new Error("non-canonical integer");
      return v;
    }
    if (info === 25) {
      const v = BigInt((this.byte() << 8) | this.byte());
      if (v < 256n) throw new Error("non-canonical integer");
      return v;
    }
    if (info === 26) {
      let v = 0n;
      for (let i = 0; i < 4; i++) v = (v << 8n) | BigInt(this.byte());
      if (v < 65536n) throw new Error("non-canonical integer");
      return v;
    }
    if (info === 27) {
      let v = 0n;
      for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(this.byte());
      if (v < 4294967296n) throw new Error("non-canonical integer");
      return v;
    }
    if (info === 31) throw new Error("indefinite length is not canonical");
    throw new Error(`invalid additional info ${info} for major ${major}`);
  }

  private bytes(n: bigint): Uint8Array {
    const len = Number(n);
    if (len > 1_000_000_000) throw new Error("length too large");
    if (this.off + len > this.buf.length) throw new Error("unexpected end of CBOR");
    const out = this.buf.slice(this.off, this.off + len);
    this.off += len;
    return out;
  }

  read(): CborValue {
    const initial = this.byte();
    const major = initial >> 5;
    const info = initial & 0x1f;

    switch (major) {
      case 0: {
        const v = this.uint(info, major);
        return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
      }
      case 2:
        return this.bytes(this.uint(info, major));
      case 3: {
        const b = this.bytes(this.uint(info, major));
        try {
          return new TextDecoder("utf-8", { fatal: true }).decode(b);
        } catch {
          throw new Error("invalid UTF-8 in CBOR text string");
        }
      }
      case 4: {
        const n = Number(this.uint(info, major));
        const out: CborValue[] = [];
        for (let i = 0; i < n; i++) out.push(this.read());
        return out;
      }
      case 5: {
        const n = Number(this.uint(info, major));
        const out: { [k: string]: CborValue } = {};
        let prevKey: Uint8Array | null = null;
        for (let i = 0; i < n; i++) {
          const keyStart = this.off;
          const key = this.read();
          const keyBytes = this.buf.slice(keyStart, this.off);
          if (typeof key !== "string") throw new Error("CBOR map keys must be text");
          if (prevKey && compareEncoded(prevKey, keyBytes) >= 0) {
            throw new Error("CBOR map keys are not in canonical order");
          }
          prevKey = keyBytes;
          out[key] = this.read();
        }
        return out;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new Error(`unsupported simple value ${info}`);
      default:
        throw new Error(`unsupported major type ${major}`);
    }
  }

  finished(): boolean {
    return this.off === this.buf.length;
  }
}

export function decodeCbor(bytes: Uint8Array): CborValue {
  const r = new Reader(bytes);
  const value = r.read();
  if (!r.finished()) throw new Error("trailing bytes after CBOR value");
  return value;
}
