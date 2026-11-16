/**
 * RFC-0017 `since`: absolute or relative block / epoch / timestamp.
 *
 * flags = (relative << 7) | (metric << 5)
 *   0x00 absolute block, 0x20 absolute epoch, 0x40 absolute timestamp
 *   0x80 relative block, 0xA0 relative epoch, 0xC0 relative timestamp
 * value = low 56 bits. For epochs: 24-bit number | 16-bit index | 16-bit length.
 */

export type SinceKind =
  | "absolute-block"
  | "absolute-epoch"
  | "absolute-timestamp"
  | "relative-block"
  | "relative-epoch"
  | "relative-timestamp"
  | "unknown";

export interface SinceInfo {
  since: bigint;
  kind: SinceKind;
  relative: boolean;
  value: bigint;
  text: string;
}

const VALUE_BITS = 56n;
const VALUE_MASK = (1n << VALUE_BITS) - 1n;

export function decodeSinceInfo(since: bigint): SinceInfo {
  const flags = Number(since >> VALUE_BITS);
  const value = since & VALUE_MASK;
  const relative = (flags & 0x80) !== 0;
  const metric = (flags >> 5) & 0x03;

  if (since === 0n) {
    return { since, kind: "unknown", relative: false, value, text: "none" };
  }

  if (metric === 0) {
    return {
      since,
      kind: relative ? "relative-block" : "absolute-block",
      relative,
      value,
      text: relative ? `${value} blocks after` : `block ${value}`,
    };
  }

  if (metric === 1) {
    const number = value & 0xffffffn;
    const index = (value >> 24n) & 0xffffn;
    const length = (value >> 40n) & 0xffffn;
    const epoch = `${number}.${index}/${length}`;
    return {
      since,
      kind: relative ? "relative-epoch" : "absolute-epoch",
      relative,
      value,
      text: relative ? `${epoch} epochs after` : `epoch ${epoch}`,
    };
  }

  if (metric === 2) {
    const ms = value;
    return {
      since,
      kind: relative ? "relative-timestamp" : "absolute-timestamp",
      relative,
      value,
      text: relative
        ? `${Number(ms) / 1000}s after`
        : new Date(Number(ms)).toISOString(),
    };
  }

  return { since, kind: "unknown", relative, value, text: `flags 0x${flags.toString(16)}` };
}
