/**
 * xUDT (RFC-0052) and sUDT (RFC-0025).
 *
 * Cell data:  <amount: uint128 LE> <xUDT data>      amount is the first 16 bytes; extra data is allowed
 * xUDT args:  <owner lock script hash: 32> <flags: uint32 LE> <extension data>
 *
 * There is no "mode byte". Owner mode is true when an input cell's lock script hash equals the
 * 32-byte owner hash in args (or via the 2023 witness `owner_script`, which we do not model yet).
 */

import { bytesToHex, hexToBytes } from "./bytes.js";
import { scriptHash } from "./hash.js";
import type { CellOutput, Script } from "./ckb.js";
import type { BoundCell } from "./psct/bind.js";

export const XUDT_CODE_HASH = "0x50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95";
export const SUDT_CODE_HASH = "0x5e7a36a77e68eecc013dfa2fe6a23f3b6c344b04005808694ae6dd45eea4cfd5";

export type TokenKind = "xudt" | "sudt";

/**
 * The same token code can be deployed under different hash types (`type` on mainnet, `data1` on
 * testnet for xUDT). The code hash is the identity; the hash type only says how it is referenced.
 */
export function tokenKind(script: Script | null): TokenKind | null {
  if (!script) return null;
  if (script.hashType !== "type" && script.hashType !== "data1" && script.hashType !== "data") return null;
  const h = script.codeHash.toLowerCase();
  if (h === XUDT_CODE_HASH) return "xudt";
  if (h === SUDT_CODE_HASH) return "sudt";
  return null;
}

export interface XudtArgs {
  ownerLockHash: string;
  flags: number;
  extensionData: string;
}

export function decodeXudtArgs(argsHex: string): XudtArgs | null {
  const b = hexToBytes(argsHex);
  if (b.length < 36) return null;
  const flags = b[32]! | (b[33]! << 8) | (b[34]! << 16) | (b[35]! << 24);
  return {
    ownerLockHash: bytesToHex(b.slice(0, 32)),
    flags: flags >>> 0,
    extensionData: bytesToHex(b.slice(36)),
  };
}

/** First 16 bytes as a little-endian u128. Returns null when the data is too short. */
export function tokenAmount(dataHex: string): bigint | null {
  const b = hexToBytes(dataHex);
  if (b.length < 16) return null;
  let v = 0n;
  for (let i = 15; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
  return v;
}

/**
 * Owner mode, per the RFC's "Owner Mode Update":
 *   flags & 0x80000000  -> compare against input type script hashes
 *   flags & 0x40000000  -> compare against output type script hashes
 *   otherwise           -> compare against input lock script hashes
 *
 * The 2023 witness `owner_script` path is not verified here (it requires running the script).
 */
export function ownerMode(
  info: XudtArgs,
  tx: { outputs: CellOutput[] },
  bound: BoundCell[],
): boolean {
  const owner = info.ownerLockHash.toLowerCase();
  if (/^0x0+$/.test(owner)) return false;

  if ((info.flags & 0x80000000) !== 0) {
    return bound.some((b) => b.cellOutput.type && scriptHash(b.cellOutput.type).toLowerCase() === owner);
  }
  if ((info.flags & 0x40000000) !== 0) {
    return tx.outputs.some((o) => o.type && scriptHash(o.type).toLowerCase() === owner);
  }
  return bound.some((b) => scriptHash(b.cellOutput.lock).toLowerCase() === owner);
}

export interface TokenSummary {
  typeHash: string;
  kind: TokenKind;
  hashType: string;
  ownerLockHash?: string;
  flags?: number;
  input: bigint;
  output: bigint;
  delta: bigint;
  ownerMode: boolean;
  issues: string[];
}

/**
 * Per-type-script token totals. A positive delta is minting and needs owner mode; a negative delta is
 * burning, which the script allows but a signer should surface.
 */
export function summarizeTokens(tx: { outputs: CellOutput[]; outputsData: string[] }, bound: BoundCell[]): TokenSummary[] {
  const byType = new Map<string, TokenSummary>();

  const touch = (type: Script): { summary: TokenSummary; info: XudtArgs | null } => {
    const kind = tokenKind(type)!;
    const hash = scriptHash(type);
    let s = byType.get(hash);
    if (!s) {
      const info = kind === "xudt" ? decodeXudtArgs(type.args) : null;
      s = {
        typeHash: hash,
        kind,
        hashType: type.hashType,
        ownerLockHash: info?.ownerLockHash,
        flags: info?.flags,
        input: 0n,
        output: 0n,
        delta: 0n,
        ownerMode: info ? ownerMode(info, tx, bound) : false,
        issues: [],
      };
      if (kind === "xudt" && !info) s.issues.push("xUDT args are shorter than 36 bytes");
      byType.set(hash, s);
    }
    return { summary: s, info: s.kind === "xudt" ? decodeXudtArgs(type.args) : null };
  };

  for (const b of bound) {
    const kind = tokenKind(b.cellOutput.type);
    if (!kind) continue;
    const { summary } = touch(b.cellOutput.type!);
    const amount = tokenAmount(b.data);
    if (amount === null) summary.issues.push(`input data is ${(b.data.length - 2) / 2} bytes, expected >= 16`);
    else summary.input += amount;
  }

  tx.outputs.forEach((o, i) => {
    if (!tokenKind(o.type)) return;
    const { summary } = touch(o.type!);
    const amount = tokenAmount(tx.outputsData[i] ?? "0x");
    if (amount === null) summary.issues.push(`output ${i} data is ${((tx.outputsData[i] ?? "0x").length - 2) / 2} bytes, expected >= 16`);
    else summary.output += amount;
  });

  for (const s of byType.values()) {
    s.delta = s.output - s.input;
    if (s.delta > 0n && !s.ownerMode) {
      s.issues.push(
        "mints tokens but owner authorisation is not visible in inputs/outputs; " +
          "it may be delegated to a witness owner_script, which this tool does not verify",
      );
    }
  }

  return [...byType.values()];
}
