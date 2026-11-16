/**
 * Occupied capacity, per ckb's `util/gen-types/src/extension/capacity.rs`:
 *
 *   Script    = args.len + 32 (code_hash) + 1 (hash_type)
 *   CellOutput = 8 (capacity) + data.len + lock + type (if present)
 *
 * Note this is a flat field sum: table headers, vector prefixes and the option tag are not counted.
 * Using the molecule size instead overstates it (by 64 bytes for a typical typed cell), which is
 * enough to understate DAO interest.
 */

import type { CellOutput, Script } from "./ckb.js";

function argBytes(s: Script): number {
  return (s.args.length - 2) / 2;
}

export function occupiedBytes(output: CellOutput, dataHex: string): number {
  let bytes = 8 + (dataHex.length - 2) / 2;
  bytes += argBytes(output.lock) + 32 + 1;
  if (output.type) bytes += argBytes(output.type) + 32 + 1;
  return bytes;
}

export function occupiedCapacity(output: CellOutput, dataHex: string): bigint {
  return BigInt(occupiedBytes(output, dataHex)) * 100_000_000n;
}
