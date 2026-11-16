/**
 * Nervos DAO (RFC-0023), from `ckb-system-scripts/c/dao.c`.
 *
 * Two shapes of DAO input cell, told apart by their data:
 *   deposit     data = 8-byte zero                 (spent in withdraw phase 1)
 *   withdrawing data = 8-byte deposit block number (spent in withdraw phase 2)
 *
 * Phase 1 (deposit -> withdrawing):
 *   - output at the same index has the DAO type
 *   - same capacity
 *   - data = 8-byte block number of the block containing the *input* cell
 *   - no witness field is required by the type script
 *
 * Phase 2 (withdrawing -> free):
 *   - witness `input_type` is 8 bytes; the script reads only its first byte as an index
 *     into `header_deps`
 *   - header_deps[index] is the deposit block header, and its number equals the cell data
 *   - input `since` flags are 0x20 (absolute epoch), and the epoch is at least
 *     deposit epoch + 180, comparing the fraction correctly
 *   - interest is computed from the two blocks' DAO accumulate rates
 *
 * Consequence for PSCT: a withdraw proof needs the raw deposit block header. This is the first
 * place where the proof payload grows beyond input cells, and it is why headers are a first-class
 * field rather than a convenience.
 */

import { bytesToHex, hexToBytes } from "./bytes.js";
import { type CellOutput, type Transaction } from "./ckb.js";
import { occupiedCapacity } from "./capacity.js";
import { decodeWitnessArgs } from "./sighash.js";
import type { BoundCell } from "./psct/bind.js";

export const DAO_CODE_HASH = "0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e";
export const LOCK_PERIOD_EPOCHS = 180;
const SINCE_EPOCH_FLAG = 0x20n;
const SINCE_VALUE_BITS = 56n;
const SINCE_VALUE_MASK = (1n << SINCE_VALUE_BITS) - 1n;

export interface Epoch {
  number: bigint;
  index: bigint;
  length: bigint;
}

export interface HeaderInfo {
  number: bigint;
  epoch: Epoch;
  /** DAO accumulate rate: bytes 8..16 of the header's dao field. */
  accumulateRate: bigint;
}

export function isDaoType(script: CellOutput["type"]): boolean {
  return script !== null && script.codeHash.toLowerCase() === DAO_CODE_HASH && script.hashType === "type";
}

export type DaoCell =
  | { kind: "deposit" }
  | { kind: "withdrawing"; depositBlockNumber: bigint };

export function classifyDaoCell(dataHex: string): DaoCell | null {
  const b = hexToBytes(dataHex);
  if (b.length !== 8) return null;
  let n = 0n;
  for (let i = 7; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n === 0n ? { kind: "deposit" } : { kind: "withdrawing", depositBlockNumber: n };
}

export function parseHeader(rawHex: string): HeaderInfo {
  const b = hexToBytes(rawHex);
  if (b.length !== 208) throw new Error(`header must be 208 bytes, got ${b.length}`);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const epochRaw = dv.getBigUint64(24, true);
  return {
    number: dv.getBigUint64(16, true),
    epoch: {
      number: epochRaw & 0xffffffn,
      index: (epochRaw >> 24n) & 0xffffn,
      length: (epochRaw >> 40n) & 0xffffn,
    },
    accumulateRate: dv.getBigUint64(168, true),
  };
}

export function encodeEpoch(e: Epoch): bigint {
  return (e.number & 0xffffffn) | ((e.index & 0xffffn) << 24n) | ((e.length & 0xffffn) << 40n);
}

export function decodeSince(since: bigint): { flags: bigint; value: bigint; epoch?: Epoch } {
  const flags = since >> SINCE_VALUE_BITS;
  const value = since & SINCE_VALUE_MASK;
  if (flags !== SINCE_EPOCH_FLAG) return { flags, value };
  return {
    flags,
    value,
    epoch: {
      number: value & 0xffffffn,
      index: (value >> 24n) & 0xffffn,
      length: (value >> 40n) & 0xffffn,
    },
  };
}

/** Compare two epoch-with-fraction values, as the DAO and multisig scripts do. */
export function compareEpoch(a: Epoch, b: Epoch): number {
  if (a.number !== b.number) return a.number < b.number ? -1 : 1;
  const left = a.index * b.length;
  const right = b.index * a.length;
  return left < right ? -1 : left > right ? 1 : 0;
}

export function maturityEpoch(deposit: Epoch): Epoch {
  return { number: deposit.number + BigInt(LOCK_PERIOD_EPOCHS), index: deposit.index, length: deposit.length };
}

export interface DaoFinding {
  input: number;
  kind: "deposit" | "withdrawing";
  depositBlockNumber?: bigint;
  depositEpoch?: Epoch;
  matureAt?: Epoch;
  sinceEpoch?: Epoch;
  mature: boolean | null;
  /** Maximum capacity the script will let this input contribute (principal + interest). */
  withdrawable?: bigint;
  /** withdrawable - capacity */
  interest?: bigint;
  issues: string[];
}

export interface DaoContext {
  /** Raw headers by hash. A withdraw must supply its deposit header and the withdrawing cell's block. */
  headers: Map<string, string>;
}

/** occupied = flat field sum, priced at 1e8 shannons per byte (see capacity.ts). */
export { occupiedCapacity } from "./capacity.js";

/**
 * Principal + interest an input can contribute, per `calculate_dao_input_capacity` in dao.c:
 *   counted  = capacity - occupied
 *   interest = floor(counted * withdrawAR / depositAR)
 *   max      = occupied + counted + interest
 */
export function withdrawableCapacity(
  capacity: bigint,
  output: CellOutput,
  dataHex: string,
  depositRate: bigint,
  withdrawRate: bigint,
): bigint {
  const occupied = occupiedCapacity(output, dataHex);
  if (capacity <= occupied) return capacity;
  const counted = capacity - occupied;
  if (depositRate === 0n) return capacity;
  return occupied + (counted * withdrawRate) / depositRate;
}

function u64Hex(n: bigint): string {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return bytesToHex(b);
}

/** Check every DAO cell in the transaction. Returns findings; issues are hard errors for a signer. */
export function inspectDao(tx: Transaction, bound: BoundCell[], ctx: DaoContext): DaoFinding[] {
  const findings: DaoFinding[] = [];

  bound.forEach((cell, index) => {
    if (!isDaoType(cell.cellOutput.type)) return;
    const parsed = classifyDaoCell(cell.data);
    if (!parsed) {
      findings.push({
        input: index,
        kind: "deposit",
        mature: null,
        issues: [`DAO cell data is ${(cell.data.length - 2) / 2} bytes, expected 8`],
      });
      return;
    }

    if (parsed.kind === "deposit") {
      const issues: string[] = [];
      const out = tx.outputs[index];
      const outData = tx.outputsData[index] ?? "0x";
      if (!out) {
        issues.push("no output at the same index for the withdrawing cell");
      } else {
        if (!isDaoType(out.type)) issues.push("output at the same index is not a DAO cell");
        if (out.capacity !== cell.cellOutput.capacity) {
          issues.push("withdrawing cell must keep the deposit's capacity");
        }
        if ((outData.length - 2) / 2 !== 8) {
          issues.push("withdrawing cell data must be 8 bytes");
        } else if (!cell.blockHash) {
          issues.push("deposit cell's block hash is not supplied; cannot check the withdrawing block number");
        } else {
          const raw = ctx.headers.get(cell.blockHash.toLowerCase());
          if (!raw) {
            issues.push(`deposit block header ${cell.blockHash.slice(0, 12)}… was not supplied`);
          } else if (outData.toLowerCase() !== u64Hex(parseHeader(raw).number)) {
            issues.push("withdrawing cell data does not equal the deposit cell's block number");
          }
        }
      }
      findings.push({ input: index, kind: "deposit", mature: null, issues });
      return;
    }

    const issues: string[] = [];
    const depositBlockNumber = parsed.depositBlockNumber;
    let depositEpoch: Epoch | undefined;
    let matureAt: Epoch | undefined;
    let sinceEpoch: Epoch | undefined;

    // Witness input_type -> header_deps index (the script reads only the first byte).
    let headerIndex: number | null = null;
    try {
      const w = tx.witnesses[index] ?? "0x";
      const args = w === "0x" ? null : decodeWitnessArgs(hexToBytes(w));
      const inputType = args?.inputType;
      if (!inputType) {
        issues.push("witness input_type is missing");
      } else if (inputType.length !== 8) {
        issues.push(`witness input_type is ${inputType.length} bytes, expected 8`);
      } else {
        headerIndex = inputType[0]!;
        if (inputType.slice(1).some((b) => b !== 0)) {
          issues.push("witness input_type bytes 1..7 are not zero (script ignores them, but this is unusual)");
        }
      }
    } catch (e) {
      issues.push(`cannot parse witness: ${(e as Error).message}`);
    }

    if (headerIndex !== null) {
      const hash = tx.headerDeps[headerIndex];
      if (!hash) {
        issues.push(`header_deps[${headerIndex}] is missing`);
      } else {
        const raw = ctx.headers.get(hash.toLowerCase());
        if (!raw) {
          issues.push(`deposit header ${hash.slice(0, 12)}… was not supplied`);
        } else {
          const header = parseHeader(raw);
          depositEpoch = header.epoch;
          matureAt = maturityEpoch(header.epoch);
          if (header.number !== depositBlockNumber) {
            issues.push(
              `cell says deposit block ${depositBlockNumber}, header says ${header.number}`,
            );
          }
        }
      }
    }

    const since = tx.inputs[index]!.since;
    const decoded = decodeSince(since);
    sinceEpoch = decoded.epoch;
    if (decoded.flags !== SINCE_EPOCH_FLAG) {
      issues.push(`since flags are 0x${decoded.flags.toString(16)}, DAO requires 0x20 (absolute epoch)`);
    } else if (!decoded.epoch) {
      issues.push("since does not decode as an epoch");
    } else if (matureAt && compareEpoch(decoded.epoch, matureAt) < 0) {
      issues.push("since is earlier than the 180-epoch maturity");
    }

    // Interest needs the header of the block that created the withdrawing cell.
    let withdrawable: bigint | undefined;
    let interest: bigint | undefined;
    let depositRate: bigint | undefined;
    if (headerIndex !== null) {
      const depositHash = tx.headerDeps[headerIndex];
      const depositRaw = depositHash ? ctx.headers.get(depositHash.toLowerCase()) : undefined;
      if (depositRaw) depositRate = parseHeader(depositRaw).accumulateRate;
    }
    if (depositRate === undefined) {
      issues.push("deposit header missing; interest cannot be computed");
    } else if (!cell.blockHash) {
      issues.push("withdrawing cell's block hash is not supplied; interest cannot be computed");
    } else {
      const withdrawRaw = ctx.headers.get(cell.blockHash.toLowerCase());
      if (!withdrawRaw) {
        issues.push(`withdrawing block header ${cell.blockHash.slice(0, 12)}… was not supplied`);
      } else {
        withdrawable = withdrawableCapacity(
          cell.cellOutput.capacity,
          cell.cellOutput,
          cell.data,
          depositRate,
          parseHeader(withdrawRaw).accumulateRate,
        );
        interest = withdrawable - cell.cellOutput.capacity;
      }
    }

    findings.push({
      input: index,
      kind: "withdrawing",
      depositBlockNumber,
      depositEpoch,
      matureAt,
      sinceEpoch,
      mature: matureAt && sinceEpoch ? compareEpoch(sinceEpoch, matureAt) >= 0 : null,
      withdrawable,
      interest,
      issues,
    });
  });

  return findings;
}

export function describeEpoch(e: Epoch): string {
  return `${e.number}.${e.index}/${e.length}`;
}
