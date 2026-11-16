/** CKB data structures: encode to molecule, parse from RPC JSON. */

import { bytesToHex, hexToBytes, toBigInt } from "./bytes.js";
import {
  byte,
  byte32,
  bytesVec,
  dynVec,
  dynVecOffsets,
  fixedVecCount,
  fixVec,
  option,
  readBytes,
  readU32,
  readU64,
  table,
  tableOffsets,
  u32,
  u64,
} from "./molecule.js";

export type Hex = string;
export type HashType = "data" | "type" | "data1" | "data2";
export type DepType = "code" | "dep_group" | "depGroup";

export interface Script {
  codeHash: Hex;
  hashType: HashType;
  args: Hex;
}

export interface OutPoint {
  txHash: Hex;
  index: number;
}

export interface CellInput {
  since: bigint;
  previousOutput: OutPoint;
}

export interface CellOutput {
  capacity: bigint;
  lock: Script;
  type: Script | null;
}

export interface CellDep {
  outPoint: OutPoint;
  depType: DepType;
}

export interface Transaction {
  version: number;
  cellDeps: CellDep[];
  headerDeps: Hex[];
  inputs: CellInput[];
  outputs: CellOutput[];
  outputsData: Hex[];
  witnesses: Hex[];
}

const HASH_TYPE_CODE: Record<HashType, number> = { data: 0, type: 1, data1: 2, data2: 4 };
const DEP_TYPE_CODE: Record<string, number> = { code: 0, dep_group: 1, depGroup: 1 };

export function encodeScript(s: Script): Uint8Array {
  return table(
    byte32(hexToBytes(s.codeHash)),
    byte(HASH_TYPE_CODE[s.hashType] ?? 1),
    bytesVec(hexToBytes(s.args)),
  );
}

export function encodeOutPoint(o: OutPoint): Uint8Array {
  return new Uint8Array([...byte32(hexToBytes(o.txHash)), ...u32(o.index)]);
}

export function encodeCellInput(i: CellInput): Uint8Array {
  return new Uint8Array([...u64(i.since), ...encodeOutPoint(i.previousOutput)]);
}

export function encodeCellOutput(o: CellOutput): Uint8Array {
  return table(u64(o.capacity), encodeScript(o.lock), option(o.type ? encodeScript(o.type) : null));
}

export function encodeCellDep(d: CellDep): Uint8Array {
  return new Uint8Array([...encodeOutPoint(d.outPoint), DEP_TYPE_CODE[d.depType] ?? 0]);
}

function txFields(t: Transaction): Uint8Array[] {
  return [
    u32(t.version),
    fixVec(t.cellDeps.map(encodeCellDep)),
    fixVec(t.headerDeps.map((h) => byte32(hexToBytes(h)))),
    fixVec(t.inputs.map(encodeCellInput)),
    dynVec(t.outputs.map(encodeCellOutput)),
    dynVec(t.outputsData.map((d) => bytesVec(hexToBytes(d)))),
  ];
}

/** RawTransaction — 6 fields, no witnesses. This is what tx_hash commits to. */
export function encodeRawTransaction(t: Transaction): Uint8Array {
  return table(...txFields(t));
}

/** Full Transaction = table { raw: RawTransaction, witnesses: BytesVec }. */
export function encodeTransaction(t: Transaction): Uint8Array {
  return table(encodeRawTransaction(t), dynVec(t.witnesses.map((w) => bytesVec(hexToBytes(w)))));
}

/** A CKB block header as a molecule struct (208 bytes). */
export interface Header {
  version: number;
  compactTarget: number;
  timestamp: bigint;
  number: bigint;
  epoch: bigint;
  parentHash: Hex;
  transactionsRoot: Hex;
  proposalsHash: Hex;
  extraHash: Hex;
  dao: Hex;
  nonce: bigint;
}

function u128(n: bigint): Uint8Array {
  const b = new Uint8Array(16);
  new DataView(b.buffer).setBigUint64(0, n & 0xffffffffffffffffn, true);
  new DataView(b.buffer).setBigUint64(8, n >> 64n, true);
  return b;
}

/** Header is a fixed struct: fields concatenated, no offsets. */
export function encodeHeader(h: Header): Uint8Array {
  return new Uint8Array([
    ...u32(h.version),
    ...u32(h.compactTarget),
    ...u64(h.timestamp),
    ...u64(h.number),
    ...u64(h.epoch),
    ...hexToBytes(h.parentHash),
    ...hexToBytes(h.transactionsRoot),
    ...hexToBytes(h.proposalsHash),
    ...hexToBytes(h.extraHash),
    ...hexToBytes(h.dao),
    ...u128(h.nonce),
  ]);
}

export interface RpcHeader {
  version: Hex;
  compact_target: Hex;
  timestamp: Hex;
  number: Hex;
  epoch: Hex;
  parent_hash: Hex;
  transactions_root: Hex;
  proposals_hash: Hex;
  extra_hash: Hex;
  dao: Hex;
  nonce: Hex;
  hash?: Hex;
}

export function fromRpcHeader(h: RpcHeader): Header {
  return {
    version: Number(toBigInt(h.version)),
    compactTarget: Number(toBigInt(h.compact_target)),
    timestamp: toBigInt(h.timestamp),
    number: toBigInt(h.number),
    epoch: toBigInt(h.epoch),
    parentHash: h.parent_hash,
    transactionsRoot: h.transactions_root,
    proposalsHash: h.proposals_hash,
    extraHash: h.extra_hash,
    dao: h.dao,
    nonce: toBigInt(h.nonce),
  };
}

/** A transaction with its witnesses removed. Binding hashes RawTransaction, so witnesses are dead weight. */
export function stripWitnesses(t: Transaction): Transaction {
  return { ...t, witnesses: [] };
}

// ---------------------------------------------------------------- decoding

const HASH_TYPE_NAME: Record<number, HashType> = {
  0: "data",
  1: "type",
  2: "data1",
  4: "data2",
};

export function decodeScript(buf: Uint8Array, start: number): Script {
  const offs = tableOffsets(buf, start, 3);
  const hashType = buf[offs[1]!]!;
  const name = HASH_TYPE_NAME[hashType];
  if (!name) throw new Error(`unknown hash type ${hashType}`);
  return {
    codeHash: bytesToHex(buf.slice(offs[0]!, offs[0]! + 32)),
    hashType: name,
    args: bytesToHex(readBytes(buf, offs[2]!)),
  };
}

export function decodeCellOutput(buf: Uint8Array, start: number): CellOutput {
  const offs = tableOffsets(buf, start, 3);
  const capacity = readU64(buf, offs[0]!);
  const lock = decodeScript(buf, offs[1]!);
  const typeStart = offs[2]!;
  const typeEnd = start + readU32(buf, start);
  const type = typeEnd <= typeStart ? null : decodeScript(buf, typeStart);
  return { capacity, lock, type };
}

export function decodeOutPoint(buf: Uint8Array, start: number): OutPoint {
  return {
    txHash: bytesToHex(buf.slice(start, start + 32)),
    index: readU32(buf, start + 32),
  };
}

/** Decode the 6-field RawTransaction. Throws on anything that does not round-trip structurally. */
export function decodeRawTransaction(buf: Uint8Array): Transaction {
  const offs = tableOffsets(buf, 0, 6);
  const size = buf.length;
  const end = (i: number) => (i + 1 < offs.length ? offs[i + 1]! : size);

  const version = readU32(buf, offs[0]!);

  const depCount = fixedVecCount(buf, offs[1]!);
  const cellDeps: CellDep[] = [];
  for (let i = 0; i < depCount; i++) {
    const at = offs[1]! + 4 + i * 37;
    const depType = buf[at + 36]!;
    const name = DEP_TYPE_NAME[depType];
    if (!name) throw new Error(`unknown dep type ${depType}`);
    cellDeps.push({ outPoint: decodeOutPoint(buf, at), depType: name });
  }

  const headerCount = fixedVecCount(buf, offs[2]!);
  const headerDeps: string[] = [];
  for (let i = 0; i < headerCount; i++) {
    const at = offs[2]! + 4 + i * 32;
    headerDeps.push(bytesToHex(buf.slice(at, at + 32)));
  }

  const inputCount = fixedVecCount(buf, offs[3]!);
  const inputs: CellInput[] = [];
  for (let i = 0; i < inputCount; i++) {
    const at = offs[3]! + 4 + i * 44;
    inputs.push({
      since: readU64(buf, at),
      previousOutput: decodeOutPoint(buf, at + 8),
    });
  }

  const outputOffsets = dynVecOffsets(buf, offs[4]!);
  const outputs = outputOffsets.map((o) => decodeCellOutput(buf, o));

  const dataOffsets = dynVecOffsets(buf, offs[5]!);
  const outputsData = dataOffsets.map((o) => bytesToHex(readBytes(buf, o)));

  if (outputs.length !== outputsData.length) {
    throw new Error(`outputs (${outputs.length}) and outputs_data (${outputsData.length}) differ`);
  }

  return { version, cellDeps, headerDeps, inputs, outputs, outputsData, witnesses: [] };
}

// ---------------------------------------------------------------- RPC JSON

interface RpcOutPoint {
  tx_hash: Hex;
  index: Hex;
}
interface RpcScript {
  code_hash: Hex;
  hash_type: HashType;
  args: Hex;
}
interface RpcCellOutput {
  capacity: Hex;
  lock: RpcScript;
  type: RpcScript | null;
}
export interface RpcTransaction {
  hash?: Hex;
  version: Hex;
  cell_deps: { out_point: RpcOutPoint; dep_type: DepType }[];
  header_deps: Hex[];
  inputs: { since: Hex; previous_output: RpcOutPoint }[];
  outputs: RpcCellOutput[];
  outputs_data: Hex[];
  witnesses: Hex[];
}

export function fromRpcScript(s: RpcScript): Script {
  return { codeHash: s.code_hash, hashType: s.hash_type, args: s.args };
}

export function fromRpcTx(t: RpcTransaction): Transaction {
  return {
    version: Number(toBigInt(t.version)),
    cellDeps: t.cell_deps.map((d) => ({
      outPoint: { txHash: d.out_point.tx_hash, index: Number(toBigInt(d.out_point.index)) },
      depType: d.dep_type,
    })),
    headerDeps: t.header_deps,
    inputs: t.inputs.map((i) => ({
      since: toBigInt(i.since),
      previousOutput: {
        txHash: i.previous_output.tx_hash,
        index: Number(toBigInt(i.previous_output.index)),
      },
    })),
    outputs: t.outputs.map((o) => ({
      capacity: toBigInt(o.capacity),
      lock: fromRpcScript(o.lock),
      type: o.type ? fromRpcScript(o.type) : null,
    })),
    outputsData: t.outputs_data,
    witnesses: t.witnesses,
  };
}

const DEP_TYPE_NAME: Record<number, DepType> = { 0: "code", 1: "dep_group" };

/** Inverse of fromRpcTx: a transaction in the shape `send_transaction` expects. */
export function toRpcTx(t: Transaction): unknown {
  return {
    version: `0x${t.version.toString(16)}`,
    cell_deps: t.cellDeps.map((d) => ({
      out_point: { tx_hash: d.outPoint.txHash, index: `0x${d.outPoint.index.toString(16)}` },
      dep_type: d.depType,
    })),
    header_deps: t.headerDeps,
    inputs: t.inputs.map((i) => ({
      since: `0x${i.since.toString(16)}`,
      previous_output: {
        tx_hash: i.previousOutput.txHash,
        index: `0x${i.previousOutput.index.toString(16)}`,
      },
    })),
    outputs: t.outputs.map((o) => ({
      capacity: `0x${o.capacity.toString(16)}`,
      lock: { code_hash: o.lock.codeHash, hash_type: o.lock.hashType, args: o.lock.args },
      type: o.type
        ? { code_hash: o.type.codeHash, hash_type: o.type.hashType, args: o.type.args }
        : null,
    })),
    outputs_data: t.outputsData,
    witnesses: t.witnesses,
  };
}
