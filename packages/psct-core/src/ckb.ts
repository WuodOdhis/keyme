/** CKB data structures: encode to molecule, parse from RPC JSON. */

import { hexToBytes, toBigInt } from "./bytes.js";
import {
  byte,
  byte32,
  bytesVec,
  dynVec,
  fixVec,
  option,
  table,
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
