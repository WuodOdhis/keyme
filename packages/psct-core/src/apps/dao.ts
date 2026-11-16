/**
 * Nervos DAO construction: deposit, prepare (phase 1) and withdraw (phase 2).
 *
 * The coordinator fetches the headers the script needs, computes maturity with the same rounding
 * the contract uses, and sets `since` to the minimal absolute epoch. The signer re-checks all of it.
 */

import { bytesToHex, fmtCkb, hexToBytes } from "../bytes.js";
import {
  encodeHeader,
  fromRpcHeader,
  fromRpcScript,
  type CellOutput,
  type HashType,
  type RpcHeader,
  type Script,
  type Transaction,
} from "../ckb.js";
import { ckbHash } from "../hash.js";
import { Rpc } from "../rpc.js";
import { networkByName, type Network, type NetworkName } from "../network.js";
import { resolveProofs } from "../psct/proofs.js";
import { buildPsct, type Psct } from "../psct/container.js";
import { encodeEpoch, parseHeader, withdrawableCapacity, type Epoch } from "../dao.js";
import { resolveSource } from "./coordinator.js";

const CKB = 100_000_000n;
const CHANGE_MIN = 61n * CKB;
const DAO_CODE = "0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e";
const DAO: Script = { codeHash: DAO_CODE, hashType: "type", args: "0x" };
const ZERO_DATA = "0x0000000000000000";

export interface DaoOptions {
  network: NetworkName;
  from?: string;
  account?: { xpub: string; index?: number };
  fee?: bigint;
}

export interface DaoResult {
  psct: Psct;
  tx: Transaction;
  fee: bigint;
  change: bigint;
  detail: string;
}

interface LiveCell {
  outPoint: { txHash: string; index: number };
  capacity: bigint;
  blockNumber: bigint;
  data: string;
  output: CellOutput;
}

function u64le(n: bigint): string {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return bytesToHex(b);
}

function readU64le(hex: string): bigint {
  const b = hexToBytes(hex);
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i] ?? 0);
  return v;
}

function sameLock(a: Script, b: Script): boolean {
  return (
    a.codeHash.toLowerCase() === b.codeHash.toLowerCase() &&
    a.hashType === b.hashType &&
    a.args.toLowerCase() === b.args.toLowerCase()
  );
}

interface RpcLiveCell {
  out_point: { tx_hash: string; index: string };
  block_number: string;
  output: {
    capacity: string;
    lock: { code_hash: string; hash_type: HashType; args: string };
    type: { code_hash: string; hash_type: HashType; args: string } | null;
  };
  output_data: string;
}

async function cells(rpc: Rpc, script: Script, scriptType: "lock" | "type"): Promise<LiveCell[]> {
  const res = await rpc.call<{ objects: RpcLiveCell[] }>("get_cells", [
    {
      script: { code_hash: script.codeHash, hash_type: script.hashType, args: script.args },
      script_type: scriptType,
    },
    "asc",
    "0x40",
    null,
  ]);
  return res.objects.map((o) => ({
    outPoint: { txHash: o.out_point.tx_hash, index: Number(BigInt(o.out_point.index)) },
    capacity: BigInt(o.output.capacity),
    blockNumber: BigInt(o.block_number),
    data: o.output_data ?? "0x",
    output: {
      capacity: BigInt(o.output.capacity),
      lock: fromRpcScript(o.output.lock),
      type: o.output.type ? fromRpcScript(o.output.type) : null,
    },
  }));
}

function pick(source: LiveCell[], required: bigint): LiveCell[] {
  const chosen: LiveCell[] = [];
  let total = 0n;
  for (const c of source) {
    chosen.push(c);
    total += c.capacity;
    if (total >= required) return chosen;
  }
  throw new Error(`not enough capacity: have ${fmtCkb(total)} CKB, need ${fmtCkb(required)} CKB`);
}

async function headerByNumber(rpc: Rpc, n: bigint): Promise<{ raw: Uint8Array; hash: string }> {
  const json = await rpc.call<RpcHeader>("get_header_by_number", [`0x${n.toString(16)}`, "0x1"]);
  const raw = encodeHeader(fromRpcHeader(json));
  return { raw, hash: bytesToHex(ckbHash(raw)) };
}

async function currentEpoch(rpc: Rpc): Promise<Epoch> {
  const json = await rpc.call<RpcHeader>("get_tip_header", []);
  return parseHeader(bytesToHex(encodeHeader(fromRpcHeader(json)))).epoch;
}

/** The contract rounds elapsed epochs up to a multiple of 180; reproduce that exactly. */
export function minimalSince(deposit: Epoch, prepare: Epoch): Epoch {
  let deposited = prepare.number - deposit.number;
  if (prepare.index * deposit.length > deposit.index * prepare.length) deposited += 1n;
  if (deposited <= 0n) throw new Error("the withdrawing cell predates its deposit");
  let lockEpochs = ((deposited + 179n) / 180n) * 180n;
  if (lockEpochs < 180n) lockEpochs = 180n;
  return { number: deposit.number + lockEpochs, index: deposit.index, length: deposit.length };
}

function sourceFrom(opts: DaoOptions, network: Network) {
  return resolveSource({ from: opts.from, account: opts.account, network });
}

export async function buildDaoDeposit(
  opts: DaoOptions & { amount: bigint },
): Promise<DaoResult> {
  const network = networkByName(opts.network);
  const rpc = new Rpc(network.rpc);
  const src = sourceFrom(opts, network);
  const fee = opts.fee ?? 1000n;

  const available = (await cells(rpc, src.fromLock, "lock")).filter(
    (c) => c.output.type === null,
  );
  const selected = pick(available, opts.amount + fee + CHANGE_MIN);
  const total = selected.reduce((n, c) => n + c.capacity, 0n);
  const change = total - opts.amount - fee;

  const tx: Transaction = {
    version: 0,
    cellDeps: [network.secpDep, network.daoDep],
    headerDeps: [],
    inputs: selected.map((c) => ({ since: 0n, previousOutput: c.outPoint })),
    outputs: [
      { capacity: opts.amount, lock: src.fromLock, type: DAO },
      { capacity: change, lock: src.changeLock, type: null },
    ],
    outputsData: [ZERO_DATA, "0x"],
    witnesses: selected.map(() => "0x"),
  };

  const proofs = await resolveProofs(tx, rpc);
  const psct = buildPsct(tx, {
    network: network.prefix,
    proofs,
    account: src.accountHint,
    inputHints: selected.map(() => ({ derivation: src.derivation })),
    outputHints: [{ role: "dao-deposit" }, { role: "change" }],
  });
  return { psct, tx, fee, change, detail: `deposit ${fmtCkb(opts.amount)} CKB` };
}

export async function buildDaoPrepare(opts: DaoOptions): Promise<DaoResult> {
  const network = networkByName(opts.network);
  const rpc = new Rpc(network.rpc);
  const src = sourceFrom(opts, network);
  const fee = opts.fee ?? 1000n;

  const dao = await cells(rpc, DAO, "type");
  const deposit = dao.find((c) => sameLock(c.output.lock, src.fromLock) && c.data === ZERO_DATA);
  if (!deposit) throw new Error("no deposit cell owned by this lock");

  const available = (await cells(rpc, src.fromLock, "lock")).filter(
    (c) =>
      c.output.type === null &&
      !(c.outPoint.txHash === deposit.outPoint.txHash && c.outPoint.index === deposit.outPoint.index),
  );
  const feeCell = available.find((c) => c.capacity >= fee + CHANGE_MIN);
  if (!feeCell) throw new Error(`need a sizeable non-DAO cell to pay ${fmtCkb(fee)} CKB fee + change`);

  const change = feeCell.capacity - fee;
  // Phase 1 loads the deposit block header; a real prepare transaction carries it in header_deps.
  const depositHeader = await headerByNumber(rpc, deposit.blockNumber);
  const tx: Transaction = {
    version: 0,
    cellDeps: [network.secpDep, network.daoDep],
    headerDeps: [depositHeader.hash],
    inputs: [
      { since: 0n, previousOutput: deposit.outPoint },
      { since: 0n, previousOutput: feeCell.outPoint },
    ],
    outputs: [
      { capacity: deposit.capacity, lock: src.fromLock, type: DAO },
      { capacity: change, lock: src.changeLock, type: null },
    ],
    outputsData: [u64le(deposit.blockNumber), "0x"],
    witnesses: ["0x", "0x"],
  };

  const proofs = await resolveProofs(tx, rpc, { blockHashes: true });
  const headers = new Map<string, string>([
    [depositHeader.hash, bytesToHex(depositHeader.raw)],
  ]);

  const psct = buildPsct(tx, {
    network: network.prefix,
    proofs,
    headers,
    account: src.accountHint,
    inputHints: [{ derivation: src.derivation }, {}],
    outputHints: [{ role: "dao-withdrawing" }, { role: "change" }],
  });
  return {
    psct,
    tx,
    fee,
    change,
    detail: `prepare: deposit block ${deposit.blockNumber}`,
  };
}

export interface DaoWithdrawOptions extends DaoOptions {
  to: string;
  amount?: bigint;
}

export async function buildDaoWithdraw(opts: DaoWithdrawOptions): Promise<DaoResult> {
  const network = networkByName(opts.network);
  const rpc = new Rpc(network.rpc);
  const src = sourceFrom(opts, network);
  const toLock = (await import("../address.js")).decodeAddress(opts.to).script;
  const fee = opts.fee ?? 1000n;

  const dao = await cells(rpc, DAO, "type");
  const withdrawing = dao.find(
    (c) =>
      sameLock(c.output.lock, src.fromLock) &&
      (c.data.length - 2) / 2 === 8 &&
      c.data !== ZERO_DATA,
  );
  if (!withdrawing) throw new Error("no withdrawing cell owned by this lock");

  const depositNumber = readU64le(withdrawing.data);
  const depositHeader = await headerByNumber(rpc, depositNumber);
  const prepareHeader = await headerByNumber(rpc, withdrawing.blockNumber);
  const dep = parseHeader(bytesToHex(depositHeader.raw));
  const prep = parseHeader(bytesToHex(prepareHeader.raw));
  const minimal = minimalSince(dep.epoch, prep.epoch);

  const current = await currentEpoch(rpc);
  if (current.number < minimal.number) {
    throw new Error(
      `DAO not mature: needs epoch ${minimal.number}, current ${current.number} (${minimal.number - current.number} epochs to go)`,
    );
  }

  const max = withdrawableCapacity(
    withdrawing.capacity,
    withdrawing.output,
    withdrawing.data,
    dep.accumulateRate,
    prep.accumulateRate,
  );
  const interest = max - withdrawing.capacity;
  const amount = opts.amount ?? max - fee;
  if (amount + fee > max) {
    throw new Error(`withdraw ${fmtCkb(amount)} + fee ${fmtCkb(fee)} exceeds ${fmtCkb(max)} CKB available`);
  }
  const change = max - amount - fee;
  if (change > 0n && change < CHANGE_MIN) {
    throw new Error(`change ${fmtCkb(change)} CKB is below the ${fmtCkb(CHANGE_MIN)} CKB cell minimum`);
  }

  const outputs = [{ capacity: amount, lock: toLock, type: null }];
  const outputsData = ["0x"];
  if (change > 0n) {
    outputs.push({ capacity: change, lock: src.changeLock, type: null });
    outputsData.push("0x");
  }

  const since = (0x20n << 56n) | encodeEpoch(minimal);
  const tx: Transaction = {
    version: 0,
    cellDeps: [network.secpDep, network.daoDep],
    // Two headers: the witness points at the deposit header (index 0), and the fee calculator also
    // needs the block that created the withdrawing cell to compute interest.
    headerDeps: [depositHeader.hash, prepareHeader.hash],
    inputs: [{ since, previousOutput: withdrawing.outPoint }],
    outputs,
    outputsData,
    witnesses: ["0x"],
  };

  const proofs = await resolveProofs(tx, rpc, { blockHashes: true });
  const headers = new Map<string, string>([
    [depositHeader.hash, bytesToHex(depositHeader.raw)],
    [prepareHeader.hash, bytesToHex(prepareHeader.raw)],
  ]);
  const psct = buildPsct(tx, {
    network: network.prefix,
    proofs,
    headers,
    account: src.accountHint,
    inputHints: [{ derivation: src.derivation }],
    outputHints: outputs.map((_, i) => ({ role: i === 0 ? "payment" : "change" })),
  });
  // WitnessArgs.input_type carries the header_deps index (only the first byte is read).
  psct.witnessTemplates[0] = { inputType: hexToBytes(u64le(0n)) };

  return {
    psct,
    tx,
    fee,
    change,
    detail: `withdraw ${fmtCkb(amount)} CKB (interest ${fmtCkb(interest)}), since epoch ${minimal.number}`,
  };
}
