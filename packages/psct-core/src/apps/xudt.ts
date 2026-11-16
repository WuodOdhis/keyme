/**
 * xUDT mint and transfer.
 *
 * A token type script is `owner_lock_script_hash (32) ‖ flags (4)`, and owner mode is true when an
 * input lock's script hash equals the owner hash. That lets us mint on a devnet without a special
 * deployment: the owner is our own lock.
 */

import { bytesToHex, fmtCkb, hexToBytes } from "../bytes.js";
import type { Script, Transaction } from "../ckb.js";
import { scriptHash } from "../hash.js";
import { occupiedCapacity } from "../capacity.js";
import { Rpc } from "../rpc.js";
import { networkByName, type Network, type NetworkName } from "../network.js";
import { resolveProofs } from "../psct/proofs.js";
import { buildPsct, type Psct } from "../psct/container.js";
import { tokenAmount } from "../xudt.js";
import { resolveSource } from "./coordinator.js";

const CKB = 100_000_000n;
const CHANGE_MIN = 61n * CKB;

export interface XudtOptions {
  network: NetworkName;
  from?: string;
  account?: { xpub: string; index?: number };
  fee?: bigint;
}

export interface XudtResult {
  psct: Psct;
  tx: Transaction;
  fee: bigint;
  change: bigint;
  typeScript: Script;
  detail: string;
}

interface LiveCell {
  outPoint: { txHash: string; index: number };
  capacity: bigint;
  data: string;
  lock: Script;
  type: Script | null;
}

function u128le(n: bigint): string {
  const b = new Uint8Array(16);
  let v = n;
  for (let i = 0; i < 16; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytesToHex(b);
}

function sameLock(a: Script, b: Script): boolean {
  return (
    a.codeHash.toLowerCase() === b.codeHash.toLowerCase() &&
    a.hashType === b.hashType &&
    a.args.toLowerCase() === b.args.toLowerCase()
  );
}

async function cells(rpc: Rpc, script: Script, scriptType: "lock" | "type"): Promise<LiveCell[]> {
  const res = await rpc.call<{
    objects: {
      out_point: { tx_hash: string; index: string };
      output: { capacity: string; lock: { code_hash: string; hash_type: "type" | "data1"; args: string }; type: { code_hash: string; hash_type: "type" | "data1"; args: string } | null };
      output_data: string;
    }[];
  }>("get_cells", [
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
    data: o.output_data ?? "0x",
    lock: {
      codeHash: o.output.lock.code_hash,
      hashType: o.output.lock.hash_type,
      args: o.output.lock.args,
    },
    type: o.output.type
      ? {
          codeHash: o.output.type.code_hash,
          hashType: o.output.type.hash_type,
          args: o.output.type.args,
        }
      : null,
  }));
}

/** Token type script owned by the given lock. */
export function xudtType(network: Network, ownerLock: Script): Script {
  const owner = scriptHash(ownerLock).replace(/^0x/, "");
  return {
    codeHash: network.xudtCodeHash,
    hashType: network.xudtHashType,
    args: `0x${owner}00000000`,
  };
}

export async function buildXudtMint(
  opts: XudtOptions & { amount: bigint; capacity?: bigint },
): Promise<XudtResult> {
  const network = networkByName(opts.network);
  const rpc = new Rpc(network.rpc);
  const src = resolveSource({ from: opts.from, account: opts.account, network });
  const fee = opts.fee ?? 1000n;
  const capacity = opts.capacity ?? 1000n * CKB;
  const type = xudtType(network, src.fromLock);

  const plain = (await cells(rpc, src.fromLock, "lock")).filter((c) => c.type === null);
  const selected: LiveCell[] = [];
  let total = 0n;
  for (const c of plain) {
    selected.push(c);
    total += c.capacity;
    if (total >= capacity + fee + CHANGE_MIN) break;
  }
  if (total < capacity + fee) throw new Error("not enough capacity to mint");
  const change = total - capacity - fee;

  const tx: Transaction = {
    version: 0,
    cellDeps: [network.secpDep, network.xudtDep],
    headerDeps: [],
    inputs: selected.map((c) => ({ since: 0n, previousOutput: c.outPoint })),
    outputs: [
      { capacity, lock: src.fromLock, type },
      { capacity: change, lock: src.changeLock, type: null },
    ],
    outputsData: [u128le(opts.amount), "0x"],
    witnesses: selected.map(() => "0x"),
  };

  const proofs = await resolveProofs(tx, rpc);
  const psct = buildPsct(tx, {
    network: network.prefix,
    proofs,
    account: src.accountHint,
    inputHints: selected.map(() => ({ derivation: src.derivation })),
    outputHints: [{ role: "token" }, { role: "change" }],
  });
  return { psct, tx, fee, change, typeScript: type, detail: `mint ${opts.amount} units` };
}

export interface XudtTransferOptions extends XudtOptions {
  to: string;
  typeScript: Script;
  amount: bigint;
  /** Capacity per token output cell; must cover occupied capacity. */
  outputCapacity?: bigint;
}

export async function buildXudtTransfer(opts: XudtTransferOptions): Promise<XudtResult> {
  const network = networkByName(opts.network);
  const rpc = new Rpc(network.rpc);
  const src = resolveSource({ from: opts.from, account: opts.account, network });
  const toLock = (await import("../address.js")).decodeAddress(opts.to).script;
  const fee = opts.fee ?? 1000n;

  const tokenCells = (await cells(rpc, opts.typeScript, "type")).filter((c) =>
    sameLock(c.lock, src.fromLock),
  );
  if (tokenCells.length === 0) throw new Error("no token cells owned by this lock");

  const selected: LiveCell[] = [];
  let tokenTotal = 0n;
  let capacityTotal = 0n;
  for (const c of tokenCells) {
    const amount = tokenAmount(c.data);
    if (amount === null) continue;
    selected.push(c);
    tokenTotal += amount;
    capacityTotal += c.capacity;
    if (tokenTotal >= opts.amount) break;
  }
  if (tokenTotal < opts.amount) throw new Error("not enough token balance");

  const changeAmount = tokenTotal - opts.amount;
  const outCap = opts.outputCapacity ?? 300n * CKB;
  const outputs: Transaction["outputs"] = [
    { capacity: outCap, lock: toLock, type: opts.typeScript },
  ];
  const data = [u128le(opts.amount)];
  if (changeAmount > 0n) {
    outputs.push({ capacity: outCap, lock: src.changeLock, type: opts.typeScript });
    data.push(u128le(changeAmount));
  }
  const ckbChange = capacityTotal - outCap * BigInt(outputs.length) - fee;
  if (ckbChange < 0n) throw new Error("token outputs need more CKB capacity");
  let plainChange = ckbChange;
  if (ckbChange > 0n && ckbChange < CHANGE_MIN) {
    // Too small for its own cell: fold it into the last token output instead.
    const last = [...outputs].reverse().find((o) => o.type !== null);
    if (!last) throw new Error(`CKB change ${fmtCkb(ckbChange)} is below the cell minimum`);
    last.capacity += ckbChange;
    plainChange = 0n;
  }
  if (plainChange > 0n) {
    outputs.push({ capacity: plainChange, lock: src.changeLock, type: null });
    data.push("0x");
  }

  for (const o of outputs) {
    const need = occupiedCapacity(o, data[outputs.indexOf(o)] ?? "0x");
    if (o.capacity < need) throw new Error("an output is below its occupied capacity");
  }

  const tx: Transaction = {
    version: 0,
    cellDeps: [network.secpDep, network.xudtDep],
    headerDeps: [],
    inputs: selected.map((c) => ({ since: 0n, previousOutput: c.outPoint })),
    outputs,
    outputsData: data,
    witnesses: selected.map(() => "0x"),
  };

  const proofs = await resolveProofs(tx, rpc);
  const psct = buildPsct(tx, {
    network: network.prefix,
    proofs,
    account: src.accountHint,
    inputHints: selected.map(() => ({ derivation: src.derivation })),
    outputHints: outputs.map((o, i) => ({ role: o.type ? "token" : i === 0 ? "payment" : "change" })),
  });
  return {
    psct,
    tx,
    fee,
    change: plainChange,
    typeScript: opts.typeScript,
    detail: `transfer ${opts.amount} units`,
  };
}
