/** Read-only inspection of a transaction, computed only from bound cells. */

import { bytesToHex, hexToBytes, fmtCkb } from "../bytes.js";
import { encodeCellOutput, type CellOutput, type Script, type Transaction } from "../ckb.js";
import { scriptHash, txHash } from "../hash.js";
import { classifyLock, classifyType } from "../profiles.js";
import type { BoundCell } from "./bind.js";

export interface Delta {
  key: string;
  kind: "ckb" | "token";
  input: bigint;
  output: bigint;
  delta: bigint;
  note?: string;
}

export interface Inspection {
  txHash: string;
  inputCapacity: bigint;
  outputCapacity: bigint;
  fee: bigint;
  feeCkb: string;
  occupied: { index: number; bytes: number; ckb: string }[];
  deltas: Delta[];
  changeCandidates: number[];
  warnings: string[];
}

function u128le(data: Uint8Array): bigint {
  let v = 0n;
  for (let i = 15; i >= 0; i--) v = (v << 8n) | BigInt(data[i] ?? 0);
  return v;
}

function typeKey(t: Script | null): string {
  if (!t) return "ckb";
  return `token:${scriptHash(t)}`;
}

export interface InspectOptions {
  /** Locks the signer considers its own (derived from the paired account, not from the file). */
  ownLocks?: Script[];
}

export function inspect(
  tx: Transaction,
  bound: BoundCell[],
  opts: InspectOptions = {},
): Inspection {
  if (bound.length !== tx.inputs.length) throw new Error("bound inputs do not match tx inputs");

  const inputCapacity = bound.reduce((n, b) => n + b.cellOutput.capacity, 0n);
  const outputCapacity = tx.outputs.reduce((n, o) => n + o.capacity, 0n);
  const fee = inputCapacity - outputCapacity;

  const occupied = tx.outputs.map((o, i) => {
    const bytes = 8 + encodeCellOutput(o).length + hexToBytes(tx.outputsData[i] ?? "0x").length;
    return { index: i, bytes, ckb: fmtCkb(BigInt(bytes) * 100_000_000n) };
  });

  const deltas = new Map<string, Delta>();
  const bump = (key: string, kind: "ckb" | "token", side: "input" | "output", amount: bigint) => {
    const d = deltas.get(key) ?? { key, kind, input: 0n, output: 0n, delta: 0n };
    d[side] += amount;
    d.delta = d.output - d.input;
    deltas.set(key, d);
  };
  const warnings: string[] = [];

  // xUDT stores the amount as a 16-byte LE integer. Anything else is a typed cell whose
  // semantics we do not know, and must not be presented as a token movement.
  const amountOf = (dataHex: string, where: string): bigint | null => {
    const data = hexToBytes(dataHex);
    if (data.length === 16) return u128le(data);
    warnings.push(`${where}: typed cell with ${data.length}-byte data — semantics unknown`);
    return null;
  };

  bound.forEach((b, i) => {
    const c = b.cellOutput;
    if (!c.type) {
      bump("ckb", "ckb", "input", c.capacity);
      return;
    }
    bump("ckb-locked", "ckb", "input", c.capacity);
    const amount = amountOf(b.data, `input ${i}`);
    if (amount !== null) bump(typeKey(c.type), "token", "input", amount);
  });
  tx.outputs.forEach((o, i) => {
    if (!o.type) {
      bump("ckb", "ckb", "output", o.capacity);
      return;
    }
    bump("ckb-locked", "ckb", "output", o.capacity);
    const amount = amountOf(tx.outputsData[i] ?? "0x", `output ${i}`);
    if (amount !== null) bump(typeKey(o.type), "token", "output", amount);
  });

  // Change candidates: outputs whose lock matches a lock the signer considers its own.
  const own = opts.ownLocks ?? bound.map((b) => b.cellOutput.lock);
  const changeCandidates = tx.outputs
    .map((o, i) => i)
    .filter((i) => own.some((l) => sameLock(tx.outputs[i]!.lock, l)));

  for (const [key, d] of deltas) {
    if (d.kind === "token" && d.delta !== 0n) {
      warnings.push(`token ${key.slice(6, 18)}… net change ${d.delta} (check direction)`);
    }
  }
  tx.outputs.forEach((o, i) => {
    if (o.type) warnings.push(`output ${i}: type script ${classifyType(o.type)} (not fully resolved)`);
    if (!o.type && hexToBytes(tx.outputsData[i] ?? "0x").length > 0) {
      warnings.push(`output ${i}: carries data but has no type script`);
    }
  });

  bound.forEach((b, i) => {
    const p = classifyLock(b.cellOutput.lock);
    if (p.kind === "unknown") {
      warnings.push(`input ${i}: lock unknown (${b.cellOutput.lock.codeHash.slice(0, 18)}…)`);
    } else if (p.profile === null) {
      warnings.push(`input ${i}: lock "${p.name}" — no verification profile`);
    }
  });
  if (fee < 0n) warnings.push(`negative fee: outputs exceed inputs — invalid transaction`);
  if (fee > 100_000_000n) warnings.push(`fee above 1 CKB (${fmtCkb(fee)}) — verify manually`);
  if (changeCandidates.length === 0) warnings.push(`no change output recognised`);

  return {
    txHash: txHash(tx),
    inputCapacity,
    outputCapacity,
    fee,
    feeCkb: fmtCkb(fee),
    occupied,
    deltas: [...deltas.values()],
    changeCandidates,
    warnings,
  };
}

function sameLock(a: Script, b: Script): boolean {
  return (
    a.codeHash.toLowerCase() === b.codeHash.toLowerCase() &&
    a.hashType === b.hashType &&
    a.args.toLowerCase() === b.args.toLowerCase()
  );
}
