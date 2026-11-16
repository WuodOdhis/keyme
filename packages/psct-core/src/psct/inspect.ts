/** Read-only inspection of a transaction, computed only from bound cells. */

import { bytesToHex, hexToBytes, fmtCkb } from "../bytes.js";
import type { Script, Transaction } from "../ckb.js";
import { occupiedBytes } from "../capacity.js";
import { txHash } from "../hash.js";
import { classifyLock, classifyType } from "../profiles.js";
import { inspectDao, isDaoType, type DaoFinding } from "../dao.js";
import { summarizeTokens, tokenKind, type TokenSummary } from "../xudt.js";
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
  dao: DaoFinding[];
  /** DAO interest minted by this transaction (0 when there is no withdraw). */
  daoInterest: bigint;
  /** False when a withdraw is present but its headers are missing, so interest is unknown. */
  interestKnown: boolean;
  tokens: TokenSummary[];
}

export interface InspectOptions {
  /** Locks the signer considers its own (derived from the paired account, not from the file). */
  ownLocks?: Script[];
  /** Raw headers by hash. DAO withdraws need the deposit header and the withdrawing cell's block. */
  headers?: Map<string, string>;
}

export function inspect(
  tx: Transaction,
  bound: BoundCell[],
  opts: InspectOptions = {},
): Inspection {
  if (bound.length !== tx.inputs.length) throw new Error("bound inputs do not match tx inputs");

  const inputCapacity = bound.reduce((n, b) => n + b.cellOutput.capacity, 0n);
  const outputCapacity = tx.outputs.reduce((n, o) => n + o.capacity, 0n);

  // DAO withdraws mint interest, so inputs - outputs is not the fee. Compute it from the headers
  // when they are present, and say so when they are not.
  const dao = inspectDao(tx, bound, { headers: opts.headers ?? new Map() });
  const withdrawing = dao.filter((f) => f.kind === "withdrawing");
  const interestKnown = withdrawing.every((f) => f.interest !== undefined);
  const daoInterest = withdrawing.reduce((n, f) => n + (f.interest ?? 0n), 0n);
  const fee = inputCapacity + daoInterest - outputCapacity;

  const occupied = tx.outputs.map((o, i) => {
    const bytes = occupiedBytes(o, tx.outputsData[i] ?? "0x");
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

  const tokens = summarizeTokens(tx, bound);

  bound.forEach((b, i) => {
    const c = b.cellOutput;
    if (!c.type) {
      bump("ckb", "ckb", "input", c.capacity);
      return;
    }
    bump("ckb-locked", "ckb", "input", c.capacity);
    if (isDaoType(c.type)) return; // DAO data is a block number, not an amount
    if (!tokenKind(c.type)) {
      const len = (b.data.length - 2) / 2;
      warnings.push(`input ${i}: typed cell with ${len}-byte data — semantics unknown`);
    }
  });
  tx.outputs.forEach((o, i) => {
    if (!o.type) {
      bump("ckb", "ckb", "output", o.capacity);
      return;
    }
    bump("ckb-locked", "ckb", "output", o.capacity);
    if (isDaoType(o.type)) return;
    if (!tokenKind(o.type)) {
      const len = ((tx.outputsData[i] ?? "0x").length - 2) / 2;
      warnings.push(`output ${i}: typed cell with ${len}-byte data — semantics unknown`);
    }
  });

  // Token movements come from the xUDT/sUDT summary, not from "any 16-byte data" heuristics.
  for (const t of tokens) {
    deltas.set(`token:${t.typeHash}`, {
      key: `token:${t.typeHash}`,
      kind: "token",
      input: t.input,
      output: t.output,
      delta: t.delta,
    });
  }

  // Change candidates: outputs whose lock matches a lock the signer considers its own.
  const own = opts.ownLocks ?? bound.map((b) => b.cellOutput.lock);
  const changeCandidates = tx.outputs
    .map((o, i) => i)
    .filter((i) => own.some((l) => sameLock(tx.outputs[i]!.lock, l)));

  for (const t of tokens) {
    for (const issue of t.issues) warnings.push(`token ${t.typeHash.slice(0, 12)}…: ${issue}`);
    if (t.delta > 0n) {
      warnings.push(
        `token ${t.typeHash.slice(0, 12)}…: ${t.ownerMode ? "owner-mode mint" : "mint"} of ${t.delta}`,
      );
    } else if (t.delta < 0n) {
      warnings.push(`token ${t.typeHash.slice(0, 12)}…: burns ${-t.delta}`);
    }
  }
  tx.outputs.forEach((o, i) => {
    if (o.type && !isDaoType(o.type) && classifyType(o.type) === "unknown type") {
      warnings.push(`output ${i}: type script unknown (${o.type.codeHash.slice(0, 18)}…)`);
    }
    if (!o.type && hexToBytes(tx.outputsData[i] ?? "0x").length > 0) {
      warnings.push(`output ${i}: carries data but has no type script`);
    }
  });

  for (const f of dao) {
    for (const issue of f.issues) warnings.push(`input ${f.input} (DAO ${f.kind}): ${issue}`);
  }
  if (withdrawing.length > 0) {
    if (!interestKnown) {
      warnings.push("DAO withdraw: interest is unknown (missing header), so the fee is a lower bound");
    } else if (daoInterest > 0n) {
      warnings.push(`DAO withdraw mints ${fmtCkb(daoInterest)} CKB of interest`);
    }
  }

  bound.forEach((b, i) => {
    const p = classifyLock(b.cellOutput.lock);
    if (p.kind === "unknown") {
      warnings.push(`input ${i}: lock unknown (${b.cellOutput.lock.codeHash.slice(0, 18)}…)`);
    } else if (p.profile === null) {
      warnings.push(`input ${i}: lock "${p.name}" — no verification profile`);
    }
  });
  if (fee < 0n && interestKnown) {
    warnings.push(`negative fee: outputs exceed inputs and DAO interest — invalid transaction`);
  }
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
    dao,
    daoInterest,
    interestKnown,
    tokens,
  };
}

function sameLock(a: Script, b: Script): boolean {
  return (
    a.codeHash.toLowerCase() === b.codeHash.toLowerCase() &&
    a.hashType === b.hashType &&
    a.args.toLowerCase() === b.args.toLowerCase()
  );
}
