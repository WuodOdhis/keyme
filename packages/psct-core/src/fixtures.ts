/** Fixture loading: normalized transactions + input proofs, no RPC. */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { CellOutput, Script, Transaction } from "./ckb.js";
import type { InputProof } from "./psct/bind.js";

export interface ManifestEntry {
  hash: string;
  inputs: number;
  outputs: number;
  fee: string;
}

export interface Fixture {
  hash: string;
  tx: Transaction;
  proofs: InputProof[];
  fee: string;
  /** Raw headers by hash, for header_deps (Nervos DAO withdraws need them). */
  headers: Map<string, string>;
}

const DIR = join(process.cwd(), "fixtures");
const cache = new Map<string, Fixture>();

function reviveScript(o: Script): Script {
  return { codeHash: o.codeHash, hashType: o.hashType, args: o.args };
}

function reviveOutput(o: CellOutput): CellOutput {
  return {
    capacity: BigInt(o.capacity as unknown as string),
    lock: reviveScript(o.lock),
    type: o.type ? reviveScript(o.type) : null,
  };
}

export function reviveTx(o: any): Transaction {
  return {
    version: Number(o.version),
    cellDeps: o.cellDeps.map((d: any) => ({ outPoint: d.outPoint, depType: d.depType })),
    headerDeps: o.headerDeps,
    inputs: o.inputs.map((i: any) => ({
      since: BigInt(i.since as unknown as string),
      previousOutput: i.previousOutput,
    })),
    outputs: o.outputs.map(reviveOutput),
    outputsData: o.outputsData,
    witnesses: o.witnesses,
  };
}

/** Generic JSON projection: bigint -> decimal string, recursively. */
export function toJson(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(toJson);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, toJson(v)]),
    );
  }
  return value;
}

export function loadManifest(): ManifestEntry[] {
  return JSON.parse(readFileSync(join(DIR, "manifest.json"), "utf8"));
}

export function loadFixture(hash: string): Fixture {
  const hit = cache.get(hash);
  if (hit) return hit;
  const entry = loadManifest().find((m) => m.hash === hash);
  if (!entry) throw new Error(`fixture ${hash} not in manifest`);
  const f = JSON.parse(readFileSync(join(DIR, `${hash}.json`), "utf8"));
  const fixture: Fixture = {
    hash,
    tx: reviveTx(f.tx),
    proofs: f.proofs.map((p: any) => ({
      prevTx: reviveTx(p.prevTx),
      index: p.index,
      blockHash: p.blockHash,
    })),
    fee: entry.fee,
    headers: new Map(
      Object.entries(f.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v as string]),
    ),
  };
  cache.set(hash, fixture);
  return fixture;
}

/** A fixture whose first lock group is a supported, verifiable profile. */
export function loadPlainFixture(): Fixture {
  for (const m of loadManifest()) {
    const f = loadFixture(m.hash);
    if (f.tx.inputs.length === 1) return f;
  }
  return loadFixture(loadManifest()[0]!.hash);
}
