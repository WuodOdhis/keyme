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
}

const DIR = join(process.cwd(), "fixtures");

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

export function loadManifest(): ManifestEntry[] {
  return JSON.parse(readFileSync(join(DIR, "manifest.json"), "utf8"));
}

export function loadFixture(hash: string): Fixture {
  const entry = loadManifest().find((m) => m.hash === hash);
  if (!entry) throw new Error(`fixture ${hash} not in manifest`);
  const f = JSON.parse(readFileSync(join(DIR, `${hash}.json`), "utf8"));
  return {
    hash,
    tx: reviveTx(f.tx),
    proofs: f.proofs.map((p: any) => ({ prevTx: reviveTx(p.prevTx), index: p.index })),
    fee: entry.fee,
  };
}

/** A fixture whose first lock group is a supported, verifiable profile. */
export function loadPlainFixture(): Fixture {
  for (const m of loadManifest()) {
    const f = loadFixture(m.hash);
    if (f.tx.inputs.length === 1) return f;
  }
  return loadFixture(loadManifest()[0]!.hash);
}
