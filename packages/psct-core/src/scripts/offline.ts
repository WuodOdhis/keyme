/**
 * Offline fixture test — no RPC.
 *
 * Proves three things without a node:
 *   - the fixture's bytes re-hash to the recorded tx_hash
 *   - every input binds to its creating transaction
 *   - every known-profile signature verifies
 *
 * Run: npx tsx src/scripts/offline.ts
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { Transaction, CellOutput, Script } from "../ckb.js";
import { bindAll, type InputProof } from "../psct/bind.js";
import { inspect } from "../psct/inspect.js";
import { txHash } from "../hash.js";
import { verifyTx } from "../verify.js";

interface ManifestEntry {
  hash: string;
  inputs: number;
  outputs: number;
  fee: string;
}

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

function reviveTx(o: any): Transaction {
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

function main() {
  const dir = join(process.cwd(), "fixtures");
  const manifest: ManifestEntry[] = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  let failures = 0;
  let groupsVerified = 0;
  let noProfile = 0;
  const unknownLocks = new Map<string, number>();

  for (const entry of manifest) {
    const file = join(dir, `${entry.hash}.json`);
    if (!readdirSync(dir).includes(`${entry.hash}.json`)) {
      console.log(`FAIL ${entry.hash}: fixture missing`);
      failures++;
      continue;
    }
    const f = JSON.parse(readFileSync(file, "utf8"));
    const tx = reviveTx(f.tx);
    const proofs: InputProof[] = f.proofs.map((p: any) => ({
      prevTx: reviveTx(p.prevTx),
      index: p.index,
    }));

    const problems: string[] = [];
    if (txHash(tx) !== entry.hash) problems.push(`tx_hash ${txHash(tx)}`);

    let bound;
    try {
      bound = bindAll(tx, proofs);
    } catch (e) {
      console.log(`FAIL ${entry.hash}: ${(e as Error).message}`);
      failures++;
      continue;
    }

    const r = inspect(tx, bound);
    if (r.fee.toString() !== entry.fee) problems.push(`fee ${r.fee} != ${entry.fee}`);

    const results = verifyTx(tx, bound);
    for (const g of results) {
      switch (g.verdict) {
        case "verified":
          groupsVerified++;
          break;
        case "no-profile":
          noProfile++;
          break;
        case "unknown-lock":
          unknownLocks.set(g.scriptHash, (unknownLocks.get(g.scriptHash) ?? 0) + 1);
          break;
        default:
          problems.push(`${g.name} inputs=[${g.inputs}] ${g.verdict}: ${g.reason ?? ""}`);
      }
    }

    if (problems.length) {
      failures++;
      console.log(`FAIL ${entry.hash}`);
      for (const p of problems) console.log(`     ${p}`);
    } else {
      console.log(
        `ok   ${entry.hash.slice(0, 18)}… inputs=${entry.inputs} groups=${results.length} fee=${entry.fee}`,
      );
    }
  }

  console.log("");
  console.log(`fixtures              ${manifest.length}`);
  console.log(`groups verified       ${groupsVerified}`);
  console.log(`refused: no profile   ${noProfile}`);
  console.log(`refused: unknown lock ${[...unknownLocks.values()].reduce((a, b) => a + b, 0)}`);
  for (const [hash, n] of [...unknownLocks.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`  unknown lock ${hash.slice(0, 18)}… x${n}`);
  }
  console.log(`failures              ${failures}`);
  if (failures) process.exitCode = 1;
}

main();
