/**
 * Offline fixture test — no RPC.
 *
 * Proves, without a node:
 *   - the fixture's bytes re-hash to the recorded tx_hash
 *   - every input binds to its creating transaction
 *   - every known-profile signature verifies
 *   - the recorded fee matches inspection (including DAO interest when headers are present)
 *
 * Run: npx tsx src/scripts/offline.ts
 */

import { bindAll } from "../psct/bind.js";
import { inspect } from "../psct/inspect.js";
import { txHash } from "../hash.js";
import { verifyTx } from "../verify.js";
import { loadFixture, loadManifest } from "../fixtures.js";

function main() {
  const manifest = loadManifest();
  let failures = 0;
  let groupsVerified = 0;
  let noProfile = 0;
  const unknownLocks = new Map<string, number>();

  for (const entry of manifest) {
    const f = loadFixture(entry.hash);
    const { tx } = f;
    const problems: string[] = [];

    if (txHash(tx) !== entry.hash) problems.push(`tx_hash ${txHash(tx)}`);

    let bound;
    try {
      bound = bindAll(tx, f.proofs);
    } catch (e) {
      console.log(`FAIL ${entry.hash}: ${(e as Error).message}`);
      failures++;
      continue;
    }

    const r = inspect(tx, bound, { headers: f.headers });
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
      const dao = r.dao.length ? ` dao=${r.dao.map((d) => d.kind).join(",")}` : "";
      console.log(
        `ok   ${entry.hash.slice(0, 18)}… inputs=${entry.inputs} groups=${results.length} fee=${entry.fee}${dao}`,
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
