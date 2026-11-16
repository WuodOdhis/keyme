/**
 * Collect offline fixtures: a real transaction plus its input proofs, as normalized JSON.
 *
 * Fixtures are the regression base for the spec. Everything a verifier needs must be here —
 * no RPC at verify time.
 *
 * Run: npx tsx src/scripts/collect.ts [count]
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { MAINNET } from "../rpc.js";
import type { RpcTransaction, Transaction } from "../ckb.js";
import { resolveProofs } from "../psct/proofs.js";
import { bindAll } from "../psct/bind.js";
import { classifyLock } from "../profiles.js";
import { isDaoType } from "../dao.js";
import { toJson } from "../fixtures.js";
import { txHash } from "../hash.js";
import type { InputProof } from "../psct/bind.js";

const OUT = join(process.cwd(), "fixtures");

async function main() {
  const want = Number(process.argv[2] ?? 6);
  mkdirSync(OUT, { recursive: true });
  const manifest: { hash: string; inputs: number; outputs: number; fee: string }[] = [];
  const tip = Number(await MAINNET.tip());
  const seen = new Set<string>();

  for (let d = 1; d < 120 && manifest.length < want; d++) {
    for (const { hash, tx } of await MAINNET.blockTxs(tip - d)) {
      if (seen.has(hash)) continue;
      if (tx.inputs.some((i) => /^0x0+$/.test(i.previousOutput.txHash))) continue;
      if (tx.witnesses.length === 0) continue;

      const computed = txHash(tx);
      if (computed !== hash) {
        console.warn(`skip ${hash}: tx_hash mismatch (${computed})`);
        continue;
      }

      const proofs = await resolveProofs(tx, MAINNET);
      let bound;
      try {
        bound = bindAll(tx, proofs);
      } catch (e) {
        console.warn(`skip ${hash}: ${(e as Error).message}`);
        continue;
      }

      // Keep the corpus representative: unknown locks are refusal cases, not payment fixtures.
      const unknown = bound.map((b) => classifyLock(b.cellOutput.lock)).find((k) => k.kind === "unknown");
      if (unknown) {
        console.warn(`skip ${hash}: ${unknown.name}`);
        continue;
      }

      // DAO transactions mint interest and need headers; import them deliberately with import-tx.
      if (tx.headerDeps.length > 0 || bound.some((b) => isDaoType(b.cellOutput.type))) {
        console.warn(`skip ${hash}: Nervos DAO transaction (use import-tx)`);
        continue;
      }
      const fee = bound.reduce((n, b) => n + b.cellOutput.capacity, 0n) - tx.outputs.reduce((n, o) => n + o.capacity, 0n);

      const fixture = {
        hash,
        tx: toJson(tx),
        proofs: proofs.map((p: InputProof) => ({ index: p.index, prevTx: toJson(p.prevTx) })),
      };
      writeFileSync(join(OUT, `${hash}.json`), JSON.stringify(fixture, null, 2));
      manifest.push({ hash, inputs: tx.inputs.length, outputs: tx.outputs.length, fee: fee.toString() });
      seen.add(hash);
      if (manifest.length >= want) break;
    }
  }

  manifest.sort((a, b) => Number(BigInt(a.fee) - BigInt(b.fee)));
  writeFileSync(join(OUT, "manifest.json"), JSON.stringify(manifest, null, 2));
  console.log(`wrote ${manifest.length} fixtures to ${OUT}`);
  for (const m of manifest) console.log(`  ${m.hash} inputs=${m.inputs} fee=${m.fee}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
