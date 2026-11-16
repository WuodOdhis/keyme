/**
 * Find a real Spore transaction: any tx with a Spore V2 output.
 * Run: npx tsx src/scripts/find-spore.ts [blocks] [mainnet|testnet]
 */

import { MAINNET, TESTNET, type Rpc } from "../rpc.js";
import { SPORE_CLUSTER_V2_CODE_HASH, SPORE_V2_CODE_HASH, parseSporeData } from "../spore.js";

async function main() {
  const blocks = Number(process.argv[2] ?? 1200);
  const rpc: Rpc = process.argv[3] === "testnet" ? TESTNET : MAINNET;
  const tip = Number(await rpc.tip());
  console.log(`scanning ${blocks} blocks from ${tip}`);

  for (let d = 1; d <= blocks; d++) {
    for (const { hash, tx } of await rpc.blockTxs(tip - d)) {
      const hit = tx.outputs.findIndex((o) => {
        const h = o.type?.codeHash.toLowerCase();
        return h === SPORE_V2_CODE_HASH || h === SPORE_CLUSTER_V2_CODE_HASH;
      });
      if (hit < 0) continue;
      const t = tx.outputs[hit]!.type!;
      const data = parseSporeData(tx.outputsData[hit] ?? "0x");
      console.log(
        [
          `tx        ${hash}`,
          `block     ${tip - d}`,
          `platform  ${t.codeHash.toLowerCase() === SPORE_V2_CODE_HASH ? "spore" : "cluster"}`,
          `output    ${hit} id=${t.args.slice(0, 18)}…`,
          `content   ${data?.contentBytes ?? "?"} bytes ${data?.contentType ?? ""}`,
        ].join("\n"),
      );
      process.exit(0);
    }
    if (d % 250 === 0) console.log(`  ...${d}`);
  }
  console.log("not found");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
