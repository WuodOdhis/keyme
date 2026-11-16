/**
 * Find a real xUDT transaction: any transaction with an xUDT-typed output.
 * Run: npx tsx src/scripts/find-xudt.ts [blocks]
 */

import { MAINNET } from "../rpc.js";
import { XUDT_CODE_HASH, tokenAmount } from "../xudt.js";

async function main() {
  const blocks = Number(process.argv[2] ?? 2000);
  const tip = Number(await MAINNET.tip());
  console.log(`scanning ${blocks} blocks from ${tip}`);

  for (let d = 1; d <= blocks; d++) {
    for (const { hash, tx } of await MAINNET.blockTxs(tip - d)) {
      const hit = tx.outputs.findIndex((o) => o.type?.codeHash.toLowerCase() === XUDT_CODE_HASH);
      if (hit < 0) continue;
      console.log(
        [
          `tx      ${hash}`,
          `block   ${tip - d}`,
          `output  ${hit} amount=${tokenAmount(tx.outputsData[hit] ?? "0x")}`,
          `args    ${tx.outputs[hit]!.type!.args}`,
          `inputs  ${tx.inputs.length} outputs ${tx.outputs.length}`,
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
