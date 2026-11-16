/**
 * Find a real Nervos DAO withdraw (phase 2) by scanning blocks.
 *
 * Withdrawing inputs are DAO-typed cells with a non-zero 8-byte block number, and the transaction
 * must carry the deposit header in header_deps.
 *
 * Run: npx tsx src/scripts/find-dao.ts [blocks] [mainnet|testnet]
 */

import { hexToBytes } from "../bytes.js";
import { MAINNET, TESTNET, type Rpc } from "../rpc.js";
import { DAO_CODE_HASH, classifyDaoCell } from "../dao.js";
import type { Transaction } from "../ckb.js";

async function main() {
  const blocks = Number(process.argv[2] ?? 800);
  const rpc: Rpc = process.argv[3] === "testnet" ? TESTNET : MAINNET;
  const tip = Number(await rpc.tip());
  const cache = new Map<string, Transaction>();
  console.log(`scanning ${blocks} blocks from ${tip}`);

  for (let d = 1; d <= blocks; d++) {
    for (const { hash, tx } of await rpc.blockTxs(tip - d)) {
      if (tx.headerDeps.length === 0) continue;

      for (const input of tx.inputs) {
        const op = input.previousOutput;
        let prev = cache.get(op.txHash);
        if (!prev) {
          try {
            prev = await rpc.tx(op.txHash);
          } catch {
            continue;
          }
          cache.set(op.txHash, prev);
        }
        const out = prev.outputs[op.index];
        const data = prev.outputsData[op.index] ?? "0x";
        if (!out?.type) continue;
        if (out.type.codeHash.toLowerCase() !== DAO_CODE_HASH) continue;
        const cell = classifyDaoCell(data);
        if (!cell || cell.kind !== "withdrawing") continue;

        console.log(
          [
            `tx            ${hash}`,
            `block         ${tip - d}`,
            `depositBlock  ${cell.depositBlockNumber}`,
            `header_deps   ${tx.headerDeps.join(" ")}`,
            `since         ${tx.inputs[tx.inputs.indexOf(input)]!.since}`,
            `witnesses     ${tx.witnesses.length}`,
          ].join("\n"),
        );
        process.exit(0);
      }
    }
    if (d % 100 === 0) console.log(`  ...${d}`);
  }
  console.log("not found");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
