/**
 * Find a DAO phase-1 transaction (deposit -> withdrawing) by scanning blocks: input is a DAO cell
 * with zero data, output at the same index is a DAO cell with a block number.
 *
 * Run: npx tsx src/scripts/find-dao-prepare.ts [blocks]
 */

import { MAINNET, type Rpc } from "../rpc.js";
import { DAO_CODE_HASH, classifyDaoCell, isDaoType } from "../dao.js";
import type { Transaction } from "../ckb.js";
import { hexToBytes } from "../bytes.js";

async function main() {
  const blocks = Number(process.argv[2] ?? 800);
  const rpc: Rpc = MAINNET;
  const tip = Number(await rpc.tip());
  const cache = new Map<string, Transaction>();
  console.log(`scanning ${blocks} blocks from ${tip}`);

  for (let d = 1; d <= blocks; d++) {
    for (const { hash, tx } of await rpc.blockTxs(tip - d)) {
      // Cheap shape filter: some output is a DAO cell with non-zero data.
      const candidate = tx.outputs.some(
        (o, i) => isDaoType(o.type) && (classifyDaoCell(tx.outputsData[i] ?? "0x")?.kind === "withdrawing"),
      );
      if (!candidate) continue;

      for (let i = 0; i < tx.inputs.length; i++) {
        const op = tx.inputs[i]!.previousOutput;
        let prev = cache.get(op.txHash);
        if (!prev) {
          try {
            prev = await rpc.tx(op.txHash);
          } catch {
            continue;
          }
          cache.set(op.txHash, prev);
        }
        const cell = prev.outputs[op.index];
        const data = prev.outputsData[op.index] ?? "0x";
        if (!cell?.type) continue;
        if (cell.type.codeHash.toLowerCase() !== DAO_CODE_HASH) continue;
        const parsed = classifyDaoCell(data);
        if (!parsed || parsed.kind !== "deposit") continue;
        if (!isDaoType(tx.outputs[i]?.type ?? null)) continue;

        console.log(
          [
            `tx          ${hash}`,
            `block       ${tip - d}`,
            `input       ${i} (deposit, 0 data)`,
            `output      ${i} data=${tx.outputsData[i]} capacity=${tx.outputs[i]!.capacity}`,
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
