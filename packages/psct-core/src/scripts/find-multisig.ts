/**
 * Find a real multisig spend by scanning blocks.
 *
 * Cheap filter first (witness lock field matches 4 + 20n + 65t), then confirm the input lock is
 * the legacy multisig script.
 *
 * Run: npx tsx src/scripts/find-multisig.ts [blocks] [mainnet|testnet]
 */

import { hexToBytes, bytesToHex } from "../bytes.js";
import { witnessLock } from "../sighash.js";
import { MAINNET, TESTNET } from "../rpc.js";

const MULTISIG = "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8";

async function main() {
  const blocks = Number(process.argv[2] ?? 600);
  const rpc = process.argv[3] === "testnet" ? TESTNET : MAINNET;
  const tip = Number(await rpc.tip());
  console.log(`scanning ${blocks} blocks from ${tip}`);

  for (let d = 1; d <= blocks; d++) {
    const txs = await rpc.blockTxs(tip - d);
    for (const { hash, tx } of txs) {
      for (const w of tx.witnesses) {
        let lock: Uint8Array | null;
        try {
          lock = witnessLock(w);
        } catch {
          continue;
        }
        if (!lock || lock.length < 4) continue;
        const n = lock[3]!;
        const t = lock[2]!;
        if (n === 0 || t === 0 || t > n) continue;
        if (lock.length !== 4 + 20 * n + 65 * t) continue;

        // Shape matches; confirm the lock used by an input.
        for (const input of tx.inputs) {
          const op = input.previousOutput;
          let prev;
          try {
            prev = await rpc.tx(op.txHash);
          } catch {
            continue;
          }
          const out = prev.outputs[op.index];
          if (out?.lock.codeHash !== MULTISIG) continue;
          console.log(
            [
              `tx        ${hash}`,
              `block     ${tip - d}`,
              `lock      ${out.lock.args}`,
              `n=${n} threshold=${t} requireFirst=${lock[1]}`,
              `lockLen   ${lock.length}`,
              `witness   ${bytesToHex(lock).slice(0, 80)}…`,
            ].join("\n"),
          );
          process.exit(0);
        }
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
