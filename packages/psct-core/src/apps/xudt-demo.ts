/**
 * xUDT mint + transfer on the devnet.
 *
 *   offckb node
 *   npx tsx src/apps/xudt-demo.ts
 */

import { execSync } from "node:child_process";
import { toRpcTx, type Transaction } from "../ckb.js";
import { Rpc } from "../rpc.js";
import { buildXudtMint, buildXudtTransfer } from "./xudt.js";
import { signPsct } from "./signer.js";
import { finalizePsct, psctFingerprint } from "../psct/container.js";

const CKB = 100_000_000n;

function accounts(): { address: string; privkey: string }[] {
  const out = execSync("npx --yes offckb accounts --show-private-keys --json", {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
  });
  return JSON.parse(out.trim().split(/\r?\n/).filter((l) => l.startsWith('{"ok":true')).pop()!).accounts;
}

async function send(rpc: Rpc, tx: Transaction, label: string) {
  const hash = await rpc.call<string>("send_transaction", [toRpcTx(tx)]);
  console.log(`${label}: sent ${hash}`);
  for (let i = 0; i < 60; i++) {
    const res = await rpc.call<{ tx_status: { block_number: string | null } }>("get_transaction", [hash, "0x0"]);
    if (res.tx_status.block_number) {
      console.log(`${label}: committed in ${BigInt(res.tx_status.block_number)}`);
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${label}: not committed`);
}

async function main() {
  const rpc = new Rpc("http://127.0.0.1:8114");
  const a = accounts();
  const a0 = a[0]!;
  const a4 = a[4]!;

  const mint = await buildXudtMint({
    network: "devnet",
    from: a0.address,
    amount: 1_000_000n,
    capacity: 1000n * CKB,
  });
  console.log("mint", psctFingerprint(mint.psct), mint.detail, "type", mint.typeScript.args.slice(0, 18));
  await send(rpc, finalizePsct(signPsct(mint.psct, a0.privkey).psct), "mint");

  const transfer = await buildXudtTransfer({
    network: "devnet",
    from: a0.address,
    to: a4.address,
    typeScript: mint.typeScript,
    amount: 400_000n,
    outputCapacity: 300n * CKB,
  });
  console.log("transfer", psctFingerprint(transfer.psct), transfer.detail, "ckb change", transfer.change.toString());
  await send(rpc, finalizePsct(signPsct(transfer.psct, a0.privkey).psct), "transfer");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
