/**
 * DAO end-to-end on a 1-block-epoch devnet.
 *
 *   offckb node (or the bundled ckb with an edited dev.toml)
 *   npx tsx src/apps/dao-demo.ts
 *
 * deposit -> prepare -> wait 180 epochs -> withdraw, each step through the coordinator/signer.
 */

import { execSync } from "node:child_process";
import { toRpcTx, type Transaction } from "../ckb.js";
import { Rpc } from "../rpc.js";
import { networkByName } from "../network.js";
import { buildDaoDeposit, buildDaoPrepare, buildDaoWithdraw } from "./dao.js";
import { signPsct } from "./signer.js";
import { finalizePsct, psctFingerprint } from "../psct/container.js";

const CKB = 100_000_000n;

function accounts(): { address: string; privkey: string }[] {
  const out = execSync("npx --yes offckb accounts --show-private-keys --json", {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
  });
  const line = out.trim().split(/\r?\n/).filter((l) => l.startsWith('{"ok":true')).pop()!;
  return JSON.parse(line).accounts;
}

async function send(rpc: Rpc, tx: Transaction, label: string): Promise<bigint> {
  const hash = await rpc.call<string>("send_transaction", [toRpcTx(tx)]);
  console.log(`${label}: sent ${hash}`);
  for (let i = 0; i < 120; i++) {
    const res = await rpc.call<{ tx_status: { block_number: string | null } }>("get_transaction", [hash, "0x0"]);
    if (res.tx_status.block_number) {
      const n = BigInt(res.tx_status.block_number);
      console.log(`${label}: committed in ${n}`);
      return n;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${label}: not committed`);
}

async function tipEpoch(rpc: Rpc): Promise<bigint> {
  const h = await rpc.call<any>("get_tip_header", []);
  return BigInt(h.epoch) & 0xffffffn;
}

async function main() {
  const network = networkByName("devnet");
  const rpc = new Rpc(network.rpc);
  const dev = accounts();
  const a0 = dev[0]!;
  const a4 = dev[4]!;

  console.log("tip epoch", await tipEpoch(rpc));

  const deposit = await buildDaoDeposit({ network: "devnet", from: a0.address, amount: 500n * CKB });
  console.log("deposit", psctFingerprint(deposit.psct));
  const depositBlock = await send(rpc, finalizePsct(signPsct(deposit.psct, a0.privkey).psct), "deposit");

  // The deposit's epoch is the block it landed in.
  const header = await rpc.call<any>("get_header_by_number", [`0x${depositBlock.toString(16)}`, "0x1"]);
  const depositEpoch = BigInt(header.epoch) & 0xffffffn;
  console.log("deposit epoch", depositEpoch);

  const prepare = await buildDaoPrepare({ network: "devnet", from: a0.address });
  console.log("prepare", psctFingerprint(prepare.psct), prepare.detail);
  await send(rpc, finalizePsct(signPsct(prepare.psct, a0.privkey).psct), "prepare");

  const target = depositEpoch + 180n;
  console.log(`waiting for epoch ${target}…`);
  for (;;) {
    const now = await tipEpoch(rpc);
    if (now >= target) {
      console.log("epoch", now);
      break;
    }
    if (now % 30n === 0n) console.log("  epoch", now);
    await new Promise((r) => setTimeout(r, 2000));
  }

  const withdraw = await buildDaoWithdraw({
    network: "devnet",
    from: a0.address,
    to: a4.address,
  });
  console.log("withdraw", psctFingerprint(withdraw.psct), withdraw.detail);
  await send(rpc, finalizePsct(signPsct(withdraw.psct, a0.privkey).psct), "withdraw");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
