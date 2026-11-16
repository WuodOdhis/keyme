/**
 * Account-pairing demo on a local devnet.
 *
 *   offckb node
 *   npx tsx src/apps/pairing-demo.ts
 *
 * 1. derive an account from a fresh seed (m/44'/1'/0')
 * 2. fund its external address /0/0 from a devnet account
 * 3. build a transfer with change to /1/0
 * 4. sign with the derived key and a paired account; the signer certifies the change
 */

import { execSync } from "node:child_process";
import { bytesToHex } from "../bytes.js";
import { toRpcTx, type Transaction } from "../ckb.js";
import { encodeAddress } from "../address.js";
import { Rpc } from "../rpc.js";
import { networkByName } from "../network.js";
import { accountFromSeed, deriveAddresses } from "../account.js";
import { derivePrivate, privateKeyHex } from "../bip32.js";
import { finalizePsct, psctFingerprint } from "../psct/container.js";
import { buildTransfer } from "./coordinator.js";
import { describePsct, signPsct } from "./signer.js";

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
  const network = networkByName("devnet");
  const rpc = new Rpc(network.rpc);
  const dev = accounts();
  const a0 = dev[0]!;
  const a4 = dev[4]!;

  const seed = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const { account, node } = accountFromSeed(seed, "testnet");
  const addrs = deriveAddresses(account.xpub, 2);
  const external = encodeAddress(addrs.external[0]!.script, "ckt");
  const change = encodeAddress(addrs.change[0]!.script, "ckt");
  console.log("account", bytesToHex(account.fingerprint));
  console.log("xpub   ", account.xpub);
  console.log("external", external);
  console.log("change  ", change);

  // fund the derived external address
  const fund = await buildTransfer({ network: "devnet", from: a0.address, to: external, amount: 500n * CKB });
  await send(rpc, finalizePsct(signPsct(fund.psct, a0.privkey).psct), "fund");

  // spend from the paired account, change to /1/0
  const spend = await buildTransfer({
    network: "devnet",
    account: { xpub: account.xpub, index: 0 },
    to: a4.address,
    amount: 100n * CKB,
  });
  console.log("coordinator", psctFingerprint(spend.psct), "from", spend.fromAddress);

  const described = describePsct(spend.psct, account);
  for (const l of described.lines) console.log(l);
  for (const w of described.warnings) console.log(`  warn: ${w}`);

  const priv = privateKeyHex(derivePrivate(node, "0/0"));
  const signed = signPsct(spend.psct, priv, account);
  console.log("signer", signed.signer, "groups", signed.signedGroups.length);
  await send(rpc, finalizePsct(signed.psct), "spend");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
