/**
 * End-to-end stage-2 demo on a local devnet.
 *
 *   offckb node            (in another terminal)
 *   npx tsx src/apps/demo.ts
 *
 * Flow A: secp transfer, coordinator -> signer -> finalize -> broadcast.
 * Flow B: fund a 2-of-3 legacy multisig, spend it with two separate signers, combine, broadcast.
 */

import { execSync } from "node:child_process";
import { toRpcTx, type Transaction } from "../ckb.js";
import { encodeAddress } from "../address.js";
import { Rpc } from "../rpc.js";
import { networkByName } from "../network.js";
import { combinePsct, finalizePsct, psctFingerprint, psctTxHash, type Psct } from "../psct/container.js";
import { buildTransfer, multisigLock, type MultisigSpec } from "./coordinator.js";
import { signPsct } from "./signer.js";

const CKB = 100_000_000n;

interface Account {
  address: string;
  privkey: string;
}

function accounts(): Account[] {
  const out = execSync("npx --yes offckb accounts --show-private-keys --json", {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
  });
  const line = out
    .trim()
    .split(/\r?\n/)
    .filter((l) => l.startsWith('{"ok":true'))
    .pop();
  if (!line) throw new Error("cannot read offckb accounts");
  return JSON.parse(line).accounts;
}

async function sendAndWait(rpc: Rpc, tx: Transaction, label: string): Promise<string> {
  const hash = await rpc.call<string>("send_transaction", [toRpcTx(tx)]);
  console.log(`${label}: sent ${hash}`);
  for (let i = 0; i < 60; i++) {
    const res = await rpc.call<{ tx_status: { block_number: string | null } }>("get_transaction", [
      hash,
      "0x0",
    ]);
    if (res.tx_status.block_number) {
      console.log(`${label}: committed in ${BigInt(res.tx_status.block_number)}`);
      return hash;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${label}: not committed`);
}

function clone(p: Psct): Psct {
  return structuredClone(p);
}

async function main() {
  const network = networkByName("devnet");
  const rpc = new Rpc(network.rpc);
  const accountsList = accounts();
  const [a0, a1, a2, a3, a4] = accountsList;
  if (!a4) throw new Error("devnet needs at least five accounts");

  console.log(`tip ${BigInt(await rpc.tip())}`);
  console.log("");

  // ---- flow A: secp transfer
  console.log("== secp transfer");
  const transfer = await buildTransfer({
    network: "devnet",
    from: a0!.address,
    to: a1!.address,
    amount: 100n * CKB,
  });
  console.log(`coordinator: ${psctFingerprint(transfer.psct)} inputs=${transfer.tx.inputs.length}`);
  const signed = signPsct(transfer.psct, a0!.privkey);
  console.log(`signer:      groups=${signed.signedGroups.length} signer=${signed.signer}`);
  const final = finalizePsct(signed.psct);
  await sendAndWait(rpc, final, "transfer");
  console.log("");

  // ---- flow B: 2-of-3 legacy multisig
  console.log("== 2-of-3 legacy multisig");
  const spec: MultisigSpec = {
    signers: [a1!.address, a2!.address, a3!.address],
    threshold: 2,
    requireFirstN: 0,
    version: "legacy",
  };
  const { lock } = multisigLock(spec);
  const multisigAddress = encodeAddress(lock, network.prefix, "full");
  console.log(`multisig ${multisigAddress}`);

  const fund = await buildTransfer({
    network: "devnet",
    from: a0!.address,
    to: multisigAddress,
    amount: 200n * CKB,
  });
  const fundSigned = signPsct(fund.psct, a0!.privkey);
  await sendAndWait(rpc, finalizePsct(fundSigned.psct), "fund");

  const spend = await buildTransfer({
    network: "devnet",
    multisig: spec,
    to: a4!.address,
    amount: 100n * CKB,
  });
  console.log(`coordinator: ${psctFingerprint(spend.psct)} inputs=${spend.tx.inputs.length}`);

  const s1 = signPsct(clone(spend.psct), a1!.privkey);
  const s2 = signPsct(clone(spend.psct), a2!.privkey);
  console.log(`signer 1:    ${s1.signer}`);
  console.log(`signer 2:    ${s2.signer}`);
  const combined = combinePsct(s1.psct, s2.psct);
  const spendFinal = finalizePsct(combined);
  await sendAndWait(rpc, spendFinal, "spend");
  console.log("");
  console.log(`done. last tx ${psctTxHash(combined)}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
