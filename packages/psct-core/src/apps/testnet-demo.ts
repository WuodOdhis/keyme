/**
 * Testnet end-to-end run: coordinator -> signer -> finalize -> broadcast.
 *
 *   npx tsx src/apps/testnet-demo.ts --key-file key.hex --from ckt1... [--amount 100]
 *
 * The recipient is a fresh key so no funding is needed for it.
 */

import { readFileSync } from "node:fs";
import { secp256k1 } from "@noble/curves/secp256k1";

import { bytesToHex, hexToBytes } from "../bytes.js";
import { blake160 } from "../hash.js";
import { encodeAddress } from "../address.js";
import { toRpcTx, type Transaction } from "../ckb.js";
import { TESTNET } from "../rpc.js";
import { buildTransfer } from "./coordinator.js";
import { signPsct } from "./signer.js";
import { finalizePsct, psctFingerprint, psctTxHash } from "../psct/container.js";

const SECP = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";

function arg(name: string, fallback?: string): string {
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0) return process.argv[i + 1]!;
  if (fallback !== undefined) return fallback;
  throw new Error(`--${name} is required`);
}

async function main() {
  const key = readFileSync(arg("key-file"), "utf8").trim();
  const from = arg("from");
  const amount = BigInt(arg("amount", "100")) * 100_000_000n;

  const rpriv = bytesToHex(secp256k1.utils.randomPrivateKey());
  const rargs = bytesToHex(blake160(secp256k1.getPublicKey(hexToBytes(rpriv), true)));
  const to = encodeAddress({ codeHash: SECP, hashType: "type", args: rargs }, "ckt", "short");

  console.log("from", from);
  console.log("to  ", to);

  const rpc = TESTNET;
  const transfer = await buildTransfer({ network: "testnet", from, to, amount });
  console.log(
    "coordinator",
    psctFingerprint(transfer.psct),
    "inputs",
    transfer.tx.inputs.length,
    "fee",
    transfer.fee.toString(),
  );

  const signed = signPsct(transfer.psct, key);
  console.log("signer", signed.signer, "groups", signed.signedGroups.length);

  const tx: Transaction = finalizePsct(signed.psct);
  const hash = await rpc.call<string>("send_transaction", [toRpcTx(tx)]);
  console.log("sent", hash, "expected", psctTxHash(signed.psct));

  for (let i = 0; i < 90; i++) {
    const res = await rpc.call<{ tx_status: { block_number: string | null } }>("get_transaction", [
      hash,
      "0x0",
    ]);
    if (res.tx_status.block_number) {
      console.log("committed in", BigInt(res.tx_status.block_number));
      return;
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error("not committed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
