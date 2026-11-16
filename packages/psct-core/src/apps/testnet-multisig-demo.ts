/**
 * Testnet 2-of-3 multisig: faucet -> fund multisig -> two signers -> combine -> broadcast.
 *
 *   npx tsx src/apps/testnet-multisig-demo.ts
 *
 * Fresh keys are generated per run; the tx hashes are the record.
 */

import { secp256k1 } from "@noble/curves/secp256k1";

import { bytesToHex, hexToBytes } from "../bytes.js";
import { blake160 } from "../hash.js";
import { encodeAddress } from "../address.js";
import { toRpcTx } from "../ckb.js";
import { Rpc } from "../rpc.js";
import { buildTransfer, multisigLock, type MultisigSpec } from "./coordinator.js";
import { signPsct } from "./signer.js";
import { combinePsct, finalizePsct, psctTxHash } from "../psct/container.js";

const CKB = 100_000_000n;
const SECP = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
const RPC = "https://testnet.ckb.dev";

function keypair() {
  const priv = bytesToHex(secp256k1.utils.randomPrivateKey());
  const pub = secp256k1.getPublicKey(hexToBytes(priv), true);
  const args = bytesToHex(blake160(pub));
  return { priv, args, address: encodeAddress({ codeHash: SECP, hashType: "type", args }, "ckt", "short") };
}

async function waitFor(rpc: Rpc, hash: string, label: string) {
  for (let i = 0; i < 120; i++) {
    const res = await rpc.call<{ tx_status: { block_number: string | null } }>("get_transaction", [hash, "0x0"]);
    if (res.tx_status.block_number) {
      console.log(`${label}: committed in ${BigInt(res.tx_status.block_number)}`);
      return;
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`${label}: not committed`);
}

async function balance(rpc: Rpc, args: string): Promise<bigint> {
  const res = await rpc.call<{ objects: { output: { capacity: string } }[] }>("get_cells", [
    { script: { code_hash: SECP, hash_type: "type", args }, script_type: "lock" },
    "asc",
    "0x40",
    null,
  ]);
  return res.objects.reduce((n, o) => n + BigInt(o.output.capacity), 0n);
}

async function main() {
  const rpc = new Rpc(RPC);
  const funder = keypair();
  const signers = [keypair(), keypair(), keypair()];

  console.log("funder ", funder.address);
  console.log("signer1", signers[0]!.address);
  console.log("signer2", signers[1]!.address);
  console.log("signer3", signers[2]!.address);

  const plan: MultisigSpec = {
    signers: signers.map((s) => s.address),
    threshold: 2,
    requireFirstN: 0,
    version: "legacy",
  };
  const multisig = encodeAddress(multisigLock(plan).lock, "ckt", "full");
  console.log("multisig", multisig);

  // 1. faucet -> funder
  const claim = await fetch("https://faucet-api.nervos.org/claim_events", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ claim_event: { address_hash: funder.address, amount: "10000" } }),
  });
  console.log("faucet", claim.status, (await claim.text()).slice(0, 120));
  for (let i = 0; i < 90 && (await balance(rpc, funder.args)) < 200n * CKB; i++) {
    await new Promise((r) => setTimeout(r, 2000));
  }
  console.log("funder balance", (await balance(rpc, funder.args)).toString());

  // 2. funder -> 2-of-3 multisig
  const fund = await buildTransfer({ network: "testnet", from: funder.address, to: multisig, amount: 200n * CKB });
  const fundSigned = signPsct(fund.psct, funder.priv);
  const fundHash = await rpc.call<string>("send_transaction", [toRpcTx(finalizePsct(fundSigned.psct))]);
  console.log("fund", fundHash);
  await waitFor(rpc, fundHash, "fund");

  // 3. multisig -> funder, signed by two separate processes
  const spend = await buildTransfer({ network: "testnet", multisig: plan, to: funder.address, amount: 100n * CKB });
  const s1 = signPsct(structuredClone(spend.psct), signers[0]!.priv);
  const s2 = signPsct(structuredClone(spend.psct), signers[1]!.priv);
  const combined = combinePsct(s1.psct, s2.psct);
  const spendHash = await rpc.call<string>("send_transaction", [toRpcTx(finalizePsct(combined))]);
  console.log("spend", spendHash, "expected", psctTxHash(combined));
  await waitFor(rpc, spendHash, "spend");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
