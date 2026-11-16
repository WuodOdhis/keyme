/**
 * Devnet proof for the legacy multisig profile.
 *
 * Funds a 2-of-3 legacy multisig on a local devnet, then spends it with two signatures and lets
 * the node's consensus decide whether our placeholder and assembly are right.
 *
 * Run: npx tsx src/scripts/devnet-multisig.ts
 * Requires `offckb node` running (RPC 127.0.0.1:8114).
 */

import { execSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1";

import { Rpc } from "../rpc.js";
import { toRpcTx, type Script, type Transaction } from "../ckb.js";
import { blake160 } from "../hash.js";
import { bytesToHex, concat, hexToBytes } from "../bytes.js";
import { encodeWitnessArgs, sighashAllMessage, sighashMessage, zeroSignatureRegion } from "../sighash.js";
import { assembleMultisigLock, type MultisigScript } from "../multisig.js";
import { verifyTx } from "../verify.js";
import { bindAll } from "../psct/bind.js";
import { toJson, loadManifest } from "../fixtures.js";

const RPC_URL = "http://127.0.0.1:8114";
const SECP_DEP = {
  outPoint: { txHash: "0x4d804f1495612631da202fe9902fa9899118554b08138cfe5dfb50e1ede76293", index: 0 },
  depType: "dep_group" as const,
};
const MULTISIG_DEP = {
  outPoint: { txHash: "0x4d804f1495612631da202fe9902fa9899118554b08138cfe5dfb50e1ede76293", index: 1 },
  depType: "dep_group" as const,
};
const MULTISIG_CODE = "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8";
const CKB = 100_000_000n;
const FEE = 1000n;

interface Account {
  index: number;
  lockScript: Script;
  lockArg: string;
  privkey: string;
}

function loadAccounts(): Account[] {
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
  if (!line) throw new Error("cannot read offckb accounts output");
  return JSON.parse(line).accounts;
}

function sign(msg: Uint8Array, privkey: string): Uint8Array {
  const sig = secp256k1.sign(msg, hexToBytes(privkey), { lowS: true });
  return concat(sig.toCompactRawBytes(), Uint8Array.of(sig.recovery ?? 0));
}

async function getCell(rpc: Rpc, lock: Script) {
  const res = await rpc.call<{
    objects: { out_point: { tx_hash: string; index: string }; output: unknown }[];
  }>("get_cells", [
    {
      script: { code_hash: lock.codeHash, hash_type: lock.hashType, args: lock.args },
      script_type: "lock",
    },
    "asc",
    "0x1",
    null,
  ]);
  const first = res.objects[0];
  if (!first) throw new Error("no live cell for account 0");
  return first;
}

async function waitCommitted(rpc: Rpc, hash: string) {
  for (let i = 0; i < 60; i++) {
    const res = await rpc.call<{ tx_status: { block_number: string | null; status: string } }>(
      "get_transaction",
      [hash, "0x0"],
    );
    if (res.tx_status.block_number) return;
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`tx ${hash} did not commit`);
}

async function send(rpc: Rpc, tx: Transaction, label: string): Promise<string> {
  const hash = await rpc.call<string>("send_transaction", [toRpcTx(tx)]);
  console.log(`${label}: ${hash}`);
  await waitCommitted(rpc, hash);
  console.log(`${label}: committed`);
  return hash;
}

async function main() {
  const rpc = new Rpc(RPC_URL);
  const accounts = loadAccounts();
  const [a0, a1, a2] = [accounts[0]!, accounts[1]!, accounts[2]!];

  // 2-of-3 legacy multisig script (no since).
  const pubkeys = [a0.lockArg, a1.lockArg, a2.lockArg];
  const scriptPart = concat(Uint8Array.of(0, 0, 2, 3), ...pubkeys.map(hexToBytes));
  const msLock: Script = { codeHash: MULTISIG_CODE, hashType: "type", args: bytesToHex(blake160(scriptPart)) };
  const config: MultisigScript = {
    requireFirstN: 0,
    threshold: 2,
    pubkeys,
    scriptHash: bytesToHex(blake160(scriptPart)),
  };
  console.log("multisig lock args", msLock.args);

  const accountCell = await getCell(rpc, a0.lockScript);
  const inputCap = BigInt(accountCell.output ? (accountCell.output as any).capacity : "0x0");
  const msCap = 100n * CKB;
  console.log("funding from", accountCell.out_point.tx_hash, accountCell.out_point.index, "cap", inputCap);

  // ---- funding transaction: account 0 -> multisig
  const funding: Transaction = {
    version: 0,
    cellDeps: [SECP_DEP],
    headerDeps: [],
    inputs: [
      {
        since: 0n,
        previousOutput: {
          txHash: accountCell.out_point.tx_hash,
          index: Number(BigInt(accountCell.out_point.index)),
        },
      },
    ],
    outputs: [
      { capacity: msCap, lock: msLock, type: null },
      { capacity: inputCap - msCap - FEE, lock: a0.lockScript, type: null },
    ],
    outputsData: ["0x", "0x"],
    witnesses: [bytesToHex(encodeWitnessArgs({ lock: new Uint8Array(65), inputType: null, outputType: null }))],
  };
  const fundingMsg = sighashAllMessage(funding, [0]);
  funding.witnesses[0] = bytesToHex(
    encodeWitnessArgs({ lock: sign(fundingMsg, a0.privkey), inputType: null, outputType: null }),
  );
  const fundingHash = await send(rpc, funding, "funding");

  // ---- spend: 2-of-3 multisig -> account 1
  const msWitness = (lock: Uint8Array) =>
    bytesToHex(encodeWitnessArgs({ lock, inputType: null, outputType: null }));

  const spend: Transaction = {
    version: 0,
    cellDeps: [MULTISIG_DEP],
    headerDeps: [],
    inputs: [{ since: 0n, previousOutput: { txHash: fundingHash, index: 0 } }],
    outputs: [{ capacity: msCap - FEE, lock: a1.lockScript, type: null }],
    outputsData: ["0x"],
    // placeholder: real script part + zeroed signature region
    witnesses: [msWitness(concat(scriptPart, new Uint8Array(65 * 2)))],
  };
  const msg = sighashMessage(spend, [0], (w) => zeroSignatureRegion(w, 65 * 2));
  const sigs = {
    [a0.lockArg]: sign(msg, a0.privkey),
    [a1.lockArg]: sign(msg, a1.privkey),
  };
  const assembled = assembleMultisigLock(config, sigs);
  if (!assembled) throw new Error("could not assemble multisig lock");
  spend.witnesses[0] = msWitness(assembled);
  console.log("assembled lock len", assembled.length);

  const spendHash = await send(rpc, spend, "spend");

  // ---- independent check with our verifier, using the funding tx as proof
  const bound = bindAll(spend, [{ prevTx: funding, index: 0 }]);
  const verdicts = verifyTx(spend, bound);
  console.log("verdicts", verdicts.map((v) => [v.name, v.verdict, v.signers?.length]));

  // ---- store as a devnet fixture
  const file = join(process.cwd(), "fixtures", `${spendHash}.json`);
  writeFileSync(
    file,
    JSON.stringify(
      {
        hash: spendHash,
        network: "devnet",
        tx: toJson(spend),
        proofs: [{ index: 0, prevTx: toJson({ ...funding, witnesses: [] }) }],
        headers: {},
      },
      null,
      2,
    ),
  );
  console.log("wrote", file);

  const manifest = loadManifest();
  if (!manifest.some((m) => m.hash === spendHash)) {
    manifest.push({ hash: spendHash, inputs: 1, outputs: 1, fee: FEE.toString() });
    writeFileSync(join(process.cwd(), "fixtures", "manifest.json"), JSON.stringify(manifest, null, 2));
    console.log("manifest updated");
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
