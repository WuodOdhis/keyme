/**
 * Import a real multisig transaction from a `ckb-cli deploy` info file.
 *
 * The deploy file embeds `used_input_txs` — the same "carry the proof with the transaction" idea
 * PSCT formalises — so the resulting fixture is fully offline-verifiable.
 *
 * Source: fiber-scripts PR #34, a mainnet 3-of-5 upgrade.
 *
 * Run: npx tsx src/scripts/import-deploy.ts
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { MAINNET } from "../rpc.js";
import { fromRpcTx, stripWitnesses, type RpcTransaction } from "../ckb.js";
import { txHash } from "../hash.js";
import { bindAll, type InputProof } from "../psct/bind.js";
import { toJson, loadManifest } from "../fixtures.js";

const URL =
  "https://raw.githubusercontent.com/nervosnetwork/fiber-scripts/026027f54f6a90cb48d8cc184b230e2018bb8611/deployment/mainnet/mainnet.json";

async function main() {
  mkdirSync(join(process.cwd(), "fixtures"), { recursive: true });

  const deploy: any = await (await fetch(URL)).json();
  const skeleton = fromRpcTx(deploy.cell_tx as RpcTransaction);
  const hash = txHash(skeleton);
  console.log(`tx ${hash}`);

  const tx = await MAINNET.tx(hash); // committed form, with the assembled witness
  const proofs: InputProof[] = tx.inputs.map((input) => {
    const raw = deploy.used_input_txs[input.previousOutput.txHash];
    if (!raw) throw new Error(`used_input_txs is missing ${input.previousOutput.txHash}`);
    return { prevTx: fromRpcTx(raw as RpcTransaction), index: input.previousOutput.index };
  });

  const bound = bindAll(tx, proofs);
  const fee =
    bound.reduce((n, b) => n + b.cellOutput.capacity, 0n) -
    tx.outputs.reduce((n, o) => n + o.capacity, 0n);

  const file = join(process.cwd(), "fixtures", `${hash}.json`);
  writeFileSync(
    file,
    JSON.stringify(
      {
        hash,
        tx: toJson(tx),
        // Witnesses are not covered by tx_hash, and the signer never needs them.
        proofs: proofs.map((p) => ({ index: p.index, prevTx: toJson(stripWitnesses(p.prevTx)) })),
      },
      null,
      2,
    ),
  );
  console.log(`wrote ${file} (${(readFileSync(file).length / 1024).toFixed(1)} KB)`);

  const manifest = loadManifest();
  if (!manifest.some((m) => m.hash === hash)) {
    manifest.push({ hash, inputs: tx.inputs.length, outputs: tx.outputs.length, fee: fee.toString() });
    writeFileSync(join(process.cwd(), "fixtures", "manifest.json"), JSON.stringify(manifest, null, 2));
    console.log("manifest updated");
  } else {
    console.log("already in manifest");
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
