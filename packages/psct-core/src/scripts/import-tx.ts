/**
 * Import any mainnet/testnet transaction as an offline fixture, with proofs and any headers its
 * `header_deps` reference (plus DAO input block headers).
 *
 * Header hashes are recomputed from the raw bytes before they are stored: a header that does not
 * hash to the requested value is refused, not recorded.
 *
 * Run: npx tsx src/scripts/import-tx.ts <txhash> [mainnet|testnet]
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { MAINNET, TESTNET, type Rpc } from "../rpc.js";
import { stripWitnesses } from "../ckb.js";
import { txHash } from "../hash.js";
import { bindAll } from "../psct/bind.js";
import { classifyLock } from "../profiles.js";
import { resolveHeaders, resolveProofs } from "../psct/proofs.js";
import { inspect } from "../psct/inspect.js";
import { toJson, loadManifest } from "../fixtures.js";

async function main() {
  const hash = process.argv[2];
  if (!hash) throw new Error("usage: import-tx <txhash> [mainnet|testnet]");
  const rpc: Rpc = process.argv[3] === "testnet" ? TESTNET : MAINNET;

  mkdirSync(join(process.cwd(), "fixtures"), { recursive: true });

  const tx = await rpc.tx(hash);
  if (txHash(tx) !== hash) throw new Error(`fetched tx does not hash to ${hash}`);

  const proofs = await resolveProofs(tx, rpc, { blockHashes: true });
  const bound = bindAll(tx, proofs);

  const unknown = bound.map((b) => classifyLock(b.cellOutput.lock)).find((k) => k.kind === "unknown");
  if (unknown) console.warn(`warning: fixture contains an unknown lock (${unknown.name})`);

  const headerMap = await resolveHeaders(tx, proofs, rpc);

  // inputs - outputs is not the fee when DAO interest is minted; use the real inspection.
  const fee = inspect(tx, bound, { headers: headerMap }).fee;

  const file = join(process.cwd(), "fixtures", `${hash}.json`);
  writeFileSync(
    file,
    JSON.stringify(
      {
        hash,
        tx: toJson(tx),
        proofs: proofs.map((p) => ({
          index: p.index,
          blockHash: p.blockHash,
          prevTx: toJson(stripWitnesses(p.prevTx)),
        })),
        headers: Object.fromEntries(headerMap),
      },
      null,
      2,
    ),
  );
  console.log(`wrote ${file} (${(readFileSync(file).length / 1024).toFixed(1)} KB)`);
  console.log(
    `inputs=${tx.inputs.length} outputs=${tx.outputs.length} headers=${headerMap.size} fee=${fee}`,
  );

  const manifest = loadManifest();
  const entry = manifest.find((m) => m.hash === hash);
  if (entry) {
    entry.inputs = tx.inputs.length;
    entry.outputs = tx.outputs.length;
    entry.fee = fee.toString();
  } else {
    manifest.push({ hash, inputs: tx.inputs.length, outputs: tx.outputs.length, fee: fee.toString() });
  }
  writeFileSync(join(process.cwd(), "fixtures", "manifest.json"), JSON.stringify(manifest, null, 2));
  console.log("manifest updated");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
