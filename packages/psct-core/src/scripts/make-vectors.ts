/**
 * Generate conformance vectors: signed PSCT files plus the expected final transaction hash.
 *
 * Run: npx tsx src/scripts/make-vectors.ts
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadFixture, loadManifest } from "../fixtures.js";
import { bindAll } from "../psct/bind.js";
import { classifyLock } from "../profiles.js";
import {
  buildPsct,
  encodePsct,
  extractExistingSignatures,
  finalizePsct,
  psctFingerprint,
  psctTxHash,
} from "../psct/container.js";
import { txHash } from "../hash.js";

interface VectorEntry {
  file: string;
  tx_hash: string;
  fingerprint: string;
  inputs: number;
  outputs: number;
  final_tx_hash: string;
  note: string;
}

function main() {
  const dir = join(process.cwd(), "vectors");
  mkdirSync(dir, { recursive: true });
  const manifest = loadManifest();
  const entries: VectorEntry[] = [];

  const fixtures = manifest.map((m) => loadFixture(m.hash));
  const plain = fixtures.find((f) =>
    bindAll(f.tx, f.proofs).every((b) => classifyLock(b.cellOutput.lock).profile === "sighash-all/secp256k1-blake160/v1"),
  );
  const multisig = fixtures.find((f) =>
    bindAll(f.tx, f.proofs).some((b) => classifyLock(b.cellOutput.lock).name.includes("Multisig")),
  );
  const dao = fixtures.find((f) => f.tx.headerDeps.length > 0);

  const selected: { f: typeof fixtures[number]; note: string }[] = [];
  if (plain) selected.push({ f: plain, note: "single-key secp256k1" });
  if (multisig) selected.push({ f: multisig, note: "multisig" });
  if (dao) selected.push({ f: dao, note: "nervos dao withdraw" });

  for (const { f, note } of selected) {
    const p = buildPsct(f.tx, {
      network: "ckb",
      proofs: f.proofs.map((x) => ({ prevTx: x.prevTx, index: x.index, blockHash: x.blockHash })),
      headers: f.headers,
    });
    extractExistingSignatures(p, f.tx, bindAll(f.tx, f.proofs));

    const encoded = encodePsct(p);
    const file = `${f.hash}.psct.b64`;
    writeFileSync(join(dir, file), Buffer.from(encoded).toString("base64"));
    const final = finalizePsct(p);
    entries.push({
      file,
      tx_hash: psctTxHash(p),
      fingerprint: psctFingerprint(p),
      inputs: f.tx.inputs.length,
      outputs: f.tx.outputs.length,
      final_tx_hash: txHash(final),
      note,
    });
    console.log(`${file}: ${encoded.length} bytes, ${note}`);
  }

  writeFileSync(join(dir, "manifest.json"), JSON.stringify(entries, null, 2));
  console.log(`wrote ${entries.length} vectors`);
}

main();
