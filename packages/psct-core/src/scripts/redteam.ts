/**
 * Red-team demo: the input-claim attack.
 *
 * CKB's sighash does not commit to the spent cell's capacity. A coordinator that supplies a
 * CellOutput without hash-binding it can therefore inflate the displayed fee. The transaction,
 * the sighash message, and the signature are all unchanged — only the number on the trusted
 * screen changes.
 *
 * Run: npx tsx src/scripts/redteam.ts [txhash]
 */

import { fmtCkb } from "../bytes.js";
import { MAINNET } from "../rpc.js";
import { sigHashExample } from "./redteam-helpers.js";

const DEFAULT_TX = "0x00b6d14f5567f2076ed3f975783b0cafda297a74795cef44803cfc265197c7cb";

async function main() {
  const hash = process.argv[2] ?? DEFAULT_TX;
  const tx = await MAINNET.tx(hash);
  const out = await sigHashExample(tx, hash, MAINNET);
  console.log(out);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
