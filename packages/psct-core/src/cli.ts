#!/usr/bin/env node
/**
 * psct CLI (v0)
 *
 *   psct inspect <txhash> [--rpc mainnet|testnet]
 *   psct verify  <txhash> [--rpc mainnet|testnet]
 *   psct redteam [txhash]
 *
 * Everything is computed from bound cell data. Nothing is read from a label.
 */

import { fmtCkb } from "./bytes.js";
import { MAINNET, TESTNET, type Rpc } from "./rpc.js";
import { resolveProofs } from "./psct/proofs.js";
import { bindAll } from "./psct/bind.js";
import { inspect } from "./psct/inspect.js";
import { verifyTx } from "./verify.js";

function usage(): never {
  console.error("usage: psct <inspect|verify|redteam> [txhash] [--rpc mainnet|testnet]");
  process.exit(2);
}

function pickRpc(argv: string[]): Rpc {
  const i = argv.indexOf("--rpc");
  if (i < 0) return MAINNET;
  const v = argv[i + 1];
  return v === "testnet" ? TESTNET : MAINNET;
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd) usage();
  const rpc = pickRpc(rest);
  const positional = rest.filter((a, i) => a !== "--rpc" && rest[i - 1] !== "--rpc");
  const hash = positional[0];

  if (cmd === "redteam") {
    const { sigHashExample } = await import("./scripts/redteam-helpers.js");
    const txHashArg =
      hash ?? "0x00b6d14f5567f2076ed3f975783b0cafda297a74795cef44803cfc265197c7cb";
    const tx = await rpc.tx(txHashArg);
    console.log(await sigHashExample(tx, txHashArg, rpc));
    return;
  }

  if (!hash) usage();
  const tx = await rpc.tx(hash);
  const bound = bindAll(tx, await resolveProofs(tx, rpc));

  if (cmd === "inspect") {
    const r = inspect(tx, bound);
    console.log(`tx            ${r.txHash}`);
    console.log(`inputs        ${tx.inputs.length}`);
    console.log(`outputs       ${tx.outputs.length}`);
    console.log(`in capacity   ${fmtCkb(r.inputCapacity)} CKB`);
    console.log(`out capacity  ${fmtCkb(r.outputCapacity)} CKB`);
    console.log(`fee           ${r.feeCkb} CKB`);
    console.log(`change        ${r.changeCandidates.join(", ") || "none"}`);
    console.log("");
    console.log("deltas (output - input, per script)");
    for (const d of r.deltas) {
      const name = d.kind === "ckb" ? d.key : `${d.key.slice(0, 18)}…`;
      console.log(`  ${name.padEnd(22)} ${d.delta >= 0n ? "+" : ""}${d.delta}`);
    }
    if (r.warnings.length) {
      console.log("");
      console.log("warnings");
      for (const w of r.warnings) console.log(`  - ${w}`);
    }
    return;
  }

  if (cmd === "verify") {
    const results = verifyTx(tx, bound);
    let bad = 0;
    for (const g of results) {
      if (g.verdict !== "verified") bad++;
      console.log(
        `${g.verdict === "verified" ? "ok  " : "FAIL"} ${g.verdict.padEnd(14)} ${g.name}` +
          ` inputs=[${g.inputs.join(",")}]` +
          (g.reason ? `  ${g.reason}` : ""),
      );
    }
    if (bad) process.exitCode = 1;
    return;
  }

  usage();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
