#!/usr/bin/env node
/**
 * psct CLI (v0)
 *
 *   psct inspect <txhash> [--rpc mainnet|testnet] [--json]
 *   psct verify  <txhash> [--rpc mainnet|testnet] [--json]
 *   psct redteam [txhash]
 *
 * Exit codes: 0 ok · 1 refused or failed · 2 usage error.
 * Everything is computed from bound cells. Nothing is read from a label.
 */

import { fmtCkb, hexToBytes } from "./bytes.js";
import { readFileSync } from "node:fs";
import { MAINNET, TESTNET, type Rpc } from "./rpc.js";
import { resolveHeaders, resolveProofs } from "./psct/proofs.js";
import { bindAll } from "./psct/bind.js";
import { inspect } from "./psct/inspect.js";
import { verifyTx } from "./verify.js";
import { describeEpoch } from "./dao.js";
import { decodePsct } from "./psct/container.js";
import { toCkbCli } from "./ckbcli.js";

function usage(): never {
  console.error("usage: psct <inspect|verify|redteam> [txhash] [--rpc mainnet|testnet] [--json]");
  process.exit(2);
}

function parseArgs(argv: string[]) {
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  const rpcIndex = argv.indexOf("--rpc");
  const rpc = rpcIndex >= 0 && argv[rpcIndex + 1] === "testnet" ? TESTNET : MAINNET;
  const positional = argv.filter((a, i) => !a.startsWith("--") && argv[i - 1] !== "--rpc");
  return { flags, rpc, positional };
}

const json = (v: unknown) =>
  JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x), 2);

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd) usage();
  const { flags, rpc, positional } = parseArgs(rest);
  const wantJson = flags.has("--json");
  const hash = positional[0];

  if (cmd === "redteam") {
    const { sigHashExample } = await import("./scripts/redteam-helpers.js");
    const txHash = hash ?? "0x00b6d14f5567f2076ed3f975783b0cafda297a74795cef44803cfc265197c7cb";
    const tx = await rpc.tx(txHash);
    console.log(await sigHashExample(tx, txHash, rpc));
    return;
  }

  if (cmd === "cli-export") {
    const file = positional[0];
    if (!file) usage();
    const text = readFileSync(file, "utf8").trim();
    const bytes = text.startsWith("0x")
      ? hexToBytes(text)
      : Uint8Array.from(Buffer.from(text, "base64"));
    console.log(json(toCkbCli(decodePsct(bytes))));
    return;
  }

  if (!hash) usage();
  const tx = await rpc.tx(hash);
  const proofs = await resolveProofs(tx, rpc, { blockHashes: true });
  const bound = bindAll(tx, proofs);

  if (cmd === "inspect") {
    const headers = await resolveHeaders(tx, proofs, rpc);
    const r = inspect(tx, bound, { headers });
    if (wantJson) {
      console.log(json(r));
      return;
    }
    console.log(`tx            ${r.txHash}`);
    console.log(`inputs        ${tx.inputs.length}`);
    console.log(`outputs       ${tx.outputs.length}`);
    console.log(`in capacity   ${fmtCkb(r.inputCapacity)} CKB`);
    console.log(`out capacity  ${fmtCkb(r.outputCapacity)} CKB`);
    console.log(`fee           ${r.feeCkb} CKB${r.interestKnown ? "" : " (lower bound)"}`);
    console.log(`change        ${r.changeCandidates.join(", ") || "none"}`);
    if (r.dao.length) {
      console.log("");
      console.log("nervos dao");
      for (const f of r.dao) {
        const bits = [`input ${f.input}: ${f.kind}`];
        if (f.depositBlockNumber !== undefined) bits.push(`deposit block ${f.depositBlockNumber}`);
        if (f.depositEpoch) bits.push(`deposit epoch ${describeEpoch(f.depositEpoch)}`);
        if (f.matureAt) bits.push(`matures ${describeEpoch(f.matureAt)}`);
        if (f.mature !== null) bits.push(f.mature ? "mature" : "NOT mature");
        if (f.interest !== undefined) bits.push(`interest ${fmtCkb(f.interest)} CKB`);
        console.log("  " + bits.join(" | "));
        for (const issue of f.issues) console.log(`    issue: ${issue}`);
      }
    }
    if (r.tokens.length) {
      console.log("");
      console.log("tokens");
      for (const t of r.tokens) {
        console.log(
          `  ${t.kind} ${t.typeHash.slice(0, 12)}… in=${t.input} out=${t.output} delta=${t.delta}` +
            (t.ownerMode ? " (owner mode)" : ""),
        );
      }
    }
    if (r.spore.length) {
      console.log("");
      console.log("spore");
      for (const f of r.spore) {
        console.log(`  ${f.kind} ${f.id.slice(0, 12)}… content=${f.data?.contentBytes ?? "?"} bytes`);
      }
    }
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
    if (wantJson) {
      console.log(json(results));
    } else {
      for (const g of results) {
        console.log(
          `${g.verdict === "verified" ? "ok  " : "FAIL"} ${g.verdict.padEnd(14)} ${g.name}` +
            ` inputs=[${g.inputs.join(",")}]` +
            (g.reason ? `  ${g.reason}` : ""),
        );
      }
    }
    if (results.some((g) => g.verdict !== "verified")) process.exitCode = 1;
    return;
  }

  usage();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
