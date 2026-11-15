/** Shared logic for the red-team demo (kept out of redteam.ts so tests can import it). */

import { bytesEqual, bytesToHex, fmtCkb } from "../bytes.js";
import type { Rpc } from "../rpc.js";
import type { Transaction } from "../ckb.js";
import { sighashAllMessage, witnessLock } from "../sighash.js";
import { verifySighashAll } from "../verify.js";
import { bindAll, BindError, type BoundCell, type InputProof } from "../psct/bind.js";
import { inspect } from "../psct/inspect.js";
import { resolveProofs } from "../psct/proofs.js";

const SECP_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";

function secpGroup(tx: Transaction, bound: BoundCell[]): { indices: number[]; args: string } | null {
  const groups = new Map<string, number[]>();
  bound.forEach((b, i) => {
    const l = b.cellOutput.lock;
    if (l.codeHash !== SECP_CODE_HASH || l.hashType !== "type" || l.args.length !== 42) return;
    groups.set(l.args, [...(groups.get(l.args) ?? []), i]);
  });
  const [args, indices] = [...groups.entries()][0] ?? [];
  return args && indices ? { indices, args } : null;
}

export async function sigHashExample(tx: Transaction, hash: string, rpc: Rpc): Promise<string> {
  const L: string[] = [];
  const proofs = await resolveProofs(tx, rpc);
  const bound = bindAll(tx, proofs);
  const real = inspect(tx, bound);

  L.push(`transaction ${hash}`);
  L.push(`inputs=${tx.inputs.length} outputs=${tx.outputs.length}`);
  L.push("");

  // 1. What the signer should show, from bound data.
  L.push("1. honest coordinator (every cell bound to its outpoint)");
  L.push(`   input capacity   ${fmtCkb(real.inputCapacity)} CKB`);
  L.push(`   output capacity  ${fmtCkb(real.outputCapacity)} CKB`);
  L.push(`   fee              ${real.feeCkb} CKB`);
  L.push(`   change outputs   ${real.changeCandidates.join(", ") || "none"}`);
  L.push("");

  // 2. Forge the first input's capacity.
  const forgedProofs: InputProof[] = proofs.map((p, i) =>
    i === 0
      ? {
          ...p,
          cellOutput: { ...bound[0]!.cellOutput, capacity: bound[0]!.cellOutput.capacity * 1000n },
          data: bound[0]!.data,
        }
      : p,
  );
  const injected = bound[0]!.cellOutput.capacity * 999n;

  // 3. The naive signer: trusts the claim, never binds.
  const naive: BoundCell[] = bound.map((b, i) =>
    i === 0 ? { ...b, cellOutput: forgedProofs[0]!.cellOutput! } : b,
  );
  const lied = inspect(tx, naive);

  L.push("2. malicious coordinator (input 0's claimed capacity inflated 1000x)");
  L.push(`   displayed fee    ${lied.feeCkb} CKB`);
  L.push(`   real fee         ${real.feeCkb} CKB`);
  L.push(`   hidden overpay   ${fmtCkb(lied.fee - real.fee)} CKB  -> miner`);
  L.push("");

  // 4. The binding check catches it.
  let bindCaught = false;
  let bindMessage = "";
  try {
    bindAll(tx, forgedProofs);
  } catch (e) {
    bindCaught = e instanceof BindError;
    bindMessage = (e as Error).message;
  }
  L.push("3. binding check");
  L.push(`   result           ${bindCaught ? "REJECTED" : "ACCEPTED (bug)"}`);
  L.push(`   reason           ${bindMessage}`);
  L.push("");

  // 5. The signature is unaffected: the tx never changed.
  const group = secpGroup(tx, bound);
  if (!group) {
    L.push("4. signature check skipped (no secp256k1-blake160 group)");
    return L.join("\n");
  }
  const msg = sighashAllMessage(tx, group.indices);
  const sig = witnessLock(tx.witnesses[group.indices[0]!] ?? "0x");
  const check = sig ? verifySighashAll(msg, bytesToHex(sig), group.args) : null;

  const msgNaive = sighashAllMessage(tx, group.indices);
  L.push("4. signature check (unchanged by the lie)");
  L.push(`   sighash identical ${bytesEqual(msg, msgNaive) ? "yes" : "no"}`);
  L.push(`   signature valid   ${check?.ok ? "yes" : "no"}`);
  L.push(`   lock args         ${group.args}`);
  L.push("");

  L.push("conclusion");
  L.push(
    injected > 0n
      ? `   a signer that trusts an unbound CellOutput can approve a ${fmtCkb(injected)} CKB fee ` +
          `increase without any change to the signed bytes.`
      : "   no forged value produced",
  );
  L.push("   therefore PSCT must carry the creating transaction and hash-bind every input.");
  return L.join("\n");
}
