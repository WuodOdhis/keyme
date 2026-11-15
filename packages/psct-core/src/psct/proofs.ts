/** Resolve input proofs from a node. In a real PSCT these travel with the file. */

import type { Rpc } from "../rpc.js";
import type { Transaction } from "../ckb.js";
import type { InputProof } from "./bind.js";

export async function resolveProofs(tx: Transaction, rpc: Rpc): Promise<InputProof[]> {
  const cache = new Map<string, Transaction>();
  const proofs: InputProof[] = [];
  for (const input of tx.inputs) {
    const op = input.previousOutput;
    let prev = cache.get(op.txHash);
    if (!prev) {
      prev = await rpc.tx(op.txHash);
      cache.set(op.txHash, prev);
    }
    proofs.push({ prevTx: prev, index: op.index });
  }
  return proofs;
}
