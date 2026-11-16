/** Resolve input proofs (and optional headers) from a node. A real PSCT carries these already. */

import { bytesToHex } from "../bytes.js";
import { encodeHeader, fromRpcHeader, type RpcHeader, type Transaction } from "../ckb.js";
import { ckbHash } from "../hash.js";
import { DAO_CODE_HASH } from "../dao.js";
import type { Rpc } from "../rpc.js";
import type { InputProof } from "./bind.js";

export interface ResolveOptions {
  /** Also record the block hash of DAO input cells (needed for interest). Costs one call each. */
  blockHashes?: boolean;
}

export async function resolveProofs(
  tx: Transaction,
  rpc: Rpc,
  opts: ResolveOptions = {},
): Promise<InputProof[]> {
  const cache = new Map<string, Transaction>();
  const proofs: InputProof[] = [];
  for (const input of tx.inputs) {
    const op = input.previousOutput;
    let prev = cache.get(op.txHash);
    if (!prev) {
      prev = await rpc.tx(op.txHash);
      cache.set(op.txHash, prev);
    }
    const proof: InputProof = { prevTx: prev, index: op.index };

    const type = prev.outputs[op.index]?.type;
    if (opts.blockHashes && type?.codeHash.toLowerCase() === DAO_CODE_HASH) {
      const res = await rpc.call<{ tx_status: { block_hash: string | null } }>("get_transaction", [
        op.txHash,
        "0x0",
      ]);
      if (res.tx_status.block_hash) proof.blockHash = res.tx_status.block_hash;
    }
    proofs.push(proof);
  }
  return proofs;
}

/**
 * Fetch raw headers for `header_deps` and for any proof that recorded a block hash.
 * Every header is hashed and compared with the value it is referenced by; a mismatch is fatal.
 */
export async function resolveHeaders(
  tx: Transaction,
  proofs: InputProof[],
  rpc: Rpc,
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const wanted = new Set<string>(tx.headerDeps.map((h) => h.toLowerCase()));
  for (const p of proofs) if (p.blockHash) wanted.add(p.blockHash.toLowerCase());

  for (const hash of wanted) {
    const json = await rpc.call<RpcHeader>("get_header", [hash]);
    const raw = encodeHeader(fromRpcHeader(json));
    const computed = bytesToHex(ckbHash(raw));
    if (computed !== hash) throw new Error(`header ${hash} hashes to ${computed}; refusing it`);
    out.set(hash, bytesToHex(raw));
  }
  return out;
}
